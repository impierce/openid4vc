use anyhow::Result;
use jsonwebtoken::Algorithm;
use oid4vc_core::utils::form_urlencoded::to_form_urlencoded_string;
use oid4vc_core::{
    SubjectSyntaxType, Validator,
    authentication::subject::SigningSubject,
    authorization_request::{AuthorizationRequest, Body, ByReference, ByValue, Object},
    authorization_response::AuthorizationResponse,
    openid4vc_extension::{Extension, ResponseHandle},
};
use reqwest::StatusCode;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::{RetryTransientMiddleware, policies::ExponentialBackoff};
use std::str::FromStr;

/// A Self-Issued OpenID Provider (SIOP), which is responsible for generating and signing [`crate::IdToken`]'s in response to
/// [`AuthorizationRequest`]'s from [crate::relying_party::RelyingParty]'s (RPs). The [`Provider`] acts as a trusted intermediary between the RPs and
/// the user who is trying to authenticate.
#[derive(Debug)]
pub struct Provider {
    pub subject: SigningSubject,
    pub supported_subject_syntax_types: Vec<SubjectSyntaxType>,
    pub supported_signing_algorithms: Vec<Algorithm>,
    client: ClientWithMiddleware,
}

impl Provider {
    // TODO: Use ProviderBuilder instead.
    pub fn new(
        subject: SigningSubject,
        supported_subject_syntax_types: Vec<impl TryInto<SubjectSyntaxType>>,
        supported_signing_algorithms: Vec<Algorithm>,
    ) -> Result<Self> {
        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(5);
        let client = ClientBuilder::new(oid4vc_core::http_client())
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();

        Ok(Provider {
            subject,
            client,
            supported_subject_syntax_types: supported_subject_syntax_types
                .into_iter()
                .map(|subject_syntax_type| {
                    subject_syntax_type
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("Invalid did method."))
                })
                .collect::<Result<_>>()?,
            supported_signing_algorithms,
        })
    }

    /// TODO: Add more validation rules.
    /// Takes a String and tries to parse it into an [`AuthorizationRequest<Object>`]. If the parsing fails, it tries to
    /// parse the [`AuthorizationRequest<Object>`] from the `request` parameter of the [`AuthorizationRequest<ByValue>`]
    /// or from the `request_uri` parameter of the [`AuthorizationRequest<ByReference>`].
    ///
    /// A Request Object is verified with the key its `kid` names. When the Client Identifier is a DID, that key has to
    /// be one of that DID. A request with its parameters in the open is not signed at all, and a Client Identifier
    /// that is not a DID is not authenticated here: whether to accept either is the caller's decision.
    #[tracing::instrument(level = "debug", err, skip(self, authorization_request))]
    pub async fn validate_request(&self, authorization_request: String) -> Result<AuthorizationRequest<Object>> {
        tracing::debug!("Validating SIOPv2 authorization request");
        let validator = Validator::Subject(self.subject.clone());

        let authorization_request = if let Ok(authorization_request) =
            authorization_request.parse::<AuthorizationRequest<Object>>()
        {
            authorization_request
        } else {
            let (client_id, authorization_request) =
                if let Ok(authorization_request) = AuthorizationRequest::<ByValue>::from_str(&authorization_request) {
                    let client_id = authorization_request.body.client_id().clone();
                    ensure_request_object_typ(&authorization_request.body.request)?;
                    ensure_signed_by_client(&authorization_request.body.request, &client_id)?;
                    let authorization_request: AuthorizationRequest<Object> =
                        validator.decode(authorization_request.body.request.to_owned()).await?;

                    (client_id, authorization_request)
                } else if let Ok(authorization_request) =
                    AuthorizationRequest::<ByReference>::from_str(&authorization_request)
                {
                    let client_id = authorization_request.body.client_id().clone();
                    let builder = self.client.get(authorization_request.body.request_uri.clone());
                    let request_value = builder.send().await?.text().await?;
                    ensure_request_object_typ(&request_value)?;
                    ensure_signed_by_client(&request_value, &client_id)?;
                    let authorization_request: AuthorizationRequest<Object> = validator.decode(request_value).await?;

                    (client_id, authorization_request)
                } else {
                    return Err(anyhow::anyhow!("Invalid SIOPv2 authorization request format."));
                };
            anyhow::ensure!(
                authorization_request.body.client_id == *client_id,
                "Client id mismatch."
            );
            authorization_request
        };

        tracing::info!(client_id = %authorization_request.body.client_id, "Successfully validated SIOPv2 authorization request");
        Ok(authorization_request)
    }

    #[tracing::instrument(level = "debug", err, skip(self, authorization_request))]
    pub async fn get_matching_signing_algorithm<E: Extension>(
        &self,
        authorization_request: &AuthorizationRequest<Object<E>>,
    ) -> Result<Algorithm> {
        let relying_party_supported_algorithms =
            E::get_relying_party_supported_algorithms(&authorization_request.body.extension).await?;

        self.supported_signing_algorithms
            .iter()
            .find(|supported_algorithm| relying_party_supported_algorithms.contains(supported_algorithm))
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("No matching signing algorithm found between Provider and Relying Party."))
    }

    #[tracing::instrument(level = "debug", err, skip(self, authorization_request))]
    pub async fn get_matching_subject_syntax_type<E: Extension>(
        &self,
        authorization_request: &AuthorizationRequest<Object<E>>,
    ) -> Result<SubjectSyntaxType> {
        let relying_party_supported_syntax_types =
            E::get_relying_party_supported_syntax_types(&authorization_request.body.extension).await?;

        self.supported_subject_syntax_types
            .iter()
            .find(|supported_syntax_type| relying_party_supported_syntax_types.contains(supported_syntax_type))
            // If no match is found, use the first supported syntax type as a fallback.
            .or_else(|| self.supported_subject_syntax_types.first())
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("No matching subject syntax type found between Provider and Relying Party."))
    }

    /// Generates an [`AuthorizationResponse`] in response to an [`AuthorizationRequest`] and the user's claims. The [`AuthorizationResponse`]
    /// contains an [`crate::IdToken`], which is signed by the [`oid4vc_core::Subject`] of the [`Provider`].
    #[tracing::instrument(level = "debug", err, skip(self, authorization_request, input))]
    pub async fn generate_response<E: Extension>(
        &self,
        authorization_request: &AuthorizationRequest<Object<E>>,
        input: <E::ResponseHandle as ResponseHandle>::Input,
    ) -> Result<AuthorizationResponse<E>> {
        let redirect_uri = authorization_request.body.uri.uri().to_string();
        let state = authorization_request.body.state.clone();

        tracing::info!(%redirect_uri, "Generating SIOPv2 authorization response");

        let signing_algorithm = self.get_matching_signing_algorithm(authorization_request).await?;
        let subject_syntax_type = self.get_matching_subject_syntax_type(authorization_request).await?;
        tracing::debug!(?signing_algorithm, %subject_syntax_type, "Selected algorithm and subject syntax type for SIOPv2 response");

        let jwts = E::generate_token(
            self.subject.clone(),
            &authorization_request.body.client_id,
            &authorization_request.body.extension,
            &input,
            subject_syntax_type.clone(),
            signing_algorithm,
        )
        .await?;

        E::build_authorization_response(jwts, input, redirect_uri, state)
    }

    #[tracing::instrument(level = "debug", err, skip(self, authorization_response))]
    pub async fn send_response<E: Extension>(
        &self,
        authorization_response: &AuthorizationResponse<E>,
    ) -> Result<StatusCode> {
        tracing::info!(redirect_uri = %authorization_response.redirect_uri, "Sending SIOPv2 authorization response");
        let encoded = to_form_urlencoded_string(&authorization_response)
            .map_err(|err| anyhow::anyhow!("Failed to encode authorization response: {err}"))?;

        let response = self
            .client
            .post(authorization_response.redirect_uri.clone())
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(encoded)
            .send()
            .await?;

        let status = response.status();
        tracing::debug!(?status, "Received response from relying party callback");
        Ok(status)
    }
}

/// The JOSE `typ` a Request Object must carry: "Wallets MUST NOT process Request Objects where the typ Header
/// Parameter is not present or does not have the value oauth-authz-req+jwt" (OpenID4VP 1.0, Section 5; RFC 9101,
/// Section 10.8). Compared as a media type (RFC 7515, Section 4.1.9): case-insensitively, `application/` optional.
fn ensure_request_object_typ(request_object: &str) -> Result<()> {
    let header = jsonwebtoken::decode_header(request_object)?;
    let typ = header.typ.as_deref().map(str::to_ascii_lowercase);
    let typ = typ
        .as_deref()
        .map(|typ| typ.strip_prefix("application/").unwrap_or(typ));
    anyhow::ensure!(
        typ == Some("oauth-authz-req+jwt"),
        "The Request Object's typ is {:?}, not \"oauth-authz-req+jwt\"; it is not processed.",
        header.typ
    );
    Ok(())
}

/// Refuses a Request Object under a DID Client Identifier that a key of another DID signed. The signature is verified
/// with the key the `kid` names, so without this check anyone could sign a request in the name of any DID. With a DID
/// as Client Identifier, "the request MUST be signed with a private key associated with the DID" and the `kid` "MUST
/// be a DID URL referring to a verification method in the DID Document" ([OpenID4VP 1.0, Section
/// 5.9.3](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.9.3)); the DID may come with
/// the `decentralized_identifier` prefix or, as in SIOPv2, without one.
///
/// A Client Identifier that is not a DID passes: this library cannot authenticate it.
fn ensure_signed_by_client(request_object: &str, client_id: &str) -> Result<()> {
    let client_did = client_id.strip_prefix("decentralized_identifier:").unwrap_or(client_id);
    if !client_did.starts_with("did:") {
        return Ok(());
    }
    let kid = jsonwebtoken::decode_header(request_object)?.kid.unwrap_or_default();
    // The DID of a DID URL ends where its path, query or fragment starts.
    let signer = kid.split(['/', '?', '#']).next().unwrap_or_default();
    anyhow::ensure!(
        signer == client_did,
        "The Request Object is not signed with a key of its Client Identifier; it is not processed."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{siopv2::SIOPv2, test_utils::TestSubject};
    use std::sync::Arc;

    /// A compact JWS whose JOSE header has this `typ` (the `typ` check reads only the header).
    fn jws_with_typ(typ: Option<&str>) -> String {
        jws_with_header(typ, Some("k"))
    }

    /// A compact JWS whose JOSE header has this `typ` and `kid`.
    fn jws_with_header(typ: Option<&str>, kid: Option<&str>) -> String {
        let mut header = jsonwebtoken::Header::new(Algorithm::HS256);
        header.typ = typ.map(str::to_string);
        header.kid = kid.map(str::to_string);
        jsonwebtoken::encode(
            &header,
            &serde_json::json!({}),
            &jsonwebtoken::EncodingKey::from_secret(b"test"),
        )
        .unwrap()
    }

    #[test]
    fn request_object_typ_must_be_oauth_authz_req_jwt() {
        for typ in [
            "oauth-authz-req+jwt",
            "application/oauth-authz-req+jwt",
            "OAuth-Authz-Req+JWT",
        ] {
            assert!(ensure_request_object_typ(&jws_with_typ(Some(typ))).is_ok(), "{typ}");
        }
        for typ in [None, Some("JWT"), Some("jwt")] {
            let error = ensure_request_object_typ(&jws_with_typ(typ)).unwrap_err().to_string();
            assert!(error.contains("not processed"), "{typ:?}: {error}");
        }
    }

    #[test]
    fn request_object_under_a_did_must_be_signed_with_a_key_of_that_did() {
        let signed_by = |kid: Option<&str>| jws_with_header(Some("oauth-authz-req+jwt"), kid);

        for (client_id, kid) in [
            ("did:example:verifier", "did:example:verifier#key-1"),
            (
                "decentralized_identifier:did:example:verifier",
                "did:example:verifier#key-1",
            ),
            (
                "did:web:example.com:verifier",
                "did:web:example.com:verifier?versionId=1#key-1",
            ),
            ("did:example:verifier", "did:example:verifier/path#key-1"),
        ] {
            assert!(
                ensure_signed_by_client(&signed_by(Some(kid)), client_id).is_ok(),
                "{client_id} {kid}"
            );
        }

        for (client_id, kid) in [
            ("did:example:verifier", Some("did:example:attacker#key-1")),
            (
                "decentralized_identifier:did:example:verifier",
                Some("did:example:attacker#key-1"),
            ),
            // Another DID that starts like the Client Identifier.
            ("did:example:verifier", Some("did:example:verifier2#key-1")),
            ("did:example:verifier", Some("did:example:verifier:attacker#key-1")),
            ("did:example:verifier", Some("#key-1")),
            ("did:example:verifier", Some("key-1")),
            ("did:example:verifier", None),
        ] {
            let error = ensure_signed_by_client(&signed_by(kid), client_id)
                .unwrap_err()
                .to_string();
            assert!(error.contains("not processed"), "{client_id} {kid:?}: {error}");
        }

        // Not a DID: nothing here to compare the `kid` with.
        for client_id in ["https://client.example.org", "origin:https://client.example.org"] {
            assert!(
                ensure_signed_by_client(&signed_by(Some("did:example:verifier#key-1")), client_id).is_ok(),
                "{client_id}"
            );
        }
    }

    #[tokio::test]
    async fn test_provider() {
        // Create a new subject and validator.
        let subject = TestSubject::new("did:test:123".to_string(), "key_id".to_string()).unwrap();

        // Create a new provider.
        let provider = Provider::new(Arc::new(subject), vec!["did:test"], vec![Algorithm::EdDSA]).unwrap();

        // Get a new SIOP authorization_request with response mode `direct_post` for cross-device communication.
        let request_url = "\
            siopv2://idtoken?\
                scope=openid\
                &response_type=id_token\
                &client_id=did%3Aexample%3AEiDrihTRe0GMdc3K16kgJB3Xbl9Hb8oqVHjzm6ufHcYDGA\
                &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb\
                &response_mode=direct_post\
                &client_metadata=%7B%22subject_syntax_types_supported%22%3A\
                %5B%22did%3Atest%22%5D%2C%0A%20%20%20%20\
                %22id_token_signing_alg_values_supported%22%3A%5B%22EdDSA%22%5D%7D\
                &nonce=n-0S6_WzA2Mj\
            ";

        // Let the provider validate the authorization_request.
        let authorization_request: AuthorizationRequest<Object> =
            provider.validate_request(request_url.to_string()).await.unwrap();

        let authorization_request =
            AuthorizationRequest::<Object<SIOPv2>>::from_generic(&authorization_request).unwrap();

        // Test whether the provider can generate a authorization_response for the authorization_request succesfully.
        assert!(
            provider
                .generate_response(&authorization_request, Default::default())
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_validate_request_rejects_invalid_request_object() {
        let subject = TestSubject::new("did:test:123".to_string(), "key_id".to_string()).unwrap();
        let provider = Provider::new(Arc::new(subject), vec!["did:test"], vec![Algorithm::EdDSA]).unwrap();

        assert!(
            provider
                .validate_request("siopv2://idtoken?client_id=did%3Aexample%3A123&request=not-a-jwt".to_string())
                .await
                .is_err()
        );
    }
}

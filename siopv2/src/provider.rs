use crate::{
    jwt, subject_syntax_type::DidMethod, AuthorizationRequest, AuthorizationResponse, IdToken, RequestUrl,
    StandardClaimsValues, Subject, Validators,
};
use anyhow::{anyhow, Result};
use chrono::{Duration, Utc};
use serde::de::DeserializeOwned;
use std::{str::FromStr, sync::Arc};

pub type SigningSubject = Arc<dyn Subject>;

/// A Self-Issued OpenID Provider (SIOP), which is responsible for generating and signing [`IdToken`]'s in response to
/// [`AuthorizationRequest`]'s from [crate::relying_party::RelyingParty]'s (RPs). The [`Provider`] acts as a trusted intermediary between the RPs and
/// the user who is trying to authenticate.
pub struct Provider {
    pub subject: SigningSubject,
    client: reqwest::Client,
}

pub struct Decoder {
    pub validators: Validators,
}

impl Decoder {
    pub async fn decode<T: DeserializeOwned>(&self, jwt: String) -> Result<T> {
        let (kid, algorithm) = jwt::extract_header(&jwt)?;
        //  TODO: decode for JWK Thumbprint
        let did_method = DidMethod::from(did_url::DID::from_str(&kid)?);

        let validator = self
            .validators
            .get(&did_method.into())
            .ok_or_else(|| anyhow!("No validator found."))?; // TODO: Use a better error message.
        let public_key = validator.public_key(&kid).await?;
        jwt::decode(&jwt, public_key, algorithm)
    }
}

impl Provider {
    // TODO: Use ProviderBuilder instead.
    pub fn new(subject: SigningSubject) -> Result<Self> {
        Ok(Provider {
            subject,
            client: reqwest::Client::new(),
        })
    }

    /// TODO: Add more validation rules.
    /// Takes a [`RequestUrl`] and returns a [`AuthorizationRequest`]. The [`RequestUrl`] can either be a [`AuthorizationRequest`] or a
    /// request by value. If the [`RequestUrl`] is a request by value, the request is decoded by the [`Subject`] of the [`Provider`].
    /// If the request is valid, the request is returned.
    pub async fn validate_request(&self, request: RequestUrl, decoder: &Decoder) -> Result<AuthorizationRequest> {
        if let RequestUrl::Request(authorization_request) = request {
            Ok(*authorization_request)
        } else {
            let (request_object, client_id) = match request {
                RequestUrl::RequestUri { request_uri, client_id } => {
                    let builder = self.client.get(request_uri);
                    let request_value = builder.send().await?.text().await?;
                    (request_value, client_id)
                }
                RequestUrl::RequestObject { request, client_id } => (request, client_id),
                _ => unreachable!(),
            };
            let authorization_request: AuthorizationRequest = decoder.decode(request_object).await?;
            anyhow::ensure!(*authorization_request.client_id() == client_id, "Client id mismatch.");
            Ok(authorization_request)
        }
    }

    /// Generates a [`AuthorizationResponse`] in response to a [`AuthorizationRequest`] and the user's claims. The [`AuthorizationResponse`]
    /// contains an [`IdToken`], which is signed by the [`Subject`] of the [`Provider`].
    pub async fn generate_response(
        &self,
        request: AuthorizationRequest,
        user_claims: StandardClaimsValues,
    ) -> Result<AuthorizationResponse> {
        let subject_identifier = self.subject.identifier()?;

        let id_token = IdToken::builder()
            .iss(subject_identifier.clone())
            .sub(subject_identifier)
            .aud(request.client_id().to_owned())
            .nonce(request.nonce().to_owned())
            .exp((Utc::now() + Duration::minutes(10)).timestamp())
            .iat((Utc::now()).timestamp())
            .claims(user_claims)
            .build()?;

        let jwt = jwt::encode(self.subject.clone(), id_token).await?;

        let mut builder = AuthorizationResponse::builder()
            .redirect_uri(request.redirect_uri().to_owned())
            .id_token(jwt);
        if let Some(state) = request.state() {
            builder = builder.state(state.clone());
        }
        builder.build()
    }

    pub async fn send_response(&self, response: AuthorizationResponse) -> Result<()> {
        let builder = self.client.post(response.redirect_uri()).form(&response);
        builder.send().await?.text().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_utils::MockSubject, SubjectSyntaxType, Validator};
    use std::str::FromStr;

    #[tokio::test]
    async fn test_provider() {
        // Create a new subject and validator.
        let subject = MockSubject::new("did:mock:123".to_string(), "key_id".to_string()).unwrap();

        // Create a new provider.
        let provider = Provider::new(Arc::new(subject)).unwrap();

        // Get a new SIOP request with response mode `post` for cross-device communication.
        let request_url = "\
            siopv2://idtoken?\
                scope=openid\
                &response_type=id_token\
                &client_id=did%3Aexample%3AEiDrihTRe0GMdc3K16kgJB3Xbl9Hb8oqVHjzm6ufHcYDGA\
                &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb\
                &response_mode=post\
                &client_metadata=%7B%22subject_syntax_types_supported%22%3A\
                %5B%22did%3Amock%22%5D%2C%0A%20%20%20%20\
                %22id_token_signing_alg_values_supported%22%3A%5B%22EdDSA%22%5D%7D\
                &nonce=n-0S6_WzA2Mj\
            ";

        // Let the provider validate the request.
        let request = provider
            .validate_request(
                request_url.parse().unwrap(),
                &Decoder {
                    validators: Validators::from([(
                        SubjectSyntaxType::from_str("did:mock").unwrap(),
                        Arc::new(Validator::Subject(
                            Arc::new(MockSubject::new("".into(), "".into()).unwrap()) as Arc<dyn Subject>,
                        )),
                    )]),
                },
            )
            .await
            .unwrap();

        // Test whether the provider can generate a response for the request succesfully.
        assert!(provider.generate_response(request, Default::default()).await.is_ok());
    }

    // TODO: Move to manager?
    // #[tokio::test]
    // async fn test_multiple_subjects() {
    //     // Create a new provider with just one did:mock subject.
    //     let subject = MockSubject::new("did:mock:123".to_string(), "key_id".to_string()).unwrap();
    //     let mut provider = Provider::new(Subjects(vec![Arc::new(subject)])).unwrap();

    //     // A request with only did:key stated in the `subject_syntax_types_supported`.
    //     let authorization_request: AuthorizationRequest = RequestUrl::builder()
    //         .client_id("did:example:123".to_string())
    //         .redirect_uri("https://example.com".to_string())
    //         .response_type(ResponseType::IdToken)
    //         .scope(Scope::openid())
    //         .nonce("123".to_string())
    //         .client_metadata(ClientMetadata::default().with_subject_syntax_types_supported(vec![
    //             SubjectSyntaxType::Did(DidMethod::from_str("did:key").unwrap()),
    //         ]))
    //         .build()
    //         .and_then(TryInto::try_into)
    //         .unwrap();

    //     // There are no subjects that match the request's supported subject syntax types.
    //     assert!(provider.matching_subject_syntax_types(&authorization_request).is_none());

    //     // Trying to set the active subject to a did:key subject fails.
    //     let key_method = SubjectSyntaxType::Did(DidMethod::from_str("did:key").unwrap());
    //     assert_eq!(
    //         provider.set_active_subject(key_method.clone()).unwrap_err().to_string(),
    //         "No subject with the given syntax type found."
    //     );

    //     // Add a did:key subject to the provider.
    //     let key_subject = KeySubject::new();
    //     provider.subjects.add(key_subject);

    //     // Setting the active subject to a did:key subject succeeds.
    //     assert!(provider.set_active_subject(key_method.clone()).is_ok());

    //     // The provider now has a subject that matches the request's supported subject syntax types.
    //     assert_eq!(
    //         provider.matching_subject_syntax_types(&authorization_request),
    //         Some(vec![SubjectSyntaxType::Did(DidMethod::from_str("did:key").unwrap())])
    //     );
    // }
}

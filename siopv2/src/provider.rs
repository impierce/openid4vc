use crate::{
    jwt, subject::Subjects, subject_syntax_type::DidMethod, AuthorizationRequest, AuthorizationResponse, IdToken,
    RequestUrl, StandardClaimsValues, Subject, SubjectSyntaxType,
};
use anyhow::Result;
use chrono::{Duration, Utc};
use std::{str::FromStr, sync::Arc};

/// A Self-Issued OpenID Provider (SIOP), which is responsible for generating and signing [`IdToken`]'s in response to
/// [`AuthorizationRequest`]'s from [crate::relying_party::RelyingParty]'s (RPs). The [`Provider`] acts as a trusted intermediary between the RPs and
/// the user who is trying to authenticate.
pub struct Provider {
    // TODO: Might need to change this to active_signer. Probably move this abstraction layer to the
    // oid-agent crate.
    pub signer_subject: Arc<dyn Subject>,
    pub subjects: Subjects,
}

impl Provider {
    // TODO: Use ProviderBuilder instead.
    pub fn new(subjects: Subjects) -> Result<Self> {
        let signer_subject = subjects
            .iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("No subjects found. At least one subject is required for a provider."))?
            .1
            .clone();
        Ok(Provider {
            signer_subject,
            subjects,
        })
    }

    /// TODO: Add more validation rules.
    /// Takes a [`RequestUrl`] and returns a [`AuthorizationRequest`]. The [`RequestUrl`] can either be a [`AuthorizationRequest`] or a
    /// request by value. If the [`RequestUrl`] is a request by value, the request is decoded by the [`Subject`] of the [`Provider`].
    /// If the request is valid, the request is returned.
    pub async fn validate_request(&self, request: RequestUrl) -> Result<AuthorizationRequest> {
        if let RequestUrl::Request(authorization_request) = request {
            Ok(*authorization_request)
        } else {
            let (request_object, client_id) = match request {
                RequestUrl::RequestUri { request_uri, client_id } => {
                    let client = reqwest::Client::new();
                    let builder = client.get(request_uri);
                    let request_value = builder.send().await?.text().await?;
                    (request_value, client_id)
                }
                RequestUrl::RequestObject { request, client_id } => (request, client_id),
                _ => unreachable!(),
            };

            let (kid, algorithm) = jwt::extract_header(&request_object)?;
            let did_method = DidMethod::from(did_url::DID::from_str(&kid)?);

            let subject = self.subjects.get(&did_method.into()).unwrap();

            let public_key = subject.public_key(&kid).await?;
            let authorization_request: AuthorizationRequest = jwt::decode(&request_object, public_key, algorithm)?;

            anyhow::ensure!(*authorization_request.client_id() == client_id, "Client id mismatch.");
            Ok(authorization_request)
        }
    }

    /// Generates a [`AuthorizationResponse`] in response to a [`AuthorizationRequest`] and the user's claims. The [`AuthorizationResponse`]
    /// contains an [`IdToken`], which is signed by the [`Subject`] of the [`Provider`].
    pub async fn generate_response(
        &self,
        subject_syntax_type: SubjectSyntaxType,
        request: AuthorizationRequest,
        user_claims: StandardClaimsValues,
    ) -> Result<AuthorizationResponse> {
        let signer_subject = self.subjects.get(&subject_syntax_type).unwrap();
        let subject_identifier = signer_subject.identifier()?;

        let id_token = IdToken::builder()
            .iss(subject_identifier.clone())
            .sub(subject_identifier)
            .aud(request.client_id().to_owned())
            .nonce(request.nonce().to_owned())
            .exp((Utc::now() + Duration::minutes(10)).timestamp())
            .iat((Utc::now()).timestamp())
            .claims(user_claims)
            .build()?;

        let jwt = jwt::encode(signer_subject.clone(), id_token).await?;

        let mut builder = AuthorizationResponse::builder()
            .redirect_uri(request.redirect_uri().to_owned())
            .id_token(jwt);
        if let Some(state) = request.state() {
            builder = builder.state(state.clone());
        }
        builder.build()
    }

    pub async fn send_response(&self, response: AuthorizationResponse) -> Result<()> {
        let client = reqwest::Client::new();
        let builder = client.post(response.redirect_uri()).form(&response);
        builder.send().await?.text().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::MockSubject;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_provider() {
        // Create a new subject and validator.
        let subject = MockSubject::new("did:mock:123".to_string(), "key_id".to_string()).unwrap();

        // Create a new provider.
        let provider = Provider::new(Subjects::from([(
            SubjectSyntaxType::from_str("did:mock").unwrap(),
            Arc::new(subject) as Arc<dyn Subject>,
        )]))
        .unwrap();

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
        let request = provider.validate_request(request_url.parse().unwrap()).await.unwrap();

        // Test whether the provider can generate a response for the request succesfully.
        assert!(provider
            .generate_response(
                SubjectSyntaxType::from_str("did:mock").unwrap(),
                request,
                Default::default()
            )
            .await
            .is_ok());
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

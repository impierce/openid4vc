use crate::{
    jwt, subject::Subjects, validator::Validators, AuthorizationRequest, AuthorizationResponse, IdToken, RequestUrl,
    StandardClaimsValues, Subject, SubjectSyntaxType,
};
use anyhow::Result;
use chrono::{Duration, Utc};
use std::sync::Arc;

/// A Self-Issued OpenID Provider (SIOP), which is responsible for generating and signing [`IdToken`]'s in response to
/// [`AuthorizationRequest`]'s from [crate::relying_party::RelyingParty]'s (RPs). The [`Provider`] acts as a trusted intermediary between the RPs and
/// the user who is trying to authenticate.
pub struct Provider {
    // TODO: Might need to change this to active_signer. Probably move this abstraction layer to the
    // oid-agent crate.
    pub active_subject: Arc<dyn Subject>,
    pub subjects: Subjects,
    pub validators: Validators,
}

impl Provider {
    // TODO: Use ProviderBuilder instead.
    pub fn new<S: Subject + 'static>(subject: S) -> Self {
        let active_subject = Arc::new(subject);
        let subjects = Subjects(vec![active_subject.clone()]);
        Provider {
            active_subject,
            subjects,
            validators: Validators::default(),
        }
    }

    pub fn set_active_subject(&mut self, subject_syntax_type: SubjectSyntaxType) -> Result<()> {
        let subject = self
            .subjects
            .iter()
            .find(|&subject| {
                subject_syntax_type
                    == subject
                        .did()
                        .and_then(|did| format!("did:{}", did.method()).try_into())
                        .unwrap()
            })
            .ok_or_else(|| anyhow::anyhow!("No subject with the given syntax type found."))?;
        self.active_subject = subject.clone();
        Ok(())
    }

    pub fn subject_syntax_types_supported(&self) -> Result<Vec<SubjectSyntaxType>> {
        self.subjects
            .iter()
            .map(|subject| subject.did().and_then(|did| format!("did:{}", did.method()).try_into()))
            .collect()
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
            let public_key = self.validators.select_validator()?.public_key(&kid).await?;
            let authorization_request: AuthorizationRequest = jwt::decode(&request_object, public_key, algorithm)?;
            anyhow::ensure!(*authorization_request.client_id() == client_id, "Client id mismatch.");
            Ok(authorization_request)
        }
    }

    // TODO: consider moving this functionality to the oid4vc-agent crate.
    pub fn matching_subject_syntax_types(
        &self,
        authorization_request: &AuthorizationRequest,
    ) -> Option<Vec<SubjectSyntaxType>> {
        let supported = self.subject_syntax_types_supported().ok()?;
        let supported_types = authorization_request
            .subject_syntax_types_supported()
            .map_or(Vec::new(), |types| {
                types.into_iter().filter(|sst| supported.contains(sst)).collect()
            });
        (!supported_types.is_empty()).then_some(supported_types.iter().map(|&sst| sst.clone()).collect())
    }

    /// Generates a [`AuthorizationResponse`] in response to a [`AuthorizationRequest`] and the user's claims. The [`AuthorizationResponse`]
    /// contains an [`IdToken`], which is signed by the [`Subject`] of the [`Provider`].
    pub async fn generate_response(
        &self,
        request: AuthorizationRequest,
        user_claims: StandardClaimsValues,
    ) -> Result<AuthorizationResponse> {
        let subject = self.active_subject.clone();
        let subject_did = subject.did()?;

        let id_token = IdToken::builder()
            .iss(subject_did.to_string())
            .sub(subject_did.to_string())
            .aud(request.client_id().to_owned())
            .nonce(request.nonce().to_owned())
            .exp((Utc::now() + Duration::minutes(10)).timestamp())
            .iat((Utc::now()).timestamp())
            .claims(user_claims)
            .build()?;

        let jwt = jwt::encode(subject, id_token).await?;

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
    use crate::{
        key_method::KeySubject,
        request::ResponseType,
        subject_syntax_type::DidMethod,
        test_utils::{MockSubject, MockValidator},
        ClientMetadata, Scope,
    };

    #[tokio::test]
    async fn test_provider() {
        // Create a new subject and validator.
        let subject = MockSubject::new("did:mock:123".to_string(), "key_identifier".to_string()).unwrap();
        let validator = MockValidator::new();

        // Create a new provider.
        let mut provider = Provider::new(subject);
        provider.validators.add(validator);

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
        assert!(provider.generate_response(request, Default::default()).await.is_ok());
    }

    #[tokio::test]
    async fn test_multiple_subjects() {
        // Create a new provider with just one did:mock subject.
        let mock_subject = MockSubject::new("did:mock:123".to_string(), "key_identifier".to_string()).unwrap();
        let mut provider = Provider::new(mock_subject);

        // A request with only did:key stated in the `subject_syntax_types_supported`.
        let authorization_request: AuthorizationRequest = RequestUrl::builder()
            .client_id("did:example:123".to_string())
            .redirect_uri("https://example.com".to_string())
            .response_type(ResponseType::IdToken)
            .scope(Scope::openid())
            .nonce("123".to_string())
            .client_metadata(
                ClientMetadata::default()
                    .with_subject_syntax_types_supported(vec![SubjectSyntaxType::Did(DidMethod("key".to_string()))]),
            )
            .build()
            .and_then(TryInto::try_into)
            .unwrap();

        // There are no subjects that match the request's supported subject syntax types.
        assert!(provider.matching_subject_syntax_types(&authorization_request).is_none());

        // Trying to set the active subject to a did:key subject fails.
        let key_method = SubjectSyntaxType::Did(DidMethod("key".to_string()));
        assert_eq!(
            provider.set_active_subject(key_method.clone()).unwrap_err().to_string(),
            "No subject with the given syntax type found."
        );

        // Add a did:key subject to the provider.
        let key_subject = KeySubject::new();
        provider.subjects.add(key_subject);

        // Setting the active subject to a did:key subject succeeds.
        assert!(provider.set_active_subject(key_method.clone()).is_ok());

        // The provider now has a subject that matches the request's supported subject syntax types.
        assert_eq!(
            provider.matching_subject_syntax_types(&authorization_request),
            Some(vec![SubjectSyntaxType::Did(DidMethod("key".to_string()))])
        );
    }
}

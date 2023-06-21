use crate::{
    jwt, request::ResponseType, token::vp_token::VpToken, AuthorizationRequest, AuthorizationResponse, Decoder,
    IdToken, RequestUrl, StandardClaimsValues, Subject,
};
use anyhow::Result;
use chrono::{Duration, Utc};
use identity_credential::presentation::JwtPresentation;
use oid4vp::PresentationSubmission;
use std::sync::Arc;

pub type SigningSubject = Arc<dyn Subject>;

/// A Self-Issued OpenID Provider (SIOP), which is responsible for generating and signing [`IdToken`]'s in response to
/// [`AuthorizationRequest`]'s from [crate::relying_party::RelyingParty]'s (RPs). The [`Provider`] acts as a trusted intermediary between the RPs and
/// the user who is trying to authenticate.
pub struct Provider {
    pub subject: SigningSubject,
    client: reqwest::Client,
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
    pub async fn validate_request(&self, request: RequestUrl, decoder: Decoder) -> Result<AuthorizationRequest> {
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
        verifiable_presentation: Option<JwtPresentation>,
        presentation_submission: Option<PresentationSubmission>,
    ) -> Result<AuthorizationResponse> {
        let subject_identifier = self.subject.identifier()?;

        let mut builder = AuthorizationResponse::builder().redirect_uri(request.redirect_uri().to_owned());

        // TODO: Clean this up!!
        match *request.response_type() {
            ResponseType::IdToken => {
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
                builder = builder.id_token(jwt);
            }
            ResponseType::IdTokenVpToken => {
                let id_token = IdToken::builder()
                    .iss(subject_identifier.clone())
                    .sub(subject_identifier.clone())
                    .aud(request.client_id().to_owned())
                    .nonce(request.nonce().to_owned())
                    .exp((Utc::now() + Duration::minutes(10)).timestamp())
                    .iat((Utc::now()).timestamp())
                    .claims(user_claims)
                    .build()?;

                let jwt = jwt::encode(self.subject.clone(), id_token).await?;
                builder = builder.id_token(jwt);

                if let (Some(verifiable_presentation), Some(presentation_submission)) =
                    (verifiable_presentation, presentation_submission)
                {
                    let vp_token = VpToken::builder()
                        .iss(subject_identifier.clone())
                        .sub(subject_identifier)
                        .aud(request.client_id().to_owned())
                        .nonce(request.nonce().to_owned())
                        .exp((Utc::now() + Duration::minutes(10)).timestamp())
                        .iat((Utc::now()).timestamp())
                        .verifiable_presentation(verifiable_presentation)
                        .build()?;

                    let jwt = jwt::encode(self.subject.clone(), vp_token).await?;
                    builder = builder.vp_token(jwt).presentation_submission(presentation_submission);
                } else {
                    anyhow::bail!("Verifiable presentation is required for this response type.");
                }
            }
        }

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
    use crate::{test_utils::MockSubject, SubjectSyntaxType, Validator, Validators};
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
                Decoder {
                    validators: Validators::from([(
                        SubjectSyntaxType::from_str("did:mock").unwrap(),
                        Arc::new(Validator::Subject(Arc::new(MockSubject::default()) as Arc<dyn Subject>)),
                    )]),
                },
            )
            .await
            .unwrap();

        // Test whether the provider can generate a response for the request succesfully.
        assert!(provider
            .generate_response(request, Default::default(), None, None)
            .await
            .is_ok());
    }
}

use crate::{
    AuthorizationRequest, AuthorizationResponse, IdToken, RequestUrl, StandardClaimsValues, Subject, SubjectSyntaxType,
    Validator,
};
use anyhow::{anyhow, Result};
use chrono::{Duration, Utc};

/// A Self-Issued OpenID Provider (SIOP), which is responsible for generating and signing [`IdToken`]'s in response to
/// [`AuthorizationRequest`]'s from [crate::relying_party::RelyingParty]'s (RPs). The [`Provider`] acts as a trusted intermediary between the RPs and
/// the user who is trying to authenticate.
#[derive(Default)]
pub struct Provider<S>
where
    S: Subject + Validator,
{
    pub subject: S,
}

impl<S> Provider<S>
where
    S: Subject + Validator,
{
    // TODO: Use ProviderBuilder instead.
    pub async fn new(subject: S) -> Result<Self> {
        Ok(Provider { subject })
    }

    pub fn subject_syntax_types_supported(&self) -> Result<Vec<SubjectSyntaxType>> {
        Ok(vec![format!("did:{}", self.subject.did()?.method()).try_into()?])
    }

    /// TODO: Add more validation rules.
    /// Takes a [`RequestUrl`] and returns a [`AuthorizationRequest`]. The [`RequestUrl`] can either be a [`AuthorizationRequest`] or a
    /// request by value. If the [`RequestUrl`] is a request by value, the request is decoded by the [`Subject`] of the [`Provider`].
    /// If the request is valid, the request is returned.
    pub async fn validate_request(&self, request: RequestUrl) -> Result<AuthorizationRequest> {
        let authorization_request = if let RequestUrl::Request(request) = request {
            *request
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
            let authorization_request: AuthorizationRequest = self.subject.decode(request_object).await?;
            anyhow::ensure!(*authorization_request.client_id() == client_id, "Client id mismatch.");
            authorization_request
        };
        self.subject_syntax_types_supported().and_then(|supported| {
            authorization_request.subject_syntax_types_supported().map_or_else(
                || Err(anyhow!("No supported subject syntax types found.")),
                |supported_types| {
                    supported_types.iter().find(|sst| supported.contains(sst)).map_or_else(
                        || Err(anyhow!("Subject syntax type not supported.")),
                        |_| Ok(authorization_request.clone()),
                    )
                },
            )
        })
        // Ok(authorization_request)
    }

    /// Generates a [`AuthorizationResponse`] in response to a [`AuthorizationRequest`] and the user's claims. The [`AuthorizationResponse`]
    /// contains an [`IdToken`], which is signed by the [`Subject`] of the [`Provider`].
    pub async fn generate_response(
        &self,
        request: AuthorizationRequest,
        user_claims: StandardClaimsValues,
    ) -> Result<AuthorizationResponse> {
        let subject_did = self.subject.did()?;

        let id_token = IdToken::builder()
            .iss(subject_did.to_string())
            .sub(subject_did.to_string())
            .aud(request.client_id().to_owned())
            .nonce(request.nonce().to_owned())
            .exp((Utc::now() + Duration::minutes(10)).timestamp())
            .iat((Utc::now()).timestamp())
            .claims(user_claims)
            .build()?;

        let jwt = self.subject.encode(id_token).await?;

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
    use crate::{subject_syntax_type::DidMethod, test_utils::MockSubject};

    #[tokio::test]
    async fn test_provider() {
        // Create a new subject.
        let subject = MockSubject::new("did:mock:123".to_string(), "key_identifier".to_string()).unwrap();

        // Create a new provider.
        let provider = Provider::new(subject).await.unwrap();

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
    async fn test_provider_subject_syntax_types_supported() {
        // Create a new provider.
        let provider = Provider::<MockSubject>::default();

        // Test whether the provider returns the correct subject syntax types.
        assert_eq!(
            provider.subject_syntax_types_supported().unwrap(),
            vec![SubjectSyntaxType::Did(DidMethod("mock".to_string()))]
        );
    }
}

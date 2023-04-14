use anyhow::{anyhow, Result};
use chrono::{Duration, Utc};
use serde::Serialize;

use crate::{IdToken, JsonWebToken, RequestUrl, SiopRequest, SiopResponse, Subject, Validator};

/// A Self-Issued OpenID Provider (SIOP), which is responsible for generating and signing [`IdToken`]'s in response to
/// [`SiopRequest`]'s from [crate::relying_party::RelyingParty]'s (RPs). The [`Provider`] acts as a trusted intermediary between the RPs and
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

    pub fn subject_syntax_types_supported(&self) -> Result<Vec<String>> {
        Ok(vec![format!("did:{}", self.subject.did()?.method())])
    }

    pub async fn validate_request(&self, request: RequestUrl) -> Result<SiopRequest> {
        let request = match request {
            RequestUrl::Request(request) => *request,
            RequestUrl::RequestUri { request_uri } => {
                let client = reqwest::Client::new();
                let builder = client.get(request_uri);
                let request_value = builder.send().await?.text().await?;
                self.subject.decode(request_value).await?
            }
        };
        let subject_syntax_types_supported = self.subject_syntax_types_supported()?;
        if request
            .subject_syntax_types_supported()
            .ok_or(anyhow!("No supported subject syntax types found."))?
            .iter()
            .any(|sst| subject_syntax_types_supported.contains(sst))
        {
            Ok(request)
        } else {
            Err(anyhow!("Subject syntax type not supported."))
        }
    }

    // TODO: needs refactoring.
    /// Generates a [`SiopResponse`] in response to a [`SiopRequest`]. The [`SiopResponse`] contains an [`IdToken`],
    /// which is signed by the [`Subject`] of the [`Provider`].
    pub async fn generate_response(&self, request: SiopRequest) -> Result<SiopResponse> {
        let subject_did = self.subject.did()?;
        let id_token = IdToken::new(
            subject_did.to_string(),
            subject_did.to_string(),
            request.client_id().clone(),
            request.nonce().clone(),
            (Utc::now() + Duration::minutes(10)).timestamp(),
        )
        .state(request.state().clone());

        let kid = self
            .subject
            .key_identifier()
            .ok_or(anyhow!("No key identifier found."))?;

        let jwt = JsonWebToken::new(id_token).kid(kid);

        let message = [base64_url_encode(&jwt.header)?, base64_url_encode(&jwt.payload)?].join(".");

        let proof_value = self.subject.sign(&message).await?;
        let signature = base64_url::encode(proof_value.as_slice());
        let id_token = [message, signature].join(".");

        Ok(SiopResponse::new(id_token, request.redirect_uri().clone()))
    }

    pub async fn send_response(&self, response: SiopResponse) -> Result<()> {
        let client = reqwest::Client::new();
        let builder = client.post(response.redirect_uri()).form(&response);
        builder.send().await?.text().await?;
        Ok(())
    }
}

fn base64_url_encode<T>(value: &T) -> Result<String>
where
    T: ?Sized + Serialize,
{
    Ok(base64_url::encode(serde_json::to_vec(value)?.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::MockSubject;

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
                &registration=%7B%22subject_syntax_types_supported%22%3A\
                %5B%22did%3Amock%22%5D%2C%0A%20%20%20%20\
                %22id_token_signing_alg_values_supported%22%3A%5B%22EdDSA%22%5D%7D\
                &nonce=n-0S6_WzA2Mj\
            ";

        let request = provider.validate_request(request_url.parse().unwrap()).await.unwrap();

        // Test whether the provider can generate a response for the request succesfully.
        assert!(provider.generate_response(request).await.is_ok());
    }

    #[tokio::test]
    async fn test_provider_subject_syntax_types_supported() {
        // Create a new provider.
        let provider = Provider::<MockSubject>::default();

        // Test whether the provider returns the correct subject syntax types.
        assert_eq!(
            provider.subject_syntax_types_supported().unwrap(),
            vec!["did:mock".to_string()]
        );
    }
}

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use serde::Serialize;

use crate::{IdToken, JsonWebToken, SiopRequest, SiopResponse};

/// A Self-Issued OpenID Provider (SIOP), which is responsible for generating and signing [`IdToken`]'s in response to
/// [`SiopRequest`]'s from [crate::relying_party::RelyingParty]'s (RPs). The [`Provider`] acts as a trusted intermediary between the RPs and
/// the user who is trying to authenticate.
#[derive(Default)]
pub struct Provider<S>
where
    S: Subject,
{
    pub subject: S,
}

impl<S> Provider<S>
where
    S: Subject,
{
    // TODO: Use ProviderBuilder instead.
    pub async fn new(subject: S) -> Result<Self> {
        Ok(Provider { subject })
    }

    pub fn subject_syntax_types_supported(&self) -> Vec<String> {
        vec![format!("did:{}", self.subject.did().method())]
    }

    // TODO: needs refactoring.
    /// Generates a [`SiopResponse`] in response to a [`SiopRequest`]. The [`SiopResponse`] contains an [`IdToken`],
    /// which is signed by the [`Subject`] of the [`Provider`].
    pub async fn generate_response(&self, request: SiopRequest) -> Result<SiopResponse> {
        if request
            .subject_syntax_types_supported()
            .iter()
            .any(|sst| self.subject_syntax_types_supported().contains(sst))
        {
            if request.is_cross_device_request() {
                if let Some(_redirect_uri) = request.redirect_uri() {
                    let id_token = IdToken::new(
                        self.subject.did().to_string(),
                        self.subject.did().to_string(),
                        request.client_id().clone(),
                        request.nonce().clone(),
                        (Utc::now() + Duration::minutes(10)).timestamp(),
                    );

                    let kid = self.subject.key_identifier().unwrap();

                    let jwt = JsonWebToken::new(id_token).kid(kid);

                    let message = [base64_url_encode(&jwt.header)?, base64_url_encode(&jwt.payload)?].join(".");

                    let proof_value = self.subject.sign(&message).await?;
                    let signature = base64_url::encode(proof_value.as_slice());
                    let id_token = [message, signature].join(".");

                    return Ok(SiopResponse::new(id_token));
                } else {
                    return Err(anyhow!("No redirect_uri found in the request."));
                }
            }
        }
        return Err(anyhow!("Subject syntax type not supported."));
    }

    pub async fn send_response(&self, response: SiopResponse, redirect_uri: String) {
        let client = reqwest::Client::new();
        let builder = client.post(redirect_uri).form(&response);
        builder.send().await.unwrap();
    }
}

fn base64_url_encode<T>(value: &T) -> Result<String>
where
    T: ?Sized + Serialize,
{
    Ok(base64_url::encode(serde_json::to_vec(value)?.as_slice()))
}

#[async_trait]
pub trait Subject {
    fn did(&self) -> did_url::DID;
    fn key_identifier(&self) -> Option<String>;
    async fn sign(&self, message: &String) -> Result<Vec<u8>>;
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
        let request: SiopRequest = serde_qs::from_str(
            "\
                response_type=id_token\
                &response_mode=post\
                &client_id=did:mock:1\
                &redirect_uri=http://127.0.0.1:4200/redirect_uri\
                &scope=openid\
                &nonce=n-0S6_WzA2Mj\
                &subject_syntax_types_supported[0]=did%3Amock\
            ",
        )
        .unwrap();

        // Test whether the provider can generate a response for the request succesfully.
        assert!(provider.generate_response(request).await.is_ok());
    }

    #[tokio::test]
    async fn test_provider_subject_syntax_types_supported() {
        // Create a new provider.
        let provider = Provider::<MockSubject>::default();

        // Test whether the provider returns the correct subject syntax types.
        assert_eq!(provider.subject_syntax_types_supported(), vec!["did:mock".to_string()]);
    }
}

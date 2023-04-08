use anyhow::{anyhow, Result};
use chrono::{Duration, Utc};
use serde::Serialize;

use crate::{IdToken, JsonWebToken, SiopRequest, SiopResponse, Subject};

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

    // TODO: needs refactoring.
    /// Generates a [`SiopResponse`] in response to a [`SiopRequest`]. The [`SiopResponse`] contains an [`IdToken`],
    /// which is signed by the [`Subject`] of the [`Provider`].
    pub async fn generate_response(&self, request: RequestUrl) -> Result<SiopResponse> {
        let request = request.try_into(&self.subject).await?;
        let subject_syntax_types_supported = self.subject_syntax_types_supported()?;
        if request
            .registration()
            .as_ref()
            .ok_or(anyhow!("No registration found."))?
            .subject_syntax_types_supported()
            .as_ref()
            .ok_or(anyhow!("No subject syntax types supported found."))?
            .iter()
            .any(|sst| subject_syntax_types_supported.contains(sst))
        {
            let subject_did = self.subject.did()?;
            let id_token = IdToken::new(
                // Use for Sphereon demo website testing.
                // "https://self-issued.me/v2".to_string(),
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
        } else {
            Err(anyhow!("Subject syntax type not supported."))
        }
    }

    pub async fn send_response(&self, response: SiopResponse) -> Result<()> {
        let redirect_uri = response.redirect_uri().as_ref().ok_or(anyhow!("No redirect URI."))?;
        let client = reqwest::Client::new();
        let builder = client.post(redirect_uri).form(&response);
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
    use crate::{key::KeySubject, test_utils::MockSubject};
    use std::str::FromStr;

    #[tokio::test]
    async fn test_provider() {
        // Create a new subject.
        let subject = MockSubject::new("did:mock:123".to_string(), "key_identifier".to_string()).unwrap();

        // Create a new provider.
        let provider = Provider::new(subject).await.unwrap();

        // Get a new SIOP request with response mode `post` for cross-device communication.
        let request = "\
            siopv2://idtoken?\
                scope=openid\
                &response_type=id_token\
                &client_id=did%3Aexample%3AEiDrihTRe0GMdc3K16kgJB3Xbl9Hb8oqVHjzm6ufHcYDGA\
                &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb\
                &response_mode=post\
                &registration=%7B%22subject_syntax_types_supported%22%3A\
                %5B%22did%3Amock%22%5D%2C%0A%20%20%20%20\
                %22id_token_signing_alg_values_supported%22%3A%5B%22ES256%22%5D%7D\
                &nonce=n-0S6_WzA2Mj\
            ";

        // Test whether the provider can generate a response for the request succesfully.
        provider
            .generate_response(RequestUrl::from_str(request).unwrap())
            .await
            .unwrap();
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

    #[tokio::test]
    async fn test_sphereon_demo_website() {
        use serde::Deserialize;

        #[derive(Deserialize, Debug)]
        #[serde(rename_all = "camelCase")]
        struct AuthRequestResponse {
            _correlation_id: String,
            _definition_id: String,
            #[serde(rename(deserialize = "authRequestURI"))]
            auth_request_uri: String,
            #[serde(rename(deserialize = "authStatusURI"))]
            _auth_status_uri: String,
        }

        let client = reqwest::Client::new();
        let builder = client
            .get("http://localhost:3002/webapp/definitions/9449e2db-791f-407c-b086-c21cc677d2e0/auth-request-uri");
        let AuthRequestResponse { auth_request_uri, .. } = builder
            .send()
            .await
            .unwrap()
            .json::<AuthRequestResponse>()
            .await
            .unwrap();

        // --------------------`After QR Code scan`--------------------

        let subject = KeySubject::default();

        let provider = Provider::new(subject).await.unwrap();

        let response = provider
            .generate_response(RequestUrl::from_str(auth_request_uri.as_str()).unwrap())
            .await
            .unwrap();

        provider.send_response(response).await.unwrap();
    }
}

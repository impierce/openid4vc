use crate::{IdToken, SiopRequest, SiopResponse, Subject, Validator};
use anyhow::Result;

pub struct RelyingParty<V>
where
    V: Validator + Subject,
{
    validator: V,
}

impl<V> RelyingParty<V>
where
    V: Validator + Subject,
{
    pub fn new(validator: V) -> Self {
        RelyingParty { validator }
    }

    pub async fn encode(&self, request: &SiopRequest) -> Result<String> {
        self.validator.encode(request).await
    }

    /// Validates a [`SiopResponse`] by decoding the header of the id_token, fetching the public key corresponding to
    /// the key identifier and finally decoding the id_token using the public key and by validating the signature.
    pub async fn validate_response(&self, response: &SiopResponse) -> Result<IdToken> {
        let token = response.id_token.clone();
        let id_token: IdToken = self.validator.decode(token).await?;
        Ok(id_token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{request::ResponseType, test_utils::MockSubject, IdToken, Provider, Registration, RequestUrl};
    use chrono::{Duration, Utc};
    use wiremock::{
        http::Method,
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[tokio::test]
    async fn test_relying_party() {
        // Create a new mock server and retreive it's url.
        let mock_server = MockServer::start().await;
        let server_url = mock_server.uri();

        // Create a new validator.
        let validator = MockSubject::new("did:mock:1".to_string(), "key_identifier".to_string()).unwrap();

        // Create a new relying party.
        let relying_party = RelyingParty::new(validator);

        // Create a new RequestUrl with response mode `post` for cross-device communication.
        let request: SiopRequest = RequestUrl::builder()
            .response_type(ResponseType::IdToken)
            .client_id("did:mock:1".to_owned())
            .scope("openid".to_owned())
            .redirect_uri(format!("{server_url}/redirect_uri"))
            .response_mode("post".to_owned())
            .registration(
                Registration::default()
                    .with_subject_syntax_types_supported(vec!["did:mock".to_owned()])
                    .with_id_token_signing_alg_values_supported(vec!["EdDSA".to_owned()]),
            )
            .exp((Utc::now() + Duration::minutes(10)).timestamp())
            .nonce("n-0S6_WzA2Mj".to_owned())
            .build()
            .and_then(TryInto::try_into)
            .unwrap();

        // Create a new `request_uri` endpoint on the mock server and load it with the JWT encoded `SiopRequest`.
        Mock::given(method("GET"))
            .and(path("/request_uri"))
            .respond_with(ResponseTemplate::new(200).set_body_string(relying_party.encode(&request).await.unwrap()))
            .mount(&mock_server)
            .await;

        // Create a new `redirect_uri` endpoint on the mock server where the `Provider` will send the `SiopResponse`.
        Mock::given(method("POST"))
            .and(path("/redirect_uri"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        // Create a new subject.
        let subject = MockSubject::new("did:mock:123".to_string(), "key_identifier".to_string()).unwrap();

        // Create a new provider.
        let provider = Provider::new(subject).await.unwrap();

        // Create a new RequestUrl which includes a `request_uri` pointing to the mock server's `request_uri` endpoint.
        let request_url = RequestUrl::builder()
            .request_uri(format!("{server_url}/request_uri"))
            .build()
            .unwrap();

        // The Provider obtains the reuquest url either by a deeplink or by scanning a QR code. It then validates the
        // request. Since in this case the request is a JWT, the provider will fetch the request by sending a GET
        // request to mock server's `request_uri` endpoint.
        let request = provider.validate_request(request_url).await.unwrap();

        // Assert that the request was successfully received by the mock server at the `request_uri` endpoint.
        let get_request = mock_server.received_requests().await.unwrap()[0].clone();
        assert_eq!(get_request.method, Method::Get);
        assert_eq!(get_request.url.path(), "/request_uri");

        // Let the provider generate a response based on the validated request. The response is an `IdToken` which is
        // encoded as a JWT.
        let response = provider.generate_response(request).await.unwrap();

        // The provider sends it's response to the mock server's `redirect_uri` endpoint.
        provider.send_response(response).await.unwrap();

        // Assert that the SiopResponse was successfully received by the mock server at the expected endpoint.
        let post_request = mock_server.received_requests().await.unwrap()[1].clone();
        assert_eq!(post_request.method, Method::Post);
        assert_eq!(post_request.url.path(), "/redirect_uri");
        let response: SiopResponse = serde_urlencoded::from_bytes(post_request.body.as_slice()).unwrap();

        // The `RelyingParty` then validates the response by decoding the header of the id_token, by fetching the public
        // key corresponding to the key identifier and finally decoding the id_token using the public key and by
        // validating the signature.
        let id_token = relying_party.validate_response(&response).await.unwrap();
        let IdToken {
            iss, sub, aud, nonce, ..
        } = IdToken::new(
            "did:mock:123".to_string(),
            "did:mock:123".to_string(),
            "did:mock:1".to_string(),
            "n-0S6_WzA2Mj".to_string(),
            (Utc::now() + Duration::minutes(10)).timestamp(),
        );
        assert_eq!(id_token.iss, iss);
        assert_eq!(id_token.sub, sub);
        assert_eq!(id_token.aud, aud);
        assert_eq!(id_token.nonce, nonce);
    }
}

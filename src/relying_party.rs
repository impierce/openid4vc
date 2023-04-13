use crate::{IdToken, SiopResponse, Validator};
use anyhow::{anyhow, Result};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};

pub struct RelyingParty<V>
where
    V: Validator,
{
    validator: V,
}

impl<V> RelyingParty<V>
where
    V: Validator,
{
    pub fn new(validator: V) -> Self {
        RelyingParty { validator }
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
    use crate::{
        test_utils::{MockSubject, MockValidator},
        IdToken, Provider,
    };
    use chrono::{Duration, Utc};

    #[tokio::test]
    async fn test_relying_party() {
        // Get a new SIOP request with response mode `post` for cross-device communication.
        let request_url = "\
            siopv2://idtoken?\
                scope=openid\
                &response_type=id_token\
                &client_id=did%3Amock%3A1\
                &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb\
                &response_mode=post\
                &registration=%7B%22subject_syntax_types_supported%22%3A\
                %5B%22did%3Amock%22%5D%2C%0A%20%20%20%20\
                %22id_token_signing_alg_values_supported%22%3A%5B%22EdDSA%22%5D%7D\
                &nonce=n-0S6_WzA2Mj\
            ";

        // Create a new subject.
        let subject = MockSubject::new("did:mock:123".to_string(), "key_identifier".to_string()).unwrap();

        // Create a new provider.
        let provider = Provider::new(subject).await.unwrap();

        let request = provider.validate_request(request_url.parse().unwrap()).await.unwrap();

        // Test whether the provider can generate a response for the request succesfully.
        let response = provider.generate_response(request).await.unwrap();

        // Create a new validator.
        let validator = MockValidator::new();

        // Create a new relying party.
        let relying_party = RelyingParty::new(validator);

        // Validate the response.
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

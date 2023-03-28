use crate::{IdToken, SiopResponse};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
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
        let id_token = response.id_token.clone();
        let header = decode_header(id_token.as_str())?;
        let id_token = if let Some(kid) = header.kid {
            // TODO: check if the subject syntax type corresponds with the validator type.
            let public_key = self.validator.public_key(&kid).await?;

            let key = DecodingKey::from_ed_der(&public_key.as_slice());
            decode::<IdToken>(id_token.as_str(), &key, &Validation::new(Algorithm::EdDSA))?.claims
        } else {
            return Err(anyhow!("No key identifier found in the header."));
        };
        Ok(id_token)
    }
}

#[async_trait]
pub trait Validator {
    async fn public_key(&self, kid: &String) -> Result<Vec<u8>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_utils::{MockSubject, MockValidator},
        IdToken, Provider, SiopRequest,
    };

    #[tokio::test]
    async fn test_relying_party() {
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

        // Generate a new response.
        let response = Provider::<MockSubject>::default()
            .generate_response(request)
            .await
            .unwrap();

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
        );
        assert_eq!(id_token.iss, iss);
        assert_eq!(id_token.sub, sub);
        assert_eq!(id_token.aud, aud);
        assert_eq!(id_token.nonce, nonce);
    }
}

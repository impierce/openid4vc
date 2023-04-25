use crate::JsonWebToken;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde::Serialize;

/// This [`Subject`] trait is used to sign and verify JWTs.
#[async_trait]
pub trait Subject {
    fn did(&self) -> Result<did_url::DID>;
    fn key_identifier(&self) -> Option<String>;
    async fn sign<'a>(&self, message: &'a str) -> Result<Vec<u8>>;

    async fn encode<C>(&self, claims: C) -> Result<String>
    where
        C: Serialize + Send,
    {
        let kid = self.key_identifier().ok_or(anyhow!("No key identifier found."))?;

        let jwt = JsonWebToken::new(claims).kid(kid);

        let message = [base64_url_encode(&jwt.header)?, base64_url_encode(&jwt.payload)?].join(".");

        let proof_value = self.sign(&message).await?;
        let signature = base64_url::encode(proof_value.as_slice());
        let message = [message, signature].join(".");
        Ok(message)
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
    use crate::{test_utils::MockSubject, IdToken, Validator};
    use serde_json::json;

    #[tokio::test]
    async fn test_encode() {
        let claims = json!({
            "iss": "did:example:123",
            "sub": "did:example:123",
            "aud": "did:example:456",
            "exp": 9223372036854775807i64,
            "iat": 1593436422,
            "nonce": "nonce",

        });
        let subject = MockSubject::new("did:mock:123".to_string(), "key_identifier".to_string()).unwrap();
        let encoded = subject.encode(claims).await.unwrap();
        let decoded = subject.decode::<IdToken>(encoded).await.unwrap();
        assert_eq!(
            decoded,
            IdToken {
                iss: "did:example:123".to_string(),
                sub: "did:example:123".to_string(),
                aud: "did:example:456".to_string(),
                exp: 9223372036854775807,
                iat: 1593436422,
                nonce: "nonce".to_string(),
                state: None,
            }
        )
    }
}

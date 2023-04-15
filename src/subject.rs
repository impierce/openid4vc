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

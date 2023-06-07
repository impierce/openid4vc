use anyhow::anyhow;
use anyhow::Result;
use async_trait::async_trait;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::de::DeserializeOwned;

/// This [`Validator`] trait is used to verify JWTs.
#[async_trait]
pub trait Validator: Sync {
    async fn public_key(&self, kid: &str) -> Result<Vec<u8>>;

    async fn decode<T>(&self, token: String) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let header = decode_header(token.as_str())?;
        let payload = if let Some(kid) = header.kid {
            // TODO: check if the subject syntax type corresponds with the validator type.
            let public_key = self.public_key(&kid).await?;

            let key = DecodingKey::from_ed_der(public_key.as_slice());
            decode::<T>(token.as_str(), &key, &Validation::new(Algorithm::EdDSA))?.claims
        } else {
            return Err(anyhow!("No key identifier found in the header."));
        };
        Ok(payload)
    }
}

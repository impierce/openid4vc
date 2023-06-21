use anyhow::Result;
use async_trait::async_trait;

/// This [`Verify`] trait is used to verify JWTs.
#[async_trait]
pub trait Verify: Sync {
    async fn public_key(&self, kid: &str) -> Result<Vec<u8>>;
}

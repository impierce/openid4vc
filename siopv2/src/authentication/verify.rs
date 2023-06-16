use anyhow::Result;
use async_trait::async_trait;

/// This [`Verify`] trait is used to verify JWTs.
#[async_trait]
pub trait Verify: Sync {
    // TODO: rename to `resolve` or something similar.
    async fn public_key(&self, kid: &str) -> Result<Vec<u8>>;
}

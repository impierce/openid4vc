use crate::Collection;
use anyhow::Result;
use async_trait::async_trait;

/// This [`Validator`] trait is used to verify JWTs.
#[async_trait]
pub trait Validator: Sync {
    // TODO: rename to `resolve` or something similar.
    async fn public_key(&self, kid: &str) -> Result<Vec<u8>>;
}

pub type Validators = Collection<dyn Validator>;

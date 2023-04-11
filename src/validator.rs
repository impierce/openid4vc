use anyhow::Result;
use async_trait::async_trait;

#[async_trait]
pub trait Validator {
    async fn public_key<'a>(&self, kid: &'a str) -> Result<Vec<u8>>;
}

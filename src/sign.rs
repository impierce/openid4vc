use anyhow::Result;
use async_trait::async_trait;

#[async_trait]
pub trait Sign {
    async fn sign<'a>(&self, message: &'a str) -> Result<Vec<u8>>;
}

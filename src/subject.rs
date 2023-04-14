use anyhow::Result;
use async_trait::async_trait;

/// This [`Subject`] trait is used to sign and verify JWTs.
#[async_trait]
pub trait Subject {
    fn did(&self) -> Result<did_url::DID>;
    fn key_identifier(&self) -> Option<String>;
    async fn sign<'a>(&self, message: &'a str) -> Result<Vec<u8>>;
}

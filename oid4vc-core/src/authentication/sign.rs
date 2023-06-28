use anyhow::Result;
use async_trait::async_trait;

#[async_trait]
pub trait Sign: Send + Sync {
    // TODO: add this?
    // fn jwt_alg_name() -> &'static str;
    fn key_id(&self) -> Option<String>;
    async fn sign(&self, message: &str) -> Result<Vec<u8>>;
}

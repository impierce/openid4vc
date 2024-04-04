use anyhow::Result;
use std::sync::Arc;

pub trait Sign: Send + Sync {
    // TODO: add this?
    // fn jwt_alg_name() -> &'static str;
    fn key_id(&self, did_method: &str) -> Option<String>;
    fn sign(&self, message: &str, did_method: &str) -> Result<Vec<u8>>;
    fn external_signer(&self) -> Option<Arc<dyn ExternalSign>>;
}

pub trait ExternalSign: Send + Sync {
    fn sign(&self, message: &str) -> Result<Vec<u8>>;
}

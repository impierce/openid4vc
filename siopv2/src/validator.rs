use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::{slice::Iter, sync::Arc};

/// This [`Validator`] trait is used to verify JWTs.
#[async_trait]
pub trait Validator: Sync {
    async fn public_key(&self, kid: &str) -> Result<Vec<u8>>;
}

#[derive(Default)]
pub struct Validators(pub Vec<Arc<dyn Validator>>);

impl Validators {
    pub fn select_validator(&self) -> Result<Arc<dyn Validator>> {
        self.0.get(0).cloned().ok_or_else(|| anyhow!("No validator found."))
    }

    pub fn add<V: Validator + 'static>(&mut self, validator: V) {
        self.0.push(Arc::new(validator));
    }

    pub fn iter(&self) -> Iter<'_, Arc<dyn Validator>> {
        self.0.iter()
    }
}

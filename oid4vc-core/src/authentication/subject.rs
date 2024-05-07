use crate::{Sign, Verify};
use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;

pub type SigningSubject = Arc<dyn Subject>;

// TODO: Use a URI of some sort.
/// This [`Subject`] trait is used to sign and verify JWTs.
#[async_trait]
pub trait Subject: Sign + Verify + Send + Sync {
    async fn identifier(&self, subject_syntax_type: &str) -> Result<String>;
}

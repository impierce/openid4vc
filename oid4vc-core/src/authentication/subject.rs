use crate::{Sign, Verify};
use anyhow::Result;
use std::sync::Arc;

pub type SigningSubject = Arc<dyn Subject>;

// TODO: Use a URI of some sort.
/// This [`Subject`] trait is used to sign and verify JWTs.
pub trait Subject: Sign + Verify + Send + Sync {
    fn identifier(&self, subject_syntax_type: &str) -> Result<String>;
}

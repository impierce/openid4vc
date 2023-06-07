use anyhow::{anyhow, Result};
use std::sync::Arc;

use crate::Sign;

/// This [`Subject`] trait is used to sign and verify JWTs.
pub trait Subject: Sign {
    fn did(&self) -> Result<did_url::DID>;
    fn key_identifier(&self) -> Option<String>;
}

#[derive(Default)]
pub struct Subjects(Vec<Arc<dyn Subject>>);

impl Subjects {
    pub fn select_subject(&self) -> Result<Arc<dyn Subject>> {
        self.0.get(0).cloned().ok_or_else(|| anyhow!("No subject found."))
    }

    pub fn add<S: Subject + 'static>(&mut self, subject: S) {
        self.0.push(Arc::new(subject));
    }
}

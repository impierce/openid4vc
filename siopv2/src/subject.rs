use anyhow::Result;
use std::{slice::Iter, sync::Arc};

use crate::Sign;

/// This [`Subject`] trait is used to sign and verify JWTs.
pub trait Subject: Sign {
    fn did(&self) -> Result<did_url::DID>;
    fn key_identifier(&self) -> Option<String>;
}

#[derive(Default)]
pub struct Subjects(pub Vec<Arc<dyn Subject>>);

impl Subjects {
    pub fn add<S: Subject + 'static>(&mut self, subject: S) {
        self.0.push(Arc::new(subject));
    }

    pub fn iter(&self) -> Iter<'_, Arc<dyn Subject>> {
        self.0.iter()
    }
}

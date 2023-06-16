use crate::{Collection, Subject, Verify};
use anyhow::Result;
use std::sync::Arc;

pub type Validators = Collection<Validator>;

pub enum Validator {
    Subject(Arc<dyn Subject>),
    Verifier(Arc<dyn Verify>),
}

impl Validator {
    pub async fn public_key(&self, kid: &str) -> Result<Vec<u8>> {
        match self {
            Validator::Subject(subject) => subject.public_key(kid).await,
            Validator::Verifier(verifier) => verifier.public_key(kid).await,
        }
    }
}

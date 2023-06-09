use crate::{Collection, Subject, Subjects, Verify};
use anyhow::Result;
use std::sync::Arc;

pub type Validators = Collection<Validator>;

impl From<&Subjects> for Validators {
    fn from(subjects: &Subjects) -> Self {
        Self::from(
            subjects
                .iter()
                .map(|(subject_syntax_type, subject)| {
                    (
                        subject_syntax_type.clone(),
                        Arc::new(Validator::Subject(subject.clone())),
                    )
                })
                .collect::<Vec<_>>(),
        )
    }
}

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

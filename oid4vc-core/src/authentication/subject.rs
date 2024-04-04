use crate::{Collection, Sign, SubjectSyntaxType, Verify};
use anyhow::Result;
use std::{str::FromStr, sync::Arc};

pub type SigningSubject = Arc<dyn Subject>;

// TODO: Use a URI of some sort.
/// This [`Subject`] trait is used to sign and verify JWTs.
pub trait Subject: Sign + Verify + Send + Sync {
    fn identifier(&self, did_method: &str) -> Result<String>;
    fn type_(&self) -> Result<SubjectSyntaxType> {
        SubjectSyntaxType::from_str(&self.identifier("FIX_THIS")?)
    }
}

pub type Subjects = Collection<dyn Subject>;

impl<const N: usize> TryFrom<[Arc<dyn Subject>; N]> for Subjects {
    type Error = anyhow::Error;

    fn try_from(subjects: [Arc<dyn Subject>; N]) -> Result<Self> {
        Ok(Self::from(
            subjects
                .iter()
                .map(|subject| subject.type_().map(|subject_type| (subject_type, subject.clone())))
                .collect::<Result<Vec<_>>>()?,
        ))
    }
}

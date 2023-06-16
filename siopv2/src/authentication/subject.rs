use crate::{Collection, Sign, SubjectSyntaxType, Verify};
use anyhow::Result;
use std::{str::FromStr, sync::Arc};

// TODO: Use a URI of some sort.
/// This [`Subject`] trait is used to sign and verify JWTs.
pub trait Subject: Sign + Verify {
    fn identifier(&self) -> Result<String>;
    // TODO: Remove?
    fn type_(&self) -> Result<SubjectSyntaxType> {
        SubjectSyntaxType::from_str(&self.identifier()?)
    }
}

pub type Subjects = Collection<dyn Subject>;

impl Subjects {
    pub fn get_subject(&self, subject_syntax_type: SubjectSyntaxType) -> Option<Arc<dyn Subject>> {
        self.iter()
            .find(|&subject| *subject.0 == subject_syntax_type)
            .map(|subject| subject.1.clone())
    }
}

impl<const N: usize> TryFrom<[Arc<dyn Subject>; N]> for Subjects {
    type Error = anyhow::Error;

    fn try_from(subjects: [Arc<dyn Subject>; N]) -> Result<Self> {
        Ok(Self::from(
            subjects
                .iter()
                .map(|subject| (subject.type_().unwrap(), subject.clone()))
                .collect::<Vec<_>>(),
        ))
    }
}

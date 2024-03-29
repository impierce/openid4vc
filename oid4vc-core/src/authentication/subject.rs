use crate::{Collection, Sign, SubjectSyntaxType, Verify};
use anyhow::Result;
use std::{str::FromStr, sync::Arc};

pub type SigningSubject = Arc<dyn Subject>;

// TODO: Use a URI of some sort.
/// This [`Subject`] trait is used to sign and verify JWTs.
pub trait Subject: Sign + Verify + Send + Sync {
    fn identifier(&self) -> Result<String>;
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
                .map(|subject| subject.type_().map(|subject_type| (subject_type, subject.clone())))
                .collect::<Result<Vec<_>>>()?,
        ))
    }
}

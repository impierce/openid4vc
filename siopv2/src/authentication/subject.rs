use crate::{Collection, Sign, SubjectSyntaxType, Verify};
use anyhow::Result;
use std::str::FromStr;

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

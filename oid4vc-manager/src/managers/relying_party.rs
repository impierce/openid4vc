use anyhow::{anyhow, Result};
use oid4vc_core::{authorization_request::AuthorizationRequestObject, Decoder, Subject, SubjectSyntaxType, Subjects};
use siopv2::{relying_party::ResponseItems, temp::SIOPv2, AuthorizationResponse, RelyingParty};
use std::sync::Arc;

/// Manager struct for [`siopv2::RelyingParty`].
pub struct RelyingPartyManager {
    pub relying_party: RelyingParty,
    subjects: Subjects,
}

impl RelyingPartyManager {
    pub fn new<const N: usize>(subjects: [Arc<dyn Subject>; N]) -> Result<Self> {
        Ok(Self {
            relying_party: RelyingParty::new(subjects.get(0).ok_or_else(|| anyhow!("No subjects found."))?.clone())?,
            subjects: Subjects::try_from(subjects)?,
        })
    }

    pub fn encode(&self, request: &AuthorizationRequestObject<SIOPv2>) -> Result<String> {
        self.relying_party.encode(request)
    }

    pub async fn validate_response(&self, response: &AuthorizationResponse) -> Result<ResponseItems> {
        self.relying_party
            .validate_response(response, Decoder::from(&self.subjects))
            .await
    }

    pub fn current_subject_syntax_type(&self) -> Result<SubjectSyntaxType> {
        self.relying_party.subject.type_()
    }

    pub fn set_subject_syntax_type(&mut self, subject_syntax_type: SubjectSyntaxType) -> Result<()> {
        self.relying_party.subject = self
            .subjects
            .get_subject(subject_syntax_type)
            .ok_or_else(|| anyhow::anyhow!("No subject with the given syntax type found."))?;
        Ok(())
    }
}

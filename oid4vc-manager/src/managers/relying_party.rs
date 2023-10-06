use anyhow::{anyhow, Result};
use oid4vc_core::{
    authorization_request::AuthorizationRequestObject, authorization_response::AuthorizationResponse,
    openid4vc_extension::Extension, Decoder, Subject, SubjectSyntaxType, Subjects,
};
use siopv2::RelyingParty;
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

    pub fn encode<E: Extension>(&self, request: &AuthorizationRequestObject<E>) -> Result<String> {
        self.relying_party.encode(request)
    }

    pub async fn validate_response<E: Extension>(
        &self,
        response: &AuthorizationResponse<E>,
    ) -> Result<E::ResponseItem> {
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

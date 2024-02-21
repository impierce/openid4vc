use anyhow::{anyhow, Result};
use oid4vc_core::{
    authorization_request::{AuthorizationRequest, Object},
    authorization_response::AuthorizationResponse,
    openid4vc_extension::{Extension, ResponseHandle},
    Decoder, Subject, SubjectSyntaxType, Subjects,
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

    pub fn encode<E: Extension>(&self, authorization_request: &AuthorizationRequest<Object<E>>) -> Result<String> {
        self.relying_party.encode(authorization_request)
    }

    pub async fn validate_response<E: Extension>(
        &self,
        authorization_response: &AuthorizationResponse<E>,
    ) -> Result<<E::ResponseHandle as ResponseHandle>::ResponseItem> {
        self.relying_party
            .validate_response(authorization_response, Decoder::from(&self.subjects))
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

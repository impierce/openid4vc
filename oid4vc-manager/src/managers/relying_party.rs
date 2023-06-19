use anyhow::{anyhow, Result};
use siopv2::{
    AuthorizationRequest, AuthorizationResponse, Decoder, IdToken, RelyingParty, Subject, SubjectSyntaxType, Subjects,
};
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

    pub async fn encode(&self, request: &AuthorizationRequest) -> Result<String> {
        self.relying_party.encode(request).await
    }

    pub async fn validate_response(&self, response: &AuthorizationResponse) -> Result<IdToken> {
        self.relying_party
            .validate_response(response, Decoder::from(&self.subjects))
            .await
    }

    pub fn set_signer_subject(&mut self, subject_syntax_type: SubjectSyntaxType) -> Result<()> {
        self.relying_party.subject = self
            .subjects
            .get_subject(subject_syntax_type)
            .ok_or_else(|| anyhow::anyhow!("No subject with the given syntax type found."))?;
        Ok(())
    }
}

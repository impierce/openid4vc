use anyhow::Result;
use oid4vc_core::{
    authorization_request::{AuthorizationRequest, AuthorizationRequestObject},
    authorization_response::AuthorizationResponse,
    openid4vc_extension::Extension,
    Decoder, Subject, SubjectSyntaxType, Subjects,
};
use reqwest::StatusCode;
use siopv2::{siopv2::SIOPv2, Provider};
use std::sync::Arc;

/// Manager struct for [`siopv2::Provider`].
pub struct ProviderManager {
    pub provider: Provider,
    subjects: Subjects,
}

impl ProviderManager {
    pub fn new<const N: usize>(subjects: [Arc<dyn Subject>; N]) -> Result<Self> {
        Ok(Self {
            provider: Provider::new(subjects[0].clone())?,
            subjects: Subjects::try_from(subjects)?,
        })
    }

    pub async fn validate_request<E: Extension>(
        &self,
        authorization_request: AuthorizationRequest,
    ) -> Result<AuthorizationRequestObject<E>> {
        self.provider
            .validate_request(authorization_request, Decoder::from(&self.subjects))
            .await
    }

    pub fn generate_response<E: Extension>(
        &self,
        authorization_request: &AuthorizationRequestObject<E>,
        user_claims: E::AuthorizationResponseInput,
    ) -> Result<AuthorizationResponse<E>> {
        self.provider.generate_response(authorization_request, user_claims)
    }

    pub async fn send_response<E: Extension>(
        &self,
        authorization_response: &AuthorizationResponse<E>,
    ) -> Result<StatusCode> {
        self.provider.send_response(authorization_response).await
    }

    pub fn current_subject_syntax_type(&self) -> Result<SubjectSyntaxType> {
        self.provider.subject.type_()
    }

    pub fn set_subject_syntax_type(&mut self, subject_syntax_type: SubjectSyntaxType) -> Result<()> {
        self.provider.subject = self
            .subjects
            .get_subject(subject_syntax_type)
            .ok_or_else(|| anyhow::anyhow!("No subject with the given syntax type found."))?;
        Ok(())
    }

    pub fn subject_syntax_types_supported(&self) -> Vec<SubjectSyntaxType> {
        self.subjects.iter().map(|subject| subject.0.to_owned()).collect()
    }

    pub fn matching_subject_syntax_types(
        &self,
        authorization_request: &AuthorizationRequestObject<SIOPv2>,
    ) -> Option<Vec<SubjectSyntaxType>> {
        let supported_types =
            authorization_request
                .extension
                .subject_syntax_types_supported()
                .map_or(Vec::new(), |types| {
                    types
                        .iter()
                        .filter(|sst| self.subject_syntax_types_supported().contains(sst))
                        .collect()
                });
        (!supported_types.is_empty()).then_some(supported_types.iter().map(|&sst| sst.clone()).collect())
    }
}

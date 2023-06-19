use anyhow::Result;
use siopv2::{
    AuthorizationRequest, AuthorizationResponse, Decoder, Provider, RequestUrl, StandardClaimsValues, Subject,
    SubjectSyntaxType, Subjects,
};
use std::sync::Arc;

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

    pub async fn validate_request(&self, request: RequestUrl) -> Result<AuthorizationRequest> {
        self.provider
            .validate_request(request, Decoder::from(&self.subjects))
            .await
    }

    pub async fn generate_response(
        &self,
        request: AuthorizationRequest,
        user_claims: StandardClaimsValues,
    ) -> Result<AuthorizationResponse> {
        self.provider.generate_response(request, user_claims).await
    }

    pub async fn send_response(&self, response: AuthorizationResponse) -> Result<()> {
        self.provider.send_response(response).await
    }

    pub fn set_signer_subject(&mut self, subject_syntax_type: SubjectSyntaxType) -> Result<()> {
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
        authorization_request: &AuthorizationRequest,
    ) -> Option<Vec<SubjectSyntaxType>> {
        let supported_types = authorization_request
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

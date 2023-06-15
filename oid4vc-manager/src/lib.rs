pub mod methods;

use anyhow::Result;
use siopv2::{AuthorizationRequest, Provider, RequestUrl, SubjectSyntaxType};

pub struct ProviderManager {
    provider: Provider,
}

impl ProviderManager {
    pub fn new(provider: Provider) -> Self {
        Self { provider }
    }

    pub async fn validate_request(&self, request: RequestUrl) -> Result<AuthorizationRequest> {
        self.provider.validate_request(request).await
    }

    pub fn set_signer_subject(&mut self, subject_syntax_type: SubjectSyntaxType) -> Result<()> {
        let signer_subject = self
            .provider
            .subjects
            .iter()
            .find(|&subject| subject.0 == &subject_syntax_type)
            .ok_or_else(|| anyhow::anyhow!("No subject with the given syntax type found."))?;
        self.provider.signer_subject = signer_subject.1.clone();
        Ok(())
    }

    pub fn subject_syntax_types_supported(&self) -> Vec<SubjectSyntaxType> {
        self.provider
            .subjects
            .iter()
            .map(|subject| subject.0.to_owned())
            .collect()
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

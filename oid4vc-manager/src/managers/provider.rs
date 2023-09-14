use anyhow::Result;
use oid4vc_core::{
    authorization_request::{AuthorizationRequest, AuthorizationRequestObject},
    authorization_response::AuthorizationResponse,
    Decoder, Extension, Subject, SubjectSyntaxType, Subjects,
};
use oid4vp::OID4VP;
use reqwest::StatusCode;
use siopv2::{Provider, SIOPv2};
use std::sync::Arc;

/// Manager struct for [`siopv2::Provider`].
pub struct ProviderManager {
    pub provider: Provider,
    subjects: Subjects,
}

pub enum AuthorizationRequestEnum {
    SIOPv2(AuthorizationRequest<SIOPv2>),
    OID4VP(AuthorizationRequest<OID4VP>),
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
        request: AuthorizationRequest,
    ) -> Result<AuthorizationRequestObject<E>> {
        self.provider
            .validate_request(request, Decoder::from(&self.subjects))
            .await
    }

    pub fn generate_response<E: Extension>(
        &self,
        request: &AuthorizationRequestObject<E>,
        user_claims: E::UserClaims,
    ) -> Result<AuthorizationResponse<E>> {
        self.provider.generate_response(request, user_claims)
    }

    pub async fn send_response<E: Extension>(&self, response: &AuthorizationResponse<E>) -> Result<StatusCode> {
        self.provider.send_response(response).await
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::methods::{iota_method::IotaSubject, key_method::KeySubject};
    use std::str::FromStr;

    #[tokio::test]
    async fn test_multiple_methods() {
        let key_subject = Arc::new(KeySubject::new());
        let iota_subject = Arc::new(IotaSubject::new().await.unwrap());

        // The first subject in the array is the default subject.
        let mut provider_manager = ProviderManager::new([key_subject, iota_subject]).unwrap();
        assert_eq!(
            provider_manager.current_subject_syntax_type().unwrap(),
            SubjectSyntaxType::from_str("did:key").unwrap()
        );

        // Set the subject syntax type to `did:iota`.
        provider_manager
            .set_subject_syntax_type(SubjectSyntaxType::from_str("did:iota").unwrap())
            .unwrap();
        assert_eq!(
            provider_manager.current_subject_syntax_type().unwrap(),
            SubjectSyntaxType::from_str("did:iota").unwrap()
        );
    }
}

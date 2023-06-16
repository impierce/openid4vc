pub mod methods;

use anyhow::Result;
use siopv2::{
    provider::Decoder, AuthorizationRequest, AuthorizationResponse, IdToken, Provider, RelyingParty, RequestUrl,
    Subject, SubjectSyntaxType, Subjects, Validator, Validators,
};
use std::sync::Arc;

pub struct RelyingPartyManager {
    pub relying_party: RelyingParty,
    subjects: Subjects,
}

impl RelyingPartyManager {
    pub fn new<const N: usize>(subjects: [Arc<dyn Subject>; N]) -> Self {
        Self {
            relying_party: RelyingParty::new(subjects[0].clone()).unwrap(),
            subjects: Subjects::from(
                subjects
                    .iter()
                    .map(|subject| (subject.type_().unwrap(), subject.clone()))
                    .collect::<Vec<_>>(),
            ),
        }
    }

    pub async fn validate_response(&self, response: &AuthorizationResponse) -> Result<IdToken> {
        self.relying_party
            .validate_response(
                response,
                &Decoder {
                    subjects: Validators::from(
                        self.subjects
                            .iter()
                            .map(|(sst, subject)| (sst.clone(), Arc::new(Validator::Subject(subject.clone()))))
                            .collect::<Vec<_>>(),
                    ),
                },
            )
            .await
    }

    // TODO: fix ugly code
    pub fn set_signer_subject(&mut self, subject_syntax_type: SubjectSyntaxType) -> Result<()> {
        let subject = self
            .subjects
            .iter()
            .find(|&subject| subject.0 == &subject_syntax_type)
            .ok_or_else(|| anyhow::anyhow!("No subject with the given syntax type found."))?;
        self.relying_party.subject = subject.1.clone();
        Ok(())
    }
}

pub struct ProviderManager {
    pub provider: Provider,
    subjects: Subjects,
}

impl ProviderManager {
    pub fn new<const N: usize>(subjects: [Arc<dyn Subject>; N]) -> Self {
        Self {
            provider: Provider::new(subjects[0].clone()).unwrap(),
            subjects: Subjects::from(
                subjects
                    .iter()
                    .map(|subject| (subject.type_().unwrap(), subject.clone()))
                    .collect::<Vec<_>>(),
            ),
        }
    }

    pub async fn validate_request(&self, request: RequestUrl) -> Result<AuthorizationRequest> {
        self.provider
            .validate_request(
                request,
                &Decoder {
                    subjects: Validators::from(
                        self.subjects
                            .iter()
                            .map(|(sst, subject)| (sst.clone(), Arc::new(Validator::Subject(subject.clone()))))
                            .collect::<Vec<_>>(),
                    ),
                },
            )
            .await
    }

    // TODO: fix ugly code
    pub fn set_signer_subject(&mut self, subject_syntax_type: SubjectSyntaxType) -> Result<()> {
        let subject = self
            .subjects
            .iter()
            .find(|&subject| subject.0 == &subject_syntax_type)
            .ok_or_else(|| anyhow::anyhow!("No subject with the given syntax type found."))?;
        self.provider.subject = subject.1.clone();
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

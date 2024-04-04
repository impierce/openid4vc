use anyhow::Result;
use oid4vc_core::{
    authorization_request::{AuthorizationRequest, Object},
    authorization_response::AuthorizationResponse,
    openid4vc_extension::{Extension, OpenID4VC, ResponseHandle},
    Subject, SubjectSyntaxType,
};
use reqwest::StatusCode;
use siopv2::Provider;
use std::sync::Arc;

/// Manager struct for [`siopv2::Provider`].
pub struct ProviderManager {
    pub provider: Provider,
}

impl ProviderManager {
    pub fn new<const N: usize>(subjects: [Arc<dyn Subject>; N], default_did_method: String) -> Result<Self> {
        Ok(Self {
            provider: Provider::new(subjects[0].clone(), default_did_method)?,
        })
    }

    pub async fn validate_request(&self, authorization_request: String) -> Result<AuthorizationRequest<Object>> {
        self.provider.validate_request(authorization_request).await
    }

    pub fn generate_response<E: Extension + OpenID4VC>(
        &self,
        authorization_request: &AuthorizationRequest<Object<E>>,
        input: <E::ResponseHandle as ResponseHandle>::Input,
    ) -> Result<AuthorizationResponse<E>> {
        self.provider.generate_response(authorization_request, input)
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
}

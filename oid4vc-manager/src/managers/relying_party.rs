use anyhow::Result;
use oid4vc_core::{
    authorization_request::{AuthorizationRequest, Object},
    authorization_response::AuthorizationResponse,
    openid4vc_extension::{Extension, ResponseHandle},
    Subject,
};
use siopv2::RelyingParty;
use std::sync::Arc;

/// Manager struct for [`siopv2::RelyingParty`].
pub struct RelyingPartyManager {
    pub relying_party: RelyingParty,
}

impl RelyingPartyManager {
    pub fn new(subject: Arc<dyn Subject>, subject_syntax_type: String) -> Result<Self> {
        Ok(Self {
            relying_party: RelyingParty::new(subject, subject_syntax_type)?,
        })
    }

    pub fn encode<E: Extension>(&self, authorization_request: &AuthorizationRequest<Object<E>>) -> Result<String> {
        self.relying_party.encode(authorization_request)
    }

    pub async fn validate_response<E: Extension>(
        &self,
        authorization_response: &AuthorizationResponse<E>,
    ) -> Result<<E::ResponseHandle as ResponseHandle>::ResponseItem> {
        self.relying_party.validate_response(authorization_response).await
    }
}

use anyhow::Result;
use jsonwebtoken::Algorithm;
use oid4vc_core::{
    authorization_request::{AuthorizationRequest, Object},
    authorization_response::AuthorizationResponse,
    openid4vc_extension::{Extension, ResponseHandle},
    Subject, SubjectSyntaxType,
};
use siopv2::RelyingParty;
use std::sync::Arc;

/// Manager struct for [`siopv2::RelyingParty`].
pub struct RelyingPartyManager {
    pub relying_party: RelyingParty,
    // TODO: this should be replaced with `client_metadata`
    pub supported_signing_algorithms: Vec<Algorithm>,
}

impl RelyingPartyManager {
    pub fn new(
        subject: Arc<dyn Subject>,
        default_subject_syntax_type: impl TryInto<SubjectSyntaxType>,
        supported_signing_algorithms: Vec<Algorithm>,
    ) -> Result<Self> {
        Ok(Self {
            relying_party: RelyingParty::new(subject, default_subject_syntax_type)?,
            supported_signing_algorithms,
        })
    }

    pub async fn encode<E: Extension>(
        &self,
        authorization_request: &AuthorizationRequest<Object<E>>,
    ) -> Result<String> {
        tracing::debug!("RelyingPartyManager: encoding authorization request");
        self.relying_party
            .encode(
                authorization_request,
                *self
                    .supported_signing_algorithms
                    .first()
                    .ok_or(anyhow::anyhow!("No supported signing algorithms"))?,
            )
            .await
    }

    #[deprecated(
        note = "This function is only used for validating `SIOPv2` Authorization Responses. For validating `OID4VP` Authorization Responses use the `VpTokenValidator` instead."
    )]
    pub async fn validate_response<E: Extension>(
        &self,
        authorization_response: &AuthorizationResponse<E>,
    ) -> Result<<E::ResponseHandle as ResponseHandle>::ResponseItem> {
        tracing::debug!("RelyingPartyManager: validating authorization response");
        #[allow(deprecated)]
        self.relying_party.validate_response(authorization_response).await
    }

    pub fn default_subject_syntax_type(&self) -> &SubjectSyntaxType {
        &self.relying_party.default_subject_syntax_type
    }
}

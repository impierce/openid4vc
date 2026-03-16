use super::verifiable_presentation_jwt_builder::VerifiablePresentationJwtBuilder;
use getset::Getters;
use identity_credential::presentation::Presentation;
use oid4vc_core::RFC7519Claims;
use serde::Serialize;
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Serialize, Clone, Debug, Getters, PartialEq)]
pub struct VerifiablePresentationJwt<CRED> {
    #[serde(flatten)]
    #[getset(get = "pub")]
    pub(super) rfc7519_claims: RFC7519Claims,
    #[serde(rename = "vp")]
    #[getset(get = "pub")]
    pub(super) verifiable_presentation: Presentation<CRED>,
    #[getset(get = "pub")]
    pub(super) nonce: Option<String>,
}

impl<CRED> VerifiablePresentationJwt<CRED> {
    pub fn builder() -> VerifiablePresentationJwtBuilder<CRED> {
        VerifiablePresentationJwtBuilder::new()
    }
}

use super::verifiable_presentation_jwt_builder::VerifiablePresentationJwtBuilder;
use getset::Getters;
use identity_credential::{credential::Jwt, presentation::Presentation};
use oid4vc_core::RFC7519Claims;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Serialize, Clone, Deserialize, Debug, Getters, PartialEq)]
pub struct VerifiablePresentationJwt {
    #[serde(flatten)]
    #[getset(get = "pub")]
    pub(super) rfc7519_claims: RFC7519Claims,
    #[serde(rename = "vp")]
    #[getset(get = "pub")]
    pub(super) verifiable_presentation: Presentation<Jwt>,
    #[getset(get = "pub")]
    pub(super) nonce: Option<String>,
}

impl VerifiablePresentationJwt {
    pub fn builder() -> VerifiablePresentationJwtBuilder {
        VerifiablePresentationJwtBuilder::new()
    }
}

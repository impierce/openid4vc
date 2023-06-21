// TODO: Move this to the OID4vp crate
use getset::Getters;
use identity_credential::presentation::JwtPresentation;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use super::{id_token::RFC7519Claims, vp_token_builder::VpTokenBuilder};

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Getters, PartialEq)]
pub struct VpToken {
    #[serde(flatten)]
    #[getset(get = "pub")]
    pub(super) rfc7519_claims: RFC7519Claims,
    #[serde(rename = "vp")]
    pub(super) verifiable_presentation: JwtPresentation,
    pub(super) nonce: Option<String>,
}

impl VpToken {
    pub fn builder() -> VpTokenBuilder {
        VpTokenBuilder::new()
    }
}

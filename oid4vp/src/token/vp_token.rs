use super::vp_token_builder::{DcqlVpTokenBuilder, VpTokenBuilder};
use crate::dcql::dcql_query::CredentialId;
use getset::Getters;
use identity_credential::{credential::Jwt, presentation::Presentation};
use oid4vc_core::RFC7519Claims;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::collections::HashMap;
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Getters, PartialEq)]
pub struct VpToken {
    #[serde(flatten)]
    #[getset(get = "pub")]
    pub(super) rfc7519_claims: RFC7519Claims,
    #[serde(rename = "vp")]
    #[getset(get = "pub")]
    pub(super) verifiable_presentation: Presentation<Jwt>,
    pub(super) nonce: Option<String>,
}

impl VpToken {
    pub fn builder() -> VpTokenBuilder {
        VpTokenBuilder::new()
    }
}
#[derive(Serialize, Deserialize, Debug, Getters, PartialEq)]
pub struct DcqlQueryVpToken {
    #[serde(flatten)]
    #[getset(get = "pub")]
    pub(super) presentations: HashMap<CredentialId, Vec<PresentationFormat>>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(untagged)]
pub enum PresentationFormat {
    Jwt(Presentation<Jwt>),
    Json(serde_json::Value),
    Binary(String),
}

impl DcqlQueryVpToken {
    pub fn new() -> Self {
        Self {
            presentations: HashMap::new(),
        }
    }

    pub fn builder() -> DcqlVpTokenBuilder {
        DcqlVpTokenBuilder::new()
    }
}

use super::vp_token_builder::VpTokenBuilder;
use crate::dcql::dcql_query::CredentialQueryId;
use getset::Getters;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Clone, Deserialize, Debug, Getters, PartialEq)]
pub struct VpToken {
    #[serde(flatten)]
    #[getset(get = "pub")]
    pub(super) presentations: HashMap<CredentialQueryId, Vec<PresentationFormat>>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(untagged)]
pub enum PresentationFormat {
    LdpVc,
    JwtVcJson(String),
    DcSdJwt(String),
    MsoMdoc(Vec<u8>),
}

pub fn builder() -> VpTokenBuilder {
    VpTokenBuilder::new()
}

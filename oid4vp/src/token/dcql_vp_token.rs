use super::dcql_vp_token_builder::DcqlVpTokenBuilder;
use crate::dcql::dcql_query::CredentialId;
use getset::Getters;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Clone, Deserialize, Debug, Getters, PartialEq)]
pub struct DcqlQueryVpToken {
    #[serde(flatten)]
    #[getset(get = "pub")]
    pub(super) presentations: HashMap<CredentialId, Vec<PresentationFormat>>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(untagged)]
pub enum PresentationFormat {
    LdpVc,
    JwtVcJson(String),
    DcSdJwt,
    MsoMdoc,
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

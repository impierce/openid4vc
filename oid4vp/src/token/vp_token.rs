use super::vp_token_builder::VpTokenBuilder;
use crate::dcql::dcql_query::CredentialQueryId;
use getset::Getters;
use nutype::nutype;
use oid4vc_core::types::string_or_object::StringOrObject;
use oid4vc_core::utils::predicates::not_empty;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Clone, Deserialize, Debug, Getters, PartialEq)]
pub struct VpToken {
    #[serde(flatten)]
    #[getset(get = "pub")]
    pub(super) presentations: HashMap<CredentialQueryId, Presentations>,
}

impl VpToken {
    pub fn builder() -> VpTokenBuilder {
        VpTokenBuilder::new()
    }
}

#[nutype(
    validate(predicate = not_empty),
    derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Deref)
)]
pub struct Presentations(Vec<StringOrObject>);

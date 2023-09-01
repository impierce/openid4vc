pub mod claims;
pub mod client_metadata;
pub mod provider;
pub mod relying_party;
// pub mod request;
pub mod authorization_request;
pub mod response;
pub mod scope;
pub mod token;

use authorization_request::{SIOPv2AuthorizationRequestBuilder, SIOPv2AuthorizationRequestParameters};
pub use claims::{ClaimRequests, StandardClaimsRequests, StandardClaimsValues};
pub use client_metadata::ClientMetadata;
use oid4vc_core::{authorization_request::Extension, serialize_unit_struct};
pub use provider::Provider;
pub use relying_party::RelyingParty;
// pub use request::{request_builder::RequestUrlBuilder, AuthorizationRequest, RequestUrl};
pub use response::AuthorizationResponse;
pub use scope::Scope;
pub use token::id_token_builder::IdTokenBuilder;

use serde::{Deserialize, Deserializer, Serialize};

#[cfg(test)]
pub mod test_utils;

#[derive(Debug, PartialEq, Default)]
pub struct IdToken;
serialize_unit_struct!("id_token", IdToken);

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct SIOPv2;
impl Extension for SIOPv2 {
    type ResponseType = IdToken;
    type AuthorizationRequest = SIOPv2AuthorizationRequestParameters;
    type AuthorizationRequestBuilder = SIOPv2AuthorizationRequestBuilder;
}

// When a struct has fields of type `Option<serde_json::Map<String, serde_json::Value>>`, by default these fields are deserialized as
// `Some(Object {})` instead of None when the corresponding values are missing.
// The `parse_other()` helper function ensures that these fields are deserialized as `None` when no value is present.
pub fn parse_other<'de, D>(deserializer: D) -> Result<Option<serde_json::Map<String, serde_json::Value>>, D::Error>
where
    D: Deserializer<'de>,
{
    serde_json::Value::deserialize(deserializer).map(|value| match value {
        serde_json::Value::Object(object) if !object.is_empty() => Some(object),
        _ => None,
    })
}

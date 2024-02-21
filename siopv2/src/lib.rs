pub mod claims;
pub mod client_metadata;
pub mod provider;
pub mod relying_party;
pub mod request;
pub mod response;
pub mod scope;
pub mod token;

pub use claims::{ClaimRequests, StandardClaimsRequests, StandardClaimsValues};
pub use client_metadata::ClientMetadata;
pub use provider::Provider;
pub use relying_party::RelyingParty;
pub use request::{request_builder::RequestUrlBuilder, AuthorizationRequest, RequestUrl};
pub use response::AuthorizationResponse;
pub use scope::Scope;
pub use token::{id_token::IdToken, id_token_builder::IdTokenBuilder};

use oid4vc_core::JsonObject;
use serde::{Deserialize, Deserializer};

// When a struct has fields of type `Option<JsonObject>`, by default these fields are deserialized as
// `Some(Object {})` instead of None when the corresponding values are missing.
// The `parse_other()` helper function ensures that these fields are deserialized as `None` when no value is present.
pub fn parse_other<'de, D>(deserializer: D) -> Result<Option<JsonObject>, D::Error>
where
    D: Deserializer<'de>,
{
    serde_json::Value::deserialize(deserializer).map(|value| match value {
        serde_json::Value::Object(object) if !object.is_empty() => Some(object),
        _ => None,
    })
}

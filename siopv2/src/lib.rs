pub mod authorization_request;
pub mod claims;
pub mod provider;
pub mod relying_party;
pub mod siopv2;
pub mod token;

pub use claims::{ClaimRequests, StandardClaimsRequests, StandardClaimsValues};
use oid4vc_core::{authorization_response::AuthorizationResponse, JsonObject, JsonValue};
pub use provider::Provider;
pub use relying_party::RelyingParty;
use serde::{Deserialize, Deserializer};
pub use token::id_token_builder::IdTokenBuilder;

#[cfg(test)]
pub mod test_utils;

// When a struct has fields of type `Option<JsonObject>`, by default these fields are deserialized as
// `Some(Object {})` instead of None when the corresponding values are missing.
// The `parse_other()` helper function ensures that these fields are deserialized as `None` when no value is present.
pub fn parse_other<'de, D>(deserializer: D) -> Result<Option<JsonObject>, D::Error>
where
    D: Deserializer<'de>,
{
    JsonValue::deserialize(deserializer).map(|value| match value {
        JsonValue::Object(object) if !object.is_empty() => Some(object),
        _ => None,
    })
}

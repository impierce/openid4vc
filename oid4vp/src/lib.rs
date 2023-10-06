pub mod authorization_request;
pub mod oid4vp_params;
pub mod openid4vc_extension;
pub mod token;

pub use dif_presentation_exchange::{
    evaluate_input, ClaimFormatDesignation, InputDescriptor, InputDescriptorMappingObject, PathNested,
    PresentationDefinition, PresentationSubmission,
};
use oid4vc_core::{JsonObject, JsonValue};
pub use oid4vp_params::Oid4vpParams;
use serde::{Deserialize, Deserializer};

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

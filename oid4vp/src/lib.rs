pub mod authorization_request;
pub mod oid4vp;
pub mod oid4vp_params;
pub mod token;

pub use dif_presentation_exchange::{
    evaluate_input, ClaimFormatDesignation, InputDescriptor, InputDescriptorMappingObject, PathNested,
    PresentationDefinition, PresentationSubmission,
};
use oid4vc_core::JsonObject;
pub use oid4vp_params::Oid4vpParams;
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

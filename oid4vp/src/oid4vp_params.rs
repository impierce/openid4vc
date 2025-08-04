use crate::VpToken;
use serde::{Deserialize, Serialize};

/// Represents the parameters of an OpenID4VP response. It can hold a Verifiable Presentation Token and a Presentation
/// Submission, or a JWT containing them.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(untagged)]
pub enum Oid4vpParams {
    Jwt { response: String },
    Params { vp_token: VpToken },
}

/// Custom serializer and deserializer for [`Oid4vpParams`].
pub mod serde_oid4vp_response {
    use super::*;
    use serde::{de, ser::SerializeMap};

    pub fn serialize<S>(oid4vp_response: &Oid4vpParams, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match oid4vp_response {
            Oid4vpParams::Jwt { response } => response.serialize(serializer),
            Oid4vpParams::Params { vp_token } => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("vp_token", vp_token)?;
                map.end()
            }
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Oid4vpParams, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let oid4vp_response = serde_json::Value::deserialize(deserializer)?;
        match oid4vp_response {
            serde_json::Value::String(response) => Ok(Oid4vpParams::Jwt { response }),
            serde_json::Value::Object(map) => {
                let vp_token = map.get("vp_token").ok_or_else(|| {
                    de::Error::custom(
                        "`vp_token` parameter is required when using `presentation_submission` parameter.",
                    )
                })?;
                Ok(Oid4vpParams::Params {
                    vp_token: serde_json::from_value(vp_token.clone()).map_err(de::Error::custom)?,
                })
            }
            _ => Err(de::Error::custom("Invalid `oid4vp_response` parameter.")),
        }
    }
}

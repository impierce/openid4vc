use dif_presentation_exchange::PresentationSubmission;
use serde::{Deserialize, Serialize};

/// Represents the parameters of an OpenID4VP response. It can hold a Verifiable Presentation Token and a Presentation
/// Submission, or a JWT containing them.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(untagged)]
pub enum Oid4vpParams {
    Jwt {
        response: String,
    },
    Params {
        vp_token: String,
        presentation_submission: PresentationSubmission,
    },
}

/// Custom serializer and deserializer for [`Oid4vpParams`].
pub mod serde_oid4vp_response {
    use super::*;
    use oid4vc_core::JsonValue;
    use serde::{
        de,
        ser::{self, SerializeMap},
    };

    pub fn serialize<S>(oid4vp_response: &Oid4vpParams, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match oid4vp_response {
            Oid4vpParams::Jwt { response } => response.serialize(serializer),
            Oid4vpParams::Params {
                vp_token,
                presentation_submission,
            } => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("vp_token", vp_token)?;
                map.serialize_entry(
                    "presentation_submission",
                    &serde_json::to_string(&presentation_submission).map_err(ser::Error::custom)?,
                )?;
                map.end()
            }
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Oid4vpParams, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let oid4vp_response = JsonValue::deserialize(deserializer)?;
        match oid4vp_response {
            JsonValue::String(response) => Ok(Oid4vpParams::Jwt { response }),
            JsonValue::Object(map) => {
                let vp_token = map.get("vp_token").ok_or_else(|| {
                    de::Error::custom(
                        "`vp_token` parameter is required when using `presentation_submission` parameter.",
                    )
                })?;
                let presentation_submission = map.get("presentation_submission").ok_or_else(|| {
                    de::Error::custom(
                        "`presentation_submission` parameter is required when using `vp_token` parameter.",
                    )
                })?;
                let presentation_submission = presentation_submission
                    .as_str()
                    .ok_or_else(|| de::Error::custom("`presentation_submission` parameter must be a string."))?;
                Ok(Oid4vpParams::Params {
                    vp_token: serde_json::from_value(vp_token.clone()).map_err(de::Error::custom)?,
                    presentation_submission: serde_json::from_str(presentation_submission)
                        .map_err(de::Error::custom)?,
                })
            }
            _ => Err(de::Error::custom("Invalid `oid4vp_response` parameter.")),
        }
    }
}

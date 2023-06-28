use anyhow::{anyhow, Result};
use getset::Getters;
use oid4vc_core::builder_fn;
use oid4vp::{Oid4vpParams, PresentationSubmission};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// Represents an Authorization AuthorizationResponse. It can hold an ID Token, a Verifiable Presentation Token, a Presentation
/// Submission, or a combination of them.
#[skip_serializing_none]
#[derive(Serialize, Default, Deserialize, Debug, Getters, PartialEq)]
pub struct AuthorizationResponse {
    #[serde(skip)]
    #[getset(get = "pub")]
    redirect_uri: String,
    #[getset(get = "pub")]
    id_token: Option<String>,
    #[serde(flatten, with = "serde_oid4vp_response")]
    #[getset(get = "pub")]
    oid4vp_response: Option<Oid4vpParams>,
    state: Option<String>,
}

pub mod serde_oid4vp_response {
    use super::*;
    use serde::{
        de,
        ser::{self, SerializeMap},
    };
    use serde_json::Value;

    pub fn serialize<S>(oid4vp_response: &Option<Oid4vpParams>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match oid4vp_response {
            Some(Oid4vpParams::Jwt { response }) => response.serialize(serializer),
            Some(Oid4vpParams::Params {
                vp_token,
                presentation_submission,
            }) => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("vp_token", vp_token)?;
                map.serialize_entry(
                    "presentation_submission",
                    &serde_json::to_string(&presentation_submission).map_err(ser::Error::custom)?,
                )?;
                map.end()
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Oid4vpParams>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let oid4vp_response = Option::<serde_json::Value>::deserialize(deserializer)?;
        match oid4vp_response {
            None => Ok(None),
            Some(Value::Object(map)) if map.is_empty() => Ok(None),
            Some(Value::String(response)) => Ok(Some(Oid4vpParams::Jwt { response })),
            Some(Value::Object(map)) => {
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
                Ok(Some(Oid4vpParams::Params {
                    vp_token: serde_json::from_value(vp_token.clone()).map_err(de::Error::custom)?,
                    presentation_submission: serde_json::from_str(presentation_submission)
                        .map_err(de::Error::custom)?,
                }))
            }
            _ => Err(de::Error::custom("Invalid `oid4vp_response` parameter.")),
        }
    }
}

impl AuthorizationResponse {
    pub fn builder() -> ResponseBuilder {
        ResponseBuilder::new()
    }
}

#[derive(Default)]
pub struct ResponseBuilder {
    redirect_uri: Option<String>,
    id_token: Option<String>,
    vp_token: Option<String>,
    presentation_submission: Option<PresentationSubmission>,
    oid4vp_response_jwt: Option<String>,
    state: Option<String>,
}

impl ResponseBuilder {
    pub fn new() -> Self {
        ResponseBuilder::default()
    }

    pub fn build(&mut self) -> Result<AuthorizationResponse> {
        let redirect_uri = self
            .redirect_uri
            .take()
            .ok_or(anyhow!("redirect_uri parameter is required."))?;

        let oid4vp_response = match (
            self.vp_token.take(),
            self.presentation_submission.take(),
            self.oid4vp_response_jwt.take(),
        ) {
            (Some(vp_token), Some(presentation_submission), None) => Ok(Some(Oid4vpParams::Params {
                vp_token,
                presentation_submission,
            })),
            (None, None, Some(response)) => Ok(Some(Oid4vpParams::Jwt { response })),
            (None, None, None) => Ok(None),
            (Some(_), None, None) => Err(anyhow!(
                "`presentation_submission` parameter is required when using `vp_token` parameter."
            )),
            (None, Some(_), None) => Err(anyhow!(
                "`vp_token` parameter is required when using `presentation_submission` parameter."
            )),
            _ => Err(anyhow!(
                "`response` parameter can not be used with `vp_token` and `presentation_submission` parameters."
            )),
        }?;

        Ok(AuthorizationResponse {
            redirect_uri,
            id_token: self.id_token.take(),
            oid4vp_response,
            state: self.state.take(),
        })
    }

    builder_fn!(redirect_uri, String);
    builder_fn!(id_token, String);
    builder_fn!(vp_token, String);
    builder_fn!(presentation_submission, PresentationSubmission);
    builder_fn!(oid4vp_response_jwt, String);
    builder_fn!(state, String);
}

#[cfg(test)]
mod tests {
    use super::*;
    use oid4vp::{InputDescriptorMappingObject, PathNested};

    #[tokio::test]
    async fn test_authorization_response_url_formencoded() {
        let authorization_response = AuthorizationResponse::builder()
            .redirect_uri("".to_string())
            .id_token("id_token".to_string())
            .vp_token("vp_token".to_string())
            .presentation_submission(PresentationSubmission {
                id: "id".to_string(),
                definition_id: "definition_id".to_string(),
                descriptor_map: vec![InputDescriptorMappingObject {
                    id: "id".to_string(),
                    path: "path".to_string(),
                    format: oid4vp::ClaimFormatDesignation::AcVc,
                    path_nested: Some(PathNested {
                        id: Some("id".to_string()),
                        format: oid4vp::ClaimFormatDesignation::AcVc,
                        path: "path".to_string(),
                        path_nested: None,
                    }),
                }],
            })
            .build()
            .unwrap();

        let encoded = serde_urlencoded::to_string(&authorization_response).unwrap();

        assert_eq!(authorization_response, serde_urlencoded::from_str(&encoded).unwrap());
    }

    #[test]
    fn test_valid_response() {
        assert!(AuthorizationResponse::builder()
            .redirect_uri("redirect".to_string())
            .id_token("id_token".to_string())
            .build()
            .is_ok());

        assert!(AuthorizationResponse::builder()
            .redirect_uri("redirect".to_string())
            .vp_token("vp_token".to_string())
            .presentation_submission(PresentationSubmission {
                id: "id".to_string(),
                definition_id: "definition_id".to_string(),
                descriptor_map: vec![],
            })
            .build()
            .is_ok());

        assert!(AuthorizationResponse::builder()
            .redirect_uri("redirect".to_string())
            .id_token("id_token".to_string())
            .vp_token("vp_token".to_string())
            .presentation_submission(PresentationSubmission {
                id: "id".to_string(),
                definition_id: "definition_id".to_string(),
                descriptor_map: vec![],
            })
            .build()
            .is_ok());
    }

    #[test]
    fn test_invalid_response() {
        assert_eq!(
            AuthorizationResponse::builder()
                .id_token("id_token".to_string())
                .build()
                .unwrap_err()
                .to_string(),
            "redirect_uri parameter is required."
        );

        assert_eq!(
            AuthorizationResponse::builder()
                .redirect_uri("redirect".to_string())
                .vp_token("vp_token".to_string())
                .build()
                .unwrap_err()
                .to_string(),
            "`presentation_submission` parameter is required when using `vp_token` parameter."
        );

        assert_eq!(
            AuthorizationResponse::builder()
                .redirect_uri("redirect".to_string())
                .presentation_submission(PresentationSubmission {
                    id: "id".to_string(),
                    definition_id: "definition_id".to_string(),
                    descriptor_map: vec![],
                })
                .build()
                .unwrap_err()
                .to_string(),
            "`vp_token` parameter is required when using `presentation_submission` parameter."
        );

        assert_eq!(
            AuthorizationResponse::builder()
                .redirect_uri("redirect".to_string())
                .presentation_submission(PresentationSubmission {
                    id: "id".to_string(),
                    definition_id: "definition_id".to_string(),
                    descriptor_map: vec![],
                })
                .oid4vp_response_jwt("response".to_string())
                .build()
                .unwrap_err()
                .to_string(),
            "`response` parameter can not be used with `vp_token` and `presentation_submission` parameters."
        );
    }
}

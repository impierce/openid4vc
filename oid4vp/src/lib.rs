pub mod authorization_request;
pub mod oid4vp_params;
pub mod token;

use authorization_request::{OID4VPAuthorizationRequestBuilder, OID4VPAuthorizationRequestParameters};
use chrono::{Duration, Utc};
pub use dif_presentation_exchange::{
    evaluate_input, ClaimFormatDesignation, InputDescriptor, InputDescriptorMappingObject, PathNested,
    PresentationDefinition, PresentationSubmission,
};
use futures::{executor::block_on, future::join_all};
use identity_credential::presentation::PresentationBuilder;
use identity_credential::{credential::Jwt, presentation::Presentation};
use jsonwebtoken::{Algorithm, Header};
use oid4vc_core::{
    authorization_response::AuthorizationResponse, jwt, serialize_unit_struct, Decoder, Extension, Subject,
};
use oid4vc_core::{JsonObject, JsonValue};
use oid4vci::VerifiableCredentialJwt;
pub use oid4vp_params::Oid4vpParams;
use serde::{Deserialize, Deserializer, Serialize};
use std::sync::Arc;

#[derive(Debug, PartialEq, Default)]
pub struct VpToken;
serialize_unit_struct!("vp_token", VpToken);

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct OID4VP;
impl Extension for OID4VP {
    type ResponseType = VpToken;
    type AuthorizationRequest = OID4VPAuthorizationRequestParameters;
    type AuthorizationRequestBuilder = OID4VPAuthorizationRequestBuilder;
    type UserClaims = OID4VPUserClaims;
    type AuthorizationResponse = OID4VPAuthorizationResponse;
    type ResponseItem = Vec<VerifiableCredentialJwt>;

    fn generate_token(
        subject: Arc<dyn Subject>,
        client_id: String,
        extension: Self::AuthorizationRequest,
        user_input: &Self::UserClaims,
    ) -> anyhow::Result<Vec<String>> {
        let subject_identifier = subject.identifier()?;

        let vp_token = crate::token::vp_token::VpToken::builder()
            .iss(subject_identifier.clone())
            .sub(subject_identifier)
            .aud(client_id)
            .nonce(extension.nonce.to_owned())
            .exp((Utc::now() + Duration::minutes(10)).timestamp())
            .iat((Utc::now()).timestamp())
            .verifiable_presentation(user_input.verifiable_presentation.clone())
            .build()?;

        let vp_token = jwt::encode(subject.clone(), Header::new(Algorithm::EdDSA), vp_token)?;
        Ok(vec![vp_token])
    }

    fn build_authorization_response(
        jwts: Vec<String>,
        user_input: Self::UserClaims,
        redirect_uri: String,
        state: Option<String>,
    ) -> anyhow::Result<AuthorizationResponse<Self>> {
        Ok(AuthorizationResponse::<OID4VP> {
            redirect_uri,
            state,
            extension: OID4VPAuthorizationResponse {
                oid4vp_parameters: Oid4vpParams::Params {
                    vp_token: jwts.get(0).unwrap().to_owned(),
                    presentation_submission: user_input.presentation_submission,
                },
            },
        })
    }

    fn decode_authorization_response(
        decoder: Decoder,
        response: &AuthorizationResponse<Self>,
    ) -> anyhow::Result<Self::ResponseItem> {
        let vp_token: crate::token::vp_token::VpToken = match &response.extension.oid4vp_parameters {
            Oid4vpParams::Jwt { .. } => todo!(),
            Oid4vpParams::Params { vp_token, .. } => block_on(decoder.decode(vp_token.to_owned()))?,
        };

        block_on(async move {
            join_all(
                vp_token
                    .verifiable_presentation()
                    .verifiable_credential
                    .iter()
                    .map(|vc| async { decoder.decode(vc.as_str().to_owned()).await }),
            )
            .await
            .into_iter()
            .collect()
        })
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct OID4VPAuthorizationResponse {
    #[serde(flatten, with = "serde_oid4vp_response")]
    pub oid4vp_parameters: Oid4vpParams,
}

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

pub struct OID4VPUserClaims {
    pub verifiable_presentation: Presentation<Jwt>,
    pub presentation_submission: PresentationSubmission,
}

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

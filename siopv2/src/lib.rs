pub mod authorization_request;
pub mod claims;
pub mod provider;
pub mod relying_party;
pub mod token;

use authorization_request::{SIOPv2AuthorizationRequestBuilder, SIOPv2AuthorizationRequestParameters};
use chrono::{Duration, Utc};
pub use claims::{ClaimRequests, StandardClaimsRequests, StandardClaimsValues};
use futures::executor::block_on;
use jsonwebtoken::{Algorithm, Header};
use oid4vc_core::{
    authorization_response::AuthorizationResponse, jwt,
    serialize_unit_struct, Decoder, Extension, JsonObject, JsonValue, Subject,
};
pub use provider::Provider;
pub use relying_party::RelyingParty;
pub use token::id_token_builder::IdTokenBuilder;

use serde::{Deserialize, Deserializer, Serialize};
use std::sync::Arc;

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
    type UserClaims = StandardClaimsValues;
    type AuthorizationResponse = SIOPv2AuthorizationResponseParameters;
    type ResponseItem = crate::token::id_token::IdToken;

    fn generate_token(
        subject: Arc<dyn Subject>,
        client_id: &str,
        extension: &Self::AuthorizationRequest,
        user_input: &Self::UserClaims,
    ) -> anyhow::Result<Vec<String>> {
        let subject_identifier = subject.identifier()?;

        let id_token = crate::token::id_token::IdToken::builder()
            .iss(subject_identifier.clone())
            .sub(subject_identifier)
            .aud(client_id)
            .nonce(extension.nonce.to_owned())
            .exp((Utc::now() + Duration::minutes(10)).timestamp())
            .iat((Utc::now()).timestamp())
            .claims(user_input.clone())
            .build()?;

        let jwt = jwt::encode(subject.clone(), Header::new(Algorithm::EdDSA), id_token)?;

        Ok(vec![jwt])
    }

    fn build_authorization_response(
        jwts: Vec<String>,
        _user_input: Self::UserClaims,
        redirect_uri: String,
        state: Option<String>,
    ) -> anyhow::Result<AuthorizationResponse<Self>> {
        let extension = SIOPv2AuthorizationResponseParameters {
            id_token: jwts[0].to_string(),
        };

        Ok(AuthorizationResponse::<SIOPv2> {
            redirect_uri,
            state,
            extension,
        })
    }

    fn decode_authorization_response(
        decoder: Decoder,
        response: &AuthorizationResponse<Self>,
    ) -> anyhow::Result<Self::ResponseItem> {
        let token = response.extension.id_token.clone();
        block_on(decoder.decode(token))
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct SIOPv2AuthorizationResponseParameters {
    pub id_token: String,
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

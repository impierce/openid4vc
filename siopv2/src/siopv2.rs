use crate::authorization_request::{SIOPv2AuthorizationRequestBuilder, SIOPv2AuthorizationRequestParameters};
use crate::claims::StandardClaimsValues;
use chrono::{Duration, Utc};
use futures::executor::block_on;
use jsonwebtoken::{Algorithm, Header};
use oid4vc_core::{
    authorization_response::AuthorizationResponse, jwt, openid4vc_extension::Extension, serialize_unit_struct, Decoder,
    Subject,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// Unit struct used for the `response_type` parameter.
#[derive(Debug, PartialEq, Default)]
pub struct IdToken;
serialize_unit_struct!("id_token", IdToken);

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct SIOPv2;
impl Extension for SIOPv2 {
    type ResponseType = IdToken;
    type AuthorizationRequest = SIOPv2AuthorizationRequestParameters;
    type AuthorizationRequestBuilder = SIOPv2AuthorizationRequestBuilder;
    type AuthorizationResponseInput = StandardClaimsValues;
    type AuthorizationResponse = SIOPv2AuthorizationResponse;
    type ResponseItem = crate::token::id_token::IdToken;

    fn generate_token(
        subject: Arc<dyn Subject>,
        client_id: &str,
        extension: &Self::AuthorizationRequest,
        user_input: &Self::AuthorizationResponseInput,
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
        _user_input: Self::AuthorizationResponseInput,
        redirect_uri: String,
        state: Option<String>,
    ) -> anyhow::Result<AuthorizationResponse<Self>> {
        let extension = SIOPv2AuthorizationResponse {
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
        authorization_response: &AuthorizationResponse<Self>,
    ) -> anyhow::Result<Self::ResponseItem> {
        let token = authorization_response.extension.id_token.clone();
        block_on(decoder.decode(token))
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct SIOPv2AuthorizationResponse {
    pub id_token: String,
}

use crate::authorization_request::{AuthorizationRequestBuilder, AuthorizationRequestParameters};
use crate::claims::StandardClaimsValues;
use chrono::{Duration, Utc};
use futures::executor::block_on;
use jsonwebtoken::{Algorithm, Header};
use oid4vc_core::openid4vc_extension::{OpenID4VC, RequestHandle, ResponseHandle};
use oid4vc_core::{
    authorization_response::AuthorizationResponse, jwt, openid4vc_extension::Extension, serialize_unit_struct, Decoder,
    Subject,
};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use std::sync::Arc;

/// This is the [`RequestHandle`] for the [`SIOPv2`] extension.
#[derive(Debug, PartialEq)]
pub struct RequestHandler {}
impl RequestHandle for RequestHandler {
    type ResponseType = IdToken;
    type Parameters = AuthorizationRequestParameters;
    type Builder = AuthorizationRequestBuilder;
}

/// This is the [`ResponseHandle`] for the [`SIOPv2`] extension.
#[derive(Debug, PartialEq)]
pub struct ResponseHandler {}
impl ResponseHandle for ResponseHandler {
    type Input = StandardClaimsValues;
    type Parameters = AuthorizationResponseParameters;
    type ResponseItem = crate::token::id_token::IdToken;
}

// Unit struct used for the `response_type` parameter.
#[derive(Debug, PartialEq, Default, DeserializeFromStr, SerializeDisplay, Clone)]
pub struct IdToken;
serialize_unit_struct!("id_token", IdToken);

/// This is the [`Extension`] implementation for the [`SIOPv2`] extension.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SIOPv2;
impl OpenID4VC for SIOPv2 {}
impl Extension for SIOPv2 {
    type RequestHandle = RequestHandler;
    type ResponseHandle = ResponseHandler;

    fn generate_token(
        subject: Arc<dyn Subject>,
        client_id: &str,
        extension_parameters: &<Self::RequestHandle as RequestHandle>::Parameters,
        user_input: &<Self::ResponseHandle as ResponseHandle>::Input,
    ) -> anyhow::Result<Vec<String>> {
        let subject_identifier = subject.identifier()?;

        let id_token = crate::token::id_token::IdToken::builder()
            .iss(subject_identifier.clone())
            .sub(subject_identifier)
            .aud(client_id)
            .nonce(extension_parameters.nonce.to_owned())
            .exp((Utc::now() + Duration::minutes(10)).timestamp())
            .iat((Utc::now()).timestamp())
            .claims(user_input.clone())
            .build()?;

        let jwt = jwt::encode(subject.clone(), Header::new(Algorithm::EdDSA), id_token)?;

        Ok(vec![jwt])
    }

    fn build_authorization_response(
        jwts: Vec<String>,
        _user_input: <Self::ResponseHandle as ResponseHandle>::Input,
        redirect_uri: String,
        state: Option<String>,
    ) -> anyhow::Result<AuthorizationResponse<Self>> {
        let extension = AuthorizationResponseParameters {
            id_token: jwts[0].to_string(),
        };

        Ok(AuthorizationResponse {
            redirect_uri,
            state,
            extension,
        })
    }

    fn decode_authorization_response(
        decoder: Decoder,
        authorization_response: &AuthorizationResponse<Self>,
    ) -> anyhow::Result<<Self::ResponseHandle as ResponseHandle>::ResponseItem> {
        let token = authorization_response.extension.id_token.clone();
        block_on(decoder.decode(token))
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct AuthorizationResponseParameters {
    pub id_token: String,
}

use crate::{
    authorization_request::AuthorizationRequestObject, authorization_response::AuthorizationResponse, Decoder,
    JsonValue, Subject,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::sync::Arc;

pub trait Extension: Serialize + PartialEq + Sized {
    type ResponseType: Serialize + DeserializeOwned + std::fmt::Debug + PartialEq;
    type AuthorizationRequest: Serialize + DeserializeOwned + std::fmt::Debug + PartialEq;
    type AuthorizationRequestBuilder: Default + std::fmt::Debug;
    type AuthorizationResponseInput;
    type AuthorizationResponse: Serialize + DeserializeOwned + std::fmt::Debug + PartialEq;
    type ResponseItem: Serialize + std::fmt::Debug + PartialEq;

    fn resolve(
        authorization_request: AuthorizationRequestObject<Unresolved>,
    ) -> anyhow::Result<AuthorizationRequestObject<Self>> {
        Ok(AuthorizationRequestObject::<Self> {
            rfc7519_claims: authorization_request.rfc7519_claims,
            response_type: serde_json::from_value(authorization_request.response_type)
                .map_err(|_| anyhow::anyhow!("Invalid `response_type` parameter."))?,
            client_id: authorization_request.client_id,
            redirect_uri: authorization_request.redirect_uri,
            state: authorization_request.state,
            extension: serde_json::from_value(authorization_request.extension)
                .map_err(|_| anyhow::anyhow!("Invalid `extension` parameter."))?,
        })
    }

    fn generate_token(
        subject: Arc<dyn Subject>,
        client_id: &str,
        extension: &Self::AuthorizationRequest,
        user_input: &Self::AuthorizationResponseInput,
    ) -> anyhow::Result<Vec<String>>;

    fn build_authorization_response(
        jwts: Vec<String>,
        user_input: Self::AuthorizationResponseInput,
        redirect_uri: String,
        state: Option<String>,
    ) -> anyhow::Result<AuthorizationResponse<Self>>;

    fn decode_authorization_response(
        decoder: Decoder,
        response: &AuthorizationResponse<Self>,
    ) -> anyhow::Result<Self::ResponseItem>;
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Unresolved;

impl Extension for Unresolved {
    type ResponseType = JsonValue;
    type AuthorizationRequest = JsonValue;
    type AuthorizationRequestBuilder = ();
    type AuthorizationResponseInput = ();
    type AuthorizationResponse = ();
    type ResponseItem = ();

    fn generate_token(
        _subject: Arc<dyn Subject>,
        _client_id: &str,
        _extension: &Self::AuthorizationRequest,
        _user_input: &Self::AuthorizationResponseInput,
    ) -> anyhow::Result<Vec<String>> {
        unreachable!()
    }

    fn build_authorization_response(
        _jwts: Vec<String>,
        _user_input: Self::AuthorizationResponseInput,
        _redirect_uri: String,
        _state: Option<String>,
    ) -> anyhow::Result<AuthorizationResponse<Self>> {
        unreachable!()
    }

    fn decode_authorization_response(
        _decoder: Decoder,
        _response: &AuthorizationResponse<Self>,
    ) -> anyhow::Result<Self::ResponseItem> {
        unreachable!()
    }
}

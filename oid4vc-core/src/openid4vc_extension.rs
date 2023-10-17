use crate::{authorization_response::AuthorizationResponse, Decoder, JsonValue, Subject};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{str::FromStr, sync::Arc};

pub trait Builder {}

pub trait RequestHandle: std::fmt::Debug + PartialEq {
    type ResponseType: Serialize + DeserializeOwned + std::fmt::Debug + PartialEq + FromStr + std::fmt::Display;
    type Parameters: Serialize + DeserializeOwned + std::fmt::Debug + PartialEq;
    type Builder: Default + std::fmt::Debug;
}

pub trait ResponseHandle: std::fmt::Debug + PartialEq {
    type Input;
    type Parameters: Serialize + DeserializeOwned + std::fmt::Debug + PartialEq;
    type ResponseItem: Serialize + std::fmt::Debug + PartialEq;
}

/// This [`Extension'] trait is used to declare what functionality an extension should have. Most notable, it declares
/// that an extension should be able to generate a token, build an authorization response, and decode an authorization response.
pub trait Extension: Serialize + PartialEq + Sized + std::fmt::Debug {
    type RequestHandle: RequestHandle;
    type ResponseHandle: ResponseHandle;

    fn generate_token(
        _subject: Arc<dyn Subject>,
        _client_id: &str,
        _extension_parameters: &<Self::RequestHandle as RequestHandle>::Parameters,
        _user_input: &<Self::ResponseHandle as ResponseHandle>::Input,
    ) -> anyhow::Result<Vec<String>> {
        // Will be overridden by the extension.
        Err(anyhow::anyhow!("Not implemented."))
    }

    fn build_authorization_response(
        _jwts: Vec<String>,
        _user_input: <Self::ResponseHandle as ResponseHandle>::Input,
        _redirect_uri: String,
        _state: Option<String>,
    ) -> anyhow::Result<AuthorizationResponse<Self>> {
        // Will be overridden by the extension.
        Err(anyhow::anyhow!("Not implemented."))
    }

    fn decode_authorization_response(
        _decoder: Decoder,
        _authorization_response: &AuthorizationResponse<Self>,
    ) -> anyhow::Result<<Self::ResponseHandle as ResponseHandle>::ResponseItem> {
        // Will be overridden by the extension.
        Err(anyhow::anyhow!("Not implemented."))
    }
}

impl RequestHandle for () {
    type ResponseType = String;
    type Parameters = JsonValue;
    type Builder = ();
}

impl ResponseHandle for () {
    type Input = ();
    type Parameters = ();
    type ResponseItem = ();
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Generic;
impl Extension for Generic {
    type RequestHandle = ();
    type ResponseHandle = ();
}

pub trait OpenID4VC {}

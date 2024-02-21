use crate::{authorization_response::AuthorizationResponse, Decoder, Subject};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::sync::Arc;

/// A [`RequestHandle`] is used to declare what functionality a request should have. Most notable, it declares the
/// `response_type``, the extension-specific parameters, and the builder for the extension-specific `AuthorizationRequest`.
pub trait RequestHandle: std::fmt::Debug + PartialEq {
    type Parameters: Serialize + DeserializeOwned + std::fmt::Debug + PartialEq + Clone;
    type Builder: Default + std::fmt::Debug;
}

/// A [`ResponseHandle`] is used to declare what functionality a response should have. Most notable, it declares the
/// input that is needed to generate a token, the extension-specific parameters, and the response item.
pub trait ResponseHandle: std::fmt::Debug + PartialEq {
    type Input;
    type Parameters: Serialize + DeserializeOwned + std::fmt::Debug + PartialEq;
    type ResponseItem: Serialize + std::fmt::Debug + PartialEq;
}

/// This [`Extension'] trait is used to declare what functionality an extension should have. Most notable, it declares
/// that an extension should be able to generate a token, build an authorization response, and decode an authorization response.
pub trait Extension: Serialize + PartialEq + Sized + std::fmt::Debug + Clone {
    type RequestHandle: RequestHandle;
    type ResponseHandle: ResponseHandle;

    fn generate_token(
        _subject: Arc<dyn Subject>,
        _client_id: &str,
        _extension_parameters: &<Self::RequestHandle as RequestHandle>::Parameters,
        _user_input: &<Self::ResponseHandle as ResponseHandle>::Input,
    ) -> anyhow::Result<Vec<String>> {
        // Will be overwritten by the extension.
        Err(anyhow::anyhow!("Not implemented."))
    }

    fn build_authorization_response(
        _jwts: Vec<String>,
        _user_input: <Self::ResponseHandle as ResponseHandle>::Input,
        _redirect_uri: String,
        _state: Option<String>,
    ) -> anyhow::Result<AuthorizationResponse<Self>> {
        // Will be overwritten by the extension.
        Err(anyhow::anyhow!("Not implemented."))
    }

    fn decode_authorization_response(
        _decoder: Decoder,
        _authorization_response: &AuthorizationResponse<Self>,
    ) -> anyhow::Result<<Self::ResponseHandle as ResponseHandle>::ResponseItem> {
        // Will be overwritten by the extension.
        Err(anyhow::anyhow!("Not implemented."))
    }
}

impl RequestHandle for () {
    type Parameters = serde_json::Value;
    type Builder = ();
}

impl ResponseHandle for () {
    type Input = ();
    type Parameters = ();
    type ResponseItem = ();
}

/// This [`Extension`] is used to declare that a struct is a [`Generic`] extension. Which means that it does not have
/// any extension-specific functionality. It is used as a default extension.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Generic;
impl Extension for Generic {
    type RequestHandle = ();
    type ResponseHandle = ();
}

/// This marker trait is used to declare that a struct is an [`OpenID4VC`] extension.
pub trait OpenID4VC {}

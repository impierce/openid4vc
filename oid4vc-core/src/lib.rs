pub mod authentication;
pub mod authorization_request;
pub mod authorization_response;
pub mod client_metadata;
pub mod collection;
pub mod decoder;
pub mod jwt;
pub mod rfc7519_claims;
pub mod scope;
pub mod subject_syntax_type;

use std::sync::Arc;

pub use authentication::{
    sign::Sign,
    subject::{Subject, Subjects},
    validator::{Validator, Validators},
    verify::Verify,
};
use authorization_request::AuthorizationRequestObject;
use authorization_response::AuthorizationResponse;
pub use collection::Collection;
pub use decoder::Decoder;
use rand::{distributions::Alphanumeric, Rng};
pub use rfc7519_claims::RFC7519Claims;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
pub use subject_syntax_type::{DidMethod, SubjectSyntaxType};

pub use serde_json::Value as JsonValue;
pub type JsonObject = serde_json::Map<String, JsonValue>;

#[cfg(test)]
mod test_utils;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Unresolved;

impl Extension for Unresolved {
    type ResponseType = JsonValue;
    type AuthorizationRequest = JsonValue;
    type AuthorizationRequestBuilder = ();
    type UserClaims = ();
    type AuthorizationResponse = ();
    type ResponseItem = ();

    fn generate_token(
        _subject: Arc<dyn Subject>,
        _client_id: &str,
        _extension: &Self::AuthorizationRequest,
        _user_input: &Self::UserClaims,
    ) -> anyhow::Result<Vec<String>> {
        unreachable!()
    }

    fn build_authorization_response(
        _jwts: Vec<String>,
        _user_input: Self::UserClaims,
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

pub trait Extension: Serialize + PartialEq + Sized {
    type ResponseType: Serialize + DeserializeOwned + std::fmt::Debug + PartialEq + Default;
    type AuthorizationRequest: Serialize + DeserializeOwned + std::fmt::Debug + PartialEq;
    type AuthorizationRequestBuilder: Default + std::fmt::Debug;
    type UserClaims;
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
        user_input: &Self::UserClaims,
    ) -> anyhow::Result<Vec<String>>;

    fn build_authorization_response(
        jwts: Vec<String>,
        user_input: Self::UserClaims,
        redirect_uri: String,
        state: Option<String>,
    ) -> anyhow::Result<AuthorizationResponse<Self>>;

    fn decode_authorization_response(
        decoder: Decoder,
        response: &AuthorizationResponse<Self>,
    ) -> anyhow::Result<Self::ResponseItem>;
}

#[macro_export]
macro_rules! builder_fn {
    ($name:ident, $ty:ty) => {
        #[allow(clippy::should_implement_trait)]
        pub fn $name(mut self, value: impl Into<$ty>) -> Self {
            self.$name.replace(value.into());
            self
        }
    };
    ($field:ident, $name:ident, $ty:ty) => {
        #[allow(clippy::should_implement_trait)]
        pub fn $name(mut self, value: impl Into<$ty>) -> Self {
            self.$field.$name.replace(value.into());
            self
        }
    };
}

// macro that generates a serialize/deserialize implementation for a unit struct.
#[macro_export]
macro_rules! serialize_unit_struct {
    ($format:literal, $name:ident) => {
        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str($format)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct Visitor;

                impl<'de> serde::de::Visitor<'de> for Visitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        formatter.write_str($format)
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        if value == $format {
                            Ok($name)
                        } else {
                            Err(serde::de::Error::custom(format!(
                                "expected {}, found {}",
                                $format, value
                            )))
                        }
                    }
                }

                deserializer.deserialize_str(Visitor)
            }
        }
    };
}

// Helper function that allows to serialize custom structs into a query string.
pub fn to_query_value<T: Serialize>(value: &T) -> anyhow::Result<String> {
    serde_json::to_string(value)
        .map(|s| s.chars().filter(|c| !c.is_whitespace()).collect::<String>())
        .map_err(|e| e.into())
}

pub fn generate_authorization_code(length: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

pub fn generate_nonce(length: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

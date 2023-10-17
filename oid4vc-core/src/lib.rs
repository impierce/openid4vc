pub mod authentication;
pub mod authorization_request;
pub mod authorization_response;
pub mod client_metadata;
pub mod collection;
pub mod decoder;
pub mod jwt;
pub mod openid4vc_extension;
pub mod rfc7519_claims;
pub mod scope;
pub mod subject_syntax_type;

pub use authentication::{
    sign::Sign,
    subject::{Subject, Subjects},
    validator::{Validator, Validators},
    verify::Verify,
};
pub use collection::Collection;
pub use decoder::Decoder;
use rand::{distributions::Alphanumeric, Rng};
pub use rfc7519_claims::RFC7519Claims;
use serde::Serialize;
pub use subject_syntax_type::{DidMethod, SubjectSyntaxType};

pub use serde_json::Value as JsonValue;
pub type JsonObject = serde_json::Map<String, JsonValue>;

#[cfg(test)]
mod test_utils;

// Macro that generates a builder function for a field.
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
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", $format)
            }
        }

        impl std::str::FromStr for $name {
            type Err = anyhow::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                if s == $format {
                    Ok($name)
                } else {
                    Err(anyhow::anyhow!(format!("expected {}, found {}", $format, s)))
                }
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

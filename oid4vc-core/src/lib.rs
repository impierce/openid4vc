pub mod authentication;
pub mod collection;
pub mod decoder;
pub mod jwt;
pub mod rfc7519_claims;
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

pub mod authentication;
pub mod claims;
pub mod client_metadata;
pub mod collection;
pub mod credential;
pub mod decoder;
pub mod jwt;
pub mod provider;
pub mod relying_party;
pub mod request;
pub mod response;
pub mod scope;
pub mod subject_syntax_type;
pub mod token;

pub use authentication::{
    sign::Sign,
    subject::{Subject, Subjects},
    validator::{Validator, Validators},
    verify::Verify,
};
pub use claims::{ClaimRequests, StandardClaimsRequests, StandardClaimsValues};
pub use client_metadata::ClientMetadata;
pub use collection::Collection;
pub use credential::VerifiableCredentialJwt;
pub use decoder::Decoder;
pub use jwt::JsonWebToken;
pub use provider::Provider;
pub use relying_party::RelyingParty;
pub use request::{request_builder::RequestUrlBuilder, AuthorizationRequest, RequestUrl};
pub use response::AuthorizationResponse;
pub use scope::Scope;
pub use subject_syntax_type::SubjectSyntaxType;
pub use token::{id_token::IdToken, id_token_builder::IdTokenBuilder};

use serde::{Deserialize, Deserializer};

#[cfg(test)]
pub mod test_utils;

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

// When a struct has fields of type `Option<serde_json::Map<String, serde_json::Value>>`, by default these fields are deserialized as
// `Some(Object {})` instead of None when the corresponding values are missing.
// The `parse_other()` helper function ensures that these fields are deserialized as `None` when no value is present.
pub fn parse_other<'de, D>(deserializer: D) -> Result<Option<serde_json::Map<String, serde_json::Value>>, D::Error>
where
    D: Deserializer<'de>,
{
    serde_json::Value::deserialize(deserializer).map(|value| match value {
        serde_json::Value::Object(object) if !object.is_empty() => Some(object),
        _ => None,
    })
}

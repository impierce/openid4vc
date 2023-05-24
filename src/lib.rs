pub mod claims;
pub mod id_token;
pub mod jwt;
pub mod key_method;
pub mod provider;
pub mod registration;
pub mod relying_party;
pub mod request;
pub mod request_builder;
pub mod response;
pub mod scope;
pub mod subject;
pub mod validator;

pub use claims::{StandardClaimsRequests, StandardClaimsValues};
pub use id_token::IdToken;
pub use jwt::JsonWebToken;
pub use provider::Provider;
pub use registration::Registration;
pub use relying_party::RelyingParty;
pub use request::{RequestUrl, SiopRequest};
pub use request_builder::RequestUrlBuilder;
pub use response::Response;
pub use scope::Scope;
pub use subject::Subject;
pub use validator::Validator;

#[cfg(test)]
pub mod test_utils;

#[macro_export]
macro_rules! builder_fn {
    ( $name:ident, $ty:ty) => {
        pub fn $name(mut self, value: $ty) -> Self {
            self.$name.replace(value);
            self
        }
    };
    ($field:ident, $name:ident, $ty:ty) => {
        pub fn $name(mut self, value: $ty) -> Self {
            self.$field.$name.replace(value);
            self
        }
    };
}

pub mod claim;
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

pub use claim::Claim;
pub use id_token::IdToken;
pub use jwt::JsonWebToken;
pub use provider::Provider;
pub use registration::Registration;
pub use relying_party::RelyingParty;
pub use request::{RequestUrl, SiopRequest};
pub use request_builder::RequestUrlBuilder;
pub use response::SiopResponse;
pub use scope::Scope;
pub use subject::Subject;
pub use validator::Validator;

#[cfg(test)]
pub mod test_utils;

pub fn serialize_field<T: Serialize>(pair: &Option<(&str, T)>) -> Option<(String, Value)> {
    pair.as_ref()
        .and_then(|(name, field)| serde_json::to_value(field).map(|value| (name.to_string(), value)).ok())
}

pub fn deserialize_field<T: DeserializeOwned>(map: &Map<String, Value>, field_name: &str) -> Option<T> {
    map.get(field_name).and_then(|value| match value {
        Value::Object(_) | Value::Array(_) => serde_json::from_value(value.clone()).ok(),
        _ => None,
    })
}

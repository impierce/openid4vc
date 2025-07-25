pub mod authorization_details;
pub mod authorization_request;
pub mod authorization_response;
pub mod credential;
pub mod credential_format_profiles;
pub mod credential_issuer;
pub mod credential_offer;
pub mod credential_request;
pub mod credential_response;
pub mod errors;
pub mod notification_request;
pub mod proof;
pub mod proofs;
pub mod token_request;
pub mod token_response;
pub mod wallet;

use std::collections::HashMap;

pub use credential::{VerifiableCredentialJwt, VerifiableCredentialJwtBuilder};
use oid4vc_core::JsonObject;
pub use pkce;
pub use proof::Proof;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::json;
pub use wallet::Wallet;

// FIXME: move this elsewhere
pub fn to_form_urlencoded_string<T: Serialize>(value: &T) -> anyhow::Result<String> {
    let map: JsonObject = json!(value)
        .as_object()
        .ok_or(std::fmt::Error)
        .unwrap()
        .iter()
        .filter_map(|(k, v)| match v {
            serde_json::Value::Object(_) | serde_json::Value::Array(_) => Some((
                k.to_owned(),
                serde_json::Value::String(serde_json::to_string(v).ok().unwrap()),
            )),
            _ => Some((k.to_owned(), v.to_owned())),
        })
        .collect();

    let encoded = serde_urlencoded::to_string(map).unwrap();
    Ok(encoded)
}

// FIXME: move this elsewhere
pub fn from_form_urlencoded_string<T: DeserializeOwned>(encoded: &str) -> anyhow::Result<T> {
    let string_map: HashMap<String, String> =
        serde_urlencoded::from_str(encoded).map_err(|e| anyhow::anyhow!("Failed to decodde: {}", e))?;

    // to convert the string map to a JSON map, parsing the stringified JSON values
    let json_map: serde_json::Map<String, serde_json::Value> = string_map
        .into_iter()
        .map(|(k, v)| {
            let json_value = serde_json::from_str(&v).unwrap_or_else(|_| serde_json::Value::String(v.to_string()));
            (k, json_value)
        })
        .collect();

    // then this converts the JSON map to the wanted type.
    let value = serde_json::Value::Object(json_map);
    serde_json::from_value(value).map_err(|e| anyhow::anyhow!("Failed to deserialize: {}", e))
}

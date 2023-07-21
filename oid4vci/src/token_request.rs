use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum GrantTypeIdentifier {
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    PreAuthorizedCode,
    #[serde(rename = "authorization_code")]
    AuthorizationCode,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct TokenRequest {
    // TODO: now is only for pre-authorize code flow
    pub grant_type: GrantTypeIdentifier,
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
    pub user_pin: Option<String>,
}

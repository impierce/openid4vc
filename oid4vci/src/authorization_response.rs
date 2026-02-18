use serde::{Deserialize, Serialize};

/// Authorization Response as described here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-successful-authorization-re
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorizationResponse {
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

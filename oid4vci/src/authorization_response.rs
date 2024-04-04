use serde::{Deserialize, Serialize};

// TODO: Temporary solution for the Authorization Code Flow. Eventually this should be implemented as described
// here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#name-successful-authorization-re
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorizationResponse {
    pub code: String,
    pub state: Option<String>,
}

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// Token Response as described here: https://openid.bitbucket.io/connect/openid-4-verifiable-credential-issuance-1_0.html#name-successful-token-response.
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub c_nonce: Option<String>,
    pub c_nonce_expires_in: Option<u64>,
    // TODO: add `authorization_details` field when support for Authorization Code Flow is added.
}

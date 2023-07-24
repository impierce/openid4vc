use dif_presentation_exchange::ClaimFormatDesignation;
use serde::{Deserialize, Serialize};

/// Credential Response as described here: https://openid.bitbucket.io/connect/openid-4-verifiable-credential-issuance-1_0.html#name-credential-response.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct CredentialResponse {
    pub format: ClaimFormatDesignation,
    pub credential: Option<serde_json::Value>,
    pub transaction_id: Option<String>,
    pub c_nonce: Option<String>,
    pub c_nonce_expires_in: Option<u64>,
}

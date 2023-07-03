use dif_presentation_exchange::ClaimFormatDesignation;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct CredentialResponse {
    pub format: ClaimFormatDesignation,
    pub credential: Option<serde_json::Value>,
    pub transaction_id: Option<String>,
    pub c_nonce: Option<String>,
    pub c_nonce_expires_in: Option<u64>,
}

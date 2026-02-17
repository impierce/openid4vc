use serde::{Deserialize, Serialize};

/// The Nonce Request is used to request a nonce as described here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-nonce-response
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NonceResponse {
    pub c_nonce: String,
}

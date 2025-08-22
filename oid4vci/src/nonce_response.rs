use serde::{Deserialize, Serialize};

// FIXME: fix comment
/// The Authorization Request is used to request authorization as described here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#name-authorization-request
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NonceResponse {
    pub c_nonce: String,
}

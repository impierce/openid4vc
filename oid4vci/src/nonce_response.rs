use serde::{Deserialize, Serialize};

/// Nonce Response as defined by OpenID4VCI.
///
/// See <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-nonce-response>.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct NonceResponse {
    pub c_nonce: String,
}

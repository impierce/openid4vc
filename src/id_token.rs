use chrono::Utc;
use serde::{Deserialize, Serialize};

/// An SIOPv2 [`IdToken`] as specified in the [SIOPv2 specification](https://openid.net/specs/openid-connect-core-1_0.html#IDToken).
#[derive(Serialize, Deserialize, Debug)]
pub struct IdToken {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub nonce: String,
}

impl IdToken {
    pub fn new(iss: String, sub: String, aud: String, nonce: String, exp: i64) -> Self {
        IdToken {
            iss,
            sub,
            aud,
            exp,
            iat: Utc::now().timestamp(),
            nonce,
        }
    }
}

use chrono::Utc;
use serde::{Deserialize, Serialize};

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

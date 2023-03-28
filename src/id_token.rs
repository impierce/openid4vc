use chrono::{Duration, Utc};
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
    pub fn new(iss: String, sub: String, aud: String, nonce: String) -> Self {
        IdToken {
            iss,
            sub,
            aud,
            exp: (Utc::now() + Duration::minutes(10)).timestamp(),
            iat: Utc::now().timestamp(),
            nonce,
        }
    }
}

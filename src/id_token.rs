use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct IdToken {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    iat: i64,
    nonce: String,
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

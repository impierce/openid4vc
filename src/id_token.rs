use crate::StandardClaims;
use chrono::Utc;
use getset::Setters;
use serde::{Deserialize, Serialize};

/// An SIOPv2 [`IdToken`] as specified in the [SIOPv2 specification](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#name-self-issued-id-token).
#[derive(Serialize, Deserialize, Debug, PartialEq, Setters)]
pub struct IdToken {
    pub iss: String,
    // TODO: sub should be part of the standard claims?
    pub sub: String,
    #[getset(set = "pub")]
    #[serde(flatten)]
    pub standard_claims: StandardClaims,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub nonce: String,
    pub state: Option<String>,
}

impl IdToken {
    pub fn new(iss: String, sub: String, aud: String, nonce: String, exp: i64) -> Self {
        IdToken {
            iss,
            sub,
            standard_claims: StandardClaims::default(),
            aud,
            exp,
            iat: Utc::now().timestamp(),
            nonce,
            state: None,
        }
    }

    pub fn state(mut self, state: Option<String>) -> Self {
        self.state = state;
        self
    }

    pub fn claims(mut self, claims: StandardClaims) -> Self {
        self.standard_claims = claims;
        self
    }
}

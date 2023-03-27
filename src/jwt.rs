use identity_core::crypto::Proof;
use jsonwebtoken::{Algorithm, Header};
use serde::Serialize;

use crate::id_token::IdToken;

#[derive(Debug, Serialize)]
pub struct JsonWebToken {
    pub header: Header,
    pub payload: IdToken,
    pub signature: Option<Proof>,
}

impl JsonWebToken {
    pub fn new(payload: IdToken) -> Self {
        JsonWebToken {
            // TODO: Undo hardcoding and consider not using the jsonwebtoken crate.
            header: Header::new(Algorithm::EdDSA),
            payload,
            signature: None,
        }
    }

    pub fn kid(mut self, kid: String) -> Self {
        self.header.kid = Some(kid);
        self
    }

    // Getter method for header field.
    pub fn header(&self) -> &Header {
        &self.header
    }
}

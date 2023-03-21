use identity_core::crypto::{GetSignature, GetSignatureMut, Proof, SetSignature};
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
}

impl GetSignature for JsonWebToken {
    fn signature(&self) -> Option<&Proof> {
        self.signature.as_ref()
    }
}

impl GetSignatureMut for JsonWebToken {
    fn signature_mut(&mut self) -> Option<&mut Proof> {
        self.signature.as_mut()
    }
}

impl SetSignature for JsonWebToken {
    fn set_signature(&mut self, signature: Proof) {
        self.signature = Some(signature);
    }
}

#[derive(Debug, Serialize)]
pub struct TempWrapper {
    pub message: String,
    pub signature: Option<Proof>,
}

impl GetSignature for TempWrapper {
    fn signature(&self) -> Option<&Proof> {
        self.signature.as_ref()
    }
}

impl GetSignatureMut for TempWrapper {
    fn signature_mut(&mut self) -> Option<&mut Proof> {
        self.signature.as_mut()
    }
}

impl SetSignature for TempWrapper {
    fn set_signature(&mut self, signature: Proof) {
        self.signature = Some(signature);
    }
}

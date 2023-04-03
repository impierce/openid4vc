use crate::{provider::Subject, relying_party::Validator};
use anyhow::Result;
use async_trait::async_trait;
use ed25519_dalek::{Keypair, Signature, Signer};
use lazy_static::lazy_static;
use rand::rngs::OsRng;

// Keypair for mocking purposes.
lazy_static! {
    pub static ref MOCK_KEYPAIR: Keypair = Keypair::generate(&mut OsRng);
}

#[derive(Default)]
pub struct MockSubject;

impl MockSubject {
    pub fn new() -> Self {
        MockSubject {}
    }
}

#[async_trait]
impl Subject for MockSubject {
    fn did(&self) -> String {
        "did:mock:123".to_string()
    }

    fn key_identifier(&self) -> Option<String> {
        Some("key_identifier".to_string())
    }

    async fn sign(&self, message: &String) -> Result<Vec<u8>> {
        let signature: Signature = MOCK_KEYPAIR.sign(message.as_bytes());
        Ok(signature.to_bytes().to_vec())
    }
}

pub struct MockValidator;

impl MockValidator {
    pub fn new() -> Self {
        MockValidator {}
    }
}

#[async_trait]
impl Validator for MockValidator {
    async fn public_key(&self, _kid: &String) -> Result<Vec<u8>> {
        Ok(MOCK_KEYPAIR.public.to_bytes().to_vec())
    }
}

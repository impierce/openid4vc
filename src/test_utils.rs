use crate::{provider::Subject, relying_party::Validator};
use anyhow::Result;
use async_trait::async_trait;
use ed25519_dalek::{Keypair, Signature, Signer};

const ED25519_BYTES: [u8; 64] = [
    184, 51, 220, 84, 185, 50, 38, 241, 159, 104, 71, 65, 69, 200, 189, 33, 0, 143, 8, 118, 121, 226, 54, 174, 25, 25,
    222, 141, 130, 143, 80, 179, 174, 9, 12, 56, 110, 213, 126, 121, 47, 192, 117, 97, 75, 99, 95, 61, 25, 206, 185,
    80, 202, 96, 180, 162, 64, 49, 105, 175, 198, 195, 44, 173,
];

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
        let keypair = Keypair::from_bytes(&ED25519_BYTES).unwrap();
        let signature: Signature = keypair.sign(message.as_bytes());
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
        let keypair = Keypair::from_bytes(&ED25519_BYTES).unwrap();
        Ok(keypair.public.to_bytes().to_vec())
    }
}

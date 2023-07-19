use crate::{Sign, Subject, Verify};
use anyhow::Result;
use async_trait::async_trait;
use derivative::{self, Derivative};
use ed25519_dalek::{Keypair, Signature, Signer};
use lazy_static::lazy_static;
use rand::rngs::OsRng;

// Keypair for mocking purposes.
lazy_static! {
    pub static ref TEST_KEYPAIR: Keypair = Keypair::generate(&mut OsRng);
}

#[derive(Derivative)]
#[derivative(Default)]
pub struct TestSubject {
    #[derivative(Default(value = "did_url::DID::parse(\"did:test:123\").unwrap()"))]
    pub did: did_url::DID,
    pub key_id: String,
}

impl TestSubject {
    pub fn new(did: String, key_id: String) -> Result<Self> {
        Ok(TestSubject {
            did: did_url::DID::parse(did)?,
            key_id,
        })
    }
}

impl Sign for TestSubject {
    fn key_id(&self) -> Option<String> {
        Some(self.key_id.clone())
    }

    fn sign(&self, message: &str) -> Result<Vec<u8>> {
        let signature: Signature = TEST_KEYPAIR.sign(message.as_bytes());
        Ok(signature.to_bytes().to_vec())
    }
}

#[async_trait]
impl Verify for TestSubject {
    async fn public_key(&self, _kid: &str) -> Result<Vec<u8>> {
        Ok(TEST_KEYPAIR.public.to_bytes().to_vec())
    }
}

impl Subject for TestSubject {
    fn identifier(&self) -> Result<String> {
        Ok(self.did.to_string())
    }
}

pub struct MockVerifier;

impl MockVerifier {
    pub fn new() -> Self {
        MockVerifier {}
    }
}

#[async_trait]
impl Verify for MockVerifier {
    async fn public_key(&self, _kid: &str) -> Result<Vec<u8>> {
        Ok(TEST_KEYPAIR.public.to_bytes().to_vec())
    }
}

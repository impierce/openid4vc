use crate::{Sign, Subject, Verify};
use anyhow::Result;
use async_trait::async_trait;
use derivative::{self, Derivative};
use ed25519_dalek::{Keypair, Signature, Signer};
use lazy_static::lazy_static;
use rand::rngs::OsRng;

// Keypair for mocking purposes.
lazy_static! {
    pub static ref MOCK_KEYPAIR: Keypair = Keypair::generate(&mut OsRng);
}

#[derive(Derivative)]
#[derivative(Default)]
pub struct MockSubject {
    #[derivative(Default(value = "did_url::DID::parse(\"did:mock:123\").unwrap()"))]
    pub did: did_url::DID,
    pub key_id: String,
}

impl MockSubject {
    pub fn new(did: String, key_id: String) -> Result<Self> {
        Ok(MockSubject {
            did: did_url::DID::parse(did)?,
            key_id,
        })
    }
}

#[async_trait]
impl Sign for MockSubject {
    fn key_id(&self) -> Option<String> {
        Some(self.key_id.clone())
    }

    async fn sign(&self, message: &str) -> Result<Vec<u8>> {
        let signature: Signature = MOCK_KEYPAIR.sign(message.as_bytes());
        Ok(signature.to_bytes().to_vec())
    }
}

#[async_trait]
impl Verify for MockSubject {
    async fn public_key(&self, _kid: &str) -> Result<Vec<u8>> {
        Ok(MOCK_KEYPAIR.public.to_bytes().to_vec())
    }
}

impl Subject for MockSubject {
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
        Ok(MOCK_KEYPAIR.public.to_bytes().to_vec())
    }
}

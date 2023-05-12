use crate::{
    claims::{ClaimValue, IndividualClaimRequest},
    StandardClaims, Subject, Validator,
};
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
    pub key_identifier: String,
}

impl MockSubject {
    pub fn new(did: String, key_identifier: String) -> Result<Self> {
        Ok(MockSubject {
            did: did_url::DID::parse(did)?,
            key_identifier,
        })
    }
}

#[async_trait]
impl Subject for MockSubject {
    fn did(&self) -> Result<did_url::DID> {
        Ok(self.did.clone())
    }

    fn key_identifier(&self) -> Option<String> {
        Some(self.key_identifier.clone())
    }

    async fn sign<'a>(&self, message: &'a str) -> Result<Vec<u8>> {
        let signature: Signature = MOCK_KEYPAIR.sign(message.as_bytes());
        Ok(signature.to_bytes().to_vec())
    }
}

#[async_trait]
impl Validator for MockSubject {
    async fn public_key<'a>(&self, _kid: &'a str) -> Result<Vec<u8>> {
        Ok(MOCK_KEYPAIR.public.to_bytes().to_vec())
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
    async fn public_key<'a>(&self, _kid: &'a str) -> Result<Vec<u8>> {
        Ok(MOCK_KEYPAIR.public.to_bytes().to_vec())
    }
}

pub trait Storage {
    fn fetch_claims(&self, request_claims: &StandardClaims<IndividualClaimRequest>) -> StandardClaims<ClaimValue>;
}

#[derive(Default, Debug)]
pub struct MemoryStorage {
    data: StandardClaims<ClaimValue>,
}

impl MemoryStorage {
    pub fn new(data: StandardClaims<ClaimValue>) -> Self {
        MemoryStorage { data }
    }
}

impl Storage for MemoryStorage {
    fn fetch_claims(&self, request_claims: &StandardClaims<IndividualClaimRequest>) -> StandardClaims<ClaimValue> {
        let mut present = StandardClaims::default();

        macro_rules! present_if {
            ($claim:ident) => {
                if request_claims.$claim.is_some() {
                    present.$claim = self.data.$claim.clone();
                }
            };
        }

        present_if!(name);
        present_if!(family_name);
        present_if!(given_name);
        present_if!(middle_name);
        present_if!(nickname);
        present_if!(preferred_username);
        present_if!(profile);
        present_if!(picture);
        present_if!(website);
        present_if!(gender);
        present_if!(birthdate);
        present_if!(zoneinfo);
        present_if!(locale);
        present_if!(updated_at);
        present_if!(email);
        present_if!(email_verified);
        present_if!(address);
        present_if!(phone_number);
        present_if!(phone_number_verified);

        present
    }
}

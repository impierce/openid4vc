// Move this to the mock repo.
pub mod memory_storage;

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use siopv2::{StandardClaimsRequests, StandardClaimsValues};

pub trait Storage {
    fn fetch_claims(&self, request_claims: &StandardClaimsRequests) -> StandardClaimsValues;
}

#[derive(Default, Debug)]
pub struct MemoryStorage {
    data: StandardClaimsValues,
}

impl MemoryStorage {
    pub fn new(data: StandardClaimsValues) -> Self {
        MemoryStorage { data }
    }
}

impl Storage for MemoryStorage {
    fn fetch_claims(&self, request_claims: &StandardClaimsRequests) -> StandardClaimsValues {
        let mut present = StandardClaimsValues::default();

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

// Get the claims from a JWT without performing validation.
pub fn get_jwt_claims(jwt: &serde_json::Value) -> serde_json::Value {
    let key = DecodingKey::from_secret(&[]);
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.insecure_disable_signature_validation();
    decode(jwt.as_str().unwrap(), &key, &validation).unwrap().claims
}

use crate::{claims::Claim, StandardClaims};

pub trait Storage {
    fn fetch_claims(&self, request_claims: &StandardClaims) -> StandardClaims;
}

#[derive(Default, Debug)]
pub struct MemoryStorage {
    data: StandardClaims,
}

impl MemoryStorage {
    pub fn new(data: StandardClaims) -> Self {
        MemoryStorage { data }
    }
}

impl Storage for MemoryStorage {
    fn fetch_claims(&self, request_claims: &StandardClaims) -> StandardClaims {
        let mut present = StandardClaims::default();

        macro_rules! present_if {
            ($claim:ident) => {
                if let Some(claim) = &request_claims.$claim {
                    match claim {
                        Claim::Request(_) | Claim::Default => present.$claim = self.data.$claim.clone(),
                        _ => {}
                    }
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

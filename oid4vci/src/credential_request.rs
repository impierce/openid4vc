use crate::credential_definition::CredentialDefinition;
use dif_presentation_exchange::ClaimFormatDesignation;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct CredentialRequest {
    pub format: ClaimFormatDesignation,
    pub credential_definition: CredentialDefinition,
    pub proof: Option<Proof>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Proof {
    pub proof_type: String,
    pub jwt: String,
}

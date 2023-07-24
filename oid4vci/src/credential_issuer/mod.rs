pub mod authorization_server_metadata;
pub mod credential_issuer_metadata;

use self::{
    authorization_server_metadata::AuthorizationServerMetadata, credential_issuer_metadata::CredentialIssuerMetadata,
};
use crate::{proof::ProofOfPossession, Proof};
use oid4vc_core::{authentication::subject::SigningSubject, Decoder};

#[derive(Clone)]
pub struct CredentialIssuer {
    pub subject: SigningSubject,
    pub metadata: CredentialIssuerMetadata,
    pub authorization_server_metadata: AuthorizationServerMetadata,
}

impl CredentialIssuer {
    pub async fn validate_proof(&self, proof: Proof, decoder: Decoder) -> anyhow::Result<ProofOfPossession> {
        match proof {
            Proof::Jwt { jwt, .. } => decoder.decode(jwt).await,
            Proof::Cwt { .. } => unimplemented!("CWT is not supported yet"),
        }
    }
}

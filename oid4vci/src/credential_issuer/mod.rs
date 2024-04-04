pub mod authorization_server_metadata;
pub mod credential_configurations_supported;
pub mod credential_issuer_metadata;

use self::{
    authorization_server_metadata::AuthorizationServerMetadata, credential_issuer_metadata::CredentialIssuerMetadata,
};
use crate::{credential_format_profiles::CredentialFormatCollection, proof::ProofOfPossession, KeyProofType};
use oid4vc_core::{authentication::subject::SigningSubject, Decoder};

#[derive(Clone)]
pub struct CredentialIssuer<CFC>
where
    CFC: CredentialFormatCollection,
{
    pub subject: SigningSubject,
    pub metadata: CredentialIssuerMetadata<CFC>,
    pub authorization_server_metadata: AuthorizationServerMetadata,
}

impl<CFC: CredentialFormatCollection> CredentialIssuer<CFC> {
    pub async fn validate_proof(&self, proof: KeyProofType, decoder: Decoder) -> anyhow::Result<ProofOfPossession> {
        match proof {
            KeyProofType::Jwt { jwt, .. } => decoder.decode(jwt).await,
            KeyProofType::Cwt { .. } => unimplemented!("CWT is not supported yet"),
        }
    }
}

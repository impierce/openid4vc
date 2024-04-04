pub mod authorization_server_metadata;
pub mod credential_issuer_metadata;
pub mod credentials_supported;

use self::{
    authorization_server_metadata::AuthorizationServerMetadata, credential_issuer_metadata::CredentialIssuerMetadata,
};
use crate::{credential_format_profiles::CredentialFormatCollection, proof::ProofOfPossession, Proof};
use oid4vc_core::{authentication::subject::SigningSubject, Validator};

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
    pub async fn validate_proof(&self, proof: Proof, validator: Validator) -> anyhow::Result<ProofOfPossession> {
        match proof {
            Proof::Jwt { jwt, .. } => validator.decode(jwt).await,
            Proof::Cwt { .. } => unimplemented!("CWT is not supported yet"),
        }
    }
}

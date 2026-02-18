pub mod authorization_server_metadata;
pub mod credential_configurations_supported;
pub mod credential_issuer_metadata;

use self::{
    authorization_server_metadata::AuthorizationServerMetadata, credential_issuer_metadata::CredentialIssuerMetadata,
};
use crate::{proof::ProofOfPossession, proofs::Proofs};
use oid4vc_core::{authentication::subject::SigningSubject, Validator};

#[derive(Clone)]
pub struct CredentialIssuer {
    pub subject: SigningSubject,
    pub metadata: CredentialIssuerMetadata,
    pub authorization_server_metadata: AuthorizationServerMetadata,
}

impl CredentialIssuer {
    pub async fn validate_proofs(
        &self,
        proofs: Proofs,
        validator: Validator,
    ) -> anyhow::Result<Vec<ProofOfPossession>> {
        if proofs.jwt.is_empty() {
            return Err(anyhow::anyhow!("No JWTs found in proofs"));
        }

        let mut validated_proofs = Vec::new();
        for jwt in &proofs.jwt {
            let proof_of_possession = validator.decode(jwt.clone()).await?;
            validated_proofs.push(proof_of_possession);
        }

        Ok(validated_proofs)
    }
}

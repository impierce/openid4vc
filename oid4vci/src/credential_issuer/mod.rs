pub mod authorization_server_metadata;
pub mod credential_issuer_metadata;

use self::{
    authorization_server_metadata::AuthorizationServerMetadata, credential_issuer_metadata::CredentialIssuerMetadata,
};
use crate::{
    credential_offer::{AuthorizationCode, PreAuthorizedCode},
    credential_response::CredentialResponse,
    proof::ProofOfPossession,
    token_response::TokenResponse,
    wallet::SigningSubject,
    Proof,
};
use oid4vc_core::Decoder;
use reqwest::Url;

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

pub trait Storage: Send + Sync + 'static {
    fn get_authorization_code(&self) -> Option<AuthorizationCode>;
    fn get_pre_authorized_code(&self) -> Option<PreAuthorizedCode>;
    fn get_token_response(&self, code: String) -> Option<TokenResponse>;
    fn get_credential_response(
        &self,
        access_token: String,
        subject_did: Url,
        issuer_did: Url,
        subject: SigningSubject,
    ) -> Option<CredentialResponse>;
}

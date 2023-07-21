use crate::{
    authorization_server_metadata::AuthorizationServerMetadata,
    credential_issuer_metadata::CredentialIssuerMetadata,
    credential_offer::{AuthorizationCode, PreAuthorizedCode},
    credential_response::CredentialResponse,
    token_response::TokenResponse,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CredentialIssuer<S>
where
    S: Storage,
{
    pub metadata: CredentialIssuerMetadata,
    pub authorization_server_metadata: AuthorizationServerMetadata,
    pub storage: S,
}

pub trait Storage: Send + Sync + 'static {
    fn get_authorization_code(&self) -> Option<AuthorizationCode>;
    fn get_pre_authorized_code(&self) -> Option<PreAuthorizedCode>;
    fn get_token_response(&self, code: String) -> Option<TokenResponse>;
    fn get_credential_response(&self, access_token: String) -> Option<CredentialResponse>;
}

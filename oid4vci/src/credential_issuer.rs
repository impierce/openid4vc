use crate::{
    authorization_server_metadata::AuthorizationServerMetadata,
    credential_issuer_metadata::CredentialIssuerMetadata,
    credential_offer::{AuthorizationCode, PreAuthorizedCode},
    token_response::TokenResponse,
};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

lazy_static! {
    pub static ref PRE_AUTHORIZED_CODE: PreAuthorizedCode = PreAuthorizedCode {
        pre_authorized_code: "adhjhdjajkdkhjhdj".to_string(),
        ..Default::default()
    };
    pub static ref USER_PIN: String = "493536".to_string();
}

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
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MemStorage;

impl Storage for MemStorage {
    fn get_authorization_code(&self) -> Option<AuthorizationCode> {
        None
    }

    fn get_pre_authorized_code(&self) -> Option<PreAuthorizedCode> {
        Some(PRE_AUTHORIZED_CODE.clone())
    }

    fn get_token_response(&self, code: String) -> Option<TokenResponse> {
        (code == PRE_AUTHORIZED_CODE.pre_authorized_code).then_some(TokenResponse {
            // TODO: dynamically create this.
            access_token: "czZCaGRSa3F0MzpnWDFmQmF0M2JW".to_string(),
            token_type: "bearer".to_string(),
            expires_in: Some(86400),
            refresh_token: None,
            scope: None,
            c_nonce: Some("c_nonce".to_string()),
            c_nonce_expires_in: Some(86400),
        })
    }
}

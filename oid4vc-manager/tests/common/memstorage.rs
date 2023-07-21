use lazy_static::lazy_static;
use oid4vci::{
    credential_issuer::Storage,
    credential_offer::{AuthorizationCode, PreAuthorizedCode},
    credential_response::CredentialResponse,
    token_response::TokenResponse,
};
use oid4vp::ClaimFormatDesignation;
use serde::{Deserialize, Serialize};

lazy_static! {
    pub static ref PRE_AUTHORIZED_CODE: PreAuthorizedCode = PreAuthorizedCode {
        pre_authorized_code: "adhjhdjajkdkhjhdj".to_string(),
        ..Default::default()
    };
    pub static ref USER_PIN: String = "493536".to_string();
    pub static ref ACCESS_TOKEN: String = "czZCaGRSa3F0MzpnWDFmQmF0M2JW".to_string();
    pub static ref C_NONCE: String = "tZignsnFbp".to_string();
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
            access_token: ACCESS_TOKEN.clone(),
            token_type: "bearer".to_string(),
            expires_in: Some(86400),
            refresh_token: None,
            scope: None,
            c_nonce: Some(C_NONCE.clone()),
            c_nonce_expires_in: Some(86400),
        })
    }

    fn get_credential_response(&self, access_token: String) -> Option<CredentialResponse> {
        (access_token == ACCESS_TOKEN.clone()).then_some(CredentialResponse {
            format: ClaimFormatDesignation::JwtVcJson,
            credential: Some(serde_json::json!("\"CREDENTIAL\"")),
            transaction_id: None,
            c_nonce: Some(C_NONCE.clone()),
            c_nonce_expires_in: Some(86400),
        })
    }
}

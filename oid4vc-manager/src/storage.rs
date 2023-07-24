use oid4vc_core::authentication::subject::SigningSubject;
use oid4vci::{
    credential_offer::{AuthorizationCode, PreAuthorizedCode},
    credential_response::CredentialResponse,
    credentials_supported::CredentialsSupportedJson,
    token_request::TokenRequest,
    token_response::TokenResponse,
    AuthorizationResponse,
};
use reqwest::Url;

// Represents the Credential Issuer's server logic.
pub trait Storage: Send + Sync + 'static {
    fn get_credentials_supported(&self) -> Vec<CredentialsSupportedJson>;
    fn get_authorization_response(&self) -> Option<AuthorizationResponse>;
    fn get_authorization_code(&self) -> Option<AuthorizationCode>;
    fn get_pre_authorized_code(&self) -> Option<PreAuthorizedCode>;
    fn get_token_response(&self, token_request: TokenRequest) -> Option<TokenResponse>;
    fn get_credential_response(
        &self,
        access_token: String,
        subject_did: Url,
        issuer_did: Url,
        subject: SigningSubject,
    ) -> Option<CredentialResponse>;
}

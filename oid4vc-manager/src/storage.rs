use std::collections::HashMap;

use oid4vc_core::authentication::subject::SigningSubject;
use oid4vci::{
    authorization_response::AuthorizationResponse,
    credential_format_profiles::CredentialFormatCollection,
    credential_issuer::credential_configurations_supported::CredentialConfigurationsSupportedObject,
    credential_offer::{AuthorizationCode, PreAuthorizedCode},
    credential_response::CredentialResponse,
    token_request::TokenRequest,
    token_response::TokenResponse,
};
use reqwest::Url;

// Represents the Credential Issuer's server logic.
pub trait Storage<CFC>: Send + Sync + 'static
where
    CFC: CredentialFormatCollection,
{
    fn get_credential_configurations_supported(&self) -> HashMap<String, CredentialConfigurationsSupportedObject<CFC>>;
    fn get_authorization_response(&self) -> Option<AuthorizationResponse>;
    fn get_authorization_code(&self) -> Option<AuthorizationCode>;
    fn get_pre_authorized_code(&self) -> Option<PreAuthorizedCode>;
    fn get_token_response(&self, token_request: TokenRequest) -> Option<TokenResponse>;
    fn get_credential_response(
        &self,
        access_token: String,
        subject_did: Url,
        issuer_did: Url,
        credential_format: CFC,
        subject: SigningSubject,
    ) -> Option<CredentialResponse>;
    fn get_state(&self) -> Option<String>;
    fn set_state(&mut self, state: String);
}

use std::fs::File;

use jsonwebtoken::{Algorithm, Header};
use lazy_static::lazy_static;
use oid4vc_core::{authentication::subject::SigningSubject, generate_authorization_code, jwt};
use oid4vc_manager::storage::Storage;
use oid4vci::{
    authorization_response::AuthorizationResponse,
    credential_format_profiles::CredentialFormatCollection,
    credential_issuer::credentials_supported::CredentialsSupportedObject,
    credential_offer::{AuthorizationCode, PreAuthorizedCode},
    credential_response::CredentialResponse,
    token_request::TokenRequest,
    token_response::TokenResponse,
    VerifiableCredentialJwt,
};
use oid4vp::ClaimFormatDesignation;
use reqwest::Url;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

lazy_static! {
    pub static ref CODE: String = generate_authorization_code(16);
    pub static ref PRE_AUTHORIZED_CODE: PreAuthorizedCode = PreAuthorizedCode {
        pre_authorized_code: generate_authorization_code(16),
        ..Default::default()
    };
    pub static ref USER_PIN: String = "493536".to_string();
    pub static ref ACCESS_TOKEN: String = "czZCaGRSa3F0MzpnWDFmQmF0M2JW".to_string();
    pub static ref C_NONCE: String = "tZignsnFbp".to_string();
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MemoryStorage;

impl<CFC: CredentialFormatCollection + DeserializeOwned> Storage<CFC> for MemoryStorage {
    fn get_credentials_supported(&self) -> Vec<CredentialsSupportedObject<CFC>> {
        let credentials_supported_object =
            File::open("./tests/common/credentials_supported_objects/university_degree.json").unwrap();
        vec![serde_json::from_reader(credentials_supported_object).unwrap()]
    }

    fn get_authorization_code(&self) -> Option<AuthorizationCode> {
        None
    }

    fn get_authorization_response(&self) -> Option<AuthorizationResponse> {
        Some(AuthorizationResponse {
            code: CODE.clone(),
            state: None,
        })
    }

    fn get_pre_authorized_code(&self) -> Option<PreAuthorizedCode> {
        Some(PRE_AUTHORIZED_CODE.clone())
    }

    fn get_token_response(&self, token_request: TokenRequest) -> Option<TokenResponse> {
        match token_request {
            TokenRequest::AuthorizationCode { code, .. } => code == CODE.clone(),
            TokenRequest::PreAuthorizedCode {
                pre_authorized_code, ..
            } => pre_authorized_code == PRE_AUTHORIZED_CODE.pre_authorized_code,
        }
        .then_some(TokenResponse {
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

    fn get_credential_response(
        &self,
        access_token: String,
        subject_did: Url,
        issuer_did: Url,
        signer: SigningSubject,
    ) -> Option<CredentialResponse> {
        let credential = File::open("./tests/common/credentials/university_degree.json").unwrap();
        let mut verifiable_credential: serde_json::Value = serde_json::from_reader(credential).unwrap();
        verifiable_credential["issuer"] = serde_json::json!(issuer_did);
        verifiable_credential["credentialSubject"]["id"] = serde_json::json!(subject_did);

        (access_token == ACCESS_TOKEN.clone()).then_some(CredentialResponse {
            format: ClaimFormatDesignation::JwtVcJson,
            credential: serde_json::to_value(
                jwt::encode(
                    signer.clone(),
                    Header::new(Algorithm::EdDSA),
                    VerifiableCredentialJwt::builder()
                        .sub(subject_did.clone())
                        .iss(issuer_did.clone())
                        .iat(0)
                        .exp(9999999999i64)
                        .verifiable_credential(verifiable_credential)
                        .build()
                        .ok(),
                )
                .ok(),
            )
            .ok(),
            transaction_id: None,
            c_nonce: Some(C_NONCE.clone()),
            c_nonce_expires_in: Some(86400),
        })
    }
}

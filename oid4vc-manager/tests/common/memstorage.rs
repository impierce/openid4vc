use jsonwebtoken::{Algorithm, Header};
use lazy_static::lazy_static;
use oid4vc_core::jwt;
use oid4vci::{
    credential_issuer::Storage,
    credential_offer::{AuthorizationCode, PreAuthorizedCode},
    credential_response::CredentialResponse,
    token_request::TokenRequest,
    token_response::TokenResponse,
    wallet::SigningSubject,
    AuthorizationResponse, VerifiableCredentialJwt,
};
use oid4vp::ClaimFormatDesignation;
use reqwest::Url;
use serde::{Deserialize, Serialize};

lazy_static! {
    pub static ref CODE: String = "SplxlOBeZQQYbYS6WxSbIA".to_string();
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
            TokenRequest::AuthorizationCode { code, .. } => {
                (code == CODE.clone()).then_some(TokenResponse {
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
            TokenRequest::PreAuthorizedCode {
                pre_authorized_code, ..
            } => {
                (pre_authorized_code == PRE_AUTHORIZED_CODE.pre_authorized_code).then_some(TokenResponse {
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
        }
    }

    fn get_credential_response(
        &self,
        access_token: String,
        subject_did: Url,
        issuer_did: Url,
        signer: SigningSubject,
    ) -> Option<CredentialResponse> {
        (access_token == ACCESS_TOKEN.clone()).then_some(CredentialResponse {
            format: ClaimFormatDesignation::JwtVcJson,
            credential: Some(
                serde_json::to_value(
                    jwt::encode(
                        signer.clone(),
                        Header::new(Algorithm::EdDSA),
                        VerifiableCredentialJwt::builder()
                            .sub(subject_did.clone())
                            .iss(issuer_did.clone())
                            .iat(0)
                            .exp(9999999999i64)
                            .verifiable_credential(serde_json::json!({
                                "@context": [
                                    "https://www.w3.org/2018/credentials/v1",
                                    "https://www.w3.org/2018/credentials/examples/v1"
                                ],
                                "type": [
                                    "VerifiableCredential",
                                    "PersonalInformation"
                                ],
                                "issuanceDate": "2022-01-01T00:00:00Z",
                                "issuer": issuer_did,
                                "credentialSubject": {
                                "id": subject_did,
                                "givenName": "Ferris",
                                "familyName": "Crabman",
                                "email": "ferris.crabman@crabmail.com",
                                "birthdate": "1985-05-21"
                                }
                            }))
                            .build()
                            .unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            ),
            transaction_id: None,
            c_nonce: Some(C_NONCE.clone()),
            c_nonce_expires_in: Some(86400),
        })
    }
}

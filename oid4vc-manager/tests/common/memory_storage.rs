use std::{collections::HashMap, fs::File};

use futures::executor::block_on;
use jsonwebtoken::{Algorithm, Header};
use oid4vc_core::{authentication::subject::SigningSubject, generate_authorization_code, jwt};
use oid4vc_manager::storage::Storage;
use oid4vci::{
    VerifiableCredentialJwt,
    authorization_response::AuthorizationResponse,
    credential_issuer::credential_configurations_supported::CredentialConfigurationsSupportedObject,
    credential_offer::{AuthorizationCode, PreAuthorizedCode},
    credential_response::{CredentialResponse, CredentialResponseObject, CredentialResponseType},
    token_request::TokenRequest,
    token_response::TokenResponse,
    wallet::PushedAuthorizationResponse,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::LazyLock;
use uuid::Uuid;

pub static CODE: LazyLock<String> = LazyLock::new(|| generate_authorization_code(16));
pub static PRE_AUTHORIZED_CODE: LazyLock<PreAuthorizedCode> = LazyLock::new(|| PreAuthorizedCode {
    pre_authorized_code: generate_authorization_code(16),
    ..Default::default()
});
pub static ACCESS_TOKEN: LazyLock<String> = LazyLock::new(|| "czZCaGRSa3F0MzpnWDFmQmF0M2JW".to_string());
pub static C_NONCE: LazyLock<String> = LazyLock::new(|| "tZignsnFbp".to_string());
pub static REQUEST_URI: LazyLock<String> = LazyLock::new(|| Uuid::new_v4().to_string());

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MemoryStorage;

impl Storage for MemoryStorage {
    fn get_credential_configurations_supported(&self) -> HashMap<String, CredentialConfigurationsSupportedObject> {
        vec![
            (
                "UniversityDegree_JWT".to_string(),
                serde_json::from_reader(
                    File::open("./tests/common/credential_configurations_supported_objects/university_degree.json")
                        .unwrap(),
                )
                .unwrap(),
            ),
            (
                "DriverLicense_JWT".to_string(),
                serde_json::from_reader(
                    File::open("./tests/common/credential_configurations_supported_objects/driver_license.json")
                        .unwrap(),
                )
                .unwrap(),
            ),
        ]
        .into_iter()
        .collect()
    }

    fn get_pushed_authorization_response(&self) -> Option<PushedAuthorizationResponse> {
        Some(PushedAuthorizationResponse {
            request_uri: REQUEST_URI.clone(),
            expires_in: 3600,
        })
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
            authorization_details: None,
        })
    }

    fn get_credential_response(
        &self,
        access_token: String,
        credential_configuration_id: String,
        subject_did: Url,
        issuer_did: Url,
        signer: SigningSubject,
    ) -> Option<CredentialResponse> {
        let credential_json = match credential_configuration_id.as_str() {
            "UniversityDegree_JWT" => File::open("./tests/common/credentials/university_degree.json").unwrap(),
            "DriverLicense_JWT" => File::open("./tests/common/credentials/driver_license.json").unwrap(),
            _ => unreachable!(),
        };

        let mut verifiable_credential: serde_json::Value = serde_json::from_reader(credential_json).unwrap();
        verifiable_credential["issuer"] = json!(issuer_did);
        verifiable_credential["credentialSubject"]["id"] = json!(subject_did);

        (access_token == ACCESS_TOKEN.clone()).then_some(CredentialResponse {
            credential: CredentialResponseType::Immediate {
                credentials: vec![CredentialResponseObject {
                    credential: block_on(async {
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
                            "did:key",
                        )
                        .await
                        .unwrap()
                    }),
                }],
                notification_id: None,
            },
        })
    }

    fn get_state(&self) -> Option<String> {
        None
    }

    fn set_state(&mut self, _state: String) {}
}

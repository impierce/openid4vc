use crate::common::memstorage::MemStorage;
use did_key::{generate, Ed25519KeyPair};
use lazy_static::lazy_static;
use oid4vc_manager::{
    methods::key_method::KeySubject,
    servers::credential_issuer::{CredentialIssuerManager, Server},
};
use oid4vci::{
    authorization_details::{AuthorizationDetails, OpenIDCredential},
    credential_format::CredentialFormat,
    credential_format_profiles::w3c_verifiable_credentials::jwt_vc_json::JwtVcJson,
    credentials_supported::CredentialsSupportedObject,
    token_request::{AuthorizationCode, TokenRequest},
    Wallet,
};
use std::sync::Arc;

lazy_static! {
    static ref CREDENTIALS_SUPPORTED: CredentialsSupportedObject<JwtVcJson> = serde_json::from_str(
        r##"{
            "format": "jwt_vc_json",
            "id": "UniversityDegree_JWT",
            "cryptographic_binding_methods_supported": [
                "did:key",
                "did:iota"
            ],
            "cryptographic_suites_supported": [
                "EdDSA"
            ],
            "credential_definition":{
                "type": [
                    "VerifiableCredential",
                    "UniversityDegreeCredential"
                ],
                "credentialSubject": {
                    "given_name": {
                        "display": [
                            {
                                "name": "Given Name",
                                "locale": "en-US"
                            }
                        ]
                    },
                    "last_name": {
                        "display": [
                            {
                                "name": "Surname",
                                "locale": "en-US"
                            }
                        ]
                    },
                    "degree": {},
                    "gpa": {
                        "display": [
                            {
                                "name": "GPA"
                            }
                        ]
                    }
                }
            },
            "proof_types_supported": [
                "jwt"
            ],
            "display": [
                {
                    "name": "University Credential",
                    "locale": "en-US",
                    "logo": {
                        "url": "https://exampleuniversity.com/public/logo.png",
                        "alt_text": "a square logo of a university"
                    },
                    "background_color": "#12107c",
                    "text_color": "#FFFFFF"
                }
            ]
        }"##
    )
    .unwrap();
}

#[tokio::test]
async fn test_authorization_code_flow() {
    let mut credential_issuer = Server::setup(
        CredentialIssuerManager::new(
            vec![CREDENTIALS_SUPPORTED.clone().into()],
            None,
            MemStorage,
            [Arc::new(KeySubject::from_keypair(generate::<Ed25519KeyPair>(Some(
                "this-is-a-very-UNSAFE-issuer-secret-key".as_bytes().try_into().unwrap(),
            ))))],
        )
        .unwrap(),
    )
    .unwrap();

    credential_issuer.start_server().unwrap();

    let wallet = Wallet::new(Arc::new(KeySubject::new()));

    let credential_issuer_url = credential_issuer
        .credential_issuer_manager
        .credential_issuer_url()
        .unwrap();

    let authorization_server_metadata = wallet
        .get_authorization_server_metadata(credential_issuer_url.clone())
        .await
        .unwrap();

    let credential_issuer_metadata = wallet
        .get_credential_issuer_metadata(credential_issuer_url.clone())
        .await
        .unwrap();

    let university_degree_credential_format = serde_json::from_value::<CredentialFormat<JwtVcJson>>(
        credential_issuer_metadata
            .credentials_supported
            .get(0)
            .unwrap()
            .0
            .clone(),
    )
    .unwrap();

    let authorization_response = wallet
        .get_authorization_code(
            authorization_server_metadata.authorization_endpoint,
            AuthorizationDetails {
                type_: OpenIDCredential,
                locations: None,
                credential_format: university_degree_credential_format.clone(),
            },
        )
        .await
        .unwrap();

    dbg!(&authorization_response);

    let token_request = TokenRequest::AuthorizationCode {
        grant_type: AuthorizationCode,
        code: authorization_response.code,
        code_verifier: None,
        redirect_uri: None,
    };

    let token_response = wallet
        .get_access_token(authorization_server_metadata.token_endpoint, token_request)
        .await
        .unwrap();

    let credential_response = wallet
        .get_credential(
            credential_issuer_metadata,
            &token_response,
            university_degree_credential_format,
        )
        .await
        .unwrap();

    dbg!(&credential_response);
}

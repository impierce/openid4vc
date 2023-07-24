use crate::common::memory_storage::MemoryStorage;
use did_key::{generate, Ed25519KeyPair};
use oid4vc_manager::{
    managers::credential_issuer::CredentialIssuerManager, methods::key_method::KeySubject,
    servers::credential_issuer::Server,
};
use oid4vci::{
    authorization_details::{AuthorizationDetails, OpenIDCredential},
    credential_format::CredentialFormat,
    credential_format_profiles::w3c_verifiable_credentials::jwt_vc_json::JwtVcJson,
    token_request::{AuthorizationCode, TokenRequest},
    Wallet,
};
use std::{fs::File, io::BufReader, sync::Arc};

#[tokio::test]
async fn test_authorization_code_flow() {
    let file = File::open("./tests/common/credentials_supported_objects/university_degree.json").unwrap();
    let reader = BufReader::new(file);

    let mut credential_issuer = Server::setup(
        CredentialIssuerManager::new(
            vec![serde_json::from_reader(reader).unwrap()],
            None,
            MemoryStorage,
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

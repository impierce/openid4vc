use crate::common::{get_jwt_claims, memory_storage::MemoryStorage};
use did_key::{generate, Ed25519KeyPair};
use oid4vc_core::Subject;
use oid4vc_manager::{
    managers::credential_issuer::CredentialIssuerManager, methods::key_method::KeySubject,
    servers::credential_issuer::Server,
};
use oid4vci::{
    authorization_details::{AuthorizationDetails, OpenIDCredential},
    credential_format_profiles::{w3c_verifiable_credentials::jwt_vc_json::JwtVcJson, CredentialFormat},
    token_request::{AuthorizationCode, TokenRequest},
    Wallet,
};
use std::sync::Arc;

// TODO: Current Authorization Code Flow is not fully conformant to the spec. Issue: https://github.com/impierce/openid4vc/issues/46
#[tokio::test]
async fn test_authorization_code_flow() {
    // Setup the credential issuer.
    let mut credential_issuer = Server::setup(
        CredentialIssuerManager::new(
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

    // Create a new subject.
    let subject = KeySubject::new();
    let subject_did = subject.identifier().unwrap();

    // Create a new wallet.
    let wallet = Wallet::new(Arc::new(subject));

    // Get the credential issuer url.
    let credential_issuer_url = credential_issuer
        .credential_issuer_manager
        .credential_issuer_url()
        .unwrap();

    // Get the authorization server metadata.
    let authorization_server_metadata = wallet
        .get_authorization_server_metadata(credential_issuer_url.clone())
        .await
        .unwrap();

    // Get the credential issuer metadata.
    let credential_issuer_metadata = wallet
        .get_credential_issuer_metadata(credential_issuer_url.clone())
        .await
        .unwrap();

    // Get the credential format for a university degree.
    let university_degree_credential_format = serde_json::from_value::<CredentialFormat<JwtVcJson>>(
        credential_issuer_metadata
            .credentials_supported
            .get(0)
            .unwrap()
            .0
            .clone(),
    )
    .unwrap();

    // Get the authorization code.
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

    let token_request = TokenRequest::AuthorizationCode {
        grant_type: AuthorizationCode,
        code: authorization_response.code,
        code_verifier: None,
        redirect_uri: None,
    };

    // Get the access token.
    let token_response = wallet
        .get_access_token(authorization_server_metadata.token_endpoint, token_request)
        .await
        .unwrap();

    // Get the credential.
    let credential_response = wallet
        .get_credential(
            credential_issuer_metadata,
            &token_response,
            university_degree_credential_format,
        )
        .await
        .unwrap();

    // Decode the JWT without performing validation
    let claims = get_jwt_claims(credential_response.credential.unwrap().clone());

    // Check the credential.
    assert_eq!(
        claims["vc"],
        serde_json::json!({
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "type": [
                "VerifiableCredential",
                "PersonalInformation"
            ],
            "issuanceDate": "2022-01-01T00:00:00Z",
            "issuer": credential_issuer_url,
            "credentialSubject": {
                "id": subject_did,
                "givenName": "Ferris",
                "familyName": "Crabman",
                "email": "ferris.crabman@crabmail.com",
                "birthdate": "1985-05-21"
            }
        })
    )
}

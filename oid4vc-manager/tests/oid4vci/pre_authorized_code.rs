use crate::common::memory_storage::MemoryStorage;
use did_key::{generate, Ed25519KeyPair};
use oid4vc_manager::{
    managers::credential_issuer::CredentialIssuerManager, methods::key_method::KeySubject,
    servers::credential_issuer::Server,
};
use oid4vci::{
    credential_format::CredentialFormat,
    credential_format_profiles::w3c_verifiable_credentials::jwt_vc_json::JwtVcJson,
    credential_offer::CredentialOfferQuery,
    token_request::{PreAuthorizedCode, TokenRequest},
    Wallet,
};
use std::{fs::File, io::BufReader, sync::Arc};

#[tokio::test]
async fn test_pre_authorized_code_flow() {
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

    // Get the credential offer url.
    let credential_offer_url = credential_issuer
        .credential_issuer_manager
        .credential_offer_uri()
        .unwrap();

    // Parse the credential offer url.
    let credential_offer = match credential_offer_url.parse().unwrap() {
        CredentialOfferQuery::CredentialOffer(credential_offer) => credential_offer,
        _ => unreachable!(),
    };

    let university_degree: CredentialFormat<JwtVcJson> =
        serde_json::from_value(credential_offer.credentials.get(0).unwrap().clone()).unwrap();

    let credential_issuer_url = credential_offer.credential_issuer;

    let wallet = Wallet::new(Arc::new(KeySubject::new()));

    let authorization_server_metadata = wallet
        .get_authorization_server_metadata(credential_issuer_url.clone())
        .await
        .unwrap();

    let credential_issuer_metadata = wallet
        .get_credential_issuer_metadata(credential_issuer_url.clone())
        .await
        .unwrap();

    let token_request = TokenRequest::PreAuthorizedCode {
        grant_type: PreAuthorizedCode,
        pre_authorized_code: credential_offer
            .grants
            .unwrap()
            .pre_authorized_code
            .unwrap()
            .pre_authorized_code,
        user_pin: Some("493536".to_string()),
    };

    let token_response = wallet
        .get_access_token(authorization_server_metadata.token_endpoint, token_request)
        .await
        .unwrap();

    let credential_response = wallet
        .get_credential(credential_issuer_metadata, &token_response, university_degree)
        .await
        .unwrap();

    dbg!(&credential_response);
}

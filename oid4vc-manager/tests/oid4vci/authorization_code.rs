use crate::common::{get_jwt_claims, memory_storage::MemoryStorage};
use did_key::{generate, Ed25519KeyPair};
use jsonwebtoken::Algorithm;
use oid4vc_core::Subject;
use oid4vc_manager::{
    managers::credential_issuer::CredentialIssuerManager, methods::key_method::KeySubject,
    servers::credential_issuer::Server,
};
use oid4vci::{
    authorization_details::{AuthorizationDetailsObject, CredentialConfigurationOrFormat, OpenidCredential},
    credential_format_profiles::{CredentialFormats, WithParameters},
    credential_response::{CredentialResponse, CredentialResponseType},
    token_request::TokenRequest,
    Wallet,
};
use std::sync::Arc;

// TODO: Current Authorization Code Flow is not fully conformant to the spec. Issue: https://github.com/impierce/openid4vc/issues/46
#[tokio::test]
async fn test_authorization_code_flow() {
    // Setup the credential issuer.
    let mut credential_issuer: Server<_, _> = Server::setup(
        CredentialIssuerManager::<_, CredentialFormats<WithParameters>>::new(
            None,
            MemoryStorage,
            Arc::new(KeySubject::from_keypair(
                generate::<Ed25519KeyPair>(Some(
                    "this-is-a-very-UNSAFE-issuer-secret-key".as_bytes().try_into().unwrap(),
                )),
                None,
            )),
        )
        .unwrap(),
        None,
    )
    .unwrap()
    .detached(true);
    credential_issuer.start_server().await.unwrap();

    // Create a new subject.
    let subject = KeySubject::new();
    let subject_did = subject.identifier("did:key", Algorithm::EdDSA).await.unwrap();

    // Create a new wallet.
    let wallet: Wallet = Wallet::new(Arc::new(subject), "did:key", vec![Algorithm::EdDSA]).unwrap();

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
    let university_degree_credential_format = credential_issuer_metadata
        .credential_configurations_supported
        .get("UniversityDegree_JWT")
        .unwrap()
        .clone();

    // Get the authorization code.
    let authorization_response = wallet
        .get_authorization_code(
            authorization_server_metadata.authorization_endpoint.unwrap(),
            vec![AuthorizationDetailsObject {
                r#type: OpenidCredential::Type,
                locations: None,
                credential_configuration_or_format: CredentialConfigurationOrFormat::CredentialFormat(
                    university_degree_credential_format.credential_format.clone(),
                ),
            }
            .into()],
        )
        .await
        .unwrap();

    let token_request = TokenRequest::AuthorizationCode {
        code: authorization_response.code,
        code_verifier: None,
        redirect_uri: None,
    };

    // Get the access token.
    let token_response = wallet
        .get_access_token(authorization_server_metadata.token_endpoint.unwrap(), token_request)
        .await
        .unwrap();

    // Get the credential.
    let credential_response: CredentialResponse = wallet
        .get_credential(
            credential_issuer_metadata,
            &token_response,
            &university_degree_credential_format,
        )
        .await
        .unwrap();

    let credential = match credential_response.credential {
        CredentialResponseType::Immediate { credential, .. } => credential,
        _ => panic!("Credential was not a JWT VC JSON."),
    };

    // Decode the JWT without performing validation
    let claims = get_jwt_claims(&credential);

    // Check the credential.
    assert_eq!(
        claims["vc"],
        serde_json::json!({
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "id": "UniversityDegree_JWT",
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

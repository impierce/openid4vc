use crate::common::{get_jwt_claims, memory_storage::MemoryStorage};
use did_key::{generate, Ed25519KeyPair};
use oid4vc_core::Subject;
use oid4vc_manager::{
    managers::credential_issuer::CredentialIssuerManager, methods::key_method::KeySubject,
    servers::credential_issuer::Server,
};
use oid4vci::{
    credential_format_profiles::{CredentialFormats, WithParameters},
    credential_offer::{CredentialOffer, CredentialOfferQuery, CredentialsObject, Grants},
    credential_response::{BatchCredentialResponse, CredentialResponse, CredentialResponseType},
    token_request::{PreAuthorizedCode, TokenRequest},
    Wallet,
};
use std::sync::Arc;

#[rstest::rstest]
#[case(false, false)]
#[case(false, true)]
#[case(true, false)]
#[case(true, true)]
#[tokio::test]
async fn test_pre_authorized_code_flow(#[case] batch: bool, #[case] by_reference: bool) {
    // Setup the credential issuer.
    let mut credential_issuer = Server::<_, CredentialFormats<WithParameters>>::setup(
        CredentialIssuerManager::new(
            None,
            MemoryStorage,
            [Arc::new(KeySubject::from_keypair(
                generate::<Ed25519KeyPair>(Some(
                    "this-is-a-very-UNSAFE-issuer-secret-key".as_bytes().try_into().unwrap(),
                )),
                None,
            ))],
        )
        .unwrap(),
        None,
    )
    .unwrap()
    .detached(true);
    credential_issuer.start_server().await.unwrap();

    // Create a new subject.
    let subject = KeySubject::new();
    let subject_did = subject.identifier().unwrap();

    // Create a new wallet.
    let wallet = Wallet::new(Arc::new(subject));

    // Get the credential offer url.
    let credential_offer_query = credential_issuer
        .credential_issuer_manager
        .credential_offer_query(by_reference)
        .unwrap();

    // Parse the credential offer url.
    let credential_offer: CredentialOffer = match credential_offer_query.parse().unwrap() {
        CredentialOfferQuery::CredentialOffer(credential_offer) => credential_offer,
        CredentialOfferQuery::CredentialOfferUri(credential_offer_uri) => {
            wallet.get_credential_offer(credential_offer_uri).await.unwrap()
        }
    };
    dbg!(&credential_offer);
    // The credential offer contains a credential issuer url.
    let credential_issuer_url = credential_offer.credential_issuer;
    dbg!("HERE");

    // Get the authorization server metadata.
    let authorization_server_metadata = wallet
        .get_authorization_server_metadata(credential_issuer_url.clone())
        .await
        .unwrap();
    dbg!("HERE");

    assert_eq!(
        authorization_server_metadata.pre_authorized_grant_anonymous_access_supported,
        Some(true)
    );

    dbg!("HERE");
    // Get the credential issuer metadata.
    let credential_issuer_metadata = wallet
        .get_credential_issuer_metadata(credential_issuer_url.clone())
        .await
        .unwrap();

    dbg!("HERE");
    // Create a token request with grant_type `pre_authorized_code`.
    let token_request = match credential_offer.grants {
        Some(Grants {
            pre_authorized_code, ..
        }) => TokenRequest::PreAuthorizedCode {
            grant_type: PreAuthorizedCode,
            pre_authorized_code: pre_authorized_code.unwrap().pre_authorized_code,
            user_pin: Some("493536".to_string()),
        },
        None => unreachable!(),
    };

    dbg!("HERE");
    // Get an access token.
    let token_response = wallet
        .get_access_token(authorization_server_metadata.token_endpoint.unwrap(), token_request)
        .await
        .unwrap();
    dbg!("HERE");

    if !batch {
        // The credential offer contains a credential format for a university degree.
        let university_degree_credential_format = match credential_offer.credentials.get(0).unwrap().clone() {
            CredentialsObject::ByValue(credential_format) => credential_format,
            _ => unreachable!(),
        };

        dbg!(university_degree_credential_format.clone());

        dbg!("HERE");
        // Get the credential.
        let credential_response: CredentialResponse = wallet
            .get_credential(
                credential_issuer_metadata,
                &token_response,
                university_degree_credential_format,
            )
            .await
            .unwrap();

        dbg!("HERE");
        let credential = match credential_response.credential {
            CredentialResponseType::Immediate(CredentialFormats::JwtVcJson(credential)) => credential.credential,
            _ => panic!("Credential was not a JWT VC JSON."),
        };

        dbg!("HERE");
        // Decode the JWT without performing validation
        let claims = get_jwt_claims(&credential);

        dbg!("HERE");
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
    } else if batch {
        // The credential offer contains two credentials
        let credentials = credential_offer
            .credentials
            .into_iter()
            .map(|credential| match credential {
                CredentialsObject::ByValue(credential_format) => credential_format.clone(),
                _ => unreachable!(),
            })
            .collect::<Vec<_>>();

        dbg!("HERE");
        // Get the credential.
        let batch_credential_response: BatchCredentialResponse = wallet
            .get_batch_credential(credential_issuer_metadata, &token_response, credentials)
            .await
            .unwrap();

        dbg!("HERE");
        let credentials: Vec<_> = batch_credential_response
            .credential_responses
            .into_iter()
            .map(|credential_response| {
                let credential = match credential_response {
                    CredentialResponseType::Immediate(CredentialFormats::JwtVcJson(credential)) => {
                        credential.credential
                    }
                    _ => panic!("Credential was not a JWT VC JSON."),
                };

                // Decode the JWT without performing validation
                let claims = get_jwt_claims(&credential);
                claims
            })
            .collect();

        dbg!("HERE");
        // Check the "UniversityDegree_JWT" credential.
        assert_eq!(
            credentials[0]["vc"],
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
        );

        // Check the "DriverLicense_JWT" credential.
        assert_eq!(
            credentials[1]["vc"],
            serde_json::json!({
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://www.w3.org/2018/credentials/examples/v1"
                ],
                "id": "DriverLicense_JWT",
                "type": [
                    "VerifiableCredential",
                    "DriverLicenseCredential"
                ],
                "issuer": credential_issuer_url,
                "issuanceDate": "2022-08-15T09:30:00Z",
                "expirationDate": "2027-08-15T23:59:59Z",
                "credentialSubject": {
                    "id": subject_did,
                    "licenseClass": "Class C",
                    "issuedBy": "California",
                    "validity": "Valid"
                }
            })
        );
    }
}

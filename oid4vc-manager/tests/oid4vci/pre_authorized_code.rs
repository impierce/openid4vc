use crate::common::memstorage::MemStorage;
use lazy_static::lazy_static;
use oid4vc_manager::{methods::key_method::KeySubject, routers::credential_issuer::CredentialIssuerManager};
use oid4vci::{
    credential_offer::CredentialOfferQuery, credentials_supported::CredentialsSupportedObject, CredentialFormat,
    JwtVcJson, Wallet,
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
async fn test_pre_authorized_code_flow() {
    let storage = MemStorage;

    let credential_issuer_server =
        CredentialIssuerManager::run(vec![CREDENTIALS_SUPPORTED.clone().into()], None, storage).unwrap();

    // Get the credential offer url.
    let credential_offer_url = credential_issuer_server.credential_offer_uri().unwrap();

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

    let token_response = wallet
        .get_access_token(
            authorization_server_metadata.token_endpoint,
            credential_offer.grants.unwrap(),
            Some("493536".to_string()),
        )
        .await
        .unwrap();

    let credential_response = wallet
        .get_credential(credential_issuer_metadata, &token_response, university_degree)
        .await
        .unwrap();

    dbg!(credential_response);
}

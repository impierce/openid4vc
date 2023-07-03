use lazy_static::lazy_static;
use oid4vc_manager::routers::credential_issuer::Server;
use oid4vci::{
    credential_definition::CredentialDefinition,
    credential_issuer_metadata::CredentialsSupportedObject,
    credential_offer::CredentialOfferQuery,
    credential_request::{CredentialRequest, Proof},
    credential_response::CredentialResponse,
    token_request::TokenRequest,
    token_response::TokenResponse,
};
use oid4vp::ClaimFormatDesignation;

lazy_static! {
    static ref CREDENTIALS_SUPPORTED: CredentialsSupportedObject = serde_json::from_str(
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
    let credential_issuer_server = Server::new(CREDENTIALS_SUPPORTED.clone(), None).unwrap();
    credential_issuer_server.start().await;
    let credential_issuer_url = credential_issuer_server.uri();
    dbg!(&credential_issuer_url);

    // Get the credential offer url.
    let credential_offer_url = credential_issuer_server.credential_offer_uri();

    // Parse the credential offer url.
    let credential_offer = match credential_offer_url.parse().unwrap() {
        CredentialOfferQuery::CredentialOffer(credential_offer) => credential_offer,
        _ => unreachable!(),
    };

    let credential_issuer = credential_offer.credential_issuer;

    let client = reqwest::Client::new();
    let credential_supported_object = client
        .get(&format!("{}/.well-known/openid-credential-issuer", credential_issuer))
        .send()
        .await
        .unwrap()
        .json::<CredentialsSupportedObject>()
        .await
        .unwrap();
    dbg!(&credential_supported_object);

    let token_response = client
        .post(&format!("{}/token", credential_issuer))
        .form(&TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            pre_authorized_code: credential_offer
                .grants
                .unwrap()
                .pre_authorized_code
                .unwrap()
                .pre_authorized_code,
            user_pin: Some("493536".to_string()),
        })
        .send()
        .await
        .unwrap()
        .json::<TokenResponse>()
        .await
        .unwrap();
    dbg!(&token_response);

    let credential_response = client
        .post(&format!("{}/credential", credential_issuer))
        .json(&CredentialRequest {
            format: ClaimFormatDesignation::JwtVcJson,
            credential_definition: CredentialDefinition {
                type_: vec![
                    "VerifiableCredential".to_string(),
                    "UniversityDegreeCredential".to_string(),
                ],
                credential_subject: None,
            },
            proof: Some(Proof {
                proof_type: "jwt".to_string(),
                jwt: "eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8/
                xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR/
                0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOiIyMDE4LTA5LTE0VDIxOjE5OjEwWiIsIm5vbm/
                NlIjoidFppZ25zbkZicCJ9.ewdkIkPV50iOeBUqMXCC_aZKPxgihac0aW9EkL1nOzM"
                    .to_string(),
            }),
        })
        .send()
        .await
        .unwrap()
        .json::<CredentialResponse>()
        .await
        .unwrap();
    dbg!(&credential_response);
}

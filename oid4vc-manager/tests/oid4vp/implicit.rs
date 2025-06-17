use did_key::{generate, Ed25519KeyPair};
use jsonwebtoken::{Algorithm, Header};
use lazy_static::lazy_static;
use oid4vc_core::authentication::subject::Subject;
use oid4vc_core::{
    authorization_request::{AuthorizationRequest, Object},
    authorization_response::AuthorizationResponse,
    client_metadata::ClientMetadataResource,
    jwt,
};
use oid4vc_manager::{methods::key_method::KeySubject, ProviderManager, RelyingPartyManager};
use oid4vci::VerifiableCredentialJwt;
use oid4vp::{
    authorization_request::{ClientId, ClientMetadataParameters},
    oid4vp::OID4VP,
    ClaimFormatDesignation, ClaimFormatProperty,
};
use oid4vp::{
    dcql::dcql_query::{CredentialId, DcqlQuery},
    token::vp_token::PresentationFormat,
    token::vp_token_builder::VpTokenBuilder,
};
use serde_json::json;
use std::{collections::HashMap, sync::Arc};

lazy_static! {
    pub static ref DCQL_QUERY: DcqlQuery = serde_json::from_value(json!({
        "credentials": [
            {
                "id": "my_credential",
                "format": "jwt_vc_json",
                "meta": {
                    "vct_values": [ "https://www.w3.org/2018/credentials/examples/v1#PersonalInformation" ]
                },
                "claims": [
                    {"path": ["credentialSubject", "familyName"]},
                    {"path": ["credentialSubject", "givenName"]},
                    {"path": ["credentialSubject", "email"]},
                    {"path": ["credentialSubject", "birthdate"]},
                ]
            }
        ]
    }))
    .unwrap();
}

#[tokio::test]
async fn test_implicit_flow_friday() {
    // Create a new issuer.
    let issuer = KeySubject::from_keypair(
        generate::<Ed25519KeyPair>(Some(
            "this-is-a-very-UNSAFE-issuer-secret-key".as_bytes().try_into().unwrap(),
        )),
        None,
    );
    let issuer_did = issuer.identifier("did:key", Algorithm::EdDSA).await.unwrap();

    // Create a new subject.
    let subject = Arc::new(KeySubject::from_keypair(
        generate::<Ed25519KeyPair>(Some("this-is-a-very-UNSAFE-secret-key".as_bytes().try_into().unwrap())),
        None,
    ));
    let subject_did = subject.identifier("did:key", Algorithm::EdDSA).await.unwrap();

    // Create a new relying party.
    let relying_party = Arc::new(KeySubject::new());
    let relying_party_did = relying_party.identifier("did:key", Algorithm::EdDSA).await.unwrap();
    let relying_party_manager = RelyingPartyManager::new(relying_party, "did:key", vec![Algorithm::EdDSA]).unwrap();

    // Create authorization request with response_type `id_token vp_token`
    let authorization_request = AuthorizationRequest::<Object<OID4VP>>::builder()
        .client_id(ClientId::parse(&relying_party_did).unwrap())
        .redirect_uri("https://example.com".parse::<url::Url>().unwrap())
        .dcql_query(DCQL_QUERY.clone())
        .client_metadata(ClientMetadataResource::ClientMetadata {
            client_name: None,
            logo_uri: None,
            extension: ClientMetadataParameters {
                vp_formats: vec![(
                    ClaimFormatDesignation::JwtVcJson,
                    ClaimFormatProperty::Alg(vec![Algorithm::EdDSA]),
                )]
                .into_iter()
                .collect(),
            },
            other: HashMap::from_iter(vec![(
                "subject_syntax_types_supported".to_string(),
                json!(vec!["did:key".to_string(),]),
            )]),
        })
        .nonce("nonce".to_string())
        .build()
        .unwrap();

    // Create a provider manager and validate the authorization request.
    let provider_manager = ProviderManager::new(subject, vec!["did:key"], vec![Algorithm::EdDSA]).unwrap();

    // Create a new verifiable credential.
    let verifiable_credential = VerifiableCredentialJwt::builder()
        .sub(&subject_did)
        .iss(&issuer_did)
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
        .unwrap();

    // Encode the verifiable credential as a JWT.
    let jwt = jwt::encode(
        Arc::new(issuer),
        Header {
            alg: Algorithm::EdDSA,
            ..Default::default()
        },
        &verifiable_credential,
        "did:key",
    )
    .await
    .unwrap();

    let vp_token = VpTokenBuilder::builder_dcql_query(DCQL_QUERY.clone())
        .add_presentation(
            CredentialId::try_new("my_credential".to_string()).unwrap(),
            PresentationFormat::JwtVcJson(jwt),
        )
        .build()
        .unwrap();

    let authorization_response: AuthorizationResponse<OID4VP> = provider_manager
        .generate_response(&authorization_request, vp_token)
        .await
        .unwrap();

    assert!(relying_party_manager
        .validate_response(&authorization_response)
        .await
        .is_ok());
}

use did_key::{generate, Ed25519KeyPair};
use identity_core::common::{Object, Url};
use identity_credential::{credential::Jwt, presentation::Presentation};
use jsonwebtoken::{Algorithm, Header};
use lazy_static::lazy_static;
use oid4vc_core::{jwt, Subject};
use oid4vc_manager::{
    managers::presentation::create_presentation_submission, methods::key_method::KeySubject, ProviderManager,
    RelyingPartyManager,
};
use oid4vci::VerifiableCredentialJwt;
use oid4vp::PresentationDefinition;
use siopv2::{request::ResponseType, AuthorizationRequest, RequestUrl, Scope};
use std::sync::Arc;

lazy_static! {
    pub static ref PRESENTATION_DEFINITION: PresentationDefinition = serde_json::from_value(serde_json::json!(
        {
            "id":"Verifiable Presentation request for sign-on",
                "input_descriptors":[
                {
                    "id":"Request for Ferris's Verifiable Credential",
                    "constraints":{
                        "fields":[
                            {
                                "path":[
                                    "$.vc.type"
                                ],
                                "filter":{
                                    "type":"array",
                                    "contains":{
                                        "const":"PersonalInformation"
                                    }
                                }
                            },
                            {
                                "path":[
                                    "$.vc.credentialSubject.givenName"
                                ]
                            },
                            {
                                "path":[
                                    "$.vc.credentialSubject.familyName"
                                ]
                            },
                            {
                                "path":[
                                    "$.vc.credentialSubject.email"
                                ]
                            },
                            {
                                "path":[
                                    "$.vc.credentialSubject.birthdate"
                                ]
                            }
                        ]
                    }
                }
            ]
        }
    ))
    .unwrap();
}

#[tokio::test]
async fn test_implicit_flow() {
    // Create a new issuer.
    let issuer = KeySubject::from_keypair(generate::<Ed25519KeyPair>(Some(
        "this-is-a-very-UNSAFE-issuer-secret-key".as_bytes().try_into().unwrap(),
    )));
    let issuer_did = issuer.identifier().unwrap();

    // Create a new subject.
    let subject = Arc::new(KeySubject::from_keypair(generate::<Ed25519KeyPair>(Some(
        "this-is-a-very-UNSAFE-secret-key".as_bytes().try_into().unwrap(),
    ))));
    let subject_did = subject.identifier().unwrap();

    // Create a new relying party.
    let relying_party = Arc::new(KeySubject::new());
    let relying_party_did = relying_party.identifier().unwrap();
    let relying_party_manager = RelyingPartyManager::new([relying_party]).unwrap();

    // Create authorization request with response_type `id_token vp_token`
    let authorization_request: AuthorizationRequest = RequestUrl::builder()
        .response_type(ResponseType::IdTokenVpToken)
        .client_id(relying_party_did)
        .redirect_uri("https://example.com".to_string())
        .scope(Scope::openid())
        .presentation_definition(PRESENTATION_DEFINITION.clone())
        .nonce("nonce".to_string())
        .build()
        .and_then(TryInto::try_into)
        .unwrap();

    // Create a provider manager and validate the authorization request.
    let provider_manager = ProviderManager::new([subject]).unwrap();
    let authorization_request = provider_manager
        .validate_request(RequestUrl::Request(Box::new(authorization_request)))
        .await
        .unwrap();

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

    // Create presentation submission using the presentation definition and the verifiable credential.
    let presentation_submission = create_presentation_submission(
        &PRESENTATION_DEFINITION,
        vec![serde_json::to_value(&verifiable_credential).unwrap()],
    )
    .unwrap();

    // Encode the verifiable credential as a JWT.
    let jwt = jwt::encode(
        Arc::new(issuer),
        Header {
            alg: Algorithm::EdDSA,
            ..Default::default()
        },
        &verifiable_credential,
    )
    .unwrap();

    // Create a verifiable presentation using the JWT.
    let verifiable_presentation = Presentation::builder(Url::parse(subject_did).unwrap(), Object::new())
        .credential(Jwt::from(jwt))
        .build()
        .unwrap();

    // Generate the response. It will include both an IdToken and a VpToken.
    let authorization_response = provider_manager
        .generate_response(
            authorization_request,
            Default::default(),
            Some(verifiable_presentation),
            Some(presentation_submission),
        )
        .unwrap();

    // Validate the response.
    assert!(relying_party_manager
        .validate_response(&authorization_response)
        .await
        .is_ok());
}

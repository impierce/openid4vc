use crate::common::{MemoryStorage, Storage, TestSubject};
use chrono::{Duration, Utc};
use lazy_static::lazy_static;
use oid4vc_core::{DidMethod, SubjectSyntaxType};
use oid4vc_manager::{ProviderManager, RelyingPartyManager};
use siopv2::{
    claims::{Address, IndividualClaimRequest},
    relying_party::ResponseItems,
    request::ResponseType,
    scope::ScopeValue,
    AuthorizationRequest, AuthorizationResponse, ClientMetadata, RequestUrl, Scope, StandardClaimsRequests,
    StandardClaimsValues,
};
use std::{str::FromStr, sync::Arc};
use wiremock::{
    http::Method,
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

lazy_static! {
    pub static ref USER_CLAIMS: serde_json::Value = serde_json::json!(
        {
            "name": "Jane Doe",
            "given_name": "Jane",
            "family_name": "Doe",
            "middle_name": "Middle",
            "nickname": "JD",
            "preferred_username": "j.doe",
            "profile": "https://example.com/janedoe",
            "picture": "https://example.com/janedoe/me.jpg",
            "website": "https://example.com",
            "email": "jane.doe@example.com",
            "updated_at": 1311280970,
            "phone_number": "+1 555 555 5555",
            "address": {
                "formatted": "100 Universal City Plaza\nHollywood, CA 91608",
                "street_address": "100 Universal City Plaza",
                "locality": "Hollywood",
                "region": "CA",
                "postal_code": "91608",
                "country": "US"
            }
        }
    );
}

#[tokio::test]
async fn test_implicit_flow() {
    // Create a new mock server and retreive it's url.
    let mock_server = MockServer::start().await;
    let server_url = mock_server.uri();

    // Create a new subject.
    let subject = TestSubject::new(
        "did:test:relying_party".to_string(),
        "did:test:relying_party#key_id".to_string(),
    )
    .unwrap();

    // Create a new relying party manager.
    let relying_party_manager = RelyingPartyManager::new([Arc::new(subject)]).unwrap();

    // Create a new RequestUrl with response mode `post` for cross-device communication.
    let request: AuthorizationRequest = RequestUrl::builder()
        .response_type(ResponseType::IdToken)
        .client_id("did:test:relyingparty".to_string())
        .scope(Scope::from(vec![ScopeValue::OpenId, ScopeValue::Phone]))
        .redirect_uri(format!("{server_url}/redirect_uri"))
        .response_mode("post".to_string())
        .client_metadata(
            ClientMetadata::default()
                .with_subject_syntax_types_supported(vec![SubjectSyntaxType::Did(
                    DidMethod::from_str("did:test").unwrap(),
                )])
                .with_id_token_signing_alg_values_supported(vec!["EdDSA".to_string()]),
        )
        .claims(
            r#"{
                "id_token": {
                    "name": null,
                    "email": {
                        "essential": true
                    },
                    "address": null,
                    "updated_at": null
                }
            }"#,
        )
        .exp((Utc::now() + Duration::minutes(10)).timestamp())
        .nonce("n-0S6_WzA2Mj".to_string())
        .build()
        .and_then(TryInto::try_into)
        .unwrap();

    // Create a new `request_uri` endpoint on the mock server and load it with the JWT encoded `AuthorizationRequest`.
    Mock::given(method("GET"))
        .and(path("/request_uri"))
        .respond_with(ResponseTemplate::new(200).set_body_string(relying_party_manager.encode(&request).unwrap()))
        .mount(&mock_server)
        .await;

    // Create a new `redirect_uri` endpoint on the mock server where the `Provider` will send the `AuthorizationResponse`.
    Mock::given(method("POST"))
        .and(path("/redirect_uri"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    // Create a new storage for the user's claims.
    let storage = MemoryStorage::new(serde_json::from_value(USER_CLAIMS.clone()).unwrap());

    // Create a new subject and validator.
    let subject = TestSubject::new("did:test:subject".to_string(), "did:test:subject#key_id".to_string()).unwrap();

    // Create a new provider manager.
    let provider_manager = ProviderManager::new([Arc::new(subject)]).unwrap();

    // Create a new RequestUrl which includes a `request_uri` pointing to the mock server's `request_uri` endpoint.
    let request_url = RequestUrl::builder()
        .client_id("did:test:relyingparty".to_string())
        .request_uri(format!("{server_url}/request_uri"))
        .build()
        .unwrap();

    // The Provider obtains the reuquest url either by a deeplink or by scanning a QR code. It then validates the
    // request. Since in this case the request is a JWT, the provider will fetch the request by sending a GET
    // request to mock server's `request_uri` endpoint.
    let request = provider_manager.validate_request(request_url).await.unwrap();

    // The provider can now access the claims requested by the relying party.
    let request_claims = request.id_token_request_claims().unwrap();
    assert_eq!(
        request_claims,
        StandardClaimsRequests {
            name: Some(IndividualClaimRequest::Null),
            email: Some(IndividualClaimRequest::object().essential(true)),
            address: Some(IndividualClaimRequest::Null),
            updated_at: Some(IndividualClaimRequest::Null),
            phone_number: Some(IndividualClaimRequest::Null),
            phone_number_verified: Some(IndividualClaimRequest::Null),
            ..Default::default()
        }
    );

    // Assert that the request was successfully received by the mock server at the `request_uri` endpoint.
    let get_request = mock_server.received_requests().await.unwrap()[0].clone();
    assert_eq!(get_request.method, Method::Get);
    assert_eq!(get_request.url.path(), "/request_uri");

    // The user can now provide the claims requested by the relying party.
    let response_claims: StandardClaimsValues = storage.fetch_claims(&request_claims);

    // Let the provider generate a response based on the validated request. The response is an `IdToken` which is
    // encoded as a JWT.
    let response = provider_manager
        .generate_response(request, response_claims, None, None)
        .await
        .unwrap();

    // The provider manager sends it's response to the mock server's `redirect_uri` endpoint.
    provider_manager.send_response(response).await.unwrap();

    // Assert that the AuthorizationResponse was successfully received by the mock server at the expected endpoint.
    let post_request = mock_server.received_requests().await.unwrap()[1].clone();
    assert_eq!(post_request.method, Method::Post);
    assert_eq!(post_request.url.path(), "/redirect_uri");
    let response: AuthorizationResponse = serde_urlencoded::from_bytes(post_request.body.as_slice()).unwrap();

    // The `RelyingParty` then validates the response by decoding the header of the id_token, by fetching the public
    // key corresponding to the key identifier and finally decoding the id_token using the public key and by
    // validating the signature.
    let ResponseItems { id_token, .. } = relying_party_manager.validate_response(&response).await.unwrap();
    assert_eq!(
        id_token.standard_claims().to_owned(),
        StandardClaimsValues {
            name: Some("Jane Doe".to_string()),
            email: Some("jane.doe@example.com".to_string()),
            updated_at: Some(1311280970),
            phone_number: Some("+1 555 555 5555".to_string()),
            address: Some(Address {
                formatted: Some("100 Universal City Plaza\nHollywood, CA 91608".to_string()),
                street_address: Some("100 Universal City Plaza".to_string()),
                locality: Some("Hollywood".to_string()),
                region: Some("CA".to_string()),
                postal_code: Some("91608".to_string()),
                country: Some("US".to_string()),
            }),
            ..Default::default()
        }
    );
}

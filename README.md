# openid4vc
This library aims to support all the specifications under the [OpenID for Verifiable Credentials](https://openid.net/openid4vc/)
works.

OpenID for Verifiable Credentials (OID4VC) consists of the following specifications:
* [OpenID for Verifiable Credential Issuance (OID4VCI)](https://openid.bitbucket.io/connect/openid-4-verifiable-credential-issuance-1_0.html) – Defines an API and corresponding OAuth-based authorization mechanisms for issuance of Verifiable Credentials

* [OpenID for Verifiable Presentations (OID4VP)](https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-1_0.html) – Defines a mechanism on top of OAuth 2.0 to allow presentation of claims in the form of Verifiable Credentials as part of the protocol flow

* [Self-Issued OpenID Provider v2 (SIOPv2)](https://openid.bitbucket.io/connect/openid-connect-self-issued-v2-1_0.html) – Enables End-Users to use OpenID Providers (OPs) that they control

* [OpenID for Verifiable Presentations over BLE](https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-over-ble-1_0.html) – Enables using Bluetooth Low Energy (BLE) to request the presentation of verifiable credentials. It uses the request and response syntax as defined in OID4VP. 


## Description

Currently the Implicit Flow is consists of four major parts:

- A `Provider` that can accept a `SiopRequest` and generate a `SiopResponse` by creating an `IdToken`, adding its key identifier to the header of the `id_token`, signing the `id_token` and wrap it into a `SiopResponse`. It can also send the `SiopResponse` using the `redirect_uri` parameter.
- A `RelyingParty` struct which can validate a `SiopResponse` by validating its `IdToken` using a key identifier (which is extracted from the `id_token`) and its public key.
- The `Subject` trait can be implemented on a custom struct representing the signing logic of a DID method. A `Provider` can ingest an object that implements the `Subject` trait so that during generation of a `SiopResponse` the DID method syntax, key identifier and signing method of the specific `Subject` can be used.
- The `Validator` trait can be implemented on a custom struct representing the validating logic of a DID method. When ingested by a `RelyingParty`, it can resolve the public key that is needed for validating an `IdToken`.

## Example

```rust
use anyhow::Result;
use async_trait::async_trait;
use chrono::{Duration, Utc};
use ed25519_dalek::{Keypair, Signature, Signer};
use lazy_static::lazy_static;
use rand::rngs::OsRng;
use serde_json::{json, Value};
use siopv2::{
    claims::{Claim, ClaimRequests},
    request::ResponseType, StandardClaim,
    IdToken, Provider, Registration, RelyingParty, RequestUrl, Scope, SiopRequest, SiopResponse, Subject, Validator,
};
use wiremock::{
    http::Method,
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};
use std::str::FromStr;

lazy_static! {
    pub static ref MOCK_KEYPAIR: Keypair = Keypair::generate(&mut OsRng);
}

// A Subject type that can be ingested by a Provider
#[derive(Default)]
pub struct MySubject;

impl MySubject {
    pub fn new() -> Self {
        MySubject {}
    }
}

#[async_trait]
impl Subject for MySubject {
    fn did(&self) -> Result<did_url::DID> {
        Ok(did_url::DID::parse("did:mymethod:subject")?)
    }

    fn key_identifier(&self) -> Option<String> {
        Some("key_identifier".to_string())
    }

    async fn sign<'a>(&self, message: &'a str) -> Result<Vec<u8>> {
        let signature: Signature = MOCK_KEYPAIR.sign(message.as_bytes());
        Ok(signature.to_bytes().to_vec())
    }
}

#[async_trait]
impl Validator for MySubject {
    async fn public_key<'a>(&self, _kid: &'a str) -> Result<Vec<u8>> {
        Ok(MOCK_KEYPAIR.public.to_bytes().to_vec())
    }
}

// A Validator type that can be ingested by a RelyingParty
#[derive(Default)]
pub struct MyValidator;

#[async_trait]
impl Validator for MyValidator {
    async fn public_key<'a>(&self, _kid: &'a str) -> Result<Vec<u8>> {
        Ok(MOCK_KEYPAIR.public.to_bytes().to_vec())
    }
}

#[tokio::main]
async fn main() {
    // Create a new mock server and retreive it's url.
    let mock_server = MockServer::start().await;
    let server_url = mock_server.uri();

    // Create a new validator.
    let validator = MySubject::default();

    // Create a new relying party.
    let relying_party = RelyingParty::new(validator);

    // Create a new RequestUrl with response mode `post` for cross-device communication.
    let request: SiopRequest = RequestUrl::builder()
        .response_type(ResponseType::IdToken)
        .client_id("did:mymethod:relyingparty".to_string())
        .scope(Scope::openid())
        .redirect_uri(format!("{server_url}/redirect_uri"))
        .response_mode("post".to_string())
        .registration(
            Registration::default()
                .with_subject_syntax_types_supported(vec!["did:mymethod".to_string()])
                .with_id_token_signing_alg_values_supported(vec!["EdDSA".to_string()]),
        )
        .claims(ClaimRequests {
            id_token: Some(StandardClaim {
                name: Some(Claim::default()),
                ..Default::default()
            }),
            ..Default::default()
        })
        .exp((Utc::now() + Duration::minutes(10)).timestamp())
        .nonce("n-0S6_WzA2Mj".to_string())
        .build()
        .and_then(TryInto::try_into)
        .unwrap();

    // Create a new `request_uri` endpoint on the mock server and load it with the JWT encoded `SiopRequest`.
    Mock::given(method("GET"))
        .and(path("/request_uri"))
        .respond_with(ResponseTemplate::new(200).set_body_string(relying_party.encode(&request).await.unwrap()))
        .mount(&mock_server)
        .await;

    // Create a new `redirect_uri` endpoint on the mock server where the `Provider` will send the `SiopResponse`.
    Mock::given(method("POST"))
        .and(path("/redirect_uri"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    // Create a new subject.
    let subject = MySubject::default();

    // Create a new provider.
    let provider = Provider::new(subject, MemoryStorage::default()).await.unwrap();

    // Create a new RequestUrl which includes a `request_uri` pointing to the mock server's `request_uri` endpoint.
    let request_url = RequestUrl::builder()
        .request_uri(format!("{server_url}/request_uri"))
        .build()
        .unwrap();

    // The Provider obtains the reuquest url either by a deeplink or by scanning a QR code. It then validates the
    // request. Since in this case the request is a JWT, the provider will fetch the request by sending a GET
    // request to mock server's `request_uri` endpoint.
    let request = provider.validate_request(request_url).await.unwrap();

    // Assert that the request was successfully received by the mock server at the `request_uri` endpoint.
    let get_request = mock_server.received_requests().await.unwrap()[0].clone();
    assert_eq!(get_request.method, Method::Get);
    assert_eq!(get_request.url.path(), "/request_uri");

    // Let the provider generate a response based on the validated request. The response is an `IdToken` which is
    // encoded as a JWT.
    let response = provider
        .generate_response(request, StandardClaim::default())
        .await
        .unwrap();

    // The provider sends it's response to the mock server's `redirect_uri` endpoint.
    provider.send_response(response).await.unwrap();

    // Assert that the SiopResponse was successfully received by the mock server at the expected endpoint.
    let post_request = mock_server.received_requests().await.unwrap()[1].clone();
    assert_eq!(post_request.method, Method::Post);
    assert_eq!(post_request.url.path(), "/redirect_uri");
    let response: SiopResponse = serde_urlencoded::from_bytes(post_request.body.as_slice()).unwrap();

    // The `RelyingParty` then validates the response by decoding the header of the id_token, by fetching the public
    // key corresponding to the key identifier and finally decoding the id_token using the public key and by
    // validating the signature.
    let id_token = relying_party.validate_response(&response).await.unwrap();
    let IdToken {
        iss, sub, aud, nonce, ..
    } = IdToken::new(
        "did:mymethod:subject".to_string(),
        "did:mymethod:subject".to_string(),
        "did:mymethod:relyingparty".to_string(),
        "n-0S6_WzA2Mj".to_string(),
        (Utc::now() + Duration::minutes(10)).timestamp(),
    );
    assert_eq!(id_token.iss, iss);
    assert_eq!(id_token.sub, sub);
    assert_eq!(id_token.aud, aud);
    assert_eq!(id_token.nonce, nonce);
}
```

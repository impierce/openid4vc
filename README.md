# siopv2
Self Issued OpenID Provider v2 (SIOPv2) authentication library in rust conform to the [SIOPv2 specification](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html).

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
    use siopv2::{
        provider::{Provider, Subject},
        relying_party::{RelyingParty, Validator},
        IdToken, SiopRequest,
    };

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
            Ok(did_url::DID::parse("did:key:123")?)
        }

        fn key_identifier(&self) -> Option<String> {
            Some("key_identifier".to_string())
        }

        async fn sign<'a>(&self, message: &'a str) -> Result<Vec<u8>> {
            let signature: Signature = MOCK_KEYPAIR.sign(message.as_bytes());
            Ok(signature.to_bytes().to_vec())
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
        // Get a new SIOP request with response mode `post` for cross-device communication.
        let request: SiopRequest = serde_qs::from_str(
            "\
                response_type=id_token\
                &response_mode=post\
                &client_id=did:key:1\
                &redirect_uri=http://127.0.0.1:4200/redirect_uri\
                &scope=openid\
                &nonce=n-0S6_WzA2Mj\
                &subject_syntax_types_supported[0]=did%3Akey\
            ",
        )
        .unwrap();

        // Generate a new response.
        let response = Provider::<MySubject>::default()
            .generate_response(request)
            .await
            .unwrap();

        // Create a new validator.
        let validator = MyValidator::default();

        // Create a new relying party.
        let relying_party = RelyingParty::new(validator);

        // Validate the response.
        let id_token = relying_party.validate_response(&response).await.unwrap();

        let IdToken {
            iss, sub, aud, nonce, ..
        } = IdToken::new(
            "did:key:123".to_string(),
            "did:key:123".to_string(),
            "did:key:1".to_string(),
            "n-0S6_WzA2Mj".to_string(),
            (Utc::now() + Duration::minutes(10)).timestamp(),
        );
        assert_eq!(id_token.iss, iss);
        assert_eq!(id_token.sub, sub);
        assert_eq!(id_token.aud, aud);
        assert_eq!(id_token.nonce, nonce);
    }

```

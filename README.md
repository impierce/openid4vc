# siop
Self Issued OpenID Provider v2 (SIOPv2) authentication library in rust.

## Description

Currently the Implicit Flow is consists of four major parts:

    - A Provider that can accept a SiopRequest and generate a SiopResponse by creating an IdToken, adding its key identifier to the header of the id_token, signing the id_token and wrap it into a SiopResponse. It can also send the SiopResponse using the redirect_uri parameter.
    - A RelyingParty struct which can validate a SiopResponse by validating its IdToken using a key identifier (which is extracted from the id_token) and its public key.
    - The Subject trait can be implemented on a custom struct representing the signing logic of a DID method. A Provider can ingest an object that implements the Subject trait so that during generation of a SiopResponse the DID method syntax, key identifier and signing method of the specific Subject can be used.
    - The Validator trait can be implemented on a custom struct representing the validating logic of a DID method. When ingested by a RelyingParty, it can resolve the public key that is needed for validating an IdToken.

## Example

```rust
    use anyhow::Result;
    use async_trait::async_trait;
    use ed25519_dalek::{Keypair, Signature, Signer};
    use siop::{
        provider::{Provider, Subject},
        relying_party::{RelyingParty, Validator},
        IdToken, SiopRequest,
    };

    const ED25519_BYTES: [u8; 64] = [
        184, 51, 220, 84, 185, 50, 38, 241, 159, 104, 71, 65, 69, 200, 189, 33, 0, 143, 8, 118, 121, 226, 54, 174, 25, 25,
        222, 141, 130, 143, 80, 179, 174, 9, 12, 56, 110, 213, 126, 121, 47, 192, 117, 97, 75, 99, 95, 61, 25, 206, 185,
        80, 202, 96, 180, 162, 64, 49, 105, 175, 198, 195, 44, 173,
    ];

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
        fn did(&self) -> String {
            "did:my_method:123".to_string()
        }

        fn key_identifier(&self) -> Option<String> {
            Some("key_identifier".to_string())
        }

        async fn sign(&self, message: &String) -> Result<Vec<u8>> {
            let keypair = Keypair::from_bytes(&ED25519_BYTES).unwrap();
            let signature: Signature = keypair.sign(message.as_bytes());
            Ok(signature.to_bytes().to_vec())
        }
    }

    // A Validator type that can be ingested by a RelyingParty
    pub struct MyValidator;

    impl MyValidator {
        pub fn new() -> Self {
            MyValidator {}
        }
    }

    #[async_trait]
    impl Validator for MyValidator {
        async fn public_key(&self, _kid: &String) -> Result<Vec<u8>> {
            let keypair = Keypair::from_bytes(&ED25519_BYTES).unwrap();
            Ok(keypair.public.to_bytes().to_vec())
        }
    }

    #[tokio::main]
    async fn main() {
        // Get a new SIOP request with response mode `post` for cross-device communication.
        let request: SiopRequest = serde_qs::from_str(
            "\
                response_type=id_token\
                &response_mode=post\
                &client_id=did:my_method:1\
                &redirect_uri=http://127.0.0.1:4200/redirect_uri\
                &scope=openid\
                &nonce=n-0S6_WzA2Mj\
                &subject_syntax_types_supported[0]=did%3Amy_method\
            ",
        )
        .unwrap();

        // Generate a new response.
        let response = Provider::<MySubject>::default()
            .generate_response(request)
            .await
            .unwrap();

        // Create a new validator.
        let validator = MyValidator::new();

        // Create a new relying party.
        let relying_party = RelyingParty::new(validator);

        // Validate the response.
        let id_token = relying_party.validate_response(&response).await.unwrap();

        let IdToken {
            iss, sub, aud, nonce, ..
        } = IdToken::new(
            "did:my_method:123".to_string(),
            "did:my_method:123".to_string(),
            "did:my_method:1".to_string(),
            "n-0S6_WzA2Mj".to_string(),
        );
        assert_eq!(id_token.iss, iss);
        assert_eq!(id_token.sub, sub);
        assert_eq!(id_token.aud, aud);
        assert_eq!(id_token.nonce, nonce);
    }


```

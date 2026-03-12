use async_trait::async_trait;
use identity_document::document::CoreDocument;
use identity_jose::jwk::Jwk;

/// A trait for resolving verification materials (DID Documents and public keys).Many components in the OID4VC ecosystem rely on the ability to resolve key material.
/// This trait abstracts away the details of how DIDs and public keys are resolved. More resolver method should be added in the future.
#[async_trait]
pub trait VerificationMaterialResolver: Send + Sync {
    /// Resolves the full DID Document
    async fn resolve_did_document(
        &self,
        did: &identity_did::CoreDID,
    ) -> Result<CoreDocument, Box<dyn std::error::Error>>;

    /// Resolves a specific public key (JWK) by its Key ID
    async fn resolve_public_key(&self, kid: &str) -> Result<Jwk, Box<dyn std::error::Error>>;
}

#[cfg(feature = "test-utils")]
pub mod test_utils {
    use super::*;
    use did_key::DIDCore as _;
    use identity_did::{DIDUrl, DID as _};

    /// A simple implementation of the `VerificationMaterialResolver` trait for testing purposes. It uses the `did:key` method to resolve DIDs and public keys.
    pub struct TestVerificationMaterialResolver;

    #[async_trait]
    impl VerificationMaterialResolver for TestVerificationMaterialResolver {
        async fn resolve_did_document(
            &self,
            did: &identity_did::CoreDID,
        ) -> Result<CoreDocument, Box<dyn std::error::Error>> {
            let res = Ok(serde_json::from_value(serde_json::json!(did_key::resolve(did.as_str())
                .unwrap()
                .get_did_document(did_key::CONFIG_JOSE_PUBLIC)))
            .unwrap());

            res
        }

        async fn resolve_public_key(&self, kid: &str) -> Result<identity_jose::jwk::Jwk, Box<dyn std::error::Error>> {
            let document = self
                .resolve_did_document(DIDUrl::parse(kid).unwrap().did())
                .await
                .unwrap();

            let key = document.resolve_method(kid, None).unwrap();

            let res = Ok(key.data().public_key_jwk().cloned().unwrap());

            res
        }
    }
}

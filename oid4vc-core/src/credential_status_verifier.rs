use async_trait::async_trait;

/// A trait for resolving verification materials (DID Documents and public keys). Many components in the OID4VC ecosystem rely on the ability to resolve key material.
/// This trait abstracts away the details of how DIDs and public keys are resolved. More resolver methods should be added in the future.
#[async_trait]
pub trait CredentialStatusVerifier: Send + Sync {
    // TODO: write comment
    async fn check_status_claim_against_status_list_token(
        &self,
        status_claim: serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

#[cfg(feature = "test-utils")]
pub mod test_utils {
    use super::*;

    /// A simple implementation of the `CredentialStatusVerifier` trait for testing purposes.
    pub struct TestCredentialStatusVerifier;

    #[async_trait]
    impl CredentialStatusVerifier for TestCredentialStatusVerifier {
        async fn check_status_claim_against_status_list_token(
            &self,
            _status_claim: serde_json::Value,
        ) -> Result<(), Box<dyn std::error::Error>> {
            // TODO: Implement a simple check for testing purposes
            Ok(())
        }
    }
}

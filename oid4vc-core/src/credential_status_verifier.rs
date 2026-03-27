use async_trait::async_trait;
/// A trait for checking the credential status, agnostic of what Status List method is used.
#[cfg_attr(feature = "test-utils", mockall::automock)]
#[async_trait]
pub trait CredentialStatusVerifier: Send + Sync {
    /// Check the status of a credential based on its status claim/property.
    async fn check_credential_status(&self, status_claim: serde_json::Value) -> Result<(), Box<dyn std::error::Error>>;
}

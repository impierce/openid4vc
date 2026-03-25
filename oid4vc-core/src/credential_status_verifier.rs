use async_trait::async_trait;

/// A trait for checking the credential status, agnostic of what Status List method is used.
#[async_trait]
pub trait CredentialStatusVerifier: Send + Sync {
    /// Check the status of a credential based on its status claim/property.
    async fn check_credential_status(&self, status_claim: serde_json::Value) -> Result<(), Box<dyn std::error::Error>>;
}

#[cfg(feature = "test-utils")]
pub mod test_utils {
    use super::*;

    /// A simple implementation of the `CredentialStatusVerifier` trait for testing purposes.
    pub struct TestCredentialStatusVerifier;

    #[async_trait]
    impl CredentialStatusVerifier for TestCredentialStatusVerifier {
        /// This test implementation parses the status claim according to a format which it understands, otherwise an error is thrown.
        /// Actual Status List fetching is skipped for simplicity and we simulate a Status List where index 123 is INVALID.
        async fn check_credential_status(
            &self,
            status_claim: serde_json::Value,
        ) -> Result<(), Box<dyn std::error::Error>> {
            // Normally errors would be better typed, but this point is where implementers can choose if operational errors would also render a credential invalid for strong security, or a more lenient approach as currently implemented.
            match fetch_credential_status(status_claim) {
                Ok(_) => Ok(()),
                Err(e) => {
                    if e.to_string().contains("Credential status is invalid") {
                        Err(e)
                    } else {
                        Ok(())
                    }
                }
            }
        }
    }

    fn fetch_credential_status(status_claim: serde_json::Value) -> Result<(), Box<dyn std::error::Error>> {
        let obj = status_claim
            .as_object()
            .ok_or("Failed to parse status claim as object")?;
        if obj.is_empty() {
            return Err("Status claim cannot be empty".into());
        }

        // Extract status list URI
        let _uri = obj
            .get("uri")
            .and_then(|v| v.as_str())
            .ok_or("Missing 'uri' field in status claim")?;

        // Extract status index
        let idx = obj
            .get("idx")
            .and_then(|v| v.as_u64())
            .ok_or("Missing 'idx' field in status claim")?;

        // In a real implementation, fetch the status list from `uri` and check the bit at position `idx`
        if idx == 123 {
            return Err(format!("Credential status is invalid").into());
        }

        Ok(())
    }
    #[cfg(test)]
    mod tests {
        use super::*;

        #[tokio::test]
        async fn test_valid_status_claim() {
            let verifier = TestCredentialStatusVerifier;
            let status_claim = serde_json::json!({
                "uri": "http://localhost:3033/status-list/1",
                "idx": 8048
            });

            let result = verifier.check_credential_status(status_claim).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_empty_claim() {
            let verifier = TestCredentialStatusVerifier;
            let status_claim = serde_json::json!({});

            let result = verifier.check_credential_status(status_claim).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_missing_uri() {
            let verifier = TestCredentialStatusVerifier;
            let status_claim = serde_json::json!({
                "idx": 8048
            });

            let result = verifier.check_credential_status(status_claim).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_missing_idx() {
            let verifier = TestCredentialStatusVerifier;
            let status_claim = serde_json::json!({
                "uri": "http://localhost:3033/status-list/1"
            });

            let result = verifier.check_credential_status(status_claim).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_revoked_status() {
            let verifier = TestCredentialStatusVerifier;
            let status_claim = serde_json::json!({
                "uri": "http://localhost:3033/status-list/1",
                "idx": 123
            });

            let result = verifier.check_credential_status(status_claim).await;
            assert!(result.is_err());
        }
    }
}

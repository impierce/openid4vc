use http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::fmt::Display;
use thiserror::Error;

pub trait ErrorStatusCode {
    fn status_code(&self) -> StatusCode;
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Error)]
pub struct OID4VCError<T>
where
    T: ErrorStatusCode,
{
    pub error: T,
    pub error_description: Option<String>,
}

impl<T> OID4VCError<T>
where
    T: ErrorStatusCode,
{
    pub fn new(error: T) -> Self {
        Self {
            error,
            error_description: None,
        }
    }

    pub fn with_description(self, error_description: &str) -> Self {
        Self {
            error_description: Some(error_description.to_string()),
            ..self
        }
    }
}

impl<T> Display for OID4VCError<T>
where
    T: ErrorStatusCode + std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Error: {:?}", self.error)?;
        if let Some(desc) = &self.error_description {
            write!(f, " - {desc}")?;
        }
        Ok(())
    }
}

/// Authorization Error Response as described here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-authorization-error-respons
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationErrorResponse {
    AccessDenied,
    InvalidRequest,
    UnauthorizedClient,
    UnsupportedResponseType,
    InvalidScope,
    ServerError,
    TemporarilyUnavailable,
}

impl ErrorStatusCode for AuthorizationErrorResponse {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::AccessDenied => StatusCode::FOUND,
            Self::InvalidRequest => StatusCode::FOUND,
            Self::UnauthorizedClient => StatusCode::FOUND,
            Self::UnsupportedResponseType => StatusCode::FOUND,
            Self::InvalidScope => StatusCode::FOUND,
            Self::ServerError => StatusCode::FOUND,
            Self::TemporarilyUnavailable => StatusCode::FOUND,
        }
    }
}

impl std::error::Error for AuthorizationErrorResponse {}
impl Display for AuthorizationErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AccessDenied => write!(f, "Access Denied"),
            Self::InvalidRequest => write!(f, "Invalid Request"),
            Self::UnauthorizedClient => write!(f, "Unauthorized Client"),
            Self::UnsupportedResponseType => write!(f, "Unsupported Response Type"),
            Self::InvalidScope => write!(f, "Invalid Scope"),
            Self::ServerError => write!(f, "Server Error"),
            Self::TemporarilyUnavailable => write!(f, "Temporarily Unavailable"),
        }
    }
}
/// Token Error Response as described here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-token-error-response
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenErrorResponse {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,
}

impl ErrorStatusCode for TokenErrorResponse {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidRequest => StatusCode::BAD_REQUEST,
            Self::InvalidClient => StatusCode::UNAUTHORIZED,
            Self::InvalidGrant => StatusCode::BAD_REQUEST,
            Self::UnauthorizedClient => StatusCode::UNAUTHORIZED,
            Self::UnsupportedGrantType => StatusCode::BAD_REQUEST,
            Self::InvalidScope => StatusCode::BAD_REQUEST,
        }
    }
}
impl std::error::Error for TokenErrorResponse {}
impl Display for TokenErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest => write!(f, "Invalid Request"),
            Self::InvalidClient => write!(f, "Invalid Client"),
            Self::InvalidGrant => write!(f, "Invalid Grant"),
            Self::UnauthorizedClient => write!(f, "Unauthorized Client"),
            Self::UnsupportedGrantType => write!(f, "Unsupported Grant Type"),
            Self::InvalidScope => write!(f, "Invalid Scope"),
        }
    }
}

/// Credential Error Response as defined in OpenID4VCI 1.0 - https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request-errors
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialErrorResponse {
    InvalidCredentialRequest,
    UnknownCredentialConfiguration,
    UnknownCredentialIdentifier,
    InvalidProof,
    InvalidNonce,
    InvalidEncryptionParameters,
    CredentialRequestDenied,
}

impl ErrorStatusCode for CredentialErrorResponse {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidCredentialRequest => StatusCode::BAD_REQUEST,
            Self::UnknownCredentialConfiguration => StatusCode::BAD_REQUEST,
            Self::UnknownCredentialIdentifier => StatusCode::BAD_REQUEST,
            Self::InvalidProof => StatusCode::BAD_REQUEST,
            Self::InvalidNonce => StatusCode::BAD_REQUEST,
            Self::InvalidEncryptionParameters => StatusCode::BAD_REQUEST,
            Self::CredentialRequestDenied => StatusCode::BAD_REQUEST,
        }
    }
}

impl std::error::Error for CredentialErrorResponse {}
impl Display for CredentialErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCredentialRequest => write!(f, "Invalid Credential Request"),
            Self::UnknownCredentialConfiguration => write!(f, "Unknown Credential Configuration"),
            Self::UnknownCredentialIdentifier => write!(f, "Unknown Credential Identifier"),
            Self::InvalidProof => write!(f, "Invalid Proof"),
            Self::InvalidNonce => write!(f, "Invalid Nonce"),
            Self::InvalidEncryptionParameters => write!(f, "Invalid Encryption Parameters"),
            Self::CredentialRequestDenied => write!(f, "Credential Request Denied"),
        }
    }
}

/// Deferred Credential Error Response as described here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-deferred-credential-error-r
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeferredCredentialErrorResponse {
    InvalidCredentialRequest,
    UnknownCredentialConfiguration,
    UnknownCredentialIdentifier,
    InvalidProof,
    InvalidNonce,
    InvalidEncryptionParameters,
    CredentialRequestDenied,
    InvalidTransactionId,
}

impl ErrorStatusCode for DeferredCredentialErrorResponse {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidCredentialRequest => StatusCode::BAD_REQUEST,
            Self::UnknownCredentialConfiguration => StatusCode::BAD_REQUEST,
            Self::UnknownCredentialIdentifier => StatusCode::BAD_REQUEST,
            Self::InvalidProof => StatusCode::BAD_REQUEST,
            Self::InvalidNonce => StatusCode::BAD_REQUEST,
            Self::InvalidEncryptionParameters => StatusCode::BAD_REQUEST,
            Self::CredentialRequestDenied => StatusCode::BAD_REQUEST,
            Self::InvalidTransactionId => StatusCode::BAD_REQUEST,
        }
    }
}

impl std::error::Error for DeferredCredentialErrorResponse {}
impl Display for DeferredCredentialErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCredentialRequest => write!(f, "Invalid Credential Request"),
            Self::UnknownCredentialConfiguration => write!(f, "Unknown Credential Configuration"),
            Self::UnknownCredentialIdentifier => write!(f, "Unknown Credential Identifier"),
            Self::InvalidProof => write!(f, "Invalid Proof"),
            Self::InvalidNonce => write!(f, "Invalid Nonce"),
            Self::InvalidEncryptionParameters => write!(f, "Invalid Encryption Parameters"),
            Self::CredentialRequestDenied => write!(f, "Credential Request Denied"),
            Self::InvalidTransactionId => write!(f, "Invalid Transaction ID"),
        }
    }
}
/// Notification Error Response as defined in OpenID4VCI 1.0: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-notification-error-response
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationErrorResponse {
    InvalidNotificationRequest,
    InvalidNotificationId,
}

impl ErrorStatusCode for NotificationErrorResponse {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidNotificationRequest => StatusCode::BAD_REQUEST,
            Self::InvalidNotificationId => StatusCode::BAD_REQUEST,
        }
    }
}

/// Interactive Authorization Error Response as defined in OID4VCI 1.1, Section 6.2.3.
///
/// In addition to standard PAR error processing rules (RFC 9126, Section 2.3), this adds
/// the `missing_interaction_type` error code.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteractiveAuthorizationErrorResponse {
    /// The `interaction_types_supported` parameter is missing a required interaction type.
    MissingInteractionType,
    /// Standard OAuth error codes may also appear.
    InvalidRequest,
    InvalidClient,
    UnauthorizedClient,
    AccessDenied,
}

impl ErrorStatusCode for InteractiveAuthorizationErrorResponse {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::MissingInteractionType => StatusCode::BAD_REQUEST,
            Self::InvalidRequest => StatusCode::BAD_REQUEST,
            Self::InvalidClient => StatusCode::UNAUTHORIZED,
            Self::UnauthorizedClient => StatusCode::UNAUTHORIZED,
            Self::AccessDenied => StatusCode::FORBIDDEN,
        }
    }
}

impl std::error::Error for InteractiveAuthorizationErrorResponse {}
impl Display for InteractiveAuthorizationErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingInteractionType => write!(f, "Missing Interaction Type"),
            Self::InvalidRequest => write!(f, "Invalid Request"),
            Self::InvalidClient => write!(f, "Invalid Client"),
            Self::UnauthorizedClient => write!(f, "Unauthorized Client"),
            Self::AccessDenied => write!(f, "Access Denied"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_oid4vc_error() {
        let error = OID4VCError::new(CredentialErrorResponse::InvalidProof).with_description("Invalid proof");
        let status = error.error.status_code();
        let json_body = serde_json::to_string(&error).unwrap();

        let response = http::Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .body(json_body)
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = response.body();
        let body_value: serde_json::Value = serde_json::from_str(body).unwrap();

        assert_eq!(
            json!({
                "error": "invalid_proof",
                "error_description": "Invalid proof"
            }),
            body_value
        );

        assert!(
            response.headers().get("Content-Type").and_then(|v| v.to_str().ok()) == Some("application/json"),
            "Content-Type header should be application/json"
        );
    }
}

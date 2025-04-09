use http::{Response, StatusCode};
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
            write!(f, " - {}", desc)?;
        }
        Ok(())
    }
}

/// Authorization Error Response as defined in OpenID4VCI - draft 13 - Section 5.3: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#name-authorization-error-respons
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

/// Token Error Response as defined in OpenID4VCI - draft 13 - Section 6.3: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#name-token-error-response
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

/// Credential Error Response as defined in OpenID4VCI - draft 13 - Section 7.3.1: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#name-credential-error-response
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialErrorResponse {
    InvalidCredentialRequest,
    UnsupportedCredentialType,
    UnsupportedCredentialFormat,
    InvalidEncryptionParameters,
    InvalidProof,
    InvalidToken,
}

impl ErrorStatusCode for CredentialErrorResponse {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidCredentialRequest => StatusCode::BAD_REQUEST,
            Self::UnsupportedCredentialType => StatusCode::BAD_REQUEST,
            Self::UnsupportedCredentialFormat => StatusCode::BAD_REQUEST,
            Self::InvalidProof => StatusCode::BAD_REQUEST,
            Self::InvalidEncryptionParameters => StatusCode::BAD_REQUEST,
            Self::InvalidToken => StatusCode::UNAUTHORIZED,
        }
    }
}

impl std::error::Error for CredentialErrorResponse {}
impl Display for CredentialErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCredentialRequest => write!(f, "Invalid Credential Request"),
            Self::UnsupportedCredentialType => write!(f, "Unsupported Credential Type"),
            Self::UnsupportedCredentialFormat => write!(f, "Unsupported Credential Format"),
            Self::InvalidEncryptionParameters => write!(f, "Invalid Encryption Parameters"),
            Self::InvalidProof => write!(f, "Invalid Proof"),
            Self::InvalidToken => write!(f, "Invalid Token"),
        }
    }
}
/// Batch Credential Error Response as defined in OpenID4VCI - draft 13 - Section 8.3: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#name-batch-credential-error-resp
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchCredentialErrorResponse {
    InvalidCredentialRequest,
    UnsupportedCredentialType,
    UnsupportedCredentialFormat,
    InvalidProof,
    InvalidToken,
    InvalidEncryptionParameters,
}

impl ErrorStatusCode for BatchCredentialErrorResponse {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidCredentialRequest => StatusCode::BAD_REQUEST,
            Self::UnsupportedCredentialType => StatusCode::BAD_REQUEST,
            Self::UnsupportedCredentialFormat => StatusCode::BAD_REQUEST,
            Self::InvalidProof => StatusCode::BAD_REQUEST,
            Self::InvalidToken => StatusCode::UNAUTHORIZED,
            Self::InvalidEncryptionParameters => StatusCode::BAD_REQUEST,
        }
    }
}

/// Deferred Credential Error Response as defined in OpenID4VCI - draft 13 - Section 9.3: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#name-deferred-credential-error-r
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeferredCredentialErrorResponse {
    InvalidCredentialRequest,
    UnsupportedCredentialType,
    UnsupportedCredentialFormat,
    InvalidProof,
    InvalidToken,
    InvalidEncryptionParameters,
    IssuancePending,
    InvalidTransactionId,
}

impl ErrorStatusCode for DeferredCredentialErrorResponse {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidCredentialRequest => StatusCode::BAD_REQUEST,
            Self::UnsupportedCredentialType => StatusCode::BAD_REQUEST,
            Self::UnsupportedCredentialFormat => StatusCode::BAD_REQUEST,
            Self::InvalidProof => StatusCode::BAD_REQUEST,
            Self::InvalidEncryptionParameters => StatusCode::BAD_REQUEST,
            Self::IssuancePending => StatusCode::BAD_REQUEST,
            Self::InvalidTransactionId => StatusCode::BAD_REQUEST,
            Self::InvalidToken => StatusCode::UNAUTHORIZED,
        }
    }
}

/// Notification Error Response as defined in OpenID4VCI - draft 13 - Section 10.3: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#name-notification-error-response
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationErrorResponse {
    InvalidNotificationRequest,
    InvalidNotificationId,
    InvalidToken,
}

impl ErrorStatusCode for NotificationErrorResponse {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidNotificationRequest => StatusCode::BAD_REQUEST,
            Self::InvalidNotificationId => StatusCode::BAD_REQUEST,
            Self::InvalidToken => StatusCode::UNAUTHORIZED,
        }
    }
}

pub fn to_http_response<T>(error: OID4VCError<T>) -> Response<OID4VCError<T>>
where
    T: ErrorStatusCode + Serialize,
{
    let status = error.error.status_code();

    let mut response = Response::new(error);
    *response.status_mut() = status;
    response.headers_mut().insert(
        "Content-Type",
        http::header::HeaderValue::from_static("application/json"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_oid4vc_error() {
        let response =
            to_http_response(OID4VCError::new(CredentialErrorResponse::InvalidProof).with_description("Invalid proof"));
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            json!({
                "error": "invalid_proof",
                "error_description": "Invalid proof"
            }),
            json!(response.body())
        );
        assert!(
            response
                .headers()
                .get("Content-Type")
                .and_then(|v| v.to_str().ok())
                .map_or(false, |content_type| content_type == "application/json"),
            "Content-Type header should be application/json"
        );
    }
}

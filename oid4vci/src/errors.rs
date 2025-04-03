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

/// Credential Error Response as defined in OpenID4VCI - draft 13 - Section 7.3.1: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#name-credential-error-response

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialErrorResponse {
    InvalidCredentialRequest,
    UnsupportedCredentialType,
    UnsupportedCredentialFormat,
    InvalidProof,
    InvalidEncryptionParameters,
}

impl ErrorStatusCode for CredentialErrorResponse {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidCredentialRequest => StatusCode::BAD_REQUEST,
            Self::UnsupportedCredentialType => StatusCode::BAD_REQUEST,
            Self::UnsupportedCredentialFormat => StatusCode::BAD_REQUEST,
            Self::InvalidProof => StatusCode::BAD_REQUEST,
            Self::InvalidEncryptionParameters => StatusCode::BAD_REQUEST,
        }
    }
}
/// Notification Error Response as defined in OpenID4VCI - draft 13 - Section 10.3: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#name-notification-error-response
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationErrorResponse {
    InvalidNotificationRequest,
    InvalidNotificationId,
    MissingNotificationParameter,
    InvalidToken,
}

impl ErrorStatusCode for NotificationErrorResponse {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidNotificationRequest => StatusCode::BAD_REQUEST,
            Self::InvalidNotificationId => StatusCode::BAD_REQUEST,
            Self::MissingNotificationParameter => StatusCode::BAD_REQUEST,
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

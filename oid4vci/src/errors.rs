use http::{Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::fmt::Display;
use strum_macros::AsRefStr;
use thiserror::Error;

pub trait ResponseErrorType {}
pub trait ErrorStatusCode {
    fn status_code(&self) -> StatusCode;
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Error)]
pub struct OID4VCError<T>
where
    T: ResponseErrorType,
{
    pub error: T,
    pub error_description: Option<String>,
}

impl<T> OID4VCError<T>
where
    T: ResponseErrorType,
{
    pub fn new(error: T) -> Self {
        Self {
            error,
            error_description: None,
        }
    }

    pub fn new_with_description(self, error_description: &str) -> Self {
        Self {
            error_description: Some(error_description.to_string()),
            ..self
        }
    }
}

impl<T> Display for OID4VCError<T>
where
    T: ResponseErrorType + std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Error: {:?}", self.error)?;
        if let Some(desc) = &self.error_description {
            write!(f, " - {}", desc)?;
        }
        Ok(())
    }
}

// - - - Notification Error Type !

#[derive(Debug, Serialize, Deserialize, AsRefStr)]
#[serde(rename_all = "snake_case")]
pub enum NotificationRequestErrorResponse {
    InvalidNotificationRequest,
    InvalidNotificationId,
    MissingNotificationParameter,
    InvalidToken,
}

impl ResponseErrorType for NotificationRequestErrorResponse {}

impl ErrorStatusCode for NotificationRequestErrorResponse {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidNotificationRequest => StatusCode::BAD_REQUEST,
            Self::InvalidNotificationId => StatusCode::BAD_REQUEST,
            Self::MissingNotificationParameter => StatusCode::BAD_REQUEST,
            Self::InvalidToken => StatusCode::UNAUTHORIZED,
        }
    }
}

// - - - Credential Error Type !

#[derive(Debug, Serialize, Deserialize, AsRefStr)]
#[serde(rename_all = "snake_case")]
pub enum CredentialRequestErrorResponse {
    InvalidCredentialRequest,
    UnsupportedCredentialType,
    UnsupportedCredentialFormat,
    InvalidProof,
    InvalidEncryptionParameters,
}

impl ResponseErrorType for CredentialRequestErrorResponse {}

impl ErrorStatusCode for CredentialRequestErrorResponse {
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
/// The HTTP response MUST use the HTTP status code 400 (Bad Request) and set the content type to application/json
pub fn to_http_response<T, B>(error: OID4VCError<T>) -> Response<B>
where
    T: ResponseErrorType + ErrorStatusCode + Serialize,
    B: From<Vec<u8>>,
{
    let status = error.error.status_code();
    let body = serde_json::to_vec(&error).unwrap_or_default();

    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(B::from(body))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(B::from(Vec::new()))
                .unwrap()
        })
}

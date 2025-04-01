use axum::{
    extract::Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use strum_macros::AsRefStr;
use thiserror::Error;

/// The HTTP response MUST use the HTTP status code 400 (Bad Request) and set the content type to application/json
#[derive(Debug, Error, Serialize, Deserialize, AsRefStr)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum NotificationError {
    #[error("The notification value is invalid")]
    InvalidNotificationRequest,
    #[error("The `notification_id` value is missing or invalid")]
    InvalidNotificationId,
    #[error("A required parameter is missing")]
    MissingNotificationParameter,
    #[error("Your access token is invalid or expired")]
    InvalidToken,
}

impl NotificationError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidNotificationRequest => StatusCode::BAD_REQUEST,
            Self::InvalidNotificationId => StatusCode::BAD_REQUEST,
            Self::MissingNotificationParameter => StatusCode::BAD_REQUEST,
            Self::InvalidToken => StatusCode::UNAUTHORIZED,
        }
    }
    pub fn error_code(&self) -> &str {
        self.as_ref()
    }
}

impl IntoResponse for NotificationError {
    fn into_response(self) -> Response {
        let body = Json(serde_json::json!({
            "error": self.error_code(),
            "error_description": self.to_string(), // uses the #[error] message from thiserror
        }));
        (self.status_code(), body).into_response()
    }
}
/// The HTTP response MUST use the HTTP status code 400 (Bad Request) and set the content type to application/json
#[derive(Debug, Error, Serialize, Deserialize, AsRefStr)]
#[serde(rename_all = "snake_case")]
pub enum CredentialRequestError {
    #[error("The Credential Request is missing a required parameter, includes an unsupported parameter or parameter value, repeats the same parameter, or is otherwise malformed.")]
    InvalidCredentialRequest,
    #[error("The requested credential type is not supported")]
    UnsupportedCredentialType,
    #[error("The reqeusted credential format is not supported")]
    UnsupportedCredentialFormat,
    #[error("The proof in the Credential Request is invalid. The proof field is not present or the provided key proof is invalid or not bound to a nonce provided by the Credential Issuer.")]
    InvalidProof,
    #[error("The encryption parameters are invalid")]
    InvalidEncryptionParameters,
}

impl CredentialRequestError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidCredentialRequest => StatusCode::BAD_REQUEST,
            Self::UnsupportedCredentialType => StatusCode::BAD_REQUEST,
            Self::UnsupportedCredentialFormat => StatusCode::BAD_REQUEST,
            Self::InvalidProof => StatusCode::BAD_REQUEST,
            Self::InvalidEncryptionParameters => StatusCode::BAD_REQUEST,
        }
    }

    pub fn error_code(&self) -> &str {
        self.as_ref()
    }
}

impl IntoResponse for CredentialRequestError {
    fn into_response(self) -> Response {
        let body = Json(serde_json::json!({
            "error": self.error_code(),
            "error_description": self.to_string(),
        }));
        (self.status_code(), body).into_response()
    }
}

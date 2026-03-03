//! Unified HTTP error type for consistent API responses.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use serde_json::json;

/// Unified error type for all HTTP responses.
/// Provides consistent error formatting across all endpoints.
#[derive(Debug)]
#[allow(dead_code)]
pub enum HttpError {
    /// 400 Bad Request - invalid input or malformed request
    BadRequest(String),
    /// 401 Unauthorized - missing or invalid authentication
    Unauthorized(String),
    /// 500 Internal Server Error - unexpected server failure
    InternalError(String),
    /// OAuth-specific error with code and description (RFC 6749)
    OAuthError {
        status: StatusCode,
        code: String,
        description: String,
    },
}

#[allow(dead_code)]
impl HttpError {
    /// Create a bad request error
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest(message.into())
    }

    /// Create an unauthorized error
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::Unauthorized(message.into())
    }

    /// Create an internal server error
    pub fn internal(message: impl Into<String>) -> Self {
        Self::InternalError(message.into())
    }

    /// Create an OAuth error response
    pub fn oauth_error(
        status: StatusCode,
        code: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self::OAuthError {
            status,
            code: code.into(),
            description: description.into(),
        }
    }

    /// Create a server_error OAuth response (500)
    pub fn server_error(description: impl Into<String>) -> Self {
        Self::OAuthError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "server_error".to_string(),
            description: description.into(),
        }
    }

    /// Create an invalid_request OAuth response (400)
    pub fn invalid_request(description: impl Into<String>) -> Self {
        Self::OAuthError {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_request".to_string(),
            description: description.into(),
        }
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        match self {
            HttpError::BadRequest(msg) => {
                (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response()
            }
            HttpError::Unauthorized(msg) => {
                (StatusCode::UNAUTHORIZED, Json(json!({ "error": msg }))).into_response()
            }
            HttpError::InternalError(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": msg })),
            )
                .into_response(),
            HttpError::OAuthError {
                status,
                code,
                description,
            } => (
                status,
                Json(json!({
                    "error": code,
                    "error_description": description
                })),
            )
                .into_response(),
        }
    }
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::BadRequest(msg) => write!(f, "Bad Request: {}", msg),
            HttpError::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
            HttpError::InternalError(msg) => write!(f, "Internal Server Error: {}", msg),
            HttpError::OAuthError {
                code, description, ..
            } => {
                write!(f, "OAuth Error ({}): {}", code, description)
            }
        }
    }
}

impl std::error::Error for HttpError {}

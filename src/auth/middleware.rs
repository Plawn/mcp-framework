//! Bearer token authentication middleware.
//!
//! This middleware extracts Bearer tokens from requests and stores them
//! in the TokenStore so tools can access them.

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;

use base64::Engine as _;
use super::{TokenStore, StoredToken, BasicAuthConfig};

/// Shared state for the auth middleware
#[derive(Clone)]
pub struct AuthMiddlewareState {
    pub resource_url: String,
    pub resource_metadata_url: String,
    pub token_store: TokenStore,
}

/// Extension to store the Bearer token for downstream handlers
#[derive(Clone, Debug)]
pub struct BearerToken(pub String);

/// Middleware that extracts Bearer token from Authorization header
/// and stores it in request extensions for handlers to use.
///
/// If no token is present, returns 401 with WWW-Authenticate header
/// pointing to the OAuth protected resource metadata.
pub async fn bearer_auth_middleware(
    State(state): State<Arc<AuthMiddlewareState>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    // Extract Authorization header
    let auth_header = request.headers().get("authorization");

    tracing::info!("Auth middleware: checking request {} {}", request.method(), request.uri());

    let token = match auth_header {
        Some(header) => {
            let header_str = match header.to_str() {
                Ok(s) => s,
                Err(_) => {
                    tracing::warn!("Auth middleware: invalid authorization header encoding");
                    return unauthorized_response(&state.resource_metadata_url);
                }
            };

            if let Some(token) = header_str.strip_prefix("Bearer ") {
                tracing::info!("Auth middleware: found Bearer token (len={})", token.len());
                token.to_string()
            } else if let Some(token) = header_str.strip_prefix("bearer ") {
                tracing::info!("Auth middleware: found bearer token lowercase (len={})", token.len());
                token.to_string()
            } else {
                tracing::warn!("Auth middleware: authorization header not Bearer type: {}", &header_str[..header_str.len().min(20)]);
                return unauthorized_response(&state.resource_metadata_url);
            }
        }
        None => {
            // No auth header - return 401 with discovery info
            tracing::info!("Auth middleware: no authorization header, returning 401");
            return unauthorized_response(&state.resource_metadata_url);
        }
    };

    // Get the MCP session ID from headers (if present)
    let session_id = request
        .headers()
        .get("mcp-session-id")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "default".to_string());

    tracing::debug!("Bearer token found for session {}, storing and allowing request", session_id);

    // Store the token in the token store so tools can access it via session ID
    let stored_token = StoredToken {
        access_token: token.clone(),
        refresh_token: None,
        expires_at: None, // We don't know expiry from the bearer token alone
    };

    state.token_store.store_token(session_id, stored_token).await;

    // Also store in request extensions for direct access
    request.extensions_mut().insert(BearerToken(token));

    // Continue to next handler
    next.run(request).await
}

/// Returns a 401 response with WWW-Authenticate header for OAuth discovery
fn unauthorized_response(resource_metadata_url: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(
            "WWW-Authenticate",
            format!("Bearer resource_metadata=\"{}\"", resource_metadata_url),
        )],
        "Unauthorized: Bearer token required",
    )
        .into_response()
}

/// Shared state for the Basic auth middleware
#[derive(Clone)]
pub struct BasicAuthMiddlewareState {
    pub config: BasicAuthConfig,
    pub token_store: TokenStore,
}

/// Middleware that validates HTTP Basic authentication.
///
/// On success, stores the password as `StoredToken.access_token` in the
/// `TokenStore` so that tools can retrieve it via the same path as Bearer mode.
pub async fn basic_auth_middleware(
    State(state): State<Arc<BasicAuthMiddlewareState>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let auth_header = request.headers().get("authorization");

    tracing::debug!("Basic auth middleware: checking request to {}", request.uri());

    let (username, password) = match auth_header {
        Some(header) => {
            let header_str = match header.to_str() {
                Ok(s) => s,
                Err(_) => {
                    tracing::debug!("Basic auth middleware: invalid authorization header encoding");
                    return basic_unauthorized_response();
                }
            };

            let encoded = match header_str.strip_prefix("Basic ").or_else(|| header_str.strip_prefix("basic ")) {
                Some(e) => e,
                None => {
                    tracing::debug!("Basic auth middleware: authorization header not Basic type");
                    return basic_unauthorized_response();
                }
            };

            let decoded = match base64::engine::general_purpose::STANDARD.decode(encoded) {
                Ok(d) => d,
                Err(_) => {
                    tracing::debug!("Basic auth middleware: invalid base64 in credentials");
                    return basic_unauthorized_response();
                }
            };

            let decoded_str = match String::from_utf8(decoded) {
                Ok(s) => s,
                Err(_) => {
                    tracing::debug!("Basic auth middleware: credentials not valid UTF-8");
                    return basic_unauthorized_response();
                }
            };

            match decoded_str.split_once(':') {
                Some((u, p)) => (u.to_string(), p.to_string()),
                None => {
                    tracing::debug!("Basic auth middleware: malformed credentials (no colon)");
                    return basic_unauthorized_response();
                }
            }
        }
        None => {
            tracing::debug!("Basic auth middleware: no authorization header present");
            return basic_unauthorized_response();
        }
    };

    // Validate credentials
    if username != state.config.username || password != state.config.password {
        tracing::debug!("Basic auth middleware: invalid credentials for user '{}'", username);
        return basic_unauthorized_response();
    }

    let session_id = request
        .headers()
        .get("mcp-session-id")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "default".to_string());

    tracing::debug!("Basic auth validated for session {}, storing token", session_id);

    // Store the password as access_token so tools work identically to Bearer mode
    let stored_token = StoredToken {
        access_token: password.clone(),
        refresh_token: None,
        expires_at: None,
    };

    state.token_store.store_token(session_id, stored_token).await;

    request.extensions_mut().insert(BearerToken(password));

    next.run(request).await
}

/// Returns a 401 response with WWW-Authenticate header for Basic auth
fn basic_unauthorized_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [("WWW-Authenticate", "Basic realm=\"MCP\"")],
        "Unauthorized: Basic credentials required",
    )
        .into_response()
}

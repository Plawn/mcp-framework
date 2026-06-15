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
use super::config::TokenMode;
use crate::constants::{
    AUTHORIZATION_HEADER, BEARER_PREFIX, BEARER_PREFIX_LOWER,
    BASIC_PREFIX, BASIC_PREFIX_LOWER, BASIC_REALM,
    MCP_SESSION_ID_HEADER, DEFAULT_SESSION_ID, WWW_AUTHENTICATE_HEADER,
};

/// Shared state for the auth middleware
#[derive(Clone)]
pub struct AuthMiddlewareState {
    pub resource_url: String,
    pub resource_metadata_url: String,
    pub token_store: TokenStore,
    pub token_mode: TokenMode,
}

/// Extension to store the Bearer token for downstream handlers
#[derive(Clone, Debug)]
pub struct BearerToken(pub String);

/// Middleware that extracts Bearer token from Authorization header
/// and stores it in request extensions for handlers to use.
///
/// In **Passthrough** mode (default): the Bearer token is stored as-is.
///
/// In **Opaque** mode: the Bearer token is an opaque UUID issued by this
/// framework. The middleware resolves it to the real Keycloak token
/// (auto-refreshing if needed) and injects that for downstream handlers.
///
/// If no token is present, returns 401 with WWW-Authenticate header
/// pointing to the OAuth protected resource metadata.
pub async fn bearer_auth_middleware(
    State(state): State<Arc<AuthMiddlewareState>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    // Extract Authorization header
    let auth_header = request.headers().get(AUTHORIZATION_HEADER);

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

            if let Some(token) = header_str.strip_prefix(BEARER_PREFIX) {
                tracing::info!("Auth middleware: found Bearer token (len={})", token.len());
                token.to_string()
            } else if let Some(token) = header_str.strip_prefix(BEARER_PREFIX_LOWER) {
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

    if state.token_mode == TokenMode::Opaque {
        // Opaque mode: resolve opaque UUID → session_id → real Keycloak token
        let resolved_session = match state.token_store.resolve_opaque_access(&token).await {
            Some(sid) => sid,
            None => {
                tracing::warn!("Auth middleware: opaque token not found, returning 401");
                return unauthorized_response(&state.resource_metadata_url);
            }
        };

        // get_token auto-refreshes the Keycloak token if expired
        match state.token_store.get_token(&resolved_session).await {
            Some(real_token) => {
                tracing::debug!(
                    "Opaque token resolved for session '{}', injecting real token",
                    resolved_session
                );
                request.extensions_mut().insert(BearerToken(real_token.access_token));
            }
            None => {
                tracing::warn!(
                    "Keycloak token expired and refresh failed for session '{}', returning 401",
                    resolved_session
                );
                state.token_store.remove_opaque_for_session(&resolved_session).await;
                return unauthorized_response(&state.resource_metadata_url);
            }
        }
    } else {
        // Passthrough mode: track the bearer in the store WITHOUT destroying
        // the refresh_token / expires_at that the token handler stored at
        // the initial exchange. If the bearer JWT is expired and we have a
        // refresh_token, attempt a server-side refresh before giving up.
        let session_id = request
            .headers()
            .get(MCP_SESSION_ID_HEADER)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| DEFAULT_SESSION_ID.to_string());

        let existing = state.token_store.peek_token(&session_id).await;
        let has_refresh = existing.as_ref().and_then(|t| t.refresh_token.as_ref()).is_some();
        let bearer_expired = jwt_is_expired(&token).unwrap_or(false);

        if bearer_expired && has_refresh {
            // Server-side auto-refresh. get_token() drives refresh_token()
            // which updates the store atomically under the per-session lock.
            match state.token_store.get_token(&session_id).await {
                Some(refreshed) => {
                    tracing::info!(
                        "Bearer JWT expired, server-side refresh succeeded for session '{}'",
                        session_id
                    );
                    request.extensions_mut().insert(BearerToken(refreshed.access_token));
                    return next.run(request).await;
                }
                None => {
                    tracing::warn!(
                        "Bearer JWT expired and refresh failed for session '{}', returning 401",
                        session_id
                    );
                    return unauthorized_response(&state.resource_metadata_url);
                }
            }
        }

        tracing::debug!("Bearer token found for session {}, storing and allowing request", session_id);

        // Preserve refresh_token + expires_at from any existing entry so that
        // a later request with an expired bearer can still trigger refresh.
        // Only write back when something actually changed.
        let needs_store = match &existing {
            Some(prev) => prev.access_token != token,
            None => true,
        };

        if needs_store {
            let (refresh_token, expires_at) = match existing {
                Some(prev) => (prev.refresh_token, prev.expires_at),
                None => (None, None),
            };
            let stored_token = StoredToken {
                access_token: token.clone(),
                refresh_token,
                expires_at,
                decoded_claims: None,
            };
            state.token_store.store_token(session_id, stored_token).await;
        }

        request.extensions_mut().insert(BearerToken(token));
    }

    // Continue to next handler
    next.run(request).await
}

/// Decode the JWT payload (without signature verification) and return
/// whether the `exp` claim is in the past.
///
/// Returns `None` when the token is not a parseable JWT or has no `exp`
/// claim — callers should treat that as "unknown, don't refresh".
/// The actual signature is validated by the downstream API; the middleware
/// only needs `exp` to decide whether a server-side refresh is warranted.
fn jwt_is_expired(token: &str) -> Option<bool> {
    let payload_b64 = token.split('.').nth(1)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    let json: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    let exp = json.get("exp")?.as_u64()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some(now >= exp)
}

/// Returns a 401 response with WWW-Authenticate header for OAuth discovery
fn unauthorized_response(resource_metadata_url: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(
            WWW_AUTHENTICATE_HEADER,
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
    let auth_header = request.headers().get(AUTHORIZATION_HEADER);

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

            let encoded = match header_str.strip_prefix(BASIC_PREFIX).or_else(|| header_str.strip_prefix(BASIC_PREFIX_LOWER)) {
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
        .get(MCP_SESSION_ID_HEADER)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| DEFAULT_SESSION_ID.to_string());

    tracing::debug!("Basic auth validated for session {}, storing token", session_id);

    // Store the password as access_token so tools work identically to Bearer mode
    let stored_token = StoredToken {
        access_token: password.clone(),
        refresh_token: None,
        expires_at: None,
        decoded_claims: None,
    };

    state.token_store.store_token(session_id, stored_token).await;

    request.extensions_mut().insert(BearerToken(password));

    next.run(request).await
}

/// Returns a 401 response with WWW-Authenticate header for Basic auth
fn basic_unauthorized_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(WWW_AUTHENTICATE_HEADER, BASIC_REALM)],
        "Unauthorized: Basic credentials required",
    )
        .into_response()
}

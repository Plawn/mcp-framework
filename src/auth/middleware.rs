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

use super::config::TokenMode;
use super::store::TokenIntrospection;
use super::{BasicAuthConfig, StoredToken, TokenStore};
use crate::constants::{
    AUTHORIZATION_HEADER, BASIC_PREFIX, BASIC_PREFIX_LOWER, BASIC_REALM, BEARER_PREFIX,
    BEARER_PREFIX_LOWER, MCP_FALLBACK_SESSION_HEADER, MCP_SESSION_ID_HEADER,
    WWW_AUTHENTICATE_HEADER,
};
use base64::Engine as _;
use sha2::{Digest, Sha256};

/// Derive a stable session identity from a credential.
///
/// The credential is hashed, so the derived id is safe to log and cannot be
/// reversed into the token it came from. The same credential always maps to the
/// same id, which is what lets a sessionless client be recognised across
/// requests and what lets the `/oauth/token` exchange pre-register an entry the
/// auth middleware will later find (see [`bearer_auth_middleware`]).
pub(crate) fn credential_session_key(credential: &str) -> String {
    let digest = Sha256::digest(credential.as_bytes());
    format!(
        "cred-{}",
        digest[..16].iter().fold(String::new(), |mut acc, b| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{b:02x}");
            acc
        })
    )
}

/// Bind a request to a framework session identity.
///
/// Deliberately NOT `mcp-session-id`: writing that header back would make
/// rmcp's Streamable HTTP transport look up a session that never existed.
fn set_framework_session_id(request: &mut Request<Body>, session_id: &str) {
    if let Ok(value) = session_id.parse() {
        request
            .headers_mut()
            .insert(MCP_FALLBACK_SESSION_HEADER, value);
    }
}

/// Strip any client-supplied [`MCP_FALLBACK_SESSION_HEADER`] before auth runs.
///
/// The header is framework-internal and authoritative for session identity (see
/// [`session_id_from_parts`]), so a client able to set it could bind its request
/// to another user's session and read their tokens. Only the auth middleware may
/// write it, and only after validating the credential it is derived from.
///
/// Applied to every request, including under [`AuthProvider::None`] where no
/// auth middleware runs to overwrite it.
///
/// [`session_id_from_parts`]: crate::session::session_id_from_parts
/// [`AuthProvider::None`]: crate::auth::AuthProvider::None
pub async fn strip_framework_session_header(mut request: Request<Body>, next: Next) -> Response {
    request.headers_mut().remove(MCP_FALLBACK_SESSION_HEADER);
    next.run(request).await
}

/// Resolve the session identity for a request, deriving one when the protocol
/// does not supply it.
///
/// MCP 2026-07-28 (SEP-2567) removes protocol sessions, so `mcp-session-id` is
/// absent for clients on that revision. Falling back to a single shared
/// `"default"` id would make every concurrent client read and overwrite the
/// same `TokenStore` entry — one user's bearer token served to another. Instead
/// we derive a stable id from the credential and inject it under
/// [`MCP_FALLBACK_SESSION_HEADER`] so the rest of the framework
/// (`resolve_session_id`, `resolve_token`) resolves it uniformly.
fn resolve_or_derive_session_id(request: &mut Request<Body>, credential: &str) -> String {
    if let Some(sid) = request
        .headers()
        .get(MCP_SESSION_ID_HEADER)
        .and_then(|h| h.to_str().ok())
    {
        return sid.to_string();
    }

    let derived = credential_session_key(credential);
    set_framework_session_id(request, &derived);
    derived
}

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
/// In **Passthrough** mode (default): tokens issued through this framework's
/// OAuth proxy are checked against the token store and their recorded expiry.
/// Unknown tokens are introspected with the authorization server before being
/// stored, which keeps bring-your-own-token clients working without trusting an
/// arbitrary non-empty header.
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

    tracing::info!(
        "Auth middleware: checking request {} {}",
        request.method(),
        request.uri()
    );

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
                tracing::info!(
                    "Auth middleware: found bearer token lowercase (len={})",
                    token.len()
                );
                token.to_string()
            } else {
                tracing::warn!(
                    "Auth middleware: authorization header not Bearer type: {}",
                    &header_str[..header_str.len().min(20)]
                );
                return unauthorized_response(&state.resource_metadata_url);
            }
        }
        None => {
            // No auth header - return 401 with discovery info
            tracing::info!("Auth middleware: no authorization header, returning 401");
            return unauthorized_response(&state.resource_metadata_url);
        }
    };

    if token.is_empty() {
        tracing::warn!("Auth middleware: empty Bearer token, returning 401");
        return unauthorized_response(&state.resource_metadata_url);
    }

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
                // The grant, not the protocol session, is the identity here:
                // the opaque token outlives any `mcp-session-id` and is what
                // keys the token store. Bind the request to it unconditionally
                // so `ctx.session_id()` and the token store agree, and so a
                // reconnect lands back on the same session.
                set_framework_session_id(&mut request, &resolved_session);
                request
                    .extensions_mut()
                    .insert(BearerToken(real_token.access_token));
            }
            None => {
                tracing::warn!(
                    "Keycloak token expired and refresh failed for session '{}', returning 401",
                    resolved_session
                );
                state
                    .token_store
                    .remove_opaque_for_session(&resolved_session)
                    .await;
                return unauthorized_response(&state.resource_metadata_url);
            }
        }
    } else {
        // Passthrough mode: track the bearer in the store WITHOUT destroying
        // the refresh_token / expires_at that the token handler stored at
        // the initial exchange. If the bearer JWT is expired and we have a
        // refresh_token, attempt a server-side refresh before giving up.
        let session_id = resolve_or_derive_session_id(&mut request, &token);

        // The `/oauth/token` exchange keys its entry by the credential, because
        // no MCP session exists at that point. Adopt that entry the first time a
        // protocol session shows up with the same bearer — otherwise the
        // `refresh_token` it captured is unreachable and server-side refresh can
        // never fire. When the id was derived from the credential the two keys
        // coincide and this is a no-op.
        let grant_key = credential_session_key(&token);
        let session_token = state.token_store.peek_token(&session_id).await;
        let matching_session_token = session_token
            .as_ref()
            .filter(|stored| stored.access_token == token)
            .cloned();
        let matching_grant_token = if matching_session_token.is_none() && grant_key != session_id {
            state
                .token_store
                .peek_token(&grant_key)
                .await
                .filter(|stored| stored.access_token == token)
        } else {
            None
        };

        // A new bearer on a session that already carries one is rejected when it
        // belongs to a different principal. Unknown credentials are introspected
        // below before any session state is mutated, so reading `sub` without
        // verifying the signature here is only used for the identity comparison.
        //
        // A legitimate "bring your own token" client rotates its access token —
        // Keycloak hands back a fresh JWT for the same user on every exchange, so
        // the `sub` is stable even though the bytes differ. That rotation is
        // accepted, but never combines the new bearer with refresh material
        // belonging to the previous one: `matching_token` stays `None` here, so
        // the store below falls back to `(None, None)`. A rotation already
        // pre-registered by `/oauth/token` is caught earlier by
        // `matching_grant_token` and keeps its captured refresh_token.
        if session_token.is_some()
            && matching_session_token.is_none()
            && matching_grant_token.is_none()
        {
            let same_principal = jwt_subject(&token)
                .zip(
                    session_token
                        .as_ref()
                        .and_then(|stored| jwt_subject(&stored.access_token)),
                )
                .is_some_and(|(new_sub, prev_sub)| new_sub == prev_sub);

            if !same_principal {
                tracing::warn!(
                    "Bearer principal does not match the principal bound to session '{}', returning 401",
                    session_id
                );
                return unauthorized_response(&state.resource_metadata_url);
            }
        }

        let matching_token = matching_session_token.or(matching_grant_token);

        // A token captured by `/oauth/token` is already trusted and carries the
        // authorization server's expiry in the store. A bring-your-own token is
        // unknown to the store, so validate it with Keycloak before allowing it
        // to create or replace a session entry. This is the boundary that rejects
        // arbitrary bearer strings and JWTs with invalid signatures.
        let introspected_expiry = if matching_token.is_none() {
            match state.token_store.introspect_access_token(&token).await {
                TokenIntrospection::Active { expires_at } => expires_at,
                TokenIntrospection::Inactive => {
                    tracing::warn!("Bearer token is inactive or invalid, returning 401");
                    return unauthorized_response(&state.resource_metadata_url);
                }
            }
        } else {
            None
        };

        let candidate = matching_token
            .clone()
            .unwrap_or_else(|| StoredToken::new(token.clone(), None, introspected_expiry));
        let token_is_expired = candidate.is_expired() || jwt_is_expired(&token).unwrap_or(false);
        let has_refresh = candidate.refresh_token.is_some();

        // Expired credentials are never passed to the MCP handler. They may only
        // continue after the framework has successfully refreshed them.
        if token_is_expired && !has_refresh {
            tracing::warn!("Bearer token expired and cannot be refreshed, returning 401");
            return unauthorized_response(&state.resource_metadata_url);
        }

        // Materialize the entry under `session_id` *before* attempting refresh:
        // refresh_token() operates on the store keyed by session id. Preserve
        // refresh_token + expires_at so an expired bearer can still be
        // refreshed. Only write back when something actually changed.
        let needs_store = session_token
            .as_ref()
            .is_none_or(|previous| previous.access_token != token);
        if needs_store {
            let (refresh_token, expires_at) = matching_token
                .as_ref()
                .map(|prev| (prev.refresh_token.clone(), prev.expires_at))
                .unwrap_or((None, introspected_expiry));
            let stored_token = StoredToken {
                access_token: token.clone(),
                refresh_token,
                expires_at,
                decoded_claims: None,
            };
            state
                .token_store
                .store_token(session_id.clone(), stored_token)
                .await;
        }

        if token_is_expired {
            // Server-side auto-refresh. get_token() drives refresh_token()
            // which updates the store atomically under the per-session lock.
            match state.token_store.get_token(&session_id).await {
                Some(refreshed) => {
                    tracing::info!(
                        "Bearer JWT expired, server-side refresh succeeded for session '{}'",
                        session_id
                    );
                    request
                        .extensions_mut()
                        .insert(BearerToken(refreshed.access_token));
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

        tracing::debug!(
            "Bearer token found for session {}, allowing request",
            session_id
        );

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

/// Decode the JWT payload (without signature verification) and return the
/// `sub` (subject) claim.
///
/// Returns `None` when the token is not a parseable JWT or carries no string
/// `sub`. Like [`jwt_is_expired`], this reads the payload directly rather than
/// going through the consumer's `claims_decoder`, so the middleware stays
/// agnostic of the concrete claims type while still able to compare principals
/// across a bearer rotation.
fn jwt_subject(token: &str) -> Option<String> {
    let payload_b64 = token.split('.').nth(1)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    let json: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    json.get("sub")?.as_str().map(str::to_string)
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

    tracing::debug!(
        "Basic auth middleware: checking request to {}",
        request.uri()
    );

    let (username, password) = match auth_header {
        Some(header) => {
            let header_str = match header.to_str() {
                Ok(s) => s,
                Err(_) => {
                    tracing::debug!("Basic auth middleware: invalid authorization header encoding");
                    return basic_unauthorized_response();
                }
            };

            let encoded = match header_str
                .strip_prefix(BASIC_PREFIX)
                .or_else(|| header_str.strip_prefix(BASIC_PREFIX_LOWER))
            {
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
        tracing::debug!(
            "Basic auth middleware: invalid credentials for user '{}'",
            username
        );
        return basic_unauthorized_response();
    }

    let session_id = resolve_or_derive_session_id(&mut request, &password);

    tracing::debug!(
        "Basic auth validated for session {}, storing token",
        session_id
    );

    // Store the password as access_token so tools work identically to Bearer mode
    let stored_token = StoredToken {
        access_token: password.clone(),
        refresh_token: None,
        expires_at: None,
        decoded_claims: None,
    };

    state
        .token_store
        .store_token(session_id, stored_token)
        .await;

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

#[cfg(test)]
mod tests {
    use super::*;

    fn request_with(headers: &[(&'static str, &str)]) -> Request<Body> {
        let mut builder = Request::builder().uri("/mcp");
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        builder.body(Body::empty()).unwrap()
    }

    #[test]
    fn protocol_session_id_wins_and_is_not_overwritten() {
        let mut request = request_with(&[(MCP_SESSION_ID_HEADER, "sess-abc")]);
        let resolved = resolve_or_derive_session_id(&mut request, "token-1");

        assert_eq!(resolved, "sess-abc");
        assert!(request.headers().get(MCP_FALLBACK_SESSION_HEADER).is_none());
    }

    #[test]
    fn sessionless_request_derives_a_stable_per_credential_id() {
        let mut a1 = request_with(&[]);
        let mut a2 = request_with(&[]);
        let mut b = request_with(&[]);

        let id_a1 = resolve_or_derive_session_id(&mut a1, "token-a");
        let id_a2 = resolve_or_derive_session_id(&mut a2, "token-a");
        let id_b = resolve_or_derive_session_id(&mut b, "token-b");

        // Same credential → same session across requests (stateless HTTP has
        // no protocol session to carry it), different credentials → isolated.
        assert_eq!(id_a1, id_a2);
        assert_ne!(id_a1, id_b);
        assert!(id_a1.starts_with("cred-"));

        // Never the shared default, and never the credential itself.
        assert_ne!(id_a1, crate::constants::DEFAULT_SESSION_ID);
        assert!(!id_a1.contains("token-a"));

        // The cross-module contract `/oauth/token` depends on: the exchange
        // stores the grant under `credential_session_key(access_token)` before
        // any MCP session exists, and this is the only reason the middleware can
        // find it again later from the bearer alone.
        assert_eq!(id_a1, credential_session_key("token-a"));
    }

    #[test]
    fn derived_id_is_injected_under_the_framework_header_only() {
        let mut request = request_with(&[]);
        let derived = resolve_or_derive_session_id(&mut request, "token-a");

        assert_eq!(
            request
                .headers()
                .get(MCP_FALLBACK_SESSION_HEADER)
                .and_then(|h| h.to_str().ok()),
            Some(derived.as_str()),
        );
        // Writing mcp-session-id back would make rmcp look up a session that
        // never existed and reject the request.
        assert!(request.headers().get(MCP_SESSION_ID_HEADER).is_none());
    }
}

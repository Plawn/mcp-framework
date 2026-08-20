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
use super::{BasicAuthConfig, StoredToken, TokenStore};
use crate::constants::{
    AUTHORIZATION_HEADER, BASIC_PREFIX, BASIC_PREFIX_LOWER, BASIC_REALM, BEARER_PREFIX,
    BEARER_PREFIX_LOWER, MCP_FALLBACK_SESSION_HEADER, MCP_SESSION_ID_HEADER,
    WWW_AUTHENTICATE_HEADER,
};
use base64::Engine as _;
use sha2::{Digest, Sha256};

/// Truncated sha256 hex of an arbitrary string — the hashing scheme shared by
/// every [`credential_session_key`] family.
fn short_hash(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest[..16].iter().fold(String::new(), |mut acc, b| {
        use std::fmt::Write as _;
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

/// Derive a stable session identity from a credential.
///
/// The identity is taken from the most *stable* thing the credential carries,
/// so that it survives the client rotating its bearer:
///
/// | source | key | stability |
/// |---|---|---|
/// | `sid` claim | `cred-sid-{hash}` | Keycloak SSO session — unchanged across every refresh |
/// | `sub` claim | `cred-sub-{hash}` | the principal — stable, but shared by all their sessions |
/// | raw bytes | `cred-{hash}` | changes on every rotation (non-JWT credentials only) |
///
/// Hashing the bearer bytes was the original scheme, and it breaks as soon as
/// the client refreshes: a resource-server bearer rotates every few minutes, so
/// the derived identity would change with it and the [`SessionStore`] entry it
/// keyed would be orphaned for its whole TTL. `sid` (with `sub` as a fallback)
/// keeps one identity for the whole SSO session. The byte hash remains for
/// credentials that are not JWTs at all (opaque bearers, Basic auth passwords).
///
/// The three families carry distinct prefixes, so a `sid` value that happens to
/// equal another token's `sub` can never collapse two identities into one.
/// Every value is hashed, so the derived id is safe to log and cannot be
/// reversed into the claim (or token) it came from.
///
/// The same credential always maps to the same id, which is what lets a
/// sessionless client be recognised across requests and what lets the
/// `/oauth/token` exchange pre-register an entry the auth middleware will later
/// find (see [`bearer_auth_middleware`]).
///
/// [`SessionStore`]: crate::session::SessionStore
pub(crate) fn credential_session_key(credential: &str) -> String {
    if let Some(sid) = jwt_claim(credential, "sid") {
        return format!("cred-sid-{}", short_hash(&sid));
    }
    if let Some(sub) = jwt_claim(credential, "sub") {
        return format!("cred-sub-{}", short_hash(&sub));
    }
    format!("cred-{}", short_hash(credential))
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
/// we derive a stable id from the credential's claims (see
/// [`credential_session_key`]) and inject it under
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
        //
        // Since the key is derived from `sid`/`sub` rather than the bearer bytes,
        // a refreshed grant re-exchanged through `/oauth/token` overwrites the
        // same entry instead of creating a new one — so the adoption below finds
        // the *current* refresh material rather than a stale sibling.
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
            let previous_credential = session_token
                .as_ref()
                .map(|stored| stored.access_token.as_str());
            let same_subject = jwt_subject(&token)
                .zip(previous_credential.and_then(jwt_subject))
                .is_some_and(|(new_sub, prev_sub)| new_sub == prev_sub);
            // A token carrying `sid` but no `sub` still has a stable identity:
            // two credentials deriving the same session key are the same SSO
            // session by construction. The byte-hash family can never match here
            // (identical bytes would have been caught as `matching_session_token`),
            // so this only ever accepts a claims-derived match.
            let same_derived_identity = previous_credential
                .is_some_and(|prev| credential_session_key(&token) == credential_session_key(prev));
            let same_principal = same_subject || same_derived_identity;

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
        // unknown to the store, so validate it — locally against the issuer's
        // JWKS, or with Keycloak — before allowing it to create or replace a
        // session entry. This is the boundary that rejects arbitrary bearer
        // strings and JWTs with invalid signatures.
        let validated_expiry = if matching_token.is_none() {
            match state.token_store.validate_unknown_bearer(&token).await {
                Ok(validated) => {
                    tracing::debug!(
                        session = %session_id,
                        source = ?validated.source,
                        subject = validated.subject.as_deref().unwrap_or("<none>"),
                        "Accepted a bearer this framework did not issue"
                    );
                    validated.expires_at
                }
                Err(rejection) => {
                    // The client always sees the same opaque 401 — the cause is
                    // for the operator's logs only, and separates "your token is
                    // bad" from "this server's OAuth client is misconfigured".
                    tracing::warn!("Rejecting bearer for session '{session_id}': {rejection}");
                    return unauthorized_response(&state.resource_metadata_url);
                }
            }
        } else {
            None
        };

        let candidate = matching_token
            .clone()
            .unwrap_or_else(|| StoredToken::new(token.clone(), None, validated_expiry));
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
                .unwrap_or((None, validated_expiry));
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

/// Decode the JWT payload (without signature verification) and return a string
/// claim from it.
///
/// Returns `None` when the token is not a parseable JWT or carries no such
/// string claim. Like [`jwt_is_expired`], this reads the payload directly rather
/// than going through the consumer's `claims_decoder`, so the middleware stays
/// agnostic of the concrete claims type.
///
/// **No signature is verified here.** The value is only ever used to *partition*
/// state (session identity, principal comparison); whether the token may be used
/// at all is decided separately by `validate_unknown_bearer` — JWKS signature
/// check or introspection — before any of that state is written.
fn jwt_claim(token: &str, claim: &str) -> Option<String> {
    let payload_b64 = token.split('.').nth(1)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    let json: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    json.get(claim)?.as_str().map(str::to_string)
}

/// The `sub` (subject) claim of a JWT, used to compare principals across a
/// bearer rotation. See [`jwt_claim`].
fn jwt_subject(token: &str) -> Option<String> {
    jwt_claim(token, "sub")
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

    /// Build a JWT-shaped token (`header.payload.sig`) whose payload is the
    /// given JSON object body, base64url-encoded like a real one. No signature
    /// is produced: nothing under test verifies one.
    fn jwt(payload: &str) -> String {
        let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!(
            "{}.{}.sig",
            enc.encode(br#"{"alg":"RS256","typ":"JWT"}"#),
            enc.encode(payload.as_bytes())
        )
    }

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
    fn sessionless_identity_survives_a_bearer_rotation_within_one_sso_session() {
        // Two distinct JWTs — different `jti`, different `exp`, different bytes —
        // for the same Keycloak SSO session. This is what a resource-server
        // client looks like every 5-15 minutes.
        let mut r1 = request_with(&[]);
        let mut r2 = request_with(&[]);
        let t1 = jwt(r#"{"sub":"alice","sid":"sso-1","jti":"a","exp":1}"#);
        let t2 = jwt(r#"{"sub":"alice","sid":"sso-1","jti":"b","exp":2}"#);
        assert_ne!(t1, t2);

        let id1 = resolve_or_derive_session_id(&mut r1, &t1);
        let id2 = resolve_or_derive_session_id(&mut r2, &t2);

        // The whole point of the ticket: the rotation must not orphan the
        // SessionStore entry keyed by this id.
        assert_eq!(id1, id2);
        assert!(id1.starts_with("cred-sid-"));
        // The claim value itself never appears in the id.
        assert!(!id1.contains("sso-1"));
    }

    #[test]
    fn a_different_sso_session_is_a_different_identity() {
        let alice_a = credential_session_key(&jwt(r#"{"sub":"alice","sid":"sso-1"}"#));
        let alice_b = credential_session_key(&jwt(r#"{"sub":"alice","sid":"sso-2"}"#));
        let bob = credential_session_key(&jwt(r#"{"sub":"bob","sid":"sso-3"}"#));

        assert_ne!(alice_a, alice_b);
        assert_ne!(alice_a, bob);
    }

    #[test]
    fn a_jwt_without_sid_falls_back_to_sub() {
        let t1 = credential_session_key(&jwt(r#"{"sub":"alice","jti":"a"}"#));
        let t2 = credential_session_key(&jwt(r#"{"sub":"alice","jti":"b"}"#));
        let other = credential_session_key(&jwt(r#"{"sub":"bob"}"#));

        assert!(t1.starts_with("cred-sub-"));
        assert_eq!(t1, t2);
        assert_ne!(t1, other);
    }

    #[test]
    fn a_non_jwt_credential_falls_back_to_the_byte_hash() {
        // Opaque bearers and Basic auth passwords carry no claims at all.
        let opaque = credential_session_key("6f1c1f6e-0f37-4f1e-9f0a-1d2c3b4a5968");
        assert!(opaque.starts_with("cred-"));
        assert!(!opaque.starts_with("cred-sid-"));
        assert!(!opaque.starts_with("cred-sub-"));

        // A JWT-shaped token whose payload carries neither claim, and one whose
        // payload is not decodable, both land here too.
        let claimless = credential_session_key(&jwt(r#"{"jti":"a"}"#));
        assert!(!claimless.starts_with("cred-sid-"));
        assert!(!claimless.starts_with("cred-sub-"));
        assert_eq!(
            credential_session_key("not.a.jwt"),
            credential_session_key("not.a.jwt")
        );
    }

    #[test]
    fn the_sid_sub_and_bytes_families_never_collide() {
        // Same value in all three positions: only the family prefix separates
        // them, which is exactly why the prefixes exist.
        let by_sid = credential_session_key(&jwt(r#"{"sid":"same-value"}"#));
        let by_sub = credential_session_key(&jwt(r#"{"sub":"same-value"}"#));
        let by_bytes = credential_session_key("same-value");

        assert_ne!(by_sid, by_sub);
        assert_ne!(by_sid, by_bytes);
        assert_ne!(by_sub, by_bytes);

        // And `sid` outranks `sub` when both are present.
        assert_eq!(
            credential_session_key(&jwt(r#"{"sub":"alice","sid":"same-value"}"#)),
            by_sid
        );
    }

    #[test]
    fn jwt_claim_reads_string_claims_only() {
        let token = jwt(r#"{"sub":"alice","sid":"sso-1","exp":123,"aud":["a","b"]}"#);

        assert_eq!(jwt_claim(&token, "sid").as_deref(), Some("sso-1"));
        assert_eq!(jwt_subject(&token).as_deref(), Some("alice"));
        // Non-string and absent claims are indistinguishable to callers, which
        // is what keeps `credential_session_key` falling through cleanly.
        assert_eq!(jwt_claim(&token, "exp"), None);
        assert_eq!(jwt_claim(&token, "aud"), None);
        assert_eq!(jwt_claim(&token, "nope"), None);
        assert_eq!(jwt_claim("opaque-token", "sid"), None);
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

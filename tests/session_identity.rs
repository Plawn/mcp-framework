//! Session identity resolution over HTTP.
//!
//! MCP 2026-07-28 (SEP-2567) removed protocol-level sessions, so `mcp-session-id`
//! is absent for clients on that revision. The auth middleware derives a stable
//! per-credential identity instead and injects it under
//! [`MCP_FALLBACK_SESSION_HEADER`]. These tests drive the real router built by
//! [`build_app`] — strip layer, auth middleware and all — and read back the
//! identity a handler would see.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::Router;
use mcp_framework::auth::{AuthProvider, BasicAuthConfig, OAuthConfig, TokenMode};
use mcp_framework::constants::{MCP_FALLBACK_SESSION_HEADER, MCP_SESSION_ID_HEADER};
use mcp_framework::session::{session_id_from_parts, SessionStore};
use mcp_framework::transport::{build_app, HttpAppConfig};
use mcp_framework::TokenStore;
use rmcp::ServerHandler;
use tower::ServiceExt as _;

/// Minimal handler — these tests exercise the HTTP layer, not MCP dispatch.
#[derive(Clone)]
struct NoopServer;

impl ServerHandler for NoopServer {}

/// Echoes the identity `resolve_session_id` would hand to a tool.
async fn whoami(parts: axum::http::request::Parts) -> String {
    session_id_from_parts(&parts).to_string()
}

fn app_with(auth: AuthProvider) -> (Router, TokenStore) {
    let config: HttpAppConfig<_, ()> = HttpAppConfig {
        public_url: "http://localhost".to_string(),
        bind_addr: "127.0.0.1:0".to_string(),
        auth,
        server_factory: || NoopServer,
        app_name: "session-identity-test".to_string(),
        capability_registry: None,
        capability_filter: None,
        access_validator: None,
        claims_decoder: None,
        session_store: SessionStore::default(),
        tool_call_logger: None,
        persistence: None,
        // `extra_routes` sits inside the auth layer, so /whoami sees exactly what
        // the MCP fallback would.
        extra_routes: Some(Router::new().route("/whoami", get(whoami))),
        public_routes: None,
    };
    let (app, token_store, _registry) = build_app(config);
    (app, token_store)
}

fn basic_auth() -> AuthProvider {
    AuthProvider::Basic(BasicAuthConfig {
        username: "user".to_string(),
        password: "s3cret".to_string(),
    })
}

fn oauth(token_mode: TokenMode) -> AuthProvider {
    AuthProvider::OAuth(OAuthConfig {
        client_id: "test-client".to_string(),
        client_secret: Some("test-secret".to_string()),
        issuer_url: "http://localhost:8080/realms/test".to_string(),
        redirect_url: "http://localhost/oauth/callback".to_string(),
        scopes: vec!["openid".to_string()],
        token_mode,
    })
}

/// Send a request to /whoami and return `(status, body)`.
async fn whoami_request(app: &Router, headers: &[(&str, &str)]) -> (StatusCode, String) {
    let mut builder = Request::builder().uri("/whoami").header("host", "localhost");
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

fn basic_header(username: &str, password: &str) -> String {
    use base64::Engine as _;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"))
    )
}

// ── Spoofing ────────────────────────────────────────────────────────

#[tokio::test]
async fn client_supplied_framework_header_is_stripped_under_no_auth() {
    let (app, _) = app_with(AuthProvider::None);

    let (status, body) = whoami_request(
        &app,
        &[(MCP_FALLBACK_SESSION_HEADER, "cred-victimsessionid")],
    )
    .await;

    // `AuthProvider::None` runs no auth middleware to overwrite the header, so
    // the strip layer is the only thing standing between a client and another
    // user's session. Without it the handler would read "cred-victimsessionid".
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "default");
}

#[tokio::test]
async fn client_supplied_framework_header_cannot_hijack_a_protocol_session() {
    let (app, _) = app_with(basic_auth());

    let (status, body) = whoami_request(
        &app,
        &[
            ("authorization", &basic_header("user", "s3cret")),
            (MCP_SESSION_ID_HEADER, "sess-mine"),
            (MCP_FALLBACK_SESSION_HEADER, "cred-victimsessionid"),
        ],
    )
    .await;

    // The framework header wins over `mcp-session-id` when present, and the auth
    // middleware returns early without touching it when a protocol session
    // exists — so only the strip layer prevents the spoof from taking effect.
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "sess-mine");
}

// ── Sessionless derivation ──────────────────────────────────────────

#[tokio::test]
async fn sessionless_basic_request_gets_a_derived_identity() {
    let (app, _) = app_with(basic_auth());
    let auth = basic_header("user", "s3cret");

    let (status, first) = whoami_request(&app, &[("authorization", &auth)]).await;
    assert_eq!(status, StatusCode::OK);
    let (_, second) = whoami_request(&app, &[("authorization", &auth)]).await;

    // No `mcp-session-id` (2026-07-28 clients never send one) → a derived id,
    // stable across requests rather than the shared "default".
    assert!(first.starts_with("cred-"), "got {first}");
    assert_eq!(first, second);
}

#[tokio::test]
async fn protocol_session_id_still_wins_when_present() {
    let (app, _) = app_with(basic_auth());

    let (_, body) = whoami_request(
        &app,
        &[
            ("authorization", &basic_header("user", "s3cret")),
            (MCP_SESSION_ID_HEADER, "sess-legacy"),
        ],
    )
    .await;

    assert_eq!(body, "sess-legacy");
}

// ── Passthrough OAuth: per-grant isolation ──────────────────────────

#[tokio::test]
async fn concurrent_sessionless_bearers_are_isolated() {
    let (app, token_store) = app_with(oauth(TokenMode::Passthrough));

    let (status_a, id_a) =
        whoami_request(&app, &[("authorization", "Bearer token-alice")]).await;
    let (status_b, id_b) = whoami_request(&app, &[("authorization", "Bearer token-bob")]).await;

    assert_eq!(status_a, StatusCode::OK);
    assert_eq!(status_b, StatusCode::OK);

    // Two users, no protocol session between them. Collapsing both onto
    // "default" would serve Alice's token to Bob.
    assert_ne!(id_a, id_b);
    assert_eq!(
        token_store.peek_token(&id_a).await.map(|t| t.access_token),
        Some("token-alice".to_string())
    );
    assert_eq!(
        token_store.peek_token(&id_b).await.map(|t| t.access_token),
        Some("token-bob".to_string())
    );
}

#[tokio::test]
async fn passthrough_adopts_the_refresh_token_captured_at_the_exchange() {
    use mcp_framework::auth::StoredToken;

    let (app, token_store) = app_with(oauth(TokenMode::Passthrough));

    // Stand in for `/oauth/token`: it keys by credential because no MCP session
    // exists yet, and it is the only place the refresh_token is ever seen.
    let (_, grant_key) = whoami_request(&app, &[("authorization", "Bearer token-alice")]).await;
    token_store
        .store_token(
            grant_key.clone(),
            StoredToken::new(
                "token-alice".to_string(),
                Some("refresh-alice".to_string()),
                None,
            ),
        )
        .await;

    // The client then connects and rmcp hands it a protocol session id. The
    // session key changes, but the grant is the same — the refresh_token must
    // follow, or server-side refresh can never fire for this user.
    let (status, id) = whoami_request(
        &app,
        &[
            ("authorization", "Bearer token-alice"),
            (MCP_SESSION_ID_HEADER, "sess-alice"),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(id, "sess-alice");
    let adopted = token_store.peek_token("sess-alice").await.expect("adopted");
    assert_eq!(adopted.access_token, "token-alice");
    assert_eq!(adopted.refresh_token.as_deref(), Some("refresh-alice"));
}

// ── Opaque OAuth ────────────────────────────────────────────────────

#[tokio::test]
async fn opaque_token_binds_the_request_to_its_grant() {
    use mcp_framework::auth::StoredToken;

    let (app, token_store) = app_with(oauth(TokenMode::Opaque));

    // What `opaque_token_handler` does: a fresh per-grant key, never the
    // (absent) `mcp-session-id`.
    let grant = "grant-0000-1111".to_string();
    token_store
        .store_token(
            grant.clone(),
            StoredToken::new(
                "keycloak-alice".to_string(),
                Some("kc-refresh-alice".to_string()),
                None,
            ),
        )
        .await;
    token_store
        .store_opaque_mapping(
            grant.clone(),
            "opaque-access".to_string(),
            "opaque-refresh".to_string(),
        )
        .await;

    // Even with a protocol session in play, the grant is the identity: the
    // opaque token outlives any `mcp-session-id` and is what keys the store.
    let (status, id) = whoami_request(
        &app,
        &[
            ("authorization", "Bearer opaque-access"),
            (MCP_SESSION_ID_HEADER, "sess-transient"),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(id, grant);
}

#[tokio::test]
async fn unknown_opaque_token_is_rejected() {
    let (app, _) = app_with(oauth(TokenMode::Opaque));

    let (status, _) = whoami_request(&app, &[("authorization", "Bearer not-a-grant")]).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

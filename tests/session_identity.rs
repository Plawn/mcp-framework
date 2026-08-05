//! Generic HTTP session identity and anti-spoofing integration tests.

mod common;

use axum::http::StatusCode;
use common::{app_with, whoami_request};
use mcp_framework::auth::{AuthProvider, BasicAuthConfig};
use mcp_framework::constants::{MCP_FALLBACK_SESSION_HEADER, MCP_SESSION_ID_HEADER};

fn basic_auth() -> AuthProvider {
    AuthProvider::Basic(BasicAuthConfig {
        username: "user".to_string(),
        password: "s3cret".to_string(),
    })
}

fn basic_header(username: &str, password: &str) -> String {
    use base64::Engine as _;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"))
    )
}

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

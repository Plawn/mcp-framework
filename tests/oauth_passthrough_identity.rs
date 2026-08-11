//! Passthrough OAuth identity binding and per-grant isolation tests.

mod common;

use axum::http::StatusCode;
use common::{app_with, whoami_request};
use mcp_framework::auth::{AuthProvider, OAuthConfig, StoredToken, TokenMode};
use mcp_framework::constants::MCP_SESSION_ID_HEADER;

fn oauth() -> AuthProvider {
    AuthProvider::OAuth(OAuthConfig {
        client_id: "test-client".to_string(),
        client_secret: Some("test-secret".to_string()),
        issuer_url: "http://localhost:8080/realms/test".to_string(),
        redirect_url: "http://localhost/oauth/callback".to_string(),
        scopes: vec!["openid".to_string()],
        token_mode: TokenMode::Passthrough,
    })
}

#[tokio::test]
async fn concurrent_sessionless_bearers_are_isolated() {
    let (app, token_store) = app_with(oauth());

    let (status_a, id_a) = whoami_request(&app, &[("authorization", "Bearer token-alice")]).await;
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
    let (app, token_store) = app_with(oauth());

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

/// Build a JWT-shaped token (`header.payload.sig`) carrying `sub`. The payload
/// is real base64url JSON so `jwt_subject` can decode it; the signature is
/// irrelevant — passthrough never verifies it. `nonce` makes two tokens for the
/// same principal differ byte-for-byte, mimicking Keycloak re-issuing a fresh
/// JWT on every token-exchange.
fn jwt_with_sub(sub: &str, nonce: &str) -> String {
    use base64::Engine as _;
    let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = enc.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let payload = enc.encode(format!(r#"{{"sub":"{sub}","jti":"{nonce}"}}"#).as_bytes());
    format!("{header}.{payload}.sig")
}

#[tokio::test]
async fn passthrough_accepts_a_rotated_bearer_for_the_same_principal() {
    let (app, token_store) = app_with(oauth());

    // A bring-your-own-token client: it obtained its own Keycloak JWT (never via
    // `/oauth/token`) and re-mints it on every request. First request seeds the
    // session entry.
    let t1 = jwt_with_sub("alice", "one");
    let (status1, id) = whoami_request(
        &app,
        &[
            ("authorization", &format!("Bearer {t1}")),
            (MCP_SESSION_ID_HEADER, "sess-alice"),
        ],
    )
    .await;
    assert_eq!(status1, StatusCode::OK);
    assert_eq!(id, "sess-alice");

    // Same user, brand-new JWT bytes, same live session. Before the fix this
    // 3rd-request-shaped rotation fell into a 401.
    let t2 = jwt_with_sub("alice", "two");
    assert_ne!(t1, t2);
    let (status2, _) = whoami_request(
        &app,
        &[
            ("authorization", &format!("Bearer {t2}")),
            (MCP_SESSION_ID_HEADER, "sess-alice"),
        ],
    )
    .await;

    assert_eq!(status2, StatusCode::OK);
    // The rotated bearer replaced the stored one and never inherited refresh
    // material (there was none here, and there must never be any carried over).
    let stored = token_store.peek_token("sess-alice").await.expect("stored");
    assert_eq!(stored.access_token, t2);
    assert_eq!(stored.refresh_token, None);
    assert_eq!(stored.expires_at, None);
}

#[tokio::test]
async fn passthrough_rotation_never_inherits_previous_refresh_material() {
    let (app, token_store) = app_with(oauth());

    // Seed the session with a JWT that *does* carry refresh material, as if the
    // grant had been adopted from `/oauth/token`.
    let t1 = jwt_with_sub("alice", "one");
    token_store
        .store_token(
            "sess-alice".to_string(),
            StoredToken::new(t1.clone(), Some("refresh-alice".to_string()), None),
        )
        .await;

    // Same principal rotates its bearer. The refresh_token belongs to the old
    // credential and must not follow the new one.
    let t2 = jwt_with_sub("alice", "two");
    let (status, _) = whoami_request(
        &app,
        &[
            ("authorization", &format!("Bearer {t2}")),
            (MCP_SESSION_ID_HEADER, "sess-alice"),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let stored = token_store.peek_token("sess-alice").await.expect("stored");
    assert_eq!(stored.access_token, t2);
    assert_eq!(stored.refresh_token, None);
}

#[tokio::test]
async fn passthrough_rejects_a_different_principal_for_an_existing_session() {
    let (app, token_store) = app_with(oauth());
    let alice = jwt_with_sub("alice", "one");
    token_store
        .store_token(
            "sess-alice".to_string(),
            StoredToken::new(alice.clone(), Some("refresh-alice".to_string()), None),
        )
        .await;

    // A valid JWT, but for a different `sub`. It must not hijack Alice's session
    // nor wipe her refresh material.
    let mallory = jwt_with_sub("mallory", "x");
    let (status, _) = whoami_request(
        &app,
        &[
            ("authorization", &format!("Bearer {mallory}")),
            (MCP_SESSION_ID_HEADER, "sess-alice"),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let unchanged = token_store.peek_token("sess-alice").await.unwrap();
    assert_eq!(unchanged.access_token, alice);
    assert_eq!(unchanged.refresh_token.as_deref(), Some("refresh-alice"));
}

#[tokio::test]
async fn passthrough_rejects_a_different_bearer_for_an_existing_session() {
    let (app, token_store) = app_with(oauth());
    token_store
        .store_token(
            "sess-alice".to_string(),
            StoredToken::new(
                "access-alice".to_string(),
                Some("refresh-alice".to_string()),
                None,
            ),
        )
        .await;

    let (status, _) = whoami_request(
        &app,
        &[
            ("authorization", "Bearer access-mallory"),
            (MCP_SESSION_ID_HEADER, "sess-alice"),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let unchanged = token_store.peek_token("sess-alice").await.unwrap();
    assert_eq!(unchanged.access_token, "access-alice");
    assert_eq!(unchanged.refresh_token.as_deref(), Some("refresh-alice"));
}

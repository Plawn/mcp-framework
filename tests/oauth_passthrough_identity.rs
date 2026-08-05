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

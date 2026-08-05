//! Opaque OAuth identity binding integration tests.

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
        token_mode: TokenMode::Opaque,
    })
}

#[tokio::test]
async fn opaque_token_binds_the_request_to_its_grant() {
    let (app, token_store) = app_with(oauth());

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
    let (app, _) = app_with(oauth());

    let (status, _) = whoami_request(&app, &[("authorization", "Bearer not-a-grant")]).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

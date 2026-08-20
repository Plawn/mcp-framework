//! Passthrough mode: a `refresh_token` grant must retire the entry it
//! supersedes. Keycloak rotates the refresh token away, so leaving the previous
//! grant in the `TokenStore` leaves a stale entry the auth middleware would
//! happily adopt — then drive into `invalid_grant` → a spurious 401. Task #922.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::{
    Json, Router,
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    routing::post,
};
use common::app_with;
use mcp_framework::TokenStore;
use mcp_framework::auth::{AuthProvider, OAuthConfig, TokenMode, UnknownTokenValidation};
use tower::ServiceExt as _;

/// A Keycloak that mints a fresh (access, refresh) pair on every exchange, the
/// way refresh-token rotation does.
async fn mock_keycloak() -> String {
    async fn token(State(calls): State<Arc<AtomicUsize>>) -> Json<serde_json::Value> {
        let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
        Json(serde_json::json!({
            "access_token": format!("access-{n}"),
            "refresh_token": format!("refresh-{n}"),
            "expires_in": 300,
            "token_type": "Bearer",
        }))
    }

    let app = Router::new()
        .route("/realms/test/protocol/openid-connect/token", post(token))
        .with_state(Arc::new(AtomicUsize::new(0)));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    format!("http://{addr}/realms/test")
}

fn passthrough_oauth(issuer_url: String) -> AuthProvider {
    AuthProvider::OAuth(OAuthConfig {
        client_id: "test-client".to_string(),
        client_secret: Some("test-secret".to_string()),
        issuer_url,
        redirect_url: "http://localhost/oauth/callback".to_string(),
        scopes: vec!["openid".to_string()],
        token_mode: TokenMode::Passthrough,
        unknown_token_validation: UnknownTokenValidation::Introspection,
        expected_audiences: vec![],
    })
}

async fn post_token(app: &Router, form: &str) -> StatusCode {
    let request = Request::builder()
        .method("POST")
        .uri("/oauth/token")
        .header("host", "localhost")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(form.to_string()))
        .unwrap();
    app.clone().oneshot(request).await.unwrap().status()
}

async fn grant_key(store: &TokenStore, refresh_token: &str) -> Option<String> {
    store.resolve_grant_refresh(refresh_token).await
}

#[tokio::test]
async fn refresh_grant_retires_the_previous_passthrough_entry() {
    let (app, token_store) = app_with(passthrough_oauth(mock_keycloak().await));

    // Initial exchange: the grant lands under a credential-derived key and is
    // indexed by the refresh token it came with.
    assert_eq!(
        post_token(&app, "grant_type=authorization_code&code=abc").await,
        StatusCode::OK
    );
    let key1 = grant_key(&token_store, "refresh-1")
        .await
        .expect("initial grant indexed by its refresh token");
    assert_eq!(
        token_store.peek_token(&key1).await.map(|t| t.access_token),
        Some("access-1".to_string())
    );

    // The client refreshes. Keycloak rotates both tokens.
    assert_eq!(
        post_token(&app, "grant_type=refresh_token&refresh_token=refresh-1").await,
        StatusCode::OK
    );

    // The superseded grant is gone — entry and index alike.
    assert_eq!(grant_key(&token_store, "refresh-1").await, None);
    assert!(
        token_store.peek_token(&key1).await.is_none(),
        "the entry holding the rotated-away refresh token must not survive"
    );

    // The new grant is in place and adoptable.
    let key2 = grant_key(&token_store, "refresh-2")
        .await
        .expect("refreshed grant indexed by its new refresh token");
    assert_ne!(key1, key2);
    let stored = token_store.peek_token(&key2).await.expect("new grant");
    assert_eq!(stored.access_token, "access-2");
    assert_eq!(stored.refresh_token.as_deref(), Some("refresh-2"));
}

/// A stable grant key (task #920 derives it from JWT `sid`/`sub`) makes the old
/// and new keys collide. The cleanup must then leave the freshly stored entry
/// alone instead of deleting the grant it just wrote.
#[tokio::test]
async fn refresh_grant_keeps_the_entry_when_the_key_is_unchanged() {
    let store = TokenStore::new();
    let session_key = "grant-stable";

    store
        .store_token(
            session_key.to_string(),
            mcp_framework::auth::StoredToken::new(
                "access-1".to_string(),
                Some("refresh-1".to_string()),
                None,
            ),
        )
        .await;
    store.index_grant_refresh("refresh-1", session_key).await;

    // What the handler does on a refresh whose new key equals the old one:
    // the removal is skipped, only the spent refresh token is de-indexed.
    assert_eq!(
        store.resolve_grant_refresh("refresh-1").await.as_deref(),
        Some(session_key)
    );
    store.remove_grant_refresh("refresh-1").await;
    store
        .store_token(
            session_key.to_string(),
            mcp_framework::auth::StoredToken::new(
                "access-2".to_string(),
                Some("refresh-2".to_string()),
                None,
            ),
        )
        .await;
    store.index_grant_refresh("refresh-2", session_key).await;

    assert_eq!(store.resolve_grant_refresh("refresh-1").await, None);
    assert_eq!(
        store.resolve_grant_refresh("refresh-2").await.as_deref(),
        Some(session_key)
    );
    assert_eq!(
        store.peek_token(session_key).await.map(|t| t.access_token),
        Some("access-2".to_string()),
        "the freshly stored grant must survive its own cleanup"
    );
}

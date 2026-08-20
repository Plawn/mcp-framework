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
use common::{app_with, app_with_persistence};
use mcp_framework::TokenStore;
use mcp_framework::auth::{AuthProvider, OAuthConfig, TokenMode, UnknownTokenValidation};
use mcp_framework::persistence::{InMemoryBackend, PersistenceBackend};
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

/// Guard for a case this branch cannot yet produce. Here the key is derived from
/// the access-token bytes, so a rotation always yields a *different* key; once
/// identity becomes claims-derived (task #920, JWT `sid`/`sub`) both grants land
/// on the same key and the removal must be skipped. The store calls below are a
/// hand-rolled replay of the handler's sequence under that future derivation.
#[tokio::test]
async fn stable_grant_key_survives_its_own_refresh_cleanup() {
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
    // `old_key != session_key` is false, so `remove_token` is skipped and only
    // the spent refresh token is de-indexed.
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

/// Two replicas sharing only a persistence backend: the exchange happens on A,
/// the refresh on B — which has never seen the grant in memory and must reach it
/// through `NS_GRANT_REFRESH` read-through. A third, freshly built store then
/// checks what actually survived in persistence.
#[tokio::test]
async fn refresh_on_a_peer_retires_the_persisted_grant() {
    let backend = Arc::new(InMemoryBackend::new());
    let issuer = mock_keycloak().await;

    let (app_a, store_a) = app_with_persistence(passthrough_oauth(issuer.clone()), backend.clone());
    let (app_b, _store_b) = app_with_persistence(passthrough_oauth(issuer), backend.clone());

    // Replica A serves the initial exchange.
    assert_eq!(
        post_token(&app_a, "grant_type=authorization_code&code=abc").await,
        StatusCode::OK
    );
    let key1 = store_a
        .resolve_grant_refresh("refresh-1")
        .await
        .expect("initial grant indexed");

    // The index landed in NS_GRANT_REFRESH, keyed by a hash (never the raw
    // refresh token) and holding the grant key as its value.
    let index_keys = backend.keys("grant_refresh").await.unwrap();
    assert_eq!(index_keys.len(), 1, "one index entry: {index_keys:?}");
    assert!(
        !index_keys[0].contains("refresh-1"),
        "the raw refresh token must never be a persistence key: {index_keys:?}"
    );
    assert_eq!(
        backend
            .get("grant_refresh", &index_keys[0])
            .await
            .unwrap()
            .as_deref(),
        Some(key1.as_bytes())
    );

    // Replica B serves the refresh. Nothing about this grant is in its memory.
    assert_eq!(
        post_token(&app_b, "grant_type=refresh_token&refresh_token=refresh-1").await,
        StatusCode::OK
    );

    // A third store, built fresh over the same backend: everything it sees comes
    // from persistence, so this is what a restarted or newly scaled-up replica
    // would find.
    let fresh = TokenStore::new().with_persistence(backend.clone());
    assert!(
        fresh.peek_token(&key1).await.is_none(),
        "the superseded grant must be gone from persistence too"
    );
    assert_eq!(fresh.resolve_grant_refresh("refresh-1").await, None);

    let key2 = fresh
        .resolve_grant_refresh("refresh-2")
        .await
        .expect("refreshed grant resolvable from persistence alone");
    assert_ne!(key1, key2);
    let stored = fresh.peek_token(&key2).await.expect("new grant adoptable");
    assert_eq!(stored.access_token, "access-2");
    assert_eq!(stored.refresh_token.as_deref(), Some("refresh-2"));

    assert_eq!(
        backend.keys("grant_refresh").await.unwrap().len(),
        1,
        "the spent index entry must not linger alongside the new one"
    );
}

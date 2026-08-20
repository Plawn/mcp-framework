//! Passthrough mode: middleware must preserve the refresh_token across
//! requests and trigger a server-side refresh when the bearer JWT is
//! expired. Covers task #573.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::{
    Json, Router,
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine as _;
use mcp_framework::auth::{
    AuthMiddlewareState, BearerToken, RefreshConfig, SessionBindings, StoredToken, TokenMode,
    TokenStore, bearer_auth_middleware,
};

fn make_jwt(exp_secs_from_now: i64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let exp = (now + exp_secs_from_now).max(0) as u64;
    let header =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
    let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(format!(r#"{{"exp":{}}}"#, exp).as_bytes());
    format!("{}.{}.sig", header, payload_b64)
}

async fn start_mock_keycloak(fresh_access: String) -> std::net::SocketAddr {
    async fn token(State(fresh): State<Arc<String>>) -> impl IntoResponse {
        Json(serde_json::json!({
            "access_token": fresh.as_str(),
            "refresh_token": "new_refresh",
            "expires_in": 300,
            "token_type": "Bearer"
        }))
    }

    let app = Router::new()
        .route("/token", post(token))
        .with_state(Arc::new(fresh_access));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

async fn echo_bearer(request: Request<Body>) -> Response {
    let token = request
        .extensions()
        .get::<BearerToken>()
        .map(|t| t.0.clone())
        .unwrap_or_default();
    Response::builder()
        .status(StatusCode::OK)
        .body(Body::from(token))
        .unwrap()
}

async fn spawn_app(state: Arc<AuthMiddlewareState>) -> std::net::SocketAddr {
    let app =
        Router::new()
            .route("/whoami", get(echo_bearer))
            .layer(middleware::from_fn_with_state(
                state,
                bearer_auth_middleware,
            ));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

#[tokio::test]
async fn passthrough_auto_refreshes_expired_bearer_when_refresh_token_present() {
    let fresh_access = make_jwt(300);
    let kc_addr = start_mock_keycloak(fresh_access.clone()).await;

    let token_store = TokenStore::with_refresh_config(RefreshConfig {
        client_id: "test-client".into(),
        client_secret: Some("secret".into()),
        token_url: format!("http://{}/token", kc_addr),
    });

    // Simulate post-/oauth/token state: passthrough handler stored a token
    // with refresh_token + expiry. Now make it expired (TTL elapsed).
    let session_id = "sess-refresh".to_string();
    let expired_jwt = make_jwt(-60);
    token_store
        .store_token(
            session_id.clone(),
            StoredToken::new(
                expired_jwt.clone(),
                Some("old_refresh".into()),
                Some(Instant::now() - Duration::from_secs(60)),
            ),
        )
        .await;

    let state = Arc::new(AuthMiddlewareState {
        resource_url: "http://test".into(),
        resource_metadata_url: "http://test/.well-known".into(),
        token_store: token_store.clone(),
        token_mode: TokenMode::Passthrough,
        // Unused in passthrough: the token kept per session is what compares
        // principals there.
        session_bindings: SessionBindings::new(Duration::from_secs(60)),
    });
    let addr = spawn_app(state).await;

    let res = reqwest::Client::new()
        .get(format!("http://{}/whoami", addr))
        .header("authorization", format!("Bearer {}", expired_jwt))
        .header("mcp-session-id", &session_id)
        .send()
        .await
        .expect("request");

    assert_eq!(res.status(), 200, "middleware should refresh & allow");
    let body = res.text().await.unwrap();
    assert_eq!(body, fresh_access, "downstream should see refreshed token");

    let stored = token_store.peek_token(&session_id).await.unwrap();
    assert_eq!(stored.access_token, fresh_access);
    assert_eq!(stored.refresh_token.as_deref(), Some("new_refresh"));
}

#[tokio::test]
async fn passthrough_preserves_refresh_token_across_requests() {
    // The original bug: a second request with the same access_token wiped
    // the refresh_token in the store. Now it must survive.
    let token_store = TokenStore::new();
    let session_id = "sess-keep".to_string();
    let bearer = make_jwt(300);

    token_store
        .store_token(
            session_id.clone(),
            StoredToken::new(
                bearer.clone(),
                Some("the_refresh".into()),
                Some(Instant::now() + Duration::from_secs(300)),
            ),
        )
        .await;

    let state = Arc::new(AuthMiddlewareState {
        resource_url: "http://test".into(),
        resource_metadata_url: "http://test/.well-known".into(),
        token_store: token_store.clone(),
        token_mode: TokenMode::Passthrough,
        // Unused in passthrough: the token kept per session is what compares
        // principals there.
        session_bindings: SessionBindings::new(Duration::from_secs(60)),
    });
    let addr = spawn_app(state).await;

    let res = reqwest::Client::new()
        .get(format!("http://{}/whoami", addr))
        .header("authorization", format!("Bearer {}", bearer))
        .header("mcp-session-id", &session_id)
        .send()
        .await
        .expect("request");
    assert_eq!(res.status(), 200);

    let stored = token_store.peek_token(&session_id).await.unwrap();
    assert_eq!(stored.refresh_token.as_deref(), Some("the_refresh"));
    assert!(stored.expires_at.is_some());
}

#[tokio::test]
async fn passthrough_returns_401_when_expired_and_no_refresh_token() {
    // No refresh_token in store → expired bearer cannot be rescued.
    // It must be rejected at the transport boundary so an MCP client can
    // restart OAuth instead of receiving a tool-level session error.
    let token_store = TokenStore::new();
    let session_id = "sess-no-rt".to_string();
    let expired_jwt = make_jwt(-60);

    let state = Arc::new(AuthMiddlewareState {
        resource_url: "http://test".into(),
        resource_metadata_url: "http://test/.well-known".into(),
        token_store: token_store.clone(),
        token_mode: TokenMode::Passthrough,
        // Unused in passthrough: the token kept per session is what compares
        // principals there.
        session_bindings: SessionBindings::new(Duration::from_secs(60)),
    });
    let addr = spawn_app(state).await;

    let res = reqwest::Client::new()
        .get(format!("http://{}/whoami", addr))
        .header("authorization", format!("Bearer {}", expired_jwt))
        .header("mcp-session-id", &session_id)
        .send()
        .await
        .expect("request");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        res.headers()
            .get("www-authenticate")
            .and_then(|value| value.to_str().ok()),
        Some("Bearer resource_metadata=\"http://test/.well-known\"")
    );
}

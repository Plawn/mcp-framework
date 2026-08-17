//! Invalid OAuth credentials must be rejected by the HTTP transport before
//! rmcp dispatches initialize, tools/list, or tools/call.

#[allow(dead_code)]
mod common;

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Json, Router,
    body::Body,
    extract::Form,
    http::{Request, StatusCode},
    routing::post,
};
use base64::Engine as _;
use common::app_with;
use mcp_framework::auth::{AuthProvider, OAuthConfig, TokenMode, UnknownTokenValidation};
use tower::ServiceExt as _;

async fn oauth() -> AuthProvider {
    async fn introspect(Form(params): Form<Vec<(String, String)>>) -> Json<serde_json::Value> {
        let token = params
            .iter()
            .find(|(key, _)| key == "token")
            .map(|(_, value)| value.as_str());
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 300;

        Json(match token {
            Some("valid-token") => serde_json::json!({ "active": true, "exp": exp }),
            _ => serde_json::json!({ "active": false }),
        })
    }

    let keycloak = Router::new().route(
        "/realms/test/protocol/openid-connect/token/introspect",
        post(introspect),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, keycloak).await.unwrap() });

    AuthProvider::OAuth(OAuthConfig {
        client_id: "test-client".to_string(),
        client_secret: Some("test-secret".to_string()),
        issuer_url: format!("http://{addr}/realms/test"),
        redirect_url: "http://localhost/oauth/callback".to_string(),
        scopes: vec!["openid".to_string()],
        token_mode: TokenMode::Passthrough,
        // Left on the default on purpose: this issuer publishes no JWKS, so
        // every unknown bearer exercises the JWKS-unavailable fall-through to
        // introspection that these assertions depend on.
        unknown_token_validation: UnknownTokenValidation::JwksThenIntrospection,
        expected_audiences: vec![],
    })
}

fn expired_jwt() -> String {
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"exp":1}"#);
    format!("{header}.{payload}.invalid-signature")
}

fn requests() -> [serde_json::Value; 3] {
    [
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "auth-test", "version": "1.0" }
            }
        }),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": { "name": "missing", "arguments": {} }
        }),
    ]
}

async fn post_mcp(app: &Router, bearer: &str, body: &serde_json::Value) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::post("/mcp")
                .header("host", "localhost")
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .header("authorization", format!("Bearer {bearer}"))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn invalid_and_expired_bearers_return_oauth_401_for_all_mcp_methods() {
    let (app, _) = app_with(oauth().await);

    for bearer in ["not-a-token".to_string(), expired_jwt()] {
        for request in requests() {
            let response = post_mcp(&app, &bearer, &request).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                response
                    .headers()
                    .get("www-authenticate")
                    .and_then(|value| value.to_str().ok()),
                Some(
                    "Bearer resource_metadata=\"http://localhost/.well-known/oauth-protected-resource/mcp\""
                )
            );
        }
    }
}

#[tokio::test]
async fn active_introspected_bearer_still_initializes_normally() {
    let (app, _) = app_with(oauth().await);
    let response = post_mcp(&app, "valid-token", &requests()[0]).await;

    assert_eq!(response.status(), StatusCode::OK);
}

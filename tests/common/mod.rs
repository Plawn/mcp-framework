use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use mcp_framework::TokenStore;
use mcp_framework::auth::AuthProvider;
use mcp_framework::session::{SessionStore, session_id_from_parts};
use mcp_framework::transport::{HttpAppConfig, build_app};
use rmcp::ServerHandler;
use tower::ServiceExt as _;

#[derive(Clone)]
struct NoopServer;

impl ServerHandler for NoopServer {}

async fn whoami(parts: axum::http::request::Parts) -> String {
    session_id_from_parts(&parts).to_string()
}

pub fn app_with(auth: AuthProvider) -> (Router, TokenStore) {
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
        protocol_lifecycle: mcp_framework::ProtocolLifecyclePolicy::Hybrid,
        extra_routes: Some(Router::new().route("/whoami", get(whoami))),
        public_routes: None,
    };
    let (app, token_store, _registry) = build_app(config);
    (app, token_store)
}

#[allow(dead_code)] // not every test binary using this harness needs it
pub async fn whoami_request(app: &Router, headers: &[(&str, &str)]) -> (StatusCode, String) {
    let mut builder = Request::builder()
        .uri("/whoami")
        .header("host", "localhost");
    for (key, value) in headers {
        builder = builder.header(*key, *value);
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

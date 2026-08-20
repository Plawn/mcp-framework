use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use mcp_framework::TokenStore;
use mcp_framework::auth::AuthProvider;
use mcp_framework::persistence::PersistenceBackend;
use mcp_framework::session::{SessionStore, session_id_from_parts};
use mcp_framework::transport::{HttpAppConfig, build_app};
use rmcp::ServerHandler;
use std::sync::Arc;
use tower::ServiceExt as _;

#[derive(Clone)]
struct NoopServer;

impl ServerHandler for NoopServer {}

async fn whoami(parts: axum::http::request::Parts) -> String {
    session_id_from_parts(&parts).to_string()
}

pub fn app_with(auth: AuthProvider) -> (Router, TokenStore) {
    app_with_optional_persistence(auth, None)
}

/// Same harness, with a persistence backend wired into the `TokenStore`. Two
/// apps built over one shared backend stand in for two replicas: each has its
/// own in-memory caches and can only reach the other's state through
/// persistence.
#[allow(dead_code)] // not every test binary using this harness needs it
pub fn app_with_persistence(
    auth: AuthProvider,
    persistence: Arc<dyn PersistenceBackend>,
) -> (Router, TokenStore) {
    app_with_optional_persistence(auth, Some(persistence))
}

fn app_with_optional_persistence(
    auth: AuthProvider,
    persistence: Option<Arc<dyn PersistenceBackend>>,
) -> (Router, TokenStore) {
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
        persistence,
        protocol_lifecycle: mcp_framework::ProtocolLifecyclePolicy::Hybrid,
        extra_routes: Some(Router::new().route("/whoami", get(whoami))),
        public_routes: None,
    };
    let (app, token_store, _registry) = build_app(config).expect("valid test configuration");
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

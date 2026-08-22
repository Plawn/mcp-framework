//! Boot-time refusal of an unusable advertised-revision ceiling.
//!
//! Its own test binary — and therefore its own process — because
//! [`MAX_PROTOCOL_VERSION_ENV`](mcp_framework::MAX_PROTOCOL_VERSION_ENV) is
//! process-wide state: setting it inside `tests/protocol_matrix.rs` would
//! reconfigure every server the other tests start in parallel.

use mcp_framework::auth::AuthProvider;
use mcp_framework::session::SessionStore;
use mcp_framework::transport::{HttpAppConfig, ProtocolLifecyclePolicy, build_app};
use rmcp::ServerHandler;

#[derive(Clone)]
struct NoopServer;

impl ServerHandler for NoopServer {}

// ── Boot-time validation ──────────────────────────────────────────────────

#[tokio::test]
async fn an_unknown_ceiling_fails_the_boot() {
    // Reached through `build_app` rather than the builder, so a consumer
    // assembling an `HttpAppConfig` by hand cannot route around the check.
    // SAFETY: single-threaded assertion on this test's own variable.
    unsafe { std::env::set_var(mcp_framework::MAX_PROTOCOL_VERSION_ENV, "2027-01-01") };
    let config: HttpAppConfig<_, ()> = HttpAppConfig {
        public_url: "http://localhost".to_string(),
        bind_addr: "127.0.0.1:0".to_string(),
        auth: AuthProvider::None,
        server_factory: || NoopServer,
        app_name: "protocol-ceiling-env".to_string(),
        capability_registry: None,
        capability_filter: None,
        access_validator: None,
        claims_decoder: None,
        session_store: SessionStore::default(),
        tool_call_logger: None,
        persistence: None,
        protocol_lifecycle: ProtocolLifecyclePolicy::Hybrid,
        max_protocol_version: None,
        extra_routes: None,
        public_routes: None,
    };
    let error = build_app(config).err().expect("unknown revision is refused");
    unsafe { std::env::remove_var(mcp_framework::MAX_PROTOCOL_VERSION_ENV) };
    assert!(
        error.message().contains("2027-01-01") && error.message().contains("2025-11-25"),
        "the error must name the bad value and the known set: {}",
        error.message()
    );
}

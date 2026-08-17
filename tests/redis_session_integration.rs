//! Integration tests for session persistence across server restarts with Redis.
//!
//! Requires a running Redis instance (default `redis://127.0.0.1/`).
//! Override with the `REDIS_URL` env var.
//!
//! Run with: `cargo test --features redis --test redis_session_integration`

#![cfg(feature = "redis")]

use std::sync::Arc;
use std::time::Duration;

use mcp_framework::auth::AuthProvider;
use mcp_framework::prelude::*;
use mcp_framework::session::{RequestContextExt, SessionStore};
use mcp_framework::transport::{HttpAppConfig, build_app};
use rmcp::model::CallToolRequestParams;
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::{ServiceExt, tool};

// ── Session data type ──────────────────────────────────────────────

#[derive(Default, Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
struct CounterSession {
    counter: u32,
}

// ── Server ─────────────────────────────────────────────────────────

#[derive(Clone)]
struct CounterServer {
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

impl CounterServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }
}

#[rmcp::tool_router]
impl CounterServer {
    #[tool(description = "Increment session counter and return the new value")]
    async fn increment(
        &self,
        Parameters(_): Parameters<EmptyParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let session = context.session::<CounterSession>();
        let data = session.update(|s| s.counter += 1).await;
        Ok(CallToolResult::success(vec![ContentBlock::text(
            data.counter.to_string(),
        )]))
    }

    #[tool(description = "Get session counter without modifying it")]
    async fn get_counter(
        &self,
        Parameters(_): Parameters<EmptyParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let session = context.session::<CounterSession>();
        let data = session.get_or_create().await;
        Ok(CallToolResult::success(vec![ContentBlock::text(
            data.counter.to_string(),
        )]))
    }
}

#[rmcp::tool_handler]
impl ServerHandler for CounterServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions("Redis session test server")
    }
}

// ── Helpers ────────────────────────────────────────────────────────

fn redis_url() -> String {
    std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string())
}

async fn redis_available() -> bool {
    RedisBackend::connect(&redis_url()).await.is_ok()
}

/// Clean up all Redis keys with the given prefix using the index sets
/// (mirrors the production pattern — no KEYS scan).
async fn cleanup_redis_prefix(prefix: &str) {
    let client = redis::Client::open(redis_url().as_str()).unwrap();
    let mut conn: redis::aio::ConnectionManager =
        redis::aio::ConnectionManager::new(client).await.unwrap();
    let mut to_del = Vec::new();
    for ns in ["sessions", "tokens"] {
        let idx_key = format!("{prefix}:{ns}:__idx__");
        let members: Vec<String> = redis::cmd("SMEMBERS")
            .arg(&idx_key)
            .query_async(&mut conn)
            .await
            .unwrap_or_default();
        for m in &members {
            to_del.push(format!("{prefix}:{ns}:{m}"));
        }
        to_del.push(idx_key);
    }
    if !to_del.is_empty() {
        redis::cmd("DEL")
            .arg(&to_del)
            .query_async::<()>(&mut conn)
            .await
            .ok();
    }
}

/// Load a fresh SessionStore from Redis and return all session entries.
async fn load_sessions_from_redis(prefix: &str) -> Vec<(String, CounterSession)> {
    let redis = Arc::new(
        RedisBackend::connect(&redis_url())
            .await
            .unwrap()
            .with_prefix(prefix),
    );
    let backend: Arc<dyn PersistenceBackend> = redis.clone();
    let store =
        SessionStore::<CounterSession>::new(Duration::from_secs(300)).with_persistence(redis);
    store.load_persisted().await.unwrap();

    let keys = backend.keys("sessions").await.unwrap();
    let mut entries = Vec::new();
    for key in keys {
        if let Some(data) = store.get(&key).await {
            entries.push((key, data));
        }
    }
    entries
}

struct TestServer {
    addr: std::net::SocketAddr,
    session_store: SessionStore<CounterSession>,
    _server_handle: tokio::task::JoinHandle<()>,
}

/// Start a server with Redis-backed session persistence.
///
/// Calls `load_persisted()` on the session store before starting the server,
/// mirroring what `run_http_mode` does in production.
async fn start_server(redis: Arc<RedisBackend>) -> TestServer {
    let mut session_store = SessionStore::<CounterSession>::new(Duration::from_secs(300));
    session_store.set_persistence(redis.clone());
    session_store.load_persisted().await.unwrap();

    let config: HttpAppConfig<_, CounterSession> = HttpAppConfig {
        public_url: "http://localhost".to_string(),
        bind_addr: "127.0.0.1:0".to_string(),
        auth: AuthProvider::None,
        server_factory: || CounterServer::new(),
        app_name: "redis-session-test".to_string(),
        capability_registry: None,
        capability_filter: None,
        access_validator: None,
        claims_decoder: None,
        session_store: session_store.clone(),
        tool_call_logger: None,
        persistence: Some(redis),
        extra_routes: None,
        public_routes: None,
    };

    let (app, _token_store, _registry) = build_app(config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    TestServer {
        addr,
        session_store,
        _server_handle: handle,
    }
}

async fn connect_client(
    addr: std::net::SocketAddr,
) -> rmcp::service::RunningService<rmcp::RoleClient, ()> {
    let url = format!("http://{}/mcp", addr);
    let transport = StreamableHttpClientTransport::from_uri(url);
    ().serve(transport).await.expect("client connect failed")
}

fn call_tool_result_text(result: &CallToolResult) -> &str {
    result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.as_str())
        .expect("expected text content")
}

fn init_test_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("rmcp=debug,mcp_framework=debug")
        .with_test_writer()
        .try_init();
}

// ── Tests ──────────────────────────────────────────────────────────

/// Session data written during tool calls is persisted to Redis and
/// restored when a new server instance starts with the same backend.
///
/// Flow:
/// 1. Server 1 starts with Redis persistence
/// 2. Client calls `increment` twice → counter reaches 2
/// 3. Server 1 stops, client disconnects
/// 4. Server 2 starts with the same Redis backend
/// 5. Assert that the old session data was loaded from Redis (counter=2)
/// 6. New client connects and calls tools successfully
#[tokio::test]
async fn session_persists_across_server_restart() -> anyhow::Result<()> {
    init_test_tracing();

    if !redis_available().await {
        eprintln!("Skipping: Redis not available at {}", redis_url());
        return Ok(());
    }

    let prefix = format!("test_{}", uuid::Uuid::new_v4().simple());
    let make_redis = || async {
        Arc::new(
            RedisBackend::connect(&redis_url())
                .await
                .unwrap()
                .with_prefix(&prefix),
        )
    };

    // ── Server 1 ──────────────────────────────────────────────────

    let server1 = start_server(make_redis().await).await;
    let client1 = connect_client(server1.addr).await;

    // Increment the counter twice
    for expected in ["1", "2"] {
        let result = client1
            .call_tool(CallToolRequestParams::new("increment"))
            .await?;
        assert_eq!(call_tool_result_text(&result), expected);
    }

    assert_eq!(server1.session_store.len().await, 1);

    client1.cancel().await?;
    server1._server_handle.abort();

    // Let persistence writes complete
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ── Verify persisted data ─────────────────────────────────────

    let entries = load_sessions_from_redis(&prefix).await;
    assert_eq!(entries.len(), 1, "one session should be in Redis");
    assert_eq!(entries[0].1.counter, 2, "restored counter should be 2");

    // ── Server 2 (simulated restart) ──────────────────────────────

    let server2 = start_server(make_redis().await).await;

    // The old session was loaded from Redis
    assert_eq!(
        server2.session_store.len().await,
        1,
        "old session should be restored from Redis after restart"
    );

    // New client connects → gets a fresh MCP session, counter starts at 0
    let client2 = connect_client(server2.addr).await;

    let result = client2
        .call_tool(CallToolRequestParams::new("increment"))
        .await?;
    assert_eq!(
        call_tool_result_text(&result),
        "1",
        "new session counter should start at 1"
    );

    // Store now has 2 sessions: the one restored from Redis + the new one
    assert_eq!(server2.session_store.len().await, 2);

    client2.cancel().await?;
    server2._server_handle.abort();
    cleanup_redis_prefix(&prefix).await;
    Ok(())
}

/// Multiple tool calls within a session accumulate state, and that state
/// is persisted to Redis after each mutation.
#[tokio::test]
async fn session_state_accumulates_and_persists() -> anyhow::Result<()> {
    init_test_tracing();

    if !redis_available().await {
        eprintln!("Skipping: Redis not available at {}", redis_url());
        return Ok(());
    }

    let prefix = format!("test_{}", uuid::Uuid::new_v4().simple());
    let redis = Arc::new(
        RedisBackend::connect(&redis_url())
            .await
            .map_err(anyhow::Error::from_boxed)?
            .with_prefix(&prefix),
    );

    let server = start_server(redis).await;
    let client = connect_client(server.addr).await;

    // Increment 5 times
    for i in 1..=5 {
        let result = client
            .call_tool(CallToolRequestParams::new("increment"))
            .await?;
        assert_eq!(call_tool_result_text(&result), i.to_string());
    }

    // Read without modifying
    let result = client
        .call_tool(CallToolRequestParams::new("get_counter"))
        .await?;
    assert_eq!(call_tool_result_text(&result), "5");

    client.cancel().await?;
    server._server_handle.abort();

    // Let persistence writes complete
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Verify the exact counter value survived in Redis
    let entries = load_sessions_from_redis(&prefix).await;
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].1.counter, 5,
        "persisted counter should be 5 after 5 increments"
    );

    cleanup_redis_prefix(&prefix).await;
    Ok(())
}

/// After restart, old session data coexists with new sessions without
/// interference. Tools called from a new connection don't see old data.
#[tokio::test]
async fn new_session_after_restart_is_independent() -> anyhow::Result<()> {
    init_test_tracing();

    if !redis_available().await {
        eprintln!("Skipping: Redis not available at {}", redis_url());
        return Ok(());
    }

    let prefix = format!("test_{}", uuid::Uuid::new_v4().simple());
    let make_redis = || async {
        Arc::new(
            RedisBackend::connect(&redis_url())
                .await
                .unwrap()
                .with_prefix(&prefix),
        )
    };

    // ── Server 1: build session state ──

    let server1 = start_server(make_redis().await).await;
    let client1 = connect_client(server1.addr).await;

    // Increment to 10
    for _ in 0..10 {
        client1
            .call_tool(CallToolRequestParams::new("increment"))
            .await?;
    }

    let result = client1
        .call_tool(CallToolRequestParams::new("get_counter"))
        .await?;
    assert_eq!(call_tool_result_text(&result), "10");

    client1.cancel().await?;
    server1._server_handle.abort();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ── Server 2: restart ──

    let server2 = start_server(make_redis().await).await;
    let client2 = connect_client(server2.addr).await;

    // New session starts fresh — counter is 0, first increment gives 1
    let result = client2
        .call_tool(CallToolRequestParams::new("get_counter"))
        .await?;
    assert_eq!(
        call_tool_result_text(&result),
        "0",
        "new session should have counter=0, not inherit old session's data"
    );

    let result = client2
        .call_tool(CallToolRequestParams::new("increment"))
        .await?;
    assert_eq!(call_tool_result_text(&result), "1");

    client2.cancel().await?;
    server2._server_handle.abort();
    cleanup_redis_prefix(&prefix).await;
    Ok(())
}

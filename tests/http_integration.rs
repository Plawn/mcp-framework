//! Integration tests for MCP servers running over HTTP/SSE transport.
//!
//! These tests use `build_app()` to create an Axum router, bind it to a
//! random port, then connect an rmcp HTTP client to exercise the full
//! Streamable HTTP + SSE path — the same path that was failing with
//! "connection closed before message completed" after the rmcp 1.2 upgrade.

use std::sync::Arc;
use std::time::Duration;

use mcp_framework::auth::AuthProvider;
use mcp_framework::prelude::*;
use mcp_framework::session::SessionStore;
use mcp_framework::transport::{HttpAppConfig, build_app};
use rmcp::handler::server::tool::schema_for_output;
use rmcp::model::{CallToolRequestParams, ClientInfo, ProtocolVersion};
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::{ClientHandler, ClientLifecycleMode, ClientServiceExt, ServiceExt, tool};

// ── Tool parameter types ────────────────────────────────────────────

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct GreetParams {
    #[schemars(description = "The name to greet")]
    name: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct SizeParams {
    #[schemars(description = "Approximate response size in bytes (default: 5000)")]
    size: Option<usize>,
}

// ── Output schema types ─────────────────────────────────────────────

#[derive(Debug, serde::Serialize, schemars::JsonSchema)]
struct GreetOutput {
    #[schemars(description = "The greeting message")]
    message: String,
}

#[derive(Debug, serde::Serialize, schemars::JsonSchema)]
struct ProjectSource {
    id: u64,
    name: String,
}

#[derive(Debug, serde::Serialize, schemars::JsonSchema)]
struct ProjectItem {
    id: u64,
    name: String,
    description: String,
    metadata: ProjectMetadata,
    sources: Vec<ProjectSource>,
}

#[derive(Debug, serde::Serialize, schemars::JsonSchema)]
struct ProjectMetadata {
    language: String,
    role: String,
}

#[derive(Debug, serde::Serialize, schemars::JsonSchema)]
struct LargeResponseOutput {
    #[schemars(description = "List of projects")]
    projects: Vec<ProjectItem>,
}

#[derive(Debug, serde::Serialize, schemars::JsonSchema)]
struct PingOutput {
    #[schemars(description = "The pong response")]
    message: String,
}

// ── Server ──────────────────────────────────────────────────────────

#[derive(Clone)]
struct TestServer {
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

impl TestServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }
}

#[rmcp::tool_router]
impl TestServer {
    #[tool(
        description = "Return a short greeting",
        output_schema = schema_for_output::<GreetOutput>()
    )]
    async fn greet(
        &self,
        Parameters(params): Parameters<GreetParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let msg = format!("Hello, {}!", params.name);
        Ok(CallToolResult::success(vec![ContentBlock::text(msg)]))
    }

    #[tool(
        description = "Return a large JSON payload to test SSE streaming",
        output_schema = schema_for_output::<LargeResponseOutput>()
    )]
    fn large_response(&self, Parameters(params): Parameters<SizeParams>) -> String {
        let size = params.size.unwrap_or(5000);
        let item = serde_json::json!({
            "id": 42,
            "name": "Test Project",
            "description": "A project with a reasonably long description to simulate real API payloads.",
            "metadata": { "language": "English", "role": "Analyst" },
            "sources": [
                {"id": 1, "name": "Source A"},
                {"id": 2, "name": "Source B"},
                {"id": 3, "name": "Source C"},
            ]
        });
        let item_str = serde_json::to_string_pretty(&item).unwrap();
        let repeat = (size / item_str.len()).max(1);
        let items: Vec<_> = (0..repeat)
            .map(|i| {
                let mut v = item.clone();
                v["id"] = serde_json::json!(i);
                v
            })
            .collect();
        serde_json::to_string_pretty(&serde_json::json!({ "projects": items })).unwrap()
    }

    #[tool(
        description = "Return pong",
        output_schema = schema_for_output::<PingOutput>()
    )]
    fn ping(&self, Parameters(_): Parameters<EmptyParams>) -> String {
        "pong".to_string()
    }
}

#[rmcp::tool_handler]
impl ServerHandler for TestServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions("HTTP integration test server")
    }
}

/// Reproduces clients that advertise the latest protocol from `get_info()`
/// but still call the legacy `ServiceExt::serve` entry point.
#[derive(Clone, Copy)]
struct ModernInitializeClient;

impl ClientHandler for ModernInitializeClient {
    fn get_info(&self) -> ClientInfo {
        ClientInfo::default().with_protocol_version(ProtocolVersion::V_2026_07_28)
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Start the HTTP MCP server on a random port, return the bound address.
async fn start_server() -> std::net::SocketAddr {
    let config: HttpAppConfig<_, ()> = HttpAppConfig {
        public_url: "http://localhost".to_string(),
        bind_addr: "127.0.0.1:0".to_string(),
        auth: AuthProvider::None,
        server_factory: || TestServer::new(),
        app_name: "http-test".to_string(),
        capability_registry: None,
        capability_filter: None,
        access_validator: None,
        claims_decoder: None,
        session_store: SessionStore::default(),
        tool_call_logger: None,
        persistence: None,
        protocol_lifecycle: ProtocolLifecyclePolicy::Hybrid,
        extra_routes: None,
        public_routes: None,
    };

    let (app, _token_store, _registry) = build_app(config).expect("valid test configuration");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    addr
}

/// Start an independent HTTP instance sharing only the persistence backend.
async fn start_server_with_persistence(persistence: Arc<InMemoryBackend>) -> std::net::SocketAddr {
    let config: HttpAppConfig<_, ()> = HttpAppConfig {
        public_url: "http://localhost".to_string(),
        bind_addr: "127.0.0.1:0".to_string(),
        auth: AuthProvider::None,
        server_factory: || TestServer::new(),
        app_name: "http-persistence-test".to_string(),
        capability_registry: None,
        capability_filter: None,
        access_validator: None,
        claims_decoder: None,
        session_store: SessionStore::default(),
        tool_call_logger: None,
        persistence: Some(persistence),
        protocol_lifecycle: ProtocolLifecyclePolicy::Hybrid,
        extra_routes: None,
        public_routes: None,
    };

    let (app, _token_store, _registry) = build_app(config).expect("valid test configuration");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// Connect an rmcp HTTP client to the server at the given address.
async fn connect_client(
    addr: std::net::SocketAddr,
) -> rmcp::service::RunningService<rmcp::RoleClient, ()> {
    let url = format!("http://{}/mcp", addr);
    let transport = StreamableHttpClientTransport::from_uri(url);
    ().serve(transport).await.expect("client connect failed")
}

async fn connect_modern_initialize_client(
    addr: std::net::SocketAddr,
) -> rmcp::service::RunningService<rmcp::RoleClient, ModernInitializeClient> {
    let url = format!("http://{}/mcp", addr);
    let transport = StreamableHttpClientTransport::from_uri(url);
    ModernInitializeClient
        .serve(transport)
        .await
        .expect("hybrid client connect failed")
}

async fn connect_modern_discover_client(
    addr: std::net::SocketAddr,
) -> rmcp::service::RunningService<rmcp::RoleClient, ()> {
    let url = format!("http://{}/mcp", addr);
    let transport = StreamableHttpClientTransport::from_uri(url);
    ().serve_with_lifecycle(
        transport,
        ClientLifecycleMode::Discover {
            preferred_versions: vec![ProtocolVersion::V_2026_07_28],
        },
    )
    .await
    .expect("modern discover client connect failed")
}

fn init_test_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("rmcp=trace,mcp_framework=trace")
        .with_test_writer()
        .try_init();
}

// ── Tests ───────────────────────────────────────────────────────────

#[tokio::test]
async fn http_initialize() -> anyhow::Result<()> {
    init_test_tracing();
    let addr = start_server().await;
    let client = connect_client(addr).await;

    let info = client.peer().peer_info().expect("server info");
    assert!(
        info.instructions
            .as_deref()
            .unwrap_or("")
            .contains("HTTP integration test")
    );

    client.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn http_list_tools() -> anyhow::Result<()> {
    init_test_tracing();
    let addr = start_server().await;
    let client = connect_client(addr).await;

    let tools = client.list_all_tools().await?;
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();

    assert!(names.contains(&"greet"), "missing greet, got: {names:?}");
    assert!(
        names.contains(&"large_response"),
        "missing large_response, got: {names:?}"
    );
    assert!(names.contains(&"ping"), "missing ping, got: {names:?}");

    client.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn http_modern_initialize_is_downgraded_to_coherent_legacy_session() -> anyhow::Result<()> {
    init_test_tracing();
    let addr = start_server().await;
    let client = connect_modern_initialize_client(addr).await;

    let info = client.peer().peer_info().expect("server info");
    assert_eq!(info.protocol_version, ProtocolVersion::V_2025_11_25);

    let tools = client.list_all_tools().await?;
    let names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();
    assert!(names.contains(&"ping"), "missing ping, got: {names:?}");
    assert!(names.contains(&"greet"), "missing greet, got: {names:?}");

    client.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn http_modern_discover_remains_stateless_and_lists_tools() -> anyhow::Result<()> {
    init_test_tracing();
    let addr = start_server().await;

    let discover_response = reqwest::Client::new()
        .post(format!("http://{addr}/mcp"))
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "server/discover")
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "server/discover",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "stateless-test",
                        "version": "1"
                    }
                }
            }
        }))
        .send()
        .await?;
    assert_eq!(discover_response.status(), reqwest::StatusCode::OK);
    assert!(
        discover_response.headers().get("mcp-session-id").is_none(),
        "modern discover must not create a session"
    );
    assert_eq!(
        discover_response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json"),
        "terminal sessionless discovery should use plain JSON"
    );

    let list_response = reqwest::Client::new()
        .post(format!("http://{addr}/mcp"))
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/list")
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "stateless-test",
                        "version": "1"
                    }
                }
            }
        }))
        .send()
        .await?;
    assert_eq!(list_response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        list_response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json"),
        "terminal sessionless tools/list should use plain JSON"
    );
    let list_body: serde_json::Value = list_response.json().await?;
    let listed_tools = list_body["result"]["tools"]
        .as_array()
        .expect("tools/list result must contain a tools array");
    assert!(!listed_tools.is_empty(), "tools/list must not be empty");

    let client = connect_modern_discover_client(addr).await;

    let info = client.peer().peer_info().expect("server info");
    assert_eq!(info.protocol_version, ProtocolVersion::V_2026_07_28);

    let tools = client.list_all_tools().await?;
    let names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();
    assert!(names.contains(&"ping"), "missing ping, got: {names:?}");
    assert!(names.contains(&"greet"), "missing greet, got: {names:?}");

    client.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn http_modern_request_without_per_request_metadata_is_rejected() -> anyhow::Result<()> {
    init_test_tracing();
    let addr = start_server().await;

    let response = reqwest::Client::new()
        .post(format!("http://{addr}/mcp"))
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }))
        .send()
        .await?;

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(
        response.text().await?.contains("protocolVersion"),
        "error must identify the missing protocol metadata"
    );
    Ok(())
}

#[tokio::test]
async fn http_legacy_session_is_restored_on_another_instance() -> anyhow::Result<()> {
    init_test_tracing();
    let persistence = Arc::new(InMemoryBackend::new());
    let first = start_server_with_persistence(persistence.clone()).await;
    let second = start_server_with_persistence(persistence.clone()).await;
    let http = reqwest::Client::new();

    let initialize = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": "multi-instance-test", "version": "1" }
        }
    });
    let initialize_response = http
        .post(format!("http://{first}/mcp"))
        .header("accept", "application/json, text/event-stream")
        .json(&initialize)
        .send()
        .await?;
    assert_eq!(initialize_response.status(), reqwest::StatusCode::OK);
    let session_id = initialize_response
        .headers()
        .get("mcp-session-id")
        .expect("initialize must create a legacy session")
        .to_str()?
        .to_owned();

    assert!(
        persistence
            .keys("mcp_transport_sessions")
            .await
            .map_err(anyhow::Error::from_boxed)?
            .contains(&session_id),
        "rmcp transport session was not persisted"
    );

    let initialized_response = http
        .post(format!("http://{second}/mcp"))
        .header("accept", "application/json, text/event-stream")
        .header("mcp-session-id", &session_id)
        .header("mcp-protocol-version", "2025-11-25")
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }))
        .send()
        .await?;
    assert_eq!(initialized_response.status(), reqwest::StatusCode::ACCEPTED);

    let list_response = http
        .post(format!("http://{second}/mcp"))
        .header("accept", "application/json, text/event-stream")
        .header("mcp-session-id", &session_id)
        .header("mcp-protocol-version", "2025-11-25")
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }))
        .send()
        .await?;
    assert_eq!(list_response.status(), reqwest::StatusCode::OK);
    let body = list_response.text().await?;
    assert!(
        body.contains("\"name\":\"ping\""),
        "unexpected body: {body}"
    );

    Ok(())
}

#[tokio::test]
async fn http_output_schemas_present() -> anyhow::Result<()> {
    init_test_tracing();
    let addr = start_server().await;
    let client = connect_client(addr).await;

    let tools = client.list_all_tools().await?;
    for tool in &tools {
        assert!(
            tool.output_schema.is_some(),
            "tool '{}' should have an output_schema",
            tool.name
        );
        let schema = tool.output_schema.as_ref().unwrap();
        assert_eq!(
            schema.get("type").and_then(|v| v.as_str()),
            Some("object"),
            "tool '{}' output_schema should have type: object",
            tool.name
        );
    }

    client.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn http_call_small_tool() -> anyhow::Result<()> {
    init_test_tracing();
    let addr = start_server().await;
    let client = connect_client(addr).await;

    let result = client
        .call_tool(
            CallToolRequestParams::new("greet").with_arguments(
                serde_json::json!({ "name": "World" })
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await?;

    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.as_str())
        .expect("expected text content");

    assert_eq!(text, "Hello, World!");

    client.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn http_call_large_tool() -> anyhow::Result<()> {
    init_test_tracing();
    let addr = start_server().await;
    let client = connect_client(addr).await;

    // Request a ~10KB response to stress SSE streaming
    let result = client
        .call_tool(
            CallToolRequestParams::new("large_response").with_arguments(
                serde_json::json!({ "size": 10000 })
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await?;

    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.as_str())
        .expect("expected text content");

    // Verify it's valid JSON and contains the projects array
    let parsed: serde_json::Value = serde_json::from_str(text)?;
    let projects = parsed["projects"]
        .as_array()
        .expect("expected projects array");
    assert!(
        projects.len() > 1,
        "expected multiple projects, got {}",
        projects.len()
    );

    client.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn http_call_empty_params_tool() -> anyhow::Result<()> {
    init_test_tracing();
    let addr = start_server().await;
    let client = connect_client(addr).await;

    let result = client.call_tool(CallToolRequestParams::new("ping")).await?;

    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.as_str())
        .expect("expected text content");

    assert_eq!(text, "pong");

    client.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn http_multiple_calls_same_session() -> anyhow::Result<()> {
    init_test_tracing();
    let addr = start_server().await;
    let client = connect_client(addr).await;

    // Make several calls on the same connection to test session reuse
    for i in 0..5 {
        let result = client
            .call_tool(
                CallToolRequestParams::new("greet").with_arguments(
                    serde_json::json!({ "name": format!("User{i}") })
                        .as_object()
                        .unwrap()
                        .clone(),
                ),
            )
            .await?;

        let text = result
            .content
            .first()
            .and_then(|c| c.as_text())
            .map(|t| t.text.as_str())
            .expect("expected text content");

        assert_eq!(text, format!("Hello, User{i}!"));
    }

    client.cancel().await?;
    Ok(())
}

// ── Query parameter tool filtering ───────────────────────────────────

/// Connect an rmcp HTTP client with a `?filter=` query parameter.
async fn connect_client_with_filter(
    addr: std::net::SocketAddr,
    filter: &str,
) -> rmcp::service::RunningService<rmcp::RoleClient, ()> {
    let url = format!("http://{}/mcp?filter={}", addr, filter);
    let transport = StreamableHttpClientTransport::from_uri(url);
    ().serve(transport).await.expect("client connect failed")
}

#[tokio::test]
async fn http_query_filter_excludes_tools() -> anyhow::Result<()> {
    init_test_tracing();
    let addr = start_server().await;

    let client = connect_client_with_filter(addr, "ping").await;

    let tools = client.list_all_tools().await?;
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();

    assert!(
        !names.contains(&"ping"),
        "ping should be filtered out, got: {names:?}"
    );
    assert!(
        names.contains(&"greet"),
        "greet should still be present, got: {names:?}"
    );

    client.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn http_query_filter_rejects_call() -> anyhow::Result<()> {
    init_test_tracing();
    let addr = start_server().await;

    let client = connect_client_with_filter(addr, "ping").await;

    let result = client.call_tool(CallToolRequestParams::new("ping")).await;

    assert!(result.is_err(), "calling filtered tool should return error");

    client.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn http_query_filter_multiple_tools() -> anyhow::Result<()> {
    init_test_tracing();
    let addr = start_server().await;

    let client = connect_client_with_filter(addr, "ping,greet").await;

    let tools = client.list_all_tools().await?;
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();

    assert!(!names.contains(&"ping"), "ping should be filtered");
    assert!(!names.contains(&"greet"), "greet should be filtered");
    assert!(
        names.contains(&"large_response"),
        "large_response should remain"
    );

    client.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn http_no_filter_returns_all_tools() -> anyhow::Result<()> {
    init_test_tracing();
    let addr = start_server().await;

    let client = connect_client(addr).await;

    let tools = client.list_all_tools().await?;
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();

    assert!(names.contains(&"ping"));
    assert!(names.contains(&"greet"));
    assert!(names.contains(&"large_response"));

    client.cancel().await?;
    Ok(())
}

// ── Regression: SSE priming events break clients ────────────────────

/// Start a *raw* MCP server using rmcp's default StreamableHttpServerConfig
/// (which enables SSE priming events). This reproduces the pre-fix behavior.
async fn start_server_with_sse_priming() -> std::net::SocketAddr {
    use rmcp::transport::streamable_http_server::{
        StreamableHttpService, session::local::LocalSessionManager,
    };

    let mcp_service = StreamableHttpService::new(
        || Ok(TestServer::new()),
        LocalSessionManager::default().into(),
        Default::default(), // <-- SSE priming enabled (sse_retry: Some(3000))
    );

    let app = axum::Router::new().fallback_service(mcp_service);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    addr
}

/// With SSE priming enabled (rmcp default), the client may fail to receive
/// tool results because it interprets the priming event as the end of the
/// response. This test documents the regression that `sse_retry: None` fixes.
///
/// If rmcp fixes priming behavior upstream, this test can be removed.
#[tokio::test]
async fn http_sse_priming_causes_client_issues() {
    init_test_tracing();
    let addr = start_server_with_sse_priming().await;

    let url = format!("http://{}/mcp", addr);
    let transport = StreamableHttpClientTransport::from_uri(url);

    // The connect itself may fail or succeed depending on how the client
    // handles the priming event during initialization.
    let client_result = tokio::time::timeout(Duration::from_secs(5), ().serve(transport)).await;

    match client_result {
        Ok(Ok(client)) => {
            // Client connected — try a tool call. With priming events,
            // the tool call may time out or return an error.
            let tool_result = tokio::time::timeout(
                Duration::from_secs(5),
                client.call_tool(CallToolRequestParams::new("ping")),
            )
            .await;

            // Document the behavior: with priming, tool calls may fail.
            // We don't assert failure (rmcp client may handle it),
            // but we log the outcome.
            match tool_result {
                Ok(Ok(result)) => {
                    tracing::info!("SSE priming: tool call succeeded (client handled priming)");
                    let text = result
                        .content
                        .first()
                        .and_then(|c| c.as_text())
                        .map(|t| t.text.as_str());
                    assert_eq!(text, Some("pong"));
                }
                Ok(Err(e)) => {
                    tracing::warn!("SSE priming: tool call failed with error: {e}");
                }
                Err(_) => {
                    tracing::warn!("SSE priming: tool call timed out (connection likely broken)");
                }
            }

            let _ = client.cancel().await;
        }
        Ok(Err(e)) => {
            tracing::warn!("SSE priming: client failed to connect: {e}");
        }
        Err(_) => {
            tracing::warn!("SSE priming: client connection timed out");
        }
    }

    // The fixed server (start_server) always works — that's covered by the other tests.
    // This test just documents the priming behavior.
}

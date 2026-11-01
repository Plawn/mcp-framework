//! What a call carried besides its arguments — the request and the credential — reaching the
//! three places that act on it: the tool handler (`ToolCallContext`), the access validator
//! (`validate_call`) and the capability filter (`filter_tools_for`).
//!
//! The point is a tenant or space chosen by the caller (`?space=`, `x-plexus-space`) or a
//! structured identity posed by an in-process caller (`LoopbackIdentity::with_extension`) being
//! readable without each consumer re-deriving it from rmcp's `RequestContext`.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use mcp_framework::auth::{AuthProvider, RequestToken, StoredToken};
use mcp_framework::prelude::*;
use mcp_framework::session::SessionStore;
use mcp_framework::transport::{HttpAppConfig, LoopbackConnectError, LoopbackIdentity, build_app};
use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, JsonObject};
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use serde_json::{Map, Value};
use std::sync::Arc;

// ── Fixtures ─────────────────────────────────────────────────────────

/// A structured identity an in-process caller poses on its session.
#[derive(Clone, Debug, PartialEq)]
struct ServicePrincipal {
    name: &'static str,
}

#[derive(Clone)]
struct EmptyServer;

impl rmcp::ServerHandler for EmptyServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
    }
}

/// `whoami` answers with what its context carried, one `key=value` per line.
async fn registry() -> CapabilityRegistry {
    let registry = CapabilityRegistry::default();
    registry
        .add_tool_with_context(
            Tool::new("whoami", "Echoes the call context", Map::new()),
            |_args: Option<JsonObject>, ctx: ToolCallContext| async move {
                let request = ctx.request.as_ref();
                let lines = [
                    format!(
                        "principal={}",
                        request
                            .and_then(|r| r.extensions.get::<ServicePrincipal>())
                            .map_or("-", |p| p.name)
                    ),
                    format!(
                        "query={}",
                        request.and_then(|r| r.uri.query()).unwrap_or("-")
                    ),
                    format!(
                        "space_param={}",
                        request
                            .and_then(|r| r.query_param("space"))
                            .unwrap_or_else(|| "-".to_string())
                    ),
                    format!(
                        "space_header={}",
                        request
                            .and_then(|r| r.headers.get("x-plexus-space"))
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("-")
                    ),
                    format!(
                        "token={}",
                        ctx.token.as_ref().map_or("-", |t| t.access_token.as_str())
                    ),
                ];
                Ok(CallToolResult::success(vec![ContentBlock::text(
                    lines.join("\n"),
                )]))
            },
        )
        .await;
    registry
        .add_tool(
            Tool::new("service_only", "Visible to service principals", Map::new()),
            |_args| async { Ok(CallToolResult::success(vec![ContentBlock::text("ok")])) },
        )
        .await;
    registry
}

/// The `key=value` lines `whoami` returned, as a map.
async fn whoami(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
) -> anyhow::Result<HashMap<String, String>> {
    let result = client
        .call_tool(CallToolRequestParams::new("whoami"))
        .await?;
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .ok_or_else(|| anyhow::anyhow!("whoami returned no text"))?;
    Ok(text
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect())
}

/// Denies `service_only` to any caller whose request carries no `ServicePrincipal`, and records
/// the space the request named — through the new `validate_call` only.
struct PrincipalValidator {
    seen_space: Arc<std::sync::Mutex<Option<String>>>,
}

impl AccessValidator for PrincipalValidator {
    fn validate_call(
        &self,
        tool_name: &str,
        _arguments: Option<&Map<String, Value>>,
        call: &CallInfo<'_>,
    ) -> Pin<Box<dyn Future<Output = AccessDecision> + Send + '_>> {
        let request = call.request;
        if let Some(space) = request.and_then(|r| r.query_param("space")) {
            *self.seen_space.lock().expect("unpoisoned") = Some(space);
        }
        let is_service = request
            .and_then(|r| r.extensions.get::<ServicePrincipal>())
            .is_some();
        let decision = if tool_name == "service_only" && !is_service {
            AccessDecision::Deny("service principals only".to_string())
        } else {
            AccessDecision::Allow
        };
        Box::pin(std::future::ready(decision))
    }
}

/// A validator written against the pre-`validate_call` surface: only `validate_tool_call`.
struct LegacyValidator;

impl AccessValidator for LegacyValidator {
    fn validate_tool_call(
        &self,
        tool_name: &str,
        _arguments: Option<&Map<String, Value>>,
        token: Option<&StoredToken>,
        session_id: &str,
    ) -> Pin<Box<dyn Future<Output = AccessDecision> + Send + '_>> {
        let decision = if tool_name == "service_only"
            && (session_id != "root" || token.is_none_or(|t| t.access_token != "secret"))
        {
            AccessDecision::Deny("root with a token only".to_string())
        } else {
            AccessDecision::Allow
        };
        Box::pin(std::future::ready(decision))
    }
}

/// Hides `service_only` from callers without a `ServicePrincipal` — through `filter_tools_for`.
struct PrincipalFilter;

impl CapabilityFilter for PrincipalFilter {
    fn filter_tools_for(&self, tools: Vec<Tool>, call: &CallInfo<'_>) -> Vec<Tool> {
        let is_service = call
            .request
            .and_then(|r| r.extensions.get::<ServicePrincipal>())
            .is_some();
        tools
            .into_iter()
            .filter(|t| is_service || t.name != "service_only")
            .collect()
    }
}

// ── Loopback ─────────────────────────────────────────────────────────

#[tokio::test]
async fn an_extension_posed_on_a_loopback_identity_reaches_the_tool() -> anyhow::Result<()> {
    let mut builder = McpAppBuilder::new("call-request-loopback")
        .server(|| EmptyServer)
        .capability_registry(registry().await);
    let endpoint = builder.loopback();

    let client = endpoint
        .connect(
            LoopbackIdentity::new("job-1")
                .with_bearer_token("secret")
                .with_extension(ServicePrincipal { name: "scheduler" }),
        )
        .await?;
    let seen = whoami(&client).await?;
    assert_eq!(seen["principal"], "scheduler");
    assert_eq!(seen["token"], "secret", "ctx.token must carry the bearer");

    let anon = endpoint.connect(LoopbackIdentity::new("job-2")).await?;
    let seen = whoami(&anon).await?;
    assert_eq!(
        seen["principal"], "-",
        "an extension must not leak across sessions"
    );
    assert_eq!(seen["token"], "-");

    client.cancel().await?;
    anon.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn validate_call_and_filter_tools_for_see_the_request() -> anyhow::Result<()> {
    let seen_space = Arc::new(std::sync::Mutex::new(None));
    let mut builder = McpAppBuilder::new("call-request-validator")
        .server(|| EmptyServer)
        .capability_registry(registry().await)
        .capability_filter(Arc::new(PrincipalFilter))
        .access_validator(Arc::new(PrincipalValidator {
            seen_space: seen_space.clone(),
        }));
    let endpoint = builder.loopback();

    let service = endpoint
        .connect(LoopbackIdentity::new("svc").with_extension(ServicePrincipal { name: "svc" }))
        .await?;
    let anon = endpoint.connect(LoopbackIdentity::new("anon")).await?;

    let visible = |tools: Vec<Tool>| -> Vec<String> {
        tools.into_iter().map(|t| t.name.to_string()).collect()
    };
    let service_tools = visible(service.list_all_tools().await?);
    let anon_tools = visible(anon.list_all_tools().await?);
    assert!(
        service_tools.contains(&"service_only".to_string()),
        "got {service_tools:?}"
    );
    assert!(
        !anon_tools.contains(&"service_only".to_string()),
        "got {anon_tools:?}"
    );

    service
        .call_tool(CallToolRequestParams::new("service_only"))
        .await?;
    let err = anon
        .call_tool(CallToolRequestParams::new("service_only"))
        .await
        .expect_err("validate_call should deny a caller without a principal");
    assert!(err.to_string().contains("service principals only"), "{err}");
    // The loopback synthesizes `POST /mcp` — no query to record.
    assert_eq!(*seen_space.lock().expect("unpoisoned"), None);

    service.cancel().await?;
    anon.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn a_validator_with_only_validate_tool_call_still_decides() -> anyhow::Result<()> {
    let mut builder = McpAppBuilder::new("call-request-legacy")
        .server(|| EmptyServer)
        .capability_registry(registry().await)
        .access_validator(Arc::new(LegacyValidator));
    let endpoint = builder.loopback();

    let root = endpoint
        .connect(LoopbackIdentity::new("root").with_bearer_token("secret"))
        .await?;
    root.call_tool(CallToolRequestParams::new("service_only"))
        .await?;

    let other = endpoint.connect(LoopbackIdentity::new("other")).await?;
    let err = other
        .call_tool(CallToolRequestParams::new("service_only"))
        .await
        .expect_err("the legacy validator should deny through the default validate_call");
    assert!(err.to_string().contains("root with a token only"), "{err}");

    root.cancel().await?;
    other.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn a_credential_extension_is_refused_at_connect() -> anyhow::Result<()> {
    let mut builder = McpAppBuilder::new("call-request-refusal")
        .server(|| EmptyServer)
        .capability_registry(registry().await);
    let endpoint = builder.loopback();

    let err = endpoint
        .connect(
            LoopbackIdentity::new("forged").with_extension(RequestToken(StoredToken::new(
                "forged".into(),
                None,
                None,
            ))),
        )
        .await
        .expect_err("a RequestToken posed in-process must not pass as a validated credential");
    assert!(
        matches!(err, LoopbackConnectError::InvalidIdentity(_)),
        "unexpected error: {err}"
    );
    Ok(())
}

// ── HTTP ─────────────────────────────────────────────────────────────

async fn start_server(
    access_validator: Option<Arc<dyn AccessValidator>>,
) -> anyhow::Result<std::net::SocketAddr> {
    let config: HttpAppConfig<_, ()> = HttpAppConfig {
        public_url: "http://localhost".to_string(),
        bind_addr: "127.0.0.1:0".to_string(),
        auth: AuthProvider::None,
        server_factory: || EmptyServer,
        app_name: "call-request-http".to_string(),
        capability_registry: Some(registry().await),
        capability_filter: None,
        access_validator,
        claims_decoder: None,
        session_store: SessionStore::default(),
        tool_call_logger: None,
        persistence: None,
        protocol_lifecycle: ProtocolLifecyclePolicy::Hybrid,
        max_protocol_version: None,
        extra_routes: None,
        public_routes: None,
    };
    let (app, _token_store, _registry) = build_app(config)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        // deliberate: the server dies with the test runtime; nothing awaits its result.
        let _ = axum::serve(listener, app).await;
    });
    Ok(addr)
}

#[tokio::test]
async fn an_http_call_carries_its_query_and_headers_to_the_tool_and_validator() -> anyhow::Result<()>
{
    let seen_space = Arc::new(std::sync::Mutex::new(None));
    let addr = start_server(Some(Arc::new(PrincipalValidator {
        seen_space: seen_space.clone(),
    })))
    .await?;

    let mut headers = HashMap::new();
    headers.insert(
        http::HeaderName::from_static("x-plexus-space"),
        http::HeaderValue::from_static("team-header"),
    );
    let transport = StreamableHttpClientTransport::from_config(
        StreamableHttpClientTransportConfig::with_uri(format!("http://{addr}/mcp?space=team"))
            .custom_headers(headers),
    );
    let client = ().serve(transport).await?;

    let seen = whoami(&client).await?;
    assert!(
        seen["query"].contains("space=team"),
        "the connection URL's query must reach the tool, got {:?}",
        seen["query"]
    );
    assert_eq!(seen["space_param"], "team");
    assert_eq!(seen["space_header"], "team-header");
    assert_eq!(
        seen["principal"], "-",
        "a network call carries no loopback extension"
    );
    assert_eq!(
        seen_space.lock().expect("unpoisoned").as_deref(),
        Some("team"),
        "validate_call must see the request too"
    );

    client.cancel().await?;
    Ok(())
}

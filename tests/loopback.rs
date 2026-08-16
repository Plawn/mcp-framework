//! The in-process transport, checked on the point that motivates it: an in-process caller takes
//! the *same* path as a network client.
//!
//! Reaching into `CapabilityRegistry::call_tool` also works, and that is the problem — it works
//! while skipping the [`CapabilityFilter`], the [`AccessValidator`] and the [`ToolCallLogger`].
//! Nothing fails, nothing is logged, and the metrics quietly describe external traffic only. Each
//! test below pins one of those three, plus the identity that carries them.

use std::sync::Arc;
use std::time::Duration;

use mcp_framework::audit::{ToolCallLogger, ToolCallOutcome, ToolCallRecord, ToolCallSource};
use mcp_framework::auth::{
    AuthProvider, OAuthConfig, StoredToken, TokenMode, UnknownTokenValidation,
};
use mcp_framework::prelude::*;
use mcp_framework::session::SessionStore;
use mcp_framework::transport::{LoopbackConnectError, LoopbackEndpoint, LoopbackIdentity};
use rmcp::model::CallToolRequestParams;
use tokio::sync::mpsc;

// ── Fixtures ─────────────────────────────────────────────────────────

/// A logger that hands each record to the test instead of storing it.
///
/// The framework logs from a detached `tokio::spawn`, so a shared `Vec` would need a sleep to be
/// read reliably. A channel turns that race into an await with a deadline.
struct ChannelLogger(mpsc::UnboundedSender<ToolCallRecord>);

impl ToolCallLogger for ChannelLogger {
    fn log_sync(&self, record: ToolCallRecord) {
        // deliberate: the receiver is dropped at the end of a test; a late record has nowhere to
        // go and nothing to fail.
        let _ = self.0.send(record);
    }
}

/// The next audited call, or a panic — a test that hangs says less than one that fails.
async fn next_record(rx: &mut mpsc::UnboundedReceiver<ToolCallRecord>) -> ToolCallRecord {
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("no tool call was audited within 5s")
        .expect("the logger channel closed")
}

/// An inner `ServerHandler` with a static tool, to exercise the dispatch path the registry does
/// not own — the one engine's forwarded backend tools take.
#[derive(Clone)]
struct InnerServer {
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

impl InnerServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }
}

#[rmcp::tool_router]
impl InnerServer {
    #[rmcp::tool(description = "A tool served by the inner handler, not the registry")]
    fn inner_echo(&self) -> String {
        "from-inner".to_string()
    }
}

#[rmcp::tool_handler]
impl ServerHandler for InnerServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
    }
}

/// A registry holding `ping` (public) and `admin_reset` (hidden without a token).
async fn test_registry() -> CapabilityRegistry {
    let registry = CapabilityRegistry::default();
    registry
        .add_tool(
            Tool::new("ping", "Returns pong", serde_json::Map::new()),
            |_args| async { Ok(CallToolResult::success(vec![ContentBlock::text("pong")])) },
        )
        .await;
    registry
        .add_tool(
            Tool::new("admin_reset", "Admin only", serde_json::Map::new()),
            |_args| async { Ok(CallToolResult::success(vec![ContentBlock::text("reset")])) },
        )
        .await;
    registry
}

/// A syntactically valid OAuth config — `validate()` rejects empty fields, and nothing here ever
/// talks to a Keycloak.
fn oauth_config() -> OAuthConfig {
    OAuthConfig {
        client_id: "loopback-test".to_string(),
        client_secret: None,
        issuer_url: "https://keycloak.invalid/realms/test".to_string(),
        redirect_url: "http://127.0.0.1:4000/oauth/callback".to_string(),
        scopes: vec!["openid".to_string()],
        token_mode: TokenMode::Passthrough,
        // `Reject` parce que ces tests n'ont pas d'autorité à joindre : l'issuer est
        // `.invalid`, et toute autre politique ferait partir une requête réseau depuis un
        // test qui n'a rien à valider à distance.
        unknown_token_validation: UnknownTokenValidation::Reject,
        expected_audiences: vec![],
    }
}

/// Hides `admin_` tools from sessions that present no token.
fn admin_filter() -> Arc<dyn CapabilityFilter> {
    Arc::new(ToolFilter(
        |tools: Vec<Tool>, token: Option<&StoredToken>| match token {
            Some(_) => tools,
            None => tools
                .into_iter()
                .filter(|t| !t.name.starts_with("admin_"))
                .collect(),
        },
    ))
}

/// The endpoint under test, with a logger wired to `rx`.
///
/// The builder is dropped without ever being run: a loopback endpoint is a client of the
/// application, not of a listening socket, and nothing here binds a port.
async fn endpoint_with_logger() -> (
    LoopbackEndpoint<(), impl Fn() -> InnerServer + Clone + Send + Sync + 'static>,
    mpsc::UnboundedReceiver<ToolCallRecord>,
) {
    let (tx, rx) = mpsc::unbounded_channel();
    let mut builder = McpAppBuilder::new("loopback-test")
        .server(InnerServer::new)
        .capability_registry(test_registry().await)
        .capability_filter(admin_filter())
        .tool_call_logger(Arc::new(ChannelLogger(tx)));
    (builder.loopback(), rx)
}

// ── The logger ───────────────────────────────────────────────────────

#[tokio::test]
async fn a_registry_call_is_audited() -> anyhow::Result<()> {
    let (endpoint, mut rx) = endpoint_with_logger().await;
    let client = endpoint.connect(LoopbackIdentity::new("thread-a")).await?;

    let result = client
        .call_tool(CallToolRequestParams::new("ping"))
        .await?;
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.as_str());
    assert_eq!(text, Some("pong"));

    let record = next_record(&mut rx).await;
    assert_eq!(record.tool_name.as_ref(), "ping");
    assert_eq!(record.source, ToolCallSource::Registry);
    assert_eq!(record.session_id.as_ref(), "thread-a");
    assert!(
        matches!(
            record.outcome,
            ToolCallOutcome::Success { is_error: false, .. }
        ),
        "unexpected outcome: {:?}",
        record.outcome
    );

    client.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn an_inner_handler_call_is_audited_too() -> anyhow::Result<()> {
    // The path a forwarded backend tool takes: not in the registry, served by the inner handler.
    // It is the half most likely to be forgotten, and the half that carries the most traffic.
    let (endpoint, mut rx) = endpoint_with_logger().await;
    let client = endpoint.connect(LoopbackIdentity::new("thread-a")).await?;

    client
        .call_tool(CallToolRequestParams::new("inner_echo"))
        .await?;

    let record = next_record(&mut rx).await;
    assert_eq!(record.tool_name.as_ref(), "inner_echo");
    assert_eq!(record.source, ToolCallSource::Inner);

    client.cancel().await?;
    Ok(())
}

// ── Identity ─────────────────────────────────────────────────────────

#[tokio::test]
async fn two_sessions_are_two_identities() -> anyhow::Result<()> {
    // One session per caller is the whole point: without it every in-process call lands on
    // `"default"` and the audit trail cannot tell two conversations apart.
    let (endpoint, mut rx) = endpoint_with_logger().await;
    let a = endpoint.connect(LoopbackIdentity::new("thread-a")).await?;
    let b = endpoint.connect(LoopbackIdentity::new("thread-b")).await?;

    a.call_tool(CallToolRequestParams::new("ping")).await?;
    let first = next_record(&mut rx).await;
    b.call_tool(CallToolRequestParams::new("ping")).await?;
    let second = next_record(&mut rx).await;

    assert_eq!(first.session_id.as_ref(), "thread-a");
    assert_eq!(second.session_id.as_ref(), "thread-b");

    a.cancel().await?;
    b.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn a_session_reopened_without_a_token_loses_the_previous_rights() -> anyhow::Result<()> {
    // The dangerous direction, and the one the filter test above does not cover.
    //
    // The token store is keyed by session id alone; a loopback token carries no `expires_at`, so
    // nothing expires it; and `resolve_token` never reads the `Authorization` header. Storing on
    // connect and doing nothing on a tokenless connect therefore made the *first* caller's rights
    // permanent for that name — a later caller claiming no credentials would still be served as
    // an admin, with an audit record indistinguishable from the anonymous call it claims to be.
    let (endpoint, _rx) = endpoint_with_logger().await;

    let authed = endpoint
        .connect(LoopbackIdentity::new("shared").with_bearer_token("secret"))
        .await?;
    let names: Vec<String> = authed
        .list_all_tools()
        .await?
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    assert!(names.contains(&"admin_reset".to_string()), "premise broken: {names:?}");
    authed.cancel().await?;

    let anon = endpoint.connect(LoopbackIdentity::new("shared")).await?;
    let names: Vec<String> = anon
        .list_all_tools()
        .await?
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    assert!(
        !names.contains(&"admin_reset".to_string()),
        "the session reopened without a token but inherited the previous caller's rights: {names:?}"
    );

    anon.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn forgetting_a_session_drops_its_token() -> anyhow::Result<()> {
    // A closed client ends the conversation but not the credential: nothing expires a loopback
    // token, so the owner of a session's lifecycle has to be able to drop it.
    let (endpoint, _rx) = endpoint_with_logger().await;

    let authed = endpoint
        .connect(LoopbackIdentity::new("job-1").with_bearer_token("secret"))
        .await?;
    authed.cancel().await?;
    endpoint.forget_session("job-1").await;

    // Re-connecting *with* a token is the case that would hide a leak, so the probe reconnects
    // with one and checks the store was empty in between.
    let after = endpoint.connect(LoopbackIdentity::new("job-1")).await?;
    let names: Vec<String> = after
        .list_all_tools()
        .await?
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    assert!(!names.contains(&"admin_reset".to_string()), "token survived forget: {names:?}");

    after.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn an_identity_the_protocol_cannot_carry_is_refused() -> anyhow::Result<()> {
    // Both shapes below used to be *accepted* and silently become something else: an empty id is
    // a valid header value that reaches a tool as a real caller name, and an id no header can
    // hold dropped the whole parts object, merging that caller into the shared `"default"`
    // session — where it could read another caller's state.
    let (endpoint, _rx) = endpoint_with_logger().await;

    let err = endpoint
        .connect(LoopbackIdentity::new(""))
        .await
        .expect_err("an empty session id should be refused");
    assert!(err.to_string().contains("empty"), "unexpected error: {err}");

    let err = endpoint
        .connect(LoopbackIdentity::new("thread\nid"))
        .await
        .expect_err("a session id no header can hold should be refused");
    assert!(
        matches!(err, mcp_framework::transport::LoopbackConnectError::InvalidIdentity(_)),
        "unexpected error: {err}"
    );
    Ok(())
}

#[tokio::test]
async fn an_opaque_bearer_is_refused_rather_than_stored() -> anyhow::Result<()> {
    // In Opaque mode the bearer a caller holds is a UUID the framework issued; the real token
    // lives in the HTTP transport's store, which this endpoint deliberately does not share.
    // Storing the UUID would produce a `StoredToken` that reads as a credential to every filter
    // and validator and authenticates nothing downstream — the worst of both.
    let oauth = OAuthConfig {
        token_mode: TokenMode::Opaque,
        ..oauth_config()
    };
    let mut builder = McpAppBuilder::new("loopback-opaque")
        .auth(AuthProvider::OAuth(oauth))
        .server(InnerServer::new)
        .capability_registry(test_registry().await)
        .capability_filter(admin_filter());
    let endpoint = builder.loopback();

    let err = endpoint
        .connect(LoopbackIdentity::new("thread-a").with_bearer_token("f81d4fae-opaque"))
        .await
        .expect_err("an opaque bearer should be refused");
    assert!(
        matches!(err, LoopbackConnectError::UnresolvableCredential { .. }),
        "unexpected error: {err}"
    );

    // Retrying anonymously is the sanctioned fallback: it de-escalates, so it is always safe.
    let anon = endpoint.connect(LoopbackIdentity::new("thread-a")).await?;
    let names: Vec<String> = anon
        .list_all_tools()
        .await?
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    assert!(
        !names.contains(&"admin_reset".to_string()),
        "the refused bearer still reached the filter: {names:?}"
    );

    anon.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn a_loopback_session_does_not_reach_a_network_client_state() -> anyhow::Result<()> {
    // The session id of a loopback caller is chosen by that caller — in engine it comes from a
    // request body. If the two transports shared a session store, naming a thread after an HTTP
    // session id would be enough to read and write that client's state from outside.
    let builder = McpAppBuilder::new("loopback-stores")
        .with_sessions::<u32>()
        .server(InnerServer::new)
        .capability_registry(test_registry().await);
    let http_store: SessionStore<u32> = SessionStore::new(Duration::from_secs(60));
    let mut builder = builder.session_store(http_store.clone());
    let endpoint = builder.loopback();

    // What a network client left behind, under a session id an in-process caller can guess.
    http_store.update("victim", |n| *n = 42).await;

    let client = endpoint.connect(LoopbackIdentity::new("victim")).await?;
    client.call_tool(CallToolRequestParams::new("ping")).await?;
    client.cancel().await?;

    assert_eq!(
        http_store.get("victim").await,
        Some(42),
        "a loopback session reached into the network transport's session store"
    );
    Ok(())
}

#[tokio::test]
async fn configuring_the_builder_after_loopback_is_refused_at_build() -> anyhow::Result<()> {
    // The endpoint is a snapshot. A filter set afterwards would apply to network clients only —
    // half the traffic, silently — so the builder refuses rather than letting the paths diverge.
    let mut builder = McpAppBuilder::new("loopback-divergence")
        .server(InnerServer::new)
        .capability_registry(test_registry().await);
    let _endpoint = builder.loopback();

    let err = builder
        .capability_filter(admin_filter())
        .build()
        // `.err()` rather than `expect_err`: a built `McpApp` is not `Debug`, and giving it that
        // impl for the sake of one assertion would be the tail wagging the dog.
        .err()
        .expect("a filter set after `loopback()` should be refused");
    let msg = err.to_string();
    assert!(msg.contains("capability_filter"), "the error must name the field: {msg}");
    Ok(())
}

// ── The filter ───────────────────────────────────────────────────────

#[tokio::test]
async fn the_capability_filter_applies_to_a_loopback_listing() -> anyhow::Result<()> {
    let (endpoint, _rx) = endpoint_with_logger().await;

    let anon = endpoint.connect(LoopbackIdentity::new("anon")).await?;
    let names: Vec<String> = anon
        .list_all_tools()
        .await?
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    assert!(names.contains(&"ping".to_string()), "got: {names:?}");
    assert!(
        !names.contains(&"admin_reset".to_string()),
        "an anonymous loopback session should not see admin tools, got: {names:?}"
    );

    let authed = endpoint
        .connect(LoopbackIdentity::new("authed").with_bearer_token("secret"))
        .await?;
    let names: Vec<String> = authed
        .list_all_tools()
        .await?
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    assert!(
        names.contains(&"admin_reset".to_string()),
        "the bearer token did not reach the filter, got: {names:?}"
    );

    anon.cancel().await?;
    authed.cancel().await?;
    Ok(())
}

// ── The validator ────────────────────────────────────────────────────

#[tokio::test]
async fn the_access_validator_can_deny_a_loopback_call() -> anyhow::Result<()> {
    // The validator reads the session id, so it also proves the identity reaches *execution*
    // control and not only the audit record: the same tool is denied to one session and served
    // to another.
    let validator: Arc<dyn AccessValidator> = Arc::new(ToolCallValidator(
        |name: &str, _args: Option<&serde_json::Map<String, serde_json::Value>>, _token: Option<&StoredToken>, session_id: &str| {
            if name == "admin_reset" && session_id != "root" {
                AccessDecision::Deny("not root".to_string())
            } else {
                AccessDecision::Allow
            }
        },
    ));
    let mut builder = McpAppBuilder::new("loopback-validator")
        .server(InnerServer::new)
        .capability_registry(test_registry().await)
        .access_validator(validator);
    let endpoint = builder.loopback();

    let denied = endpoint.connect(LoopbackIdentity::new("thread-a")).await?;
    let err = denied
        .call_tool(CallToolRequestParams::new("admin_reset"))
        .await
        .expect_err("the validator should have denied this call");
    assert!(
        err.to_string().contains("Access denied"),
        "unexpected error: {err}"
    );

    let allowed = endpoint.connect(LoopbackIdentity::new("root")).await?;
    allowed
        .call_tool(CallToolRequestParams::new("admin_reset"))
        .await?;

    denied.cancel().await?;
    allowed.cancel().await?;
    Ok(())
}

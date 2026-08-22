//! What the wire looks like for every combination of announced lifecycle,
//! [`ProtocolLifecyclePolicy`] and advertised-revision ceiling.
//!
//! The bug this matrix exists for: rmcp's `ServerHandler` default advertises
//! every [`ProtocolVersion::KNOWN_VERSIONS`], so a server offers `2026-07-28`
//! without anyone deciding to. Clients that take it up go down the sessionless
//! `server/discover` path — a lifecycle the deployment may never have been
//! exercised against. `max_protocol_version` makes the offer an explicit
//! decision; these tests pin what capping actually changes on the wire, and
//! (just as importantly) what it does *not*.

use mcp_framework::auth::AuthProvider;
use mcp_framework::session::SessionStore;
use mcp_framework::transport::{HttpAppConfig, ProtocolLifecyclePolicy, build_app};
use rmcp::ServerHandler;
use rmcp::model::{ProtocolVersion, ServerCapabilities, ServerInfo};

#[derive(Clone)]
struct MatrixServer;

impl ServerHandler for MatrixServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info
    }
}

async fn start(policy: ProtocolLifecyclePolicy, cap: Option<ProtocolVersion>) -> std::net::SocketAddr {
    let config: HttpAppConfig<_, ()> = HttpAppConfig {
        public_url: "http://localhost".to_string(),
        bind_addr: "127.0.0.1:0".to_string(),
        auth: AuthProvider::None,
        server_factory: || MatrixServer,
        app_name: "protocol-matrix".to_string(),
        capability_registry: None,
        capability_filter: None,
        access_validator: None,
        claims_decoder: None,
        session_store: SessionStore::default(),
        tool_call_logger: None,
        persistence: None,
        protocol_lifecycle: policy,
        max_protocol_version: cap,
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

/// One handshake, reported the way an operator reads it off the wire.
struct Handshake {
    status: u16,
    /// `result.protocolVersion` on success — what the peer will actually speak.
    negotiated: Option<String>,
    /// `error.code` on refusal. rmcp answers `-32022` for an unsupported revision.
    error_code: Option<i64>,
    /// `result.supportedVersions` — what `server/discover` puts on offer.
    advertised: Option<Vec<String>>,
    /// `error.data.supported` — the list a well-behaved client retries against.
    supported: Option<Vec<String>>,
    /// Whether rmcp created a transport session (absent = stateless).
    session: bool,
}

async fn handshake(
    addr: std::net::SocketAddr,
    method: &str,
    version: &str,
) -> Handshake {
    let response = reqwest::Client::new()
        .post(format!("http://{addr}/mcp"))
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", version)
        // SEP-2243: from 2026-07-28 on, the method is also a header.
        .header("mcp-method", method)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            // `server/discover` carries no negotiation parameters — the revision it
            // asks for travels in per-request `_meta`. `initialize` carries it in the
            // body, and rmcp rejects a header/body mismatch, so both are set alike.
            "params": if method == "initialize" {
                serde_json::json!({
                    "protocolVersion": version,
                    "capabilities": {},
                    "clientInfo": { "name": "matrix", "version": "0" }
                })
            } else {
                // SEP-2567: a sessionless request carries its own context in
                // `_meta` instead of leaning on a negotiated session.
                serde_json::json!({
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": version,
                        "io.modelcontextprotocol/clientCapabilities": {},
                        "io.modelcontextprotocol/clientInfo": {
                            "name": "matrix", "version": "0"
                        }
                    }
                })
            }
        }))
        .send()
        .await
        .expect("request reaches the server");

    let status = response.status().as_u16();
    let session = response.headers().contains_key("mcp-session-id");
    let body = response.text().await.unwrap_or_default();
    // A legacy session answers over SSE, so the JSON sits behind a `data:` line.
    let json: serde_json::Value = body
        .lines()
        .find_map(|line| serde_json::from_str(line.trim_start_matches("data: ")).ok())
        .unwrap_or(serde_json::Value::Null);

    Handshake {
        status,
        negotiated: json["result"]["protocolVersion"]
            .as_str()
            .map(str::to_owned),
        advertised: json["result"]["supportedVersions"].as_array().map(|values| {
            values
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        }),
        error_code: json["error"]["code"].as_i64(),
        supported: json["error"]["data"]["supported"].as_array().map(|values| {
            values
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        }),
        session,
    }
}

const MODERN: &str = "2026-07-28";
const LEGACY: &str = "2025-11-25";
const ALL_REVISIONS: [&str; 5] = [
    "2024-11-05",
    "2025-03-26",
    "2025-06-18",
    "2025-11-25",
    "2026-07-28",
];
/// `ALL_REVISIONS` minus the one the ceiling removes.
const UP_TO_LEGACY: [&str; 4] = ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"];

// ── Uncapped: the rmcp default, and the shape of the problem ──────────────

#[tokio::test]
async fn uncapped_discover_advertises_every_known_revision_statelessly() {
    // rmcp's default, and the shape of the problem: nobody chose to serve
    // 2026-07-28, yet `server/discover` puts it on offer.
    for policy in [ProtocolLifecyclePolicy::Hybrid, ProtocolLifecyclePolicy::Strict] {
        let addr = start(policy, None).await;
        let result = handshake(addr, "server/discover", MODERN).await;
        assert_eq!(result.status, 200, "{policy:?}");
        assert_eq!(
            result.advertised.as_deref(),
            Some(ALL_REVISIONS.map(str::to_owned).as_slice()),
            "{policy:?}"
        );
        assert!(!result.session, "{policy:?}: discover must stay sessionless");
    }
}

// ── Capped: what the ceiling actually changes ─────────────────────────────

#[tokio::test]
async fn capped_discover_is_refused_with_the_supported_list() {
    // The load-bearing case. A client asking for a revision above the ceiling
    // gets `-32022` carrying what *is* on offer, and retries against it — which
    // is how a modern client is steered onto the legacy lifecycle without the
    // server having to guess anything about it.
    for policy in [ProtocolLifecyclePolicy::Hybrid, ProtocolLifecyclePolicy::Strict] {
        let addr = start(policy, Some(ProtocolVersion::V_2025_11_25)).await;
        let result = handshake(addr, "server/discover", MODERN).await;
        assert_eq!(result.status, 400, "{policy:?}");
        assert_eq!(result.error_code, Some(-32022), "{policy:?}");
        assert_eq!(
            result.supported.as_deref(),
            Some(UP_TO_LEGACY.map(str::to_owned).as_slice()),
            "{policy:?}: the advertised set must stop at the ceiling"
        );
    }
}

#[tokio::test]
async fn capped_discover_advertises_only_what_is_on_offer() {
    // `DiscoverResult::supported_versions` is what a client reads to pick a
    // revision, and rmcp's default builds it from the *inner* handler — so this
    // is the assertion that catches the ceiling being applied to the refusal
    // check but not to the advertised list.
    let addr = start(ProtocolLifecyclePolicy::Strict, Some(ProtocolVersion::V_2025_11_25)).await;
    let result = handshake(addr, "server/discover", LEGACY).await;
    assert_eq!(result.status, 200);
    assert_eq!(
        result.advertised.as_deref(),
        Some(UP_TO_LEGACY.map(str::to_owned).as_slice())
    );
    assert!(!result.session);
}

#[tokio::test]
async fn the_ceiling_never_refuses_a_revision_at_or_below_it() {
    let addr = start(ProtocolLifecyclePolicy::Hybrid, Some(ProtocolVersion::V_2025_11_25)).await;
    for version in ["2024-11-05", "2025-03-26", "2025-06-18", LEGACY] {
        let result = handshake(addr, "initialize", version).await;
        assert_eq!(result.status, 200, "{version}");
        assert_eq!(result.negotiated.as_deref(), Some(version), "{version}");
    }
}

// ── Where the ceiling does NOT bite ───────────────────────────────────────

#[tokio::test]
async fn hybrid_rewrites_a_modern_initialize_before_the_ceiling_is_consulted() {
    // `normalize_protocol_lifecycle` runs as middleware, ahead of rmcp, so the
    // request rmcp sees already says 2025-11-25 — capped or not, the answer is
    // identical. Documented so the ceiling is not credited with this downgrade.
    for cap in [None, Some(ProtocolVersion::V_2025_11_25)] {
        let addr = start(ProtocolLifecyclePolicy::Hybrid, cap.clone()).await;
        let result = handshake(addr, "initialize", MODERN).await;
        assert_eq!(result.status, 200, "cap={cap:?}");
        assert_eq!(result.negotiated.as_deref(), Some(LEGACY), "cap={cap:?}");
        assert!(result.session, "cap={cap:?}: Hybrid creates a session");
    }
}

#[tokio::test]
async fn strict_initialize_ignores_the_ceiling_upstream_bug() {
    // **rmcp 3.1.4 bug.** `server/discover` honours `supported_protocol_versions`
    // (see `capped_discover_is_refused_with_the_supported_list`) but the
    // `initialize` route does not: it answers 200 and echoes a revision the
    // server never advertised.
    //
    // Pinned rather than worked around, because the framework has no business
    // second-guessing rmcp's routing — and because this assertion will fail the
    // day the upstream fix lands, which is exactly when this note should be
    // revisited. Harmless in practice: the clients that reach `initialize` with
    // a modern version are legacy-lifecycle clients that Hybrid already repairs.
    let addr = start(ProtocolLifecyclePolicy::Strict, Some(ProtocolVersion::V_2025_11_25)).await;
    let result = handshake(addr, "initialize", MODERN).await;
    assert_eq!(result.status, 200);
    assert_eq!(
        result.negotiated.as_deref(),
        Some(MODERN),
        "if this now says {LEGACY}, rmcp fixed the initialize route — drop this test"
    );
}

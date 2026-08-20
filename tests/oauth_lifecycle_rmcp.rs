//! End-to-end OAuth lifecycle harness: a real Keycloak, the framework in
//! [`TokenMode::ResourceServer`], and the *real* rmcp client auth state machine
//! ([`OAuthState`] → [`AuthClient`] → [`StreamableHttpClientTransport`]).
//!
//! What this covers that the unit tests cannot: the framework's resource-server
//! mode is defined by what it *refuses* to do — no `/oauth/token`, no stored
//! grant, no server-side refresh — so its correctness is a property of the
//! client/AS pair, not of the server alone. A mock issuer proves the JWKS math;
//! only a real authorization server proves that a client left to refresh on its
//! own keeps landing on the same `SessionStore` entry.
//!
//! Every test is `#[ignore]`d: it needs Docker. Run them with
//!
//! ```bash
//! cargo test --test oauth_lifecycle_rmcp -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! `--test-threads=1` is not optional: the tests share one Keycloak container
//! and scenario 3 revokes alice's sessions realm-wide.
//!
//! ## Shape of the fixture
//!
//! One container per test binary, behind a [`OnceCell`] holding a leaked
//! [`ContainerAsync`] — Keycloak takes 15-30 s to boot, and paying that per test
//! would make the suite unusable. The realm is `keycloak/mcp-realm.json`, the
//! file a deployment actually imports, patched at test time on exactly two
//! points (access-token lifespan, audience) so the harness tests the shipped
//! artefact rather than a parallel copy of it.
//!
//! Each test starts its *own* framework instance (fresh `SessionStore`, fresh
//! `InMemoryBackend`) against that shared Keycloak, so assertions about stored
//! state are not polluted by a neighbouring test.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use mcp_framework::auth::{AuthProvider, OAuthConfig, TokenMode, UnknownTokenValidation};
use mcp_framework::constants::{JWKS_CLOCK_SKEW_LEEWAY, NS_TOKENS};
use mcp_framework::prelude::*;
use mcp_framework::session::SessionStore;
use mcp_framework::transport::{HttpAppConfig, build_app};
use rmcp::model::{CallToolRequestParams, ProtocolVersion};
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::auth::{AuthError, AuthorizationRequest, OAuthState};
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::{ClientLifecycleMode, ClientServiceExt, ServiceExt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use testcontainers::core::{ContainerPort, Mount};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use tokio::sync::OnceCell;

// ── Fixture constants ───────────────────────────────────────────────

const KEYCLOAK_IMAGE: &str = "quay.io/keycloak/keycloak";
const KEYCLOAK_TAG: &str = "26.3";
const REALM: &str = "mcp";
const CLIENT_ID: &str = "mcp-client";
const ADMIN_USER: &str = "admin";
const ADMIN_PASSWORD: &str = "admin";

/// The audience the realm's mapper injects and the framework demands.
///
/// Deliberately *not* derived from the framework's bound URL: the container is
/// shared by every test in this binary while each test binds its own ephemeral
/// port, so an address-derived audience would need a realm re-import per test.
/// What matters for the confused-deputy check is that both sides agree on one
/// opaque string, which they do here by construction.
const AUDIENCE: &str = "https://mcp-framework.test/mcp";

/// Access-token lifespan pushed into the realm at test time (the shipped value
/// is 600 s). Short enough that "sleep past expiry" costs seconds, not minutes.
///
/// Note this is well under rmcp's 30 s `REFRESH_BUFFER_SECS`, so the client
/// refreshes ahead of *every* request. That is a feature here — it exercises
/// refresh-token rotation (`revokeRefreshToken: true`, `refreshTokenMaxReuse:
/// 0`) far harder than a realistic lifespan would — but it means expiry itself
/// is asserted separately, by replaying a stale bearer with a raw client.
const ACCESS_TOKEN_LIFESPAN_SECS: u64 = 5;

/// Never listened on. The harness scrapes the `Location` header of Keycloak's
/// 302 instead of running a callback server: an unbound loopback port keeps the
/// test from depending on port availability, and RFC 8252 loopback redirect
/// URIs are matched by Keycloak on host + path, not by anyone connecting.
const REDIRECT_URI: &str = "http://127.0.0.1:1/callback";

/// Marks every container this harness starts, so the next run can reap it.
const HARNESS_LABEL_KEY: &str = "app.mcp-framework.harness";
const HARNESS_LABEL_VALUE: &str = "oauth-lifecycle";
const HARNESS_LABEL: &str = "app.mcp-framework.harness=oauth-lifecycle";

/// A well-formed `initialize`, used by the raw probes below. It has to be
/// well-formed: an unparsable body is rejected with `422` *after* the auth
/// middleware has had its say, which would make "not 401" indistinguishable
/// from "accepted".
const RAW_INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"raw-probe","version":"0"}}}"#;

const DOCKER_HINT: &str = "Docker unavailable — skipping (this test needs a Keycloak container)";

// ── Keycloak fixture ────────────────────────────────────────────────

struct Keycloak {
    base_url: String,
    _container: ContainerAsync<GenericImage>,
}

impl Keycloak {
    fn issuer(&self) -> String {
        format!("{}/realms/{REALM}", self.base_url)
    }
}

static KEYCLOAK: OnceCell<Option<&'static Keycloak>> = OnceCell::const_new();

/// The shared container, or `None` when Docker is not reachable.
async fn keycloak() -> Option<&'static Keycloak> {
    *KEYCLOAK
        .get_or_init(|| async {
            if !docker_is_available() {
                eprintln!("{DOCKER_HINT}");
                return None;
            }
            // Docker answers, so a failure from here on is a real failure —
            // swallowing it as "skipped" would turn a broken realm into a
            // green suite.
            let keycloak = start_keycloak()
                .await
                .expect("Docker is available but Keycloak did not start");
            Some(&*Box::leak(Box::new(keycloak)))
        })
        .await
}

/// Remove any container this harness left behind on a previous run.
///
/// testcontainers 0.27 ships no reaper: a container is removed by
/// `ContainerAsync::drop`, and this fixture is a `static`, which Rust never
/// drops — the container therefore outlives the test binary. Rather than pay a
/// fresh 30 s boot per test to get a droppable local, every container is
/// labelled and each run sweeps the previous one's. Steady state is one stray
/// Keycloak between runs, and `docker rm -f -l` on the label cleans it by hand.
fn sweep_leaked_containers() {
    let listed = std::process::Command::new("docker")
        .args(["ps", "-aq", "--filter", &format!("label={HARNESS_LABEL}")])
        .output();
    let Ok(listed) = listed else { return };
    for id in String::from_utf8_lossy(&listed.stdout).split_whitespace() {
        let _ = std::process::Command::new("docker")
            .args(["rm", "-f", id])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

/// Whether the Docker daemon answers at all. The only condition under which
/// these tests skip rather than fail.
fn docker_is_available() -> bool {
    std::process::Command::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Write the patched realm somewhere the container can bind-mount it.
///
/// A directory, not the file itself: bind-mounting a single file is the one
/// case Docker Desktop's file sharing handles inconsistently across platforms.
fn write_patched_realm() -> anyhow::Result<PathBuf> {
    let mut realm: Value = serde_json::from_str(include_str!("../keycloak/mcp-realm.json"))?;

    realm["accessTokenLifespan"] = json!(ACCESS_TOKEN_LIFESPAN_SECS);

    let scopes = realm["clientScopes"]
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("realm has no clientScopes array"))?;
    let audience_scope = scopes
        .iter_mut()
        .find(|scope| scope["name"] == "mcp-audience")
        .ok_or_else(|| anyhow::anyhow!("realm has no `mcp-audience` client scope"))?;
    let mappers = audience_scope["protocolMappers"]
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("`mcp-audience` has no protocolMappers"))?;
    anyhow::ensure!(!mappers.is_empty(), "`mcp-audience` has no audience mapper");
    for mapper in mappers {
        mapper["config"]["included.custom.audience"] = json!(AUDIENCE);
    }

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("mcp-framework-realm-{nanos}"));
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        dir.join("mcp-realm.json"),
        serde_json::to_vec_pretty(&realm)?,
    )?;
    Ok(dir)
}

async fn start_keycloak() -> anyhow::Result<Keycloak> {
    sweep_leaked_containers();
    let realm_dir = write_patched_realm()?;
    let realm_dir = realm_dir
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("realm directory path is not UTF-8"))?
        .to_string();

    let container = GenericImage::new(KEYCLOAK_IMAGE, KEYCLOAK_TAG)
        .with_exposed_port(ContainerPort::Tcp(8080))
        // No log-based readiness condition on purpose. Quarkus writes
        // "Listening on: ..." to *stderr*, and that line only says the socket
        // is open — the realm import completes separately. `await_realm` polls
        // the realm's own discovery document instead, which is the one signal
        // that means what the tests need it to mean.
        .with_cmd(["start-dev", "--import-realm", "--http-port", "8080"])
        .with_env_var("KC_BOOTSTRAP_ADMIN_USERNAME", ADMIN_USER)
        .with_env_var("KC_BOOTSTRAP_ADMIN_PASSWORD", ADMIN_PASSWORD)
        .with_env_var("KC_HEALTH_ENABLED", "true")
        .with_env_var("KC_HOSTNAME_STRICT", "false")
        .with_mount(Mount::bind_mount(realm_dir, "/opt/keycloak/data/import"))
        .with_label(HARNESS_LABEL_KEY, HARNESS_LABEL_VALUE)
        .with_startup_timeout(Duration::from_secs(300))
        .start()
        .await?;

    let port = container
        .get_host_port_ipv4(ContainerPort::Tcp(8080))
        .await?;
    let keycloak = Keycloak {
        base_url: format!("http://127.0.0.1:{port}"),
        _container: container,
    };
    await_realm(&keycloak).await?;
    Ok(keycloak)
}

/// Poll the realm's discovery document — the only signal that says the *import*
/// landed, as opposed to the server having merely opened a socket.
async fn await_realm(keycloak: &Keycloak) -> anyhow::Result<()> {
    let url = format!("{}/.well-known/openid-configuration", keycloak.issuer());
    let http = reqwest13::Client::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(300);
    let mut last = String::from("never attempted");
    while std::time::Instant::now() < deadline {
        match http.get(&url).send().await {
            Ok(response) if response.status().is_success() => {
                let metadata: Value = response.json().await?;
                anyhow::ensure!(
                    metadata["issuer"] == json!(keycloak.issuer()),
                    "realm issuer is {:?}, expected {:?} — KC_HOSTNAME is wrong",
                    metadata["issuer"],
                    keycloak.issuer(),
                );
                return Ok(());
            }
            Ok(response) => last = format!("HTTP {}", response.status()),
            Err(error) => last = error.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    anyhow::bail!("realm `{REALM}` never became available ({last})")
}

// ── The framework under test ────────────────────────────────────────

/// Per-session application data. Deliberately a *counter*: it is the cheapest
/// assertion that two calls landed on the same `SessionStore` entry, which is
/// the whole point of a stable claims-derived identity.
#[derive(Clone, Default, Serialize, Deserialize)]
struct TestData {
    calls: u32,
}

#[derive(Clone)]
struct TestServer;

impl ServerHandler for TestServer {}

struct Framework {
    addr: SocketAddr,
    sessions: SessionStore<TestData>,
    backend: Arc<InMemoryBackend>,
}

impl Framework {
    fn mcp_url(&self) -> String {
        format!("http://{}/mcp", self.addr)
    }

    /// Keys the framework wrote into the token namespace. Resource-server mode
    /// keeps no grant, so this must stay empty for the whole run.
    async fn stored_token_keys(&self) -> Vec<String> {
        self.backend
            .keys(NS_TOKENS)
            .await
            .expect("the in-memory backend cannot fail")
    }
}

fn resource_server_auth(issuer_url: String) -> AuthProvider {
    AuthProvider::OAuth(OAuthConfig {
        client_id: CLIENT_ID.to_string(),
        client_secret: None,
        issuer_url,
        redirect_url: REDIRECT_URI.to_string(),
        scopes: vec!["openid".to_string()],
        token_mode: TokenMode::ResourceServer,
        unknown_token_validation: UnknownTokenValidation::Jwks,
        expected_audiences: vec![AUDIENCE.to_string()],
    })
}

async fn start_framework(issuer_url: String) -> anyhow::Result<Framework> {
    // Bind first: `public_url` has to be the address the client actually
    // reaches, because it is what the `WWW-Authenticate` challenge points at
    // for RFC 9728 discovery.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let sessions: SessionStore<TestData> = SessionStore::new(Duration::from_secs(600));
    let backend = Arc::new(InMemoryBackend::new());
    let registry = CapabilityRegistry::new();

    let tool_sessions = sessions.clone();
    registry
        .add_tool_with_context(
            Tool::new(
                "whoami",
                "Report the caller's framework session identity and how many times \
                 this session has called the tool.",
                serde_json::Map::new(),
            ),
            move |_args, ctx: ToolCallContext| {
                let sessions = tool_sessions.clone();
                async move {
                    let data = sessions
                        .update(&ctx.session_id, |data| data.calls += 1)
                        .await;
                    let payload = json!({ "session_id": ctx.session_id, "calls": data.calls });
                    Ok(CallToolResult::success(vec![ContentBlock::text(
                        payload.to_string(),
                    )]))
                }
            },
        )
        .await;

    let config: HttpAppConfig<_, TestData> = HttpAppConfig {
        public_url: format!("http://{addr}"),
        bind_addr: addr.to_string(),
        auth: resource_server_auth(issuer_url),
        server_factory: || TestServer,
        app_name: "oauth-lifecycle-harness".to_string(),
        capability_registry: Some(registry),
        capability_filter: None,
        access_validator: None,
        claims_decoder: None,
        session_store: sessions.clone(),
        tool_call_logger: None,
        persistence: Some(backend.clone()),
        protocol_lifecycle: ProtocolLifecyclePolicy::Hybrid,
        extra_routes: None,
        public_routes: None,
    };

    let (app, _token_store, _registry) = build_app(config)?;
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    Ok(Framework {
        addr,
        sessions,
        backend,
    })
}

// ── Driving the OAuth flow the way a real client does ───────────────

/// The `WWW-Authenticate` challenge the framework answers an anonymous MCP
/// request with. This is the *reactive* discovery entry point: the client
/// learns where to authenticate from the 401, not from configuration.
async fn discovery_challenge(mcp_url: &str) -> anyhow::Result<String> {
    let response = reqwest13::Client::new()
        .post(mcp_url)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(RAW_INITIALIZE)
        .send()
        .await?;
    anyhow::ensure!(
        response.status() == reqwest13::StatusCode::UNAUTHORIZED,
        "unauthenticated MCP request answered {} — expected 401",
        response.status()
    );
    let challenge = response
        .headers()
        .get(reqwest13::header::WWW_AUTHENTICATE)
        .ok_or_else(|| anyhow::anyhow!("401 carried no WWW-Authenticate challenge"))?
        .to_str()?
        .to_string();
    anyhow::ensure!(
        challenge.contains("resource_metadata"),
        "challenge does not advertise protected-resource metadata: {challenge}"
    );
    Ok(challenge)
}

/// Post Keycloak's login form and return the `Location` of the resulting 302.
///
/// Cookies are handled by hand rather than with reqwest's cookie store: under
/// `sslRequired: none` Keycloak still marks `AUTH_SESSION_ID` and friends
/// `Secure; SameSite=None`, so a spec-compliant jar correctly refuses to send
/// them back over plain HTTP and the POST fails with `cookie_not_found`.
async fn keycloak_login(auth_url: &str, username: &str, password: &str) -> anyhow::Result<String> {
    let http = reqwest13::Client::builder()
        .redirect(reqwest13::redirect::Policy::none())
        .build()?;

    let response = http.get(auth_url).send().await?;
    anyhow::ensure!(
        response.status().is_success(),
        "authorization endpoint answered {}",
        response.status()
    );
    let cookies = response
        .headers()
        .get_all(reqwest13::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|cookie| cookie.split(';').next())
        .collect::<Vec<_>>()
        .join("; ");
    let body = response.text().await?;

    let form_action = regex::Regex::new(r#"id="kc-form-login"[^>]*action="([^"]+)""#)
        .expect("static regex")
        .captures(&body)
        .ok_or_else(|| anyhow::anyhow!("no Keycloak login form in the response"))?[1]
        .replace("&amp;", "&");

    let response = http
        .post(&form_action)
        .header(reqwest13::header::COOKIE, cookies)
        .form(&[
            ("username", username),
            ("password", password),
            ("credentialId", ""),
        ])
        .send()
        .await?;

    let status = response.status();
    let location = response
        .headers()
        .get(reqwest13::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    match location {
        Some(location) if status.is_redirection() => Ok(location),
        _ => anyhow::bail!(
            "login did not redirect (HTTP {status}); Keycloak said: {}",
            response.text().await.unwrap_or_default().replace('\n', " ")
        ),
    }
}

/// The whole client-side authorization code + PKCE flow, driven by rmcp's own
/// state machine — discovery from the challenge, authorization URL, callback,
/// token exchange — with only the human at the login form replaced.
async fn authorize(mcp_url: &str, username: &str, password: &str) -> anyhow::Result<AuthClient> {
    let challenge = discovery_challenge(mcp_url).await?;

    let mut state = OAuthState::new(mcp_url, None).await?;
    state
        .start_authorization(
            AuthorizationRequest::new(REDIRECT_URI)
                .with_preregistered_client(CLIENT_ID)
                .with_scopes(["openid"])
                .with_challenge(challenge),
        )
        .await?;

    let auth_url = state.get_authorization_url().await?;
    let location = keycloak_login(&auth_url, username, password).await?;
    // Also validates the RFC 9207 `iss` Keycloak puts on the redirect.
    state.handle_callback_url(&location).await?;

    let manager = state
        .into_authorization_manager()
        .ok_or_else(|| anyhow::anyhow!("authorization did not reach the authorized state"))?;
    Ok(AuthClient::new(reqwest13::Client::default(), manager))
}

// ── Talking MCP ─────────────────────────────────────────────────────

type AuthClient = rmcp::transport::auth::AuthClient<reqwest13::Client>;
type Client = rmcp::service::RunningService<rmcp::RoleClient, ()>;

/// Which protocol revision the client negotiates — which decides *where the
/// framework's session identity comes from*, and so what these tests may
/// assert.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Lifecycle {
    /// Whatever rmcp negotiates by default: MCP 2025-11-25, with a protocol
    /// session. The framework identity **is** the `mcp-session-id`, so it is
    /// scoped to the connection: a new `initialize` is a new identity even for
    /// the same principal.
    LegacySession,
    /// MCP 2026-07-28: no protocol session at all, so identity comes from the
    /// credential's claims (`cred-sid-…`). It survives both a token refresh and
    /// a reconnection, because neither changes the SSO session.
    Sessionless,
}

impl Lifecycle {
    /// Whether re-`initialize`-ing with the same grant lands on the same
    /// framework identity. This is the substantive difference between the two
    /// revisions, and the reason scenario 2 is parameterised over them.
    fn identity_survives_reconnect(self) -> bool {
        matches!(self, Lifecycle::Sessionless)
    }
}

async fn connect(auth: &AuthClient, mcp_url: &str, lifecycle: Lifecycle) -> anyhow::Result<Client> {
    let transport = StreamableHttpClientTransport::with_client(
        auth.clone(),
        StreamableHttpClientTransportConfig::with_uri(mcp_url.to_string()),
    );
    let client = match lifecycle {
        Lifecycle::LegacySession => ().serve(transport).await?,
        Lifecycle::Sessionless => {
            ().serve_with_lifecycle(
                transport,
                ClientLifecycleMode::Discover {
                    preferred_versions: vec![ProtocolVersion::V_2026_07_28],
                },
            )
            .await?
        }
    };
    Ok(client)
}

/// Call `whoami` and return `(session identity, call count)`.
async fn whoami(client: &Client) -> anyhow::Result<(String, u32)> {
    let result = client
        .call_tool(CallToolRequestParams::new("whoami"))
        .await?;
    let text = result
        .content
        .iter()
        .find_map(|block| block.as_text().map(|text| text.text.clone()))
        .ok_or_else(|| anyhow::anyhow!("whoami returned no text content"))?;
    let payload: Value = serde_json::from_str(&text)?;
    Ok((
        payload["session_id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("whoami returned no session_id"))?
            .to_string(),
        payload["calls"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("whoami returned no call count"))? as u32,
    ))
}

/// Replay a bearer with a bare HTTP client, bypassing rmcp's refresh. Used to
/// prove a token really did expire rather than merely being refreshed early.
async fn raw_mcp_status(mcp_url: &str, bearer: &str) -> anyhow::Result<reqwest13::StatusCode> {
    let response = reqwest13::Client::new()
        .post(mcp_url)
        .bearer_auth(bearer)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(RAW_INITIALIZE)
        .send()
        .await?;
    Ok(response.status())
}

// ── Keycloak admin REST ─────────────────────────────────────────────

async fn admin_token(keycloak: &Keycloak) -> anyhow::Result<String> {
    let response: Value = reqwest13::Client::new()
        .post(format!(
            "{}/realms/master/protocol/openid-connect/token",
            keycloak.base_url
        ))
        .form(&[
            ("client_id", "admin-cli"),
            ("grant_type", "password"),
            ("username", ADMIN_USER),
            ("password", ADMIN_PASSWORD),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(response["access_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("admin token response carried no access_token"))?
        .to_string())
}

/// Revoke everything `username` holds: the online SSO session *and* the offline
/// grant.
///
/// Both are needed, and the second is the non-obvious one.
/// `AuthorizationSession::new` calls `add_offline_access_if_supported`, which
/// appends `offline_access` whenever the authorization server advertises it —
/// and Keycloak's discovery document does. The resulting refresh token is
/// `typ: Offline`, has no `exp`, and **survives a user logout**: verified
/// against Keycloak 26.3, a logout alone leaves the refresh working with the
/// same `sid`. Deleting the client consent drops the offline session with it,
/// which is what actually makes the grant unusable (`invalid_grant`,
/// "Offline user session not found").
async fn revoke_user_sessions(keycloak: &Keycloak, username: &str) -> anyhow::Result<()> {
    let http = reqwest13::Client::new();
    let token = admin_token(keycloak).await?;

    let users: Value = http
        .get(format!(
            "{}/admin/realms/{REALM}/users?username={username}&exact=true",
            keycloak.base_url
        ))
        .bearer_auth(&token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let user_id = users
        .get(0)
        .and_then(|user| user["id"].as_str())
        .ok_or_else(|| anyhow::anyhow!("no user `{username}` in realm `{REALM}`"))?;

    http.post(format!(
        "{}/admin/realms/{REALM}/users/{user_id}/logout",
        keycloak.base_url
    ))
    .bearer_auth(&token)
    .send()
    .await?
    .error_for_status()?;

    http.delete(format!(
        "{}/admin/realms/{REALM}/users/{user_id}/consents/{CLIENT_ID}",
        keycloak.base_url
    ))
    .bearer_auth(&token)
    .send()
    .await?
    .error_for_status()?;

    Ok(())
}

// ── Test plumbing ───────────────────────────────────────────────────

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mcp_framework=debug,rmcp=info".into()),
        )
        .with_test_writer()
        .try_init();
}

/// Sleep past the access token's lifetime, with a margin for clock skew between
/// the host and the container.
async fn sleep_past_expiry() {
    tokio::time::sleep(Duration::from_secs(ACCESS_TOKEN_LIFESPAN_SECS + 3)).await;
}

/// Boilerplate every scenario shares: skip without Docker, boot a fresh
/// framework, run the body.
macro_rules! scenario {
    (|$kc:ident, $fw:ident| $body:block) => {{
        init_tracing();
        let Some($kc) = keycloak().await else {
            eprintln!("{DOCKER_HINT}");
            return Ok(());
        };
        let $fw = start_framework($kc.issuer()).await?;
        $body
    }};
}

// ── Scenario 1 — discovery, authorization, expiry, refresh ──────────

/// A client that knows nothing but the MCP URL: 401 → challenge → metadata →
/// PKCE authorization → tool call. Then the access token expires and the client
/// refreshes *on its own* — the framework holds no grant to refresh — and the
/// session data survives it.
async fn scenario_discovery_and_refresh(lifecycle: Lifecycle) -> anyhow::Result<()> {
    scenario!(|keycloak, framework| {
        let mcp_url = framework.mcp_url();
        let auth = authorize(&mcp_url, "alice", "alice").await?;
        let client = connect(&auth, &mcp_url, lifecycle).await?;

        let (session, calls) = whoami(&client).await?;
        assert_eq!(calls, 1, "first call on a fresh session");
        assert!(
            !session.is_empty() && session != "default",
            "{lifecycle:?}: session identity collapsed onto the fallback: {session:?}",
        );
        if lifecycle == Lifecycle::Sessionless {
            assert!(
                session.starts_with("cred-"),
                "a sessionless client must be identified from its credential's claims, got {session:?}",
            );
        }

        // The bearer in flight right now, and proof the framework takes it.
        let before = auth.get_access_token().await?;
        assert_eq!(
            raw_mcp_status(&mcp_url, &before).await?,
            reqwest13::StatusCode::OK,
            "a fresh bearer should be accepted",
        );

        sleep_past_expiry().await;

        // Same client, same manager: rmcp refreshes transparently.
        let (session_after, calls_after) = whoami(&client).await?;
        assert_eq!(
            session_after, session,
            "{lifecycle:?}: identity changed across a token refresh — session state was orphaned",
        );
        assert_eq!(calls_after, 2, "session data did not survive the refresh");

        // The call really did travel on new credentials — the client refreshed
        // rather than replaying a token the framework happened to still accept.
        // (That the *framework* eventually refuses the old one is a separate,
        // slower assertion: see `expired_bearer_is_refused_once_the_skew_leeway_passes`.)
        assert_ne!(
            auth.get_access_token().await?,
            before,
            "the access token never rotated — no refresh took place",
        );

        assert!(
            framework.stored_token_keys().await.is_empty(),
            "resource-server mode stored a token: {:?}",
            framework.stored_token_keys().await,
        );
        assert_eq!(framework.sessions.len().await, 1, "one caller, one session");

        let _ = keycloak;
        client.cancel().await?;
        Ok(())
    })
}

#[tokio::test]
#[ignore = "needs Docker (Keycloak testcontainer); run with --ignored"]
async fn lifecycle_discovery_auth_and_refresh_legacy_session() -> anyhow::Result<()> {
    scenario_discovery_and_refresh(Lifecycle::LegacySession).await
}

/// The same scenario for MCP 2026-07-28, where there is no `mcp-session-id` at
/// all and the framework must derive identity from the JWT's `sid`. This is the
/// case that silently collapsed every user onto `"default"` before task 920.
#[tokio::test]
#[ignore = "needs Docker (Keycloak testcontainer); run with --ignored"]
async fn lifecycle_discovery_auth_and_refresh_sessionless() -> anyhow::Result<()> {
    scenario_discovery_and_refresh(Lifecycle::Sessionless).await
}

// ── Scenario 2 — session loss and repeated refresh ──────────────────

/// The transport session dies — the client `DELETE`s it, which is what an
/// expired or evicted server-side session presents as — and the client
/// reconnects with the same grant. Then two consecutive refresh cycles, the
/// pair that catches a client reusing a refresh token the AS has rotated away
/// (`revokeRefreshToken: true`, `refreshTokenMaxReuse: 0`).
///
/// What the reconnection means depends on the negotiated revision, and the
/// difference is the point of parameterising this:
///
/// - **2026-07-28** — identity is derived from the credential's `sid`, so the
///   reconnection lands on the *same* `SessionStore` entry and its counter
///   keeps going up. This is what makes a long-lived MCP client survive its own
///   reconnections without losing per-user state.
/// - **2025-11-25** — identity *is* the `mcp-session-id`, so a new `initialize`
///   is a new identity by construction and the counter restarts. Not a defect:
///   the protocol session is the unit of identity when the protocol has one.
///   Asserted rather than glossed over, because it is the thing a consumer
///   keying state off `ctx.session_id` has to know.
async fn scenario_session_loss(lifecycle: Lifecycle) -> anyhow::Result<()> {
    scenario!(|keycloak, framework| {
        let mcp_url = framework.mcp_url();
        let auth = authorize(&mcp_url, "alice", "alice").await?;

        let client = connect(&auth, &mcp_url, lifecycle).await?;
        let (session, calls) = whoami(&client).await?;
        assert_eq!(calls, 1);

        // Ends the rmcp session server-side.
        client.cancel().await?;

        // Fresh transport, fresh `initialize`, same credential.
        let client = connect(&auth, &mcp_url, lifecycle).await?;
        let (session_again, mut calls_expected) = whoami(&client).await?;

        if lifecycle.identity_survives_reconnect() {
            assert_eq!(
                session_again, session,
                "{lifecycle:?}: re-initializing with the same bearer produced a different identity",
            );
            assert_eq!(
                calls_expected, 2,
                "session data was lost on re-initialization"
            );
        } else {
            assert_ne!(
                session_again, session,
                "{lifecycle:?}: a new protocol session must be a new identity",
            );
            assert_eq!(calls_expected, 1, "the new protocol session started fresh");
        }

        // Two consecutive refresh cycles, on whichever identity we now hold.
        for cycle in 1..=2 {
            sleep_past_expiry().await;
            let (session_now, calls_now) = whoami(&client).await?;
            calls_expected += 1;
            assert_eq!(
                session_now, session_again,
                "{lifecycle:?}: identity drifted on refresh cycle {cycle}",
            );
            assert_eq!(
                calls_now, calls_expected,
                "{lifecycle:?}: session data lost on refresh cycle {cycle}",
            );
        }

        assert!(
            framework.stored_token_keys().await.is_empty(),
            "resource-server mode stored a token: {:?}",
            framework.stored_token_keys().await,
        );

        let _ = keycloak;
        client.cancel().await?;
        Ok(())
    })
}

/// The case the ticket is really about: a sessionless client keeps its identity
/// across a reconnection, because the identity is the credential's.
#[tokio::test]
#[ignore = "needs Docker (Keycloak testcontainer); run with --ignored"]
async fn lifecycle_session_loss_then_reinitialize_sessionless() -> anyhow::Result<()> {
    scenario_session_loss(Lifecycle::Sessionless).await
}

/// The contrasting case, pinned down so the difference cannot regress silently.
#[tokio::test]
#[ignore = "needs Docker (Keycloak testcontainer); run with --ignored"]
async fn lifecycle_session_loss_then_reinitialize_legacy_session() -> anyhow::Result<()> {
    scenario_session_loss(Lifecycle::LegacySession).await
}

// ── Scenario 3 — revocation ─────────────────────────────────────────

/// The authorization server revokes the grant out from under the client. The
/// framework cannot know — it validates signatures locally and holds no state —
/// so what has to work is the *client* side: refresh fails, rmcp surfaces
/// [`AuthError::AuthorizationRequired`], and a fresh authorization recovers.
///
/// The recovered identity is deliberately **different**: revocation ends the
/// SSO session, a new login mints a new `sid`, and `credential_session_key`
/// derives identity from `sid`. Same human, new session — that is the design of
/// task 920, not a bug, and asserting it pins the behaviour down.
#[tokio::test]
#[ignore = "needs Docker (Keycloak testcontainer); run with --ignored"]
async fn lifecycle_revoked_grant_requires_reauthorization() -> anyhow::Result<()> {
    scenario!(|keycloak, framework| {
        let mcp_url = framework.mcp_url();
        let auth = authorize(&mcp_url, "alice", "alice").await?;
        let client = connect(&auth, &mcp_url, Lifecycle::LegacySession).await?;

        let (session, calls) = whoami(&client).await?;
        assert_eq!(calls, 1);

        revoke_user_sessions(keycloak, "alice").await?;
        sleep_past_expiry().await;

        assert!(
            whoami(&client).await.is_err(),
            "a tool call succeeded after the grant was revoked",
        );
        assert!(
            matches!(
                auth.get_access_token().await,
                Err(AuthError::AuthorizationRequired)
            ),
            "a revoked grant must surface as AuthorizationRequired",
        );
        let _ = client.cancel().await;

        // Full re-authorization, from a brand new state machine.
        let auth = authorize(&mcp_url, "alice", "alice").await?;
        let client = connect(&auth, &mcp_url, Lifecycle::LegacySession).await?;
        let (new_session, new_calls) = whoami(&client).await?;

        assert_ne!(
            new_session, session,
            "a new SSO session must yield a new framework identity",
        );
        assert_eq!(new_calls, 1, "the new identity started from fresh state");

        assert!(
            framework.stored_token_keys().await.is_empty(),
            "resource-server mode stored a token: {:?}",
            framework.stored_token_keys().await,
        );

        client.cancel().await?;
        Ok(())
    })
}

// ── Guard: expiry actually bites ────────────────────────────────────

/// The framework refuses an expired bearer — eventually.
///
/// Split out from scenario 1 because of the wait it forces. JWKS validation
/// allows [`JWKS_CLOCK_SKEW_LEEWAY`] past `exp` (the host and the container do
/// not share a clock), so "expired" and "refused" are 30 s apart. Scenario 1
/// cannot afford that on every run, but the property is worth pinning once:
/// without it, "the client refreshed" and "the old token still worked" are
/// indistinguishable.
#[tokio::test]
#[ignore = "needs Docker (Keycloak testcontainer); run with --ignored"]
async fn expired_bearer_is_refused_once_the_skew_leeway_passes() -> anyhow::Result<()> {
    scenario!(|keycloak, framework| {
        let _ = keycloak;
        let mcp_url = framework.mcp_url();
        let auth = authorize(&mcp_url, "bob", "bob").await?;
        let bearer = auth.get_access_token().await?;

        assert_eq!(
            raw_mcp_status(&mcp_url, &bearer).await?,
            reqwest13::StatusCode::OK,
            "a fresh bearer should be accepted",
        );

        tokio::time::sleep(
            Duration::from_secs(ACCESS_TOKEN_LIFESPAN_SECS)
                + JWKS_CLOCK_SKEW_LEEWAY
                + Duration::from_secs(5),
        )
        .await;

        assert_eq!(
            raw_mcp_status(&mcp_url, &bearer).await?,
            reqwest13::StatusCode::UNAUTHORIZED,
            "the framework kept accepting a bearer well past its `exp`",
        );
        Ok(())
    })
}

// ── Guard: the mode's own preconditions ─────────────────────────────

/// The realm must actually inject the audience the framework demands. A
/// `protocolMapper` Keycloak does not recognise is accepted at import and then
/// injects nothing, which would show up as an unexplained 401 in every scenario
/// above — so it is worth one direct assertion.
#[tokio::test]
#[ignore = "needs Docker (Keycloak testcontainer); run with --ignored"]
async fn realm_injects_the_expected_audience() -> anyhow::Result<()> {
    scenario!(|keycloak, framework| {
        let mcp_url = framework.mcp_url();
        let auth = authorize(&mcp_url, "bob", "bob").await?;
        let token = auth.get_access_token().await?;

        let payload = token
            .split('.')
            .nth(1)
            .ok_or_else(|| anyhow::anyhow!("access token is not a JWT"))?;
        let decoded =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload)?;
        let claims: Value = serde_json::from_slice(&decoded)?;

        let audiences = match &claims["aud"] {
            Value::String(one) => vec![one.clone()],
            Value::Array(many) => many
                .iter()
                .filter_map(|value| value.as_str().map(str::to_string))
                .collect(),
            other => anyhow::bail!("unexpected aud claim: {other}"),
        };
        assert!(
            audiences.iter().any(|aud| aud == AUDIENCE),
            "the `mcp-audience` mapper injected {audiences:?}, expected {AUDIENCE:?}",
        );
        assert_eq!(
            claims["iss"],
            json!(keycloak.issuer()),
            "token issuer does not match the discovered issuer",
        );
        assert!(claims["sid"].is_string(), "token carries no `sid` claim");
        Ok(())
    })
}

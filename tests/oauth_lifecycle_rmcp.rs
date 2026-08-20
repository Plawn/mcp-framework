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

use mcp_framework::auth::{
    AuthProvider, OAuthConfig, TokenMode, TokenStore, UnknownTokenValidation,
};
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

/// What this deployment declares as `OAUTH_SCOPES`, and therefore what
/// discovery advertises and clients request. The two MCP-specific ones are
/// optional client scopes in the realm, so they only end up in a token if the
/// client actually asks — which is the point: a scope nobody is told about is a
/// scope nobody requests.
const SCOPES: [&str; 5] = ["openid", "profile", "email", "mcp:tools", "mcp:resources"];

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

/// The shared container, or `None` when Docker is not reachable **locally**.
///
/// On CI there is no such thing as "not reachable": the `integration-keycloak`
/// job exists to run these tests, so a missing daemon there is the job silently
/// passing without having tested anything. `CI` (set by GitHub Actions, and by
/// every other runner worth the name) turns the skip into a panic.
async fn keycloak() -> Option<&'static Keycloak> {
    *KEYCLOAK
        .get_or_init(|| async {
            if !docker_is_available() {
                assert!(
                    std::env::var_os("CI").is_none(),
                    "CI is set but the Docker daemon does not answer — these tests \
                     cannot be skipped here, they are the whole point of the job",
                );
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
///
/// The shipped realm is deliberately *not* a test fixture — it is what a
/// deployment imports, so it demands TLS and ships no users. Everything a test
/// needs that a production realm must not have is injected here instead, which
/// keeps the harness testing the shipped artefact rather than a parallel copy:
///
/// 1. `accessTokenLifespan` — 600 s shipped, seconds here.
/// 2. every audience mapper — rewritten to the audience this binary uses.
/// 3. `sslRequired` — `external` shipped; the container speaks plain HTTP.
/// 4. `users` — alice and bob, with permanent passwords equal to their names.
///
/// The DCR policies are **not** patched: `trusted-hosts` is exercised as
/// shipped, which is what makes
/// [`direct_registration_from_an_untrusted_redirect_host_is_refused`] mean
/// anything.
fn write_patched_realm() -> anyhow::Result<PathBuf> {
    let mut realm: Value = serde_json::from_str(include_str!("../keycloak/mcp-realm.json"))?;

    realm["accessTokenLifespan"] = json!(ACCESS_TOKEN_LIFESPAN_SECS);
    realm["sslRequired"] = json!("none");
    realm["users"] = json!([test_user("alice"), test_user("bob")]);

    rewrite_audience(&mut realm)?;

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

/// A test user whose password is their username. Never shipped in the realm:
/// an importable file carrying enabled accounts with permanent, guessable
/// passwords is a footgun aimed at whoever imports it into a real Keycloak.
fn test_user(name: &str) -> Value {
    json!({
        "username": name,
        "enabled": true,
        "emailVerified": true,
        "email": format!("{name}@example.com"),
        "firstName": name,
        "lastName": "Example",
        "credentials": [{ "type": "password", "value": name, "temporary": false }],
        "realmRoles": ["default-roles-mcp"],
    })
}

/// Point every `oidc-audience-mapper` in the realm at [`AUDIENCE`].
///
/// Exactly three scopes must carry one, and the test insists on all three by
/// name: `mcp-audience`, which preregistered clients get as a default scope,
/// and `mcp:tools` / `mcp:resources`, which is how a *dynamically registered*
/// client gets the audience at all — see
/// [`lifecycle_dynamic_client_registration`]. A "at least one mapper found"
/// check would pass a realm where two of the three lost theirs, and the
/// resulting failure would surface three tests later as an unexplained `401`.
fn rewrite_audience(realm: &mut Value) -> anyhow::Result<()> {
    const AUDIENCE_SCOPES: [&str; 3] = ["mcp-audience", "mcp:tools", "mcp:resources"];

    let scopes = realm["clientScopes"]
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("realm has no clientScopes array"))?;

    for expected in AUDIENCE_SCOPES {
        let scope = scopes
            .iter_mut()
            .find(|scope| scope["name"] == json!(expected))
            .ok_or_else(|| anyhow::anyhow!("realm has no `{expected}` client scope"))?;
        let mappers = scope["protocolMappers"]
            .as_array_mut()
            .ok_or_else(|| anyhow::anyhow!("client scope `{expected}` has no protocolMappers"))?;
        let mut rewritten = 0;
        for mapper in mappers {
            if mapper["protocolMapper"] == json!("oidc-audience-mapper") {
                mapper["config"]["included.custom.audience"] = json!(AUDIENCE);
                rewritten += 1;
            }
        }
        anyhow::ensure!(
            rewritten == 1,
            "client scope `{expected}` carries {rewritten} audience mappers, expected exactly 1",
        );
    }
    Ok(())
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
    tokens: TokenStore,
}

impl Framework {
    fn mcp_url(&self) -> String {
        format!("http://{}/mcp", self.addr)
    }

    fn prm_url(&self) -> String {
        format!("http://{}/.well-known/oauth-protected-resource", self.addr)
    }

    fn as_metadata_url(&self) -> String {
        format!(
            "http://{}/.well-known/oauth-authorization-server",
            self.addr
        )
    }

    fn register_url(&self) -> String {
        format!("http://{}/oauth/register", self.addr)
    }

    /// Resource-server mode keeps no grant, and this is the assertion that says
    /// so. It has to look in *both* places: the persistence backend catches a
    /// write-through, but in this mode the `TokenStore` is built without a
    /// backend at all, so an in-memory `store_token` would leave the namespace
    /// empty and slip past a backend-only check.
    ///
    /// The in-memory half is checked twice over. `token_count` is the honest
    /// one — it sees an entry under *any* key, including one keyed by something
    /// no test ever observes. `identities` then names the keys the requests
    /// actually ran under, so that the common regression (a grant stored under
    /// the caller's own identity) fails with that identity in the message
    /// rather than as a bare count.
    async fn assert_no_token_state(&self, identities: &[&str]) {
        let keys = self
            .backend
            .keys(NS_TOKENS)
            .await
            .expect("the in-memory backend cannot fail");
        assert!(
            keys.is_empty(),
            "resource-server mode persisted a token: {keys:?}",
        );
        for identity in identities {
            assert!(
                self.tokens.peek_token(identity).await.is_none(),
                "resource-server mode kept a token in memory for {identity:?}",
            );
        }
        assert_eq!(
            self.tokens.token_count().await,
            0,
            "resource-server mode kept a token in memory under a key no test observed",
        );
    }
}

fn resource_server_auth(issuer_url: String) -> AuthProvider {
    AuthProvider::OAuth(OAuthConfig {
        client_id: CLIENT_ID.to_string(),
        client_secret: None,
        issuer_url,
        redirect_url: REDIRECT_URI.to_string(),
        scopes: SCOPES.iter().map(|scope| scope.to_string()).collect(),
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

    let (app, tokens, _registry) = build_app(config)?;
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    Ok(Framework {
        addr,
        sessions,
        backend,
        tokens,
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

/// Drive Keycloak's browser flow to the redirect back to [`REDIRECT_URI`] and
/// return that `Location`.
///
/// Written as a small browser loop — follow redirects, fill in whatever form
/// the page turns out to be — because the number of steps is not fixed. A
/// preregistered `mcp-client` needs one form. A client the realm's `Consent
/// Required` registration policy marked `consentRequired` needs three steps:
/// the login form, the 302 to the `OAUTH_GRANT` required action, and the
/// consent form it renders.
///
/// Cookies are handled by hand rather than with reqwest's cookie store: under
/// `sslRequired: none` Keycloak still marks `AUTH_SESSION_ID` and friends
/// `Secure; SameSite=None`, so a spec-compliant jar correctly refuses to send
/// them back over plain HTTP and the POST fails with `cookie_not_found`.
async fn keycloak_login(auth_url: &str, username: &str, password: &str) -> anyhow::Result<String> {
    let http = reqwest13::Client::builder()
        .redirect(reqwest13::redirect::Policy::none())
        .build()?;

    let mut cookies = Cookies::default();
    let mut response = http.get(auth_url).send().await?;

    for _ in 0..8 {
        cookies.absorb(&response);

        if response.status().is_redirection() {
            let location = redirect_location(&response)
                .ok_or_else(|| anyhow::anyhow!("Keycloak redirected without a Location"))?;
            if location.starts_with(REDIRECT_URI) {
                return Ok(location);
            }
            response = http
                .get(&location)
                .header(reqwest13::header::COOKIE, cookies.header())
                .send()
                .await?;
            continue;
        }

        let status = response.status();
        anyhow::ensure!(status.is_success(), "Keycloak answered {status}");
        // A form action may be a path rather than a URL — resolve it against
        // the page it came from.
        let page = response.url().clone();
        let body = response.text().await?;

        response =
            if let Some(action) = capture(r#"id="kc-form-login"[^>]*action="([^"]+)""#, &body) {
                http.post(page.join(&action)?)
                    .header(reqwest13::header::COOKIE, cookies.header())
                    .form(&[
                        ("username", username),
                        ("password", password),
                        ("credentialId", ""),
                    ])
                    .send()
                    .await?
            } else if let Some(action) = consent_action(&body) {
                let code = capture(r#"name="code"[^>]*value="([^"]+)""#, &body)
                    .or_else(|| capture(r#"value="([^"]+)"[^>]*name="code""#, &body))
                    .ok_or_else(|| anyhow::anyhow!("consent form carries no `code`"))?;
                http.post(page.join(&action)?)
                    .header(reqwest13::header::COOKIE, cookies.header())
                    .form(&[("code", code.as_str()), ("accept", "Yes")])
                    .send()
                    .await?
            } else {
                anyhow::bail!(
                    "Keycloak rendered a page that is neither login nor consent: {}",
                    excerpt(&body)
                );
            };
    }

    anyhow::bail!("the browser flow did not reach {REDIRECT_URI} within 8 steps")
}

/// The consent form is recognised by where it posts — `login-actions/consent`
/// — not by an id: Keycloak 26's `login-oauth-grant.ftl` gives the form neither
/// an id nor a class of its own.
fn consent_action(body: &str) -> Option<String> {
    capture(
        r#"<form[^>]*action="([^"]*login-actions/consent[^"]*)""#,
        body,
    )
}

fn excerpt(body: &str) -> String {
    body.replace('\n', " ").chars().take(400).collect()
}

/// The cookies Keycloak set so far, latest value per name. A map rather than a
/// concatenation: `AUTH_SESSION_ID` and `KEYCLOAK_IDENTITY` are re-set as the
/// flow advances, and sending both the old and the new value makes Keycloak
/// pick the wrong one.
#[derive(Default)]
struct Cookies(std::collections::BTreeMap<String, String>);

impl Cookies {
    fn absorb(&mut self, response: &reqwest13::Response) {
        for cookie in collect_cookies(response) {
            if let Some((name, value)) = cookie.split_once('=') {
                self.0.insert(name.trim().to_string(), value.to_string());
            }
        }
    }

    fn header(&self) -> String {
        self.0
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

fn collect_cookies(response: &reqwest13::Response) -> Vec<String> {
    response
        .headers()
        .get_all(reqwest13::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|cookie| cookie.split(';').next())
        .map(str::to_string)
        .collect()
}

fn redirect_location(response: &reqwest13::Response) -> Option<String> {
    response
        .headers()
        .get(reqwest13::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

/// First capture group of `pattern` in `haystack`, with HTML entities undone.
/// A regex rather than an HTML parser: the two forms this has to read are
/// Keycloak's own templates, and the alternative is a parser dependency for
/// four `action` attributes.
fn capture(pattern: &str, haystack: &str) -> Option<String> {
    regex::Regex::new(pattern)
        .expect("static regex")
        .captures(haystack)
        .map(|found| found[1].replace("&amp;", "&"))
}

/// The whole client-side authorization code + PKCE flow, driven by rmcp's own
/// state machine — discovery from the challenge, authorization URL, callback,
/// token exchange — with only the human at the login form replaced.
///
/// Uses the preregistered `mcp-client`, which is what a configured deployment
/// looks like. The registration path is [`authorize_dynamically`].
async fn authorize(mcp_url: &str, username: &str, password: &str) -> anyhow::Result<AuthClient> {
    run_authorization(
        mcp_url,
        username,
        password,
        AuthorizationRequest::new(REDIRECT_URI).with_preregistered_client(CLIENT_ID),
    )
    .await
}

/// The same flow with no client identity at all, which sends rmcp down the RFC
/// 7591 branch: it reads `registration_endpoint` out of the authorization
/// server metadata — the framework's `/oauth/register` — and registers itself.
async fn authorize_dynamically(
    mcp_url: &str,
    username: &str,
    password: &str,
) -> anyhow::Result<AuthClient> {
    run_authorization(
        mcp_url,
        username,
        password,
        AuthorizationRequest::new(REDIRECT_URI).with_client_name("mcp-framework harness"),
    )
    .await
}

async fn run_authorization(
    mcp_url: &str,
    username: &str,
    password: &str,
    request: AuthorizationRequest,
) -> anyhow::Result<AuthClient> {
    let challenge = discovery_challenge(mcp_url).await?;

    let mut state = OAuthState::new(mcp_url, None).await?;
    state
        .start_authorization(request.with_scopes(SCOPES).with_challenge(challenge))
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

/// Terminate a transport session from outside the client that owns it — the
/// server-side half of "your session is gone", which is what a client hitting
/// an instance that never saw the session runs into.
async fn raw_delete_session(
    mcp_url: &str,
    bearer: &str,
    session_id: &str,
) -> anyhow::Result<reqwest13::StatusCode> {
    let response = reqwest13::Client::new()
        .delete(mcp_url)
        .bearer_auth(bearer)
        .header("mcp-session-id", session_id)
        .header("mcp-protocol-version", "2025-11-25")
        .send()
        .await?;
    Ok(response.status())
}

/// Send a request *as* an existing session, to see whether the server still
/// knows it. A live session answers `200`; a terminated one answers `404`,
/// which is the signal rmcp turns into a re-`initialize`.
async fn raw_session_probe(
    mcp_url: &str,
    bearer: &str,
    session_id: &str,
) -> anyhow::Result<reqwest13::StatusCode> {
    let response = reqwest13::Client::new()
        .post(mcp_url)
        .bearer_auth(bearer)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-session-id", session_id)
        .header("mcp-protocol-version", "2025-11-25")
        .body(r#"{"jsonrpc":"2.0","id":99,"method":"ping"}"#)
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

/// The Keycloak client record for `client_id`, straight from the admin API.
/// Used to check that a *dynamically registered* client really exists there —
/// the framework's own response would be just as happy with a fabricated id.
async fn admin_client_record(keycloak: &Keycloak, client_id: &str) -> anyhow::Result<Value> {
    let token = admin_token(keycloak).await?;
    let clients: Value = reqwest13::Client::new()
        .get(format!(
            "{}/admin/realms/{REALM}/clients?clientId={client_id}",
            keycloak.base_url
        ))
        .bearer_auth(&token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    clients
        .get(0)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("realm `{REALM}` has no client `{client_id}`"))
}

/// The names of every client scope in the realm that carries an
/// `oidc-audience-mapper` pointing at [`AUDIENCE`], read from the running
/// Keycloak rather than from the file on disk — the point being to check what
/// the import produced, not what the export said.
async fn audience_carrying_scopes(keycloak: &Keycloak) -> anyhow::Result<Vec<String>> {
    let token = admin_token(keycloak).await?;
    let scopes: Value = reqwest13::Client::new()
        .get(format!(
            "{}/admin/realms/{REALM}/client-scopes",
            keycloak.base_url
        ))
        .bearer_auth(&token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let scopes = scopes
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("admin API returned no client-scope array"))?;
    Ok(scopes
        .iter()
        .filter(|scope| {
            scope["protocolMappers"]
                .as_array()
                .is_some_and(|mappers| mappers.iter().any(is_audience_mapper))
        })
        .filter_map(|scope| scope["name"].as_str().map(str::to_string))
        .collect())
}

fn is_audience_mapper(mapper: &Value) -> bool {
    mapper["protocolMapper"] == json!("oidc-audience-mapper")
        && mapper["config"]["included.custom.audience"] == json!(AUDIENCE)
}

/// Post an RFC 7591 registration straight at Keycloak's own endpoint — the one
/// the protected-resource metadata sends a spec-current client to — and return
/// the raw response, status included.
async fn register_directly(
    keycloak: &Keycloak,
    client_name: &str,
    redirect_uris: &[&str],
) -> anyhow::Result<reqwest13::Response> {
    Ok(reqwest13::Client::new()
        .post(format!(
            "{}/clients-registrations/openid-connect",
            keycloak.issuer()
        ))
        .json(&json!({
            "client_name": client_name,
            "redirect_uris": redirect_uris,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "scope": SCOPES.join(" "),
        }))
        .send()
        .await?)
}

// ── Test plumbing ───────────────────────────────────────────────────

/// The claims of a JWT, decoded without verifying anything — these tests only
/// read what the authorization server put in the token they already hold.
fn jwt_claims(token: &str) -> anyhow::Result<Value> {
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("access token is not a JWT"))?;
    let decoded =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload)?;
    Ok(serde_json::from_slice(&decoded)?)
}

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

        framework.assert_no_token_state(&[&session]).await;
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

/// Two consecutive refresh cycles on a client that is already connected — the
/// pair that catches a client reusing a refresh token the AS has rotated away
/// (`revokeRefreshToken: true`, `refreshTokenMaxReuse: 0`). Returns the call
/// count reached.
async fn two_refresh_cycles(
    client: &Client,
    identity: &str,
    mut calls: u32,
    lifecycle: Lifecycle,
) -> anyhow::Result<u32> {
    for cycle in 1..=2 {
        sleep_past_expiry().await;
        let (session_now, calls_now) = whoami(client).await?;
        calls += 1;
        assert_eq!(
            session_now, identity,
            "{lifecycle:?}: identity drifted on refresh cycle {cycle}",
        );
        assert_eq!(
            calls_now, calls,
            "{lifecycle:?}: session data lost on refresh cycle {cycle}",
        );
    }
    Ok(calls)
}

/// The server-side transport session disappears under a *running* client.
///
/// This is the failure a horizontally scaled deployment produces constantly: an
/// instance that never saw the session answers `404`, and the question is what
/// the client does next. The harness reproduces it exactly — a side-channel
/// `DELETE /mcp` carrying the live `mcp-session-id`, which is what rmcp's server
/// treats as "this session is gone" — rather than closing the client politely
/// and building a new one, which tests the harness rather than the transport.
///
/// **rmcp 3.1.0 recovers transparently.** `StreamableHttpClientTransportConfig`
/// defaults `reinit_on_expired_session` to `true`, so on `SessionExpired` the
/// transport replays the saved `initialize`, adopts the new session id and
/// re-sends the request that failed. The caller never sees an error — asserted
/// here, because the alternative contract (surfacing `SessionExpired` and
/// making the caller reconnect) is what the code would look like if that flag
/// ever flipped.
///
/// What the framework then does is the part that matters to a consumer: the
/// re-`initialize` mints a *new* `mcp-session-id`, and on 2025-11-25 the
/// framework identity **is** that id — so the recovered call lands on a fresh
/// `SessionStore` entry and the counter restarts. Not a defect (the protocol
/// session is the unit of identity when the protocol has one), but it is
/// precisely what a consumer keying state off `ctx.session_id` has to know, and
/// it is the reason the sessionless variant below exists.
#[tokio::test]
#[ignore = "needs Docker (Keycloak testcontainer); run with --ignored"]
async fn lifecycle_session_loss_then_reinitialize_legacy_session() -> anyhow::Result<()> {
    let lifecycle = Lifecycle::LegacySession;
    scenario!(|keycloak, framework| {
        let mcp_url = framework.mcp_url();
        let auth = authorize(&mcp_url, "alice", "alice").await?;

        let client = connect(&auth, &mcp_url, lifecycle).await?;
        let (session, calls) = whoami(&client).await?;
        assert_eq!(calls, 1);

        // In this revision the framework identity *is* the transport session
        // id, which is what makes it usable as the DELETE target.
        let bearer = auth.get_access_token().await?;
        let status = raw_delete_session(&mcp_url, &bearer, &session).await?;
        assert!(
            status.is_success() || status == reqwest13::StatusCode::NO_CONTENT,
            "the server refused to terminate session {session}: HTTP {status}",
        );
        // And it really is gone: a replay of the same session id now 404s.
        assert_eq!(
            raw_session_probe(&mcp_url, &bearer, &session).await?,
            reqwest13::StatusCode::NOT_FOUND,
            "the terminated session is still being served",
        );

        // Same client object, no reconnection by us: rmcp re-initializes.
        let (session_again, calls_again) = whoami(&client).await?;
        assert_ne!(
            session_again, session,
            "rmcp reused a session the server had terminated",
        );
        assert_eq!(
            calls_again, 1,
            "a new protocol session must start from fresh state",
        );

        let calls = two_refresh_cycles(&client, &session_again, calls_again, lifecycle).await?;
        assert_eq!(calls, 3);

        framework
            .assert_no_token_state(&[&session, &session_again])
            .await;

        let _ = keycloak;
        client.cancel().await?;
        Ok(())
    })
}

/// The case the ticket is really about: with MCP 2026-07-28 there is no
/// protocol session to lose, so there is nothing to `DELETE` — every request is
/// served statelessly. Identity comes from the credential's `sid`, which means
/// a client that throws away its transport and builds a new one lands back on
/// the same `SessionStore` entry and its counter keeps going up. That is what
/// makes a long-lived MCP client survive its own reconnections without losing
/// per-user state.
#[tokio::test]
#[ignore = "needs Docker (Keycloak testcontainer); run with --ignored"]
async fn lifecycle_session_loss_then_reinitialize_sessionless() -> anyhow::Result<()> {
    let lifecycle = Lifecycle::Sessionless;
    scenario!(|keycloak, framework| {
        let mcp_url = framework.mcp_url();
        let auth = authorize(&mcp_url, "alice", "alice").await?;

        let client = connect(&auth, &mcp_url, lifecycle).await?;
        let (session, calls) = whoami(&client).await?;
        assert_eq!(calls, 1);
        assert!(
            session.starts_with("cred-"),
            "a sessionless client must be identified from its credential: {session:?}",
        );

        // Drop the whole connection and build a new one from the same grant.
        client.cancel().await?;
        let client = connect(&auth, &mcp_url, lifecycle).await?;
        let (session_again, calls_again) = whoami(&client).await?;

        assert_eq!(
            session_again, session,
            "re-initializing with the same bearer produced a different identity",
        );
        assert_eq!(calls_again, 2, "session data was lost on reconnection");

        let calls = two_refresh_cycles(&client, &session_again, calls_again, lifecycle).await?;
        assert_eq!(calls, 4);

        framework.assert_no_token_state(&[&session]).await;

        let _ = keycloak;
        client.cancel().await?;
        Ok(())
    })
}

// ── Scenario 3 — revocation ─────────────────────────────────────────

/// The authorization server revokes the grant out from under the client. The
/// framework cannot know — it validates signatures locally and holds no state —
/// so what has to work is the *client* side: refresh fails, rmcp surfaces
/// [`AuthError::AuthorizationRequired`], and a fresh authorization recovers.
///
/// Run **sessionless** on purpose. The interesting claim is that the recovered
/// identity is a *different* one, and that claim is only causal here: identity
/// is `cred-sid-{sha256(sid)}`, revocation ends the SSO session, and a new login
/// mints a new `sid`. Under 2025-11-25 the identity is the `mcp-session-id`, so
/// reconnecting would change it whether or not anything was revoked — the same
/// assertion would pass for the wrong reason. Same human, new session: that is
/// the design of task 920, and this is where it is pinned down.
#[tokio::test]
#[ignore = "needs Docker (Keycloak testcontainer); run with --ignored"]
async fn lifecycle_revoked_grant_requires_reauthorization() -> anyhow::Result<()> {
    scenario!(|keycloak, framework| {
        let mcp_url = framework.mcp_url();
        let auth = authorize(&mcp_url, "alice", "alice").await?;
        let client = connect(&auth, &mcp_url, Lifecycle::Sessionless).await?;

        let (session, calls) = whoami(&client).await?;
        assert_eq!(calls, 1);
        assert!(
            session.starts_with("cred-sid-"),
            "identity should be derived from the SSO session id, got {session:?}",
        );

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
        let client = connect(&auth, &mcp_url, Lifecycle::Sessionless).await?;
        let (new_session, new_calls) = whoami(&client).await?;

        assert!(
            new_session.starts_with("cred-sid-"),
            "identity should be derived from the SSO session id, got {new_session:?}",
        );
        assert_ne!(
            new_session, session,
            "a new SSO session must yield a new framework identity",
        );
        assert_eq!(new_calls, 1, "the new identity started from fresh state");

        framework
            .assert_no_token_state(&[&session, &new_session])
            .await;

        client.cancel().await?;
        Ok(())
    })
}

// ── Scenario 4 — dynamic client registration ────────────────────────

/// The same flow with **no client id configured anywhere on the client side**.
///
/// Every other scenario calls `with_preregistered_client`, which is the happy
/// path a deployment sets up by hand — and which walks straight past dynamic
/// registration and the realm's client registration policies. A browser-based
/// MCP client has no preregistered id, so RFC 7591 is the path it actually
/// takes.
///
/// **Where the registration lands, and why the framework still proxies one.**
/// rmcp follows RFC 9728: it reads the framework's protected-resource metadata,
/// takes the `authorization_servers` entry — which in resource-server mode is
/// *Keycloak's* issuer, not the framework — and fetches that server's metadata.
/// The `registration_endpoint` it finds there is Keycloak's own
/// `clients-registrations/openid-connect`, so a spec-current client registers
/// **directly with Keycloak** and never touches `/oauth/register`. That route
/// is nonetheless still advertised by the framework's own
/// `/.well-known/oauth-authorization-server` — the document MCP 2025-03-26
/// clients probe on the resource server — and still needed there for the reason
/// it has always existed: Keycloak's registration endpoint sends no CORS
/// headers, so a browser cannot post to it. Both halves are asserted below and
/// both paths are then exercised: rmcp's direct registration end to end, and
/// the framework's proxy by hand.
///
/// Either way it is the realm's **anonymous** registration policies that decide,
/// and this is the only test that puts them under load: `Trusted Hosts` (the
/// redirect URI has to resolve to one — [`REDIRECT_URI`] is `127.0.0.1`, which
/// the shipped realm trusts), `Allowed Client Scopes`, `Max Clients Limit`, and
/// `Consent Required` — which is why the dynamic client, unlike `mcp-client`,
/// shows a consent form that [`keycloak_login`] has to answer.
///
/// What it pins down: Keycloak really minted a client, verified through the
/// admin API by looking up the `azp` of the token that came out and checking
/// the redirect URI recorded for it, and the resulting credential then works
/// against the MCP endpoint like any other.
#[tokio::test]
#[ignore = "needs Docker (Keycloak testcontainer); run with --ignored"]
async fn lifecycle_dynamic_client_registration() -> anyhow::Result<()> {
    scenario!(|keycloak, framework| {
        let mcp_url = framework.mcp_url();

        // Which registration endpoint each kind of client is sent to.
        let prm = fetch_json(&framework.prm_url()).await?;
        let authorization_server = prm["authorization_servers"][0]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("protected-resource metadata names no AS: {prm}"))?
            .to_string();
        assert_eq!(
            authorization_server,
            keycloak.issuer(),
            "resource-server mode must point clients at Keycloak, not at itself",
        );
        let as_metadata = fetch_json(&format!(
            "{authorization_server}/.well-known/oauth-authorization-server"
        ))
        .await?;
        let keycloak_registration = as_metadata["registration_endpoint"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Keycloak advertises no registration_endpoint"))?;
        assert!(
            keycloak_registration.starts_with(&keycloak.base_url),
            "an RFC 9728 client registers with the AS itself, but the endpoint it \
             would use is {keycloak_registration:?}",
        );
        let ours = fetch_json(&framework.as_metadata_url()).await?;
        assert_eq!(
            ours["registration_endpoint"],
            json!(framework.register_url()),
            "the framework's own AS document must keep advertising its CORS-capable \
             registration proxy for MCP 2025-03-26 clients",
        );

        // 1. rmcp, all the way through: register, authorize, call a tool.
        let auth = authorize_dynamically(&mcp_url, "bob", "bob").await?;
        let bearer = auth.get_access_token().await?;
        let claims = jwt_claims(&bearer)?;

        let azp = claims["azp"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("token carries no `azp`"))?;
        assert_ne!(
            azp, CLIENT_ID,
            "the flow fell back to the preregistered client — DCR did not happen",
        );
        assert_dynamic_client(keycloak, azp).await?;

        // And the credential it produced is an ordinary working credential.
        let client = connect(&auth, &mcp_url, Lifecycle::Sessionless).await?;
        let (session, calls) = whoami(&client).await?;
        assert_eq!(calls, 1);
        framework.assert_no_token_state(&[&session]).await;
        client.cancel().await?;

        // 2. The framework's proxy, which is what a browser-based 2025-03-26
        //    client posts to. It must reach Keycloak — the handler answers 201
        //    with the *configured* client id when Keycloak refuses, so a
        //    successful-looking response proves nothing on its own.
        let proxied =
            register_through_framework(&framework, "mcp-framework harness (proxy)").await?;
        assert_ne!(
            proxied, CLIENT_ID,
            "/oauth/register returned the configured client id — that is the offline \
             fallback, so the proxy to Keycloak did not go through",
        );
        assert_dynamic_client(keycloak, &proxied).await?;
        assert_registered_scopes(keycloak, &proxied).await?;

        Ok(())
    })
}

/// The proxy forwards RFC 7591 `scope`, and the client Keycloak minted really
/// carries those scopes — with an audience among them.
///
/// Both halves matter and neither implies the other. Forwarding is what makes
/// an authorization request for `mcp:tools` succeed instead of failing
/// `invalid_scope`; but forwarding a `scope` at all is also what makes Keycloak
/// **replace** the client's default scopes, dropping `mcp-audience` with them.
/// That is the reason `mcp:tools` / `mcp:resources` carry the audience mapper
/// too, and this is where that reason is checked rather than asserted in prose:
/// whatever scopes the client ended up with, at least one of them must inject
/// [`AUDIENCE`], or the resource server would `401` every token it ever mints.
///
/// Observed against Keycloak 26.3: a registration carrying `scope` leaves the
/// client with `basic` as its only *default* scope and everything it asked for
/// as *optional* — so the check is on the union, not on `defaultClientScopes`.
/// An optional scope is one the client must request per authorization, which
/// rmcp does, which is how the audience gets in.
async fn assert_registered_scopes(keycloak: &Keycloak, client_id: &str) -> anyhow::Result<()> {
    let record = admin_client_record(keycloak, client_id).await?;
    let names = |field: &str| -> Vec<String> {
        record[field]
            .as_array()
            .map(|scopes| {
                scopes
                    .iter()
                    .filter_map(|scope| scope.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let default_scopes = names("defaultClientScopes");
    let optional_scopes = names("optionalClientScopes");
    let attached = [default_scopes.clone(), optional_scopes.clone()].concat();

    for requested in ["mcp:tools", "mcp:resources"] {
        assert!(
            attached.iter().any(|scope| scope == requested),
            "the proxy dropped the RFC 7591 `scope`: client {client_id} carries \
             default {default_scopes:?} / optional {optional_scopes:?}, none of them \
             {requested:?}",
        );
    }

    let audience_scopes = audience_carrying_scopes(keycloak).await?;
    assert!(
        attached.iter().any(|scope| audience_scopes.contains(scope)),
        "no scope attached to {client_id} injects {AUDIENCE:?} — its tokens would \
         carry no `aud` and the resource server would refuse every one of them \
         (attached {attached:?}, audience-carrying {audience_scopes:?})",
    );
    Ok(())
}

/// The `trusted-hosts` registration policy, exercised as shipped.
///
/// The shipped realm turns `host-sending-registration-request-must-match`
/// **off** and leaves `client-uris-must-match` **on**, and this is the test
/// that says the remaining half still bites: an anonymous registration asking
/// for a `redirect_uri` on a host the realm does not trust is refused (`403`,
/// "URI doesn't match any trusted host or trusted domain"). Without it, "we
/// disabled a check" and "we disabled the policy" would look the same from
/// here.
///
/// The accepted case is covered by [`lifecycle_dynamic_client_registration`],
/// which registers with [`REDIRECT_URI`] — `127.0.0.1`, a trusted host.
#[tokio::test]
#[ignore = "needs Docker (Keycloak testcontainer); run with --ignored"]
async fn direct_registration_from_an_untrusted_redirect_host_is_refused() -> anyhow::Result<()> {
    init_tracing();
    let Some(keycloak) = keycloak().await else {
        eprintln!("{DOCKER_HINT}");
        return Ok(());
    };

    let response = register_directly(
        keycloak,
        "mcp-framework harness (untrusted)",
        &["https://attacker.example.net/callback"],
    )
    .await?;

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    assert_eq!(
        status,
        reqwest13::StatusCode::FORBIDDEN,
        "Keycloak accepted a registration whose redirect URI is on an untrusted \
         host: HTTP {status} — {}",
        excerpt(&body),
    );
    // Named explicitly: a `403` from `Max Clients Limit` or `Allowed Client
    // Scopes` would prove nothing about the host list. Keycloak 26.3 answers
    // `insufficient_scope` with "Policy '<name>' rejected request …", and the
    // name is the one this realm gives the policy.
    assert!(
        body.contains("Trusted Hosts"),
        "the registration was refused by something other than the trusted-hosts \
         policy: {}",
        excerpt(&body),
    );
    Ok(())
}

/// Keycloak holds a real, public client under `client_id`, carrying the
/// redirect URI it was registered with. The framework's own response would be
/// just as happy with a fabricated id, so this reads the admin API instead.
async fn assert_dynamic_client(keycloak: &Keycloak, client_id: &str) -> anyhow::Result<()> {
    let record = admin_client_record(keycloak, client_id).await?;
    let redirects = record["redirectUris"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("registered client has no redirectUris"))?;
    assert!(
        redirects.iter().any(|uri| uri == REDIRECT_URI),
        "the dynamically registered client does not carry {REDIRECT_URI:?}: {redirects:?}",
    );
    assert_eq!(
        record["publicClient"],
        json!(true),
        "a client registered with token_endpoint_auth_method=none must be public",
    );
    Ok(())
}

/// An RFC 7591 registration posted at the framework's proxy, returning the
/// `client_id` it hands back.
async fn register_through_framework(
    framework: &Framework,
    client_name: &str,
) -> anyhow::Result<String> {
    let response: Value = reqwest13::Client::new()
        .post(framework.register_url())
        .json(&json!({
            "client_name": client_name,
            "redirect_uris": [REDIRECT_URI],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "scope": SCOPES.join(" "),
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    response["client_id"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("/oauth/register answered without a client_id: {response}"))
}

/// A discovery document, fetched and parsed. These are all public endpoints.
async fn fetch_json(url: &str) -> anyhow::Result<Value> {
    Ok(reqwest13::Client::new()
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
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

        // The accepted request above is the one that could have written a
        // grant; it ran under an identity this test never reads back, which is
        // exactly what `token_count` is for.
        framework.assert_no_token_state(&[]).await;
        Ok(())
    })
}

// ── Guard: the mode's own preconditions ─────────────────────────────

/// Two preconditions every scenario above silently depends on, asserted here so
/// a failure of either shows up as itself rather than as an unexplained 401.
///
/// **The audience.** A `protocolMapper` Keycloak does not recognise is accepted
/// at import and then injects nothing, and `OAUTH_EXPECTED_AUDIENCE` is
/// mandatory in this mode — so a typo in the realm turns every request into a
/// confused-deputy rejection with no clue attached.
///
/// **The scopes.** `mcp:tools` and `mcp:resources` are *optional* client scopes:
/// they reach a token only if the client requests them, and a client only
/// requests what discovery advertises. That makes the chain here three links
/// long — `OAUTH_SCOPES` → the RFC 8414 / RFC 9728 documents → the `scope` claim
/// — and a break anywhere in it is invisible until someone wonders why an
/// authorization rule keyed on `mcp:tools` never fires.
#[tokio::test]
#[ignore = "needs Docker (Keycloak testcontainer); run with --ignored"]
async fn realm_injects_the_expected_audience_and_scopes() -> anyhow::Result<()> {
    scenario!(|keycloak, framework| {
        let mcp_url = framework.mcp_url();

        // Link 1: the protected-resource document advertises what this
        // deployment configured, not a hard-coded list.
        let prm: Value = reqwest13::Client::new()
            .get(framework.prm_url())
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let advertised = prm["scopes_supported"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("protected-resource metadata has no scopes_supported"))?
            .iter()
            .filter_map(|scope| scope.as_str().map(str::to_string))
            .collect::<Vec<_>>();
        for scope in SCOPES {
            assert!(
                advertised.iter().any(|found| found == scope),
                "discovery does not advertise {scope:?}: {advertised:?}",
            );
        }

        // Links 2 and 3: the client asks for them, Keycloak grants them.
        let auth = authorize(&mcp_url, "bob", "bob").await?;
        let claims = jwt_claims(&auth.get_access_token().await?)?;

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

        let granted = claims["scope"].as_str().unwrap_or_default();
        for scope in ["mcp:tools", "mcp:resources"] {
            assert!(
                granted.split_whitespace().any(|found| found == scope),
                "the access token does not carry {scope:?}: {granted:?}",
            );
        }

        assert_eq!(
            claims["iss"],
            json!(keycloak.issuer()),
            "token issuer does not match the discovered issuer",
        );
        assert!(claims["sid"].is_string(), "token carries no `sid` claim");
        Ok(())
    })
}

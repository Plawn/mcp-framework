//! `TokenMode::ResourceServer` — the framework as a pure OAuth resource server.
//!
//! What the mode is for: in passthrough the client and the server both hold the
//! same refresh token. Keycloak rotates refresh tokens, so the first
//! server-side refresh invalidates the copy the client is holding, and the link
//! breaks one cycle later. MCP 2025-06-18 resolved this by classifying the MCP
//! server as a resource server — it validates, it does not exchange.
//!
//! So the properties under test are as much about what does *not* happen as
//! about what does: no token is written anywhere, no refresh is attempted, and
//! the endpoints that would perform an exchange are not mounted at all.

#[allow(dead_code)]
mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Json, Router,
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    routing::{get, post},
};
use common::{app_with, whoami_request};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use mcp_framework::CapabilityRegistry;
use mcp_framework::auth::{
    AuthProvider, OAuthConfig, StoredToken, TokenMode, UnknownTokenValidation,
};
use mcp_framework::capability::{CapabilityFilter, ToolFilter};
use mcp_framework::constants::MCP_SESSION_ID_HEADER;
use mcp_framework::session::SessionStore;
use mcp_framework::transport::{HttpAppConfig, build_app, run_http};
use rmcp::ServerHandler;
use rmcp::model::{CallToolResult, ContentBlock, Tool};
use tower::ServiceExt as _;

const KEY_1: &str = include_str!("fixtures/jwks_test_key_1.pem");
const KEY_2: &str = include_str!("fixtures/jwks_test_key_2.pem");

/// Modulus of `jwks_test_key_1.pem` — the only key the mock issuer publishes.
/// Key 2 exists so a token can be signed by a key the issuer does not vouch for.
const MODULUS_1: &str = "t9pJsVVvTdGuph_D6wVlw84VxTSHsmd2OoJRsL1_2N3BAu9DGSascsocrCPogzGmd-AaEr2VNMWub8Erdt4HhdYuCSRYVwDRjquOyKsBFH1p7QQqzohUdrgvvhBbzAWhZo0JkBEcd7f1dyJoZoyANs3r0-g_xUj_6DqE3Fb9DU7s22dv_aPfna7_yWcmYXv2Nd9AK9NE33KLAxUQ7VOPm2mBuP0c5bJxQID0LCcYgpas01Sf3m5QLH_ywiL78z2s2h-rQRJoKAoi7yGtgtwZcYplFbk6EsvUHRRnIFoP2nlCAF3i_wgeIyPEXsLTxl25lXFJnPnROZobWpH42JSttQ";

/// The audience the deployment declares. `OAUTH_EXPECTED_AUDIENCE` is mandatory
/// in this mode — see `resource_server_mode_refuses_an_unconstrained_audience`.
const AUDIENCE: &str = "blumana-mcp";

/// A mock Keycloak, and the counters proving what the framework did and did not
/// ask it.
struct MockIssuer {
    auth: AuthProvider,
    /// How many times the issuer's signing keys were fetched.
    jwks_hits: Arc<AtomicUsize>,
    /// How many times RFC 7662 introspection was called. A pure resource server
    /// must never reach this endpoint, whatever the configured policy says.
    introspect_hits: Arc<AtomicUsize>,
}

#[derive(Clone)]
struct IssuerState {
    base: String,
    jwks_hits: Arc<AtomicUsize>,
    introspect_hits: Arc<AtomicUsize>,
}

/// A mock Keycloak that serves discovery + JWKS, and an introspection endpoint
/// that says "active" to *anything*. It deliberately has no token endpoint:
/// nothing in this mode may talk to one. The permissive introspection is the
/// trap: it is exactly what an introspection fallback would wave through.
async fn issuer() -> MockIssuer {
    let jwks_hits = Arc::new(AtomicUsize::new(0));
    let introspect_hits = Arc::new(AtomicUsize::new(0));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let issuer_url = format!("http://{addr}/realms/test");

    async fn discovery(State(state): State<IssuerState>) -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "issuer": state.base,
            "jwks_uri": format!("{}/protocol/openid-connect/certs", state.base),
        }))
    }

    async fn certs(State(state): State<IssuerState>) -> Json<serde_json::Value> {
        state.jwks_hits.fetch_add(1, Ordering::Relaxed);
        Json(serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": "k1",
                "n": MODULUS_1,
                "e": "AQAB",
            }]
        }))
    }

    async fn introspect(State(state): State<IssuerState>) -> Json<serde_json::Value> {
        state.introspect_hits.fetch_add(1, Ordering::Relaxed);
        Json(serde_json::json!({ "active": true }))
    }

    let app = Router::new()
        .route(
            "/realms/test/.well-known/openid-configuration",
            get(discovery),
        )
        .route("/realms/test/protocol/openid-connect/certs", get(certs))
        .route(
            "/realms/test/protocol/openid-connect/token/introspect",
            post(introspect),
        )
        .with_state(IssuerState {
            base: issuer_url.clone(),
            jwks_hits: jwks_hits.clone(),
            introspect_hits: introspect_hits.clone(),
        });

    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    MockIssuer {
        auth: AuthProvider::OAuth(resource_server_config(issuer_url)),
        jwks_hits,
        introspect_hits,
    }
}

fn resource_server_config(issuer_url: String) -> OAuthConfig {
    OAuthConfig {
        client_id: "mcp".to_string(),
        client_secret: None,
        issuer_url,
        redirect_url: "http://localhost/oauth/callback".to_string(),
        scopes: vec!["openid".to_string()],
        token_mode: TokenMode::ResourceServer,
        // Local verification only: a pure resource server has no reason to ask
        // the authorization server anything.
        unknown_token_validation: UnknownTokenValidation::Jwks,
        expected_audiences: vec![AUDIENCE.to_string()],
    }
}

fn issuer_url_of(auth: &AuthProvider) -> String {
    match auth {
        AuthProvider::OAuth(config) => config.issuer_url.clone(),
        _ => unreachable!("these tests always build an OAuth provider"),
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A bearer as the client obtains it directly from Keycloak — the framework
/// never sees the exchange that produced it.
struct Jwt {
    key: &'static str,
    kid: &'static str,
    issuer: String,
    subject: &'static str,
    session_state: Option<&'static str>,
    audience: &'static str,
    exp: u64,
}

impl Jwt {
    fn valid(auth: &AuthProvider) -> Self {
        Self {
            key: KEY_1,
            kid: "k1",
            issuer: issuer_url_of(auth),
            subject: "user-alice",
            session_state: Some("kc-session-alice"),
            audience: AUDIENCE,
            exp: now() + 300,
        }
    }

    fn sign(&self) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.to_string());
        let mut claims = serde_json::json!({
            "iss": self.issuer,
            "sub": self.subject,
            "aud": self.audience,
            "azp": "mcp",
            "iat": now() - 10,
            "exp": self.exp,
        });
        if let Some(sid) = self.session_state {
            claims["sid"] = serde_json::json!(sid);
        }
        encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(self.key.as_bytes()).unwrap(),
        )
        .unwrap()
    }
}

async fn get_json(app: &Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::get(uri)
                .header("host", "localhost")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

// ---------------------------------------------------------------------------
// Validation: what gets through, and what does not
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_request_without_a_bearer_is_told_where_to_authenticate() {
    let auth = issuer().await.auth;
    let (app, _) = app_with(auth);

    let response = app
        .clone()
        .oneshot(
            Request::get("/whoami")
                .header("host", "localhost")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let challenge = response
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .expect("a 401 must carry the RFC 9728 challenge");
    assert!(
        challenge.contains("resource_metadata="),
        "the challenge points the client at the protected-resource metadata: {challenge}"
    );
}

#[tokio::test]
async fn a_valid_bearer_is_accepted_and_nothing_is_kept() {
    let auth = issuer().await.auth;
    let bearer = Jwt::valid(&auth).sign();
    let (app, token_store) = app_with(auth);

    let (status, session_id) =
        whoami_request(&app, &[("authorization", &format!("Bearer {bearer}"))]).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        session_id.starts_with("cred-sid-"),
        "identity is derived from the JWT's `sid`, not from the bearer bytes: {session_id}"
    );

    // The point of the mode: the request was authenticated, and the server kept
    // nothing to authenticate the next one with.
    assert!(
        token_store.peek_token(&session_id).await.is_none(),
        "a pure resource server writes no token state"
    );
    assert!(
        token_store.peek_token("default").await.is_none(),
        "and none under the stdio fallback key either"
    );
}

#[tokio::test]
async fn an_expired_bearer_is_refused_rather_than_refreshed() {
    let auth = issuer().await.auth;
    let bearer = Jwt {
        exp: now() - 3600,
        ..Jwt::valid(&auth)
    }
    .sign();
    let (app, _) = app_with(auth);

    let (status, _) = whoami_request(&app, &[("authorization", &format!("Bearer {bearer}"))]).await;

    // There is no refresh token on this side to refresh with; the client owns
    // the grant and re-authenticates on its own.
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_token_minted_for_another_service_is_refused() {
    let auth = issuer().await.auth;
    let bearer = Jwt {
        audience: "some-other-api",
        ..Jwt::valid(&auth)
    }
    .sign();
    let (app, _) = app_with(auth);

    let (status, _) = whoami_request(&app, &[("authorization", &format!("Bearer {bearer}"))]).await;

    // The confused-deputy case. It is only caught because the deployment
    // declared its audience — hence the boot check.
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_bearer_signed_by_a_key_the_issuer_does_not_publish_is_refused() {
    let auth = issuer().await.auth;
    // Signed with key 2 but claiming key 1's `kid`: the signature check fails
    // against the published key.
    let bearer = Jwt {
        key: KEY_2,
        ..Jwt::valid(&auth)
    }
    .sign();
    let (app, _) = app_with(auth);

    let (status, _) = whoami_request(&app, &[("authorization", &format!("Bearer {bearer}"))]).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_non_jwt_credential_is_refused_without_asking_anyone() {
    let MockIssuer {
        auth, jwks_hits, ..
    } = issuer().await;
    let (app, _) = app_with(auth);

    let (status, _) = whoami_request(&app, &[("authorization", "Bearer not-a-jwt")]).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        jwks_hits.load(Ordering::Relaxed),
        0,
        "an opaque credential cannot be a JWT, so no key is fetched for it"
    );
}

#[tokio::test]
async fn the_same_user_lands_on_the_same_identity_across_requests() {
    let auth = issuer().await.auth;
    let auth_header = format!("Bearer {}", Jwt::valid(&auth).sign());
    let (app, _) = app_with(auth);

    let (_, first) = whoami_request(&app, &[("authorization", &auth_header)]).await;
    let (_, second) = whoami_request(&app, &[("authorization", &auth_header)]).await;

    assert_eq!(first, second);
}

#[tokio::test]
async fn a_client_cannot_bind_itself_to_someone_elses_identity() {
    let auth = issuer().await.auth;
    let auth_header = format!("Bearer {}", Jwt::valid(&auth).sign());
    let (app, _) = app_with(auth);

    let (_, honest) = whoami_request(&app, &[("authorization", &auth_header)]).await;
    let (status, spoofed) = whoami_request(
        &app,
        &[
            ("authorization", &auth_header),
            ("x-mcp-framework-session", "cred-sid-victim"),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        spoofed, honest,
        "the framework session header is stripped before auth runs"
    );
}

// ---------------------------------------------------------------------------
// What the consumers of a token actually receive
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct NoopServer;
impl ServerHandler for NoopServer {}

/// Build the real router with a capability filter that records what it was
/// handed. The filter is the narrow end of the funnel — access validators and
/// tool handlers resolve their token through the same `resolve_token`.
fn app_with_filter(
    auth: AuthProvider,
    filter: Arc<dyn CapabilityFilter>,
    registry: CapabilityRegistry,
) -> Router {
    let config: HttpAppConfig<_, ()> = HttpAppConfig {
        public_url: "http://localhost".to_string(),
        bind_addr: "127.0.0.1:0".to_string(),
        auth,
        server_factory: || NoopServer,
        app_name: "resource-server-test".to_string(),
        capability_registry: Some(registry),
        capability_filter: Some(filter),
        access_validator: None,
        claims_decoder: None,
        session_store: SessionStore::default(),
        tool_call_logger: None,
        persistence: None,
        protocol_lifecycle: mcp_framework::ProtocolLifecyclePolicy::Hybrid,
        extra_routes: None,
        public_routes: None,
    };
    let (app, _token_store, _registry) = build_app(config).expect("valid test configuration");
    app
}

async fn post_mcp(
    app: &Router,
    bearer: &str,
    session: Option<&str>,
    body: &serde_json::Value,
) -> axum::response::Response {
    let mut builder = Request::post("/mcp")
        .header("host", "localhost")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("authorization", format!("Bearer {bearer}"));
    if let Some(session) = session {
        builder = builder.header(MCP_SESSION_ID_HEADER, session);
    }
    app.clone()
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn a_filter_still_sees_the_credential_although_nothing_is_stored() {
    let auth = issuer().await.auth;
    let bearer = Jwt::valid(&auth).sign();

    let saw_token = Arc::new(AtomicBool::new(false));
    let matched_bearer = Arc::new(AtomicBool::new(false));
    let had_refresh_token = Arc::new(AtomicBool::new(false));

    let filter = {
        let (saw, matched, refresh) = (
            saw_token.clone(),
            matched_bearer.clone(),
            had_refresh_token.clone(),
        );
        let expected = bearer.clone();
        Arc::new(ToolFilter(
            move |tools: Vec<Tool>, token: Option<&StoredToken>| {
                if let Some(token) = token {
                    saw.store(true, Ordering::Relaxed);
                    matched.store(token.access_token == expected, Ordering::Relaxed);
                    refresh.store(token.refresh_token.is_some(), Ordering::Relaxed);
                }
                tools
            },
        )) as Arc<dyn CapabilityFilter>
    };

    let registry = CapabilityRegistry::default();
    registry
        .add_tool(
            Tool::new("ping", "Returns pong", serde_json::Map::new()),
            |_args| async { Ok(CallToolResult::success(vec![ContentBlock::text("pong")])) },
        )
        .await;

    let app = app_with_filter(auth, filter, registry);

    let response = post_mcp(
        &app,
        &bearer,
        None,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "rs-test", "version": "1.0" }
            }
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "initialize");
    let session = response
        .headers()
        .get(MCP_SESSION_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .expect("initialize hands back a session id");

    let response = post_mcp(
        &app,
        &bearer,
        Some(&session),
        &serde_json::json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "tools/list");
    // The response body is a stream: the handler — and therefore the filter —
    // only runs as it is consumed.
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(
        String::from_utf8_lossy(&body).contains("ping"),
        "the filter let the tool through"
    );

    assert!(
        saw_token.load(Ordering::Relaxed),
        "the filter must receive the credential — a store lookup would have found nothing"
    );
    assert!(
        matched_bearer.load(Ordering::Relaxed),
        "and it is the very bearer the client sent"
    );
    assert!(
        !had_refresh_token.load(Ordering::Relaxed),
        "the refresh token belongs to the client and never reaches this process"
    );
}

// ---------------------------------------------------------------------------
// Routing: the endpoints that would perform an exchange are gone
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_token_endpoint_is_not_proxied() {
    let auth = issuer().await.auth;
    let (app, _) = app_with(auth);

    let response = app
        .clone()
        .oneshot(
            Request::post("/oauth/token")
                .header("host", "localhost")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("grant_type=authorization_code&code=x"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "the framework must never see the grant"
    );
}

#[tokio::test]
async fn the_authorization_and_login_flows_are_not_proxied() {
    let auth = issuer().await.auth;
    let (app, _) = app_with(auth);

    // `/oauth/authorize` goes with `/oauth/token`: it rewrites `client_id`, so
    // the code it returns would not be redeemable at Keycloak's own token
    // endpoint. `/oauth/login` & co. exchange the code server-side and write the
    // grant into the store — the exact state this mode abolishes.
    //
    // They answer 404 rather than being absent from the router: an absent path
    // falls through to the auth-wrapped MCP fallback, which would answer 401 and
    // blame the client's credentials for a route that simply does not exist.
    for uri in [
        "/oauth/authorize?response_type=code&client_id=x&redirect_uri=http://localhost/cb",
        "/oauth/login",
        "/oauth/callback?code=x&state=y",
        "/oauth/status",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::get(uri)
                    .header("host", "localhost")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
    }
}

#[tokio::test]
async fn dynamic_client_registration_stays_because_keycloak_sends_no_cors() {
    let auth = issuer().await.auth;
    let expected_client_id = match &auth {
        AuthProvider::OAuth(config) => config.client_id.clone(),
        _ => unreachable!(),
    };
    let (app, _) = app_with(auth);

    // The mock issuer has no `clients-registrations` endpoint, so the proxy
    // falls back — and in this mode the fallback must hand back the *configured*
    // client id: nothing rewrites `client_id` downstream any more, so an
    // invented one would simply not exist at Keycloak.
    let response = app
        .clone()
        .oneshot(
            Request::post("/oauth/register")
                .header("host", "localhost")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "client_name": "some-mcp-client",
                        "redirect_uris": ["http://localhost/cb"],
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["client_id"], serde_json::json!(expected_client_id));
}

// ---------------------------------------------------------------------------
// Discovery: the client is sent to the real authorization server
// ---------------------------------------------------------------------------

#[tokio::test]
async fn protected_resource_metadata_names_the_authorization_server() {
    let auth = issuer().await.auth;
    let issuer_url = issuer_url_of(&auth);
    let (app, _) = app_with(auth);

    for uri in [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
    ] {
        let (status, body) = get_json(&app, uri).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert_eq!(
            body["authorization_servers"],
            serde_json::json!([issuer_url]),
            "RFC 9728: the resource server points at the AS, not at itself ({uri})"
        );
        assert_eq!(body["resource"], serde_json::json!("http://localhost/mcp"));
    }
}

#[tokio::test]
async fn authorization_server_metadata_describes_keycloak_not_this_server() {
    let auth = issuer().await.auth;
    let issuer_url = issuer_url_of(&auth);
    let (app, _) = app_with(auth);

    // Kept for MCP 2025-03-26 clients, which still probe the resource server
    // for this document — but it now describes the real AS, so the issuer it
    // advertises matches the `iss` the tokens carry (RFC 9207).
    let (status, body) = get_json(&app, "/.well-known/oauth-authorization-server").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["issuer"], serde_json::json!(issuer_url));
    assert_eq!(
        body["token_endpoint"],
        serde_json::json!(format!("{issuer_url}/protocol/openid-connect/token")),
    );
    assert_eq!(
        body["authorization_endpoint"],
        serde_json::json!(format!("{issuer_url}/protocol/openid-connect/auth")),
    );
    // The one endpoint that stays ours, for the CORS reason above.
    assert_eq!(
        body["registration_endpoint"],
        serde_json::json!("http://localhost/oauth/register"),
    );
}

#[tokio::test]
async fn the_proxying_modes_still_advertise_themselves() {
    // Guard against the branch leaking into passthrough.
    let auth = issuer().await.auth;
    let issuer_url = issuer_url_of(&auth);
    let mut config = resource_server_config(issuer_url);
    config.token_mode = TokenMode::Passthrough;
    let (app, _) = app_with(AuthProvider::OAuth(config));

    let (_, body) = get_json(&app, "/.well-known/oauth-authorization-server").await;
    assert_eq!(body["issuer"], serde_json::json!("http://localhost"));
    assert_eq!(
        body["token_endpoint"],
        serde_json::json!("http://localhost/oauth/token"),
    );

    let (_, prm) = get_json(&app, "/.well-known/oauth-protected-resource").await;
    assert_eq!(
        prm["authorization_servers"],
        serde_json::json!(["http://localhost"]),
    );
}

// ---------------------------------------------------------------------------
// Boot check
// ---------------------------------------------------------------------------

#[test]
fn resource_server_mode_refuses_an_unconstrained_audience() {
    let mut config = resource_server_config("http://issuer/realms/test".to_string());
    config.expected_audiences.clear();

    let error = config
        .validate()
        .expect_err("this cannot be allowed to run")
        .to_string();
    assert!(
        error.contains("OAUTH_EXPECTED_AUDIENCE"),
        "the message must name the variable to set: {error}"
    );
}

#[test]
fn resource_server_mode_refuses_the_reject_policy() {
    let mut config = resource_server_config("http://issuer/realms/test".to_string());
    config.unknown_token_validation = UnknownTokenValidation::Reject;

    let error = config
        .validate()
        .expect_err("nothing would ever be accepted")
        .to_string();
    assert!(error.contains("reject"), "{error}");
}

#[test]
fn the_proxying_modes_are_left_alone_by_the_boot_check() {
    for mode in [TokenMode::Passthrough, TokenMode::Opaque] {
        let mut config = resource_server_config("http://issuer/realms/test".to_string());
        config.token_mode = mode.clone();
        config.expected_audiences.clear();
        config.unknown_token_validation = UnknownTokenValidation::Reject;

        assert!(
            config.validate().is_ok(),
            "the requirement is specific to resource-server mode ({mode:?})"
        );
    }
}

#[test]
fn resource_server_mode_refuses_the_introspection_policy() {
    let mut config = resource_server_config("http://issuer/realms/test".to_string());
    config.unknown_token_validation = UnknownTokenValidation::Introspection;

    let error = config
        .validate()
        .expect_err("introspection cannot enforce an audience")
        .to_string();
    assert!(
        error.contains("OAUTH_EXPECTED_AUDIENCE"),
        "the message must say what introspection fails to check: {error}"
    );
}

#[test]
fn the_default_policy_is_coerced_to_jwks_rather_than_refused() {
    // `jwks_then_introspection` is the default value of the env var, so
    // refusing it outright would break every deployment that never set it.
    let mut config = resource_server_config("http://issuer/realms/test".to_string());
    config.unknown_token_validation = UnknownTokenValidation::JwksThenIntrospection;

    assert!(config.validate().is_ok(), "the default must still boot");
    assert_eq!(
        config.effective_unknown_token_validation(),
        UnknownTokenValidation::Jwks,
        "but the fallback half of it is dropped"
    );

    let mut passthrough = resource_server_config("http://issuer/realms/test".to_string());
    passthrough.token_mode = TokenMode::Passthrough;
    passthrough.unknown_token_validation = UnknownTokenValidation::JwksThenIntrospection;
    assert_eq!(
        passthrough.effective_unknown_token_validation(),
        UnknownTokenValidation::JwksThenIntrospection,
        "the coercion is specific to resource-server mode"
    );
}

#[tokio::test]
async fn introspection_never_gets_a_say_even_when_the_policy_asks_for_it() {
    // The hole this closes: RFC 7662 answers "is this token active", never
    // "who was it minted for". A token the issuer signed for another service
    // introspects as active, so an introspection fallback silently defeats the
    // mandatory audience check — the whole reason this mode is safe.
    let MockIssuer {
        auth,
        introspect_hits,
        ..
    } = issuer().await;
    let mut config = match auth {
        AuthProvider::OAuth(config) => config,
        _ => unreachable!(),
    };
    config.unknown_token_validation = UnknownTokenValidation::JwksThenIntrospection;
    let (app, _) = app_with(AuthProvider::OAuth(config));

    // An opaque credential: JWKS cannot speak for it, which is precisely the
    // case `jwks_then_introspection` would hand to the authorization server —
    // and this mock says "active" to anything.
    let (status, _) = whoami_request(&app, &[("authorization", "Bearer opaque-but-active")]).await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a credential the issuer's keys cannot vouch for is refused"
    );
    assert_eq!(
        introspect_hits.load(Ordering::Relaxed),
        0,
        "and the authorization server is never even asked"
    );
}

/// The boot check must hold on the public entry points too, not only on
/// `McpAppBuilder` — `HttpAppConfig` is a plain struct anyone can fill in.
fn config_with(auth: AuthProvider) -> HttpAppConfig<fn() -> NoopServer, ()> {
    HttpAppConfig {
        public_url: "http://localhost".to_string(),
        bind_addr: "127.0.0.1:0".to_string(),
        auth,
        server_factory: (|| NoopServer) as fn() -> NoopServer,
        app_name: "resource-server-test".to_string(),
        capability_registry: None,
        capability_filter: None,
        access_validator: None,
        claims_decoder: None,
        session_store: SessionStore::default(),
        tool_call_logger: None,
        persistence: None,
        protocol_lifecycle: mcp_framework::ProtocolLifecyclePolicy::Hybrid,
        extra_routes: None,
        public_routes: None,
    }
}

#[tokio::test]
async fn build_app_refuses_a_configuration_that_cannot_work() {
    let mut config = resource_server_config("http://issuer/realms/test".to_string());
    config.expected_audiences.clear();

    let error = build_app(config_with(AuthProvider::OAuth(config)))
        .err()
        .expect("a router that accepts every token the issuer signs must not be built");
    assert!(
        error.to_string().contains("OAUTH_EXPECTED_AUDIENCE"),
        "{error}"
    );
}

#[tokio::test]
async fn run_http_fails_before_it_binds_anything() {
    let mut config = resource_server_config("http://issuer/realms/test".to_string());
    config.expected_audiences.clear();

    // A valid configuration would serve until shutdown, so the timeout is the
    // assertion that the check happens *before* the listener is created.
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        run_http(config_with(AuthProvider::OAuth(config))),
    )
    .await
    .expect("run_http must return, not start serving");

    let error = outcome.err().expect("a misconfigured server must not run");
    assert!(
        error.to_string().contains("OAUTH_EXPECTED_AUDIENCE"),
        "{error}"
    );
}

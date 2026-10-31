//! The `/oauth/authorize` proxy owns Keycloak's authorization response (#1190).
//!
//! In the proxying token modes the framework advertises itself as the
//! authorization server (`issuer = public_url`). When it relayed Keycloak's
//! redirect straight to the client, the client received Keycloak's `iss` and a
//! strict RFC 9207 client (Claude Code, rmcp) refused the response. Keycloak is
//! now sent back to `/oauth/callback`, which forwards `code` / `state` to the
//! client with `iss = public_url`.
//!
//! The fake Keycloak below behaves like the real one where it matters: it puts
//! **its own** `iss` on the redirect, requires the token exchange to repeat the
//! `redirect_uri` of the authorization request, and checks PKCE.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::{
    Form, Json, Router,
    extract::{Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine as _;
use mcp_framework::auth::{AuthProvider, OAuthConfig, TokenMode, UnknownTokenValidation};
use mcp_framework::session::SessionStore;
use mcp_framework::transport::{HttpAppConfig, build_app};
use rmcp::ServerHandler;
use rmcp::transport::auth::{AuthorizationRequest, OAuthState};
use sha2::{Digest, Sha256};

const CLIENT_REDIRECT: &str = "http://127.0.0.1:1/callback";

// ── Fake Keycloak ───────────────────────────────────────────────────

#[derive(Default)]
struct Kc {
    issuer: String,
    /// code → (redirect_uri of the authorization request, code_challenge)
    codes: HashMap<String, (String, Option<String>)>,
    /// `redirect_uri` of every authorization request, in order.
    authorize_redirects: Vec<String>,
    /// The form of every token request, in order.
    token_requests: Vec<HashMap<String, String>>,
    /// When set, the authorization endpoint answers with this error.
    deny: Option<String>,
}

type KcState = Arc<Mutex<Kc>>;

async fn kc_authorize(
    State(kc): State<KcState>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let mut kc = kc.lock().unwrap();
    let redirect_uri = q["redirect_uri"].clone();
    kc.authorize_redirects.push(redirect_uri.clone());

    let mut target = url::Url::parse(&redirect_uri).unwrap();
    {
        let mut pairs = target.query_pairs_mut();
        if let Some(error) = kc.deny.clone() {
            pairs.append_pair("error", &error);
            pairs.append_pair("error_description", "denied by the fake");
        } else {
            let code = format!("kc-code-{}", kc.codes.len());
            kc.codes.insert(
                code.clone(),
                (redirect_uri.clone(), q.get("code_challenge").cloned()),
            );
            pairs.append_pair("code", &code);
        }
        if let Some(state) = q.get("state") {
            pairs.append_pair("state", state);
        }
        pairs.append_pair("session_state", "kc-session");
        // What makes a strict client refuse a relayed response.
        pairs.append_pair("iss", &kc.issuer);
    }
    (StatusCode::FOUND, [(header::LOCATION, target.to_string())]).into_response()
}

async fn kc_token(
    State(kc): State<KcState>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let mut kc = kc.lock().unwrap();
    kc.token_requests.push(form.clone());

    let invalid = |why: &str| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_grant", "error_description": why })),
        )
            .into_response()
    };
    let Some((redirect_uri, challenge)) = kc.codes.remove(&form["code"]) else {
        return invalid("unknown code");
    };
    if form.get("redirect_uri") != Some(&redirect_uri) {
        return invalid("Incorrect redirect_uri");
    }
    if let Some(challenge) = challenge {
        let verifier = form.get("code_verifier").cloned().unwrap_or_default();
        let computed = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(verifier.as_bytes()));
        if computed != challenge {
            return invalid("PKCE verification failed");
        }
    }
    Json(serde_json::json!({
        "access_token": "kc-access",
        "refresh_token": "kc-refresh",
        "token_type": "Bearer",
        "expires_in": 300,
    }))
    .into_response()
}

async fn kc_register() -> Response {
    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "client_id": "kc-dcr-client" })),
    )
        .into_response()
}

async fn spawn_keycloak() -> (String, KcState) {
    let kc: KcState = Arc::default();
    let app = Router::new()
        .route(
            "/realms/test/protocol/openid-connect/auth",
            get(kc_authorize),
        )
        .route("/realms/test/protocol/openid-connect/token", post(kc_token))
        .route(
            "/realms/test/clients-registrations/openid-connect",
            post(kc_register),
        )
        .with_state(kc.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let issuer = format!("http://{addr}/realms/test");
    kc.lock().unwrap().issuer = issuer.clone();
    (issuer, kc)
}

// ── Framework under test ────────────────────────────────────────────

#[derive(Clone)]
struct NoopServer;
impl ServerHandler for NoopServer {}

/// A framework served on a real port, `public_url` being that address.
async fn spawn_framework(token_mode: TokenMode, allowed_redirect_uris: Vec<String>) -> Setup {
    let (issuer, kc) = spawn_keycloak().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let public_url = format!("http://{}", listener.local_addr().unwrap());

    let config: HttpAppConfig<_, ()> = HttpAppConfig {
        public_url: public_url.clone(),
        bind_addr: "127.0.0.1:0".to_string(),
        auth: AuthProvider::OAuth(OAuthConfig {
            client_id: "mcp-server".to_string(),
            client_secret: Some("secret".to_string()),
            issuer_url: issuer.clone(),
            redirect_url: format!("{public_url}/oauth/callback"),
            scopes: vec!["openid".to_string()],
            token_mode,
            unknown_token_validation: UnknownTokenValidation::Introspection,
            expected_audiences: vec![],
            allowed_redirect_uris,
        }),
        server_factory: || NoopServer,
        app_name: "proxy-callback-test".to_string(),
        capability_registry: None,
        capability_filter: None,
        access_validator: None,
        claims_decoder: None,
        session_store: SessionStore::default(),
        tool_call_logger: None,
        persistence: None,
        protocol_lifecycle: mcp_framework::ProtocolLifecyclePolicy::Hybrid,
        max_protocol_version: None,
        extra_routes: None,
        public_routes: None,
    };
    let (app, _store, _registry) = build_app(config).expect("valid configuration");
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    Setup {
        public_url,
        issuer,
        kc,
    }
}

struct Setup {
    public_url: String,
    issuer: String,
    kc: KcState,
}

impl Setup {
    fn callback(&self) -> String {
        format!("{}/oauth/callback", self.public_url)
    }

    fn authorize_url(&self, client_id: &str, redirect_uri: &str, state: &str) -> String {
        format!(
            "{}/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&state={}&scope=openid",
            self.public_url,
            urlencoding::encode(client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(state),
        )
    }
}

fn no_redirects() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

/// Follow redirects by hand until one points at `stop_at`; return it.
async fn browse_until(start: &str, stop_at: &str) -> String {
    let http = no_redirects();
    let mut url = start.to_string();
    for _ in 0..6 {
        let response = http.get(&url).send().await.unwrap();
        assert!(
            response.status().is_redirection(),
            "{url} answered {} — {}",
            response.status(),
            response.text().await.unwrap_or_default()
        );
        url = response.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .to_string();
        if url.starts_with(stop_at) {
            return url;
        }
    }
    panic!("never redirected to {stop_at}");
}

fn query_of(url: &str) -> HashMap<String, String> {
    url::Url::parse(url)
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect()
}

// ── A strict RFC 9207 client, end to end ────────────────────────────

/// The acceptance criterion: rmcp's client — which validates `iss` against the
/// discovered issuer, and *requires* it once the metadata declares
/// `authorization_response_iss_parameter_supported` — completes the flow with
/// no manual surgery on the callback URL.
async fn strict_client_completes_the_flow(token_mode: TokenMode) {
    let setup = spawn_framework(token_mode, vec![]).await;
    let mcp_url = format!("{}/mcp", setup.public_url);

    let challenge = reqwest::Client::new()
        .post(&mcp_url)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(challenge.status(), StatusCode::UNAUTHORIZED);
    let challenge = challenge.headers()[header::WWW_AUTHENTICATE]
        .to_str()
        .unwrap()
        .to_string();

    let mut state = OAuthState::new(&mcp_url, None).await.unwrap();
    state
        .start_authorization(
            AuthorizationRequest::new(CLIENT_REDIRECT)
                .with_preregistered_client("claude-code")
                .with_scopes(["openid"])
                .with_challenge(challenge),
        )
        .await
        .unwrap();
    let auth_url = state.get_authorization_url().await.unwrap();

    let callback = browse_until(&auth_url, CLIENT_REDIRECT).await;
    let params = query_of(&callback);
    assert_eq!(params.get("iss"), Some(&setup.public_url));
    assert!(
        !callback.contains(&urlencoding::encode(&setup.issuer).to_string()),
        "Keycloak's iss leaked to the client: {callback}"
    );
    assert!(!params.contains_key("session_state"));

    state
        .handle_callback_url(&callback)
        .await
        .expect("a strict RFC 9207 client accepts the response");
    assert!(state.into_authorization_manager().is_some());

    let kc = setup.kc.lock().unwrap();
    assert_eq!(kc.authorize_redirects, [setup.callback()]);
    let exchange = kc.token_requests.last().unwrap();
    assert_eq!(exchange["redirect_uri"], setup.callback());
    assert_eq!(exchange["client_id"], "mcp-server");
}

#[tokio::test]
async fn passthrough_strict_client_completes_the_flow() {
    strict_client_completes_the_flow(TokenMode::Passthrough).await;
}

#[tokio::test]
async fn opaque_strict_client_completes_the_flow() {
    strict_client_completes_the_flow(TokenMode::Opaque).await;
}

// ── The callback dispatch, case by case ─────────────────────────────

#[tokio::test]
async fn client_state_and_existing_query_are_preserved() {
    let setup = spawn_framework(TokenMode::Passthrough, vec![]).await;
    let redirect = "http://localhost:4242/cb?keep=me";

    let callback = browse_until(
        &setup.authorize_url("any", redirect, "client-state-42"),
        "http://localhost:4242/cb",
    )
    .await;
    let params = query_of(&callback);

    assert_eq!(params["keep"], "me");
    assert_eq!(params["state"], "client-state-42");
    assert_eq!(params["iss"], setup.public_url);
    assert!(params["code"].starts_with("kc-code-"));

    // Keycloak only ever saw the framework's callback.
    let kc = setup.kc.lock().unwrap();
    assert_eq!(kc.authorize_redirects, [setup.callback()]);
}

#[tokio::test]
async fn a_keycloak_error_is_relayed_to_the_client() {
    let setup = spawn_framework(TokenMode::Passthrough, vec![]).await;
    setup.kc.lock().unwrap().deny = Some("access_denied".to_string());

    let callback = browse_until(
        &setup.authorize_url("any", CLIENT_REDIRECT, "s"),
        CLIENT_REDIRECT,
    )
    .await;
    let params = query_of(&callback);

    assert_eq!(params["error"], "access_denied");
    assert_eq!(params["error_description"], "denied by the fake");
    assert_eq!(params["state"], "s");
    assert_eq!(params["iss"], setup.public_url);
    assert!(!params.contains_key("code"));
}

#[tokio::test]
async fn the_server_state_is_single_use() {
    let setup = spawn_framework(TokenMode::Passthrough, vec![]).await;
    let http = no_redirects();

    // Stop at the framework's callback, replay it twice.
    let to_callback = browse_until(
        &setup.authorize_url("any", CLIENT_REDIRECT, "s"),
        &setup.callback(),
    )
    .await;
    let first = http.get(&to_callback).send().await.unwrap();
    assert_eq!(first.status(), StatusCode::FOUND);

    // The second lands on the historical login flow, which knows no such state.
    let replay = http.get(&to_callback).send().await.unwrap();
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_login_flow_still_owns_unknown_states() {
    let setup = spawn_framework(TokenMode::Passthrough, vec![]).await;
    let response = no_redirects()
        .get(format!("{}?code=x&state=unknown", setup.callback()))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ── The redirect_uri guard ──────────────────────────────────────────

#[tokio::test]
async fn an_unregistered_redirect_uri_gets_no_code() {
    let setup = spawn_framework(TokenMode::Passthrough, vec![]).await;
    let response = no_redirects()
        .get(setup.authorize_url("any", "https://attacker.example/cb", "s"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(setup.kc.lock().unwrap().authorize_redirects.is_empty());
}

#[tokio::test]
async fn a_redirect_uri_registered_through_dcr_is_accepted_for_that_client_only() {
    let setup = spawn_framework(TokenMode::Passthrough, vec![]).await;
    let hosted = "https://client.example/oauth/cb";

    let registered: serde_json::Value = reqwest::Client::new()
        .post(format!("{}/oauth/register", setup.public_url))
        .json(&serde_json::json!({ "client_name": "hosted", "redirect_uris": [hosted] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let client_id = registered["client_id"].as_str().unwrap();
    assert_eq!(client_id, "kc-dcr-client");

    let callback = browse_until(&setup.authorize_url(client_id, hosted, "s"), hosted).await;
    assert_eq!(query_of(&callback)["iss"], setup.public_url);

    let other = no_redirects()
        .get(setup.authorize_url("someone-else", hosted, "s"))
        .send()
        .await
        .unwrap();
    assert_eq!(other.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_configured_redirect_uri_is_accepted_without_registration() {
    let claude = "https://claude.ai/api/mcp/auth_callback";
    let setup = spawn_framework(TokenMode::Passthrough, vec![claude.to_string()]).await;

    let callback = browse_until(&setup.authorize_url("forgotten", claude, "s"), claude).await;
    assert_eq!(query_of(&callback)["iss"], setup.public_url);
}

#[tokio::test]
async fn the_deployments_own_origin_is_accepted() {
    let setup = spawn_framework(TokenMode::Passthrough, vec![]).await;
    let spa = format!("{}/", setup.public_url);

    let callback = browse_until(&setup.authorize_url("spa", &spa, "s"), &spa).await;
    assert!(query_of(&callback)["code"].starts_with("kc-code-"));
}

// ── Metadata ────────────────────────────────────────────────────────

#[tokio::test]
async fn stateful_metadata_declares_iss_support() {
    for mode in [TokenMode::Passthrough, TokenMode::Opaque] {
        let setup = spawn_framework(mode, vec![]).await;
        let metadata: serde_json::Value = reqwest::get(format!(
            "{}/.well-known/oauth-authorization-server",
            setup.public_url
        ))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
        assert_eq!(metadata["issuer"], setup.public_url);
        assert_eq!(
            metadata["authorization_response_iss_parameter_supported"],
            true
        );
    }
}

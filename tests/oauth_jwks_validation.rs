//! Local (JWKS) validation of bearers the OAuth proxy did not issue.
//!
//! The production failure this covers: Keycloak refuses `/token/introspect` to
//! a **public** client with `403 {"error":"invalid_request",
//! "error_description":"Client not allowed."}`. In `TokenMode::Passthrough`
//! that left no way to validate a token-exchange bearer, so every MCP
//! `initialize` behind such a deployment answered 401.

#[allow(dead_code)]
mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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
use mcp_framework::auth::{
    AuthProvider, OAuthConfig, StoredToken, TokenMode, UnknownTokenValidation,
};
use mcp_framework::constants::MCP_SESSION_ID_HEADER;
use tower::ServiceExt as _;

const KEY_1: &str = include_str!("fixtures/jwks_test_key_1.pem");
const KEY_2: &str = include_str!("fixtures/jwks_test_key_2.pem");

/// Modulus of `jwks_test_key_1.pem`. Only key 1 is ever *published*; key 2
/// exists so a token can be signed by a key the issuer does not vouch for.
const MODULUS_1: &str = "t9pJsVVvTdGuph_D6wVlw84VxTSHsmd2OoJRsL1_2N3BAu9DGSascsocrCPogzGmd-AaEr2VNMWub8Erdt4HhdYuCSRYVwDRjquOyKsBFH1p7QQqzohUdrgvvhBbzAWhZo0JkBEcd7f1dyJoZoyANs3r0-g_xUj_6DqE3Fb9DU7s22dv_aPfna7_yWcmYXv2Nd9AK9NE33KLAxUQ7VOPm2mBuP0c5bJxQID0LCcYgpas01Sf3m5QLH_ywiL78z2s2h-rQRJoKAoi7yGtgtwZcYplFbk6EsvUHRRnIFoP2nlCAF3i_wgeIyPEXsLTxl25lXFJnPnROZobWpH42JSttQ";

/// How many times the mock issuer served each endpoint. What the assertions in
/// this file are really about: the *absence* of a call is the property under
/// test (no introspection on the nominal path, no JWKS round-trip for a
/// proxy-issued token, one refetch — not one per request — on an unknown `kid`).
#[derive(Clone, Default)]
struct Hits {
    jwks: Arc<AtomicUsize>,
    introspect: Arc<AtomicUsize>,
}

impl Hits {
    fn jwks(&self) -> usize {
        self.jwks.load(Ordering::Relaxed)
    }
    fn introspect(&self) -> usize {
        self.introspect.load(Ordering::Relaxed)
    }
}

/// How the mock Keycloak answers `/token/introspect`.
#[derive(Clone, Copy, PartialEq)]
enum Introspection {
    /// The bug: a public client is not allowed to introspect.
    NotPermitted,
    /// A confidential client that reports every token as unknown.
    Inactive,
}

/// Spawn a mock issuer and return the `AuthProvider` pointing at it.
async fn issuer(
    introspection: Introspection,
    policy: UnknownTokenValidation,
) -> (AuthProvider, Hits) {
    let hits = Hits::default();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let issuer_url = format!("http://{addr}/realms/test");

    async fn discovery(State((base, _)): State<(String, Hits)>) -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "issuer": base,
            "jwks_uri": format!("{base}/protocol/openid-connect/certs"),
        }))
    }

    async fn certs(State((_, hits)): State<(String, Hits)>) -> Json<serde_json::Value> {
        hits.jwks.fetch_add(1, Ordering::Relaxed);
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

    let hits_for_introspect = hits.clone();
    let app = Router::new()
        .route(
            "/realms/test/.well-known/openid-configuration",
            get(discovery),
        )
        .route("/realms/test/protocol/openid-connect/certs", get(certs))
        .with_state((issuer_url.clone(), hits.clone()))
        .route(
            "/realms/test/protocol/openid-connect/token/introspect",
            post(move || {
                let hits = hits_for_introspect.clone();
                async move {
                    hits.introspect.fetch_add(1, Ordering::Relaxed);
                    match introspection {
                        Introspection::NotPermitted => (
                            StatusCode::FORBIDDEN,
                            Json(serde_json::json!({
                                "error": "invalid_request",
                                "error_description": "Client not allowed.",
                            })),
                        ),
                        Introspection::Inactive => {
                            (StatusCode::OK, Json(serde_json::json!({ "active": false })))
                        }
                    }
                }
            }),
        );

    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let auth = AuthProvider::OAuth(OAuthConfig {
        // A *public* client: no secret, which is exactly why Keycloak refuses
        // it the introspection endpoint.
        client_id: "mcp".to_string(),
        client_secret: None,
        issuer_url: issuer_url.clone(),
        redirect_url: "http://localhost/oauth/callback".to_string(),
        scopes: vec!["openid".to_string()],
        token_mode: TokenMode::Passthrough,
        unknown_token_validation: policy,
        expected_audiences: vec![],
    });

    (auth, hits)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

struct Jwt {
    key: &'static str,
    kid: &'static str,
    issuer: String,
    audience: &'static str,
    exp: u64,
}

impl Jwt {
    /// A token-exchange token as `blumana-agent` obtains it: signed by the
    /// issuer's current key, carrying the *downstream* service as `aud`.
    fn token_exchange(auth: &AuthProvider) -> Self {
        Self {
            key: KEY_1,
            kid: "k1",
            issuer: issuer_url_of(auth),
            audience: "blumana-mcp",
            exp: now() + 300,
        }
    }

    fn sign(&self) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.to_string());
        encode(
            &header,
            &serde_json::json!({
                "iss": self.issuer,
                "sub": "user-alice",
                "aud": self.audience,
                "azp": "blumana-agent",
                "iat": now() - 10,
                "exp": self.exp,
            }),
            &EncodingKey::from_rsa_pem(self.key.as_bytes()).unwrap(),
        )
        .unwrap()
    }
}

fn issuer_url_of(auth: &AuthProvider) -> String {
    match auth {
        AuthProvider::OAuth(config) => config.issuer_url.clone(),
        _ => unreachable!("these tests always build an OAuth provider"),
    }
}

fn initialize_request() -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": "jwks-test", "version": "1.0" }
        }
    })
}

fn mcp_requests() -> [serde_json::Value; 3] {
    [
        initialize_request(),
        serde_json::json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": { "name": "missing", "arguments": {} }
        }),
    ]
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

// ---------------------------------------------------------------------------
// The bug, and the fix
// ---------------------------------------------------------------------------

#[tokio::test]
async fn introspection_only_rejects_the_token_exchange_bearer() {
    // The production behaviour before this change: the only validation path
    // available is the one Keycloak refuses to a public client.
    let (auth, hits) = issuer(
        Introspection::NotPermitted,
        UnknownTokenValidation::Introspection,
    )
    .await;
    let bearer = Jwt::token_exchange(&auth).sign();
    let (app, _) = app_with(auth);

    let (status, _) = whoami_request(&app, &[("authorization", &format!("Bearer {bearer}"))]).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(hits.introspect(), 1, "it did try, and was turned away");
    assert_eq!(hits.jwks(), 0, "JWKS is not consulted under this policy");
}

#[tokio::test]
async fn a_token_exchange_bearer_is_accepted_without_introspection() {
    let (auth, hits) = issuer(
        Introspection::NotPermitted,
        UnknownTokenValidation::JwksThenIntrospection,
    )
    .await;
    let bearer = Jwt::token_exchange(&auth).sign();
    let (app, token_store) = app_with(auth);

    // A real MCP conversation, not three isolated posts: `tools/list` and
    // `tools/call` are only meaningful on an initialized session, and rmcp
    // answers 422 without one — which would mask the auth verdict under test.
    let response = post_mcp(&app, &bearer, None, &mcp_requests()[0]).await;
    assert_eq!(response.status(), StatusCode::OK, "initialize");
    let session = response
        .headers()
        .get(MCP_SESSION_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .expect("initialize hands back a session id");

    for request in &mcp_requests()[1..] {
        assert_eq!(
            post_mcp(&app, &bearer, Some(&session), request)
                .await
                .status(),
            StatusCode::OK,
            "method {} should pass auth",
            request["method"]
        );
    }

    assert_eq!(
        hits.introspect(),
        0,
        "the whole point: the endpoint that 403s is never reached"
    );
    assert_eq!(hits.jwks(), 1, "one fetch, then the cache serves the rest");

    // The validated bearer became the session's token, so downstream handlers
    // see it exactly as they would a proxy-issued one.
    let (_, session) =
        whoami_request(&app, &[("authorization", &format!("Bearer {bearer}"))]).await;
    assert_eq!(
        token_store
            .peek_token(&session)
            .await
            .map(|t| t.access_token),
        Some(bearer)
    );
}

// ---------------------------------------------------------------------------
// Strict validation — a locally checked token is not a trusted token
// ---------------------------------------------------------------------------

/// Each of these is signed-shaped but must not be accepted, and — because the
/// issuer's own keys answered — must not get a second opinion from
/// introspection either.
#[tokio::test]
async fn expired_wrongly_signed_and_foreign_issuer_tokens_are_refused() {
    let (auth, hits) = issuer(
        Introspection::NotPermitted,
        UnknownTokenValidation::JwksThenIntrospection,
    )
    .await;
    let expired = Jwt {
        exp: now() - 60,
        ..Jwt::token_exchange(&auth)
    };
    let forged = Jwt {
        // Signed by a key the issuer never published, under a `kid` it did.
        key: KEY_2,
        ..Jwt::token_exchange(&auth)
    };
    let foreign = Jwt {
        issuer: "https://attacker.example/realms/test".to_string(),
        ..Jwt::token_exchange(&auth)
    };

    let (app, _) = app_with(auth);

    for (label, jwt) in [
        ("expired", expired),
        ("bad signature", forged),
        ("wrong issuer", foreign),
    ] {
        let bearer = jwt.sign();
        let (status, _) =
            whoami_request(&app, &[("authorization", &format!("Bearer {bearer}"))]).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{label} must be refused");
    }

    assert_eq!(
        hits.introspect(),
        0,
        "a verdict from the issuer's own keys is final"
    );
}

#[tokio::test]
async fn an_unknown_kid_triggers_exactly_one_refetch() {
    let (auth, hits) = issuer(
        Introspection::NotPermitted,
        UnknownTokenValidation::JwksThenIntrospection,
    )
    .await;
    let rotated = Jwt {
        // The issuer publishes `k1` only; `k9` is what a rotated-away — or
        // forged — token looks like.
        kid: "k9",
        ..Jwt::token_exchange(&auth)
    };
    let known = Jwt::token_exchange(&auth);
    let (app, _) = app_with(auth);

    let bearer = rotated.sign();
    for _ in 0..3 {
        let (status, _) =
            whoami_request(&app, &[("authorization", &format!("Bearer {bearer}"))]).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // Anti-hammering: an unknown `kid` misses the cache on every request, but
    // the cooldown keeps that from becoming one outbound fetch per inbound one.
    assert_eq!(hits.jwks(), 1);

    // And the keys fetched by that single refetch still serve the good token.
    let bearer = known.sign();
    let (status, _) = whoami_request(&app, &[("authorization", &format!("Bearer {bearer}"))]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(hits.jwks(), 1);
}

// ---------------------------------------------------------------------------
// No regression on the paths that already worked
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_proxy_issued_token_never_reaches_the_issuer() {
    let (auth, hits) = issuer(
        Introspection::NotPermitted,
        UnknownTokenValidation::JwksThenIntrospection,
    )
    .await;
    let (app, token_store) = app_with(auth);

    // What `/oauth/token` leaves behind: an opaque-to-us access token already
    // trusted because this process performed the exchange itself.
    token_store
        .store_token(
            "sess-1".to_string(),
            StoredToken::new("proxy-issued-token".to_string(), None, None),
        )
        .await;

    let (status, _) = whoami_request(
        &app,
        &[
            ("authorization", "Bearer proxy-issued-token"),
            (MCP_SESSION_ID_HEADER, "sess-1"),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(hits.jwks(), 0, "no needless JWKS round-trip");
    assert_eq!(hits.introspect(), 0);
}

#[tokio::test]
async fn an_unknown_opaque_token_still_falls_back_to_introspection() {
    // Not a JWT at all — JWKS cannot have an opinion, so the decision is
    // introspection's to make, and it says no.
    let (auth, hits) = issuer(
        Introspection::Inactive,
        UnknownTokenValidation::JwksThenIntrospection,
    )
    .await;
    let (app, _) = app_with(auth);

    let (status, _) = whoami_request(&app, &[("authorization", "Bearer not-a-jwt")]).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(hits.introspect(), 1);
    assert_eq!(hits.jwks(), 0, "an opaque token has no `kid` to look up");
}

#[tokio::test]
async fn an_unknown_opaque_token_is_refused_when_introspection_is_unavailable() {
    // Both doors are shut: it is not a JWT, and the issuer will not introspect
    // for this client. The refusal is explicit rather than a silent "inactive".
    let (auth, hits) = issuer(
        Introspection::NotPermitted,
        UnknownTokenValidation::JwksThenIntrospection,
    )
    .await;
    let (app, _) = app_with(auth);

    for _ in 0..2 {
        let (status, _) = whoami_request(&app, &[("authorization", "Bearer not-a-jwt")]).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // The 403 is latched after the first attempt, so a misconfigured client
    // does not keep hammering an endpoint that will never answer differently.
    assert_eq!(hits.introspect(), 1);
}

#[tokio::test]
async fn the_reject_policy_short_circuits_every_unknown_bearer() {
    let (auth, hits) = issuer(Introspection::Inactive, UnknownTokenValidation::Reject).await;
    let bearer = Jwt::token_exchange(&auth).sign();
    let (app, _) = app_with(auth);

    let (status, _) = whoami_request(&app, &[("authorization", &format!("Bearer {bearer}"))]).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(hits.jwks(), 0);
    assert_eq!(hits.introspect(), 0);
}

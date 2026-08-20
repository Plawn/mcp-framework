//! Passthrough OAuth identity binding and per-grant isolation tests.

mod common;

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{Json, Router, http::StatusCode, routing::post};
use common::{app_with, whoami_request};
use mcp_framework::auth::{
    AuthProvider, OAuthConfig, StoredToken, TokenMode, UnknownTokenValidation,
};
use mcp_framework::constants::MCP_SESSION_ID_HEADER;

async fn oauth() -> AuthProvider {
    async fn introspect() -> Json<serde_json::Value> {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 300;
        Json(serde_json::json!({ "active": true, "exp": exp }))
    }

    let app = Router::new().route(
        "/realms/test/protocol/openid-connect/token/introspect",
        post(introspect),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    AuthProvider::OAuth(OAuthConfig {
        client_id: "test-client".to_string(),
        client_secret: Some("test-secret".to_string()),
        issuer_url: format!("http://{addr}/realms/test"),
        redirect_url: "http://localhost/oauth/callback".to_string(),
        scopes: vec!["openid".to_string()],
        token_mode: TokenMode::Passthrough,
        // Left on the default on purpose: this issuer publishes no JWKS, so
        // every unknown bearer exercises the JWKS-unavailable fall-through to
        // introspection that these assertions depend on.
        unknown_token_validation: UnknownTokenValidation::JwksThenIntrospection,
        expected_audiences: vec![],
    })
}

#[tokio::test]
async fn concurrent_sessionless_bearers_are_isolated() {
    let (app, token_store) = app_with(oauth().await);

    let (status_a, id_a) = whoami_request(&app, &[("authorization", "Bearer token-alice")]).await;
    let (status_b, id_b) = whoami_request(&app, &[("authorization", "Bearer token-bob")]).await;

    assert_eq!(status_a, StatusCode::OK);
    assert_eq!(status_b, StatusCode::OK);

    // Two users, no protocol session between them. Collapsing both onto
    // "default" would serve Alice's token to Bob.
    assert_ne!(id_a, id_b);
    assert_eq!(
        token_store.peek_token(&id_a).await.map(|t| t.access_token),
        Some("token-alice".to_string())
    );
    assert_eq!(
        token_store.peek_token(&id_b).await.map(|t| t.access_token),
        Some("token-bob".to_string())
    );
}

#[tokio::test]
async fn passthrough_adopts_the_refresh_token_captured_at_the_exchange() {
    let (app, token_store) = app_with(oauth().await);

    // Stand in for `/oauth/token`: it keys by credential because no MCP session
    // exists yet, and it is the only place the refresh_token is ever seen.
    let (_, grant_key) = whoami_request(&app, &[("authorization", "Bearer token-alice")]).await;
    token_store
        .store_token(
            grant_key.clone(),
            StoredToken::new(
                "token-alice".to_string(),
                Some("refresh-alice".to_string()),
                None,
            ),
        )
        .await;

    // The client then connects and rmcp hands it a protocol session id. The
    // session key changes, but the grant is the same — the refresh_token must
    // follow, or server-side refresh can never fire for this user.
    let (status, id) = whoami_request(
        &app,
        &[
            ("authorization", "Bearer token-alice"),
            (MCP_SESSION_ID_HEADER, "sess-alice"),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(id, "sess-alice");
    let adopted = token_store.peek_token("sess-alice").await.expect("adopted");
    assert_eq!(adopted.access_token, "token-alice");
    assert_eq!(adopted.refresh_token.as_deref(), Some("refresh-alice"));
}

/// Build a JWT-shaped token (`header.payload.sig`) carrying `sub`. The payload
/// is real base64url JSON so `jwt_subject` can decode it. The mock introspection
/// endpoint above stands in for signature validation. `nonce` makes two tokens
/// for the same principal differ byte-for-byte, mimicking Keycloak re-issuing a
/// fresh JWT on every token-exchange.
fn jwt_with_sub(sub: &str, nonce: &str) -> String {
    use base64::Engine as _;
    let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = enc.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let payload = enc.encode(format!(r#"{{"sub":"{sub}","jti":"{nonce}"}}"#).as_bytes());
    format!("{header}.{payload}.sig")
}

/// Same as [`jwt_with_sub`], plus the `sid` claim Keycloak puts on every token
/// minted from one SSO session — the claim the session identity is derived from.
fn jwt_with_sid(sub: &str, sid: &str, nonce: &str) -> String {
    use base64::Engine as _;
    let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = enc.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let payload =
        enc.encode(format!(r#"{{"sub":"{sub}","sid":"{sid}","jti":"{nonce}"}}"#).as_bytes());
    format!("{header}.{payload}.sig")
}

#[tokio::test]
async fn sessionless_identity_survives_a_bearer_refresh() {
    let (app, token_store) = app_with(oauth().await);

    // A sessionless (MCP 2026-07-28) client whose bearer rotates every few
    // minutes. Before the claims-derived key, each rotation produced a brand-new
    // identity and orphaned everything the previous one keyed.
    let t1 = jwt_with_sid("alice", "sso-1", "one");
    let t2 = jwt_with_sid("alice", "sso-1", "two");
    assert_ne!(t1, t2);

    let (status1, id1) = whoami_request(&app, &[("authorization", &format!("Bearer {t1}"))]).await;
    let (status2, id2) = whoami_request(&app, &[("authorization", &format!("Bearer {t2}"))]).await;

    assert_eq!(status1, StatusCode::OK);
    assert_eq!(status2, StatusCode::OK);
    assert_eq!(id1, id2, "a refreshed bearer must keep its session identity");
    assert!(id1.starts_with("cred-sid-"), "got {id1}");

    // One entry, holding the current bearer — not two half-live ones.
    let stored = token_store.peek_token(&id1).await.expect("stored");
    assert_eq!(stored.access_token, t2);
}

#[tokio::test]
async fn sessionless_identity_isolates_two_sso_sessions_of_the_same_user() {
    let (app, token_store) = app_with(oauth().await);

    // Same `sub`, different `sid`: the same human logged in twice (two devices,
    // or one device after a full re-login). They must not share token state.
    let desktop = jwt_with_sid("alice", "sso-desktop", "one");
    let mobile = jwt_with_sid("alice", "sso-mobile", "one");

    let (_, id_desktop) =
        whoami_request(&app, &[("authorization", &format!("Bearer {desktop}"))]).await;
    let (_, id_mobile) =
        whoami_request(&app, &[("authorization", &format!("Bearer {mobile}"))]).await;

    assert_ne!(id_desktop, id_mobile);
    assert_eq!(
        token_store
            .peek_token(&id_desktop)
            .await
            .map(|t| t.access_token),
        Some(desktop)
    );
    assert_eq!(
        token_store
            .peek_token(&id_mobile)
            .await
            .map(|t| t.access_token),
        Some(mobile)
    );
}

/// The consequence of a stable key on the passthrough store/adopt path: a
/// rotation now lands on the *same* entry the previous bearer wrote, so it goes
/// through the principal check and replaces it — rather than silently forking a
/// second entry as the byte-hash key did.
#[tokio::test]
async fn sessionless_rotation_replaces_the_grant_entry_and_drops_stale_refresh_material() {
    let (app, token_store) = app_with(oauth().await);

    let t1 = jwt_with_sid("alice", "sso-1", "one");
    let (_, id) = whoami_request(&app, &[("authorization", &format!("Bearer {t1}"))]).await;

    // Stand in for `/oauth/token`: it keys the grant the same way, so the
    // refresh material lands on this very entry.
    token_store
        .store_token(
            id.clone(),
            StoredToken::new(t1.clone(), Some("refresh-alice".to_string()), None),
        )
        .await;

    // The client rotates its bearer *without* going through this proxy's
    // `/oauth/token` (bring-your-own-token). The refresh_token we hold belongs
    // to the superseded credential — Keycloak's rotation has already invalidated
    // it — so it must not be carried onto the new bearer.
    let t2 = jwt_with_sid("alice", "sso-1", "two");
    let (status, id2) = whoami_request(&app, &[("authorization", &format!("Bearer {t2}"))]).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(id2, id);
    let stored = token_store.peek_token(&id).await.expect("stored");
    assert_eq!(stored.access_token, t2);
    assert_eq!(stored.refresh_token, None);
}

/// A `sid`-carrying token and a `sub`-only token for the same user derive keys
/// in different families. Landed on the same protocol session, the newcomer is
/// still recognised as the same principal via `sub` rather than 401'd.
#[tokio::test]
async fn a_sid_token_and_a_sub_only_token_for_one_user_are_the_same_principal() {
    let (app, token_store) = app_with(oauth().await);

    let with_sid = jwt_with_sid("alice", "sso-1", "one");
    let (status1, _) = whoami_request(
        &app,
        &[
            ("authorization", &format!("Bearer {with_sid}")),
            (MCP_SESSION_ID_HEADER, "sess-alice"),
        ],
    )
    .await;
    assert_eq!(status1, StatusCode::OK);

    let without_sid = jwt_with_sub("alice", "two");
    let (status2, _) = whoami_request(
        &app,
        &[
            ("authorization", &format!("Bearer {without_sid}")),
            (MCP_SESSION_ID_HEADER, "sess-alice"),
        ],
    )
    .await;

    assert_eq!(status2, StatusCode::OK);
    assert_eq!(
        token_store
            .peek_token("sess-alice")
            .await
            .map(|t| t.access_token),
        Some(without_sid)
    );
}

#[tokio::test]
async fn passthrough_accepts_a_rotated_bearer_for_the_same_principal() {
    let (app, token_store) = app_with(oauth().await);

    // A bring-your-own-token client: it obtained its own Keycloak JWT (never via
    // `/oauth/token`) and re-mints it on every request. First request seeds the
    // session entry.
    let t1 = jwt_with_sub("alice", "one");
    let (status1, id) = whoami_request(
        &app,
        &[
            ("authorization", &format!("Bearer {t1}")),
            (MCP_SESSION_ID_HEADER, "sess-alice"),
        ],
    )
    .await;
    assert_eq!(status1, StatusCode::OK);
    assert_eq!(id, "sess-alice");

    // Same user, brand-new JWT bytes, same live session. Before the fix this
    // 3rd-request-shaped rotation fell into a 401.
    let t2 = jwt_with_sub("alice", "two");
    assert_ne!(t1, t2);
    let (status2, _) = whoami_request(
        &app,
        &[
            ("authorization", &format!("Bearer {t2}")),
            (MCP_SESSION_ID_HEADER, "sess-alice"),
        ],
    )
    .await;

    assert_eq!(status2, StatusCode::OK);
    // The rotated bearer replaced the stored one and never inherited refresh
    // material. Its expiry comes from the successful introspection response.
    let stored = token_store.peek_token("sess-alice").await.expect("stored");
    assert_eq!(stored.access_token, t2);
    assert_eq!(stored.refresh_token, None);
    assert!(stored.expires_at.is_some());
}

#[tokio::test]
async fn passthrough_rotation_never_inherits_previous_refresh_material() {
    let (app, token_store) = app_with(oauth().await);

    // Seed the session with a JWT that *does* carry refresh material, as if the
    // grant had been adopted from `/oauth/token`.
    let t1 = jwt_with_sub("alice", "one");
    token_store
        .store_token(
            "sess-alice".to_string(),
            StoredToken::new(t1.clone(), Some("refresh-alice".to_string()), None),
        )
        .await;

    // Same principal rotates its bearer. The refresh_token belongs to the old
    // credential and must not follow the new one.
    let t2 = jwt_with_sub("alice", "two");
    let (status, _) = whoami_request(
        &app,
        &[
            ("authorization", &format!("Bearer {t2}")),
            (MCP_SESSION_ID_HEADER, "sess-alice"),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let stored = token_store.peek_token("sess-alice").await.expect("stored");
    assert_eq!(stored.access_token, t2);
    assert_eq!(stored.refresh_token, None);
}

#[tokio::test]
async fn passthrough_rejects_a_different_principal_for_an_existing_session() {
    let (app, token_store) = app_with(oauth().await);
    let alice = jwt_with_sub("alice", "one");
    token_store
        .store_token(
            "sess-alice".to_string(),
            StoredToken::new(alice.clone(), Some("refresh-alice".to_string()), None),
        )
        .await;

    // A valid JWT, but for a different `sub`. It must not hijack Alice's session
    // nor wipe her refresh material.
    let mallory = jwt_with_sub("mallory", "x");
    let (status, _) = whoami_request(
        &app,
        &[
            ("authorization", &format!("Bearer {mallory}")),
            (MCP_SESSION_ID_HEADER, "sess-alice"),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let unchanged = token_store.peek_token("sess-alice").await.unwrap();
    assert_eq!(unchanged.access_token, alice);
    assert_eq!(unchanged.refresh_token.as_deref(), Some("refresh-alice"));
}

#[tokio::test]
async fn passthrough_rejects_a_different_bearer_for_an_existing_session() {
    let (app, token_store) = app_with(oauth().await);
    token_store
        .store_token(
            "sess-alice".to_string(),
            StoredToken::new(
                "access-alice".to_string(),
                Some("refresh-alice".to_string()),
                None,
            ),
        )
        .await;

    let (status, _) = whoami_request(
        &app,
        &[
            ("authorization", "Bearer access-mallory"),
            (MCP_SESSION_ID_HEADER, "sess-alice"),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let unchanged = token_store.peek_token("sess-alice").await.unwrap();
    assert_eq!(unchanged.access_token, "access-alice");
    assert_eq!(unchanged.refresh_token.as_deref(), Some("refresh-alice"));
}

//! OAuth proxy handlers for Keycloak integration.
//!
//! Handles:
//! - `/oauth/authorize` - Redirects to Keycloak
//! - `/oauth/token` - Proxies token exchange to Keycloak

use axum::{
    Json,
    body::Body,
    extract::{Query, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect},
};
use serde::Deserialize;
use std::sync::Arc;
use url::form_urlencoded;

use super::config::TokenMode;
use super::middleware::credential_session_key;
use super::{McpOAuthState, StoredToken};
use crate::constants::{CONTENT_TYPE_FORM, OPAQUE_ACCESS_TTL};
use crate::http_util::HttpError;
use std::time::{Duration, Instant};

/// Authorization request query parameters
#[derive(Debug, Deserialize)]
pub struct AuthorizeRequest {
    pub response_type: String,
    #[allow(dead_code)]
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    /// RFC 8707 resource indicator
    pub resource: Option<String>,
}

/// Handler for `/oauth/authorize` - redirects to Keycloak.
pub async fn authorize_handler(
    State(state): State<Arc<McpOAuthState>>,
    Query(request): Query<AuthorizeRequest>,
) -> impl IntoResponse {
    // Use our configured Keycloak client_id, not the one from the MCP client
    let mut keycloak_auth_url = format!(
        "{}/protocol/openid-connect/auth?response_type={}&client_id={}&redirect_uri={}",
        state.keycloak_realm_url,
        urlencoding::encode(&request.response_type),
        urlencoding::encode(&state.keycloak_client_id),
        urlencoding::encode(&request.redirect_uri),
    );

    if let Some(scope) = &request.scope {
        keycloak_auth_url.push_str(&format!("&scope={}", urlencoding::encode(scope)));
    }

    if let Some(state_param) = &request.state {
        keycloak_auth_url.push_str(&format!("&state={}", urlencoding::encode(state_param)));
    }

    if let Some(code_challenge) = &request.code_challenge {
        keycloak_auth_url.push_str(&format!(
            "&code_challenge={}",
            urlencoding::encode(code_challenge)
        ));
    }

    if let Some(code_challenge_method) = &request.code_challenge_method {
        keycloak_auth_url.push_str(&format!(
            "&code_challenge_method={}",
            urlencoding::encode(code_challenge_method)
        ));
    }

    // Forward RFC 8707 resource indicator if present
    if let Some(resource) = &request.resource {
        keycloak_auth_url.push_str(&format!("&resource={}", urlencoding::encode(resource)));
    }

    tracing::info!("Redirecting to Keycloak: {}", keycloak_auth_url);

    Redirect::temporary(&keycloak_auth_url)
}

/// Parse the token request body into a list of key-value parameters.
fn parse_token_params(
    content_type: &str,
    body_str: &str,
) -> Result<Vec<(String, String)>, HttpError> {
    // Always try form-urlencoded first (OAuth 2.1 spec requires it).
    // Some clients send Content-Type: application/json but still use form-urlencoded body.
    let params: Vec<(String, String)> = form_urlencoded::parse(body_str.as_bytes())
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    if params.iter().any(|(k, _)| k == "grant_type") {
        tracing::info!("Parsed {} params from form body", params.len());
        return Ok(params);
    }

    if content_type.contains("application/json") {
        match serde_json::from_str::<serde_json::Value>(body_str) {
            Ok(json) => {
                let mut jp = Vec::new();
                if let Some(obj) = json.as_object() {
                    for (k, v) in obj {
                        let val = match v {
                            serde_json::Value::String(s) => s.clone(),
                            other => other.to_string(),
                        };
                        jp.push((k.clone(), val));
                    }
                }
                tracing::info!("Parsed {} params from JSON body", jp.len());
                return Ok(jp);
            }
            Err(e) => {
                tracing::error!("Failed to parse token request body: {}", e);
                return Err(HttpError::invalid_request("Invalid request body"));
            }
        }
    }

    tracing::info!(
        "Parsed {} params from form body (no grant_type found)",
        params.len()
    );
    Ok(params)
}

/// Inject the Keycloak client credentials into the parameter list.
fn inject_keycloak_credentials(params: &mut Vec<(String, String)>, state: &McpOAuthState) {
    for (key, value) in params.iter_mut() {
        if key == "client_id" {
            *value = state.keycloak_client_id.clone();
        }
    }

    if let Some(ref secret) = state.keycloak_client_secret
        && !params.iter().any(|(k, _)| k == "client_secret")
    {
        params.push(("client_secret".to_string(), secret.clone()));
    }
}

fn token_param_for_log(key: &str, value: &str) -> String {
    match key {
        "client_secret" | "client_assertion" | "code" | "code_verifier" | "password"
        | "refresh_token" => "***".to_string(),
        _ => value.to_string(),
    }
}

/// Forward a token request to Keycloak and return the raw response.
async fn forward_to_keycloak(
    state: &McpOAuthState,
    params: &[(String, String)],
) -> Result<(reqwest::StatusCode, HeaderMap, Vec<u8>), HttpError> {
    let keycloak_token_url = format!("{}/protocol/openid-connect/token", state.keycloak_realm_url);

    let new_body: String = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params)
        .finish();

    tracing::debug!("Token request to Keycloak: {}", keycloak_token_url);
    tracing::debug!(
        body_len = new_body.len(),
        "Forwarding redacted OAuth token request"
    );

    let result = state
        .http_client
        .post(&keycloak_token_url)
        .header("content-type", CONTENT_TYPE_FORM)
        .body(new_body)
        .send()
        .await;

    match result {
        Ok(response) => {
            let status = response.status();
            let headers = response.headers().clone();
            match response.bytes().await {
                Ok(body) => Ok((status, headers, body.to_vec())),
                Err(e) => {
                    tracing::error!("Failed to read Keycloak token response: {}", e);
                    Err(HttpError::server_error("Failed to read token response"))
                }
            }
        }
        Err(e) => {
            tracing::error!("Failed to contact Keycloak for token: {}", e);
            Err(HttpError::server_error(
                "Failed to contact authorization server",
            ))
        }
    }
}

/// Build an HTTP response from a Keycloak token response, forwarding status and content-type.
fn build_passthrough_response(
    status: reqwest::StatusCode,
    response_headers: &HeaderMap,
    body: &[u8],
) -> axum::response::Response {
    let mut builder = axum::response::Response::builder().status(status.as_u16());

    if let Some(ct) = response_headers.get("content-type") {
        builder = builder.header("content-type", ct);
    }

    builder.body(axum::body::Body::from(body.to_vec())).unwrap()
}

/// Handler for `/oauth/token` — proxies to Keycloak.
///
/// Dispatches to [`passthrough_token_handler`] or [`opaque_token_handler`]
/// depending on the configured [`TokenMode`].
///
/// Not reachable in [`TokenMode::ResourceServer`]: `mcp_oauth_router` does not
/// mount the route at all, so the request 404s in the router rather than
/// arriving here. The arm exists because the match must be exhaustive.
pub async fn token_handler(
    State(state): State<Arc<McpOAuthState>>,
    headers: HeaderMap,
    body: Body,
) -> Result<impl IntoResponse, HttpError> {
    match state.token_mode {
        TokenMode::Opaque => opaque_token_handler(state, headers, body).await,
        TokenMode::Passthrough => passthrough_token_handler(state, headers, body).await,
        TokenMode::ResourceServer => Err(HttpError::oauth_error(
            axum::http::StatusCode::NOT_FOUND,
            "invalid_request",
            "This server is a pure OAuth resource server and does not proxy token \
             requests. Use the token endpoint advertised by the authorization server.",
        )),
    }
}

/// Passthrough token handler: proxies the token request to Keycloak and
/// forwards the response as-is. On success, stores the token in the
/// `TokenStore` for downstream use.
async fn passthrough_token_handler(
    state: Arc<McpOAuthState>,
    headers: HeaderMap,
    body: Body,
) -> Result<axum::response::Response, HttpError> {
    let (mut params, grant_type) = read_token_request(body, &headers).await?;

    // On a refresh grant, remember which refresh token is being spent: Keycloak
    // rotates it away, so the entry it belongs to must not outlive this
    // exchange (see the cleanup below).
    let spent_refresh_token = (grant_type == "refresh_token")
        .then(|| {
            params
                .iter()
                .find(|(k, _)| k == "refresh_token")
                .map(|(_, v)| v.clone())
        })
        .flatten();

    inject_keycloak_credentials(&mut params, &state);

    let (status, response_headers, response_body) = forward_to_keycloak(&state, &params).await?;
    let body_str = String::from_utf8_lossy(&response_body);

    if status.is_success() {
        tracing::info!("Token exchange successful, status: {}", status);
        tracing::debug!(
            body_len = response_body.len(),
            "Received OAuth token response"
        );

        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body_str)
            && let Some(access_token) = json["access_token"].as_str()
        {
            // Key by the credential, not by `mcp-session-id`: the MCP
            // session does not exist yet at token-exchange time, so that
            // header is never present and every grant would land on the
            // shared `"default"` slot — each user overwriting the previous
            // one. The credential-derived key is what `bearer_auth_middleware`
            // recomputes from the bearer it receives, so it can adopt the
            // `refresh_token` captured here.
            //
            // The key comes from the token's `sid`/`sub` claims, not its bytes,
            // so a `refresh_token` grant for the same SSO session **replaces**
            // this entry rather than adding a sibling: the store keeps exactly
            // one live entry per grant, and its `refresh_token` is always the
            // most recently issued one (which is what Keycloak's refresh-token
            // rotation requires). Only a genuinely opaque, non-JWT access token
            // still falls back to a per-bytes key.
            let session_key = credential_session_key(access_token);

            // Retire the superseded grant *before* storing the new one. Its
            // refresh token has just been rotated away by Keycloak, but the
            // entry stayed adoptable by `bearer_auth_middleware`, which would
            // then drive a refresh into `invalid_grant` → a spurious 401.
            //
            // The key hashes the access token, so a rotation currently always
            // yields a different one; a claims-derived identity (`sid`/`sub`)
            // would map both grants onto the same key. The removal is skipped in
            // that case rather than deleting the grant this exchange is about to
            // write. Only the *spent* refresh token's index entry is dropped;
            // the new one is written below.
            if let Some(ref spent) = spent_refresh_token {
                if let Some(old_key) = state.token_store.resolve_grant_refresh(spent).await
                    && old_key != session_key
                {
                    tracing::debug!("Removing superseded passthrough grant '{}'", old_key);
                    state.token_store.remove_token(&old_key).await;
                }
                state.token_store.remove_grant_refresh(spent).await;
            }

            let refresh_token = json["refresh_token"].as_str().map(|s| s.to_string());
            let stored = StoredToken {
                access_token: access_token.to_string(),
                refresh_token: refresh_token.clone(),
                expires_at: json["expires_in"]
                    .as_u64()
                    .map(|secs| Instant::now() + Duration::from_secs(secs)),
                decoded_claims: None,
            };
            state
                .token_store
                .store_token(session_key.clone(), stored)
                .await;
            if let Some(ref refresh_token) = refresh_token {
                state
                    .token_store
                    .index_grant_refresh(refresh_token, &session_key)
                    .await;
            }
            tracing::debug!("Stored token for session '{}'", session_key);
        }
    } else {
        tracing::error!("Token exchange failed with status: {}", status);
    }

    Ok(build_passthrough_response(
        status,
        &response_headers,
        &response_body,
    ))
}

/// Opaque token handler: wraps [`passthrough_token_handler`]-style Keycloak
/// proxying with opaque token issuance. Refresh requests are intercepted
/// to resolve opaque tokens before contacting Keycloak.
async fn opaque_token_handler(
    state: Arc<McpOAuthState>,
    headers: HeaderMap,
    body: Body,
) -> Result<axum::response::Response, HttpError> {
    let (mut params, grant_type) = read_token_request(body, &headers).await?;

    // Intercept refresh_token grants: resolve the opaque refresh token
    // to the real Keycloak token before forwarding.
    if grant_type == "refresh_token" {
        return handle_opaque_refresh(&state, &params).await;
    }

    inject_keycloak_credentials(&mut params, &state);

    let (status, response_headers, response_body) = forward_to_keycloak(&state, &params).await?;
    let body_str = String::from_utf8_lossy(&response_body);

    if status.is_success() {
        tracing::info!("Token exchange successful, status: {}", status);
        tracing::debug!(
            body_len = response_body.len(),
            "Received OAuth token response"
        );

        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body_str)
            && let Some(access_token) = json["access_token"].as_str()
        {
            // Mint a fresh key per grant. `mcp-session-id` is never present
            // on a token exchange (the MCP session does not exist yet), so
            // reading it collapsed every user onto `"default"`: each new
            // login overwrote the previous user's Keycloak token *and*
            // revoked their opaque tokens via `store_opaque_mapping`.
            //
            // Unlike passthrough, this cannot be derived from the credential:
            // in opaque mode the client never sees the Keycloak token, and
            // the opaque tokens it does see rotate on every refresh while
            // this key must stay put. It is resolved from the opaque token
            // instead, by `TokenStore::resolve_opaque_access`.
            let session_key = uuid::Uuid::new_v4().to_string();
            let stored = StoredToken {
                access_token: access_token.to_string(),
                refresh_token: json["refresh_token"].as_str().map(|s| s.to_string()),
                expires_at: json["expires_in"]
                    .as_u64()
                    .map(|secs| Instant::now() + Duration::from_secs(secs)),
                decoded_claims: None,
            };
            state
                .token_store
                .store_token(session_key.clone(), stored)
                .await;
            tracing::debug!("Stored token for session '{}'", session_key);

            let kc_expires_in = json["expires_in"].as_u64();
            return Ok(build_opaque_response(&state, &session_key, kc_expires_in).await);
        }
    } else {
        tracing::error!("Token exchange failed with status: {}", status);
    }

    // Keycloak error or unparseable success — forward as-is
    Ok(build_passthrough_response(
        status,
        &response_headers,
        &response_body,
    ))
}

/// Read the request body, parse parameters, and extract the grant_type.
async fn read_token_request(
    body: Body,
    headers: &HeaderMap,
) -> Result<(Vec<(String, String)>, String), HttpError> {
    let body_bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!("Failed to read token request body: {}", e);
            return Err(HttpError::invalid_request("Invalid request body"));
        }
    };

    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body_str = String::from_utf8_lossy(&body_bytes);

    tracing::info!(
        content_type,
        body_len = body_bytes.len(),
        "OAuth token request received (body redacted)"
    );

    let params = parse_token_params(content_type, &body_str)?;

    for (k, v) in &params {
        let display_val = token_param_for_log(k, v);
        tracing::info!("  token param: {}={}", k, display_val);
    }

    let grant_type = params
        .iter()
        .find(|(k, _)| k == "grant_type")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();

    Ok((params, grant_type))
}

/// Build an opaque token response for the given session.
///
/// Generates new opaque UUIDs, stores the mapping, and returns a JSON
/// response with the opaque tokens. `keycloak_expires_in` is the
/// `expires_in` from the upstream Keycloak response; the opaque token
/// uses the minimum of that and `OPAQUE_ACCESS_TTL` so the client
/// refreshes before the server-side token actually expires.
async fn build_opaque_response(
    state: &McpOAuthState,
    session_key: &str,
    keycloak_expires_in: Option<u64>,
) -> axum::response::Response {
    let opaque_access = uuid::Uuid::new_v4().to_string();
    let opaque_refresh = uuid::Uuid::new_v4().to_string();

    let expires_in = match keycloak_expires_in {
        Some(kc) => kc.min(OPAQUE_ACCESS_TTL.as_secs()),
        None => OPAQUE_ACCESS_TTL.as_secs(),
    };

    state
        .token_store
        .store_opaque_mapping_with_access_ttl(
            session_key.to_string(),
            opaque_access.clone(),
            opaque_refresh.clone(),
            Duration::from_secs(expires_in),
        )
        .await;

    tracing::info!(
        "Issued opaque tokens for session '{}' (expires_in={}s)",
        session_key,
        expires_in
    );

    Json(serde_json::json!({
        "access_token": opaque_access,
        "token_type": "Bearer",
        "expires_in": expires_in,
        "refresh_token": opaque_refresh,
    }))
    .into_response()
}

/// Handle `grant_type=refresh_token` in Opaque mode.
///
/// 1. Resolve the opaque refresh token → session_id
/// 2. Check if the Keycloak token needs refreshing
/// 3. If so, refresh it upstream
/// 4. Issue new opaque tokens
async fn handle_opaque_refresh(
    state: &McpOAuthState,
    params: &[(String, String)],
) -> Result<axum::response::Response, HttpError> {
    let client_refresh_token = params
        .iter()
        .find(|(k, _)| k == "refresh_token")
        .map(|(_, v)| v.clone())
        .ok_or_else(|| HttpError::invalid_request("refresh_token required"))?;

    let session_id = state
        .token_store
        .resolve_opaque_refresh(&client_refresh_token)
        .await
        .ok_or_else(|| {
            tracing::warn!("Opaque refresh token not found, forcing re-auth");
            HttpError::unauthorized("Invalid refresh token")
        })?;

    tracing::info!("Opaque refresh for session '{}'", session_id);

    // get_token does auto-refresh if the Keycloak token is expired
    let token = match state.token_store.get_token(&session_id).await {
        Some(t) => t,
        None => {
            tracing::warn!(
                "Keycloak token expired and refresh failed for session '{}', forcing re-auth",
                session_id
            );
            state
                .token_store
                .remove_opaque_for_session(&session_id)
                .await;
            return Err(HttpError::unauthorized(
                "Session expired, re-authentication required",
            ));
        }
    };

    // Derive the remaining TTL from the real Keycloak token so the client
    // refreshes before it actually expires.
    let kc_expires_in = token.expires_at.map(|ea| {
        let now = Instant::now();
        if ea > now { (ea - now).as_secs() } else { 0 }
    });

    Ok(build_opaque_response(state, &session_id, kc_expires_in).await)
}

#[cfg(test)]
#[path = "proxy_tests.rs"]
mod tests;

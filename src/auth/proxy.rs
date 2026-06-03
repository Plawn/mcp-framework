//! OAuth proxy handlers for Keycloak integration.
//!
//! Handles:
//! - `/oauth/authorize` - Redirects to Keycloak
//! - `/oauth/token` - Proxies token exchange to Keycloak

use axum::{
    body::Body,
    extract::{Query, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect},
    Json,
};
use serde::Deserialize;
use std::sync::Arc;
use url::form_urlencoded;

use super::{McpOAuthState, StoredToken};
use super::config::TokenMode;
use crate::constants::{MCP_SESSION_ID_HEADER, DEFAULT_SESSION_ID, CONTENT_TYPE_FORM, OPAQUE_ACCESS_TTL};
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

/// Handler for `/oauth/token` - proxies to Keycloak.
pub async fn token_handler(
    State(state): State<Arc<McpOAuthState>>,
    headers: HeaderMap,
    body: Body,
) -> Result<impl IntoResponse, HttpError> {
    let keycloak_token_url = format!(
        "{}/protocol/openid-connect/token",
        state.keycloak_realm_url
    );

    // Read the body
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
        "Token request received: content-type={}, body_len={}, body={}",
        content_type,
        body_bytes.len(),
        body_str
    );

    // Always try form-urlencoded first (OAuth 2.1 spec requires it).
    // Some clients send Content-Type: application/json but still use form-urlencoded body.
    let mut params: Vec<(String, String)> = {
        let p: Vec<(String, String)> = form_urlencoded::parse(body_str.as_bytes())
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        // If form parsing got params with a grant_type, use them
        if p.iter().any(|(k, _)| k == "grant_type") {
            tracing::info!("Parsed {} params from form body", p.len());
            p
        } else if content_type.contains("application/json") {
            // Fallback: try JSON parsing
            match serde_json::from_str::<serde_json::Value>(&body_str) {
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
                    jp
                }
                Err(e) => {
                    tracing::error!("Failed to parse token request body: {}", e);
                    return Err(HttpError::invalid_request("Invalid request body"));
                }
            }
        } else {
            tracing::info!("Parsed {} params from form body (no grant_type found)", p.len());
            p
        }
    };

    // Log parsed params (redact sensitive values)
    for (k, v) in &params {
        let display_val = match k.as_str() {
            "client_secret" | "code" | "code_verifier" | "refresh_token" => "***".to_string(),
            _ => v.clone(),
        };
        tracing::info!("  token param: {}={}", k, display_val);
    }

    let grant_type = params
        .iter()
        .find(|(k, _)| k == "grant_type")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();

    // In Opaque mode with grant_type=refresh_token, intercept before forwarding
    // to resolve the opaque refresh token → real Keycloak refresh token.
    if state.token_mode == TokenMode::Opaque && grant_type == "refresh_token" {
        return handle_opaque_refresh(&state, &params).await;
    }

    // Replace client_id with our Keycloak client_id
    for (key, value) in params.iter_mut() {
        if key == "client_id" {
            *value = state.keycloak_client_id.clone();
        }
    }

    // Add client_secret if we have one and it's not already in the request
    if let Some(ref secret) = state.keycloak_client_secret
        && !params.iter().any(|(k, _)| k == "client_secret") {
            params.push(("client_secret".to_string(), secret.clone()));
        }

    // Rebuild the form body
    let new_body: String = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(&params)
        .finish();

    tracing::debug!("Token request to Keycloak: {}", keycloak_token_url);
    tracing::debug!("Forwarded body: {}", new_body);

    // Forward to Keycloak - always use form-urlencoded content type
    let keycloak_request = state
        .http_client
        .post(&keycloak_token_url)
        .header("content-type", CONTENT_TYPE_FORM);

    let result = keycloak_request.body(new_body).send().await;

    match result {
        Ok(response) => {
            let status = response.status();
            let response_headers = response.headers().clone();

            match response.bytes().await {
                Ok(body) => {
                    let body_str = String::from_utf8_lossy(&body);
                    if status.is_success() {
                        tracing::info!("Token exchange successful, status: {}", status);
                        tracing::debug!("Token response: {}", body_str);

                        let session_key = headers
                            .get(MCP_SESSION_ID_HEADER)
                            .and_then(|h| h.to_str().ok())
                            .unwrap_or(DEFAULT_SESSION_ID);

                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body_str)
                            && let Some(access_token) = json["access_token"].as_str() {
                                let stored = StoredToken {
                                    access_token: access_token.to_string(),
                                    refresh_token: json["refresh_token"].as_str().map(|s| s.to_string()),
                                    expires_at: json["expires_in"].as_u64().map(|secs| Instant::now() + Duration::from_secs(secs)),
                                    decoded_claims: None,
                                };
                                state.token_store.store_token(session_key.to_string(), stored).await;
                                tracing::debug!("Stored token for session '{}'", session_key);

                                // In Opaque mode, replace the response with opaque tokens
                                if state.token_mode == TokenMode::Opaque {
                                    let kc_expires_in = json["expires_in"].as_u64();
                                    return Ok(build_opaque_response(&state, session_key, kc_expires_in).await);
                                }
                            }
                    } else {
                        tracing::error!(
                            "Token exchange failed, status: {}, body: {}",
                            status,
                            body_str
                        );
                    }

                    let mut builder = axum::response::Response::builder().status(status);

                    // Copy content-type header
                    if let Some(ct) = response_headers.get("content-type") {
                        builder = builder.header("content-type", ct);
                    }

                    Ok(builder
                        .body(axum::body::Body::from(body.to_vec()))
                        .unwrap())
                }
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

    state
        .token_store
        .store_opaque_mapping(
            session_key.to_string(),
            opaque_access.clone(),
            opaque_refresh.clone(),
        )
        .await;

    let expires_in = match keycloak_expires_in {
        Some(kc) => kc.min(OPAQUE_ACCESS_TTL.as_secs()),
        None => OPAQUE_ACCESS_TTL.as_secs(),
    };

    tracing::info!("Issued opaque tokens for session '{}' (expires_in={}s)", session_key, expires_in);

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
            state.token_store.remove_opaque_for_session(&session_id).await;
            return Err(HttpError::unauthorized("Session expired, re-authentication required"));
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

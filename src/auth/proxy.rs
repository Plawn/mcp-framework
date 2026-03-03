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
};
use serde::Deserialize;
use std::sync::Arc;
use url::form_urlencoded;

use super::McpOAuthState;
use crate::http_util::HttpError;

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

    // Replace client_id with our Keycloak client_id
    for (key, value) in params.iter_mut() {
        if key == "client_id" {
            *value = state.keycloak_client_id.clone();
        }
    }

    // Add client_secret if we have one and it's not already in the request
    if let Some(ref secret) = state.keycloak_client_secret {
        if !params.iter().any(|(k, _)| k == "client_secret") {
            params.push(("client_secret".to_string(), secret.clone()));
        }
    }

    // Rebuild the form body
    let new_body: String = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params)
        .finish();

    tracing::debug!("Token request to Keycloak: {}", keycloak_token_url);
    tracing::debug!("Forwarded body: {}", new_body);

    // Forward to Keycloak - always use form-urlencoded content type
    let keycloak_request = state
        .http_client
        .post(&keycloak_token_url)
        .header("content-type", "application/x-www-form-urlencoded");

    let result = keycloak_request.body(new_body).send().await;

    match result {
        Ok(response) => {
            let status = response.status();
            let response_headers = response.headers().clone();

            match response.bytes().await {
                Ok(body) => {
                    // Log the token response for debugging
                    let body_str = String::from_utf8_lossy(&body);
                    if status.is_success() {
                        tracing::info!("Token exchange successful, status: {}", status);
                        tracing::debug!("Token response: {}", body_str);
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

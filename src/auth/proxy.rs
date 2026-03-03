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

    // Parse the form body and replace client_id with our configured one
    let body_str = String::from_utf8_lossy(&body_bytes);
    let mut params: Vec<(String, String)> = form_urlencoded::parse(body_str.as_bytes())
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

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

    // Forward to Keycloak
    let mut keycloak_request = state.http_client.post(&keycloak_token_url);

    // Copy relevant headers (but not authorization - we're using form-based auth)
    if let Some(content_type) = headers.get("content-type") {
        keycloak_request = keycloak_request.header("content-type", content_type);
    }

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

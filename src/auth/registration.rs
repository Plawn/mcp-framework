//! Dynamic Client Registration (RFC 7591).
//!
//! Proxies DCR requests to Keycloak with fallback for offline scenarios.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::McpOAuthState;
use crate::http_util::HttpError;

/// Dynamic Client Registration Request (RFC 7591)
#[derive(Debug, Deserialize)]
pub struct ClientRegistrationRequest {
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Option<Vec<String>>,
    pub response_types: Option<Vec<String>>,
    pub token_endpoint_auth_method: Option<String>,
    #[allow(dead_code)]
    pub scope: Option<String>,
}

/// Dynamic Client Registration Response
#[derive(Debug, Serialize)]
pub struct ClientRegistrationResponse {
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub token_endpoint_auth_method: String,
}

/// Build a fallback registration response when Keycloak DCR fails.
fn build_fallback_registration(request: &ClientRegistrationRequest) -> ClientRegistrationResponse {
    let client_id = request
        .client_name
        .clone()
        .unwrap_or_else(|| format!("mcp-{}", uuid::Uuid::new_v4()));

    ClientRegistrationResponse {
        client_id,
        client_secret: None,
        client_name: request.client_name.clone(),
        redirect_uris: request.redirect_uris.clone(),
        grant_types: vec!["authorization_code".to_string(), "refresh_token".to_string()],
        response_types: vec!["code".to_string()],
        token_endpoint_auth_method: "none".to_string(),
    }
}

/// Handler for Dynamic Client Registration (RFC 7591).
/// Proxies to Keycloak's DCR endpoint with fallback support.
pub async fn register_handler(
    State(state): State<Arc<McpOAuthState>>,
    Json(request): Json<ClientRegistrationRequest>,
) -> Result<impl IntoResponse, HttpError> {
    let keycloak_register_url = format!(
        "{}/clients-registrations/openid-connect",
        state.keycloak_realm_url
    );

    tracing::info!(
        "DCR request for client: {:?}, redirects: {:?}",
        request.client_name,
        request.redirect_uris
    );

    // Build request body for Keycloak using standard OIDC DCR fields (RFC 7591)
    let keycloak_request = serde_json::json!({
        "client_name": request.client_name.clone().unwrap_or_else(|| "mcp-client".to_string()),
        "redirect_uris": request.redirect_uris,
        "grant_types": request.grant_types.clone().unwrap_or_else(|| vec!["authorization_code".to_string(), "refresh_token".to_string()]),
        "response_types": request.response_types.clone().unwrap_or_else(|| vec!["code".to_string()]),
        "token_endpoint_auth_method": request.token_endpoint_auth_method.clone().unwrap_or_else(|| "none".to_string()),
    });

    // Try to register with Keycloak
    let result = state
        .http_client
        .post(&keycloak_register_url)
        .header("Content-Type", "application/json")
        .json(&keycloak_request)
        .send()
        .await;

    match result {
        Ok(response) => {
            if response.status().is_success() {
                match response.json::<serde_json::Value>().await {
                    Ok(keycloak_response) => {
                        // Keycloak returns client_id in standard OIDC format
                        let client_id = keycloak_response["client_id"]
                            .as_str()
                            .unwrap_or("unknown")
                            .to_string();
                        let client_secret = keycloak_response["client_secret"]
                            .as_str()
                            .map(|s| s.to_string());

                        tracing::info!("DCR successful, client_id: {}", client_id);

                        let response = ClientRegistrationResponse {
                            client_id,
                            client_secret,
                            client_name: request.client_name,
                            redirect_uris: request.redirect_uris,
                            grant_types: request
                                .grant_types
                                .unwrap_or_else(|| vec!["authorization_code".to_string()]),
                            response_types: request
                                .response_types
                                .unwrap_or_else(|| vec!["code".to_string()]),
                            token_endpoint_auth_method: request
                                .token_endpoint_auth_method
                                .unwrap_or_else(|| "none".to_string()),
                        };

                        Ok((StatusCode::CREATED, Json(response)))
                    }
                    Err(e) => {
                        tracing::error!("Failed to parse Keycloak DCR response: {}", e);
                        Err(HttpError::server_error("Failed to parse registration response"))
                    }
                }
            } else {
                let status = response.status();
                let error_body = response.text().await.unwrap_or_default();
                tracing::warn!(
                    "Keycloak DCR failed: {} - {}, using fallback client",
                    status,
                    error_body
                );

                // Keycloak DCR failed - return a fallback client
                let response = build_fallback_registration(&request);
                Ok((StatusCode::CREATED, Json(response)))
            }
        }
        Err(e) => {
            tracing::error!("Failed to contact Keycloak for DCR: {}", e);
            tracing::warn!("Keycloak unreachable for DCR, returning fallback client");

            // Fallback: return a generated client_id so the flow can continue
            let response = build_fallback_registration(&request);
            Ok((StatusCode::CREATED, Json(response)))
        }
    }
}

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
use crate::constants::{CONTENT_TYPE_JSON, MCP_CLIENT_ID_PREFIX};
use crate::http_util::HttpError;

/// Dynamic Client Registration Request (RFC 7591)
#[derive(Debug, Deserialize)]
pub struct ClientRegistrationRequest {
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Option<Vec<String>>,
    pub response_types: Option<Vec<String>>,
    pub token_endpoint_auth_method: Option<String>,
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
///
/// `configured_client_id` is `Some` only in [`TokenMode::ResourceServer`]. In
/// the proxying modes a fabricated id is harmless: `/oauth/authorize` rewrites
/// `client_id` to the configured one before forwarding to Keycloak, so whatever
/// is handed out here never reaches the authorization server. A pure resource
/// server proxies nothing — the client takes this id straight to Keycloak,
/// where an invented one does not exist — so it is handed the configured client
/// id instead. (As before, that Keycloak client must allow the client's
/// `redirect_uri`.)
///
/// [`TokenMode::ResourceServer`]: super::TokenMode::ResourceServer
fn build_fallback_registration(
    request: &ClientRegistrationRequest,
    configured_client_id: Option<&str>,
) -> ClientRegistrationResponse {
    let client_id = configured_client_id
        .map(str::to_string)
        .or_else(|| request.client_name.clone())
        .unwrap_or_else(|| format!("{}{}", MCP_CLIENT_ID_PREFIX, uuid::Uuid::new_v4()));

    ClientRegistrationResponse {
        client_id,
        client_secret: None,
        client_name: request.client_name.clone(),
        redirect_uris: request.redirect_uris.clone(),
        grant_types: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
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

    // See `build_fallback_registration`.
    let fallback_client_id =
        (!state.token_mode.is_stateful()).then(|| state.keycloak_client_id.clone());

    tracing::info!(
        "DCR request for client: {:?}, redirects: {:?}",
        request.client_name,
        request.redirect_uris
    );

    // Build request body for Keycloak using standard OIDC DCR fields (RFC 7591)
    let mut keycloak_request = serde_json::json!({
        "client_name": request.client_name.clone().unwrap_or_else(|| "mcp-client".to_string()),
        "redirect_uris": request.redirect_uris,
        "grant_types": request.grant_types.clone().unwrap_or_else(|| vec!["authorization_code".to_string(), "refresh_token".to_string()]),
        "response_types": request.response_types.clone().unwrap_or_else(|| vec!["code".to_string()]),
        "token_endpoint_auth_method": request.token_endpoint_auth_method.clone().unwrap_or_else(|| "none".to_string()),
    });

    // RFC 7591 §2 `scope`: what the client declares it will ask for, and what
    // Keycloak turns into the client's scope assignment. Dropping it was
    // invisible as long as the realm's default client scopes were a superset of
    // what the client wanted; it stops being invisible the moment a deployment
    // makes its MCP scopes *optional* (as `keycloak/mcp-realm.json` does), since
    // the registered client then does not carry them and the authorization
    // request asking for them fails `invalid_scope`.
    //
    // Forwarded only when non-empty: sending `"scope": ""` is not the same
    // request as sending none — Keycloak replaces the client's default scopes
    // as soon as the field is present, so an empty string would strip the
    // realm's defaults instead of leaving them alone (see
    // `keycloak/README.md`, "Enregistrement dynamique").
    if let Some(scope) = request.scope.as_deref().filter(|s| !s.trim().is_empty()) {
        keycloak_request["scope"] = serde_json::json!(scope);
    }

    // Try to register with Keycloak
    let result = state
        .http_client
        .post(&keycloak_register_url)
        .header("Content-Type", CONTENT_TYPE_JSON)
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
                        Err(HttpError::server_error(
                            "Failed to parse registration response",
                        ))
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
                let response = build_fallback_registration(&request, fallback_client_id.as_deref());
                Ok((StatusCode::CREATED, Json(response)))
            }
        }
        Err(e) => {
            tracing::error!("Failed to contact Keycloak for DCR: {}", e);
            tracing::warn!("Keycloak unreachable for DCR, returning fallback client");

            // Fallback: return a generated client_id so the flow can continue
            let response = build_fallback_registration(&request, fallback_client_id.as_deref());
            Ok((StatusCode::CREATED, Json(response)))
        }
    }
}

//! OAuth server metadata endpoints (RFC 8414 / RFC 9728).
//!
//! Handles:
//! - `/.well-known/oauth-authorization-server` - Authorization Server Metadata
//! - `/.well-known/oauth-protected-resource` - Protected Resource Metadata

use axum::{
    extract::State,
    response::{IntoResponse, Json},
};
use serde::Serialize;
use std::sync::Arc;

use super::McpOAuthState;

/// OAuth 2.0 Authorization Server Metadata (RFC 8414)
#[derive(Debug, Serialize)]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub registration_endpoint: String,
    pub scopes_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
}

/// OAuth 2.0 Protected Resource Metadata (RFC 9728)
/// Tells MCP clients where to authenticate.
#[derive(Debug, Serialize)]
pub struct ProtectedResourceMetadata {
    pub resource: String,
    pub authorization_servers: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub bearer_methods_supported: Vec<String>,
}

/// Shared state for well-known endpoints (Protected Resource Metadata).
///
/// `authorization_server` is where clients are told to authenticate. In the
/// proxying token modes that is this server (it fronts `/oauth/authorize` and
/// `/oauth/token`); in [`TokenMode::ResourceServer`](super::TokenMode::ResourceServer)
/// it is the Keycloak issuer itself, since the framework proxies nothing.
#[derive(Clone)]
pub struct WellKnownState {
    pub resource_url: String,
    pub authorization_server: String,
    pub scopes: Vec<String>,
}

/// Handler for `/.well-known/oauth-authorization-server`
///
/// A resource server is not an authorization server, so under RFC 9728 a
/// spec-current client never asks this server for this document — it reads the
/// protected-resource metadata and follows `authorization_servers` to the real
/// AS. The endpoint is kept because MCP 2025-03-26 clients still probe the
/// resource server for it, and answering `404` strands them.
///
/// What it answers depends on the token mode:
///
/// - **Passthrough / Opaque** — this server really does act as the
///   authorization server for the client: it proxies `/oauth/authorize` and
///   `/oauth/token`, so it advertises its own endpoints.
/// - **ResourceServer** — nothing is proxied any more; the document describes
///   **Keycloak** (`issuer`, `authorization_endpoint`, `token_endpoint`), so a
///   legacy client is sent straight to the real authorization server. The one
///   endpoint that stays ours is `registration_endpoint`: Keycloak's
///   registration endpoint serves no CORS headers, so a browser-based client
///   cannot call it directly and still needs the framework's translation.
///   Advertising Keycloak as the issuer also makes the advertised issuer match
///   the `iss` the tokens actually carry (RFC 9207).
pub async fn authorization_server_metadata_handler(
    State(state): State<Arc<McpOAuthState>>,
) -> impl IntoResponse {
    let realm = state.keycloak_realm_url.trim_end_matches('/');
    let (issuer, authorization_endpoint, token_endpoint) = if state.token_mode.is_stateful() {
        (
            state.public_url.clone(),
            format!("{}/oauth/authorize", state.public_url),
            format!("{}/oauth/token", state.public_url),
        )
    } else {
        (
            realm.to_string(),
            format!("{realm}/protocol/openid-connect/auth"),
            format!("{realm}/protocol/openid-connect/token"),
        )
    };

    let metadata = AuthorizationServerMetadata {
        issuer,
        authorization_endpoint,
        token_endpoint,
        registration_endpoint: format!("{}/oauth/register", state.public_url),
        scopes_supported: vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ],
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        code_challenge_methods_supported: vec!["S256".to_string()],
        token_endpoint_auth_methods_supported: vec![
            "client_secret_basic".to_string(),
            "client_secret_post".to_string(),
            "none".to_string(),
        ],
    };

    Json(metadata)
}

/// Handler for `/.well-known/oauth-protected-resource`
pub async fn protected_resource_metadata_handler(
    State(state): State<Arc<WellKnownState>>,
) -> impl IntoResponse {
    let metadata = ProtectedResourceMetadata {
        resource: state.resource_url.clone(),
        authorization_servers: vec![state.authorization_server.clone()],
        scopes_supported: state.scopes.clone(),
        bearer_methods_supported: vec!["header".to_string()],
    };

    Json(metadata)
}

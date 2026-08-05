mod config;
mod metadata;
mod middleware;
mod proxy;
mod registration;
mod routes;
mod store;
mod templates;

use axum::{routing::{get, post}, Router};
use std::sync::Arc;
use crate::constants::{OAUTH_REGISTER_PATH, OAUTH_AUTHORIZE_PATH, OAUTH_TOKEN_PATH};

pub use config::{AuthProvider, BasicAuthConfig, OAuthConfig, TokenMode};
pub use metadata::{
    authorization_server_metadata_handler, protected_resource_metadata_handler, WellKnownState,
};
pub use routes::{oauth_router, OAuthState};
pub use store::{ClaimsDecoderFn, RefreshConfig, StoredToken, TokenStore};

// Re-export middleware
#[allow(unused_imports)]
pub use middleware::{
    basic_auth_middleware, bearer_auth_middleware, strip_framework_session_header,
    AuthMiddlewareState, BasicAuthMiddlewareState, BearerToken,
};

/// State for MCP OAuth endpoints
#[derive(Clone)]
pub struct McpOAuthState {
    pub public_url: String,
    pub keycloak_realm_url: String,
    pub keycloak_client_id: String,
    pub keycloak_client_secret: Option<String>,
    pub http_client: reqwest::Client,
    pub token_store: TokenStore,
    pub token_mode: TokenMode,
}

impl McpOAuthState {
    pub fn from_oauth_config(
        oauth_config: &OAuthConfig,
        public_url: String,
        token_store: TokenStore,
        http_client: reqwest::Client,
    ) -> Self {
        Self {
            public_url,
            keycloak_realm_url: oauth_config.issuer_url.clone(),
            keycloak_client_id: oauth_config.client_id.clone(),
            keycloak_client_secret: oauth_config.client_secret.clone(),
            http_client,
            token_store,
            token_mode: oauth_config.token_mode.clone(),
        }
    }
}

/// Create the MCP OAuth router with register, authorize, and token endpoints.
pub fn mcp_oauth_router(state: McpOAuthState) -> Router {
    Router::new()
        .route(OAUTH_REGISTER_PATH, post(registration::register_handler))
        .route(OAUTH_AUTHORIZE_PATH, get(proxy::authorize_handler))
        .route(OAUTH_TOKEN_PATH, post(proxy::token_handler))
        .with_state(Arc::new(state))
}

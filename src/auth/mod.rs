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

pub use config::{AuthProvider, BasicAuthConfig, OAuthConfig};
pub use metadata::{
    authorization_server_metadata_handler, protected_resource_metadata_handler, WellKnownState,
};
pub use routes::{oauth_router, OAuthState};
pub use store::{RefreshConfig, StoredToken, TokenStore};

// Re-export middleware
#[allow(unused_imports)]
pub use middleware::{
    basic_auth_middleware, bearer_auth_middleware, AuthMiddlewareState, BasicAuthMiddlewareState,
    BearerToken,
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
}

/// Create the MCP OAuth router with register, authorize, and token endpoints.
pub fn mcp_oauth_router(state: McpOAuthState) -> Router {
    Router::new()
        .route("/register", post(registration::register_handler))
        .route("/authorize", get(proxy::authorize_handler))
        .route("/token", post(proxy::token_handler))
        .with_state(Arc::new(state))
}

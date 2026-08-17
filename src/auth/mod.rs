mod config;
mod jwks;
mod metadata;
mod middleware;
mod proxy;
mod registration;
mod routes;
mod store;
mod templates;

use crate::constants::{OAUTH_AUTHORIZE_PATH, OAUTH_REGISTER_PATH, OAUTH_TOKEN_PATH};
use axum::{
    Router,
    routing::{get, post},
};
use std::sync::Arc;

pub use config::{AuthProvider, BasicAuthConfig, OAuthConfig, TokenMode, UnknownTokenValidation};
pub use jwks::{JwksRejection, JwksValidator, ValidatedJwt};
pub use metadata::{
    WellKnownState, authorization_server_metadata_handler, protected_resource_metadata_handler,
};
pub use routes::{OAuthState, oauth_router};
pub use store::{ClaimsDecoderFn, RefreshConfig, StoredToken, TokenStore};

// Re-export middleware
#[allow(unused_imports)]
pub use middleware::{
    AuthMiddlewareState, BasicAuthMiddlewareState, BearerToken, basic_auth_middleware,
    bearer_auth_middleware, strip_framework_session_header,
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

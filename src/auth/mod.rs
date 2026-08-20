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
pub use proxy::not_proxied_handler;
pub use routes::{OAuthState, oauth_router};
pub use store::{ClaimsDecoderFn, RefreshConfig, StoredToken, TokenStore};

// Re-export middleware
#[allow(unused_imports)]
pub use middleware::{
    AuthMiddlewareState, BasicAuthMiddlewareState, BearerToken, RequestToken,
    basic_auth_middleware, bearer_auth_middleware, strip_framework_session_header,
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

/// Create the MCP OAuth router.
///
/// In the proxying token modes this is register + authorize + token.
///
/// In [`TokenMode::ResourceServer`] only `/oauth/register` is mounted:
///
/// - `/oauth/token` is the whole point of the mode — the framework must never
///   see the grant, so it cannot proxy the exchange.
/// - `/oauth/authorize` goes with it. The proxy rewrites `client_id` to the
///   configured `OAUTH_CLIENT_ID`, so the authorization code it returns is
///   bound to *that* client; the client then calls Keycloak's token endpoint
///   directly with its own `client_id` and gets `invalid_grant`. Half a proxied
///   flow is worse than none, so the client is pointed at Keycloak's
///   authorization endpoint through the advertised metadata instead.
/// - `/oauth/register` stays: Keycloak's `clients-registrations` endpoint sends
///   no CORS headers, so a browser-based MCP client cannot perform dynamic
///   client registration against it directly.
///
/// The two retired paths answer `404` with a reason rather than being left out
/// of the router — see [`proxy::not_proxied_handler`].
pub fn mcp_oauth_router(state: McpOAuthState) -> Router {
    let stateful = state.token_mode.is_stateful();
    let router = Router::new().route(OAUTH_REGISTER_PATH, post(registration::register_handler));

    let router = if stateful {
        router
            .route(OAUTH_AUTHORIZE_PATH, get(proxy::authorize_handler))
            .route(OAUTH_TOKEN_PATH, post(proxy::token_handler))
    } else {
        router
            .route(OAUTH_AUTHORIZE_PATH, get(proxy::not_proxied_handler))
            .route(OAUTH_TOKEN_PATH, post(proxy::not_proxied_handler))
    };

    router.with_state(Arc::new(state))
}

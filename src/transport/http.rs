use std::sync::Arc;
use std::time::Duration;

use axum::{routing::get, Router};
use rmcp::transport::streamable_http_server::{StreamableHttpService, session::local::LocalSessionManager};
use rmcp::ServerHandler;

use crate::auth::{
    authorization_server_metadata_handler, basic_auth_middleware, bearer_auth_middleware,
    mcp_oauth_router, oauth_router, protected_resource_metadata_handler, AuthMiddlewareState,
    AuthProvider, BasicAuthMiddlewareState, McpOAuthState, OAuthState, RefreshConfig, TokenStore,
    WellKnownState,
};

/// Configuration for building the HTTP app
pub struct HttpAppConfig<F> {
    pub public_url: String,
    pub bind_addr: String,
    pub auth: AuthProvider,
    pub server_factory: F,
    pub app_name: String,
}

/// Build the axum router with all routes configured.
/// This is extracted for testability - tests can spawn this app on a test server.
pub fn build_app<F, S>(config: HttpAppConfig<F>) -> Router
where
    F: Fn(TokenStore) -> S + Clone + Send + Sync + 'static,
    S: ServerHandler + Send + 'static,
{
    // Create token store based on auth mode
    let token_store = match &config.auth {
        AuthProvider::OAuth(oauth_config) => {
            let refresh_config = RefreshConfig {
                client_id: oauth_config.client_id.clone(),
                client_secret: oauth_config.client_secret.clone(),
                token_url: format!(
                    "{}/protocol/openid-connect/token",
                    oauth_config.issuer_url.trim_end_matches('/')
                ),
            };
            TokenStore::with_refresh_config(refresh_config)
        }
        _ => TokenStore::new(),
    };

    // Start building the router
    let mut app = Router::new();

    // OAuth-specific routes (only registered for AuthProvider::OAuth)
    if let AuthProvider::OAuth(oauth_config) = &config.auth {
        let http_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to build HTTP client");

        let well_known_state = Arc::new(WellKnownState {
            resource_url: config.public_url.clone(),
            authorization_server: config.public_url.clone(),
            scopes: oauth_config.scopes.clone(),
        });

        let well_known_state_mcp = Arc::new(WellKnownState {
            resource_url: format!("{}/mcp", config.public_url),
            authorization_server: config.public_url.clone(),
            scopes: oauth_config.scopes.clone(),
        });

        let mcp_oauth_state = McpOAuthState {
            public_url: config.public_url.clone(),
            keycloak_realm_url: oauth_config.issuer_url.clone(),
            keycloak_client_id: oauth_config.client_id.clone(),
            keycloak_client_secret: Some(oauth_config.client_secret.clone()),
            http_client: http_client.clone(),
        };

        let oauth_state = OAuthState {
            config: oauth_config.clone(),
            store: token_store.clone(),
            http_client,
            app_name: config.app_name.clone(),
        };

        app = app
            .route(
                "/.well-known/oauth-protected-resource",
                get(protected_resource_metadata_handler).with_state(well_known_state.clone()),
            )
            .route(
                "/.well-known/oauth-protected-resource/mcp",
                get(protected_resource_metadata_handler).with_state(well_known_state_mcp),
            )
            .route(
                "/.well-known/oauth-authorization-server",
                get(authorization_server_metadata_handler)
                    .with_state(Arc::new(mcp_oauth_state.clone())),
            )
            .nest(
                "/oauth",
                mcp_oauth_router(mcp_oauth_state).merge(oauth_router(oauth_state)),
            );
    }

    // Create MCP service
    let factory = config.server_factory;
    let token_store_clone = token_store.clone();
    let mcp_service = StreamableHttpService::new(
        move || Ok(factory(token_store_clone.clone())),
        LocalSessionManager::default().into(),
        Default::default(),
    );

    // Build MCP router with appropriate auth middleware
    let mcp_router = match &config.auth {
        AuthProvider::None => {
            Router::new().fallback_service(mcp_service)
        }
        AuthProvider::Basic(basic_config) => {
            let basic_state = Arc::new(BasicAuthMiddlewareState {
                config: basic_config.clone(),
                token_store: token_store.clone(),
            });
            Router::new()
                .fallback_service(mcp_service)
                .layer(axum::middleware::from_fn_with_state(
                    basic_state,
                    basic_auth_middleware,
                ))
        }
        AuthProvider::OAuth(_) => {
            let auth_middleware_state = Arc::new(AuthMiddlewareState {
                resource_url: format!("{}/mcp", config.public_url),
                resource_metadata_url: format!("{}/.well-known/oauth-protected-resource/mcp", config.public_url),
                token_store: token_store.clone(),
            });
            Router::new()
                .fallback_service(mcp_service)
                .layer(axum::middleware::from_fn_with_state(
                    auth_middleware_state,
                    bearer_auth_middleware,
                ))
        }
    };

    let app = app.nest("/mcp", mcp_router);

    // Add CORS for browser access
    let cors = tower_http::cors::CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods(tower_http::cors::Any)
        .allow_headers(tower_http::cors::Any)
        .expose_headers(tower_http::cors::Any)
        .allow_credentials(false);

    // Add request/response tracing to log every HTTP request
    let trace_layer = tower_http::trace::TraceLayer::new_for_http()
        .make_span_with(|request: &axum::http::Request<_>| {
            tracing::info_span!(
                "http_request",
                method = %request.method(),
                uri = %request.uri(),
            )
        })
        .on_request(|request: &axum::http::Request<_>, _span: &tracing::Span| {
            tracing::info!(
                method = %request.method(),
                uri = %request.uri(),
                ">> incoming request"
            );
        })
        .on_response(
            |response: &axum::http::Response<_>,
             latency: std::time::Duration,
             _span: &tracing::Span| {
                tracing::info!(
                    status = %response.status(),
                    latency_ms = latency.as_millis(),
                    "<< response"
                );
            },
        );

    app.layer(cors).layer(trace_layer)
}

/// Run the MCP server with HTTP transport (for remote connections)
pub async fn run_http<F, S>(config: HttpAppConfig<F>) -> anyhow::Result<()>
where
    F: Fn(TokenStore) -> S + Clone + Send + Sync + 'static,
    S: ServerHandler + Send + 'static,
{
    let bind_addr: std::net::SocketAddr = config.bind_addr.parse()?;

    let public_url = config.public_url.clone();

    tracing::info!("Starting MCP server on {}", bind_addr);
    tracing::info!("Public URL: {}", public_url);

    match &config.auth {
        AuthProvider::None => {
            tracing::info!("Auth: none (MCP endpoint is open)");
        }
        AuthProvider::Basic(_) => {
            tracing::info!("Auth: HTTP Basic");
        }
        AuthProvider::OAuth(oauth_config) => {
            tracing::info!("Auth: OAuth with issuer {}", oauth_config.issuer_url);
            tracing::info!(
                "OAuth discovery: {}/.well-known/oauth-protected-resource",
                public_url
            );
            tracing::info!(
                "OAuth server:    {}/.well-known/oauth-authorization-server",
                public_url
            );
            tracing::info!("OAuth endpoints: /oauth/register, /oauth/authorize, /oauth/token");
            tracing::info!("Legacy OAuth:    /oauth/login, /oauth/callback, /oauth/status");
        }
    }

    tracing::info!("MCP server listening on http://{}", bind_addr);
    tracing::info!("MCP endpoint: http://{}/mcp", bind_addr);

    let app = build_app(config);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;

    // Graceful shutdown with timeout
    let shutdown_signal = async {
        tokio::signal::ctrl_c().await.unwrap();
        tracing::info!("Shutdown signal received, stopping server...");

        // Give connections 5 seconds to close gracefully, then force exit
        tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            tracing::warn!("Graceful shutdown timed out, forcing exit");
            std::process::exit(0);
        });
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await?;

    tracing::info!("Server stopped");
    Ok(())
}

use std::sync::Arc;
use std::time::Duration;

use axum::{routing::get, Router};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService,
    session::local::LocalSessionManager,
};
use rmcp::ServerHandler;

use crate::auth::{
    authorization_server_metadata_handler, basic_auth_middleware, bearer_auth_middleware,
    mcp_oauth_router, oauth_router, protected_resource_metadata_handler, AuthMiddlewareState,
    AuthProvider, BasicAuthMiddlewareState, McpOAuthState, OAuthState, RefreshConfig, TokenStore,
    WellKnownState,
};
use crate::audit::ToolCallLogger;
use crate::capability::{AccessValidator, CapabilityFilter, CapabilityRegistry, DynamicHandler, HandlerContext};
use crate::session::SessionStore;

/// Configuration for building the HTTP app
pub struct HttpAppConfig<F, T: Send + Sync + Default + Clone + 'static = ()> {
    pub public_url: String,
    pub bind_addr: String,
    pub auth: AuthProvider,
    pub server_factory: F,
    pub app_name: String,
    /// Optional dynamic capability registry.
    pub capability_registry: Option<CapabilityRegistry>,
    /// Optional capability filter for per-session visibility.
    pub capability_filter: Option<Arc<dyn CapabilityFilter>>,
    /// Optional access validator for pre-execution authorization.
    pub access_validator: Option<Arc<dyn AccessValidator>>,
    /// Optional global claims decoder.
    pub claims_decoder: Option<crate::auth::ClaimsDecoderFn>,
    /// Session store for typed per-session data.
    pub session_store: SessionStore<T>,
    /// Optional tool call audit logger.
    pub tool_call_logger: Option<Arc<dyn ToolCallLogger>>,
    /// Extra routes merged into the auth-wrapped MCP router.
    ///
    /// Routes registered here sit inside the same `AuthProvider` middleware as
    /// the MCP fallback, so consumers can expose REST endpoints that share the
    /// OAuth / Basic auth story with `/mcp` without wiring a second middleware.
    /// OAuth discovery (`/.well-known/*`) and `/oauth/*` routes remain outside
    /// this layer and stay publicly accessible.
    ///
    /// Avoid registering `/mcp` here — it will silently shadow the MCP fallback.
    pub extra_routes: Option<Router>,
}

/// Wrap a router with the appropriate auth middleware based on the auth provider.
fn wrap_auth_middleware(
    router: Router,
    auth: &AuthProvider,
    public_url: &str,
    token_store: &TokenStore,
) -> Router {
    match auth {
        AuthProvider::None => router,
        AuthProvider::Basic(basic_config) => {
            let basic_state = Arc::new(BasicAuthMiddlewareState {
                config: basic_config.clone(),
                token_store: token_store.clone(),
            });
            router.layer(axum::middleware::from_fn_with_state(
                basic_state,
                basic_auth_middleware,
            ))
        }
        AuthProvider::OAuth(_) => {
            let auth_middleware_state = Arc::new(AuthMiddlewareState {
                resource_url: format!("{}/mcp", public_url),
                resource_metadata_url: format!(
                    "{}/.well-known/oauth-protected-resource/mcp",
                    public_url
                ),
                token_store: token_store.clone(),
            });
            router.layer(axum::middleware::from_fn_with_state(
                auth_middleware_state,
                bearer_auth_middleware,
            ))
        }
    }
}

/// Build the axum router with all routes configured.
///
/// Returns `(Router, TokenStore)` so the caller can start a cleanup task on
/// the token store and abort it on shutdown.
pub fn build_app<F, S, T>(config: HttpAppConfig<F, T>) -> (Router, TokenStore)
where
    F: Fn() -> S + Clone + Send + Sync + 'static,
    S: ServerHandler + Send + 'static,
    T: Send + Sync + Default + Clone + 'static,
{
    // Create token store based on auth mode
    let mut token_store = match &config.auth {
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

    // Apply global claims decoder if configured
    if let Some(decoder) = config.claims_decoder {
        token_store.claims_decoder = Some(decoder);
    }

    // Start building the router
    let mut app = Router::new();

    // OAuth-specific routes (only registered for AuthProvider::OAuth)
    if let AuthProvider::OAuth(oauth_config) = &config.auth {
        let http_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to build HTTP client");

        // Both well-known endpoints describe the same protected resource: the MCP endpoint at /mcp
        let well_known_state = Arc::new(WellKnownState {
            resource_url: format!("{}/mcp", config.public_url),
            authorization_server: config.public_url.clone(),
            scopes: oauth_config.scopes.clone(),
        });

        let mcp_oauth_state = McpOAuthState {
            public_url: config.public_url.clone(),
            keycloak_realm_url: oauth_config.issuer_url.clone(),
            keycloak_client_id: oauth_config.client_id.clone(),
            keycloak_client_secret: oauth_config.client_secret.clone(),
            http_client: http_client.clone(),
            token_store: token_store.clone(),
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
                get(protected_resource_metadata_handler).with_state(well_known_state.clone()),
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

    // Create MCP service / router with Streamable HTTP transport
    let factory = config.server_factory;
    let registry = config.capability_registry.unwrap_or_default();
    let filter = config.capability_filter;
    let access_validator = config.access_validator;
    let token_store_clone = token_store.clone();
    let session_store = config.session_store;
    let tool_call_logger = config.tool_call_logger;

    // Disable SSE priming events (sse_retry: None) for broad client compatibility.
    // rmcp 1.x defaults to sending empty SSE "priming" frames before each response,
    // which some MCP clients (e.g. Claude) misinterpret, causing the connection to
    // close before the tool result is delivered.
    //
    // rmcp 1.5 validates the Host header against an allowlist (default: loopback
    // only). For public deployments we derive the allowed host from PUBLIC_URL.
    let mut allowed_hosts: Vec<String> = vec![
        "localhost".into(),
        "127.0.0.1".into(),
        "::1".into(),
    ];
    if let Ok(url) = url::Url::parse(&config.public_url) {
        if let Some(host) = url.host_str() {
            let authority = match url.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            };
            if !allowed_hosts.contains(&authority) {
                allowed_hosts.push(authority);
            }
        }
    }
    tracing::info!(allowed_hosts = ?allowed_hosts, "MCP host validation configured");
    let mcp_config = StreamableHttpServerConfig::default()
        .with_sse_retry(None)
        .with_allowed_hosts(allowed_hosts);

    let mcp_service = StreamableHttpService::new(
        move || {
            let server = factory();
            Ok(DynamicHandler::new(
                server,
                registry.clone(),
                HandlerContext {
                    filter: filter.clone(),
                    access_validator: access_validator.clone(),
                    token_store: token_store_clone.clone(),
                    session_store: session_store.clone(),
                    tool_call_logger: tool_call_logger.clone(),
                },
            ))
        },
        LocalSessionManager::default().into(),
        mcp_config,
    );

    let mcp_router = {
        let base = config
            .extra_routes
            .unwrap_or_default()
            .fallback_service(mcp_service);
        wrap_auth_middleware(base, &config.auth, &config.public_url, &token_store)
    };

    // Use fallback_service so the MCP handler responds at ANY path (/, /mcp, etc.).
    // Specific routes (/.well-known/*, /oauth/*) take priority over the fallback.
    let app = app.fallback_service(mcp_router);

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
            let host = request
                .headers()
                .get(axum::http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("-");
            tracing::info_span!(
                "http_request",
                method = %request.method(),
                uri = %request.uri(),
                host = %host,
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
                let status = response.status();
                if status == axum::http::StatusCode::FORBIDDEN {
                    tracing::warn!(
                        status = %status,
                        latency_ms = latency.as_millis(),
                        "<< request rejected (check allowed_hosts if Host header mismatch)"
                    );
                } else {
                    tracing::info!(
                        status = %status,
                        latency_ms = latency.as_millis(),
                        "<< response"
                    );
                }
            },
        );

    (app.layer(cors).layer(trace_layer), token_store)
}

/// Run the MCP server with HTTP transport (for remote connections)
pub async fn run_http<F, S, T>(config: HttpAppConfig<F, T>) -> anyhow::Result<()>
where
    F: Fn() -> S + Clone + Send + Sync + 'static,
    S: ServerHandler + Send + 'static,
    T: Send + Sync + Default + Clone + 'static,
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
    tracing::info!("MCP endpoint: http://{} (also accepts /mcp)", bind_addr);

    // Start session cleanup task
    let session_cleanup = config.session_store.start_cleanup_task();

    let (app, token_store) = build_app(config);

    // Start token cleanup task (purge expired tokens every 5 minutes)
    let token_cleanup = token_store.start_cleanup_task(Duration::from_secs(300));

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;

    // Graceful shutdown with timeout
    let shutdown_signal = async move {
        tokio::signal::ctrl_c().await.unwrap();
        tracing::info!("Shutdown signal received, stopping server...");

        // Stop cleanup tasks
        session_cleanup.abort();
        token_cleanup.abort();

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

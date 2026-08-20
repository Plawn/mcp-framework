use std::sync::Arc;

use axum::{Router, routing::get};
use rmcp::ServerHandler;
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};

use crate::audit::ToolCallLogger;
use crate::auth::{
    AuthMiddlewareState, AuthProvider, BasicAuthMiddlewareState, McpOAuthState, OAuthConfig,
    OAuthState, RefreshConfig, TokenStore, WellKnownState, authorization_server_metadata_handler,
    basic_auth_middleware, bearer_auth_middleware, mcp_oauth_router, oauth_router,
    protected_resource_metadata_handler, strip_framework_session_header,
};
use crate::capability::{
    AccessValidator, CapabilityFilter, CapabilityRegistry, DynamicHandler, HandlerContext,
};
use crate::constants::{
    CLEANUP_INTERVAL, GRACEFUL_SHUTDOWN_TIMEOUT, HTTP_REQUEST_TIMEOUT, OAUTH_MOUNT,
};
use crate::persistence::PersistenceBackend;
use crate::session::{SessionData, SessionStore};
use crate::transport::protocol::{ProtocolLifecyclePolicy, normalize_protocol_lifecycle};
use crate::transport::session_persistence::TransportSessionStore;

/// Configuration for building the HTTP app
pub struct HttpAppConfig<F, T: SessionData = ()> {
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
    /// Optional persistence backend shared by tokens, dynamic capabilities,
    /// application sessions, and rmcp transport sessions.
    pub persistence: Option<Arc<dyn PersistenceBackend>>,
    /// Streamable HTTP lifecycle compatibility policy.
    pub protocol_lifecycle: ProtocolLifecyclePolicy,
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
    /// Public (unauthenticated) routes — health checks, probes, metrics.
    ///
    /// Unlike [`extra_routes`](Self::extra_routes), these are merged **outside**
    /// the auth middleware (like the OAuth discovery routes) so they stay
    /// reachable without credentials. Set via
    /// [`McpAppBuilder::public_routes`](crate::McpAppBuilder::public_routes).
    pub public_routes: Option<Router>,
}

/// Wrap a router with the appropriate auth middleware based on the auth provider.
fn wrap_auth_middleware(
    router: Router,
    auth: &AuthProvider,
    public_url: &str,
    token_store: &TokenStore,
) -> Router {
    let router = match auth {
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
        AuthProvider::OAuth(oauth_config) => {
            let auth_middleware_state = Arc::new(AuthMiddlewareState {
                resource_url: format!("{}/mcp", public_url),
                resource_metadata_url: format!(
                    "{}/.well-known/oauth-protected-resource/mcp",
                    public_url
                ),
                token_store: token_store.clone(),
                token_mode: oauth_config.token_mode.clone(),
            });
            router.layer(axum::middleware::from_fn_with_state(
                auth_middleware_state,
                bearer_auth_middleware,
            ))
        }
    };

    // Added last, so it runs first — before any auth middleware can consult or
    // write the header. Without it a client could set the framework session
    // header itself and bind its request to another user's session; under
    // `AuthProvider::None` no auth middleware runs to overwrite it at all.
    router.layer(axum::middleware::from_fn(strip_framework_session_header))
}

/// Build OAuth discovery and authorization routes.
fn setup_oauth_routes(
    oauth_config: &OAuthConfig,
    public_url: &str,
    app_name: &str,
    token_store: &TokenStore,
) -> Router {
    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(HTTP_REQUEST_TIMEOUT)
        .build()
        .expect("Failed to build HTTP client");

    // RFC 9728: where clients are told to authenticate. A pure resource server
    // proxies nothing, so it names the real authorization server; the proxying
    // modes name themselves, because they front the authorize/token endpoints.
    let authorization_server = if oauth_config.token_mode.is_stateful() {
        public_url.to_string()
    } else {
        oauth_config.issuer_url.trim_end_matches('/').to_string()
    };

    let well_known_state = Arc::new(WellKnownState {
        resource_url: format!("{}/mcp", public_url),
        authorization_server,
        scopes: oauth_config.scopes.clone(),
    });

    let mcp_oauth_state = McpOAuthState::from_oauth_config(
        oauth_config,
        public_url.to_string(),
        token_store.clone(),
        http_client.clone(),
    );

    // The browser login flow (`/oauth/login`, `/oauth/callback`, `/oauth/status`)
    // performs a server-side code exchange and writes the grant into the
    // `TokenStore` — exactly the state a pure resource server abolishes. It is
    // therefore not mounted in `TokenMode::ResourceServer`.
    let oauth_routes = if oauth_config.token_mode.is_stateful() {
        let oauth_state = OAuthState {
            config: oauth_config.clone(),
            store: token_store.clone(),
            http_client,
            app_name: app_name.to_string(),
        };
        mcp_oauth_router(mcp_oauth_state.clone()).merge(oauth_router(oauth_state))
    } else {
        mcp_oauth_router(mcp_oauth_state.clone())
    };

    Router::new()
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
        .nest(OAUTH_MOUNT, oauth_routes)
}

/// Build the axum router with all routes configured.
///
/// Returns `(Router, TokenStore)` so the caller can start a cleanup task on
/// the token store and abort it on shutdown.
pub fn build_app<F, S, T>(config: HttpAppConfig<F, T>) -> (Router, TokenStore, CapabilityRegistry)
where
    F: Fn() -> S + Clone + Send + Sync + 'static,
    S: ServerHandler + Send + 'static,
    T: SessionData,
{
    let transport_session_ttl = config.session_store.ttl();
    let transport_persistence = config.persistence.clone();

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
            let mut store = TokenStore::with_refresh_config(refresh_config);
            // Lets a bearer the proxy never issued be validated against the
            // issuer's published keys — the only path open when the configured
            // OAuth client is public and Keycloak refuses introspection to it.
            store.configure_unknown_bearer_validation(oauth_config);
            store
        }
        _ => TokenStore::new(),
    };

    if let Some(decoder) = config.claims_decoder {
        token_store.claims_decoder = Some(decoder);
    }

    let mut registry = config.capability_registry.unwrap_or_default();
    if let Some(ref backend) = config.persistence {
        token_store.set_persistence(backend.clone());
        registry.set_persistence(backend.clone());
    }

    let mut app = Router::new();

    // Public routes (health, probes, metrics) — merged outside the auth layer
    // so they stay reachable without credentials. Take priority over the MCP
    // fallback for their paths.
    if let Some(public_routes) = config.public_routes {
        app = app.merge(public_routes);
    }

    if let AuthProvider::OAuth(oauth_config) = &config.auth {
        app = app.merge(setup_oauth_routes(
            oauth_config,
            &config.public_url,
            &config.app_name,
            &token_store,
        ));
    }

    // Create MCP service / router with Streamable HTTP transport
    let factory = config.server_factory;
    let registry_ref = registry.clone();
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
    let mut allowed_hosts: Vec<String> = vec!["localhost".into(), "127.0.0.1".into(), "::1".into()];
    if let Ok(url) = url::Url::parse(&config.public_url)
        && let Some(host) = url.host_str()
    {
        let authority = match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        };
        if !allowed_hosts.contains(&authority) {
            allowed_hosts.push(authority);
        }
    }
    tracing::info!(allowed_hosts = ?allowed_hosts, "MCP host validation configured");
    let mut mcp_config = StreamableHttpServerConfig::default()
        .with_sse_retry(None)
        .with_allowed_hosts(allowed_hosts)
        // Modern requests are self-contained. Require both the HTTP header and
        // the SEP-2575 request metadata instead of silently treating malformed
        // modern traffic as an older protocol.
        .with_stateless_protocol_metadata_required(true);

    if let Some(backend) = transport_persistence {
        mcp_config.session_store = Some(Arc::new(TransportSessionStore::new(
            backend,
            transport_session_ttl,
        )));
    }

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
                    loopback_identity: None,
                },
            ))
        },
        LocalSessionManager::default().into(),
        mcp_config,
    );

    // Scope lifecycle normalization to the MCP fallback. Extra application
    // routes must receive their request bodies byte-for-byte unchanged.
    let mcp_fallback =
        Router::new()
            .fallback_service(mcp_service)
            .layer(axum::middleware::from_fn_with_state(
                config.protocol_lifecycle,
                normalize_protocol_lifecycle,
            ));

    let mcp_router = {
        let base = config
            .extra_routes
            .unwrap_or_default()
            .fallback_service(mcp_fallback);
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

    (
        app.layer(cors).layer(trace_layer),
        token_store,
        registry_ref,
    )
}

/// Run the MCP server with HTTP transport (for remote connections)
pub async fn run_http<F, S, T>(config: HttpAppConfig<F, T>) -> anyhow::Result<()>
where
    F: Fn() -> S + Clone + Send + Sync + 'static,
    S: ServerHandler + Send + 'static,
    T: SessionData,
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
            tracing::info!("Token mode: {:?}", oauth_config.token_mode);
            tracing::info!(
                "OAuth discovery: {}/.well-known/oauth-protected-resource",
                public_url
            );
            tracing::info!(
                "OAuth server:    {}/.well-known/oauth-authorization-server",
                public_url
            );
            if oauth_config.token_mode.is_stateful() {
                tracing::info!(
                    "OAuth endpoints: /oauth/register, /oauth/authorize, /oauth/token"
                );
                tracing::info!("Legacy OAuth:    /oauth/login, /oauth/callback, /oauth/status");
            } else {
                tracing::info!("OAuth endpoints: /oauth/register (DCR translation only)");
                tracing::info!(
                    "Pure resource server: authorize/token/login are NOT proxied; clients \
                     authenticate directly against {}",
                    oauth_config.issuer_url
                );
                tracing::info!(
                    "Accepted audiences: {}",
                    oauth_config.expected_audiences.join(", ")
                );
            }
        }
    }

    tracing::info!("MCP server listening on http://{}", bind_addr);
    tracing::info!("MCP endpoint: http://{} (also accepts /mcp)", bind_addr);

    // Start session cleanup task
    let session_cleanup = config.session_store.start_cleanup_task();

    let (app, token_store, registry) = build_app(config);

    token_store
        .load_persisted()
        .await
        .map_err(|e| anyhow::anyhow!("failed to load persisted tokens: {e}"))?;

    registry
        .load_persisted_versions()
        .await
        .map_err(|e| anyhow::anyhow!("failed to load persisted capability versions: {e}"))?;

    // Start token cleanup task (purge expired tokens every 5 minutes)
    let token_cleanup = token_store.start_cleanup_task(CLEANUP_INTERVAL);

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
            tokio::time::sleep(GRACEFUL_SHUTDOWN_TIMEOUT).await;
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

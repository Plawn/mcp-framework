use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use clap::{Parser, ValueEnum};
use rmcp::ServerHandler;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use std::any::Any;

use crate::audit::ToolCallLogger;
use crate::auth::{AuthProvider, ClaimsDecoderFn, StoredToken, TokenStore};
use crate::capability::{AccessValidator, CapabilityFilter, CapabilityRegistry, DynamicHandler, HandlerContext};
use crate::persistence::PersistenceBackend;
use crate::constants::{DEFAULT_BIND_ADDR, DEFAULT_SESSION_TTL};
use crate::session::{SessionData, SessionStore};
use crate::transport::{run_http, run_stdio, HttpAppConfig};

/// Transport mode for the MCP server.
#[derive(Debug, Clone, ValueEnum, PartialEq, Eq)]
pub enum TransportMode {
    /// HTTP transport (Streamable HTTP) - for remote connections
    Http,
    /// Stdio transport - for local Claude Desktop integration
    Stdio,
}

/// Log level for the MCP server.
#[derive(Debug, Clone, Default)]
pub enum LogLevel {
    Error,
    #[default]
    Info,
    Debug,
    Trace,
}

/// Manual settings for the MCP server, as an alternative to CLI args and env vars.
///
/// When provided on [`McpApp`], these take precedence over CLI arguments and
/// environment variables. `.env` files are **not** loaded automatically.
#[derive(Debug, Clone)]
pub struct Settings {
    /// Transport mode (default: Http)
    pub transport: TransportMode,
    /// Log level (default: Info)
    pub log_level: LogLevel,
    /// Bind address for HTTP mode (default: "0.0.0.0:4000")
    pub bind_addr: String,
    /// Public URL for OAuth callbacks. If `None`, derived as `http://{bind_addr}`.
    pub public_url: Option<String>,
    /// Session TTL for the `SessionStore`. If `None`, defaults to 30 minutes.
    pub session_ttl: Option<Duration>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            transport: TransportMode::Http,
            log_level: LogLevel::Info,
            bind_addr: DEFAULT_BIND_ADDR.to_string(),
            public_url: None,
            session_ttl: None,
        }
    }
}

/// High-level configuration for an MCP application.
///
/// The generic parameter `T` is the session data type stored per MCP session.
/// It defaults to `()` for backward compatibility — consumers that don't need
/// per-session state can omit it entirely.
///
/// For a more ergonomic API, use [`McpAppBuilder`] instead of constructing
/// the struct directly:
///
/// ```rust,ignore
/// McpAppBuilder::new("my-server")
///     .server(|| MyServer::new())
///     .run()
///     .await?;
/// ```
pub struct McpApp<F, T = ()>
where
    T: SessionData,
{
    /// Application name (used in OAuth templates and logs)
    pub name: String,
    /// Authentication provider to use in HTTP mode
    pub auth: AuthProvider,
    /// Factory that creates a `ServerHandler` instance
    pub server_factory: F,
    /// Env var name holding the token for stdio mode (e.g. `"MY_APP_TOKEN"`)
    pub stdio_token_env: Option<String>,
    /// Manual settings. When `Some`, CLI args and env vars are bypassed.
    pub settings: Option<Settings>,
    /// Optional dynamic capability registry for adding/removing tools, prompts,
    /// and resources at runtime.
    pub capability_registry: Option<CapabilityRegistry>,
    /// Optional filter to control which capabilities are visible per session.
    pub capability_filter: Option<Arc<dyn CapabilityFilter>>,
    /// Optional access validator for pre-execution authorization checks.
    pub access_validator: Option<Arc<dyn AccessValidator>>,
    /// Optional global claims decoder. Applied by the `TokenStore` during `store_token`.
    pub claims_decoder: Option<ClaimsDecoderFn>,
    /// Optional session store. When `None`, a default store is created automatically.
    pub session_store: Option<SessionStore<T>>,
    /// Optional tool call audit logger.
    pub tool_call_logger: Option<Arc<dyn ToolCallLogger>>,
    /// Optional persistence backend shared by `TokenStore` and `SessionStore`.
    pub persistence: Option<Arc<dyn PersistenceBackend>>,
    /// Extra axum routes merged into the auth-wrapped MCP router.
    ///
    /// See [`HttpAppConfig::extra_routes`](crate::transport::HttpAppConfig::extra_routes).
    pub extra_routes: Option<Router>,
}

impl<F, T> McpApp<F, T>
where
    T: SessionData,
{
    /// Create a builder for an `McpApp` with the given application name.
    ///
    /// For most cases, prefer [`McpAppBuilder::new`] which doesn't require
    /// specifying `F`:
    ///
    /// ```rust,ignore
    /// McpAppBuilder::new("my-server")
    ///     .server(|| MyServer::new())
    ///     .run()
    ///     .await?;
    /// ```
    pub fn builder(name: impl Into<String>) -> McpAppBuilder<T> {
        McpAppBuilder {
            name: name.into(),
            auth: AuthProvider::None,
            server_factory: (),
            stdio_token_env: None,
            settings: None,
            capability_registry: None,
            capability_filter: None,
            access_validator: None,
            claims_decoder: None,
            session_store: None,
            tool_call_logger: None,
            persistence: None,
            extra_routes: None,
        }
    }
}

/// Fluent builder for [`McpApp`].
///
/// Created via [`McpApp::builder`] or [`McpAppBuilder::new`]. The type parameter
/// `F` starts as `()` and becomes a concrete factory type after calling
/// `.server()`. `.build()` and `.run()` are only available once a factory is set.
///
/// # Example
///
/// ```rust,ignore
/// use mcp_framework::prelude::*;
///
/// // Minimal — 3 meaningful lines
/// McpAppBuilder::new("my-server")
///     .server(|| MyServer::new())
///     .run()
///     .await?;
///
/// // With custom session type
/// McpAppBuilder::new("my-server")
///     .with_sessions::<MySession>()
///     .server(|| MyServer::new())
///     .run()
///     .await?;
/// ```
pub struct McpAppBuilder<T: SessionData = (), F = ()> {
    name: String,
    auth: AuthProvider,
    server_factory: F,
    stdio_token_env: Option<String>,
    settings: Option<Settings>,
    capability_registry: Option<CapabilityRegistry>,
    capability_filter: Option<Arc<dyn CapabilityFilter>>,
    access_validator: Option<Arc<dyn AccessValidator>>,
    claims_decoder: Option<Arc<dyn Fn(&str) -> Option<Arc<dyn Any + Send + Sync>> + Send + Sync>>,
    session_store: Option<SessionStore<T>>,
    tool_call_logger: Option<Arc<dyn ToolCallLogger>>,
    persistence: Option<Arc<dyn PersistenceBackend>>,
    extra_routes: Option<Router>,
}

impl McpAppBuilder<()> {
    /// Create a new builder with the given application name and `T = ()` (no session data).
    ///
    /// This is the most common entry point. For custom session types,
    /// chain `.with_sessions::<T>()`:
    ///
    /// ```rust,ignore
    /// McpAppBuilder::new("my-server")
    ///     .server(|| MyServer::new())
    ///     .run()
    ///     .await?;
    /// ```
    pub fn new(name: impl Into<String>) -> Self {
        McpAppBuilder {
            name: name.into(),
            auth: AuthProvider::None,
            server_factory: (),
            stdio_token_env: None,
            settings: None,
            capability_registry: None,
            capability_filter: None,
            access_validator: None,
            claims_decoder: None,
            session_store: None,
            tool_call_logger: None,
            persistence: None,
            extra_routes: None,
        }
    }
}

/// Methods to set the session type. Only available when `T = ()` (session type not yet chosen).
impl<F> McpAppBuilder<(), F> {
    /// Switch to a custom session type `T`.
    ///
    /// ```rust,ignore
    /// McpAppBuilder::new("my-server")
    ///     .with_sessions::<MySession>()
    ///     .server(|| MyServer::new())
    ///     .run()
    ///     .await?;
    /// ```
    pub fn with_sessions<T: SessionData>(
        self,
    ) -> McpAppBuilder<T, F> {
        McpAppBuilder {
            name: self.name,
            auth: self.auth,
            server_factory: self.server_factory,
            stdio_token_env: self.stdio_token_env,
            settings: self.settings,
            capability_registry: self.capability_registry,
            capability_filter: self.capability_filter,
            access_validator: self.access_validator,
            claims_decoder: self.claims_decoder,
            session_store: None,
            tool_call_logger: self.tool_call_logger,
            persistence: self.persistence,
            extra_routes: self.extra_routes,
        }
    }
}

// Configuration methods available on any builder state.
impl<T: SessionData, F> McpAppBuilder<T, F> {
    /// Set the authentication provider (default: `AuthProvider::None`).
    pub fn auth(mut self, auth: AuthProvider) -> Self {
        self.auth = auth;
        self
    }

    /// Set the env var name for the stdio token (e.g. `"MY_APP_TOKEN"`).
    pub fn stdio_token_env(mut self, env_var: impl Into<String>) -> Self {
        self.stdio_token_env = Some(env_var.into());
        self
    }

    /// Provide manual settings (bypasses CLI parsing and env vars).
    pub fn settings(mut self, settings: Settings) -> Self {
        self.settings = Some(settings);
        self
    }

    /// Set the dynamic capability registry.
    pub fn capability_registry(mut self, registry: CapabilityRegistry) -> Self {
        self.capability_registry = Some(registry);
        self
    }

    /// Set the capability filter for per-session visibility.
    pub fn capability_filter(mut self, filter: Arc<dyn CapabilityFilter>) -> Self {
        self.capability_filter = Some(filter);
        self
    }

    /// Provide a pre-built session store.
    pub fn session_store(mut self, store: SessionStore<T>) -> Self {
        self.session_store = Some(store);
        self
    }

    /// Set the access validator for pre-execution authorization checks.
    ///
    /// When set, every `call_tool`, `get_prompt`, and `read_resource` request
    /// is validated before dispatch. Denied requests return an MCP error.
    pub fn access_validator(mut self, validator: Arc<dyn AccessValidator>) -> Self {
        self.access_validator = Some(validator);
        self
    }

    /// Set the global claims decoder.
    ///
    /// The decoder is called automatically during
    /// [`TokenStore::store_token`](crate::auth::TokenStore::store_token) and the
    /// result is attached to [`StoredToken::decoded_claims`](crate::auth::StoredToken::decoded_claims).
    /// Access decoded claims via [`StoredToken::claims::<C>()`](crate::auth::StoredToken::claims).
    ///
    /// The decoder is shared between all features that access tokens (filters, validators, handlers).
    pub fn claims_decoder<C: Any + Send + Sync + 'static>(
        mut self,
        decoder: impl Fn(&str) -> Option<C> + Send + Sync + 'static,
    ) -> Self {
        self.claims_decoder = Some(Arc::new(move |token: &str| {
            decoder(token).map(|c| Arc::new(c) as Arc<dyn Any + Send + Sync>)
        }));
        self
    }

    /// Set the tool call audit logger.
    ///
    /// When set, every `call_tool` invocation is logged asynchronously
    /// (fire-and-forget via `tokio::spawn`).
    pub fn tool_call_logger(mut self, logger: Arc<dyn ToolCallLogger>) -> Self {
        self.tool_call_logger = Some(logger);
        self
    }

    /// Register additional axum routes that live inside the auth-wrapped MCP router.
    ///
    /// Use this to expose REST endpoints (or any non-MCP HTTP surface) that share
    /// the same `AuthProvider` middleware as `/mcp`. Routes merged here take
    /// priority over the MCP fallback, so path collisions resolve in the user's
    /// favor. OAuth discovery (`/.well-known/*`) and `/oauth/*` stay publicly
    /// accessible — they are registered on the outer app before the fallback.
    ///
    /// Stdio mode ignores this field (no HTTP surface).
    ///
    /// ```rust,ignore
    /// use axum::{routing::get, Router};
    ///
    /// let api = Router::new().route("/api/tools", get(list_tools));
    ///
    /// McpAppBuilder::new("my-server")
    ///     .auth(AuthProvider::OAuth(oauth_config))
    ///     .extra_routes(api)
    ///     .server(|| MyServer::new())
    ///     .run()
    ///     .await?;
    /// ```
    pub fn extra_routes(mut self, routes: Router) -> Self {
        self.extra_routes = Some(routes);
        self
    }

    /// Set the persistence backend, shared by `TokenStore` and `SessionStore`.
    pub fn persistence(mut self, backend: Arc<dyn PersistenceBackend>) -> Self {
        self.persistence = Some(backend);
        self
    }

    /// Transfer all non-factory fields into a new builder with a different factory type.
    fn with_factory<G>(self, factory: G) -> McpAppBuilder<T, G> {
        McpAppBuilder {
            name: self.name,
            auth: self.auth,
            server_factory: factory,
            stdio_token_env: self.stdio_token_env,
            settings: self.settings,
            capability_registry: self.capability_registry,
            capability_filter: self.capability_filter,
            access_validator: self.access_validator,
            claims_decoder: self.claims_decoder,
            session_store: self.session_store,
            tool_call_logger: self.tool_call_logger,
            persistence: self.persistence,
            extra_routes: self.extra_routes,
        }
    }

    /// Provide a zero-arg server factory.
    ///
    /// Stores (tokens, sessions) are accessible via
    /// [`RequestContextExt`](crate::session::RequestContextExt) on the request context
    /// — no need to capture them in the server struct.
    pub fn server<S, Fac>(self, factory: Fac) -> McpAppBuilder<T, Fac>
    where
        S: ServerHandler + Send + 'static,
        Fac: Fn() -> S + Clone + Send + Sync + 'static,
    {
        self.with_factory(factory)
    }
}

// Build and run methods — only available when a valid server factory is set.
impl<T, F, S> McpAppBuilder<T, F>
where
    T: SessionData,
    F: Fn() -> S + Clone + Send + Sync + 'static,
    S: ServerHandler + Send + 'static,
{
    /// Validate the builder configuration.
    fn validate(&self) -> anyhow::Result<()> {
        // Validate bind_addr is parseable if settings are provided
        if let Some(ref s) = self.settings {
            s.bind_addr.parse::<std::net::SocketAddr>().map_err(|e| {
                anyhow::anyhow!(
                    "McpAppBuilder: invalid bind_addr '{}': {}",
                    s.bind_addr,
                    e
                )
            })?;

            // Validate session_ttl >= 1 second
            if let Some(ttl) = s.session_ttl
                && ttl < Duration::from_secs(1) {
                    anyhow::bail!(
                        "McpAppBuilder: session_ttl must be at least 1 second, got {:?}",
                        ttl
                    );
                }
        }

        // Validate OAuth config fields are non-empty
        if let AuthProvider::OAuth(ref oauth) = self.auth {
            if oauth.client_id.is_empty() {
                anyhow::bail!("McpAppBuilder: OAuth client_id must not be empty");
            }
            if oauth.issuer_url.is_empty() {
                anyhow::bail!("McpAppBuilder: OAuth issuer_url must not be empty");
            }
            if oauth.redirect_url.is_empty() {
                anyhow::bail!("McpAppBuilder: OAuth redirect_url must not be empty");
            }
        }

        // Warn if auth != None in stdio mode (auth is ignored there)
        if let Some(ref s) = self.settings
            && s.transport == TransportMode::Stdio && !matches!(self.auth, AuthProvider::None) {
                tracing::warn!(
                    "Auth provider is set but transport is Stdio — auth will be ignored"
                );
            }

        Ok(())
    }

    /// Build the [`McpApp`], consuming the builder.
    pub fn build(self) -> anyhow::Result<McpApp<F, T>> {
        self.validate()?;
        Ok(McpApp {
            name: self.name,
            auth: self.auth,
            server_factory: self.server_factory,
            stdio_token_env: self.stdio_token_env,
            settings: self.settings,
            capability_registry: self.capability_registry,
            capability_filter: self.capability_filter,
            access_validator: self.access_validator,
            claims_decoder: self.claims_decoder,
            session_store: self.session_store,
            tool_call_logger: self.tool_call_logger,
            persistence: self.persistence,
            extra_routes: self.extra_routes,
        })
    }

    /// Build and run the MCP application.
    ///
    /// Shorthand for `builder.build()?.run().await`.
    pub async fn run(self) -> anyhow::Result<()> {
        let app = self.build()?;
        crate::runner::run(app).await
    }
}

#[derive(Parser, Debug)]
#[command(about = "MCP server")]
struct CliArgs {
    /// Transport mode to use
    #[arg(short, long, default_value = "http")]
    transport: TransportMode,

    /// Enable debug logging
    #[arg(short, long)]
    debug: bool,

    /// Enable trace-level logging (very verbose)
    #[arg(long)]
    trace: bool,
}

fn init_tracing(level: &str) {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| level.into()),
        )
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();
}

fn setup_tracing_from_cli(args: &CliArgs) {
    let level = if args.trace {
        "trace"
    } else if args.debug {
        "debug"
    } else {
        match args.transport {
            TransportMode::Stdio => "error",
            TransportMode::Http => "info",
        }
    };

    init_tracing(level);

    if args.debug || args.trace {
        tracing::info!(
            log_level = %level,
            transport = ?args.transport,
            "Debug logging enabled"
        );
    }
}

fn setup_tracing_from_settings(settings: &Settings) {
    let level = match settings.log_level {
        LogLevel::Error => "error",
        LogLevel::Info => "info",
        LogLevel::Debug => "debug",
        LogLevel::Trace => "trace",
    };
    init_tracing(level);
}

fn resolve_http_addrs(settings: Option<&Settings>) -> (String, String) {
    match settings {
        Some(s) => {
            let public_url = s
                .public_url
                .clone()
                .unwrap_or_else(|| format!("http://{}", s.bind_addr));
            (s.bind_addr.clone(), public_url)
        }
        None => {
            let bind_addr =
                std::env::var("BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string());
            let public_url = std::env::var("PUBLIC_URL")
                .unwrap_or_else(|_| format!("http://{}", bind_addr));
            (bind_addr, public_url)
        }
    }
}

fn resolve_session_store<T: SessionData>(
    session_store: &Option<SessionStore<T>>,
    settings: &Option<Settings>,
) -> SessionStore<T> {
    if let Some(store) = session_store {
        return store.clone();
    }
    let ttl = settings
        .as_ref()
        .and_then(|s| s.session_ttl)
        .unwrap_or(DEFAULT_SESSION_TTL);
    SessionStore::new(ttl)
}

async fn run_http_mode<F, S, T>(app: McpApp<F, T>) -> anyhow::Result<()>
where
    F: Fn() -> S + Clone + Send + Sync + 'static,
    S: ServerHandler + Send + 'static,
    T: SessionData,
{
    let (bind_addr, public_url) = resolve_http_addrs(app.settings.as_ref());
    let mut session_store = resolve_session_store(&app.session_store, &app.settings);
    let persistence = app.persistence;

    if let Some(ref backend) = persistence {
        session_store.set_persistence(backend.clone());
        session_store.load_persisted().await.map_err(anyhow::Error::from_boxed)?;
    }

    run_http(HttpAppConfig {
        public_url,
        bind_addr,
        auth: app.auth,
        server_factory: app.server_factory,
        app_name: app.name.clone(),
        capability_registry: app.capability_registry,
        capability_filter: app.capability_filter,
        access_validator: app.access_validator,
        claims_decoder: app.claims_decoder,
        session_store,
        tool_call_logger: app.tool_call_logger,
        persistence,
        extra_routes: app.extra_routes,
    })
    .await
}

async fn run_stdio_mode<F, S, T>(app: McpApp<F, T>) -> anyhow::Result<()>
where
    F: Fn() -> S + Clone + Send + Sync + 'static,
    S: ServerHandler + Send + 'static,
    T: SessionData,
{
    let mut token_store = TokenStore::new();
    if let Some(decoder) = app.claims_decoder {
        token_store.claims_decoder = Some(decoder);
    }
    let mut session_store = resolve_session_store(&app.session_store, &app.settings);
    if let Some(ref backend) = app.persistence {
        token_store.set_persistence(backend.clone());
        token_store.load_persisted().await.map_err(anyhow::Error::from_boxed)?;
        session_store.set_persistence(backend.clone());
        session_store.load_persisted().await.map_err(anyhow::Error::from_boxed)?;
    }

    if let Some(ref env_var) = app.stdio_token_env {
        if let Ok(t) = std::env::var(env_var) {
            token_store
                .store_token(
                    "stdio".to_string(),
                    StoredToken {
                        access_token: t,
                        refresh_token: None,
                        expires_at: None,
                        decoded_claims: None,
                    },
                )
                .await;
            eprintln!("Using {} from environment", env_var);
        } else {
            eprintln!(
                "Warning: {} not set. Tools will require 'token' parameter.",
                env_var
            );
        }
    }

    let server = (app.server_factory)();
    let mut registry = app.capability_registry.unwrap_or_default();
    if let Some(ref backend) = app.persistence {
        registry.set_persistence(backend.clone());
        registry.load_persisted_versions().await.map_err(anyhow::Error::from_boxed)?;
    }
    let handler = DynamicHandler::new(
        server,
        registry,
        HandlerContext {
            filter: app.capability_filter,
            access_validator: app.access_validator,
            token_store,
            session_store,
            tool_call_logger: app.tool_call_logger,
        },
    );
    run_stdio(handler).await
}

/// Run an MCP application.
///
/// When `app.settings` is `Some`, the provided settings are used directly
/// (no `.env` loading, no CLI parsing).
///
/// When `app.settings` is `None`, `.env` is loaded, CLI args are parsed,
/// and `BIND_ADDR`/`PUBLIC_URL` env vars are read (original behavior).
pub async fn run<F, S, T>(app: McpApp<F, T>) -> anyhow::Result<()>
where
    F: Fn() -> S + Clone + Send + Sync + 'static,
    S: ServerHandler + Send + 'static,
    T: SessionData,
{
    if let Some(ref settings) = app.settings {
        let transport = settings.transport.clone();
        setup_tracing_from_settings(settings);
        match transport {
            TransportMode::Http => {
                run_http_mode(app).await
            }
            TransportMode::Stdio => run_stdio_mode(app).await,
        }
    } else {
        dotenvy::dotenv().ok();
        let args = CliArgs::parse();
        setup_tracing_from_cli(&args);
        match args.transport {
            TransportMode::Http => {
                run_http_mode(app).await
            }
            TransportMode::Stdio => run_stdio_mode(app).await,
        }
    }
}

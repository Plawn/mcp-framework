use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use clap::{Parser, ValueEnum};
use rmcp::ServerHandler;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use std::any::Any;

use crate::audit::ToolCallLogger;
use crate::auth::{AuthProvider, ClaimsDecoderFn, StoredToken, TokenMode, TokenStore};
use crate::capability::{
    AccessValidator, CapabilityFilter, CapabilityRegistry, DynamicHandler, HandlerContext,
};
use crate::constants::{DEFAULT_BIND_ADDR, DEFAULT_SESSION_ID, DEFAULT_SESSION_TTL};
use crate::persistence::PersistenceBackend;
use crate::session::{SessionData, SessionStore};
use crate::transport::{
    HttpAppConfig, LoopbackEndpoint, ProtocolLifecyclePolicy, run_http, run_stdio,
};

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
    /// Optional persistence backend shared by tokens, application state, and
    /// legacy rmcp transport sessions.
    pub persistence: Option<Arc<dyn PersistenceBackend>>,
    /// Streamable HTTP lifecycle compatibility policy.
    pub protocol_lifecycle: ProtocolLifecyclePolicy,
    /// Extra axum routes merged into the auth-wrapped MCP router.
    ///
    /// See [`HttpAppConfig::extra_routes`](crate::transport::HttpAppConfig::extra_routes).
    pub extra_routes: Option<Router>,
    /// Public axum routes mounted **outside** the auth layer (health checks,
    /// readiness probes, the metrics endpoint, …).
    ///
    /// The counterpart to [`extra_routes`](Self::extra_routes): those sit behind
    /// the auth middleware, these stay reachable without credentials. Set via
    /// [`McpAppBuilder::public_routes`]; [`McpAppBuilder::metrics`] merges its
    /// endpoint here too.
    pub public_routes: Option<Router>,
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
            protocol_lifecycle: ProtocolLifecyclePolicy::default(),
            extra_routes: None,
            public_routes: None,
            loopback: LoopbackGuard::default(),
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
    claims_decoder: Option<ClaimsDecoderFn>,
    session_store: Option<SessionStore<T>>,
    tool_call_logger: Option<Arc<dyn ToolCallLogger>>,
    persistence: Option<Arc<dyn PersistenceBackend>>,
    protocol_lifecycle: ProtocolLifecyclePolicy,
    extra_routes: Option<Router>,
    public_routes: Option<Router>,
    loopback: LoopbackGuard,
}

/// Remembers whether a loopback endpoint has been handed out, and what changed afterwards.
///
/// [`McpAppBuilder::loopback`] takes a **snapshot**: the endpoint holds its own clones of the
/// registry, the filter, the validator, the logger and the server factory. Configuring any of
/// those afterwards therefore reconfigures the network transport and leaves the in-process one on
/// the old value — the two paths diverge, and the whole point of the loopback is that they do not.
///
/// Nothing about the shape of the API prevents that order of calls, so the builder records it and
/// [`validate`](McpAppBuilder::validate) refuses to build. A boot failure naming the field beats a
/// filter that quietly applies to half the callers.
#[derive(Default)]
struct LoopbackGuard {
    handed_out: bool,
    diverged: Vec<&'static str>,
}

impl LoopbackGuard {
    /// Record that `field` was set. A no-op until an endpoint has actually been handed out.
    fn note(&mut self, field: &'static str) {
        if self.handed_out && !self.diverged.contains(&field) {
            self.diverged.push(field);
        }
    }
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
            protocol_lifecycle: ProtocolLifecyclePolicy::default(),
            extra_routes: None,
            public_routes: None,
            loopback: LoopbackGuard::default(),
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
    pub fn with_sessions<T: SessionData>(mut self) -> McpAppBuilder<T, F> {
        self.loopback.note("with_sessions");
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
            protocol_lifecycle: self.protocol_lifecycle,
            extra_routes: self.extra_routes,
            public_routes: self.public_routes,
            loopback: self.loopback,
        }
    }
}

// Configuration methods available on any builder state.
impl<T: SessionData, F> McpAppBuilder<T, F> {
    /// Set the authentication provider (default: `AuthProvider::None`).
    pub fn auth(mut self, auth: AuthProvider) -> Self {
        self.auth = auth;
        self.loopback.note("auth");
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
        self.loopback.note("settings");
        self
    }

    /// Set the dynamic capability registry.
    pub fn capability_registry(mut self, registry: CapabilityRegistry) -> Self {
        self.capability_registry = Some(registry);
        self.loopback.note("capability_registry");
        self
    }

    /// Set the capability filter for per-session visibility.
    pub fn capability_filter(mut self, filter: Arc<dyn CapabilityFilter>) -> Self {
        self.capability_filter = Some(filter);
        self.loopback.note("capability_filter");
        self
    }

    /// Provide a pre-built session store.
    pub fn session_store(mut self, store: SessionStore<T>) -> Self {
        self.session_store = Some(store);
        self.loopback.note("session_store");
        self
    }

    /// Set the access validator for pre-execution authorization checks.
    ///
    /// When set, every `call_tool`, `get_prompt`, and `read_resource` request
    /// is validated before dispatch. Denied requests return an MCP error.
    pub fn access_validator(mut self, validator: Arc<dyn AccessValidator>) -> Self {
        self.access_validator = Some(validator);
        self.loopback.note("access_validator");
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
        self.loopback.note("claims_decoder");
        self
    }

    /// Set the tool call audit logger.
    ///
    /// When set, every `call_tool` invocation is logged asynchronously
    /// (fire-and-forget via `tokio::spawn`).
    pub fn tool_call_logger(mut self, logger: Arc<dyn ToolCallLogger>) -> Self {
        self.tool_call_logger = Some(logger);
        self.loopback.note("tool_call_logger");
        self
    }

    /// Enable effectiveness metrics collection (feature `metrics`).
    ///
    /// The collector aggregates per-tool and per-session statistics from the
    /// tool call stream. This method:
    /// - registers the collector as a [`ToolCallLogger`], composing with any
    ///   logger already set via [`tool_call_logger`](Self::tool_call_logger)
    ///   (both receive every record);
    /// - mounts the metrics HTTP endpoint into [`public_routes`](Self::public_routes)
    ///   (unauthenticated) at the path from
    ///   [`MetricsConfig`](crate::metrics::MetricsConfig), if enabled.
    ///
    /// Hold the `Arc` to query [`MetricsCollector::snapshot`](crate::metrics::MetricsCollector::snapshot)
    /// in-process (works in stdio mode too).
    ///
    /// Because it composes with the logger set so far, call `.metrics()` *after*
    /// any [`tool_call_logger`](Self::tool_call_logger) — a later
    /// `.tool_call_logger()` overwrites (last-wins) and would drop the collector.
    ///
    /// ```rust,ignore
    /// let metrics = MetricsCollector::new(MetricsConfig::default());
    /// McpAppBuilder::new("my-server")
    ///     .metrics(metrics.clone())
    ///     .server(|| MyServer::new())
    ///     .run()
    ///     .await?;
    /// ```
    #[cfg(feature = "metrics")]
    pub fn metrics(mut self, collector: Arc<crate::metrics::MetricsCollector>) -> Self {
        let logger: Arc<dyn ToolCallLogger> = collector.clone();
        self.tool_call_logger = Some(match self.tool_call_logger.take() {
            Some(existing) => Arc::new(crate::audit::CompositeLogger::new(vec![existing, logger])),
            None => logger,
        });
        self.loopback.note("metrics");
        if let Some(route) = crate::metrics::metrics_router(collector) {
            self = self.public_routes(route);
        }
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

    /// Register public axum routes mounted **outside** the auth layer.
    ///
    /// The counterpart to [`extra_routes`](Self::extra_routes): use this for
    /// surfaces that must stay reachable without credentials — health checks,
    /// readiness probes, a Prometheus scrape endpoint. Like the OAuth discovery
    /// routes, these are merged before the auth-wrapped MCP fallback, so they
    /// take priority for their paths and bypass the middleware.
    ///
    /// Calls accumulate (routers are merged), so multiple `.public_routes(...)`
    /// compose rather than overwrite. [`metrics`](Self::metrics) reuses this.
    ///
    /// Stdio mode ignores this field (no HTTP surface).
    pub fn public_routes(mut self, routes: Router) -> Self {
        self.public_routes = Some(match self.public_routes.take() {
            Some(existing) => existing.merge(routes),
            None => routes,
        });
        self
    }

    /// Set the persistence backend shared by tokens, application state, and
    /// legacy rmcp transport sessions.
    pub fn persistence(mut self, backend: Arc<dyn PersistenceBackend>) -> Self {
        self.persistence = Some(backend);
        self
    }

    /// Set the Streamable HTTP lifecycle policy.
    ///
    /// [`ProtocolLifecyclePolicy::Hybrid`] is the default. It supports both
    /// modern `server/discover` clients and legacy initialize clients, while
    /// repairing clients that advertise a modern version but still use the
    /// legacy handshake.
    pub fn protocol_lifecycle(mut self, policy: ProtocolLifecyclePolicy) -> Self {
        self.protocol_lifecycle = policy;
        self
    }

    /// Transfer all non-factory fields into a new builder with a different factory type.
    fn with_factory<G>(mut self, factory: G) -> McpAppBuilder<T, G> {
        self.loopback.note("server");
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
            protocol_lifecycle: self.protocol_lifecycle,
            extra_routes: self.extra_routes,
            public_routes: self.public_routes,
            loopback: self.loopback,
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
                anyhow::anyhow!("McpAppBuilder: invalid bind_addr '{}': {}", s.bind_addr, e)
            })?;

            // Validate session_ttl >= 1 second
            if let Some(ttl) = s.session_ttl
                && ttl < Duration::from_secs(1)
            {
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

        // A loopback endpoint is a *snapshot* of the builder, and nothing in the API stops a
        // caller from configuring the application further afterwards. What follows would then
        // apply to the network transport only, while the in-process caller kept the old value —
        // a filter or a validator applied to half the traffic, silently. Naming the fields is the
        // whole value of the check: "configure before `loopback()`" is not actionable on its own.
        if !self.loopback.diverged.is_empty() {
            anyhow::bail!(
                "McpAppBuilder: {} set after `loopback()` handed out an endpoint — that endpoint \
                 kept the earlier value, so in-process callers and network clients would no longer \
                 take the same path. Configure everything before calling `loopback()`.",
                self.loopback.diverged.join(", ")
            );
        }

        // Warn if auth != None in stdio mode (auth is ignored there)
        if let Some(ref s) = self.settings
            && s.transport == TransportMode::Stdio
            && !matches!(self.auth, AuthProvider::None)
        {
            tracing::warn!("Auth provider is set but transport is Stdio — auth will be ignored");
        }

        Ok(())
    }

    /// A factory for in-process clients of this application.
    ///
    /// An in-process caller — an agent loop, a scheduler — that reaches into the
    /// [`CapabilityRegistry`] directly takes a path no network client takes, and so slips past
    /// the capability filter, the access validator and the tool-call logger. A loopback client
    /// takes the same path as everyone else, minus the socket.
    ///
    /// Does **not** consume the builder: the application can serve its network transport and
    /// hand out loopback sessions at once. The registry is materialized here if unset, so both
    /// sides dispatch through the same one — that shared registry is the point of the whole
    /// exercise.
    ///
    /// Everything the endpoint captures is a **snapshot**. Configuring any of those fields
    /// afterwards makes the two paths diverge, so the builder records it and
    /// [`validate`](Self::validate) refuses to build. Call `loopback()` last.
    ///
    /// # What the endpoint does *not* share
    ///
    /// The [`TokenStore`] **and** the [`SessionStore`], both for the same reason: a loopback
    /// session id is chosen by the in-process caller (a chat thread id, a job name), an HTTP one
    /// is chosen by the network client, and they are keyed in the same namespace. Sharing either
    /// store would mean an in-process caller that names its session after an HTTP session id
    /// reads and writes that client's state — and in engine's case the thread id comes straight
    /// from a request body, so the collision would be reachable from outside.
    ///
    /// Consequences worth knowing rather than discovering: in-process session data is **not**
    /// persisted (a persistence backend attached to the app reaches the HTTP store only), and it
    /// does not survive a restart. Sessions of `T = ()` — the common case — hold nothing anyway.
    pub fn loopback(&mut self) -> LoopbackEndpoint<T, F> {
        let registry = self
            .capability_registry
            .get_or_insert_with(CapabilityRegistry::default)
            .clone();
        let ttl = self
            .settings
            .as_ref()
            .and_then(|s| s.session_ttl)
            .unwrap_or(DEFAULT_SESSION_TTL);

        let mut token_store = TokenStore::new();
        if let Some(ref decoder) = self.claims_decoder {
            token_store.claims_decoder = Some(decoder.clone());
        }

        // Only OAuth has a token mode; everything else behaves as Passthrough.
        let token_mode = match self.auth {
            AuthProvider::OAuth(ref oauth) => oauth.token_mode.clone(),
            AuthProvider::None | AuthProvider::Basic(_) => TokenMode::Passthrough,
        };

        self.loopback.handed_out = true;
        LoopbackEndpoint::new(
            self.server_factory.clone(),
            registry,
            self.capability_filter.clone(),
            self.access_validator.clone(),
            self.tool_call_logger.clone(),
            token_store,
            SessionStore::new(ttl),
            token_mode,
        )
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
            protocol_lifecycle: self.protocol_lifecycle,
            extra_routes: self.extra_routes,
            public_routes: self.public_routes,
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
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| level.into()),
        )
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .try_init()
        .ok();
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
            let public_url =
                std::env::var("PUBLIC_URL").unwrap_or_else(|_| format!("http://{}", bind_addr));
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
        session_store
            .load_persisted()
            .await
            .map_err(anyhow::Error::from_boxed)?;
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
        protocol_lifecycle: app.protocol_lifecycle,
        extra_routes: app.extra_routes,
        public_routes: app.public_routes,
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
        token_store
            .load_persisted()
            .await
            .map_err(anyhow::Error::from_boxed)?;
        session_store.set_persistence(backend.clone());
        session_store
            .load_persisted()
            .await
            .map_err(anyhow::Error::from_boxed)?;
    }

    if let Some(ref env_var) = app.stdio_token_env {
        if let Ok(t) = std::env::var(env_var) {
            token_store
                .store_token(
                    DEFAULT_SESSION_ID.to_string(),
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
        registry
            .load_persisted_versions()
            .await
            .map_err(anyhow::Error::from_boxed)?;
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
            loopback_identity: None,
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
            TransportMode::Http => run_http_mode(app).await,
            TransportMode::Stdio => run_stdio_mode(app).await,
        }
    } else {
        dotenvy::dotenv().ok();
        let args = CliArgs::parse();
        setup_tracing_from_cli(&args);
        match args.transport {
            TransportMode::Http => run_http_mode(app).await,
            TransportMode::Stdio => run_stdio_mode(app).await,
        }
    }
}

use clap::{Parser, ValueEnum};
use rmcp::ServerHandler;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::auth::{AuthProvider, StoredToken, TokenStore};
use crate::transport::{run_http, run_stdio, HttpAppConfig};

const DEFAULT_BIND_ADDR: &str = "0.0.0.0:4000";

/// Transport mode for the MCP server.
#[derive(Debug, Clone, ValueEnum)]
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
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            transport: TransportMode::Http,
            log_level: LogLevel::Info,
            bind_addr: DEFAULT_BIND_ADDR.to_string(),
            public_url: None,
        }
    }
}

/// High-level configuration for an MCP application.
pub struct McpApp<F> {
    /// Application name (used in OAuth templates and logs)
    pub name: &'static str,
    /// Authentication provider to use in HTTP mode
    pub auth: AuthProvider,
    /// Factory that creates a `ServerHandler` from a `TokenStore`
    pub server_factory: F,
    /// Env var name holding the token for stdio mode (e.g. `"MY_APP_TOKEN"`)
    pub stdio_token_env: Option<&'static str>,
    /// Manual settings. When `Some`, CLI args and env vars are bypassed.
    pub settings: Option<Settings>,
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

async fn run_http_mode<F, S>(app: McpApp<F>) -> anyhow::Result<()>
where
    F: Fn(TokenStore) -> S + Clone + Send + Sync + 'static,
    S: ServerHandler + Send + 'static,
{
    let (bind_addr, public_url) = resolve_http_addrs(app.settings.as_ref());

    run_http(HttpAppConfig {
        public_url,
        bind_addr,
        auth: app.auth,
        server_factory: app.server_factory,
        app_name: app.name.to_string(),
    })
    .await
}

async fn run_stdio_mode<F, S>(app: McpApp<F>) -> anyhow::Result<()>
where
    F: Fn(TokenStore) -> S + Clone + Send + Sync + 'static,
    S: ServerHandler + Send + 'static,
{
    let token_store = TokenStore::new();

    if let Some(env_var) = app.stdio_token_env {
        if let Ok(t) = std::env::var(env_var) {
            token_store
                .store_token(
                    "stdio".to_string(),
                    StoredToken {
                        access_token: t,
                        refresh_token: None,
                        expires_at: None,
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

    let server = (app.server_factory)(token_store);
    run_stdio(server).await
}

/// Run an MCP application.
///
/// When `app.settings` is `Some`, the provided settings are used directly
/// (no `.env` loading, no CLI parsing).
///
/// When `app.settings` is `None`, `.env` is loaded, CLI args are parsed,
/// and `BIND_ADDR`/`PUBLIC_URL` env vars are read (original behavior).
pub async fn run<F, S>(app: McpApp<F>) -> anyhow::Result<()>
where
    F: Fn(TokenStore) -> S + Clone + Send + Sync + 'static,
    S: ServerHandler + Send + 'static,
{
    if let Some(ref settings) = app.settings {
        setup_tracing_from_settings(settings);
        match settings.transport {
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

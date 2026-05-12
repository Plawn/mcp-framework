use std::time::Duration;

// === MCP Headers ===
pub const MCP_SESSION_ID_HEADER: &str = "mcp-session-id";
pub const DEFAULT_SESSION_ID: &str = "default";

// === Durations ===
pub const TOKEN_EXPIRY_BUFFER: Duration = Duration::from_secs(30);
pub const PENDING_AUTH_TIMEOUT: Duration = Duration::from_secs(300);
pub const CLEANUP_INTERVAL: Duration = Duration::from_secs(300);
pub const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
pub const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(30 * 60);

// === Network ===
pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:4000";

// === OAuth routes ===
pub const OAUTH_MOUNT: &str = "/oauth";
pub const OAUTH_REGISTER_PATH: &str = "/register";
pub const OAUTH_AUTHORIZE_PATH: &str = "/authorize";
pub const OAUTH_TOKEN_PATH: &str = "/token";
pub const OAUTH_LOGIN_PATH: &str = "/login";
pub const OAUTH_CALLBACK_PATH: &str = "/callback";
pub const OAUTH_STATUS_PATH: &str = "/status";

// === Persistence namespaces ===
pub const NS_TOKENS: &str = "tokens";
pub const NS_SESSIONS: &str = "sessions";

// === Auth ===
pub const BEARER_PREFIX: &str = "Bearer ";
pub const BEARER_PREFIX_LOWER: &str = "bearer ";
pub const BASIC_PREFIX: &str = "Basic ";
pub const BASIC_PREFIX_LOWER: &str = "basic ";
pub const BASIC_REALM: &str = "Basic realm=\"MCP\"";
pub const MCP_CLIENT_ID_PREFIX: &str = "mcp-";
pub const AUTHORIZATION_HEADER: &str = "authorization";
pub const WWW_AUTHENTICATE_HEADER: &str = "WWW-Authenticate";
pub const CONTENT_TYPE_JSON: &str = "application/json";
pub const CONTENT_TYPE_FORM: &str = "application/x-www-form-urlencoded";

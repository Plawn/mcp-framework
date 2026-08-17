use oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl, basic::BasicClient};

// Type alias for the configured client
pub type ConfiguredClient = oauth2::Client<
    oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>,
    oauth2::StandardTokenResponse<oauth2::EmptyExtraTokenFields, oauth2::basic::BasicTokenType>,
    oauth2::StandardTokenIntrospectionResponse<
        oauth2::EmptyExtraTokenFields,
        oauth2::basic::BasicTokenType,
    >,
    oauth2::StandardRevocableToken,
    oauth2::StandardErrorResponse<oauth2::RevocationErrorResponseType>,
    oauth2::EndpointSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointSet,
>;

/// OAuth configuration for Keycloak OIDC
#[derive(Clone)]
pub struct OAuthConfig {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub issuer_url: String,
    pub redirect_url: String,
    pub scopes: Vec<String>,
    pub token_mode: TokenMode,
    /// How to validate a bearer the `/oauth/token` proxy did not issue.
    pub unknown_token_validation: UnknownTokenValidation,
    /// Audiences a locally validated JWT must carry. Empty means `aud` is not
    /// constrained (the observed `aud`/`azp` is logged instead, so the
    /// deployment can be hardened later from real traffic).
    pub expected_audiences: Vec<String>,
}

impl OAuthConfig {
    /// Create config from environment variables
    ///
    /// Required env vars:
    /// - OAUTH_CLIENT_ID
    /// - OAUTH_ISSUER_URL (e.g., https://keycloak.example.com/realms/myrealm)
    /// - OAUTH_REDIRECT_URL (e.g., http://localhost:3000/oauth/callback)
    ///
    /// Optional:
    /// - OAUTH_CLIENT_SECRET (omit for public OIDC clients using PKCE)
    /// - OAUTH_SCOPES (comma-separated, defaults to "openid,profile,email")
    /// - OAUTH_UNKNOWN_TOKEN_VALIDATION (see [`UnknownTokenValidation`])
    /// - OAUTH_EXPECTED_AUDIENCE (comma-separated, defaults to unconstrained)
    pub fn from_env() -> Result<Self, String> {
        let client_id = std::env::var("OAUTH_CLIENT_ID").map_err(|_| "OAUTH_CLIENT_ID not set")?;
        let client_secret = std::env::var("OAUTH_CLIENT_SECRET").ok();
        let issuer_url =
            std::env::var("OAUTH_ISSUER_URL").map_err(|_| "OAUTH_ISSUER_URL not set")?;
        let redirect_url =
            std::env::var("OAUTH_REDIRECT_URL").map_err(|_| "OAUTH_REDIRECT_URL not set")?;

        let scopes = std::env::var("OAUTH_SCOPES")
            .unwrap_or_else(|_| "openid,profile,email".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();

        let token_mode = TokenMode::from_env();
        let unknown_token_validation = UnknownTokenValidation::from_env();
        let expected_audiences = std::env::var("OAUTH_EXPECTED_AUDIENCE")
            .map(|raw| {
                raw.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self {
            client_id,
            client_secret,
            issuer_url,
            redirect_url,
            scopes,
            token_mode,
            unknown_token_validation,
            expected_audiences,
        })
    }

    /// Build the OAuth2 client for Keycloak
    pub fn build_client(&self) -> Result<ConfiguredClient, String> {
        // Keycloak OIDC endpoints follow a standard pattern
        let auth_url = format!(
            "{}/protocol/openid-connect/auth",
            self.issuer_url.trim_end_matches('/')
        );
        let token_url = format!(
            "{}/protocol/openid-connect/token",
            self.issuer_url.trim_end_matches('/')
        );

        let mut client = BasicClient::new(ClientId::new(self.client_id.clone()))
            .set_auth_uri(AuthUrl::new(auth_url).map_err(|e| e.to_string())?)
            .set_token_uri(TokenUrl::new(token_url).map_err(|e| e.to_string())?)
            .set_redirect_uri(
                RedirectUrl::new(self.redirect_url.clone()).map_err(|e| e.to_string())?,
            );

        if let Some(ref secret) = self.client_secret {
            client = client.set_client_secret(ClientSecret::new(secret.clone()));
        }

        Ok(client)
    }
}

/// Basic HTTP authentication configuration
#[derive(Clone)]
pub struct BasicAuthConfig {
    pub username: String,
    pub password: String,
}

impl BasicAuthConfig {
    /// Create config from environment variables
    ///
    /// Required env vars:
    /// - BASIC_AUTH_USERNAME
    /// - BASIC_AUTH_PASSWORD
    pub fn from_env() -> Result<Self, String> {
        let username =
            std::env::var("BASIC_AUTH_USERNAME").map_err(|_| "BASIC_AUTH_USERNAME not set")?;
        let password =
            std::env::var("BASIC_AUTH_PASSWORD").map_err(|_| "BASIC_AUTH_PASSWORD not set")?;
        Ok(Self { username, password })
    }
}

/// Controls how OAuth tokens are issued to MCP clients.
///
/// - **Passthrough** (default): Keycloak tokens are forwarded directly to the
///   MCP client. Simple, but the client holds real JWTs and logout on the
///   platform side immediately kills the MCP session.
/// - **Opaque**: The framework emits its own opaque UUID tokens to the client
///   and keeps the real Keycloak tokens server-side. The client never sees a
///   JWT, and the framework handles refresh internally.
///
/// Configurable via `MCP_TOKEN_MODE=passthrough|opaque` (default: `passthrough`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum TokenMode {
    #[default]
    Passthrough,
    Opaque,
}

impl TokenMode {
    pub fn from_env() -> Self {
        match std::env::var("MCP_TOKEN_MODE").as_deref() {
            Ok("opaque") => TokenMode::Opaque,
            _ => TokenMode::Passthrough,
        }
    }
}

/// How a bearer that this framework's `/oauth/token` proxy never issued is
/// validated before it is allowed to seed a session.
///
/// Tokens the proxy issued are always resolved from the [`TokenStore`] first;
/// this policy only governs the "unknown credential" path — typically a
/// bring-your-own-token client, or a service that obtained a token by Keycloak
/// token-exchange and sends it as `Authorization: Bearer`.
///
/// RFC 7662 token introspection is not always usable: Keycloak refuses the
/// endpoint to **public** clients (`403 Client not allowed.`), which is a
/// property of the configured `OAUTH_CLIENT_ID`, not of the token. Local JWKS
/// validation has no such requirement — it only needs the issuer's public keys.
///
/// Configurable via `OAUTH_UNKNOWN_TOKEN_VALIDATION`
/// (`jwks` | `introspection` | `jwks_then_introspection` | `reject`,
/// default: `jwks_then_introspection`).
///
/// [`TokenStore`]: crate::auth::TokenStore
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UnknownTokenValidation {
    /// Only accept JWTs the issuer's JWKS can verify. Opaque tokens are refused.
    Jwks,
    /// Only ask the authorization server (RFC 7662). Requires a confidential client.
    Introspection,
    /// Verify locally when possible, fall back to introspection when JWKS cannot
    /// answer (non-JWT credential, or issuer keys unreachable). A JWT the JWKS
    /// actively rejects is never re-litigated through introspection.
    #[default]
    JwksThenIntrospection,
    /// Refuse every unknown bearer — only tokens minted by `/oauth/token` work.
    Reject,
}

impl UnknownTokenValidation {
    pub fn from_env() -> Self {
        match std::env::var("OAUTH_UNKNOWN_TOKEN_VALIDATION")
            .as_deref()
            .map(str::trim)
        {
            Ok("jwks") => Self::Jwks,
            Ok("introspection") => Self::Introspection,
            Ok("reject") => Self::Reject,
            Ok("jwks_then_introspection") | Err(_) => Self::JwksThenIntrospection,
            Ok(other) => {
                tracing::warn!(
                    "Unknown OAUTH_UNKNOWN_TOKEN_VALIDATION value '{other}', \
                     falling back to jwks_then_introspection"
                );
                Self::JwksThenIntrospection
            }
        }
    }

    /// Whether local JWKS verification may be attempted.
    pub(crate) fn allows_jwks(self) -> bool {
        matches!(self, Self::Jwks | Self::JwksThenIntrospection)
    }

    /// Whether the authorization server may be asked.
    pub(crate) fn allows_introspection(self) -> bool {
        matches!(self, Self::Introspection | Self::JwksThenIntrospection)
    }
}

/// Pluggable authentication provider for MCP servers
#[derive(Clone)]
pub enum AuthProvider {
    /// No authentication — MCP endpoint is open
    None,
    /// HTTP Basic authentication
    Basic(BasicAuthConfig),
    /// OAuth 2.0 with Keycloak OIDC proxy
    OAuth(OAuthConfig),
}

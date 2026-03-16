use oauth2::{
    AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl,
    basic::BasicClient,
};

// Type alias for the configured client
pub type ConfiguredClient = oauth2::Client<
    oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>,
    oauth2::StandardTokenResponse<oauth2::EmptyExtraTokenFields, oauth2::basic::BasicTokenType>,
    oauth2::StandardTokenIntrospectionResponse<oauth2::EmptyExtraTokenFields, oauth2::basic::BasicTokenType>,
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
    pub fn from_env() -> Result<Self, String> {
        let client_id = std::env::var("OAUTH_CLIENT_ID")
            .map_err(|_| "OAUTH_CLIENT_ID not set")?;
        let client_secret = std::env::var("OAUTH_CLIENT_SECRET").ok();
        let issuer_url = std::env::var("OAUTH_ISSUER_URL")
            .map_err(|_| "OAUTH_ISSUER_URL not set")?;
        let redirect_url = std::env::var("OAUTH_REDIRECT_URL")
            .map_err(|_| "OAUTH_REDIRECT_URL not set")?;

        let scopes = std::env::var("OAUTH_SCOPES")
            .unwrap_or_else(|_| "openid,profile,email".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();

        Ok(Self {
            client_id,
            client_secret,
            issuer_url,
            redirect_url,
            scopes,
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
            .set_redirect_uri(RedirectUrl::new(self.redirect_url.clone()).map_err(|e| e.to_string())?);

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
        let username = std::env::var("BASIC_AUTH_USERNAME")
            .map_err(|_| "BASIC_AUTH_USERNAME not set")?;
        let password = std::env::var("BASIC_AUTH_PASSWORD")
            .map_err(|_| "BASIC_AUTH_PASSWORD not set")?;
        Ok(Self { username, password })
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

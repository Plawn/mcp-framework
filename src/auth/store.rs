use std::{collections::HashMap, sync::Arc, time::{Duration, Instant}};
use tokio::sync::RwLock;
use oauth2::{TokenResponse, basic::BasicTokenResponse};
use reqwest::Client as HttpClient;

/// A stored OAuth token with expiry tracking
#[derive(Clone, Debug)]
pub struct StoredToken {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<Instant>,
}

impl StoredToken {
    pub fn from_token_response(response: &BasicTokenResponse) -> Self {
        let expires_at = response.expires_in().map(|d| Instant::now() + d);

        Self {
            access_token: response.access_token().secret().clone(),
            refresh_token: response.refresh_token().map(|t| t.secret().clone()),
            expires_at,
        }
    }

    /// Check if the token is expired (with 30 second buffer)
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(expires_at) => Instant::now() + Duration::from_secs(30) > expires_at,
            None => false, // No expiry means it doesn't expire
        }
    }
}

/// Pending authorization state (PKCE code verifier + state)
#[derive(Clone, Debug)]
pub struct PendingAuth {
    pub pkce_verifier: String,
    pub created_at: Instant,
}

impl PendingAuth {
    /// Check if this pending auth has expired (5 minute timeout)
    pub fn is_expired(&self) -> bool {
        Instant::now() > self.created_at + Duration::from_secs(300)
    }
}

/// Configuration needed for token refresh
#[derive(Clone)]
pub struct RefreshConfig {
    pub client_id: String,
    pub client_secret: String,
    pub token_url: String,
}

/// Token store for managing OAuth tokens per session
#[derive(Clone)]
pub struct TokenStore {
    /// Map from session_id to stored token
    tokens: Arc<RwLock<HashMap<String, StoredToken>>>,
    /// Map from state to pending auth (for PKCE flow)
    pending_auths: Arc<RwLock<HashMap<String, PendingAuth>>>,
    /// HTTP client for token refresh requests
    http_client: HttpClient,
    /// OAuth config for refresh (optional - not available in all modes)
    refresh_config: Arc<RwLock<Option<RefreshConfig>>>,
}

impl TokenStore {
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
            pending_auths: Arc::new(RwLock::new(HashMap::new())),
            http_client: HttpClient::new(),
            refresh_config: Arc::new(RwLock::new(None)),
        }
    }

    /// Create a new TokenStore with refresh configuration
    pub fn with_refresh_config(config: RefreshConfig) -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
            pending_auths: Arc::new(RwLock::new(HashMap::new())),
            http_client: HttpClient::new(),
            refresh_config: Arc::new(RwLock::new(Some(config))),
        }
    }

    /// Attempt to refresh an expired token
    /// Returns Ok(new_token) if refresh succeeded, Err if refresh not possible
    pub async fn refresh_token(&self, session_id: &str) -> Result<StoredToken, String> {
        // Get current token to extract refresh_token
        let stored = self.get_token(session_id).await
            .ok_or_else(|| "No token found for session".to_string())?;

        let refresh_token = stored.refresh_token
            .ok_or_else(|| "No refresh token available".to_string())?;

        // Get refresh config
        let config_guard = self.refresh_config.read().await;
        let config = config_guard.as_ref()
            .ok_or_else(|| "Refresh configuration not available".to_string())?;

        // Build the refresh request
        let params = [
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh_token),
            ("client_id", &config.client_id),
            ("client_secret", &config.client_secret),
        ];

        tracing::debug!("Attempting token refresh for session {}", session_id);

        let response = self.http_client
            .post(&config.token_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| format!("Refresh request failed: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            tracing::warn!("Token refresh failed: {} - {}", status, body);
            return Err(format!("Token refresh failed: {} - {}", status, body));
        }

        // Parse the token response
        let token_response: serde_json::Value = response.json().await
            .map_err(|e| format!("Failed to parse refresh response: {}", e))?;

        let access_token = token_response["access_token"]
            .as_str()
            .ok_or_else(|| "No access_token in response".to_string())?
            .to_string();

        let new_refresh_token = token_response["refresh_token"]
            .as_str()
            .map(|s| s.to_string());

        let expires_at = token_response["expires_in"]
            .as_u64()
            .map(|secs| Instant::now() + Duration::from_secs(secs));

        let new_token = StoredToken {
            access_token,
            refresh_token: new_refresh_token.or(Some(refresh_token)), // Keep old refresh token if not rotated
            expires_at,
        };

        // Store the refreshed token
        self.store_token(session_id.to_string(), new_token.clone()).await;

        tracing::info!("Token refreshed successfully for session {}", session_id);

        Ok(new_token)
    }

    /// Store a pending authorization (before redirect to Keycloak)
    pub async fn store_pending_auth(&self, state: String, pkce_verifier: String) {
        let mut pending = self.pending_auths.write().await;

        // Clean up expired pending auths
        pending.retain(|_, v| !v.is_expired());

        pending.insert(state, PendingAuth {
            pkce_verifier,
            created_at: Instant::now(),
        });
    }

    /// Get and remove a pending authorization
    pub async fn take_pending_auth(&self, state: &str) -> Option<PendingAuth> {
        let mut pending = self.pending_auths.write().await;
        pending.remove(state)
    }

    /// Store a token for a session
    pub async fn store_token(&self, session_id: String, token: StoredToken) {
        let mut tokens = self.tokens.write().await;
        tokens.insert(session_id, token);
    }

    /// Get a token for a session
    pub async fn get_token(&self, session_id: &str) -> Option<StoredToken> {
        let tokens = self.tokens.read().await;
        tokens.get(session_id).cloned()
    }

    /// Remove a token for a session
    #[allow(dead_code)]
    pub async fn remove_token(&self, session_id: &str) {
        let mut tokens = self.tokens.write().await;
        tokens.remove(session_id);
    }

    /// Check if a session has a valid (non-expired) token
    pub async fn has_valid_token(&self, session_id: &str) -> bool {
        match self.get_token(session_id).await {
            Some(token) => !token.is_expired(),
            None => false,
        }
    }
}

impl Default for TokenStore {
    fn default() -> Self {
        Self::new()
    }
}

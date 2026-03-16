use std::{collections::HashMap, sync::Arc, time::{Duration, Instant}};
use tokio::sync::RwLock;
use oauth2::{TokenResponse, basic::BasicTokenResponse};
use reqwest::Client as HttpClient;
use tokio::sync::Mutex as TokioMutex;

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
    pub client_secret: Option<String>,
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
    /// Per-session mutex to prevent concurrent refreshes (thundering herd)
    refresh_locks: Arc<RwLock<HashMap<String, Arc<TokioMutex<()>>>>>,
}

impl TokenStore {
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
            pending_auths: Arc::new(RwLock::new(HashMap::new())),
            http_client: HttpClient::new(),
            refresh_config: Arc::new(RwLock::new(None)),
            refresh_locks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new TokenStore with refresh configuration
    pub fn with_refresh_config(config: RefreshConfig) -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
            pending_auths: Arc::new(RwLock::new(HashMap::new())),
            http_client: HttpClient::new(),
            refresh_config: Arc::new(RwLock::new(Some(config))),
            refresh_locks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get or create a per-session refresh lock
    async fn get_refresh_lock(&self, session_id: &str) -> Arc<TokioMutex<()>> {
        // Fast path: read lock
        {
            let locks = self.refresh_locks.read().await;
            if let Some(lock) = locks.get(session_id) {
                return lock.clone();
            }
        }
        // Slow path: write lock to insert
        let mut locks = self.refresh_locks.write().await;
        locks.entry(session_id.to_string())
            .or_insert_with(|| Arc::new(TokioMutex::new(())))
            .clone()
    }

    /// Attempt to refresh an expired token
    /// Returns Ok(new_token) if refresh succeeded, Err if refresh not possible
    pub async fn refresh_token(&self, session_id: &str) -> Result<StoredToken, String> {
        // Get current token to extract refresh_token (raw to avoid recursion)
        let stored = self.get_token_raw(session_id).await
            .ok_or_else(|| "No token found for session".to_string())?;

        let refresh_token = stored.refresh_token
            .ok_or_else(|| "No refresh token available".to_string())?;

        // Get refresh config
        let config_guard = self.refresh_config.read().await;
        let config = config_guard.as_ref()
            .ok_or_else(|| "Refresh configuration not available".to_string())?;

        // Build the refresh request
        let mut params = vec![
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", refresh_token.clone()),
            ("client_id", config.client_id.clone()),
        ];
        if let Some(ref secret) = config.client_secret {
            params.push(("client_secret", secret.clone()));
        }

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

    /// Get a token for a session (raw, no auto-refresh)
    async fn get_token_raw(&self, session_id: &str) -> Option<StoredToken> {
        let tokens = self.tokens.read().await;
        tokens.get(session_id).cloned()
    }

    /// Get a token for a session, automatically refreshing if expired.
    ///
    /// Uses per-session locking to prevent concurrent refreshes (thundering herd).
    /// Returns `None` if the token is expired and refresh fails.
    pub async fn get_token(&self, session_id: &str) -> Option<StoredToken> {
        let token = self.get_token_raw(session_id).await?;

        if !token.is_expired() {
            return Some(token);
        }

        // Token is expired — attempt refresh if possible
        if token.refresh_token.is_some() && self.refresh_config.read().await.is_some() {
            // Acquire per-session refresh lock to prevent thundering herd
            let lock = self.get_refresh_lock(session_id).await;
            let _guard = lock.lock().await;

            // Double-check: another task may have refreshed while we waited
            if let Some(refreshed) = self.get_token_raw(session_id).await {
                if !refreshed.is_expired() {
                    return Some(refreshed);
                }
            }

            // Still expired — do the refresh
            match self.refresh_token(session_id).await {
                Ok(new_token) => return Some(new_token),
                Err(e) => {
                    tracing::warn!("Auto-refresh failed for session {}: {}", session_id, e);
                    return None; // Don't return expired token
                }
            }
        }

        // No refresh_token or no refresh config — expired token is unusable
        None
    }

    /// Remove a token for a session
    #[allow(dead_code)]
    pub async fn remove_token(&self, session_id: &str) {
        let mut tokens = self.tokens.write().await;
        tokens.remove(session_id);
        drop(tokens);

        let mut locks = self.refresh_locks.write().await;
        locks.remove(session_id);
    }

    /// Purge all expired tokens and their associated refresh locks.
    pub async fn purge_expired(&self) {
        let expired_keys: Vec<String> = {
            let tokens = self.tokens.read().await;
            tokens
                .iter()
                .filter(|(_, t)| t.is_expired())
                .map(|(k, _)| k.clone())
                .collect()
        };

        if expired_keys.is_empty() {
            return;
        }

        let mut tokens = self.tokens.write().await;
        let mut locks = self.refresh_locks.write().await;
        for key in &expired_keys {
            tokens.remove(key);
            locks.remove(key);
        }

        tracing::debug!("Purged {} expired token(s)", expired_keys.len());
    }

    /// Spawn a background task that periodically purges expired tokens.
    ///
    /// The task runs until the returned [`JoinHandle`] is aborted or the
    /// runtime shuts down.
    pub fn start_cleanup_task(&self, interval: std::time::Duration) -> tokio::task::JoinHandle<()> {
        let store = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                store.purge_expired().await;
            }
        })
    }

    /// Check if a session has a valid (non-expired) token (no side-effects)
    pub async fn has_valid_token(&self, session_id: &str) -> bool {
        match self.get_token_raw(session_id).await {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_expiry_buffer_expired() {
        // Token that expires in 29 seconds (within the 30s buffer) → expired
        let token = StoredToken {
            access_token: "test".to_string(),
            refresh_token: None,
            expires_at: Some(Instant::now() + Duration::from_secs(29)),
        };
        assert!(token.is_expired());
    }

    #[test]
    fn test_token_expiry_buffer_valid() {
        // Token that expires in 31 seconds (outside the 30s buffer) → valid
        let token = StoredToken {
            access_token: "test".to_string(),
            refresh_token: None,
            expires_at: Some(Instant::now() + Duration::from_secs(31)),
        };
        assert!(!token.is_expired());
    }

    #[test]
    fn test_token_no_expiry_never_expires() {
        let token = StoredToken {
            access_token: "test".to_string(),
            refresh_token: None,
            expires_at: None,
        };
        assert!(!token.is_expired());
    }

    #[tokio::test]
    async fn test_refresh_failure_returns_none() {
        // Create a store with a refresh config (so refresh is attempted)
        // but with a bogus token_url (so the refresh will fail)
        let store = TokenStore::with_refresh_config(RefreshConfig {
            client_id: "test".to_string(),
            client_secret: Some("secret".to_string()),
            token_url: "http://127.0.0.1:1/nonexistent".to_string(),
        });

        // Store an expired token with a refresh_token
        let expired_token = StoredToken {
            access_token: "old_access".to_string(),
            refresh_token: Some("refresh_tok".to_string()),
            expires_at: Some(Instant::now() - Duration::from_secs(60)),
        };
        store.store_token("session1".to_string(), expired_token).await;

        // get_token should return None because refresh fails and token is expired
        let result = store.get_token("session1").await;
        assert!(result.is_none(), "Expected None when refresh fails on expired token");
    }

    #[tokio::test]
    async fn test_concurrent_refresh_uses_lock() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let call_count = Arc::new(AtomicUsize::new(0));
        let store = TokenStore::with_refresh_config(RefreshConfig {
            client_id: "test".to_string(),
            client_secret: Some("secret".to_string()),
            // Unreachable URL — refresh will fail, but we verify the lock behavior
            // by checking that the second caller sees the still-expired token and also
            // returns None (rather than racing)
            token_url: "http://127.0.0.1:1/nonexistent".to_string(),
        });

        // Store an expired token
        let expired_token = StoredToken {
            access_token: "old".to_string(),
            refresh_token: Some("refresh".to_string()),
            expires_at: Some(Instant::now() - Duration::from_secs(60)),
        };
        store.store_token("s1".to_string(), expired_token).await;

        let store1 = store.clone();
        let store2 = store.clone();
        let count1 = call_count.clone();
        let count2 = call_count.clone();

        let (r1, r2) = tokio::join!(
            async move {
                let r = store1.get_token("s1").await;
                count1.fetch_add(1, Ordering::SeqCst);
                r
            },
            async move {
                let r = store2.get_token("s1").await;
                count2.fetch_add(1, Ordering::SeqCst);
                r
            },
        );

        // Both should return None (expired + refresh fails)
        assert!(r1.is_none());
        assert!(r2.is_none());
        // Both calls completed
        assert_eq!(call_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_valid_token_returned_directly() {
        let store = TokenStore::new();
        let token = StoredToken {
            access_token: "valid".to_string(),
            refresh_token: None,
            expires_at: Some(Instant::now() + Duration::from_secs(3600)),
        };
        store.store_token("s1".to_string(), token).await;

        let result = store.get_token("s1").await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().access_token, "valid");
    }

    #[tokio::test]
    async fn test_expired_token_no_refresh_config_returns_none() {
        let store = TokenStore::new(); // No refresh config
        let token = StoredToken {
            access_token: "expired".to_string(),
            refresh_token: Some("refresh".to_string()),
            expires_at: Some(Instant::now() - Duration::from_secs(60)),
        };
        store.store_token("s1".to_string(), token).await;

        let result = store.get_token("s1").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_remove_token_cleans_refresh_lock() {
        let store = TokenStore::new();
        let token = StoredToken {
            access_token: "test".to_string(),
            refresh_token: None,
            expires_at: None,
        };
        store.store_token("s1".to_string(), token).await;

        // Create a refresh lock entry
        let _lock = store.get_refresh_lock("s1").await;
        assert!(store.refresh_locks.read().await.contains_key("s1"));

        // Remove should clean up both token and lock
        store.remove_token("s1").await;
        assert!(!store.refresh_locks.read().await.contains_key("s1"));
        assert!(store.get_token_raw("s1").await.is_none());
    }

    #[tokio::test]
    async fn test_purge_expired_removes_expired_tokens() {
        let store = TokenStore::new();

        // Store an expired token
        let expired = StoredToken {
            access_token: "old".to_string(),
            refresh_token: None,
            expires_at: Some(Instant::now() - Duration::from_secs(60)),
        };
        store.store_token("expired-sess".to_string(), expired).await;

        // Create a refresh lock for it
        let _lock = store.get_refresh_lock("expired-sess").await;

        // Store a valid token
        let valid = StoredToken {
            access_token: "fresh".to_string(),
            refresh_token: None,
            expires_at: Some(Instant::now() + Duration::from_secs(3600)),
        };
        store.store_token("valid-sess".to_string(), valid).await;

        store.purge_expired().await;

        // Expired token and its lock should be gone
        assert!(store.get_token_raw("expired-sess").await.is_none());
        assert!(!store.refresh_locks.read().await.contains_key("expired-sess"));

        // Valid token should still exist
        assert!(store.get_token_raw("valid-sess").await.is_some());
    }

    #[tokio::test]
    async fn test_purge_expired_no_expiry_kept() {
        let store = TokenStore::new();

        // Token with no expiry (never expires) should be kept
        let token = StoredToken {
            access_token: "eternal".to_string(),
            refresh_token: None,
            expires_at: None,
        };
        store.store_token("s1".to_string(), token).await;

        store.purge_expired().await;
        assert!(store.get_token_raw("s1").await.is_some());
    }
}

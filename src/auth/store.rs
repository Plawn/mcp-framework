use std::any::Any;
use std::{collections::HashMap, sync::Arc, time::{Duration, Instant}};
use serde::{Serialize, Deserialize};
use tokio::sync::RwLock;
use oauth2::{TokenResponse, basic::BasicTokenResponse};
use reqwest::Client as HttpClient;
use tokio::sync::Mutex as TokioMutex;

use crate::constants::{
    NS_TOKENS, NS_OPAQUE, NS_OPAQUE_ACCESS, NS_OPAQUE_REFRESH, NS_REFRESH_LOCK,
    TOKEN_EXPIRY_BUFFER, PENDING_AUTH_TIMEOUT, OPAQUE_REFRESH_TTL,
    REFRESH_LOCK_TTL, REFRESH_LOCK_WAIT, REFRESH_LOCK_POLL,
};
use crate::persistence::{PersistenceBackend, PersistenceError, spawn_persist, spawn_persist_raw};

/// A stored OAuth token with expiry tracking and optional decoded claims.
///
/// When a [`ClaimsDecoder`](TokenStore::with_claims_decoder) is configured on the
/// `TokenStore`, claims are decoded automatically during [`store_token`](TokenStore::store_token)
/// and attached to the `decoded_claims` field. Access them with [`claims::<C>()`](StoredToken::claims).
#[derive(Clone)]
pub struct StoredToken {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<Instant>,
    /// Decoded claims from the access token, populated by the global claims decoder.
    /// Use [`claims::<C>()`](Self::claims) to access them.
    pub(crate) decoded_claims: Option<Arc<dyn Any + Send + Sync>>,
}

impl StoredToken {
    /// Build a `StoredToken` from its public fields. `decoded_claims` is
    /// populated automatically when the token is inserted via
    /// [`TokenStore::store_token`] (if a claims decoder is configured).
    pub fn new(
        access_token: String,
        refresh_token: Option<String>,
        expires_at: Option<Instant>,
    ) -> Self {
        Self {
            access_token,
            refresh_token,
            expires_at,
            decoded_claims: None,
        }
    }

    pub fn from_token_response(response: &BasicTokenResponse) -> Self {
        let expires_at = response.expires_in().map(|d| Instant::now() + d);

        Self {
            access_token: response.access_token().secret().clone(),
            refresh_token: response.refresh_token().map(|t| t.secret().clone()),
            expires_at,
            decoded_claims: None,
        }
    }

    /// Downcast the decoded claims to the expected type.
    ///
    /// Returns `None` if no claims decoder was configured, if the token could
    /// not be decoded, or if `C` does not match the type produced by the decoder.
    pub fn claims<C: 'static>(&self) -> Option<&C> {
        self.decoded_claims.as_ref()?.downcast_ref::<C>()
    }

    /// Check if the token is expired (with 30 second buffer)
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(expires_at) => Instant::now() + TOKEN_EXPIRY_BUFFER > expires_at,
            None => false, // No expiry means it doesn't expire
        }
    }
}

impl std::fmt::Debug for StoredToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredToken")
            .field("access_token", &"[redacted]")
            .field("refresh_token", &self.refresh_token.as_ref().map(|_| "[redacted]"))
            .field("expires_at", &self.expires_at)
            .field("has_decoded_claims", &self.decoded_claims.is_some())
            .finish()
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
        Instant::now() > self.created_at + PENDING_AUTH_TIMEOUT
    }
}

#[derive(Serialize, Deserialize)]
struct PersistedToken {
    access_token: String,
    refresh_token: Option<String>,
    expires_in_secs: Option<u64>,
}

impl PersistedToken {
    fn from_stored(token: &StoredToken) -> Self {
        let expires_in_secs = token.expires_at.map(|ea| {
            let now = Instant::now();
            if ea > now {
                // Round up to avoid truncating sub-second time
                (ea - now).as_secs().saturating_add(1)
            } else {
                0
            }
        });
        Self {
            access_token: token.access_token.clone(),
            refresh_token: token.refresh_token.clone(),
            expires_in_secs,
        }
    }

    fn into_stored(self) -> StoredToken {
        let expires_at = self
            .expires_in_secs
            .map(|secs| Instant::now() + Duration::from_secs(secs));
        StoredToken {
            access_token: self.access_token,
            refresh_token: self.refresh_token,
            expires_at,
            decoded_claims: None,
        }
    }
}

/// Persisted opaque-to-session mapping (one entry per session in opaque mode).
#[derive(Serialize, Deserialize)]
struct PersistedOpaqueMapping {
    opaque_access: String,
    opaque_refresh: String,
}

/// Configuration needed for token refresh
#[derive(Clone)]
pub struct RefreshConfig {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub token_url: String,
}

/// Type-erased claims decoder function.
pub type ClaimsDecoderFn = Arc<dyn Fn(&str) -> Option<Arc<dyn Any + Send + Sync>> + Send + Sync>;

/// Consolidated index for opaque token mappings, guarded by a single RwLock
/// to ensure atomicity across all three maps.
#[derive(Default)]
struct OpaqueIndex {
    /// opaque access token → session_id
    access_to_session: HashMap<String, String>,
    /// opaque refresh token → session_id
    refresh_to_session: HashMap<String, String>,
    /// session_id → (opaque_access, opaque_refresh)
    session_to_opaques: HashMap<String, (String, String)>,
}

impl OpaqueIndex {
    /// Remove all maps for a session, returning the `(opaque_access, opaque_refresh)`
    /// pair that was removed (so callers can clean up the persisted inverse index).
    fn remove_session(&mut self, session_id: &str) -> Option<(String, String)> {
        if let Some((oa, or)) = self.session_to_opaques.remove(session_id) {
            self.access_to_session.remove(&oa);
            self.refresh_to_session.remove(&or);
            Some((oa, or))
        } else {
            None
        }
    }
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
    /// Global claims decoder applied during `store_token`.
    pub(crate) claims_decoder: Option<ClaimsDecoderFn>,
    /// Optional persistence backend for surviving restarts.
    persistence: Option<Arc<dyn PersistenceBackend>>,

    /// Opaque token index (only populated in Opaque token mode).
    opaque_index: Arc<RwLock<OpaqueIndex>>,
}

impl TokenStore {
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
            pending_auths: Arc::new(RwLock::new(HashMap::new())),
            http_client: HttpClient::new(),
            refresh_config: Arc::new(RwLock::new(None)),
            refresh_locks: Arc::new(RwLock::new(HashMap::new())),
            claims_decoder: None,
            persistence: None,
            opaque_index: Arc::new(RwLock::new(OpaqueIndex::default())),
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
            claims_decoder: None,
            persistence: None,
            opaque_index: Arc::new(RwLock::new(OpaqueIndex::default())),
        }
    }

    /// Attach a persistence backend for surviving server restarts.
    pub fn with_persistence(mut self, backend: Arc<dyn PersistenceBackend>) -> Self {
        self.persistence = Some(backend);
        self
    }

    /// Set the persistence backend (mutable reference variant).
    pub fn set_persistence(&mut self, backend: Arc<dyn PersistenceBackend>) {
        self.persistence = Some(backend);
    }

    /// Configure a global claims decoder.
    ///
    /// The decoder is called automatically during [`store_token`](Self::store_token)
    /// and the result is attached to [`StoredToken::decoded_claims`]. Access the
    /// decoded claims via [`StoredToken::claims::<C>()`](StoredToken::claims).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// #[derive(Debug, Clone)]
    /// struct MyClaims { roles: Vec<String> }
    ///
    /// let store = TokenStore::new().with_claims_decoder(|token: &str| -> Option<MyClaims> {
    ///     let payload = base64_decode(token.split('.').nth(1)?)?;
    ///     serde_json::from_slice(&payload).ok()
    /// });
    /// ```
    pub fn with_claims_decoder<C: Any + Send + Sync + 'static>(
        mut self,
        decoder: impl Fn(&str) -> Option<C> + Send + Sync + 'static,
    ) -> Self {
        self.claims_decoder = Some(Arc::new(move |token: &str| {
            decoder(token).map(|c| Arc::new(c) as Arc<dyn Any + Send + Sync>)
        }));
        self
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
            decoded_claims: None, // re-decoded by store_token via claims_decoder
        };

        // Store the refreshed token (store_token applies the claims decoder)
        self.store_token(session_id.to_string(), new_token).await;

        tracing::info!("Token refreshed successfully for session {}", session_id);

        // Return the stored version which has decoded claims applied
        Ok(self.get_token_raw(session_id).await.expect("just stored"))
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

    /// Store a token for a session.
    ///
    /// If a [claims decoder](Self::with_claims_decoder) is configured, it is
    /// applied automatically and the result is stored in
    /// [`StoredToken::decoded_claims`].
    pub async fn store_token(&self, session_id: String, mut token: StoredToken) {
        if let Some(ref decoder) = self.claims_decoder {
            token.decoded_claims = (decoder)(&token.access_token);
        }

        let persist_data = self.persistence.as_ref().map(|backend| {
            let persisted = PersistedToken::from_stored(&token);
            let ttl = token.expires_at.map(|ea| {
                let now = Instant::now();
                if ea > now { ea - now } else { Duration::ZERO }
            });
            (backend, persisted, ttl)
        });

        let mut tokens = self.tokens.write().await;
        tokens.insert(session_id.clone(), token);
        drop(tokens);

        if let Some((backend, persisted, ttl)) = persist_data {
            spawn_persist(backend, NS_TOKENS, session_id, &persisted, ttl);
        }
    }

    /// Get a token for a session (raw, no auto-refresh).
    ///
    /// On a memory miss, falls back to the persistence backend (read-through) so
    /// that a request served by an instance that did not create the session can
    /// still resolve the token. A token read from the backend is written back to
    /// the in-memory cache.
    async fn get_token_raw(&self, session_id: &str) -> Option<StoredToken> {
        // Fast path: in-memory hit (no backend round-trip).
        if let Some(token) = self.tokens.read().await.get(session_id).cloned() {
            return Some(token);
        }

        // Slow path: read-through to the persistence backend.
        let token = self.load_token_from_backend(session_id).await?;

        // Write-back to the cache. If a concurrent task already populated the
        // entry, keep that one (it may be fresher) and return it.
        let mut tokens = self.tokens.write().await;
        let entry = tokens.entry(session_id.to_string()).or_insert(token);
        Some(entry.clone())
    }

    /// Read a token directly from the persistence backend, applying the claims
    /// decoder. Does not touch the in-memory cache. Returns `None` if there is no
    /// backend, no entry, or the entry is corrupted.
    async fn load_token_from_backend(&self, session_id: &str) -> Option<StoredToken> {
        let backend = self.persistence.as_ref()?;
        let bytes = match backend.get(NS_TOKENS, session_id).await {
            Ok(b) => b?,
            Err(e) => {
                tracing::warn!("Read-through get failed for token {session_id}: {e}");
                return None;
            }
        };
        let persisted: PersistedToken = match serde_json::from_slice(&bytes) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("Corrupted persisted token for session {session_id}: {e}");
                return None;
            }
        };
        let mut token = persisted.into_stored();
        if let Some(ref decoder) = self.claims_decoder {
            token.decoded_claims = (decoder)(&token.access_token);
        }
        Some(token)
    }

    /// Read the stored token for a session without triggering a refresh.
    ///
    /// Returns the token as-is (even if expired). Use [`get_token`](Self::get_token)
    /// when you need an auto-refresh on expiry.
    pub async fn peek_token(&self, session_id: &str) -> Option<StoredToken> {
        self.get_token_raw(session_id).await
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
            // Acquire per-session refresh lock to prevent intra-process thundering herd
            let lock = self.get_refresh_lock(session_id).await;
            let _guard = lock.lock().await;

            // Double-check: another task (or instance, via read-through) may have
            // refreshed while we waited.
            if let Some(refreshed) = self.get_token_raw(session_id).await
                && !refreshed.is_expired() {
                    return Some(refreshed);
                }

            // Still expired — refresh, coordinating across instances.
            return self.refresh_with_distributed_lock(session_id).await;
        }

        // No refresh_token or no refresh config — expired token is unusable
        None
    }

    /// Refresh the token while serializing across instances with a distributed
    /// lock. If a peer instance is already refreshing, wait for its result to
    /// land in persistence and adopt it instead of issuing a duplicate refresh.
    ///
    /// Falls back to a plain local refresh when no persistence backend is
    /// configured (single-instance) or when the backend does not support
    /// distributed locking.
    async fn refresh_with_distributed_lock(&self, session_id: &str) -> Option<StoredToken> {
        let Some(backend) = self.persistence.clone() else {
            return self.do_refresh(session_id).await;
        };

        // Unique token for this acquisition so we only ever release our own lock.
        let lock_token = uuid::Uuid::new_v4().to_string();
        let deadline = Instant::now() + REFRESH_LOCK_WAIT;
        let mut holding = false;
        loop {
            match backend.try_acquire_lock(NS_REFRESH_LOCK, session_id, &lock_token, REFRESH_LOCK_TTL).await {
                Ok(true) => {
                    holding = true;
                    break;
                }
                Ok(false) => {
                    // A peer holds the lock — adopt its refreshed token if it has
                    // already been written back to persistence.
                    if let Some(fresh) = self.adopt_persisted_token(session_id).await {
                        return Some(fresh);
                    }
                    if Instant::now() >= deadline {
                        tracing::warn!(
                            "Distributed refresh lock wait timed out for session {session_id}; refreshing locally"
                        );
                        break;
                    }
                    tokio::time::sleep(REFRESH_LOCK_POLL).await;
                }
                Err(e) => {
                    tracing::warn!("Distributed refresh lock error for session {session_id}: {e}; refreshing locally");
                    break;
                }
            }
        }

        // Final check before doing the work ourselves: a peer may have written a
        // fresh token in the window just before we acquired the lock.
        if let Some(fresh) = self.adopt_persisted_token(session_id).await {
            if holding {
                let _ = backend.release_lock(NS_REFRESH_LOCK, session_id, &lock_token).await;
            }
            return Some(fresh);
        }

        let result = self.do_refresh(session_id).await;
        if holding {
            let _ = backend.release_lock(NS_REFRESH_LOCK, session_id, &lock_token).await;
        }
        result
    }

    /// Perform a token refresh, logging and swallowing failures into `None`.
    async fn do_refresh(&self, session_id: &str) -> Option<StoredToken> {
        match self.refresh_token(session_id).await {
            Ok(new_token) => Some(new_token),
            Err(e) => {
                tracing::warn!("Auto-refresh failed for session {}: {}", session_id, e);
                None // Don't return expired token
            }
        }
    }

    /// Read the persisted token for a session and, if it is non-expired, adopt it
    /// into the in-memory cache and return it. Used to pick up a refresh performed
    /// by a peer instance without re-issuing the refresh.
    async fn adopt_persisted_token(&self, session_id: &str) -> Option<StoredToken> {
        let token = self.load_token_from_backend(session_id).await?;
        if token.is_expired() {
            return None;
        }
        self.tokens.write().await.insert(session_id.to_string(), token.clone());
        Some(token)
    }

    // === Opaque token mode ===

    /// Store an opaque-to-session mapping (used in Opaque token mode).
    ///
    /// Replaces any existing mapping for the same session, cleaning up old
    /// opaque tokens in the process. All index mutations happen under a
    /// single write lock to prevent concurrent observers from seeing
    /// inconsistent state.
    pub async fn store_opaque_mapping(
        &self,
        session_id: String,
        opaque_access: String,
        opaque_refresh: String,
    ) {
        let persist_mapping = self.persistence.is_some().then(|| PersistedOpaqueMapping {
            opaque_access: opaque_access.clone(),
            opaque_refresh: opaque_refresh.clone(),
        });

        let old = {
            let mut idx = self.opaque_index.write().await;
            let old = idx.remove_session(&session_id);
            idx.access_to_session.insert(opaque_access.clone(), session_id.clone());
            idx.refresh_to_session.insert(opaque_refresh.clone(), session_id.clone());
            idx.session_to_opaques.insert(session_id.clone(), (opaque_access.clone(), opaque_refresh.clone()));
            old
        };

        if let Some(ref backend) = self.persistence {
            // Forward mapping (session_id → opaques), used by load_persisted/cleanup.
            spawn_persist(backend, NS_OPAQUE, session_id.clone(), &persist_mapping.unwrap(), Some(OPAQUE_REFRESH_TTL));
            // Inverse index (opaque → session_id), enables cross-instance read-through.
            spawn_persist_raw(backend, NS_OPAQUE_ACCESS, opaque_access, session_id.clone().into_bytes(), Some(OPAQUE_REFRESH_TTL));
            spawn_persist_raw(backend, NS_OPAQUE_REFRESH, opaque_refresh, session_id.into_bytes(), Some(OPAQUE_REFRESH_TTL));

            // Drop the previous session's inverse entries (opaque tokens rotated).
            if let Some((old_access, old_refresh)) = old {
                let backend = backend.clone();
                tokio::spawn(async move {
                    let _ = backend.delete(NS_OPAQUE_ACCESS, &old_access).await;
                    let _ = backend.delete(NS_OPAQUE_REFRESH, &old_refresh).await;
                });
            }
        }
    }

    /// Resolve an opaque access token to a session ID.
    ///
    /// On a memory miss, falls back to the persisted inverse index
    /// (`NS_OPAQUE_ACCESS`) so a request served by an instance that did not mint
    /// the opaque token can still resolve it. The full opaque mapping is then
    /// hydrated into the in-memory index.
    pub async fn resolve_opaque_access(&self, opaque_access: &str) -> Option<String> {
        if let Some(s) = self.opaque_index.read().await.access_to_session.get(opaque_access).cloned() {
            return Some(s);
        }
        let session_id = self.load_inverse(NS_OPAQUE_ACCESS, opaque_access).await?;
        self.hydrate_opaque(&session_id).await;
        Some(session_id)
    }

    /// Resolve an opaque refresh token to a session ID (read-through, see
    /// [`resolve_opaque_access`](Self::resolve_opaque_access)).
    pub async fn resolve_opaque_refresh(&self, opaque_refresh: &str) -> Option<String> {
        if let Some(s) = self.opaque_index.read().await.refresh_to_session.get(opaque_refresh).cloned() {
            return Some(s);
        }
        let session_id = self.load_inverse(NS_OPAQUE_REFRESH, opaque_refresh).await?;
        self.hydrate_opaque(&session_id).await;
        Some(session_id)
    }

    /// Read an inverse-index entry (`opaque token → session_id`) from persistence.
    async fn load_inverse(&self, ns: &'static str, token: &str) -> Option<String> {
        let backend = self.persistence.as_ref()?;
        let bytes = match backend.get(ns, token).await {
            Ok(b) => b?,
            Err(e) => {
                tracing::warn!("Read-through get failed for {ns}/{token}: {e}");
                return None;
            }
        };
        String::from_utf8(bytes).ok()
    }

    /// Reconstruct the full in-memory opaque index for a session from the
    /// persisted forward mapping (`NS_OPAQUE`). No-op if already present locally
    /// (don't clobber fresher local state).
    async fn hydrate_opaque(&self, session_id: &str) {
        let Some(backend) = self.persistence.as_ref() else { return };
        let mapping: PersistedOpaqueMapping = match backend.get(NS_OPAQUE, session_id).await {
            Ok(Some(bytes)) => match serde_json::from_slice(&bytes) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!("Corrupted opaque mapping for session {session_id}: {e}");
                    return;
                }
            },
            _ => return,
        };

        let mut idx = self.opaque_index.write().await;
        if idx.session_to_opaques.contains_key(session_id) {
            return;
        }
        idx.access_to_session.insert(mapping.opaque_access.clone(), session_id.to_string());
        idx.refresh_to_session.insert(mapping.opaque_refresh.clone(), session_id.to_string());
        idx.session_to_opaques.insert(session_id.to_string(), (mapping.opaque_access, mapping.opaque_refresh));
    }

    /// Remove all opaque mappings for a session (in memory and persisted,
    /// including the inverse index).
    pub async fn remove_opaque_for_session(&self, session_id: &str) {
        let removed = {
            let mut idx = self.opaque_index.write().await;
            idx.remove_session(session_id)
        };

        let Some(backend) = self.persistence.clone() else { return };

        // Determine the opaque token values to clean up the inverse index. If the
        // session wasn't in local memory (cross-instance), recover them from the
        // persisted forward mapping.
        let opaques = match removed {
            Some(pair) => Some(pair),
            None => match backend.get(NS_OPAQUE, session_id).await {
                Ok(Some(bytes)) => serde_json::from_slice::<PersistedOpaqueMapping>(&bytes)
                    .ok()
                    .map(|m| (m.opaque_access, m.opaque_refresh)),
                _ => None,
            },
        };

        let key = session_id.to_string();
        tokio::spawn(async move {
            if let Err(e) = backend.delete(NS_OPAQUE, &key).await {
                tracing::warn!("Failed to delete persisted opaque mapping for {key}: {e}");
            }
            if let Some((oa, or)) = opaques {
                let _ = backend.delete(NS_OPAQUE_ACCESS, &oa).await;
                let _ = backend.delete(NS_OPAQUE_REFRESH, &or).await;
            }
        });
    }

    /// Remove a token for a session
    #[allow(dead_code)]
    pub async fn remove_token(&self, session_id: &str) {
        let mut tokens = self.tokens.write().await;
        tokens.remove(session_id);
        drop(tokens);

        let mut locks = self.refresh_locks.write().await;
        locks.remove(session_id);
        drop(locks);

        self.remove_opaque_for_session(session_id).await;

        if let Some(ref backend) = self.persistence {
            let backend = backend.clone();
            let key = session_id.to_string();
            tokio::spawn(async move {
                if let Err(e) = backend.delete(NS_TOKENS, &key).await {
                    tracing::warn!("Failed to delete persisted token for session {key}: {e}");
                }
            });
        }
    }

    /// Purge all expired tokens and their associated refresh locks and opaque mappings.
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
        drop(tokens);
        drop(locks);

        // Clean up opaque mappings for expired sessions, capturing the opaque
        // token values so the persisted inverse index can be cleaned too.
        let removed_opaques: Vec<(String, String)> = {
            let mut idx = self.opaque_index.write().await;
            expired_keys
                .iter()
                .filter_map(|key| idx.remove_session(key))
                .collect()
        };

        tracing::debug!("Purged {} expired token(s)", expired_keys.len());

        if let Some(ref backend) = self.persistence {
            let backend = backend.clone();
            let keys = expired_keys;
            tokio::spawn(async move {
                for key in &keys {
                    if let Err(e) = backend.delete(NS_TOKENS, key).await {
                        tracing::warn!("Failed to delete persisted token {key}: {e}");
                    }
                    if let Err(e) = backend.delete(NS_OPAQUE, key).await {
                        tracing::warn!("Failed to delete persisted opaque mapping {key}: {e}");
                    }
                }
                for (oa, or) in &removed_opaques {
                    let _ = backend.delete(NS_OPAQUE_ACCESS, oa).await;
                    let _ = backend.delete(NS_OPAQUE_REFRESH, or).await;
                }
            });
        }
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

    /// Load all tokens and opaque mappings from the persistence backend into memory.
    ///
    /// Entries that fail to deserialize are skipped with a warning.
    /// The claims decoder is applied to each loaded token.
    pub async fn load_persisted(&self) -> Result<(), PersistenceError> {
        let backend = match &self.persistence {
            Some(b) => b,
            None => return Ok(()),
        };

        // Load tokens
        let keys = backend.keys(NS_TOKENS).await?;
        let mut entries = Vec::new();

        for key in keys {
            let bytes = match backend.get(NS_TOKENS, &key).await? {
                Some(b) => b,
                None => continue,
            };

            let persisted: PersistedToken = match serde_json::from_slice(&bytes) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!("Skipping corrupted persisted token for session {key}: {e}");
                    continue;
                }
            };

            let mut token = persisted.into_stored();

            if token.is_expired() {
                let _ = backend.delete(NS_TOKENS, &key).await;
                continue;
            }

            if let Some(ref decoder) = self.claims_decoder {
                token.decoded_claims = (decoder)(&token.access_token);
            }

            entries.push((key, token));
        }

        if !entries.is_empty() {
            let count = entries.len();
            let mut tokens = self.tokens.write().await;
            for (key, token) in entries {
                tokens.insert(key, token);
            }
            tracing::info!("Loaded {count} persisted token(s)");
        }

        // Load opaque mappings.
        // Snapshot valid session IDs under a short read lock, then release it
        // before the I/O loop so token writes aren't blocked.
        let opaque_keys = backend.keys(NS_OPAQUE).await?;
        let valid_sessions: std::collections::HashSet<String> = {
            let tokens = self.tokens.read().await;
            tokens.keys().cloned().collect()
        };
        let mut opaque_entries = Vec::new();

        for session_id in opaque_keys {
            let bytes = match backend.get(NS_OPAQUE, &session_id).await? {
                Some(b) => b,
                None => continue,
            };

            let mapping: PersistedOpaqueMapping = match serde_json::from_slice(&bytes) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!("Skipping corrupted opaque mapping for session {session_id}: {e}");
                    continue;
                }
            };

            if !valid_sessions.contains(&session_id) {
                // Orphaned mapping (token expired) — drop the forward mapping and
                // its inverse-index entries so they don't leak.
                let _ = backend.delete(NS_OPAQUE, &session_id).await;
                let _ = backend.delete(NS_OPAQUE_ACCESS, &mapping.opaque_access).await;
                let _ = backend.delete(NS_OPAQUE_REFRESH, &mapping.opaque_refresh).await;
                continue;
            }

            opaque_entries.push((session_id, mapping));
        }

        if !opaque_entries.is_empty() {
            let count = opaque_entries.len();
            let mut idx = self.opaque_index.write().await;
            for (session_id, mapping) in opaque_entries {
                idx.access_to_session.insert(mapping.opaque_access.clone(), session_id.clone());
                idx.refresh_to_session.insert(mapping.opaque_refresh.clone(), session_id.clone());
                idx.session_to_opaques.insert(session_id, (mapping.opaque_access, mapping.opaque_refresh));
            }
            tracing::info!("Loaded {count} persisted opaque mapping(s)");
        }

        Ok(())
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
#[path = "store_tests.rs"]
mod tests;

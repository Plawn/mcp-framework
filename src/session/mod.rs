//! Typed session storage for MCP servers.
//!
//! [`SessionStore`] provides a generic, thread-safe store keyed by session ID.
//! Consumers define their own session data type `T` (must be `Send + Sync + Default + Clone + 'static`),
//! and the store handles creation, access, TTL expiration, and background cleanup.
//!
//! # Example
//!
//! ```rust,ignore
//! use mcp_framework::session::SessionStore;
//! use std::time::Duration;
//!
//! #[derive(Default, Clone)]
//! struct MySession {
//!     user_name: Option<String>,
//!     request_count: u32,
//! }
//!
//! let store = SessionStore::<MySession>::new(Duration::from_secs(1800));
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rmcp::model::Extensions;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

/// Internal entry wrapping session data with a last-access timestamp.
struct SessionEntry<T> {
    data: T,
    last_access: Instant,
}

/// A generic, thread-safe session store keyed by session ID.
///
/// `T` is the consumer-defined session data type. It must implement
/// `Send + Sync + Default + Clone + 'static`.
///
/// Cloning a `SessionStore` produces a new handle to the **same** underlying data
/// (same pattern as [`TokenStore`](crate::auth::TokenStore)).
#[derive(Clone)]
pub struct SessionStore<T: Send + Sync + 'static> {
    sessions: Arc<RwLock<HashMap<String, SessionEntry<T>>>>,
    ttl: Duration,
}

impl<T: Send + Sync + Default + Clone + 'static> SessionStore<T> {
    /// Create a new session store with the given TTL.
    pub fn new(ttl: Duration) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            ttl,
        }
    }

    /// Get the session data for `session_id`, creating it with `T::default()` if absent.
    ///
    /// Updates the last-access timestamp.
    pub async fn get_or_create(&self, session_id: &str) -> T {
        let mut sessions = self.sessions.write().await;
        let entry = sessions
            .entry(session_id.to_string())
            .or_insert_with(|| SessionEntry {
                data: T::default(),
                last_access: Instant::now(),
            });
        entry.last_access = Instant::now();
        entry.data.clone()
    }

    /// Get the session data for `session_id` if it exists.
    ///
    /// Updates the last-access timestamp on hit.
    pub async fn get(&self, session_id: &str) -> Option<T> {
        let mut sessions = self.sessions.write().await;
        if let Some(entry) = sessions.get_mut(session_id) {
            entry.last_access = Instant::now();
            Some(entry.data.clone())
        } else {
            None
        }
    }

    /// Update the session data for `session_id` using a closure.
    ///
    /// If the session does not exist, it is created with `T::default()` first.
    /// Returns the updated value.
    pub async fn update<F>(&self, session_id: &str, f: F) -> T
    where
        F: FnOnce(&mut T),
    {
        let mut sessions = self.sessions.write().await;
        let entry = sessions
            .entry(session_id.to_string())
            .or_insert_with(|| SessionEntry {
                data: T::default(),
                last_access: Instant::now(),
            });
        f(&mut entry.data);
        entry.last_access = Instant::now();
        entry.data.clone()
    }

    /// Remove the session for `session_id`, returning the data if it existed.
    pub async fn remove(&self, session_id: &str) -> Option<T> {
        let mut sessions = self.sessions.write().await;
        sessions.remove(session_id).map(|e| e.data)
    }

    /// Purge all sessions whose last access is older than the TTL.
    pub async fn purge_expired(&self) {
        let mut sessions = self.sessions.write().await;
        let now = Instant::now();
        let ttl = self.ttl;
        sessions.retain(|_, entry| now.duration_since(entry.last_access) < ttl);
    }

    /// Spawn a background task that periodically purges expired sessions.
    ///
    /// The cleanup interval is `ttl / 2`. The task runs until the returned
    /// [`JoinHandle`] is aborted or the runtime shuts down.
    pub fn start_cleanup_task(&self) -> JoinHandle<()> {
        let store = self.clone();
        let interval = self.ttl / 2;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                store.purge_expired().await;
            }
        })
    }

    /// Return the number of active sessions.
    pub async fn len(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// Return whether the store is empty.
    pub async fn is_empty(&self) -> bool {
        self.sessions.read().await.is_empty()
    }
}

/// Default TTL for sessions: 30 minutes.
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(30 * 60);

impl<T: Send + Sync + Default + Clone + 'static> Default for SessionStore<T> {
    fn default() -> Self {
        Self::new(DEFAULT_SESSION_TTL)
    }
}

/// Extract the MCP session ID from request context extensions.
///
/// Looks for the `mcp-session-id` header in the HTTP request parts
/// injected by `StreamableHttpService`. Returns `"default"` if no
/// HTTP parts or header are available (e.g., stdio mode).
pub fn resolve_session_id(extensions: &Extensions) -> &str {
    extensions
        .get::<http::request::Parts>()
        .and_then(|parts| {
            parts
                .headers
                .get("mcp-session-id")
                .and_then(|h| h.to_str().ok())
        })
        .unwrap_or("default")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default, Clone, Debug, PartialEq)]
    struct TestSession {
        counter: u32,
        name: Option<String>,
    }

    #[tokio::test]
    async fn get_or_create_returns_default() {
        let store = SessionStore::<TestSession>::new(Duration::from_secs(60));
        let session = store.get_or_create("sess-1").await;
        assert_eq!(session, TestSession::default());
    }

    #[tokio::test]
    async fn get_returns_none_for_missing() {
        let store = SessionStore::<TestSession>::new(Duration::from_secs(60));
        assert!(store.get("nonexistent").await.is_none());
    }

    #[tokio::test]
    async fn update_modifies_session() {
        let store = SessionStore::<TestSession>::new(Duration::from_secs(60));
        store.get_or_create("sess-1").await;

        let updated = store
            .update("sess-1", |s| {
                s.counter = 42;
                s.name = Some("Alice".to_string());
            })
            .await;

        assert_eq!(updated.counter, 42);
        assert_eq!(updated.name.as_deref(), Some("Alice"));

        // Verify persistence
        let fetched = store.get("sess-1").await.unwrap();
        assert_eq!(fetched.counter, 42);
    }

    #[tokio::test]
    async fn update_creates_if_absent() {
        let store = SessionStore::<TestSession>::new(Duration::from_secs(60));
        let result = store.update("new-sess", |s| s.counter = 10).await;
        assert_eq!(result.counter, 10);
    }

    #[tokio::test]
    async fn remove_returns_data() {
        let store = SessionStore::<TestSession>::new(Duration::from_secs(60));
        store.update("sess-1", |s| s.counter = 5).await;

        let removed = store.remove("sess-1").await;
        assert_eq!(removed.unwrap().counter, 5);
        assert!(store.get("sess-1").await.is_none());
    }

    #[tokio::test]
    async fn purge_expired_removes_old_sessions() {
        let store = SessionStore::<TestSession>::new(Duration::from_millis(50));
        store.get_or_create("old").await;

        // Wait for TTL to expire
        tokio::time::sleep(Duration::from_millis(60)).await;

        // Create a fresh session
        store.get_or_create("fresh").await;

        store.purge_expired().await;

        assert!(store.get("old").await.is_none());
        // "fresh" was re-created by get, so still has a recent last_access
        // but purge_expired doesn't touch last_access — re-check
        assert_eq!(store.len().await, 1);
    }

    #[tokio::test]
    async fn cleanup_task_purges_expired() {
        let store = SessionStore::<TestSession>::new(Duration::from_millis(50));
        store.get_or_create("will-expire").await;

        let handle = store.start_cleanup_task();

        // Wait for cleanup to run (interval = ttl/2 = 25ms, plus some margin)
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(store.is_empty().await);
        handle.abort();
    }

    #[test]
    fn resolve_session_id_no_parts() {
        let extensions = Extensions::new();
        assert_eq!(resolve_session_id(&extensions), "default");
    }

    #[test]
    fn resolve_session_id_with_header() {
        let mut extensions = Extensions::new();
        let request = http::Request::builder()
            .header("mcp-session-id", "sess-abc")
            .body(())
            .unwrap();
        let (parts, _) = request.into_parts();
        extensions.insert(parts);

        assert_eq!(resolve_session_id(&extensions), "sess-abc");
    }

    #[test]
    fn resolve_session_id_no_header() {
        let mut extensions = Extensions::new();
        let request = http::Request::builder().body(()).unwrap();
        let (parts, _) = request.into_parts();
        extensions.insert(parts);

        assert_eq!(resolve_session_id(&extensions), "default");
    }

    #[tokio::test]
    async fn default_store_has_30min_ttl() {
        let store = SessionStore::<TestSession>::default();
        assert_eq!(store.ttl, DEFAULT_SESSION_TTL);
    }
}

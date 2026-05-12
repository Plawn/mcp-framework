use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::RwLock;

pub type PersistenceError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Async key-value persistence backend.
///
/// Used by both [`SessionStore`](crate::session::SessionStore) and
/// [`TokenStore`](crate::auth::TokenStore) to survive server restarts.
/// Keys are scoped by namespace (`"tokens"`, `"sessions"`) to avoid collisions
/// when a single backend instance (e.g. one Redis connection) is shared.
///
/// # Object safety
///
/// Methods return `Pin<Box<dyn Future>>` so the trait is object-safe and can be
/// stored as `Arc<dyn PersistenceBackend>`.
pub trait PersistenceBackend: Send + Sync + 'static {
    fn get(
        &self,
        ns: &str,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, PersistenceError>> + Send + '_>>;

    fn set(
        &self,
        ns: &str,
        key: &str,
        value: &[u8],
        ttl: Option<Duration>,
    ) -> Pin<Box<dyn Future<Output = Result<(), PersistenceError>> + Send + '_>>;

    fn delete(
        &self,
        ns: &str,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), PersistenceError>> + Send + '_>>;

    fn keys(
        &self,
        ns: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, PersistenceError>> + Send + '_>>;
}

/// In-memory persistence backend for testing.
///
/// Stores all data in a `HashMap` behind an `RwLock`. TTL is ignored — entries
/// persist until explicitly deleted or overwritten. A real backend (e.g. Redis)
/// may auto-expire entries based on TTL; keep this in mind when writing tests.
pub struct InMemoryBackend {
    data: Arc<RwLock<HashMap<(String, String), Vec<u8>>>>,
}

impl InMemoryBackend {
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn dump(&self) -> HashMap<(String, String), Vec<u8>> {
        self.data.read().await.clone()
    }
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl PersistenceBackend for InMemoryBackend {
    fn get(
        &self,
        ns: &str,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, PersistenceError>> + Send + '_>> {
        let ns = ns.to_string();
        let key = key.to_string();
        Box::pin(async move {
            let data = self.data.read().await;
            Ok(data.get(&(ns, key)).cloned())
        })
    }

    fn set(
        &self,
        ns: &str,
        key: &str,
        value: &[u8],
        _ttl: Option<Duration>,
    ) -> Pin<Box<dyn Future<Output = Result<(), PersistenceError>> + Send + '_>> {
        let ns = ns.to_string();
        let key = key.to_string();
        let value = value.to_vec();
        Box::pin(async move {
            let mut data = self.data.write().await;
            data.insert((ns, key), value);
            Ok(())
        })
    }

    fn delete(
        &self,
        ns: &str,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), PersistenceError>> + Send + '_>> {
        let ns = ns.to_string();
        let key = key.to_string();
        Box::pin(async move {
            let mut data = self.data.write().await;
            data.remove(&(ns, key));
            Ok(())
        })
    }

    fn keys(
        &self,
        ns: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, PersistenceError>> + Send + '_>> {
        let ns = ns.to_string();
        Box::pin(async move {
            let data = self.data.read().await;
            let keys = data
                .keys()
                .filter(|(n, _)| *n == ns)
                .map(|(_, k)| k.clone())
                .collect();
            Ok(keys)
        })
    }
}

pub(crate) fn spawn_persist<T: Serialize>(
    backend: &Arc<dyn PersistenceBackend>,
    ns: &'static str,
    key: String,
    value: &T,
    ttl: Option<Duration>,
) {
    match serde_json::to_vec(value) {
        Ok(bytes) => {
            let backend = backend.clone();
            tokio::spawn(async move {
                if let Err(e) = backend.set(ns, &key, &bytes, ttl).await {
                    tracing::warn!("Failed to persist {ns}/{key}: {e}");
                }
            });
        }
        Err(e) => {
            tracing::warn!("Failed to serialize {ns}/{key}: {e}");
        }
    }
}

#[cfg(test)]
#[path = "persistence_tests.rs"]
mod tests;

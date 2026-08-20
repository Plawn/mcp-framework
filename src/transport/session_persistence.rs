use std::sync::Arc;
use std::time::Duration;

use rmcp::transport::streamable_http_server::session::store::{
    SessionState, SessionStore, SessionStoreError,
};

use crate::persistence::PersistenceBackend;

const NS_TRANSPORT_SESSIONS: &str = "mcp_transport_sessions";

/// Adapts the framework persistence backend to rmcp's transport session store.
///
/// This state is deliberately namespaced separately from the framework's typed
/// application sessions: rmcp persists initialize parameters, while
/// `crate::session::SessionStore` persists consumer-defined application data.
///
/// rmcp writes an entry once, when the session is created, and reads it only on
/// the instance that has to rebuild the session — it never refreshes it while
/// the originating instance serves traffic. The entry therefore carries the
/// same TTL as the framework's application sessions, and a successful `load`
/// re-arms that TTL: a session recovered on one instance stays recoverable on
/// the next, instead of expiring a fixed interval after its creation.
pub(crate) struct TransportSessionStore {
    backend: Arc<dyn PersistenceBackend>,
    ttl: Duration,
}

impl TransportSessionStore {
    pub(crate) fn new(backend: Arc<dyn PersistenceBackend>, ttl: Duration) -> Self {
        Self { backend, ttl }
    }
}

#[async_trait::async_trait]
impl SessionStore for TransportSessionStore {
    async fn load(&self, session_id: &str) -> Result<Option<SessionState>, SessionStoreError> {
        let Some(bytes) = self.backend.get(NS_TRANSPORT_SESSIONS, session_id).await? else {
            return Ok(None);
        };
        let state = serde_json::from_slice(&bytes)?;
        // Re-arm the TTL: this instance is about to own the session, and the
        // next failover must be able to find it too. A failed re-arm is not a
        // failed load — the state was read; only its lifetime stays as it was.
        if let Err(e) = self
            .backend
            .set(NS_TRANSPORT_SESSIONS, session_id, &bytes, Some(self.ttl))
            .await
        {
            tracing::warn!(session_id, error = %e, "could not re-arm transport session TTL");
        }
        Ok(Some(state))
    }

    async fn store(&self, session_id: &str, state: &SessionState) -> Result<(), SessionStoreError> {
        let bytes = serde_json::to_vec(state)?;
        self.backend
            .set(NS_TRANSPORT_SESSIONS, session_id, &bytes, Some(self.ttl))
            .await
    }

    async fn delete(&self, session_id: &str) -> Result<(), SessionStoreError> {
        self.backend.delete(NS_TRANSPORT_SESSIONS, session_id).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use rmcp::model::{ClientCapabilities, Implementation, InitializeRequestParams};

    use super::*;
    use crate::persistence::{BoxFuture, InMemoryBackend};

    /// Records every `set`, including the TTL the store asks for — which
    /// `InMemoryBackend` alone would drop on the floor.
    struct Spy {
        inner: InMemoryBackend,
        sets: Mutex<Vec<(String, Option<Duration>)>>,
    }

    impl PersistenceBackend for Spy {
        fn get(&self, ns: &str, key: &str) -> BoxFuture<'_, Option<Vec<u8>>> {
            self.inner.get(ns, key)
        }
        fn set(
            &self,
            ns: &str,
            key: &str,
            value: &[u8],
            ttl: Option<Duration>,
        ) -> BoxFuture<'_, ()> {
            self.sets.lock().unwrap().push((key.to_owned(), ttl));
            self.inner.set(ns, key, value, ttl)
        }
        fn delete(&self, ns: &str, key: &str) -> BoxFuture<'_, ()> {
            self.inner.delete(ns, key)
        }
        fn keys(&self, ns: &str) -> BoxFuture<'_, Vec<String>> {
            self.inner.keys(ns)
        }
    }

    fn state() -> SessionState {
        SessionState::new(InitializeRequestParams::new(
            ClientCapabilities::default(),
            Implementation::new("spy-client", "1"),
        ))
    }

    #[tokio::test]
    async fn load_re_arms_the_ttl_and_returns_the_stored_state() {
        let ttl = Duration::from_secs(1234);
        let spy = Arc::new(Spy {
            inner: InMemoryBackend::new(),
            sets: Mutex::new(Vec::new()),
        });
        let store = TransportSessionStore::new(spy.clone(), ttl);

        store.store("s1", &state()).await.unwrap();
        let loaded = store
            .load("s1")
            .await
            .unwrap()
            .expect("stored state is found");
        assert_eq!(loaded.initialize_params.client_info.name, "spy-client");

        let sets = spy.sets.lock().unwrap();
        assert_eq!(
            sets.len(),
            2,
            "store + re-arm on load, nothing else: {sets:?}"
        );
        assert!(sets.iter().all(|(k, t)| k == "s1" && *t == Some(ttl)));
    }

    #[tokio::test]
    async fn load_of_an_unknown_session_does_not_write() {
        let spy = Arc::new(Spy {
            inner: InMemoryBackend::new(),
            sets: Mutex::new(Vec::new()),
        });
        let store = TransportSessionStore::new(spy.clone(), Duration::from_secs(1));
        assert!(store.load("nope").await.unwrap().is_none());
        assert!(spy.sets.lock().unwrap().is_empty());
    }
}

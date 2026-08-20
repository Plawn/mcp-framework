use std::sync::Arc;
use std::time::Duration;

use rmcp::transport::streamable_http_server::session::store::{
    SessionState, SessionStore, SessionStoreError,
};

use crate::persistence::{PersistenceBackend, Touch};

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
/// re-arms that TTL (atomically, via `PersistenceBackend::touch`): a session
/// recovered on one instance stays recoverable on the next, instead of
/// expiring a fixed interval after its creation.
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
        // next failover must be able to find it too. `touch` is atomic, so a
        // session a peer deleted between the read and this point is reported
        // gone rather than resurrected with a fresh lifetime.
        match self
            .backend
            .touch(NS_TRANSPORT_SESSIONS, session_id, self.ttl)
            .await
        {
            Ok(Touch::Armed) => Ok(Some(state)),
            // No write happened, so nothing was resurrected; the state is
            // simply not re-armed — what a backend did before `touch` existed.
            Ok(Touch::Unsupported) => Ok(Some(state)),
            Ok(Touch::Missing) => Ok(None),
            // Without a verdict the state read above may be a session that no
            // longer exists. "Unknown session" is the answer rmcp turns into a
            // 404, which makes the client re-initialize — a `SessionStoreError`
            // would become a 500 and a retry loop on the same session.
            Err(e) => {
                tracing::warn!(
                    session_id,
                    error = %e,
                    "transport session TTL could not be re-armed; treating the session as unknown"
                );
                Ok(None)
            }
        }
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
    use std::sync::atomic::{AtomicBool, Ordering};

    use rmcp::model::{ClientCapabilities, Implementation, InitializeRequestParams};

    use super::*;
    use crate::persistence::{BoxFuture, InMemoryBackend, PersistenceError, Touch};

    /// Wraps `InMemoryBackend` to observe `touch`, and to script what happens
    /// to the key between the read and the re-arm.
    struct Spy {
        inner: InMemoryBackend,
        touches: Mutex<Vec<(String, Duration)>>,
        /// Delete the key right after `get` returns — a peer's `DELETE` landing
        /// in the window the re-arm must not paper over.
        delete_after_get: AtomicBool,
        /// Make `touch` fail — the backend is unreachable for that one call.
        fail_touch: AtomicBool,
    }

    impl Spy {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                inner: InMemoryBackend::new(),
                touches: Mutex::new(Vec::new()),
                delete_after_get: AtomicBool::new(false),
                fail_touch: AtomicBool::new(false),
            })
        }
    }

    impl PersistenceBackend for Spy {
        fn get(&self, ns: &str, key: &str) -> BoxFuture<'_, Option<Vec<u8>>> {
            let ns = ns.to_owned();
            let key = key.to_owned();
            Box::pin(async move {
                let value = self.inner.get(&ns, &key).await?;
                if self.delete_after_get.load(Ordering::SeqCst) {
                    self.inner.delete(&ns, &key).await?;
                }
                Ok(value)
            })
        }
        fn set(
            &self,
            ns: &str,
            key: &str,
            value: &[u8],
            ttl: Option<Duration>,
        ) -> BoxFuture<'_, ()> {
            self.inner.set(ns, key, value, ttl)
        }
        fn delete(&self, ns: &str, key: &str) -> BoxFuture<'_, ()> {
            self.inner.delete(ns, key)
        }
        fn keys(&self, ns: &str) -> BoxFuture<'_, Vec<String>> {
            self.inner.keys(ns)
        }
        fn touch(&self, ns: &str, key: &str, ttl: Duration) -> BoxFuture<'_, Touch> {
            self.touches.lock().unwrap().push((key.to_owned(), ttl));
            if self.fail_touch.load(Ordering::SeqCst) {
                return Box::pin(async { Err(PersistenceError::from("touch unavailable")) });
            }
            self.inner.touch(ns, key, ttl)
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
        let spy = Spy::new();
        let store = TransportSessionStore::new(spy.clone(), ttl);

        store.store("s1", &state()).await.unwrap();
        let loaded = store
            .load("s1")
            .await
            .unwrap()
            .expect("stored state is found");
        assert_eq!(loaded.initialize_params.client_info.name, "spy-client");

        let touches = spy.touches.lock().unwrap();
        assert_eq!(touches.as_slice(), &[("s1".to_owned(), ttl)]);
    }

    #[tokio::test]
    async fn load_of_an_unknown_session_does_not_touch() {
        let spy = Spy::new();
        let store = TransportSessionStore::new(spy.clone(), Duration::from_secs(1));
        assert!(store.load("nope").await.unwrap().is_none());
        assert!(spy.touches.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_session_deleted_between_read_and_re_arm_is_reported_gone() {
        let spy = Spy::new();
        let store = TransportSessionStore::new(spy.clone(), Duration::from_secs(1));
        store.store("s1", &state()).await.unwrap();

        spy.delete_after_get.store(true, Ordering::SeqCst);
        assert!(
            store.load("s1").await.unwrap().is_none(),
            "a peer's delete must win over the re-arm, never be undone by it"
        );
        assert!(
            spy.inner
                .get(NS_TRANSPORT_SESSIONS, "s1")
                .await
                .unwrap()
                .is_none(),
            "the entry must not have been resurrected"
        );
    }

    #[tokio::test]
    async fn a_re_arm_that_cannot_answer_reports_the_session_unknown() {
        let spy = Spy::new();
        let store = TransportSessionStore::new(spy.clone(), Duration::from_secs(1));
        store.store("s1", &state()).await.unwrap();

        // The peer's delete lands in the window *and* the re-arm errors: the
        // state read must not be handed out on the strength of a stale read —
        // and the answer is "unknown" (404, re-initialize), not an error (500).
        spy.delete_after_get.store(true, Ordering::SeqCst);
        spy.fail_touch.store(true, Ordering::SeqCst);
        assert!(store.load("s1").await.unwrap().is_none());
    }

    /// A backend that keeps the trait's default `touch` still restores — it
    /// simply gets no TTL extension, since nothing was written.
    #[tokio::test]
    async fn a_backend_without_touch_restores_without_re_arming() {
        struct NoTouch(InMemoryBackend);
        impl PersistenceBackend for NoTouch {
            fn get(&self, ns: &str, key: &str) -> BoxFuture<'_, Option<Vec<u8>>> {
                self.0.get(ns, key)
            }
            fn set(
                &self,
                ns: &str,
                key: &str,
                v: &[u8],
                ttl: Option<Duration>,
            ) -> BoxFuture<'_, ()> {
                self.0.set(ns, key, v, ttl)
            }
            fn delete(&self, ns: &str, key: &str) -> BoxFuture<'_, ()> {
                self.0.delete(ns, key)
            }
            fn keys(&self, ns: &str) -> BoxFuture<'_, Vec<String>> {
                self.0.keys(ns)
            }
        }
        let store = TransportSessionStore::new(
            Arc::new(NoTouch(InMemoryBackend::new())),
            Duration::from_secs(1),
        );
        store.store("s1", &state()).await.unwrap();
        let loaded = store.load("s1").await.unwrap().expect("restored");
        assert_eq!(loaded.initialize_params.client_info.name, "spy-client");
    }
}

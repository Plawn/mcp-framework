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
        Ok(Some(serde_json::from_slice(&bytes)?))
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

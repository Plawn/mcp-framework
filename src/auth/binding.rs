//! Binding a protocol session to the principal that opened it.
//!
//! # The hole this closes
//!
//! A protocol session id (`mcp-session-id`) is minted by rmcp and keys, on this
//! side, the [`SessionStore`](crate::session::SessionStore) entry and everything
//! else `session_id_from_parts` resolves. In
//! [`TokenMode::ResourceServer`](super::TokenMode::ResourceServer) the auth
//! middleware accepts any bearer the issuer's keys vouch for — so Bob, holding a
//! perfectly valid JWT of his own, could send Alice's session id and land inside
//! Alice's session.
//!
//! The proxying modes are not exposed to this: passthrough keeps a token per
//! session and refuses a bearer whose principal differs from the one already
//! bound to that session; opaque resolves the session id *from the opaque token*
//! and overwrites whatever the client sent. Resource-server mode keeps no token
//! state at all, which is precisely what removed the comparison — so the binding
//! has to be kept explicitly, and it is kept as a **hash**, never as token
//! material.
//!
//! # Shape
//!
//! `session_id → credential_session_key(bearer)` — the same `sha256`-derived,
//! non-reversible identity the framework already uses for sessionless clients.
//! The first request carrying a given session id establishes the binding; every
//! later request must present the same identity or be refused.
//!
//! Bounded and expiring, so it cannot grow without limit, and written through to
//! persistence (namespace [`NS_SESSION_BINDING`]) so a peer instance enforces
//! the same binding — without it, a deployment behind a round-robin load
//! balancer would let the attack through on whichever instance had not yet seen
//! the session.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

use crate::constants::{NS_SESSION_BINDING, SESSION_BINDING_MAX_ENTRIES};
use crate::persistence::PersistenceBackend;

struct Binding {
    identity: String,
    expires_at: Instant,
}

/// Protocol session id → the verified identity that opened it.
#[derive(Clone)]
pub struct SessionBindings {
    bindings: Arc<RwLock<HashMap<String, Binding>>>,
    persistence: Option<Arc<dyn PersistenceBackend>>,
    ttl: Duration,
    max_entries: usize,
}

impl SessionBindings {
    /// `ttl` should track the session TTL: a binding that outlived its session
    /// would refuse a session id rmcp has since handed to someone else.
    pub fn new(ttl: Duration) -> Self {
        Self {
            bindings: Arc::new(RwLock::new(HashMap::new())),
            persistence: None,
            ttl,
            max_entries: SESSION_BINDING_MAX_ENTRIES,
        }
    }

    pub fn set_persistence(&mut self, backend: Arc<dyn PersistenceBackend>) {
        self.persistence = Some(backend);
    }

    /// Claim `session_id` for `identity`.
    ///
    /// Returns `true` when the session is unclaimed (it becomes this identity's)
    /// or already claimed by this identity, and `false` when it belongs to
    /// somebody else.
    pub async fn claim(&self, session_id: &str, identity: &str) -> bool {
        let now = Instant::now();

        // Hot path: a session already seen on this instance.
        {
            let bindings = self.bindings.read().await;
            if let Some(existing) = bindings.get(session_id)
                && existing.expires_at > now
            {
                if existing.identity != identity {
                    return false;
                }
                // Only extend once the entry is past half-life, so a busy
                // session does not take the write lock on every request.
                if existing.expires_at.saturating_duration_since(now) > self.ttl / 2 {
                    return true;
                }
            }
        }

        // Cold path: a session this instance has not seen. A peer may have.
        if let Some(backend) = &self.persistence {
            match backend.get(NS_SESSION_BINDING, session_id).await {
                Ok(Some(bytes)) => match String::from_utf8(bytes) {
                    Ok(peer_identity) => {
                        // Cache the peer's verdict either way: the next request
                        // for this session is then settled in the hot path.
                        self.remember(session_id, &peer_identity).await;
                        if peer_identity != identity {
                            return false;
                        }
                        return true;
                    }
                    Err(_) => {
                        tracing::warn!(
                            session = %session_id,
                            "discarding an unreadable persisted session binding"
                        );
                    }
                },
                Ok(None) => {}
                Err(e) => {
                    // Fail open rather than locking every user out when Redis
                    // blips: the bearer itself was already validated, so the
                    // worst case is that the binding is not enforced for as long
                    // as the backend is down.
                    tracing::warn!(
                        session = %session_id,
                        "could not read the persisted session binding: {e}"
                    );
                }
            }
        }

        self.remember(session_id, identity).await;

        if let Some(backend) = &self.persistence {
            let backend = backend.clone();
            let session_id = session_id.to_string();
            let value = identity.as_bytes().to_vec();
            let ttl = self.ttl;
            tokio::spawn(async move {
                if let Err(e) = backend
                    .set(NS_SESSION_BINDING, &session_id, &value, Some(ttl))
                    .await
                {
                    tracing::warn!(session = %session_id, "session binding write-through failed: {e}");
                }
            });
        }

        true
    }

    /// Insert or refresh an entry, keeping the map bounded.
    async fn remember(&self, session_id: &str, identity: &str) {
        let now = Instant::now();
        let mut bindings = self.bindings.write().await;

        if bindings.len() >= self.max_entries && !bindings.contains_key(session_id) {
            bindings.retain(|_, binding| binding.expires_at > now);

            // Still full: drop whatever is closest to expiring anyway. Evicting
            // a live binding un-protects that session until its next request
            // re-establishes it, so the cap is deliberately far above any
            // plausible concurrent-session count and the eviction is logged.
            while bindings.len() >= self.max_entries {
                let Some(victim) = bindings
                    .iter()
                    .min_by_key(|(_, binding)| binding.expires_at)
                    .map(|(key, _)| key.clone())
                else {
                    break;
                };
                tracing::warn!(
                    max_entries = self.max_entries,
                    "session binding table is full; evicting the oldest entry"
                );
                bindings.remove(&victim);
            }
        }

        bindings.insert(
            session_id.to_string(),
            Binding {
                identity: identity.to_string(),
                expires_at: now + self.ttl,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::InMemoryBackend;

    #[tokio::test]
    async fn the_first_claimant_keeps_the_session() {
        let bindings = SessionBindings::new(Duration::from_secs(60));

        assert!(bindings.claim("session-1", "alice").await);
        assert!(bindings.claim("session-1", "alice").await);
        assert!(!bindings.claim("session-1", "bob").await);
        // Bob's rejection must not have displaced Alice.
        assert!(bindings.claim("session-1", "alice").await);
    }

    #[tokio::test]
    async fn an_expired_binding_frees_the_session() {
        let bindings = SessionBindings::new(Duration::from_millis(20));

        assert!(bindings.claim("session-1", "alice").await);
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(
            bindings.claim("session-1", "bob").await,
            "rmcp may hand the same id to someone else once the session is gone"
        );
    }

    #[tokio::test]
    async fn a_peer_instance_enforces_the_same_binding() {
        let backend = Arc::new(InMemoryBackend::new());

        let mut first = SessionBindings::new(Duration::from_secs(60));
        first.set_persistence(backend.clone());
        assert!(first.claim("session-1", "alice").await);

        // Give the fire-and-forget write-through a chance to land.
        for _ in 0..50 {
            if backend
                .get(NS_SESSION_BINDING, "session-1")
                .await
                .unwrap()
                .is_some()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }

        // An instance that never saw the session — no sticky sessions.
        let mut second = SessionBindings::new(Duration::from_secs(60));
        second.set_persistence(backend);
        assert!(!second.claim("session-1", "bob").await);
        assert!(second.claim("session-1", "alice").await);
    }

    #[tokio::test]
    async fn the_table_stays_bounded() {
        let mut bindings = SessionBindings::new(Duration::from_secs(60));
        bindings.max_entries = 8;

        for i in 0..64 {
            assert!(bindings.claim(&format!("session-{i}"), "alice").await);
        }

        assert!(bindings.bindings.read().await.len() <= 8);
    }
}

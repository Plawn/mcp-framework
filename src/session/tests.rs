use super::*;

#[derive(Default, Clone, Debug, PartialEq, Serialize, serde::Deserialize)]
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

    tokio::time::sleep(Duration::from_millis(60)).await;

    store.get_or_create("fresh").await;

    store.purge_expired().await;

    assert!(store.get("old").await.is_none());
    assert_eq!(store.len().await, 1);
}

#[tokio::test]
async fn cleanup_task_purges_expired() {
    let store = SessionStore::<TestSession>::new(Duration::from_millis(50));
    store.get_or_create("will-expire").await;

    let handle = store.start_cleanup_task();

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

// ── Session handle tests ────────────────────────────────────────

#[tokio::test]
async fn session_handle_get_or_create() {
    let store = SessionStore::<TestSession>::new(Duration::from_secs(60));
    let session = Session {
        store: &store,
        session_id: "s1",
    };

    let data = session.get_or_create().await;
    assert_eq!(data, TestSession::default());
}

#[tokio::test]
async fn session_handle_update() {
    let store = SessionStore::<TestSession>::new(Duration::from_secs(60));
    let session = Session {
        store: &store,
        session_id: "s1",
    };

    let data = session.update(|s| s.counter = 42).await;
    assert_eq!(data.counter, 42);
    assert_eq!(session.id(), "s1");

    let fetched = session.get().await.unwrap();
    assert_eq!(fetched.counter, 42);
}

#[tokio::test]
async fn session_handle_remove() {
    let store = SessionStore::<TestSession>::new(Duration::from_secs(60));
    let session = Session {
        store: &store,
        session_id: "s1",
    };

    session.update(|s| s.counter = 10).await;
    let removed = session.remove().await;
    assert_eq!(removed.unwrap().counter, 10);
    assert!(session.get().await.is_none());
}

// ── Persistence tests ───────────────────────────────────────────

#[tokio::test]
async fn session_store_persists_on_update() {
    let backend = Arc::new(crate::persistence::InMemoryBackend::new());
    let store = SessionStore::<TestSession>::new(Duration::from_secs(60))
        .with_persistence(backend.clone());

    store.update("s1", |s| s.counter = 42).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let data = backend.dump().await;
    assert!(data.contains_key(&("sessions".to_string(), "s1".to_string())));

    let bytes = &data[&("sessions".to_string(), "s1".to_string())];
    let persisted: PersistedSession<TestSession> = serde_json::from_slice(bytes).unwrap();
    assert_eq!(persisted.data.counter, 42);
    assert_eq!(persisted.remaining_ttl_secs, 60);
}

#[tokio::test]
async fn session_store_loads_persisted() {
    let backend = Arc::new(crate::persistence::InMemoryBackend::new());

    let persisted = PersistedSession {
        data: TestSession {
            counter: 99,
            name: Some("loaded".to_string()),
        },
        remaining_ttl_secs: 60,
    };
    backend
        .set("sessions", "s1", &serde_json::to_vec(&persisted).unwrap(), None)
        .await
        .unwrap();

    let store = SessionStore::<TestSession>::new(Duration::from_secs(60))
        .with_persistence(backend);
    store.load_persisted().await.unwrap();

    let data = store.get("s1").await.unwrap();
    assert_eq!(data.counter, 99);
    assert_eq!(data.name.as_deref(), Some("loaded"));
}

#[tokio::test]
async fn session_store_remove_cleans_backend() {
    let backend = Arc::new(crate::persistence::InMemoryBackend::new());
    let store = SessionStore::<TestSession>::new(Duration::from_secs(60))
        .with_persistence(backend.clone());

    store.update("s1", |s| s.counter = 1).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(backend.dump().await.contains_key(&("sessions".into(), "s1".into())));

    store.remove("s1").await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!backend.dump().await.contains_key(&("sessions".into(), "s1".into())));
}

#[tokio::test]
async fn session_store_purge_cleans_backend() {
    let backend = Arc::new(crate::persistence::InMemoryBackend::new());
    let store = SessionStore::<TestSession>::new(Duration::from_millis(50))
        .with_persistence(backend.clone());

    store.update("s1", |s| s.counter = 1).await;
    tokio::time::sleep(Duration::from_millis(30)).await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    store.purge_expired().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert!(backend.dump().await.is_empty());
}

#[tokio::test]
async fn session_store_no_backend_unchanged() {
    let store = SessionStore::<TestSession>::new(Duration::from_secs(60));
    store.update("s1", |s| s.counter = 1).await;
    assert_eq!(store.get("s1").await.unwrap().counter, 1);
    store.load_persisted().await.unwrap();
}

#[tokio::test]
async fn session_store_skips_corrupted() {
    let backend = Arc::new(crate::persistence::InMemoryBackend::new());
    backend.set("sessions", "bad", b"garbage", None).await.unwrap();

    let persisted = PersistedSession {
        data: TestSession { counter: 1, name: None },
        remaining_ttl_secs: 60,
    };
    backend.set("sessions", "good", &serde_json::to_vec(&persisted).unwrap(), None).await.unwrap();

    let store = SessionStore::<TestSession>::new(Duration::from_secs(60))
        .with_persistence(backend);
    store.load_persisted().await.unwrap();

    assert!(store.get("bad").await.is_none());
    assert_eq!(store.get("good").await.unwrap().counter, 1);
}

#[tokio::test]
async fn session_read_through_cross_instance() {
    // Two stores sharing one backend simulate two replicas behind a non-sticky LB.
    let backend = Arc::new(crate::persistence::InMemoryBackend::new());
    let store_a = SessionStore::<TestSession>::new(Duration::from_secs(60))
        .with_persistence(backend.clone());
    let store_b = SessionStore::<TestSession>::new(Duration::from_secs(60))
        .with_persistence(backend.clone());

    // Session created on instance A.
    store_a.update("s1", |s| s.counter = 7).await;
    tokio::time::sleep(Duration::from_millis(50)).await; // let fire-and-forget persist land

    // Instance B never saw it in RAM — resolves via read-through.
    let data = store_b.get("s1").await.expect("B should read session through Redis");
    assert_eq!(data.counter, 7);

    // Now cached in B.
    assert_eq!(store_b.len().await, 1);
}

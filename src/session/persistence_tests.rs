use super::*;

#[derive(Default, Clone, Debug, PartialEq, Serialize, serde::Deserialize)]
struct TestSession {
    counter: u32,
    name: Option<String>,
}

// ── Persistence tests ───────────────────────────────────────────

#[tokio::test]
async fn session_store_persists_on_update() {
    let backend = Arc::new(crate::persistence::InMemoryBackend::new());
    let store =
        SessionStore::<TestSession>::new(Duration::from_secs(60)).with_persistence(backend.clone());

    store.update("s1", |s| s.counter = 42).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let data = backend.dump().await;
    assert!(data.contains_key(&("sessions".to_string(), "s1".to_string())));

    let bytes = &data[&("sessions".to_string(), "s1".to_string())];
    let persisted: PersistedSession<TestSession> = serde_json::from_slice(bytes).unwrap();
    assert_eq!(persisted.data.counter, 42);
    assert!(persisted.expires_at_unix_ms.is_some());
    assert!(persisted.remaining_ttl_secs.is_none());
}

#[tokio::test]
async fn session_store_loads_persisted() {
    let backend = Arc::new(crate::persistence::InMemoryBackend::new());

    let persisted = PersistedSession {
        data: TestSession {
            counter: 99,
            name: Some("loaded".to_string()),
        },
        expires_at_unix_ms: None,
        remaining_ttl_secs: Some(60),
    };
    backend
        .set(
            "sessions",
            "s1",
            &serde_json::to_vec(&persisted).unwrap(),
            None,
        )
        .await
        .unwrap();

    let store = SessionStore::<TestSession>::new(Duration::from_secs(60)).with_persistence(backend);
    store.load_persisted().await.unwrap();

    let data = store.get("s1").await.unwrap();
    assert_eq!(data.counter, 99);
    assert_eq!(data.name.as_deref(), Some("loaded"));
}

#[tokio::test]
async fn session_store_does_not_reset_an_absolute_expiry_on_restart() {
    let backend = Arc::new(crate::persistence::InMemoryBackend::new());
    let persisted = PersistedSession {
        data: TestSession {
            counter: 99,
            name: None,
        },
        expires_at_unix_ms: Some(instant_to_unix_millis(
            Instant::now() - Duration::from_secs(1),
        )),
        remaining_ttl_secs: None,
    };
    backend
        .set(
            "sessions",
            "expired",
            &serde_json::to_vec(&persisted).unwrap(),
            None,
        )
        .await
        .unwrap();

    let store =
        SessionStore::<TestSession>::new(Duration::from_secs(60)).with_persistence(backend.clone());
    store.load_persisted().await.unwrap();

    assert!(store.get("expired").await.is_none());
    assert!(
        !backend
            .dump()
            .await
            .contains_key(&("sessions".to_string(), "expired".to_string()))
    );
}

#[tokio::test]
async fn session_store_remove_cleans_backend() {
    let backend = Arc::new(crate::persistence::InMemoryBackend::new());
    let store =
        SessionStore::<TestSession>::new(Duration::from_secs(60)).with_persistence(backend.clone());

    store.update("s1", |s| s.counter = 1).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        backend
            .dump()
            .await
            .contains_key(&("sessions".into(), "s1".into()))
    );

    store.remove("s1").await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !backend
            .dump()
            .await
            .contains_key(&("sessions".into(), "s1".into()))
    );
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
    backend
        .set("sessions", "bad", b"garbage", None)
        .await
        .unwrap();

    let persisted = PersistedSession {
        data: TestSession {
            counter: 1,
            name: None,
        },
        expires_at_unix_ms: None,
        remaining_ttl_secs: Some(60),
    };
    backend
        .set(
            "sessions",
            "good",
            &serde_json::to_vec(&persisted).unwrap(),
            None,
        )
        .await
        .unwrap();

    let store = SessionStore::<TestSession>::new(Duration::from_secs(60)).with_persistence(backend);
    store.load_persisted().await.unwrap();

    assert!(store.get("bad").await.is_none());
    assert_eq!(store.get("good").await.unwrap().counter, 1);
}

#[tokio::test]
async fn session_read_through_cross_instance() {
    // Two stores sharing one backend simulate two replicas behind a non-sticky LB.
    let backend = Arc::new(crate::persistence::InMemoryBackend::new());
    let store_a =
        SessionStore::<TestSession>::new(Duration::from_secs(60)).with_persistence(backend.clone());
    let store_b =
        SessionStore::<TestSession>::new(Duration::from_secs(60)).with_persistence(backend.clone());

    // Session created on instance A.
    store_a.update("s1", |s| s.counter = 7).await;
    // Instance B never saw it in RAM — resolves via read-through.
    let data = store_b
        .get("s1")
        .await
        .expect("B should read session through Redis");
    assert_eq!(data.counter, 7);

    // Now cached in B.
    assert_eq!(store_b.len().await, 1);
}

#[tokio::test]
async fn session_updates_use_the_latest_cross_instance_value() {
    let backend = Arc::new(crate::persistence::InMemoryBackend::new());
    let store_a =
        SessionStore::<TestSession>::new(Duration::from_secs(60)).with_persistence(backend.clone());
    let store_b =
        SessionStore::<TestSession>::new(Duration::from_secs(60)).with_persistence(backend.clone());

    store_a.update("s1", |s| s.counter = 7).await;
    assert_eq!(store_b.get("s1").await.unwrap().counter, 7);

    // B now has a stale cache after A's second update. Its update must reload
    // the authoritative value instead of overwriting it with 7 + 1.
    store_a.update("s1", |s| s.counter = 9).await;
    let updated = store_b.update("s1", |s| s.counter += 1).await;
    assert_eq!(updated.counter, 10);

    let fresh = SessionStore::<TestSession>::new(Duration::from_secs(60)).with_persistence(backend);
    assert_eq!(fresh.get("s1").await.unwrap().counter, 10);
}

#[tokio::test]
async fn session_persistence_finishes_before_mutation_returns() {
    let backend = Arc::new(crate::persistence::InMemoryBackend::new());
    let store =
        SessionStore::<TestSession>::new(Duration::from_secs(60)).with_persistence(backend.clone());

    store.update("ordered", |s| s.counter = 1).await;
    let bytes = backend
        .dump()
        .await
        .remove(&("sessions".to_string(), "ordered".to_string()))
        .expect("update must already be persisted");
    let persisted: PersistedSession<TestSession> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(persisted.data.counter, 1);

    store.remove("ordered").await;
    assert!(
        !backend
            .dump()
            .await
            .contains_key(&("sessions".to_string(), "ordered".to_string()))
    );
}

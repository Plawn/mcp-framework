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

#[tokio::test]
async fn default_store_has_30min_ttl() {
    let store = SessionStore::<TestSession>::default();
    assert_eq!(store.ttl, DEFAULT_SESSION_TTL);
}

use super::*;

#[derive(Default, Clone, Debug, PartialEq, Serialize, serde::Deserialize)]
struct TestSession {
    counter: u32,
    name: Option<String>,
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

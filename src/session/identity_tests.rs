use super::*;

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

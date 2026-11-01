use super::*;

fn request(uri: &str) -> CallRequest {
    CallRequest {
        uri: uri.parse().expect("valid test uri"),
        ..CallRequest::default()
    }
}

#[test]
fn query_param_reads_the_first_matching_pair_decoded() {
    let req = request("/mcp?filter=a,b&space=team%20blue&space=other");
    assert_eq!(req.query_param("space").as_deref(), Some("team blue"));
    assert_eq!(req.query_param("filter").as_deref(), Some("a,b"));
}

#[test]
fn query_param_is_none_without_a_query_or_the_key() {
    assert_eq!(request("/mcp").query_param("space"), None);
    assert_eq!(request("/mcp?spaces=x").query_param("space"), None);
}

#[test]
fn query_param_without_a_value_is_empty() {
    assert_eq!(
        request("/mcp?space").query_param("space").as_deref(),
        Some("")
    );
}

#[test]
fn from_parts_keeps_headers_uri_and_extensions() {
    #[derive(Clone, Debug, PartialEq)]
    struct Marker(u8);

    let (mut parts, ()) = http::Request::builder()
        .uri("/mcp?space=team")
        .header("x-plexus-space", "team")
        .body(())
        .expect("valid request")
        .into_parts();
    parts.extensions.insert(Marker(7));

    let req = CallRequest::from_parts(&parts);
    assert_eq!(req.uri.query(), Some("space=team"));
    assert_eq!(
        req.headers
            .get("x-plexus-space")
            .and_then(|v| v.to_str().ok()),
        Some("team")
    );
    assert_eq!(req.extensions.get::<Marker>(), Some(&Marker(7)));
}

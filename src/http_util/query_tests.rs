use super::*;

#[test]
fn test_required_params() {
    let builder = QueryBuilder::new()
        .required("foo", "bar")
        .required("num", 42);
    let query = builder.build();

    assert_eq!(query.len(), 2);
    assert_eq!(query[0], ("foo", "bar"));
    assert_eq!(query[1], ("num", "42"));
}

#[test]
fn test_optional_params() {
    let limit: Option<i32> = Some(10);
    let offset: Option<i32> = None;

    let builder = QueryBuilder::new()
        .required("key", "value")
        .optional("limit", limit)
        .optional("offset", offset);
    let query = builder.build();

    assert_eq!(query.len(), 2);
    assert_eq!(query[0], ("key", "value"));
    assert_eq!(query[1], ("limit", "10"));
}

#[test]
fn test_optional_str_ref() {
    let search: Option<&str> = Some("hello");
    let filter: Option<&str> = None;

    let builder = QueryBuilder::new()
        .optional("search", search)
        .optional("filter", filter);
    let query = builder.build();

    assert_eq!(query.len(), 1);
    assert_eq!(query[0], ("search", "hello"));
}

#[test]
fn test_empty_builder() {
    let builder = QueryBuilder::new();
    let query = builder.build();
    assert!(query.is_empty());
}

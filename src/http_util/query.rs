//! Query parameter builder for cleaner API request construction.

use std::fmt::Display;

/// Builder for constructing URL query parameters.
///
/// Simplifies the common pattern of conditionally adding optional parameters.
///
/// # Example
/// ```ignore
/// let query = QueryBuilder::new()
///     .required("startDate", start_date)
///     .optional("limit", limit)
///     .optional("offset", offset)
///     .build();
/// ```
#[derive(Default)]
pub struct QueryBuilder {
    params: Vec<(String, String)>,
}

impl QueryBuilder {
    /// Create a new empty query builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a required parameter.
    pub fn required(mut self, key: &str, value: impl Display) -> Self {
        self.params.push((key.to_string(), value.to_string()));
        self
    }

    /// Add an optional parameter (only added if Some).
    pub fn optional<T: Display>(mut self, key: &str, value: Option<T>) -> Self {
        if let Some(v) = value {
            self.params.push((key.to_string(), v.to_string()));
        }
        self
    }

    /// Build the final query parameter slice.
    /// Returns a Vec of tuple references suitable for reqwest's `.query()`.
    pub fn build(&self) -> Vec<(&str, &str)> {
        self.params
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
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
}

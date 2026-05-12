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
#[path = "query_tests.rs"]
mod tests;

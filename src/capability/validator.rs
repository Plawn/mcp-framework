//! Access validation for tool calls, prompt access, and resource access.
//!
//! Unlike [`CapabilityFilter`](super::CapabilityFilter) which controls *visibility*
//! in `list_*` responses, [`AccessValidator`] controls *execution* — it runs before
//! dispatch in `call_tool`, `get_prompt`, and `read_resource`, and can reject
//! requests with an MCP error.

use std::future::Future;
use std::pin::Pin;

use serde_json::{Map, Value};

use crate::auth::StoredToken;

/// The result of an access validation check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessDecision {
    /// The request is allowed to proceed.
    Allow,
    /// The request is denied with the given reason.
    Deny(String),
}

/// Trait for validating access before executing tools, prompts, or resources.
///
/// Unlike [`CapabilityFilter`](super::CapabilityFilter) which controls *visibility*
/// in `list_*` responses, `AccessValidator` controls *execution* — it runs before
/// dispatch in `call_tool`, `get_prompt`, and `read_resource`, and can reject
/// requests with an error.
///
/// When a [claims decoder](crate::auth::TokenStore::with_claims_decoder) is configured,
/// the `token` parameter contains decoded claims accessible via
/// [`StoredToken::claims::<C>()`](StoredToken::claims).
///
/// The default implementations allow all requests. Override only the methods you need.
pub trait AccessValidator: Send + Sync + 'static {
    /// Validate access for a `call_tool` request.
    fn validate_tool_call(
        &self,
        tool_name: &str,
        arguments: Option<&Map<String, Value>>,
        token: Option<&StoredToken>,
        session_id: &str,
    ) -> Pin<Box<dyn Future<Output = AccessDecision> + Send + '_>> {
        let _ = (tool_name, arguments, token, session_id);
        Box::pin(std::future::ready(AccessDecision::Allow))
    }

    /// Validate access for a `get_prompt` request.
    fn validate_prompt_access(
        &self,
        prompt_name: &str,
        arguments: Option<&Map<String, Value>>,
        token: Option<&StoredToken>,
        session_id: &str,
    ) -> Pin<Box<dyn Future<Output = AccessDecision> + Send + '_>> {
        let _ = (prompt_name, arguments, token, session_id);
        Box::pin(std::future::ready(AccessDecision::Allow))
    }

    /// Validate access for a `read_resource` request.
    fn validate_resource_access(
        &self,
        resource_uri: &str,
        token: Option<&StoredToken>,
        session_id: &str,
    ) -> Pin<Box<dyn Future<Output = AccessDecision> + Send + '_>> {
        let _ = (resource_uri, token, session_id);
        Box::pin(std::future::ready(AccessDecision::Allow))
    }
}

/// Validates only tool calls via a closure. Prompts and resources are always allowed.
///
/// # Example
///
/// ```rust,ignore
/// use mcp_framework::prelude::*;
///
/// let validator = Arc::new(ToolCallValidator(
///     |tool_name: &str, _args, token: Option<&StoredToken>, _session: &str| {
///         if tool_name.starts_with("admin_") {
///             match token.and_then(|t| t.claims::<MyClaims>()) {
///                 Some(c) if c.roles.contains(&"admin".into()) => AccessDecision::Allow,
///                 _ => AccessDecision::Deny("admin role required".into()),
///             }
///         } else {
///             AccessDecision::Allow
///         }
///     },
/// ));
/// ```
pub struct ToolCallValidator<F>(pub F);

impl<F> AccessValidator for ToolCallValidator<F>
where
    F: Fn(&str, Option<&Map<String, Value>>, Option<&StoredToken>, &str) -> AccessDecision
        + Send
        + Sync
        + 'static,
{
    fn validate_tool_call(
        &self,
        tool_name: &str,
        arguments: Option<&Map<String, Value>>,
        token: Option<&StoredToken>,
        session_id: &str,
    ) -> Pin<Box<dyn Future<Output = AccessDecision> + Send + '_>> {
        let result = (self.0)(tool_name, arguments, token, session_id);
        Box::pin(std::future::ready(result))
    }
}

#[cfg(test)]
#[path = "validator_tests.rs"]
mod tests;

//! What a call carried besides its arguments: the request it arrived on, and who made it.
//!
//! [`CallRequest`] is the transport-level view of a call — headers, URI, and the typed extensions
//! the middleware attached — handed to tool handlers through
//! [`ToolCallContext::request`](super::ToolCallContext::request). [`CallInfo`] is the borrowed
//! bundle the [`AccessValidator`](super::AccessValidator) and the
//! [`CapabilityFilter`](super::CapabilityFilter) receive through their `*_call` / `*_for` methods.
//!
//! Both exist so an application can read caller-supplied context (a tenant chosen by a header or a
//! query parameter, a structured identity attached by an in-process caller) without each
//! consumer re-deriving it from `RequestContext` extensions on its own.

use crate::auth::StoredToken;

/// The HTTP request a call arrived on — or, for the loopback transport, the one it synthesizes.
///
/// `None` wherever there is no request to speak of: in stdio mode, and on a programmatic
/// [`CapabilityRegistry::call_tool_with_context`](super::CapabilityRegistry::call_tool_with_context)
/// that does not provide one.
///
/// `extensions` is the request's own type-map, so what the auth middleware attached is readable
/// here: [`BearerToken`](crate::auth::BearerToken) for any authenticated HTTP call,
/// [`RequestToken`](crate::auth::RequestToken) in
/// [`TokenMode::ResourceServer`](crate::auth::TokenMode::ResourceServer), and whatever an
/// in-process caller posed with
/// [`LoopbackIdentity::with_extension`](crate::transport::LoopbackIdentity::with_extension).
///
/// The method and body are left out on purpose: every call is a `POST /mcp`, and the body is the
/// JSON-RPC message the arguments already came from.
#[derive(Clone, Debug, Default)]
pub struct CallRequest {
    pub headers: http::HeaderMap,
    pub uri: http::Uri,
    pub extensions: http::Extensions,
}

impl CallRequest {
    /// Copy what a handler may read out of the request parts rmcp injects into a call's context.
    pub fn from_parts(parts: &http::request::Parts) -> Self {
        Self {
            headers: parts.headers.clone(),
            uri: parts.uri.clone(),
            extensions: parts.extensions.clone(),
        }
    }

    /// The value of query parameter `name`, percent-decoded — `None` when absent.
    ///
    /// Only the first occurrence counts. A convenience for the common case (a tenant or space
    /// chosen in the connection URL), not a query-string parser.
    pub fn query_param(&self, name: &str) -> Option<String> {
        self.uri.query()?.split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (key == name).then(|| {
                urlencoding::decode(value)
                    .map(|v| v.into_owned())
                    .unwrap_or_else(|_| value.to_string())
            })
        })
    }
}

/// Everything known about a call before it runs, borrowed for the duration of a check.
///
/// Passed to [`AccessValidator::validate_call`](super::AccessValidator::validate_call) and
/// [`CapabilityFilter::filter_tools_for`](super::CapabilityFilter::filter_tools_for). A struct
/// rather than more positional parameters so the next piece of context is a field, not another
/// trait method.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct CallInfo<'a> {
    /// The resolved session identity — the same value the audit record carries.
    pub session_id: &'a str,
    /// The caller's credential, resolved exactly as for the legacy validator methods.
    pub token: Option<&'a StoredToken>,
    /// The request the call arrived on; `None` in stdio mode.
    pub request: Option<&'a CallRequest>,
}

impl<'a> CallInfo<'a> {
    pub fn new(
        session_id: &'a str,
        token: Option<&'a StoredToken>,
        request: Option<&'a CallRequest>,
    ) -> Self {
        Self {
            session_id,
            token,
            request,
        }
    }
}

#[cfg(test)]
#[path = "request_tests.rs"]
mod tests;

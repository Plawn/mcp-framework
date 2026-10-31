//! Which `redirect_uri` `/oauth/authorize` may send an authorization code to.
//!
//! In the proxying token modes Keycloak only ever sees the framework's own
//! callback (`{public_url}/oauth/callback`); the hop to the client's
//! `redirect_uri` is made by the framework. Keycloak's per-client redirect
//! allowlist therefore no longer guards that hop, and without a check here
//! `/oauth/authorize` would be an open redirector that hands out codes.
//!
//! A `redirect_uri` is accepted when it is
//!
//! 1. one the `client_id` registered through `/oauth/register` (RFC 7591);
//! 2. a loopback URI (`http://localhost`, `127.0.0.1` or `[::1]`, any port —
//!    RFC 8252 §7.3, native clients such as Claude Code);
//! 3. on the `public_url` origin (the deployment's own SPA);
//! 4. listed verbatim in `OAUTH_ALLOWED_REDIRECT_URIS`.
//!
//! A URI carrying a fragment is always refused (RFC 6749 §3.1.2).

use url::{Host, Url};

/// Decide whether `redirect_uri` may receive a code. See the module docs.
pub(crate) fn redirect_uri_allowed(
    redirect_uri: &str,
    registered: Option<&[String]>,
    public_url: &str,
    allowlist: &[String],
) -> bool {
    let Ok(uri) = Url::parse(redirect_uri) else {
        return false;
    };
    if uri.fragment().is_some() {
        return false;
    }

    let listed = |uris: &[String]| uris.iter().any(|allowed| allowed == redirect_uri);

    registered.is_some_and(listed)
        || is_loopback(&uri)
        || Url::parse(public_url).is_ok_and(|public| public.origin() == uri.origin())
        || listed(allowlist)
}

fn is_loopback(uri: &Url) -> bool {
    if uri.scheme() != "http" {
        return false;
    }
    match uri.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBLIC: &str = "https://mcp.example.com";

    fn allowed(uri: &str) -> bool {
        redirect_uri_allowed(uri, None, PUBLIC, &[])
    }

    #[test]
    fn loopback_uris_are_accepted_on_any_port() {
        assert!(allowed("http://localhost:53127/callback"));
        assert!(allowed("http://127.0.0.1:1/callback"));
        assert!(allowed("http://[::1]:8080/cb"));
    }

    #[test]
    fn loopback_lookalikes_are_refused() {
        assert!(!allowed("https://localhost.attacker.example/callback"));
        assert!(!allowed("http://127.0.0.1.attacker.example/callback"));
        // Loopback is an http-only allowance (RFC 8252 §7.3).
        assert!(!allowed("ftp://127.0.0.1/callback"));
    }

    #[test]
    fn the_public_origin_is_accepted_and_only_it() {
        assert!(allowed("https://mcp.example.com/"));
        assert!(allowed("https://mcp.example.com/app/callback?x=1"));
        assert!(!allowed("http://mcp.example.com/"));
        assert!(!allowed("https://mcp.example.com:8443/"));
        assert!(!allowed("https://mcp.example.com.attacker.example/"));
    }

    #[test]
    fn registered_and_configured_uris_match_exactly() {
        let registered = ["https://client.example/cb".to_string()];
        let allowlist = ["https://claude.ai/api/mcp/auth_callback".to_string()];
        let check = |uri| redirect_uri_allowed(uri, Some(&registered), PUBLIC, &allowlist);

        assert!(check("https://client.example/cb"));
        assert!(check("https://claude.ai/api/mcp/auth_callback"));
        assert!(!check("https://client.example/cb/other"));
        assert!(!check("https://claude.ai/api/mcp/auth_callback2"));
    }

    #[test]
    fn unregistered_foreign_uris_and_fragments_are_refused() {
        assert!(!allowed("https://attacker.example/callback"));
        assert!(!allowed("http://localhost:1/callback#frag"));
        assert!(!allowed("not a url"));
    }
}

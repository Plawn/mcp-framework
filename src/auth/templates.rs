//! HTML templates for OAuth flow responses.

use axum::response::Html;

/// Escape HTML special characters to prevent XSS.
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Generate a success page after OAuth authentication.
pub fn success_page(session_id: &str, app_name: &str) -> Html<String> {
    let session_id = escape_html(session_id);
    let app_name = escape_html(app_name);
    Html(format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Authentication Successful</title>
    <style>
        body {{ font-family: system-ui, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }}
        .success {{ color: #059669; }}
        code {{ background: #f3f4f6; padding: 2px 6px; border-radius: 4px; }}
    </style>
</head>
<body>
    <h1 class="success">Authentication Successful!</h1>
    <p>You have been authenticated with {}.</p>
    <p>Session ID: <code>{}</code></p>
    <p>You can now close this window and return to your MCP client.</p>
</body>
</html>"#,
        app_name, session_id
    ))
}

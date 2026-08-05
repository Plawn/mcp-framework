use super::token_param_for_log;

#[test]
fn oauth_secrets_are_redacted_before_logging() {
    for key in [
        "client_secret",
        "client_assertion",
        "code",
        "code_verifier",
        "password",
        "refresh_token",
    ] {
        assert_eq!(token_param_for_log(key, "super-secret"), "***");
    }
    assert_eq!(
        token_param_for_log("grant_type", "authorization_code"),
        "authorization_code"
    );
}

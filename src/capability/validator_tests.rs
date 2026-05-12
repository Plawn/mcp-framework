use super::*;

struct AllowAll;
impl AccessValidator for AllowAll {}

struct DenyAdmin;
impl AccessValidator for DenyAdmin {
    fn validate_tool_call(
        &self,
        tool_name: &str,
        _arguments: Option<&Map<String, Value>>,
        _token: Option<&StoredToken>,
        _session_id: &str,
    ) -> Pin<Box<dyn Future<Output = AccessDecision> + Send + '_>> {
        let decision = if tool_name.starts_with("admin_") {
            AccessDecision::Deny("admin only".into())
        } else {
            AccessDecision::Allow
        };
        Box::pin(std::future::ready(decision))
    }
}

#[tokio::test]
async fn default_implementations_allow_all() {
    let v = AllowAll;
    assert_eq!(
        v.validate_tool_call("any", None, None, "s1").await,
        AccessDecision::Allow
    );
    assert_eq!(
        v.validate_prompt_access("any", None, None, "s1").await,
        AccessDecision::Allow
    );
    assert_eq!(
        v.validate_resource_access("any://uri", None, "s1").await,
        AccessDecision::Allow
    );
}

#[tokio::test]
async fn custom_validator_denies() {
    let v = DenyAdmin;
    assert_eq!(
        v.validate_tool_call("admin_delete", None, None, "s1").await,
        AccessDecision::Deny("admin only".into())
    );
    assert_eq!(
        v.validate_tool_call("public_read", None, None, "s1").await,
        AccessDecision::Allow
    );
    assert_eq!(
        v.validate_prompt_access("admin_prompt", None, None, "s1")
            .await,
        AccessDecision::Allow
    );
}

#[tokio::test]
async fn tool_call_validator_closure() {
    let v = ToolCallValidator(
        |name: &str,
         _args: Option<&Map<String, Value>>,
         _token: Option<&StoredToken>,
         _session: &str| {
            if name == "blocked" {
                AccessDecision::Deny("blocked".into())
            } else {
                AccessDecision::Allow
            }
        },
    );
    assert_eq!(
        v.validate_tool_call("blocked", None, None, "s1").await,
        AccessDecision::Deny("blocked".into())
    );
    assert_eq!(
        v.validate_tool_call("allowed", None, None, "s1").await,
        AccessDecision::Allow
    );
    assert_eq!(
        v.validate_prompt_access("anything", None, None, "s1")
            .await,
        AccessDecision::Allow
    );
}

#[tokio::test]
async fn tool_call_validator_with_claims() {
    use std::sync::Arc;

    #[derive(Debug)]
    struct Claims {
        role: String,
    }

    let token = StoredToken {
        access_token: "jwt".into(),
        refresh_token: None,
        expires_at: None,
        decoded_claims: Some(Arc::new(Claims {
            role: "admin".into(),
        })),
    };

    let v = ToolCallValidator(
        |_name: &str,
         _args: Option<&Map<String, Value>>,
         token: Option<&StoredToken>,
         _session: &str| {
            match token.and_then(|t| t.claims::<Claims>()) {
                Some(c) if c.role == "admin" => AccessDecision::Allow,
                _ => AccessDecision::Deny("not admin".into()),
            }
        },
    );

    assert_eq!(
        v.validate_tool_call("any", None, Some(&token), "s1").await,
        AccessDecision::Allow
    );
    assert_eq!(
        v.validate_tool_call("any", None, None, "s1").await,
        AccessDecision::Deny("not admin".into())
    );
}

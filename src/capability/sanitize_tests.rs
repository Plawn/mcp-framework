use super::*;
use std::sync::Arc;

fn make_tool(name: &'static str, schema: serde_json::Map<String, Value>) -> Tool {
    Tool::new(name, name, Arc::new(schema))
}

/// Sanitize with a throwaway audit, so no test can silence another through the
/// audit's deduplication.
fn sanitize(tools: &mut [Tool]) {
    sanitize_tool_schemas(tools, &DescriptionAudit::new());
}

#[test]
fn patches_missing_type_object() {
    let mut tools = vec![make_tool("bad", serde_json::Map::new())];
    sanitize(&mut tools);

    let schema = tools[0].input_schema.as_ref();
    assert_eq!(schema.get("type").unwrap(), "object");
    assert!(schema.contains_key("properties"));
}

#[test]
fn leaves_valid_schema_untouched() {
    let mut schema = serde_json::Map::new();
    schema.insert("type".to_string(), Value::String("object".to_string()));
    schema.insert(
        "properties".to_string(),
        Value::Object({
            let mut m = serde_json::Map::new();
            m.insert("name".to_string(), Value::Object(Default::default()));
            m
        }),
    );
    let mut tools = vec![make_tool("good", schema.clone())];
    sanitize(&mut tools);

    assert_eq!(tools[0].input_schema.as_ref(), &schema);
}

#[test]
fn strips_schema_and_title_from_valid_schema() {
    let mut schema = serde_json::Map::new();
    schema.insert("type".to_string(), Value::String("object".to_string()));
    schema.insert(
        "$schema".to_string(),
        Value::String("https://json-schema.org/draft/2020-12/schema".to_string()),
    );
    schema.insert("title".to_string(), Value::String("MyParams".to_string()));
    schema.insert(
        "properties".to_string(),
        Value::Object(serde_json::Map::new()),
    );

    let mut tools = vec![make_tool("with_meta", schema)];
    sanitize(&mut tools);

    let patched = tools[0].input_schema.as_ref();
    assert_eq!(patched.get("type").unwrap(), "object");
    assert!(!patched.contains_key("$schema"));
    assert!(!patched.contains_key("title"));
}

#[test]
fn inlines_ref_enums() {
    let schema: serde_json::Map<String, Value> = serde_json::from_value(serde_json::json!({
        "$defs": {
            "MyAction": { "enum": ["ask", "brief"], "type": "string" }
        },
        "type": "object",
        "properties": {
            "action": {
                "$ref": "#/$defs/MyAction",
                "description": "The action"
            }
        },
        "required": ["action"]
    }))
    .unwrap();

    let mut tools = vec![make_tool("t", schema)];
    sanitize(&mut tools);

    let patched = tools[0].input_schema.as_ref();
    assert!(!patched.contains_key("$defs"), "$defs should be removed");

    let action = patched["properties"]["action"].as_object().unwrap();
    assert_eq!(
        action.get("enum").unwrap(),
        &serde_json::json!(["ask", "brief"]),
    );
    assert_eq!(action.get("type").unwrap(), "string");
    assert_eq!(action.get("description").unwrap(), "The action");
    assert!(!action.contains_key("$ref"));
}

#[test]
fn inlines_anyof_with_ref() {
    let schema: serde_json::Map<String, Value> = serde_json::from_value(serde_json::json!({
        "$defs": {
            "DetailLevel": { "enum": ["brief", "detailed"], "type": "string" }
        },
        "type": "object",
        "properties": {
            "detail": {
                "anyOf": [
                    { "$ref": "#/$defs/DetailLevel" },
                    { "type": "null" }
                ],
                "description": "Level of detail"
            }
        }
    }))
    .unwrap();

    let mut tools = vec![make_tool("t", schema)];
    sanitize(&mut tools);

    let patched = tools[0].input_schema.as_ref();
    assert!(!patched.contains_key("$defs"));

    let variants = patched["properties"]["detail"]["anyOf"].as_array().unwrap();
    assert_eq!(variants.len(), 2);
    assert_eq!(
        variants[0],
        serde_json::json!({"enum": ["brief", "detailed"], "type": "string"}),
    );
    assert_eq!(variants[1], serde_json::json!({"type": "null"}));
}

#[test]
fn flattens_top_level_oneof_tagged_enum() {
    let schema: serde_json::Map<String, Value> = serde_json::from_value(serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "ManageNotesInput",
        "oneOf": [
            {
                "type": "object",
                "properties": {
                    "action": { "type": "string", "const": "add" }
                },
                "$ref": "#/$defs/AddNoteInput",
                "required": ["action"]
            },
            {
                "type": "object",
                "properties": {
                    "action": { "type": "string", "const": "delete" }
                },
                "$ref": "#/$defs/DeleteNoteInput",
                "required": ["action"]
            }
        ],
        "$defs": {
            "AddNoteInput": {
                "type": "object",
                "properties": {
                    "task_id": { "type": "string" },
                    "body": { "type": "string" }
                },
                "required": ["task_id", "body"]
            },
            "DeleteNoteInput": {
                "type": "object",
                "properties": {
                    "task_id": { "type": "string" },
                    "note_id": { "type": "string" }
                },
                "required": ["task_id", "note_id"]
            }
        }
    }))
    .unwrap();

    let mut tools = vec![make_tool("manage_notes", schema)];
    sanitize(&mut tools);
    let patched = tools[0].input_schema.as_ref();

    assert_eq!(patched.get("type").unwrap(), "object");
    assert!(!patched.contains_key("oneOf"));
    assert!(!patched.contains_key("anyOf"));
    assert!(!patched.contains_key("allOf"));
    assert!(!patched.contains_key("$defs"));
    assert!(!patched.contains_key("title"));
    assert!(!patched.contains_key("$schema"));

    let props = patched["properties"].as_object().unwrap();
    let action = props["action"].as_object().unwrap();
    assert_eq!(action["type"], "string");
    let action_enum: Vec<&str> = action["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(action_enum, vec!["add", "delete"]);

    assert_eq!(props["task_id"]["type"], "string");
    assert_eq!(props["body"]["type"], "string");
    assert_eq!(props["note_id"]["type"], "string");

    let required: Vec<&str> = patched["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(required, vec!["action"]);
}

#[test]
fn resolve_refs_deep_merges_properties_and_required() {
    let schema: serde_json::Map<String, Value> = serde_json::from_value(serde_json::json!({
        "type": "object",
        "properties": {
            "variant": {
                "type": "object",
                "properties": { "tag": { "const": "x" } },
                "$ref": "#/$defs/Inner",
                "required": ["tag"]
            }
        },
        "$defs": {
            "Inner": {
                "type": "object",
                "properties": {
                    "a": { "type": "string" },
                    "b": { "type": "integer" }
                },
                "required": ["a"]
            }
        }
    }))
    .unwrap();

    let mut tools = vec![make_tool("t", schema)];
    sanitize(&mut tools);
    let variant = tools[0].input_schema.as_ref()["properties"]["variant"]
        .as_object()
        .unwrap();

    let props = variant["properties"].as_object().unwrap();
    assert!(props.contains_key("tag"));
    assert!(props.contains_key("a"));
    assert!(props.contains_key("b"));

    let required: Vec<&str> = variant["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(required.contains(&"a"));
    assert!(required.contains(&"tag"));
}

#[test]
fn flattens_top_level_oneof_without_discriminator() {
    let schema: serde_json::Map<String, Value> = serde_json::from_value(serde_json::json!({
        "oneOf": [
            {
                "type": "object",
                "properties": {
                    "a": { "type": "string" }
                },
                "required": ["a"]
            },
            {
                "type": "object",
                "properties": {
                    "b": { "type": "integer" }
                },
                "required": ["b"]
            }
        ]
    }))
    .unwrap();

    let mut tools = vec![make_tool("t", schema)];
    sanitize(&mut tools);
    let patched = tools[0].input_schema.as_ref();

    assert_eq!(patched.get("type").unwrap(), "object");
    assert!(!patched.contains_key("oneOf"));
    assert!(!patched.contains_key("required"));
    let props = patched["properties"].as_object().unwrap();
    assert!(props.contains_key("a"));
    assert!(props.contains_key("b"));
}

#[test]
fn patches_serde_json_value_style_schema() {
    let mut schema = serde_json::Map::new();
    schema.insert(
        "$schema".to_string(),
        Value::String("http://json-schema.org/draft-07/schema#".to_string()),
    );
    schema.insert("title".to_string(), Value::String("AnyValue".to_string()));

    let mut tools = vec![make_tool("any_value", schema)];
    sanitize(&mut tools);

    let patched = tools[0].input_schema.as_ref();
    assert_eq!(patched.get("type").unwrap(), "object");
    assert!(patched.contains_key("properties"));
    assert!(!patched.contains_key("$schema"));
    assert!(!patched.contains_key("title"));
}

#[test]
fn replaces_boolean_true_schemas_in_properties() {
    let schema: serde_json::Map<String, Value> = serde_json::from_value(serde_json::json!({
        "type": "object",
        "properties": {
            "structured": { "type": "integer" },
            "opaque": true
        },
        "required": ["structured", "opaque"]
    }))
    .unwrap();

    let mut tool = make_tool("t", serde_json::Map::new());
    tool.output_schema = Some(Arc::new(schema));
    let mut tools = vec![tool];
    sanitize(&mut tools);

    let os = tools[0].output_schema.as_ref().unwrap().as_ref();
    let props = os["properties"].as_object().unwrap();

    assert_eq!(props["structured"]["type"], "integer");
    assert!(props["opaque"].is_object());
    assert_eq!(props["opaque"], serde_json::json!({}));
}

#[test]
fn strips_title_from_nested_schemas() {
    let schema: serde_json::Map<String, Value> = serde_json::from_value(serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "TopLevel",
        "type": "object",
        "properties": {
            "items": {
                "type": "array",
                "items": {
                    "type": "object",
                    "title": "NestedItem",
                    "properties": {
                        "id": { "type": "integer" }
                    }
                }
            }
        }
    }))
    .unwrap();

    let mut tool = make_tool("t", serde_json::Map::new());
    tool.output_schema = Some(Arc::new(schema));
    let mut tools = vec![tool];
    sanitize(&mut tools);

    let os = tools[0].output_schema.as_ref().unwrap().as_ref();
    assert!(!os.contains_key("$schema"));
    assert!(!os.contains_key("title"));

    let nested = &os["properties"]["items"]["items"];
    assert!(!nested.as_object().unwrap().contains_key("title"));
}

#[test]
fn flatten_preserves_variant_docs_and_required() {
    let schema: serde_json::Map<String, Value> = serde_json::from_value(serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "ManageNotesInput",
        "oneOf": [
            {
                "type": "object",
                "description": "Add a note to a task.",
                "properties": {
                    "action": { "type": "string", "const": "add" }
                },
                "$ref": "#/$defs/AddNoteInput",
                "required": ["action"]
            },
            {
                "type": "object",
                "description": "Remove a note from a task.",
                "properties": {
                    "action": { "type": "string", "const": "remove" }
                },
                "$ref": "#/$defs/RemoveNoteInput",
                "required": ["action"]
            }
        ],
        "$defs": {
            "AddNoteInput": {
                "type": "object",
                "properties": {
                    "task_id": { "type": "string", "description": "The task." },
                    "body": { "type": "string", "description": "The note body." }
                },
                "required": ["task_id", "body"]
            },
            "RemoveNoteInput": {
                "type": "object",
                "properties": {
                    "task_id": { "type": "string" },
                    "note_id": { "type": "string", "description": "The note to drop." }
                },
                "required": ["task_id", "note_id"]
            }
        }
    }))
    .unwrap();

    let mut tools = vec![make_tool("manage_notes", schema)];
    sanitize(&mut tools);
    let props = tools[0].input_schema.as_ref()["properties"]
        .as_object()
        .unwrap()
        .clone();

    // The synthesized discriminant carries every variant's doc.
    assert_eq!(
        props["action"]["description"],
        "`add`: Add a note to a task. · `remove`: Remove a note from a task."
    );

    // Per-variant `required` survives as prose, appended to the existing doc.
    assert_eq!(
        props["body"]["description"],
        "The note body. Required when action=add."
    );
    assert_eq!(
        props["note_id"]["description"],
        "The note to drop. Required when action=remove."
    );
    // Required by both variants, and the retained (first) entry had no
    // description — the homonym from the second variant is irrelevant here,
    // only the constraint suffix applies.
    assert_eq!(
        props["task_id"]["description"],
        "The task. Required when action=add, remove."
    );

    // Flattening itself is unchanged.
    let required: Vec<&str> = tools[0].input_schema.as_ref()["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(required, vec!["action"]);
}

#[test]
fn flatten_collision_keeps_the_available_description() {
    let schema: serde_json::Map<String, Value> = serde_json::from_value(serde_json::json!({
        "oneOf": [
            {
                "type": "object",
                "properties": {
                    "action": { "type": "string", "const": "add" },
                    "target": { "type": "string" }
                },
                "required": ["action"]
            },
            {
                "type": "object",
                "properties": {
                    "action": { "type": "string", "const": "remove" },
                    "target": { "type": "string", "description": "What to act on." }
                },
                "required": ["action"]
            }
        ]
    }))
    .unwrap();

    let mut tools = vec![make_tool("t", schema)];
    sanitize(&mut tools);
    let props = tools[0].input_schema.as_ref()["properties"]
        .as_object()
        .unwrap()
        .clone();

    // First variant wins the slot but had no description; the later one's is copied.
    assert_eq!(props["target"]["description"], "What to act on.");
    // No variant is documented → no invented description on the discriminant.
    assert!(
        !props["action"]
            .as_object()
            .unwrap()
            .contains_key("description")
    );
}

#[test]
fn flatten_discriminant_description_falls_back_to_undocumented_variants() {
    let schema: serde_json::Map<String, Value> = serde_json::from_value(serde_json::json!({
        "oneOf": [
            {
                "type": "object",
                "description": "Add something.",
                "properties": { "action": { "type": "string", "const": "add" } },
                "required": ["action"]
            },
            {
                "type": "object",
                "properties": { "action": { "type": "string", "const": "remove" } },
                "required": ["action"]
            }
        ]
    }))
    .unwrap();

    let mut tools = vec![make_tool("t", schema)];
    sanitize(&mut tools);
    let action = tools[0].input_schema.as_ref()["properties"]["action"]
        .as_object()
        .unwrap()
        .clone();

    // A variant with no doc contributes just its value.
    assert_eq!(action["description"], "`add`: Add something. · `remove`");
}

// ── 919: title fallback + documentation audit ──────────────────────

#[test]
fn folds_title_into_description_when_absent() {
    let schema: serde_json::Map<String, Value> = serde_json::from_value(serde_json::json!({
        "type": "object",
        "title": "SearchParams",
        "properties": {
            "query": { "type": "string", "title": "Full-text query" },
            "items": {
                "type": "array",
                "items": { "type": "object", "title": "A single hit" }
            }
        }
    }))
    .unwrap();

    let mut tools = vec![make_tool("t", schema)];
    sanitize(&mut tools);
    let patched = tools[0].input_schema.as_ref();

    // `title` is still gone at every level — but its text survives.
    assert!(!patched.contains_key("title"));
    assert_eq!(patched["description"], "SearchParams");

    let query = patched["properties"]["query"].as_object().unwrap();
    assert!(!query.contains_key("title"));
    assert_eq!(query["description"], "Full-text query");

    let item = patched["properties"]["items"]["items"].as_object().unwrap();
    assert!(!item.contains_key("title"));
    assert_eq!(item["description"], "A single hit");
}

#[test]
fn strips_title_when_description_is_present() {
    let schema: serde_json::Map<String, Value> = serde_json::from_value(serde_json::json!({
        "type": "object",
        "title": "SearchParams",
        "description": "Search the corpus.",
        "properties": {
            "query": {
                "type": "string",
                "title": "Full-text query",
                "description": "What to look for."
            },
            "blank": { "type": "string", "title": "   ", "description": "Kept." }
        }
    }))
    .unwrap();

    let mut tools = vec![make_tool("t", schema)];
    sanitize(&mut tools);
    let patched = tools[0].input_schema.as_ref();

    assert!(!patched.contains_key("title"));
    assert_eq!(patched["description"], "Search the corpus.");

    let query = patched["properties"]["query"].as_object().unwrap();
    assert!(!query.contains_key("title"));
    assert_eq!(query["description"], "What to look for.");

    // A blank title is dropped, never promoted over nothing.
    let blank = patched["properties"]["blank"].as_object().unwrap();
    assert!(!blank.contains_key("title"));
    assert_eq!(blank["description"], "Kept.");
}

#[test]
fn blank_title_is_not_promoted() {
    let schema: serde_json::Map<String, Value> = serde_json::from_value(serde_json::json!({
        "type": "object",
        "properties": { "a": { "type": "string", "title": "  " } }
    }))
    .unwrap();

    let mut tools = vec![make_tool("t", schema)];
    sanitize(&mut tools);

    let a = tools[0].input_schema.as_ref()["properties"]["a"]
        .as_object()
        .unwrap()
        .clone();
    assert!(!a.contains_key("title"));
    assert!(!a.contains_key("description"));
}

#[test]
fn audit_reports_missing_tool_and_property_descriptions() {
    let schema: serde_json::Map<String, Value> = serde_json::from_value(serde_json::json!({
        "type": "object",
        "properties": {
            "documented": { "type": "string", "description": "Fine." },
            "bare": { "type": "string" },
            "blank": { "type": "string", "description": "   " }
        }
    }))
    .unwrap();

    let mut tool = make_tool("t", schema);
    tool.description = None;

    assert_eq!(
        audit_descriptions(&tool),
        vec![
            "the tool itself has no description".to_string(),
            "parameters without a description: bare, blank".to_string(),
        ],
    );
}

#[test]
fn audit_is_silent_on_a_fully_documented_tool() {
    let schema: serde_json::Map<String, Value> = serde_json::from_value(serde_json::json!({
        "type": "object",
        "properties": { "query": { "type": "string", "description": "What to look for." } }
    }))
    .unwrap();

    let tool = make_tool("search", schema);
    assert!(tool.description.is_some());
    assert!(audit_descriptions(&tool).is_empty());
}

#[test]
fn audit_accepts_a_description_folded_from_a_title() {
    let schema: serde_json::Map<String, Value> = serde_json::from_value(serde_json::json!({
        "type": "object",
        "properties": { "query": { "type": "string", "title": "Full-text query" } }
    }))
    .unwrap();

    let mut tools = vec![make_tool("search", schema)];
    // Before sanitization the title is not yet documentation.
    assert_eq!(
        audit_descriptions(&tools[0]),
        vec!["parameters without a description: query".to_string()],
    );

    sanitize(&mut tools);
    assert!(audit_descriptions(&tools[0]).is_empty());
}

#[test]
fn audit_reports_a_schema_with_no_properties_only_for_the_tool() {
    let mut tool = make_tool("t", serde_json::Map::new());
    tool.description = None;
    let mut tools = vec![tool];
    sanitize(&mut tools);

    assert_eq!(
        audit_descriptions(&tools[0]),
        vec!["the tool itself has no description".to_string()],
    );
}

// ── Blank descriptions are missing descriptions (918 follow-up) ────

#[test]
fn flatten_collision_prefers_a_real_description_over_a_blank_one() {
    let schema: serde_json::Map<String, Value> = serde_json::from_value(serde_json::json!({
        "oneOf": [
            {
                "type": "object",
                "properties": {
                    "action": { "type": "string", "const": "add" },
                    "target": { "type": "string", "description": "   " }
                },
                "required": ["action"]
            },
            {
                "type": "object",
                "properties": {
                    "action": { "type": "string", "const": "remove" },
                    "target": { "type": "string", "description": "What to act on." }
                },
                "required": ["action"]
            }
        ]
    }))
    .unwrap();

    let mut tools = vec![make_tool("t", schema)];
    sanitize(&mut tools);
    let props = tools[0].input_schema.as_ref()["properties"]
        .as_object()
        .unwrap()
        .clone();

    // The retained entry's whitespace-only description documents nothing, so it
    // must not shut out the real one that comes later.
    assert_eq!(props["target"]["description"], "What to act on.");
}

#[test]
fn flatten_discriminant_ignores_a_blank_variant_doc() {
    let schema: serde_json::Map<String, Value> = serde_json::from_value(serde_json::json!({
        "oneOf": [
            {
                "type": "object",
                "description": "   ",
                "properties": { "action": { "type": "string", "const": "add" } },
                "required": ["action"]
            },
            {
                "type": "object",
                "description": "Remove it.",
                "properties": { "action": { "type": "string", "const": "remove" } },
                "required": ["action"]
            }
        ]
    }))
    .unwrap();

    let mut tools = vec![make_tool("t", schema)];
    sanitize(&mut tools);

    assert_eq!(
        tools[0].input_schema.as_ref()["properties"]["action"]["description"],
        "`add` · `remove`: Remove it.",
    );
}

#[test]
fn flatten_discriminant_fallback_skips_a_blank_property_description() {
    let schema: serde_json::Map<String, Value> = serde_json::from_value(serde_json::json!({
        "oneOf": [
            {
                "type": "object",
                "properties": {
                    "action": { "type": "string", "const": "add", "description": "  " }
                },
                "required": ["action"]
            },
            {
                "type": "object",
                "properties": {
                    "action": { "type": "string", "const": "remove", "description": "Which one." }
                },
                "required": ["action"]
            }
        ]
    }))
    .unwrap();

    let mut tools = vec![make_tool("t", schema)];
    sanitize(&mut tools);

    // No variant is documented, so the fallback is the discriminator property's
    // own description — the first *real* one, not the first one.
    assert_eq!(
        tools[0].input_schema.as_ref()["properties"]["action"]["description"],
        "Which one.",
    );
}

#[test]
fn flatten_required_suffix_replaces_a_blank_description() {
    let schema: serde_json::Map<String, Value> = serde_json::from_value(serde_json::json!({
        "oneOf": [
            {
                "type": "object",
                "properties": {
                    "action": { "type": "string", "const": "add" },
                    "body": { "type": "string", "description": "   " }
                },
                "required": ["action", "body"]
            }
        ]
    }))
    .unwrap();

    let mut tools = vec![make_tool("t", schema)];
    sanitize(&mut tools);

    assert_eq!(
        tools[0].input_schema.as_ref()["properties"]["body"]["description"],
        "Required when action=add.",
    );
}

// ── Audit deduplication (919 follow-up) ────────────────────────────

#[test]
fn audit_reports_a_tool_version_only_once() {
    let schema: serde_json::Map<String, Value> = serde_json::from_value(serde_json::json!({
        "type": "object",
        "properties": { "bare": { "type": "string" } }
    }))
    .unwrap();
    let tool = make_tool("t", schema);
    let audit = DescriptionAudit::new();

    assert_eq!(
        audit.audit(&tool),
        Some(vec!["parameters without a description: bare".to_string()]),
    );
    // A polling client calling tools/list in a loop must not re-log this.
    assert_eq!(audit.audit(&tool), None);
}

#[test]
fn audit_reports_again_when_the_tool_changes() {
    let bare: serde_json::Map<String, Value> = serde_json::from_value(serde_json::json!({
        "type": "object",
        "properties": { "a": { "type": "string" } }
    }))
    .unwrap();
    let audit = DescriptionAudit::new();

    let mut tool = make_tool("t", bare);
    assert!(audit.audit(&tool).is_some());
    assert!(audit.audit(&tool).is_none());

    // A new property with no description is a new deficit, on a new version.
    let grown: serde_json::Map<String, Value> = serde_json::from_value(serde_json::json!({
        "type": "object",
        "properties": { "a": { "type": "string" }, "b": { "type": "string" } }
    }))
    .unwrap();
    tool.input_schema = Arc::new(grown);
    assert_eq!(
        audit.audit(&tool),
        Some(vec!["parameters without a description: a, b".to_string()]),
    );

    // So is a change of the tool's own description.
    tool.description = Some("Now documented.".into());
    assert!(audit.audit(&tool).is_some());
}

#[test]
fn audit_of_a_documented_tool_is_a_first_look_with_nothing_to_say() {
    let schema: serde_json::Map<String, Value> = serde_json::from_value(serde_json::json!({
        "type": "object",
        "properties": { "query": { "type": "string", "description": "What to look for." } }
    }))
    .unwrap();
    let audit = DescriptionAudit::new();
    let tool = make_tool("search", schema);

    assert_eq!(audit.audit(&tool), Some(Vec::new()));
    assert_eq!(audit.audit(&tool), None);
}

#[test]
fn two_sanitize_passes_share_one_audit() {
    let schema: serde_json::Map<String, Value> = serde_json::from_value(serde_json::json!({
        "type": "object",
        "properties": { "bare": { "type": "string" } }
    }))
    .unwrap();
    let audit = DescriptionAudit::new();

    let mut first = vec![make_tool("t", schema.clone())];
    sanitize_tool_schemas(&mut first, &audit);
    // The listing path consumed the finding; a second tools/list says nothing.
    let mut second = vec![make_tool("t", schema)];
    sanitize_tool_schemas(&mut second, &audit);
    assert!(audit.audit(&second[0]).is_none());
}

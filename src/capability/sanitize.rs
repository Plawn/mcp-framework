use std::sync::Arc;

use rmcp::model::Tool;
use serde_json::Value;

/// Strip schemars 1.x meta-fields (`$schema`, `title`) from a JSON schema object,
/// and recursively sanitize the entire schema tree:
/// - Removes `$schema` and `title` at every nesting level.
/// - Replaces boolean `true` schemas with `{}` — schemars emits `true` for
///   `serde_json::Value` (the "accept anything" schema), but strict MCP clients
///   like dust.tt reject boolean schemas and expect objects.
fn strip_meta_fields(schema: &mut serde_json::Map<String, Value>) {
    schema.remove("$schema");
    schema.remove("title");

    for value in schema.values_mut() {
        sanitize_value_recursive(value);
    }
}

/// Walk a JSON value and clean up schema nodes:
/// - `true` → `{}` (boolean schema → empty object schema)
/// - Objects get `$schema`/`title` removed, then recurse into their values
/// - Arrays recurse into each element
fn sanitize_value_recursive(value: &mut Value) {
    match value {
        Value::Bool(true) => {
            *value = Value::Object(serde_json::Map::new());
        }
        Value::Object(map) => {
            map.remove("$schema");
            map.remove("title");
            for v in map.values_mut() {
                sanitize_value_recursive(v);
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                sanitize_value_recursive(v);
            }
        }
        _ => {}
    }
}

/// Recursively resolve `$ref: "#/$defs/..."` pointers by inlining the
/// referenced definition.
///
/// When the `$ref` holder has sibling keys, they are combined with the
/// referenced definition per JSON Schema semantics:
/// - `properties` is deep-merged (sibling keys win on collision).
/// - `required` is unioned.
/// - Other keys (e.g. `description`, `default`) override keys from the def.
///
/// This matters for `#[serde(tag = "...")]` tagged enums, where schemars emits
/// a variant shaped like
/// `{ "type": "object", "properties": {"action": {"const": "add"}}, "$ref": "#/$defs/Variant", "required": ["action"] }`.
/// A naive override would wipe out `Variant.properties` and `Variant.required`,
/// losing all the variant's real fields.
fn resolve_refs(value: &mut Value, defs: &serde_json::Map<String, Value>) {
    match value {
        Value::Object(map) => {
            if let Some(Value::String(ref_str)) = map.get("$ref")
                && let Some(name) = ref_str.strip_prefix("#/$defs/")
                && let Some(def) = defs.get(name)
            {
                let mut inlined = def.clone();
                if let Value::Object(ref mut inlined_map) = inlined {
                    for (k, v) in map.iter() {
                        if k == "$ref" {
                            continue;
                        }
                        match (k.as_str(), inlined_map.get_mut(k), v) {
                            // Deep-merge properties (sibling wins on key collision).
                            (
                                "properties",
                                Some(Value::Object(def_props)),
                                Value::Object(sib_props),
                            ) => {
                                for (pk, pv) in sib_props {
                                    def_props.insert(pk.clone(), pv.clone());
                                }
                            }
                            // Union required lists.
                            ("required", Some(Value::Array(def_req)), Value::Array(sib_req)) => {
                                for item in sib_req {
                                    if !def_req.contains(item) {
                                        def_req.push(item.clone());
                                    }
                                }
                            }
                            // Everything else: sibling overrides def.
                            _ => {
                                inlined_map.insert(k.clone(), v.clone());
                            }
                        }
                    }
                }
                *value = inlined;
                // The inlined definition may itself contain $refs
                resolve_refs(value, defs);
                return;
            }
            for v in map.values_mut() {
                resolve_refs(v, defs);
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                resolve_refs(v, defs);
            }
        }
        _ => {}
    }
}

/// Extract `$defs` from a schema and inline all `$ref` pointers that
/// reference them, then drop `$defs`.  This produces a self-contained
/// schema without indirection — friendlier for MCP clients that do not
/// fully support JSON Schema references.
fn inline_defs(schema: &mut serde_json::Map<String, Value>) {
    let defs = match schema.remove("$defs") {
        Some(Value::Object(d)) => d,
        other => {
            if let Some(v) = other {
                schema.insert("$defs".to_string(), v);
            }
            return;
        }
    };

    for value in schema.values_mut() {
        resolve_refs(value, &defs);
    }
}

/// Flatten a top-level `oneOf` / `anyOf` / `allOf` into a single object schema.
///
/// Anthropic's API rejects these combinators at the **root** of `input_schema`
/// (nested uses are fine). schemars 1.x emits a root-level `oneOf` for
/// `#[serde(tag = "...")]` tagged enums, where each variant is an object whose
/// `properties` include the discriminator with a `const` value.
///
/// We detect that pattern, merge every variant's properties into a single flat
/// object, and synthesize a `string` `enum` for the discriminator. The merged
/// schema advertises only the discriminator as `required`, since per-variant
/// constraints conflict when flattened. Runtime `serde` deserialization still
/// enforces the full per-variant contract, so no actual validation is lost —
/// only the LLM loses a visibility aid.
///
/// Documentation is **not** lost in the process:
/// - each variant's `description` (its `///` doc comment) is composed into the
///   synthesized discriminator's description, as
///   ``` `add`: <doc> · `remove`: <doc> ``` (a variant with no doc contributes
///   just its value);
/// - every non-discriminator property gets the variants that require it appended
///   to its description (`Required when action=add, remove.`) — the only place
///   the per-variant `required` can survive the flattening;
/// - when the same property name appears in several variants, the first
///   occurrence is kept, but a description from a later variant fills in for a
///   missing one.
///
/// For combinators without a discriminator, we fall back to a plain property
/// union with no `required` fields.
fn flatten_top_level_combinator(schema: &mut serde_json::Map<String, Value>) {
    let combinator_key = ["oneOf", "anyOf", "allOf"]
        .iter()
        .copied()
        .find(|k| schema.contains_key(*k));
    let Some(combinator_key) = combinator_key else {
        return;
    };

    let Some(Value::Array(variants)) = schema.remove(combinator_key) else {
        return;
    };

    let mut merged_props = serde_json::Map::new();
    let mut tag_key: Option<String> = None;
    // `(discriminant value, variant description)`, in variant order.
    let mut tag_entries: Vec<(Value, Option<Value>)> = Vec::new();
    // A description carried by the discriminator property itself (rather than by
    // the variant); used as a fallback when no variant is documented.
    let mut tag_prop_description: Option<String> = None;
    // Non-discriminator property → discriminant values of the variants that
    // list it in `required`, in variant order.
    let mut required_by: std::collections::BTreeMap<String, Vec<String>> = Default::default();

    for variant in &variants {
        let Some(v_obj) = variant.as_object() else {
            continue;
        };
        let Some(Value::Object(v_props)) = v_obj.get("properties") else {
            continue;
        };

        // First pass: identify this variant's discriminant value, so the second
        // pass can attribute per-variant `required` to it regardless of the
        // order properties happen to be iterated in.
        let mut variant_tag: Option<Value> = None;
        for (prop_name, prop_schema) in v_props {
            // A property with a `const` value is the tagged-enum discriminator.
            let Some(const_val) = prop_schema.get("const") else {
                continue;
            };
            if tag_key.is_none() {
                tag_key = Some(prop_name.clone());
            }
            if tag_key.as_deref() != Some(prop_name.as_str()) {
                continue;
            }
            variant_tag = Some(const_val.clone());
            if tag_prop_description.is_none()
                && let Some(Value::String(d)) = prop_schema.get("description")
            {
                tag_prop_description = Some(d.clone());
            }
            if !tag_entries.iter().any(|(v, _)| v == const_val) {
                tag_entries.push((const_val.clone(), v_obj.get("description").cloned()));
            }
        }

        let variant_required: Vec<&str> = v_obj
            .get("required")
            .and_then(Value::as_array)
            .map(|r| r.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();

        // Second pass: merge the non-discriminator properties.
        for (prop_name, prop_schema) in v_props {
            if prop_schema.get("const").is_some() {
                continue;
            }

            match merged_props.entry(prop_name.clone()) {
                serde_json::map::Entry::Vacant(slot) => {
                    slot.insert(prop_schema.clone());
                }
                // Homonymous property across variants: first wins, but never at
                // the cost of a description the retained entry does not have.
                serde_json::map::Entry::Occupied(mut slot) => {
                    let kept_has_description = slot
                        .get()
                        .get("description")
                        .and_then(Value::as_str)
                        .is_some_and(|d| !d.is_empty());
                    if !kept_has_description
                        && let Some(new_description) = prop_schema.get("description")
                        && let Some(kept) = slot.get_mut().as_object_mut()
                    {
                        kept.insert("description".to_string(), new_description.clone());
                    }
                }
            }

            if let Some(tag) = variant_tag.as_ref()
                && variant_required.contains(&prop_name.as_str())
            {
                let label = value_label(tag);
                let entry = required_by.entry(prop_name.clone()).or_default();
                if !entry.contains(&label) {
                    entry.push(label);
                }
            }
        }
    }

    let mut required: Vec<Value> = Vec::new();
    if let Some(ref tk) = tag_key {
        let mut discriminant = serde_json::json!({
            "type": "string",
            "enum": tag_entries.iter().map(|(v, _)| v.clone()).collect::<Vec<_>>(),
        });
        if let Some(description) = compose_discriminant_description(&tag_entries)
            .or(tag_prop_description)
            && let Some(obj) = discriminant.as_object_mut()
        {
            obj.insert("description".to_string(), Value::String(description));
        }
        merged_props.insert(tk.clone(), discriminant);
        required.push(Value::String(tk.clone()));

        // Re-attach the per-variant `required` as prose on each property, since
        // the flattened schema can only advertise the discriminator as required.
        for (prop_name, tags) in &required_by {
            let Some(Value::Object(prop)) = merged_props.get_mut(prop_name) else {
                continue;
            };
            let suffix = format!("Required when {tk}={}.", tags.join(", "));
            let merged = match prop.get("description").and_then(Value::as_str) {
                Some(existing) if !existing.is_empty() => {
                    format!("{} {suffix}", existing.trim_end())
                }
                _ => suffix,
            };
            prop.insert("description".to_string(), Value::String(merged));
        }
    }

    schema.insert("type".to_string(), Value::String("object".to_string()));
    schema.insert("properties".to_string(), Value::Object(merged_props));
    if required.is_empty() {
        schema.remove("required");
    } else {
        schema.insert("required".to_string(), Value::Array(required));
    }
}

/// Render a discriminant value for prose: strings unquoted, anything else as JSON.
fn value_label(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Compose the variant docs into a single description for the synthesized
/// discriminator: ``` `add`: Add a note · `remove`: Remove a note ```.
///
/// Returns `None` when no variant is documented — the enum values alone would
/// only restate the `enum` keyword.
fn compose_discriminant_description(entries: &[(Value, Option<Value>)]) -> Option<String> {
    let documented = entries.iter().any(|(_, d)| {
        d.as_ref()
            .and_then(Value::as_str)
            .is_some_and(|s| !s.trim().is_empty())
    });
    if !documented {
        return None;
    }

    let parts: Vec<String> = entries
        .iter()
        .map(|(value, description)| {
            let label = format!("`{}`", value_label(value));
            match description.as_ref().and_then(Value::as_str) {
                Some(d) if !d.trim().is_empty() => format!("{label}: {}", d.trim()),
                _ => label,
            }
        })
        .collect();

    Some(parts.join(" · "))
}

/// Sanitize tool schemas for MCP client compatibility.
///
/// 1. Strips `$schema` and `title` keys that schemars 1.x injects — many MCP
///    clients (including Claude) don't expect meta-schema references in
///    `inputSchema` / `outputSchema` and may reject the tool or fail during
///    execution.
/// 2. Inlines `$defs` by resolving `$ref` pointers recursively.
/// 3. Flattens any top-level `oneOf` / `anyOf` / `allOf` into a single object
///    schema (the Anthropic API rejects these combinators at the root of
///    `input_schema`).
/// 4. Ensures every input schema contains `"type": "object"` — some parameter
///    types (e.g. `serde_json::Value`) produce schemas without a `"type"` key,
///    which causes clients to silently reject the tool.
pub(crate) fn sanitize_tool_schemas(tools: &mut [Tool]) {
    for tool in tools.iter_mut() {
        // ── input_schema ───────────────────────────────────────────
        let schema = Arc::make_mut(&mut tool.input_schema);
        strip_meta_fields(schema);
        inline_defs(schema);
        flatten_top_level_combinator(schema);

        if !schema.contains_key("type") {
            tracing::warn!(
                tool = %tool.name,
                "Tool input_schema is missing \"type\": \"object\" — patching at runtime. \
                 Consider using mcp_framework::EmptyParams instead of serde_json::Value \
                 for tools with no parameters."
            );
            schema.insert("type".to_string(), Value::String("object".to_string()));
            if !schema.contains_key("properties") {
                schema.insert("properties".to_string(), Value::Object(Default::default()));
            }
        }

        // ── output_schema ──────────────────────────────────────────
        if let Some(ref mut output_schema) = tool.output_schema {
            let os = Arc::make_mut(output_schema);
            strip_meta_fields(os);
            inline_defs(os);
            flatten_top_level_combinator(os);
        }
    }
}

#[cfg(test)]
#[path = "sanitize_tests.rs"]
mod tests;

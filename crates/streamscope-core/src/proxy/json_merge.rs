//! Force-merge a preset's native settings fragment onto an already-translated
//! upstream request body.
//!
//! A model preset (`model_presets.settings`) is a partial request body authored
//! in the bound model's own protocol vocabulary. The proxy applies it *after*
//! protocol translation — when `body_bytes` is already in the upstream's
//! protocol — so the merge is a protocol-agnostic JSON deep-merge: objects
//! recurse (so nested groups like Gemini `generationConfig.*` or Anthropic
//! `thinking` compose key-by-key), scalars and arrays are overwritten. The
//! preset wins on every key it sets (**force**); a key it omits passes through
//! untouched (**allow**).
//!
//! Each changed leaf is recorded as an [`InjectionBlock`] so the audit trail
//! surfaces exactly what the preset replaced — nothing is silently changed.

use serde_json::{Map, Value};

use super::content::InjectionBlock;

/// Deep-merge `overlay` onto `base` in place (overlay wins), returning one
/// [`InjectionBlock`] per changed leaf key (dotted path). A no-op overlay
/// (empty object, or every key already equal) returns an empty vec.
pub fn json_force_merge(base: &mut Value, overlay: &Value) -> Vec<InjectionBlock> {
    let mut blocks = Vec::new();
    if let (Value::Object(base_obj), Value::Object(overlay_obj)) = (&mut *base, overlay) {
        merge_object(base_obj, overlay_obj, "", &mut blocks);
    }
    blocks
}

/// The per-protocol keys under which a preset authors the response output-token
/// cap: chat (`max_tokens`), chat-with-reasoning (`max_completion_tokens`),
/// Responses (`max_output_tokens`), Gemini (`maxOutputTokens`). Kept in sync with
/// the admin-side preset validator.
const PRESET_MAX_OUTPUT_KEYS: &[&str] =
    &["max_tokens", "max_completion_tokens", "max_output_tokens", "maxOutputTokens"];

/// The effective output-token cap a preset sets, in whichever native protocol
/// vocabulary it was authored — top level, or nested in the Gemini
/// `generationConfig` group. Returns the first positive value found (a preset
/// carries at most one, enforced at save time), else `None` for a passthrough
/// preset that sets no cap.
///
/// Because the proxy force-merges the preset onto every request, this is the
/// real per-call output ceiling for the alias → it is what client configs and
/// `GET /v1/models` should advertise, in preference to the raw model/catalog
/// `max_output_tokens` (which is the model's absolute ceiling, not the alias's
/// effective default).
pub fn preset_max_output_tokens(settings: &Value) -> Option<i64> {
    fn scan(obj: &Map<String, Value>) -> Option<i64> {
        PRESET_MAX_OUTPUT_KEYS
            .iter()
            .find_map(|k| obj.get(*k).and_then(Value::as_i64).filter(|&n| n > 0))
    }
    let obj = settings.as_object()?;
    scan(obj).or_else(|| obj.get("generationConfig").and_then(Value::as_object).and_then(scan))
}

fn merge_object(
    base: &mut Map<String, Value>,
    overlay: &Map<String, Value>,
    prefix: &str,
    blocks: &mut Vec<InjectionBlock>,
) {
    for (key, ov) in overlay {
        let path = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };

        if let Some(bv) = base.get_mut(key) {
            // Both objects → recurse so nested groups compose key-by-key.
            if let (Value::Object(bo), Value::Object(oo)) = (&mut *bv, ov) {
                merge_object(bo, oo, &path, blocks);
                continue;
            }
            // Scalar / array / type mismatch → overwrite (force).
            if bv != ov {
                blocks.push(block(&path, summarize(bv), summarize(ov), "replace"));
                *bv = ov.clone();
            }
        } else {
            blocks.push(block(&path, "(unset)".to_string(), summarize(ov), "create"));
            base.insert(key.clone(), ov.clone());
        }
    }
}

fn block(field: &str, from: String, to: String, action: &str) -> InjectionBlock {
    InjectionBlock {
        transform: "preset".to_string(),
        scope: "params".to_string(),
        field: field.to_string(),
        action: action.to_string(),
        content: format!("{from} → {to}"),
    }
}

/// Compact, length-bounded rendering of a JSON value for the audit block.
fn summarize(v: &Value) -> String {
    let s = match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    if s.len() > 120 {
        let cut = s.floor_char_boundary(120);
        format!("{}…", &s[..cut])
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn overwrites_scalar_force() {
        let mut base = json!({"temperature": 0.9, "model": "m"});
        let blocks = json_force_merge(&mut base, &json!({"temperature": 0.0}));
        assert_eq!(base["temperature"], json!(0.0));
        assert_eq!(base["model"], json!("m")); // untouched key passes through
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].field, "temperature");
        assert_eq!(blocks[0].action, "replace");
    }

    #[test]
    fn nested_objects_compose_key_by_key() {
        // Gemini-shaped: generationConfig already has temperature; preset adds topK
        // and overrides temperature, leaving maxOutputTokens intact.
        let mut base = json!({
            "generationConfig": {"temperature": 0.9, "maxOutputTokens": 1024}
        });
        let blocks = json_force_merge(
            &mut base,
            &json!({"generationConfig": {"temperature": 0.0, "topK": 5}}),
        );
        assert_eq!(base["generationConfig"]["temperature"], json!(0.0));
        assert_eq!(base["generationConfig"]["maxOutputTokens"], json!(1024));
        assert_eq!(base["generationConfig"]["topK"], json!(5));
        // one replace (temperature) + one create (topK), both dotted-pathed.
        assert_eq!(blocks.len(), 2);
        assert!(blocks.iter().any(|b| b.field == "generationConfig.temperature" && b.action == "replace"));
        assert!(blocks.iter().any(|b| b.field == "generationConfig.topK" && b.action == "create"));
    }

    #[test]
    fn creates_absent_nested_group() {
        // Anthropic-shaped: base has no `thinking`; preset adds the whole object.
        let mut base = json!({"max_tokens": 100});
        let blocks = json_force_merge(
            &mut base,
            &json!({"thinking": {"type": "enabled", "budget_tokens": 2048}}),
        );
        assert_eq!(base["thinking"]["type"], json!("enabled"));
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].field, "thinking");
        assert_eq!(blocks[0].action, "create");
    }

    #[test]
    fn array_is_overwritten_not_merged() {
        let mut base = json!({"stop": ["a", "b"]});
        let blocks = json_force_merge(&mut base, &json!({"stop": ["x"]}));
        assert_eq!(base["stop"], json!(["x"]));
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].action, "replace");
    }

    #[test]
    fn type_mismatch_object_replaces_scalar() {
        let mut base = json!({"thinking": false});
        let blocks = json_force_merge(&mut base, &json!({"thinking": {"type": "enabled"}}));
        assert_eq!(base["thinking"], json!({"type": "enabled"}));
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].action, "replace");
    }

    #[test]
    fn equal_value_is_noop() {
        let mut base = json!({"temperature": 0.0});
        let blocks = json_force_merge(&mut base, &json!({"temperature": 0.0}));
        assert!(blocks.is_empty());
    }

    #[test]
    fn empty_overlay_is_noop() {
        let mut base = json!({"temperature": 0.9});
        let blocks = json_force_merge(&mut base, &json!({}));
        assert!(blocks.is_empty());
        assert_eq!(base["temperature"], json!(0.9));
    }

    #[test]
    fn preset_max_output_reads_every_protocol_vocab() {
        // Chat / Anthropic.
        assert_eq!(preset_max_output_tokens(&json!({"max_tokens": 65536})), Some(65536));
        // Chat with reasoning.
        assert_eq!(preset_max_output_tokens(&json!({"max_completion_tokens": 32000})), Some(32000));
        // OpenAI Responses.
        assert_eq!(preset_max_output_tokens(&json!({"max_output_tokens": 4096})), Some(4096));
        // Gemini nests it under generationConfig.
        assert_eq!(
            preset_max_output_tokens(&json!({"generationConfig": {"maxOutputTokens": 8000}})),
            Some(8000)
        );
    }

    #[test]
    fn preset_max_output_none_for_passthrough_or_nonpositive() {
        assert_eq!(preset_max_output_tokens(&json!({})), None);
        assert_eq!(preset_max_output_tokens(&json!({"temperature": 0.5})), None);
        assert_eq!(preset_max_output_tokens(&json!({"max_tokens": 0})), None);
        assert_eq!(preset_max_output_tokens(&Value::Null), None);
    }
}

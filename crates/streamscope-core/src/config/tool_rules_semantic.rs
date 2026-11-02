//! Semantic checks applied to agent-proposed tool rules on top of the
//! structural validator in [`crate::config::tool_rules::validate`].
//!
//! `validate()` ensures the rule's shape conforms to the matrix (phase ×
//! scope × action, valid targets, op compatibility). This module rejects
//! the failure modes structural validation alone misses on weak-model
//! output: literal placeholders the model forgot to substitute, IDs that
//! collide with built-ins, garbage values on canonical-id targets, and
//! filter strings that use comma separators instead of pipes.

use std::collections::HashSet;

use crate::config::tool_rules::{Op, Rule};

/// Literal-token rejects on values — bare placeholder labels the model
/// emitted instead of a real string.
const PLACEHOLDER_TOKENS: &[&str] = &["TODO", "FIXME", "XXX"];

/// Reserved id prefixes the built-in seed set uses. Proposals using these
/// would visually pose as canonical rules; reject them.
const RESERVED_PREFIXES: &[&str] = &["SAFE-", "INT-"];

/// Reserved id exact-match rejects.
const RESERVED_EXACT: &[&str] = &["UNK"];

/// Regex matching `<placeholder>` style literals (any wrapper text).
fn looks_like_placeholder(s: &str) -> bool {
    let trimmed = s.trim();
    if PLACEHOLDER_TOKENS.contains(&trimmed) {
        return true;
    }
    trimmed.starts_with('<') && trimmed.ends_with('>') && trimmed.len() >= 3
}

/// Returns `Ok(())` if the proposal passes all semantic checks; otherwise
/// `Err(reason)` with a short operator-facing explanation.
pub fn semantic_check(rule: &Rule, builtin_ids: &HashSet<String>) -> Result<(), String> {
    let trimmed = rule.id.trim();
    if trimmed.is_empty() {
        return Err("rule id is empty".into());
    }
    if RESERVED_EXACT.contains(&trimmed) {
        return Err(format!("rule id `{trimmed}` is reserved for built-ins"));
    }
    for prefix in RESERVED_PREFIXES {
        if trimmed.starts_with(prefix) {
            return Err(format!(
                "rule id `{trimmed}` uses reserved prefix `{prefix}` — pick a CUSTOM-* id instead"
            ));
        }
    }
    if builtin_ids.contains(trimmed) {
        return Err(format!(
            "rule id `{trimmed}` collides with an existing built-in rule"
        ));
    }

    for cond in &rule.conditions {
        let target = cond.target.as_str();

        if let Some(suffix) = target.strip_prefix("arg.")
            && (looks_like_placeholder(suffix) || suffix.is_empty())
        {
            return Err(format!(
                "match target `{target}` is a literal placeholder — substitute the canonical arg name"
            ));
        }

        let canonical_id_target =
            matches!(target, "tool_id" | "resource_id" | "prompt_id");

        match cond.op {
            // `Detector` values are checked against the detector registry by
            // `tool_rules::validate`; a detector name is never a placeholder
            // and never a canonical id, so there is nothing further to read.
            Op::Detector => {}
            Op::Glob | Op::Regex | Op::Equals => {
                if let Some(s) = cond.value.as_str() {
                    if looks_like_placeholder(s) {
                        return Err(format!(
                            "match value `{s}` on target `{target}` is a literal placeholder"
                        ));
                    }
                    if canonical_id_target {
                        check_canonical_id_value(target, s)?;
                    }
                }
            }
            Op::ContainsAny | Op::ContainsWordAny | Op::In => {
                if let Some(arr) = cond.value.as_array() {
                    for v in arr {
                        if let Some(s) = v.as_str() {
                            if looks_like_placeholder(s) {
                                return Err(format!(
                                    "match value `{s}` on target `{target}` is a literal placeholder"
                                ));
                            }
                            if canonical_id_target {
                                check_canonical_id_value(target, s)?;
                            }
                        }
                    }
                }
            }
        }
    }

    check_filter_separator("model_filter", rule.model_filter.as_deref())?;
    check_filter_separator("app_filter", rule.app_filter.as_deref())?;
    check_filter_separator("mcp_server_filter", rule.mcp_server_filter.as_deref())?;
    check_filter_separator("a2a_agent_filter", rule.a2a_agent_filter.as_deref())?;

    Ok(())
}

fn check_canonical_id_value(target: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("match value on target `{target}` is empty"));
    }
    for ch in value.chars() {
        let ok = ch.is_ascii_alphanumeric()
            || matches!(ch, '_' | '-' | '.' | '/' | '*' | ':');
        if !ok {
            return Err(format!(
                "match value `{value}` on canonical-id target `{target}` contains illegal character `{ch}` — expected [a-z0-9_./*:-]"
            ));
        }
    }
    Ok(())
}

fn check_filter_separator(name: &str, value: Option<&str>) -> Result<(), String> {
    let Some(s) = value else { return Ok(()) };
    if s.contains(',') && !s.contains('|') {
        return Err(format!(
            "{name} `{s}` uses comma separators; the schema is pipe-separated (e.g. `gpt-4o|claude-opus`)"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tool_rules::{MatchCondition, Phase, Rule, RuleAction, Scope};
    use serde_json::json;

    fn base_rule() -> Rule {
        Rule {
            id: "CUSTOM-TEST".into(),
            title: Some("test".into()),
            description: None,
            risk: "caution".into(),
            phase: Phase::Response,
            scope: Scope::ToolCalls,
            conditions: vec![MatchCondition {
                target: "tool_id".into(),
                op: Op::Equals,
                value: json!("Bash"),
            }],
            action: RuleAction::Classify,
            priority: 100,
            model_filter: None,
            app_filter: None,
            mcp_server_filter: None,
            a2a_agent_filter: None,
            enabled: true,
            framework_refs: vec![],
            is_builtin: false,
            profile_id: None,
            forked_from: None,
        }
    }

    fn empty_builtins() -> HashSet<String> {
        HashSet::new()
    }

    #[test]
    fn accepts_clean_rule() {
        assert!(semantic_check(&base_rule(), &empty_builtins()).is_ok());
    }

    #[test]
    fn rejects_placeholder_arg_target() {
        let mut r = base_rule();
        r.conditions = vec![MatchCondition {
            target: "arg.<field>".into(),
            op: Op::ContainsAny,
            value: json!(["secret"]),
        }];
        r.scope = Scope::ToolCalls;
        let err = semantic_check(&r, &empty_builtins()).unwrap_err();
        assert!(err.contains("placeholder"), "got: {err}");
    }

    #[test]
    fn rejects_empty_arg_target() {
        let mut r = base_rule();
        r.conditions = vec![MatchCondition {
            target: "arg.".into(),
            op: Op::ContainsAny,
            value: json!(["secret"]),
        }];
        let err = semantic_check(&r, &empty_builtins()).unwrap_err();
        assert!(err.contains("placeholder"), "got: {err}");
    }

    #[test]
    fn rejects_reserved_safe_prefix() {
        let mut r = base_rule();
        r.id = "SAFE-03-02".into();
        let err = semantic_check(&r, &empty_builtins()).unwrap_err();
        assert!(err.contains("reserved prefix"), "got: {err}");
    }

    #[test]
    fn rejects_reserved_int_prefix() {
        let mut r = base_rule();
        r.id = "INT-99".into();
        let err = semantic_check(&r, &empty_builtins()).unwrap_err();
        assert!(err.contains("reserved prefix"), "got: {err}");
    }

    #[test]
    fn rejects_reserved_unk_exact() {
        let mut r = base_rule();
        r.id = "UNK".into();
        let err = semantic_check(&r, &empty_builtins()).unwrap_err();
        assert!(err.contains("reserved"), "got: {err}");
    }

    #[test]
    fn rejects_builtin_collision() {
        let mut r = base_rule();
        r.id = "ASI02-06".into();
        let mut builtins = HashSet::new();
        builtins.insert("ASI02-06".into());
        let err = semantic_check(&r, &builtins).unwrap_err();
        assert!(err.contains("collides"), "got: {err}");
    }

    #[test]
    fn allows_custom_prefix() {
        let mut r = base_rule();
        r.id = "CUSTOM-SLACK".into();
        assert!(semantic_check(&r, &empty_builtins()).is_ok());
    }

    #[test]
    fn rejects_placeholder_in_value() {
        let mut r = base_rule();
        r.conditions = vec![MatchCondition {
            target: "tool_id".into(),
            op: Op::Equals,
            value: json!("<tool>"),
        }];
        let err = semantic_check(&r, &empty_builtins()).unwrap_err();
        assert!(err.contains("placeholder"), "got: {err}");
    }

    #[test]
    fn rejects_garbage_on_canonical_id() {
        let mut r = base_rule();
        r.conditions = vec![MatchCondition {
            target: "tool_id".into(),
            op: Op::Equals,
            value: json!("Notion ticket title"),
        }];
        let err = semantic_check(&r, &empty_builtins()).unwrap_err();
        assert!(err.contains("illegal character"), "got: {err}");
    }

    #[test]
    fn allows_glob_wildcards_on_canonical_id() {
        let mut r = base_rule();
        r.conditions = vec![MatchCondition {
            target: "tool_id".into(),
            op: Op::Equals,
            value: json!("read_file"),
        }];
        assert!(semantic_check(&r, &empty_builtins()).is_ok());
    }

    #[test]
    fn rejects_comma_in_model_filter() {
        let mut r = base_rule();
        r.model_filter = Some("gpt-4o,claude-opus".into());
        let err = semantic_check(&r, &empty_builtins()).unwrap_err();
        assert!(err.contains("comma"), "got: {err}");
    }

    #[test]
    fn accepts_pipe_in_model_filter() {
        let mut r = base_rule();
        r.model_filter = Some("gpt-4o|claude-opus".into());
        assert!(semantic_check(&r, &empty_builtins()).is_ok());
    }

    #[test]
    fn rejects_todo_value() {
        let mut r = base_rule();
        r.conditions = vec![MatchCondition {
            target: "args".into(),
            op: Op::ContainsAny,
            value: json!(["TODO"]),
        }];
        let err = semantic_check(&r, &empty_builtins()).unwrap_err();
        assert!(err.contains("placeholder"), "got: {err}");
    }
}

//! Expert axis definitions.
//!
//! Expert prompts and metadata are loaded from disk via `SeedLoader`.
//! This module provides prompt assembly utilities and the UI color palette.

use std::str::FromStr;

/// What an expert receives in its analysis context.
///
/// Most variants are snippet-backed: a corresponding file in `seeds/snippets/`
/// is appended to the system prompt. `SecurityFrameworks` is **runtime-injected**
/// — its data flows through `inject_security_frameworks` reading
/// `seeds/tool-policy/frameworks.json`, so it has no snippet file.
///
/// Adding a new variant is a compile-time exhaustive change: every match arm
/// in the codebase must be updated, and unknown values in seed files become
/// load-time parse errors (see `FromStr` impl).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExpertInput {
    Session,
    SessionCluster,
    ToolInventory,
    Memory,
    SecurityFrameworks,
}

impl ExpertInput {
    /// Stable string tag used in seed files and DB storage. Kept public for
    /// round-trip with `FromStr` and for future call sites that want typed
    /// dispatch over the `Vec<String>` storage.
    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::SessionCluster => "session_cluster",
            Self::ToolInventory => "tool_inventory",
            Self::Memory => "memory",
            Self::SecurityFrameworks => "security_frameworks",
        }
    }

    /// Snippet file (under `seeds/snippets/`) loaded for this input. `None`
    /// means runtime-injected — the framework supplies the data, no snippet.
    pub fn snippet_key(self) -> Option<&'static str> {
        match self {
            Self::Session => Some("session"),
            Self::SessionCluster => Some("session_cluster"),
            Self::ToolInventory => Some("tool_inventory"),
            Self::Memory => Some("memory"),
            Self::SecurityFrameworks => None,
        }
    }
}

impl FromStr for ExpertInput {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "session" => Ok(Self::Session),
            "session_cluster" => Ok(Self::SessionCluster),
            "tool_inventory" => Ok(Self::ToolInventory),
            "memory" => Ok(Self::Memory),
            "security_frameworks" => Ok(Self::SecurityFrameworks),
            other => Err(format!("unknown expert input type: {other}")),
        }
    }
}

/// What an expert can propose. Every variant is snippet-backed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExpertOutput {
    TransformSuggestion,
    ToolRules,
    FieldProfileSuggestion,
    Alert,
    Memory,
    SessionLabel,
}

impl ExpertOutput {
    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TransformSuggestion => "transform_suggestion",
            Self::ToolRules => "tool_rules",
            Self::FieldProfileSuggestion => "field_profile_suggestion",
            Self::Alert => "alert",
            Self::Memory => "memory",
            Self::SessionLabel => "session_label",
        }
    }

    pub fn snippet_key(self) -> Option<&'static str> {
        Some(match self {
            Self::TransformSuggestion => "transform_suggestion",
            Self::ToolRules => "tool_rules",
            Self::FieldProfileSuggestion => "field_profile_suggestion",
            Self::Alert => "alert",
            Self::Memory => "memory",
            Self::SessionLabel => "session_label",
        })
    }
}

impl FromStr for ExpertOutput {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "transform_suggestion" => Ok(Self::TransformSuggestion),
            "tool_rules" => Ok(Self::ToolRules),
            "field_profile_suggestion" => Ok(Self::FieldProfileSuggestion),
            "alert" => Ok(Self::Alert),
            "memory" => Ok(Self::Memory),
            "session_label" => Ok(Self::SessionLabel),
            other => Err(format!("unknown expert output type: {other}")),
        }
    }
}

/// An expert axis — a name, a system prompt, and configuration.
#[derive(Debug, Clone)]
#[allow(dead_code)] // fields are set during construction, read via DB in routes
pub struct Expert {
    /// Machine-readable identifier (e.g. "security", "tool_policy").
    pub axis: String,
    /// Short human-readable description for UI display.
    pub description: Option<String>,
    /// Full system prompt with capability references appended.
    pub prompt: String,
    /// Raw prompt without references (stored in DB).
    pub raw_prompt: String,
    /// What data the expert receives: "session", "session_cluster", "tool_inventory".
    pub input_types: Vec<String>,
    /// What the expert can propose: "transform_suggestion", "session_label", "tool_rules", "alert", "memory".
    pub output_types: Vec<String>,
    /// Optional model override (alias or upstream_model name). NULL = use the expert profile's model.
    pub model_override: Option<String>,
    /// Optional UI color (hex string).
    pub color: Option<String>,
    /// Ordered snippet keys for prompt assembly.
    pub snippet_keys: Vec<String>,
}

/// Colors assigned to experts in the UI.
pub const EXPERT_COLORS: &[&str] = &[
    "#6366f1", "#ec4899", "#14b8a6", "#f97316", "#8b5cf6", "#06b6d4",
    "#f43f5e", "#10b981", "#eab308", "#3b82f6", "#a855f7", "#ef4444",
];

/// Assemble the full prompt from raw_prompt + ordered snippet keys.
/// Missing keys are skipped with a warning.
pub fn assemble_prompt(
    raw_prompt: &str,
    snippet_keys: &[String],
    snippets: &std::collections::HashMap<String, String>,
) -> String {
    let mut prompt = raw_prompt.to_string();
    for key in snippet_keys {
        if let Some(content) = snippets.get(key.as_str()) {
            prompt.push_str(content);
        } else {
            tracing::warn!(key = %key, "prompt snippet not found, skipping");
        }
    }
    prompt
}

/// Snippet key of the panel preamble prepended to every merged (multi-axis)
/// prompt. Seeded from `seeds/snippets/panel.md`; never part of a solo
/// expert's snippet set.
pub const PANEL_SNIPPET_KEY: &str = "panel";

/// Assemble the merged system prompt for a pooled analysis call.
///
/// Layout: panel preamble (the mandatory-answer + attribution contract from
/// the `panel` snippet) → the axis roster (one line per member from its
/// description) → one `# Axis:` section per member (raw prompt, no snippets)
/// → the union of the members' snippet keys, deduplicated in first-occurrence
/// order so shared references (session format, alert levels, output shapes)
/// render exactly once.
pub fn assemble_group_prompt(
    members: &[&Expert],
    snippets: &std::collections::HashMap<String, String>,
) -> String {
    let mut prompt = String::new();

    if let Some(panel) = snippets.get(PANEL_SNIPPET_KEY) {
        prompt.push_str(panel);
    } else {
        tracing::warn!("panel snippet not found — merged prompt runs without the panel contract");
    }

    prompt.push_str("\n\n## Panel Axes\n\n");
    for m in members {
        let desc = m.description.as_deref().unwrap_or("");
        prompt.push_str(&format!("- `{}` — {}\n", m.axis, desc));
    }

    for m in members {
        prompt.push_str(&format!("\n\n# Axis: {}\n\n", m.axis));
        prompt.push_str(m.raw_prompt.trim());
        prompt.push('\n');
    }

    // Union of member snippet keys, first-occurrence order, rendered once.
    let mut seen: Vec<&str> = Vec::new();
    for m in members {
        for key in &m.snippet_keys {
            if !seen.contains(&key.as_str()) {
                seen.push(key);
            }
        }
    }
    for key in seen {
        if let Some(content) = snippets.get(key) {
            prompt.push_str(content);
        } else {
            tracing::warn!(key = %key, "prompt snippet not found, skipping");
        }
    }

    prompt
}

/// One-line confinement preamble for a solo (unmerged) expert call. The seed
/// bodies carry no cross-expert deference text, so the lane boundary for a
/// solo run is restated here instead.
pub fn solo_preamble(axis: &str) -> String {
    format!(
        "You are the `{axis}` analysis expert. Confine your entire answer to this axis; \
         ignore concerns that belong to other analysis dimensions. Deliver the analysis \
         by calling `submit_analysis` once — a text-only reply is discarded.\n\n"
    )
}

/// Compute the default snippet keys from input/output types.
///
/// Each input_type / output_type is parsed into the typed enum and only the
/// variants that have a snippet file contribute a key. Runtime-injected
/// inputs (e.g. `security_frameworks`) return `None` from `snippet_key()`
/// and are silently skipped — they receive their data via a runtime injector,
/// not a snippet file.
///
/// Unknown values are parse errors at seed-load time (see seed_loader); by
/// the time this function runs, the inputs have already been validated.
/// Any unknown string here is logged and skipped to keep the agent running.
pub fn default_snippet_keys(input_types: &[String], output_types: &[String]) -> Vec<String> {
    let mut keys: Vec<String> = Vec::new();

    for raw in input_types {
        match raw.parse::<ExpertInput>() {
            Ok(input) => {
                if let Some(key) = input.snippet_key() {
                    let key_str = key.to_string();
                    if !keys.contains(&key_str) {
                        keys.push(key_str);
                    }
                }
            }
            Err(e) => tracing::warn!(value = %raw, "skipping unknown expert input: {e}"),
        }
    }

    for raw in output_types {
        match raw.parse::<ExpertOutput>() {
            Ok(output) => {
                if let Some(key) = output.snippet_key() {
                    let key_str = key.to_string();
                    if !keys.contains(&key_str) {
                        keys.push(key_str);
                    }
                }
            }
            Err(e) => tracing::warn!(value = %raw, "skipping unknown expert output: {e}"),
        }
    }

    keys
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn assemble_prompt_appends_matching_keys_in_order() {
        let mut snippets = HashMap::new();
        snippets.insert("a".to_string(), " [A]".to_string());
        snippets.insert("b".to_string(), " [B]".to_string());

        let keys = vec!["a".to_string(), "b".to_string()];
        let result = assemble_prompt("raw", &keys, &snippets);
        assert_eq!(result, "raw [A] [B]");
    }

    #[test]
    fn assemble_prompt_skips_missing_keys() {
        let mut snippets = HashMap::new();
        snippets.insert("a".to_string(), " [A]".to_string());

        let keys = vec!["a".to_string(), "missing".to_string()];
        let result = assemble_prompt("raw", &keys, &snippets);
        assert_eq!(result, "raw [A]");
    }

    #[test]
    fn assemble_prompt_empty_keys_returns_raw() {
        let snippets = HashMap::new();
        let result = assemble_prompt("raw", &[], &snippets);
        assert_eq!(result, "raw");
    }

    #[test]
    fn default_snippet_keys_deduplicates_memory() {
        let input = vec!["session".to_string(), "memory".to_string()];
        let output = vec!["transform_suggestion".to_string(), "alert".to_string(), "memory".to_string()];
        let keys = default_snippet_keys(&input, &output);
        // memory appears in both input and output but should only be listed once
        assert_eq!(
            keys,
            vec!["session", "memory", "transform_suggestion", "alert"]
        );
    }

    #[test]
    fn default_snippet_keys_cluster_expert() {
        let input = vec!["session_cluster".to_string(), "memory".to_string()];
        let output = vec!["session_label".to_string(), "alert".to_string(), "memory".to_string()];
        let keys = default_snippet_keys(&input, &output);
        assert_eq!(
            keys,
            vec!["session_cluster", "memory", "session_label", "alert"]
        );
    }

    #[test]
    fn default_snippet_keys_skips_runtime_injected_inputs() {
        // security_frameworks is runtime-injected; no snippet file should be loaded.
        let input = vec![
            "session".to_string(),
            "tool_inventory".to_string(),
            "memory".to_string(),
            "security_frameworks".to_string(),
        ];
        let output = vec!["transform_suggestion".to_string(), "tool_rules".to_string()];
        let keys = default_snippet_keys(&input, &output);
        assert!(
            !keys.contains(&"security_frameworks".to_string()),
            "security_frameworks must not produce a snippet key, got: {keys:?}"
        );
        assert_eq!(
            keys,
            vec!["session", "tool_inventory", "memory", "transform_suggestion", "tool_rules"]
        );
    }

    #[test]
    fn default_snippet_keys_skips_unknown_strings() {
        // Unknown values warn and are skipped (parse errors are caught at seed load,
        // but be defensive here in case DB rows pre-date the typing rules).
        let input = vec!["session".to_string(), "totally_made_up".to_string()];
        let output = vec!["alert".to_string()];
        let keys = default_snippet_keys(&input, &output);
        assert_eq!(keys, vec!["session", "alert"]);
    }

    #[test]
    fn expert_input_round_trip_through_str() {
        for variant in [
            ExpertInput::Session,
            ExpertInput::SessionCluster,
            ExpertInput::ToolInventory,
            ExpertInput::Memory,
            ExpertInput::SecurityFrameworks,
        ] {
            assert_eq!(variant.as_str().parse::<ExpertInput>().unwrap(), variant);
        }
    }

    #[test]
    fn expert_output_round_trip_through_str() {
        for variant in [
            ExpertOutput::TransformSuggestion,
            ExpertOutput::ToolRules,
            ExpertOutput::FieldProfileSuggestion,
            ExpertOutput::Alert,
            ExpertOutput::Memory,
            ExpertOutput::SessionLabel,
        ] {
            assert_eq!(variant.as_str().parse::<ExpertOutput>().unwrap(), variant);
        }
    }

    #[test]
    fn security_frameworks_has_no_snippet_key() {
        assert_eq!(ExpertInput::SecurityFrameworks.snippet_key(), None);
    }

    #[test]
    fn unknown_input_parses_as_error() {
        assert!("not_a_real_input".parse::<ExpertInput>().is_err());
    }
}

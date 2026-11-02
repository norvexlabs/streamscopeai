//! Deterministic detection of subagent "spawn points" in a conversation.
//!
//! A spawn point is a tool call the model made to launch a child agent (Claude
//! Code `Task`/`Agent`, opencode `subagent`, …). This module is the single source of
//! truth for the spawn-tool vocabulary — the seed prose that teaches the judge
//! the same list is kept in sync by a test in `agent::seed_loader`. Detected
//! points are surfaced on the conversation read-model so the cluster judge can
//! CONFIRM a child↔spawn link and the UI can anchor the child card to the exact
//! call, instead of the model estimating a turn from raw text.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::ConversationEvent;

/// Tool names that launch a child agent. SINGLE SOURCE OF TRUTH — the seed
/// snippets (`seeds/snippets/session_label.md`, `seeds/snippets/session_cluster.md`)
/// repeat this list as prose for the judge; `agent::seed_loader` has a test that
/// fails if the prose and this constant drift.
pub const SPAWN_TOOL_NAMES: &[&str] = &[
    "Task",
    "Agent",
    "task",
    "new_task",
    "use_subagents",
    "runSubagent",
    "spawn_agent",
    "delegate_to_agent",
    "delegate_task",
    "dispatch",
    "dispatch_agent",
    "subagent",
];

/// Whether `name` is a subagent-spawning tool.
pub fn is_spawn_tool(name: &str) -> bool {
    SPAWN_TOOL_NAMES.contains(&name)
}

/// A subagent-spawning tool call detected in a parent conversation. The judge
/// references it by its position in the per-session list (`[P0]`, `[P1]`, …); the
/// UI anchors a child card to the composite `(turn_number, tool_call_id)` because
/// `tool_call_id` alone is only turn-unique (Gemini/legacy shapes synthesize a
/// per-turn `call_0`).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DetectedSpawnPoint {
    /// Parent turn the spawn call was made in.
    pub turn_number: i32,
    /// Tool-call id of the spawn call (turn-unique, not session-unique).
    pub tool_call_id: String,
    /// Spawn tool name (`Task`, `Agent`, …).
    pub tool_name: String,
    /// First ~200 chars of the child prompt/description the call carried, so the
    /// judge can match it to a child session's first user message.
    pub prompt_preview: String,
}

/// Scan already-built conversation events for spawn-tool calls. On-read and
/// cheap (a name lookup over tool calls already in hand). Empty-id events
/// (synthesized blocked calls) are skipped — they cannot be anchored to.
///
/// A baseline/context-reset turn re-emits the whole history, so the same spawn
/// call reappears at a later turn number; we keep only the FIRST occurrence,
/// keyed on `(tool_call_id, tool_name, prompt_preview)` — NOT `tool_call_id`
/// alone, so a legitimately turn-unique synthesized id (Gemini's per-turn
/// `call_0`) at two genuinely distinct calls is preserved.
pub fn detect_spawn_points(events: &[ConversationEvent]) -> Vec<DetectedSpawnPoint> {
    let mut seen: std::collections::HashSet<(String, String, String)> =
        std::collections::HashSet::new();
    events
        .iter()
        .filter_map(|e| match e {
            ConversationEvent::ToolCall {
                name,
                arguments,
                id,
                turn,
                ..
            } if is_spawn_tool(name) && !id.is_empty() => {
                let point = DetectedSpawnPoint {
                    turn_number: *turn,
                    tool_call_id: id.clone(),
                    tool_name: name.clone(),
                    prompt_preview: spawn_prompt_preview(arguments),
                };
                let key = (
                    point.tool_call_id.clone(),
                    point.tool_name.clone(),
                    point.prompt_preview.clone(),
                );
                seen.insert(key).then_some(point)
            }
            _ => None,
        })
        .collect()
}

/// Best-effort extraction of the child prompt from a spawn call's arguments:
/// prefer the common prompt-bearing keys, else compact JSON. Truncated on a
/// UTF-8 boundary to ~200 chars.
fn spawn_prompt_preview(arguments: &serde_json::Value) -> String {
    const MAX: usize = 200;
    let raw = ["prompt", "description", "task", "message", "input", "instructions"]
        .iter()
        .find_map(|k| arguments.get(*k).and_then(|v| v.as_str()))
        .map(str::to_string)
        .unwrap_or_else(|| {
            let s = arguments.to_string();
            if s == "{}" || s == "null" {
                String::new()
            } else {
                s
            }
        });
    // Collapse whitespace so a multi-line Task prompt can't splinter the one-line
    // `[P{j}]` judge-prompt entry (and to match the UI's client-side normalization).
    let collapsed = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.len() <= MAX {
        collapsed
    } else {
        collapsed[..collapsed.floor_char_boundary(MAX)].to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tool_call(name: &str, id: &str, turn: i32, args: serde_json::Value) -> ConversationEvent {
        ConversationEvent::ToolCall {
            name: name.to_string(),
            arguments: args,
            id: id.to_string(),
            turn,
            is_new: true,
            metadata: None,
            raw: None,
            risk_level: None,
            risk_description: None,
            blocked: None,
            intercepted: None,
            modifications: None,
        }
    }

    #[test]
    fn detects_spawn_tools_only() {
        let events = vec![
            tool_call("Read", "call_0", 1, json!({"path": "a"})),
            tool_call("Task", "toolu_1", 2, json!({"prompt": "research the auth bug"})),
            tool_call("grep", "call_2", 3, json!({})),
        ];
        let points = detect_spawn_points(&events);
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].tool_name, "Task");
        assert_eq!(points[0].turn_number, 2);
        assert_eq!(points[0].tool_call_id, "toolu_1");
        assert_eq!(points[0].prompt_preview, "research the auth bug");
    }

    #[test]
    fn skips_empty_id() {
        // A blocked spawn call synthesizes an empty id — it cannot be anchored to.
        let events = vec![tool_call("Agent", "", 1, json!({"description": "x"}))];
        assert!(detect_spawn_points(&events).is_empty());
    }

    #[test]
    fn turn_unique_ids_are_kept_distinct_by_turn() {
        // Gemini/legacy synthesize a per-turn `call_0`; two GENUINELY DISTINCT
        // spawn calls in different turns share the id but different prompts, so the
        // (id, name, preview) dedup key keeps both — distinguished by turn.
        let events = vec![
            tool_call("Task", "call_0", 3, json!({"prompt": "first"})),
            tool_call("Task", "call_0", 7, json!({"prompt": "second"})),
        ];
        let points = detect_spawn_points(&events);
        assert_eq!(points.len(), 2);
        assert_eq!(points[0].turn_number, 3);
        assert_eq!(points[1].turn_number, 7);
    }

    #[test]
    fn baseline_replay_of_same_call_is_deduped_to_first() {
        // A context-reset/baseline turn re-emits history: the SAME call (id, name,
        // preview) reappears at a later turn. Keep only the first (its real turn).
        let events = vec![
            tool_call("Task", "toolu_9", 2, json!({"prompt": "research the bug"})),
            tool_call("Read", "call_1", 5, json!({"path": "x"})),
            tool_call("Task", "toolu_9", 8, json!({"prompt": "research the bug"})),
        ];
        let points = detect_spawn_points(&events);
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].turn_number, 2, "keeps the original turn, not the replay");
    }

    #[test]
    fn preview_prefers_prompt_then_falls_back_to_json() {
        let p = spawn_prompt_preview(&json!({"subagent_type": "researcher", "foo": 1}));
        assert!(p.contains("researcher"));
        assert!(spawn_prompt_preview(&json!({})).is_empty());
        let long = "x".repeat(500);
        assert!(spawn_prompt_preview(&json!({ "prompt": long })).len() <= 200);
    }
}

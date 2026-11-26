//! The agent loop guard: a request whose history ends in a repeated cycle of
//! tool calls — the same calls getting the same results, step after step — is
//! recorded, and by the workspace's settings nudged (a note written where the
//! last tool result is read) or stopped (the model refused tool calls for this reply
//! and asked to answer in text).
//!
//! **Stateless.** Every agent turn re-sends its history, so the guard reads the
//! request alone: no per-session counter, the same verdict on every replica.
//! The note a nudge adds is never part of the client's history, so it is added
//! again on every turn the streak lasts; it states the count, so the model sees
//! it was already warned.
//!
//! **A step** is one assistant turn's tool calls and everything the client sent
//! back before the next assistant turn (the tool results, and any user text —
//! a harness's auto-continue joins the step; a human's new message, unique,
//! breaks the cycle). Its digests leave out every id (a call id changes every
//! step) and the volatile parts a client injects (`canonicalize_content_value`).
//! Two keys: the calls with any text beside the results (`call` — badges
//! only), and that with the results too (`full` — the only key that ever rewrites a request, so a poll
//! whose answer changes is never acted on).
//!
//! **Not detected, by design:** a history held by the server (a Responses
//! `previous_response_id`: the request carries no steps), tools spelled as text
//! (no wire tool call), a cycle longer than [`MAX_CYCLE`] steps, a step with no
//! tool call (it never repeats), a loop with varying arguments, a Responses
//! `shell_call` / `local_shell_call` (not read as a call). A result
//! carrying a value that changes every run (a timing, a PID) is another result:
//! such a loop is recorded on the `call` key, never rewritten.

use sha2::{Digest, Sha256};

use crate::api::domain_request::{DomainContentBlock, DomainMessage, DomainRequest, DomainRole};
use crate::api::tool_choice::DomainToolChoice;
use crate::api::domain::ResponseInput;
use crate::api::ApiRequest;
pub use crate::audit::ToolLoopAction;
use crate::config::loop_guard::{LoopGuardMode, LoopGuardSettings, LOOP_GUARD_MAX_STOP_AT, LOOP_GUARD_MIN_NUDGE_AT};

/// The longest cycle of steps the guard recognises (edit → build → revert →
/// build is 4).
pub const MAX_CYCLE: usize = 5;

/// Repetitions of the calls alone (results ignored) at which a cycle is
/// recorded, whatever the thresholds.
pub const DETECT_AT: u32 = 3;

/// How many tool names a badge or a note lists.
const MAX_NAMED_TOOLS: usize = 5;

/// A step's two digests.
struct StepKey {
    /// The calls alone; `None` for a step with no tool call, which matches no
    /// other step.
    call: Option<[u8; 32]>,
    /// The calls and everything sent back after them.
    full: Option<[u8; 32]>,
    /// The step's tool names, for the badge and the note.
    tools: Vec<String>,
}

/// What the guard found in a request's history.
#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct LoopFinding {
    /// Whole repetitions of the longest repeating cycle of calls with their
    /// results (`1` = the last cycle happened once: no repeat).
    pub streak: u32,
    /// The same, reading the calls alone.
    pub call_streak: u32,
    /// The cycle's length in steps (of the `full` cycle when it repeats, else
    /// of the `call` one).
    pub cycle_len: u32,
    /// The tool names of the cycle, sorted, at most [`MAX_NAMED_TOOLS`].
    pub tools: Vec<String>,
    /// The walk stopped at its step budget with the cycle still repeating:
    /// the counts are a floor, the loop is longer.
    pub capped: bool,
}

/// The guard's decision for one request.
#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct LoopVerdict {
    pub finding: LoopFinding,
    /// What was done (`Detected` in observe mode).
    pub action: ToolLoopAction,
    /// In observe mode, what a rewriting mode would have done.
    pub would: Option<ToolLoopAction>,
}

/// The thresholds the guard acts at: the settings', each brought within the
/// bounds `LoopGuardSettings::validate` holds (`nudge_at` ≥ 2, `stop_at` ≥
/// `nudge_at` + 2, `stop_at` ≤ 50). The admin API refuses anything else; this
/// keeps the edge from acting on a corrupt body (a step that did not repeat,
/// an overflow).
fn effective_thresholds(settings: &LoopGuardSettings) -> (u32, u32) {
    let nudge_at = settings.nudge_at.clamp(LOOP_GUARD_MIN_NUDGE_AT, LOOP_GUARD_MAX_STOP_AT - 2);
    let stop_at = settings.stop_at.clamp(nudge_at + 2, LOOP_GUARD_MAX_STOP_AT);
    (nudge_at, stop_at)
}

/// Read the request's history and decide. `None` when the guard is off or
/// nothing repeats enough to record.
pub fn evaluate(request: &ApiRequest, settings: &LoopGuardSettings) -> Option<LoopVerdict> {
    if settings.mode == LoopGuardMode::Off {
        return None;
    }
    let (nudge_at, stop_at) = effective_thresholds(settings);
    let finding = find(request, stop_at);
    let due = if finding.streak >= stop_at {
        Some(if client_forces_a_tool(request) { ToolLoopAction::StopSkipped } else { ToolLoopAction::Stopped })
    } else if finding.streak >= nudge_at {
        Some(ToolLoopAction::Nudged)
    } else {
        None
    };
    if due.is_none() && finding.call_streak < DETECT_AT {
        return None;
    }
    let applied = match (settings.mode, due) {
        (LoopGuardMode::Stop, Some(action)) => Some(action),
        (LoopGuardMode::Nudge, Some(_)) => Some(ToolLoopAction::Nudged),
        _ => None,
    };
    Some(match applied {
        Some(action) => LoopVerdict { finding, action, would: None },
        None => LoopVerdict { finding, action: ToolLoopAction::Detected, would: due },
    })
}

/// The note a rewriting verdict writes; `None` for `Detected`.
pub fn note_for(verdict: &LoopVerdict) -> Option<String> {
    let f = &verdict.finding;
    // Worded for the known false positive too: a poll whose answer has not
    // changed yet is a repeat with the same result, and is told so. No tool
    // is named: the guard read the client's names, and a transform may have
    // renamed what the model was offered.
    let steps = f.streak.saturating_mul(f.cycle_len.max(1));
    let steps = if f.capped { format!("{steps} or more") } else { steps.to_string() };
    let head =
        format!("[Gateway notice] The last {steps} steps made the same tool calls and got the same results each time.");
    match verdict.action {
        ToolLoopAction::Detected => None,
        ToolLoopAction::Nudged | ToolLoopAction::StopSkipped => Some(format!(
            "{head} If you are waiting for something still in progress, say so. Otherwise re-read those results and change approach, or tell the user what is blocking you."
        )),
        ToolLoopAction::Stopped => Some(format!(
            "{head} Tool calls are disabled for this reply. Answer in text: what you were trying to do, what you tried, what keeps failing or what you are waiting for, and what you need from the user to continue."
        )),
    }
}

/// One change a rewrite made, for the audit's injection blocks: the field
/// written, how (`append`, `replace`), what was written, and the field's scope
/// (`messages`, `params`).
pub type Change = (String, &'static str, String, &'static str);

/// Settle a verdict on the request as it reaches the guard and apply it: what
/// is recorded is what happened. A rewrite is applied ([`apply`]); one with no
/// place to write is recorded as detected, the action it was due as `would`. In
/// observe mode the `would` is settled the same way, on a copy: what a
/// rewriting mode would really do to this request, or nothing.
pub fn settle(request: &mut ApiRequest, verdict: &LoopVerdict) -> (LoopVerdict, Vec<Change>) {
    let detected = |would| LoopVerdict { action: ToolLoopAction::Detected, would, ..verdict.clone() };
    if verdict.action == ToolLoopAction::Detected {
        let would = verdict.would.and_then(|would| {
            let mut probe = request.clone();
            let (changes, action) = apply(&mut probe, &LoopVerdict { action: would, ..verdict.clone() });
            (!changes.is_empty()).then_some(action)
        });
        return (detected(would), Vec::new());
    }
    let (changes, action) = apply(request, verdict);
    if changes.is_empty() {
        // Due, but nowhere to write: recorded as what was due.
        return (detected(Some(action)), changes);
    }
    (LoopVerdict { action, would: None, ..verdict.clone() }, changes)
}

/// Apply a rewriting verdict to the request: the note where the last tool
/// result is read (see [`append_to_last_tool_result`]) and, for a stop, the
/// tool choice narrowed to none. Returns what changed, as `(field, action,
/// content)` for the audit's injection blocks — empty when no tool result
/// follows the last assistant turn (the note has no place every protocol
/// accepts, so nothing is written) — and the action taken.
pub fn apply(request: &mut ApiRequest, verdict: &LoopVerdict) -> (Vec<Change>, ToolLoopAction) {
    // A stop is settled on the request as it reaches the guard, after the
    // transforms and the tool policy: one that now forces a tool is nudged
    // instead (a text-only reply would break it), and one that declares no
    // tool has nothing to refuse — nudged, so nothing claims a refusal that
    // never reached the wire.
    let action = match verdict.action {
        ToolLoopAction::Stopped if client_forces_a_tool(request) => ToolLoopAction::StopSkipped,
        ToolLoopAction::Stopped if !declares_tools(request) => ToolLoopAction::Nudged,
        other => other,
    };
    let settled = LoopVerdict { action, ..verdict.clone() };
    let Some(note) = note_for(&settled) else { return (Vec::new(), action) };
    let Some(field) = append_to_last_tool_result(request, &note) else { return (Vec::new(), action) };
    let mut changes = vec![(field, "append", note, "messages")];
    if action == ToolLoopAction::Stopped {
        let (field, written) = refuse_tool_calls(request);
        changes.push((field, "replace", written, "params"));
    }
    (changes, action)
}

// ── Detection ────────────────────────────────────────────────────────────────

/// The longest step window ever read: enough for [`MAX_CYCLE`]-step cycles
/// repeated up to the highest stop threshold, plus the step that broke them.
fn step_budget(stop_at: u32) -> usize {
    MAX_CYCLE * (stop_at as usize + 1) + 1
}

fn find(request: &ApiRequest, stop_at: u32) -> LoopFinding {
    let (steps, cut) = recent_steps(request, step_budget(stop_at));
    let (streak, full_len) = longest_cycle(&steps, |s| s.full);
    let (call_streak, call_len) = longest_cycle(&steps, |s| s.call);
    let cycle_len = if streak >= 2 { full_len } else { call_len };
    let mut tools: Vec<String> = steps.iter().rev().take(cycle_len).flat_map(|s| s.tools.iter().cloned()).collect();
    tools.sort();
    tools.dedup();
    tools.truncate(MAX_NAMED_TOOLS);
    // A floor only for the key whose streak is reported, and only when its
    // cycle was still repeating where the walk stopped.
    let capped = if streak >= 2 { cut.full } else { cut.call };
    LoopFinding { streak, call_streak, cycle_len: cycle_len as u32, tools, capped }
}

/// The longest run of whole repetitions of a cycle of 1..=[`MAX_CYCLE`] steps
/// ending at the last step, by `key`: `(repetitions, cycle length)`, the
/// shortest cycle on a tie. A step whose key is `None` repeats nothing.
fn longest_cycle(steps: &[StepKey], key: impl Fn(&StepKey) -> Option<[u8; 32]>) -> (u32, usize) {
    let keys: Vec<Option<[u8; 32]>> = steps.iter().map(&key).collect();
    let n = keys.len();
    let mut best = (1u32, 1usize);
    for k in 1..=MAX_CYCLE.min(n) {
        let tail = &keys[n - k..];
        if tail.iter().any(Option::is_none) {
            continue;
        }
        // A k-step tail that is a shorter cycle repeated counts fewer
        // repetitions than that shorter cycle, met first: never chosen.
        let mut reps = 1u32;
        while n >= (reps as usize + 1) * k && keys[n - (reps as usize + 1) * k..n - reps as usize * k] == *tail {
            reps += 1;
        }
        if reps > best.0 {
            best = (reps, k);
        }
    }
    best
}

/// The request's last steps, oldest first, at most `budget` of them, and, per
/// key, whether the budget cut a cycle still repeating. Walks the conversation back
/// item by item, converting only what it reads, and stops as soon as no cycle
/// of up to [`MAX_CYCLE`] steps can still extend — after a handful of steps on
/// a request with no loop.
fn recent_steps(request: &ApiRequest, budget: usize) -> (Vec<StepKey>, Cut) {
    let len = DomainRequest::conversation_len(request);
    // Newest first while walking.
    let mut steps_rev: Vec<StepKey> = Vec::new();
    // What the client sent back after the assistant turn being assembled
    // (newest first), and that turn's calls.
    let mut sent_back = SentBack::default();
    let mut calls: Vec<([u8; 32], String)> = Vec::new();
    let mut in_assistant = false;
    let mut live = Liveness::default();
    let mut cut = Cut::default();
    'walk: for index in (0..len).rev() {
        let messages = DomainRequest::item_conversation(request, index);
        for (position, message) in messages.iter().enumerate().rev() {
            match message.role {
                DomainRole::Assistant => {
                    in_assistant = true;
                    for block in message.content.iter().rev() {
                        if let DomainContentBlock::ToolUse { name, input, input_raw, .. } = block {
                            calls.push((call_digest(name, input, input_raw.as_deref()), name.clone()));
                        }
                    }
                }
                DomainRole::User | DomainRole::Tool { .. } => {
                    if in_assistant {
                        steps_rev.push(step_key(std::mem::take(&mut calls), std::mem::take(&mut sent_back)));
                        in_assistant = false;
                        if !live.admit(&steps_rev) {
                            break 'walk;
                        }
                        if steps_rev.len() >= budget {
                            // A floor only when something older is left unread.
                            if index > 0 || position > 0 {
                                cut = live.alive();
                            }
                            break 'walk;
                        }
                    }
                    sent_back_digests(message, &mut sent_back);
                }
                DomainRole::System => {}
            }
        }
    }
    if in_assistant && steps_rev.len() < budget {
        steps_rev.push(step_key(calls, sent_back));
    }
    steps_rev.reverse();
    (steps_rev, cut)
}

/// Per key, whether a cycle was still repeating when the walk stopped at its
/// budget.
#[derive(Default, Clone, Copy)]
struct Cut {
    full: bool,
    call: bool,
}

/// Which cycle lengths can still extend as the walk prepends older steps: the
/// walk stops once none can, for either key.
#[derive(Default)]
struct Liveness {
    dead_full: [bool; MAX_CYCLE + 1],
    dead_call: [bool; MAX_CYCLE + 1],
}

impl Liveness {
    /// Record the step just prepended (`steps_rev`'s last); whether any cycle
    /// length is still alive.
    fn admit(&mut self, steps_rev: &[StepKey]) -> bool {
        let j = steps_rev.len() - 1;
        let new = &steps_rev[j];
        for k in 1..=MAX_CYCLE {
            if j < k {
                // Not yet compared: a step with no calls still kills it.
                if new.full.is_none() {
                    self.dead_full[k] = true;
                }
                if new.call.is_none() {
                    self.dead_call[k] = true;
                }
                continue;
            }
            let then = &steps_rev[j - k];
            if new.full.is_none() || new.full != then.full {
                self.dead_full[k] = true;
            }
            if new.call.is_none() || new.call != then.call {
                self.dead_call[k] = true;
            }
        }
        // A step that breaks every cycle is still read (it bounds the run);
        // only the next one is not needed.
        let alive = self.alive();
        alive.full || alive.call
    }

    /// Per key, whether some cycle length can still extend.
    fn alive(&self) -> Cut {
        Cut {
            full: (1..=MAX_CYCLE).any(|k| !self.dead_full[k]),
            call: (1..=MAX_CYCLE).any(|k| !self.dead_call[k]),
        }
    }
}

/// What the client sent back after an assistant turn: its tool results, and
/// any other content (user text) beside them.
#[derive(Default)]
struct SentBack {
    results: Vec<[u8; 32]>,
    texts: Vec<[u8; 32]>,
}

fn step_key(mut calls: Vec<([u8; 32], String)>, mut sent_back: SentBack) -> StepKey {
    if calls.is_empty() {
        return StepKey { call: None, full: None, tools: Vec::new() };
    }
    calls.sort();
    sent_back.results.sort();
    sent_back.texts.sort();
    // The calls, with any text the client sent beside them: a human's new
    // message makes the step another one on both keys.
    let mut call = Sha256::new();
    for (digest, _) in &calls {
        call.update(digest);
    }
    call.update(b"|");
    for digest in &sent_back.texts {
        call.update(digest);
    }
    let call: [u8; 32] = call.finalize().into();
    let mut full = Sha256::new();
    full.update(call);
    full.update(b"|");
    for digest in &sent_back.results {
        full.update(digest);
    }
    let mut tools: Vec<String> = calls.into_iter().map(|(_, name)| name).collect();
    tools.dedup();
    StepKey { call: Some(call), full: Some(full.finalize().into()), tools }
}

/// A call's digest: its name and its arguments in their canonical form (keys
/// sorted), never its id. Arguments that did not parse are read as sent.
fn call_digest(name: &str, input: &serde_json::Value, input_raw: Option<&str>) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update(b"\0");
    match (input, input_raw) {
        (serde_json::Value::Null, Some(raw)) => h.update(raw.as_bytes()),
        _ => h.update(serde_json::to_string(input).unwrap_or_default().as_bytes()),
    }
    h.finalize().into()
}

/// Add the digests of what a user-side message sent back: each tool result's
/// content and error flag (never its id), and each other block as text, with
/// cache breakpoints and client-injected volatile parts left out.
fn sent_back_digests(message: &DomainMessage, into: &mut SentBack) {
    let digest = |value: &serde_json::Value| -> [u8; 32] {
        Sha256::digest(serde_json::to_string(value).unwrap_or_default().as_bytes()).into()
    };
    let result = |content: &[DomainContentBlock], is_error: Option<bool>| {
        let mut content = serde_json::to_value(content).unwrap_or_default();
        crate::proxy::content::strip_breakpoints(&mut content);
        // Parts the client injects whole go first, then what it injects
        // inside a part's text (a reminder appended to a result); a part left
        // empty says nothing.
        crate::proxy::content::canonicalize_content_value(&mut content);
        match &mut content {
            serde_json::Value::Array(parts) => {
                for part in parts.iter_mut() {
                    if let Some(text) = part.get_mut("text") {
                        crate::proxy::content::canonicalize_content_value(text);
                    }
                }
                parts.retain(|part| !is_empty_text(part));
            }
            text @ serde_json::Value::String(_) => {
                crate::proxy::content::canonicalize_content_value(text);
            }
            _ => {}
        }
        digest(&serde_json::json!({"result": content, "is_error": is_error.unwrap_or(false)}))
    };
    // A result carried as a message of its own (a Chat `tool` message).
    if let DomainRole::Tool { is_error, .. } = &message.role {
        into.results.push(result(&message.content, *is_error));
        return;
    }
    for block in &message.content {
        match block {
            DomainContentBlock::ToolResult { content, is_error, .. } => into.results.push(result(content, *is_error)),
            other => {
                let Ok(mut value) = serde_json::to_value(other) else { continue };
                crate::proxy::content::strip_breakpoints(&mut value);
                // A part the client injects whole (a reminder) says nothing new.
                if crate::proxy::content::is_volatile_text_part(&value) {
                    continue;
                }
                if let Some(text) = value.get_mut("text") {
                    crate::proxy::content::canonicalize_content_value(text);
                }
                if is_empty_text(&value) {
                    continue;
                }
                into.texts.push(digest(&value));
            }
        }
    }
}

/// A text block left empty once its volatile parts were dropped: the client's
/// injection alone, which says nothing the model did not already see.
fn is_empty_text(value: &serde_json::Value) -> bool {
    value.get("type").and_then(|t| t.as_str()) == Some("text")
        && value.get("text").and_then(|t| t.as_str()).is_some_and(|t| t.trim().is_empty())
}

/// Whether the client forced a tool call: a reply refused every tool would
/// then break the client's own contract.
fn client_forces_a_tool(request: &ApiRequest) -> bool {
    match DomainRequest::without_conversation(request).tool_choice {
        None | Some(DomainToolChoice::Auto) | Some(DomainToolChoice::None) => false,
        Some(DomainToolChoice::Allowed { required, .. }) => required,
        // `Native` holds a choice with no cross-protocol reading (forcing a
        // hosted tool, an MCP server): read as forcing, so it is never undone.
        Some(DomainToolChoice::Required | DomainToolChoice::Function(_) | DomainToolChoice::Native { .. }) => true,
    }
}

// ── Rewrites ─────────────────────────────────────────────────────────────────

/// Write `note` where the last tool result after the last assistant turn is
/// read — whatever the client sent after it (an auto-continue message, a
/// transform's addition): on Anthropic, a text block at the end of the request
/// (inside that result while a server tool is pending — the message may then
/// hold only results); on Chat Completions and Responses, inside that result (a
/// message after a `tool` message is refused by some compatible upstreams); on
/// Gemini, a member of that `functionResponse`'s object (a text part beside one
/// is unspecified). Placed by the client's protocol: a translation carries the
/// Anthropic block as it carries any text a client sends beside its results
/// (into the tool message for Chat Completions). Returns the field written, or
/// `None` when no tool result follows the last assistant turn.
fn append_to_last_tool_result(request: &mut ApiRequest, note: &str) -> Option<String> {
    use crate::api::domain::{ContentPart, MessageContent};
    match request {
        ApiRequest::ChatCompletions(r) => {
            let index = r
                .messages
                .iter()
                .rposition(|m| m.role == "tool" || m.role == "assistant")
                .filter(|&i| r.messages[i].role == "tool")?;
            let message = &mut r.messages[index];
            match &mut message.content {
                Some(MessageContent::Text(text)) => append_text(text, note),
                Some(MessageContent::Parts(parts)) => {
                    parts.push(ContentPart::Text { text: note.to_string(), extra: Default::default() })
                }
                None => message.content = Some(MessageContent::Text(note.to_string())),
            }
            Some(format!("messages[{index}].content"))
        }
        ApiRequest::Responses(r) => {
            let ResponseInput::Raw(items) = &mut r.input else { return None };
            let kind = |item: &serde_json::Value| -> Option<bool> {
                match item.get("type").and_then(|t| t.as_str()) {
                    Some("function_call_output" | "custom_tool_call_output") => Some(true),
                    // What the model produced: a call, its reasoning, its message.
                    Some("function_call" | "custom_tool_call" | "reasoning") => Some(false),
                    _ if item.get("role").and_then(|r| r.as_str()) == Some("assistant") => Some(false),
                    _ => None,
                }
            };
            let index = items.iter().rposition(|i| kind(i).is_some()).filter(|&i| kind(&items[i]) == Some(true))?;
            let item = items[index].as_object_mut()?;
            match item.get_mut("output") {
                Some(serde_json::Value::String(text)) => append_text(text, note),
                Some(serde_json::Value::Array(parts)) => {
                    parts.push(serde_json::json!({"type": "input_text", "text": note}))
                }
                _ => return None,
            }
            Some(format!("input[{index}].output"))
        }
        ApiRequest::AnthropicMessages(r) => {
            use crate::api::messages::{AnthropicContent, ContentBlock, ToolResultBlock, ToolResultContent};
            let last = r.messages.len().checked_sub(1)?;
            let assistant = r.messages.iter().rposition(|m| m.role == "assistant");
            // The last tool result after the last assistant turn.
            let (message_index, block_index) = (assistant.map_or(0, |a| a + 1)..r.messages.len()).rev().find_map(|i| {
                let AnthropicContent::Blocks(blocks) = &r.messages[i].content else { return None };
                blocks.iter().rposition(|b| matches!(b, ContentBlock::ToolResult { .. })).map(|b| (i, b))
            })?;
            // A server tool the last assistant turn called, still without its
            // result block: the message must then hold only tool results.
            let server_tool_pending = assistant.is_some_and(|a| calls_a_server_tool(&r.messages[a].content));
            if !server_tool_pending && r.messages[last].role == "user" {
                // A text block of its own at the very end: the spec's place for
                // text beside tool results, and outside the client's cache
                // breakpoint (on a result or before it), so the prefix the
                // next turn reads from the cache is the one this turn wrote.
                match &mut r.messages[last].content {
                    AnthropicContent::Blocks(blocks) => {
                        blocks.push(ContentBlock::Text { text: note.to_string(), cache_control: None, extra: Default::default() });
                        return Some(format!("messages[{last}].content[{}]", blocks.len() - 1));
                    }
                    AnthropicContent::Text(text) => {
                        append_text(text, note);
                        return Some(format!("messages[{last}].content"));
                    }
                }
            }
            let AnthropicContent::Blocks(blocks) = &mut r.messages[message_index].content else { return None };
            let ContentBlock::ToolResult { content, .. } = &mut blocks[block_index] else { return None };
            match content {
                Some(ToolResultContent::Text(text)) => append_text(text, note),
                Some(ToolResultContent::Blocks(parts)) => parts.push(ToolResultBlock::Text {
                    text: note.to_string(),
                    cache_control: None,
                    extra: Default::default(),
                }),
                None => *content = Some(ToolResultContent::Text(note.to_string())),
            }
            Some(format!("messages[{message_index}].content[{block_index}].content"))
        }
        ApiRequest::GoogleGemini(r) => {
            use crate::api::gemini::GeminiPart;
            let has_response = |c: &crate::api::gemini::GeminiContent| {
                c.parts.iter().any(|p| matches!(p, GeminiPart::FunctionResponse { .. }))
            };
            let index = r
                .contents
                .iter()
                .rposition(|c| c.role.as_deref() == Some("model") || has_response(c))
                .filter(|&i| has_response(&r.contents[i]))?;
            let (part_index, response) =
                r.contents[index].parts.iter_mut().enumerate().rev().find_map(|(i, p)| match p {
                    GeminiPart::FunctionResponse { function_response } => Some((i, &mut function_response.response)),
                    _ => None,
                })?;
            // `response` is a JSON object (a protobuf `Struct`): the note is a
            // member of its own, beside the tool's.
            let object = response.as_object_mut()?;
            object.insert("gateway_notice".to_string(), serde_json::Value::String(note.to_string()));
            Some(format!("contents[{index}].parts[{part_index}].functionResponse.response.gateway_notice"))
        }
    }
}

/// Whether an Anthropic assistant turn calls a tool the server runs (a
/// `server_tool_use` or `mcp_tool_use` block) whose result block it does not
/// carry yet.
fn calls_a_server_tool(content: &crate::api::messages::AnthropicContent) -> bool {
    use crate::api::messages::{AnthropicContent, ContentBlock};
    let AnthropicContent::Blocks(blocks) = content else { return false };
    let unknown = || blocks.iter().filter_map(|b| match b {
        ContentBlock::Unknown(v) => Some(v),
        _ => None,
    });
    let answered: Vec<&str> = unknown()
        .filter(|v| v.get("type").and_then(|t| t.as_str()).is_some_and(|t| t.ends_with("_tool_result")))
        .filter_map(|v| v.get("tool_use_id").and_then(|id| id.as_str()))
        .collect();
    unknown().any(|v| {
        matches!(v.get("type").and_then(|t| t.as_str()), Some("server_tool_use" | "mcp_tool_use"))
            && !v.get("id").and_then(|id| id.as_str()).is_some_and(|id| answered.contains(&id))
    })
}

fn append_text(text: &mut String, note: &str) {
    if !text.is_empty() {
        text.push_str("\n\n");
    }
    text.push_str(note);
}

/// Narrow the request's tool choice to none, its tools kept declared (the
/// history references them). Returns the field written and its value, as the
/// protocol spells them.
fn refuse_tool_calls(request: &mut ApiRequest) -> (String, String) {
    match request {
        ApiRequest::ChatCompletions(r) => {
            r.tool_choice = Some(serde_json::json!("none"));
            ("tool_choice".to_string(), "none".to_string())
        }
        ApiRequest::Responses(r) => {
            r.tool_choice = Some(serde_json::json!("none"));
            ("tool_choice".to_string(), "none".to_string())
        }
        ApiRequest::AnthropicMessages(r) => {
            let choice = serde_json::json!({"type": "none"});
            let written = choice.to_string();
            r.tool_choice = Some(choice);
            ("tool_choice".to_string(), written)
        }
        ApiRequest::GoogleGemini(r) => {
            // The whole config: an allowlist beside NONE would be read as one.
            r.tool_config = Some(crate::api::gemini::GeminiToolConfig {
                function_calling_config: Some(crate::api::gemini::GeminiFunctionCallingConfig {
                    mode: Some("NONE".to_string()),
                    allowed_function_names: None,
                }),
            });
            ("toolConfig".to_string(), serde_json::json!({"functionCallingConfig": {"mode": "NONE"}}).to_string())
        }
    }
}

/// Whether the request declares a tool the model could call.
fn declares_tools(request: &ApiRequest) -> bool {
    match request {
        ApiRequest::ChatCompletions(r) => r.tools.as_ref().is_some_and(|t| !t.is_empty()),
        ApiRequest::Responses(r) => r.tools.as_ref().is_some_and(|t| !t.is_empty()),
        ApiRequest::AnthropicMessages(r) => r.tools.as_ref().is_some_and(|t| !t.is_empty()),
        ApiRequest::GoogleGemini(r) => r.tools.as_ref().is_some_and(|t| !t.is_empty()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::{json, Value};

    /// One agent step: a call, and what came back for it.
    #[derive(Clone)]
    struct Step {
        name: &'static str,
        args: Value,
        result: String,
    }

    fn step(name: &'static str, args: Value, result: &str) -> Step {
        Step { name, args, result: result.to_string() }
    }

    fn settings(mode: LoopGuardMode, nudge_at: u32, stop_at: u32) -> LoopGuardSettings {
        LoopGuardSettings { mode, nudge_at, stop_at }
    }

    /// An Anthropic request: the task, then each step (ids unique per step, as
    /// a client mints them), then the tail. `between` is user text sent with
    /// each step's result (a harness's reminder or auto-continue).
    fn anthropic(steps: &[Step], between: Option<&str>, tool_choice: Option<Value>) -> ApiRequest {
        let mut messages = vec![json!({"role": "user", "content": "Fix the failing build."})];
        for (i, s) in steps.iter().enumerate() {
            let id = format!("toolu_{i:04}");
            messages.push(json!({"role": "assistant", "content": [
                {"type": "text", "text": format!("Attempt {i}")},
                {"type": "tool_use", "id": id, "name": s.name, "input": s.args},
            ]}));
            let mut content = vec![json!({"type": "tool_result", "tool_use_id": id, "content": s.result})];
            if let Some(text) = between {
                content.push(json!({"type": "text", "text": text}));
            }
            messages.push(json!({"role": "user", "content": content}));
        }
        let mut body = json!({
            "model": "m", "max_tokens": 100, "messages": messages,
            "tools": [{"name": "bash", "input_schema": {"type": "object"}}, {"name": "edit", "input_schema": {"type": "object"}}],
        });
        if let Some(choice) = tool_choice {
            body["tool_choice"] = choice;
        }
        ApiRequest::AnthropicMessages(serde_json::from_value(body).expect("anthropic request"))
    }

    fn repeat(s: &Step, n: usize) -> Vec<Step> {
        vec![s.clone(); n]
    }

    fn ls() -> Step {
        step("bash", json!({"command": "ls", "cwd": "/w"}), "error: no such file")
    }

    fn verdict(req: &ApiRequest, s: LoopGuardSettings) -> Option<LoopVerdict> {
        evaluate(req, &s)
    }

    #[test]
    fn the_same_call_with_the_same_result_is_a_streak_whatever_its_ids() {
        let req = anthropic(&repeat(&ls(), 4), None, None);
        let v = verdict(&req, settings(LoopGuardMode::Observe, 3, 8)).expect("detected");
        assert_eq!(v.finding.streak, 4);
        assert_eq!(v.finding.call_streak, 4);
        assert_eq!(v.finding.cycle_len, 1);
        assert_eq!(v.finding.tools, vec!["bash".to_string()]);
        assert_eq!(v.action, ToolLoopAction::Detected);
        assert_eq!(v.would, Some(ToolLoopAction::Nudged));
    }

    #[test]
    fn argument_key_order_does_not_make_another_call() {
        let a = step("bash", json!({"command": "ls", "cwd": "/w"}), "same");
        let b = step("bash", serde_json::from_str(r#"{"cwd": "/w", "command": "ls"}"#).unwrap(), "same");
        let req = anthropic(&[a.clone(), b, a], None, None);
        assert_eq!(verdict(&req, LoopGuardSettings::default()).expect("detected").finding.streak, 3);
    }

    #[test]
    fn a_result_that_changes_is_never_a_full_streak_but_the_calls_are_recorded() {
        let steps: Vec<Step> = (0..4).map(|i| step("bash", json!({"command": "gh run view"}), &format!("in_progress {i}"))).collect();
        let req = anthropic(&steps, None, None);
        let v = verdict(&req, settings(LoopGuardMode::Stop, 2, 4)).expect("recorded");
        assert_eq!(v.finding.streak, 1);
        assert_eq!(v.finding.call_streak, 4);
        // Nothing is due on the full key: recorded, never rewritten.
        assert_eq!(v.action, ToolLoopAction::Detected);
        assert_eq!(v.would, None);
    }

    #[test]
    fn calls_that_repeat_fewer_times_than_the_detection_floor_are_not_recorded() {
        let steps: Vec<Step> = (0..2).map(|i| step("bash", json!({"command": "x"}), &format!("r{i}"))).collect();
        assert_eq!(verdict(&anthropic(&steps, None, None), LoopGuardSettings::default()), None);
        let steps: Vec<Step> = (0..3).map(|i| step("bash", json!({"command": "x"}), &format!("r{i}"))).collect();
        assert!(verdict(&anthropic(&steps, None, None), LoopGuardSettings::default()).is_some());
    }

    #[test]
    fn a_two_step_cycle_is_counted_in_whole_cycles() {
        let edit = step("edit", json!({"path": "a.rs", "text": "x"}), "ok");
        let build = step("bash", json!({"command": "cargo build"}), "error[E0425]");
        let steps = [edit.clone(), build.clone(), edit.clone(), build.clone(), edit, build];
        let v = verdict(&anthropic(&steps, None, None), LoopGuardSettings::default()).expect("detected");
        assert_eq!((v.finding.streak, v.finding.cycle_len), (3, 2));
        assert_eq!(v.finding.tools, vec!["bash".to_string(), "edit".to_string()]);
    }

    #[test]
    fn cycles_up_to_five_steps_are_seen_and_six_are_not() {
        let make = |k: usize| -> Vec<Step> {
            let cycle: Vec<Step> = (0..k).map(|i| step("bash", json!({"command": format!("c{i}")}), "r")).collect();
            cycle.iter().cloned().cycle().take(k * 3).collect()
        };
        let five = verdict(&anthropic(&make(5), None, None), LoopGuardSettings::default()).expect("k = 5");
        assert_eq!((five.finding.streak, five.finding.cycle_len), (3, 5));
        assert_eq!(verdict(&anthropic(&make(6), None, None), LoopGuardSettings::default()), None);
    }

    #[test]
    fn a_five_step_cycle_is_read_back_far_enough_to_reach_the_stop_threshold() {
        let cycle: Vec<Step> = (0..5).map(|i| step("bash", json!({"command": format!("c{i}")}), "r")).collect();
        for stop_at in [8u32, 50] {
            let steps: Vec<Step> = cycle.iter().cloned().cycle().take(5 * stop_at as usize).collect();
            let v = verdict(&anthropic(&steps, None, None), settings(LoopGuardMode::Stop, 3, stop_at)).unwrap();
            assert_eq!((v.finding.streak, v.finding.cycle_len), (stop_at, 5), "stop_at {stop_at}");
            assert_eq!(v.action, ToolLoopAction::Stopped, "stop_at {stop_at}");
        }
    }

    #[test]
    fn the_cycle_reported_is_the_results_one_when_they_repeat_else_the_calls_one() {
        // The same call every step, its result alternating: the calls repeat
        // with a period of 1, the calls with their results with a period of 2.
        let steps: Vec<Step> = (0..6).map(|i| step("bash", json!({"command": "x"}), if i % 2 == 0 { "a" } else { "b" })).collect();
        let v = verdict(&anthropic(&steps, None, None), LoopGuardSettings::default()).unwrap();
        assert_eq!((v.finding.streak, v.finding.call_streak, v.finding.cycle_len), (3, 6, 2));
        // Two calls alternating, every result different: only the calls repeat.
        let steps: Vec<Step> = (0..6)
            .map(|i| step("bash", json!({"command": if i % 2 == 0 { "edit" } else { "build" }}), &format!("r{i}")))
            .collect();
        let v = verdict(&anthropic(&steps, None, None), LoopGuardSettings::default()).unwrap();
        assert_eq!((v.finding.streak, v.finding.call_streak, v.finding.cycle_len), (1, 3, 2));
    }

    fn chat(messages: Vec<Value>) -> ApiRequest {
        ApiRequest::ChatCompletions(serde_json::from_value(json!({"model": "m", "messages": messages})).unwrap())
    }

    fn chat_step(i: usize, arguments: &str, result: &str) -> [Value; 2] {
        [
            json!({"role": "assistant", "content": null, "tool_calls": [{"id": format!("c{i}"), "type": "function", "function": {"name": "bash", "arguments": arguments}}]}),
            json!({"role": "tool", "tool_call_id": format!("c{i}"), "content": result}),
        ]
    }

    #[test]
    fn a_history_that_opens_with_the_loop_counts_its_first_step() {
        // No task message: the oldest item is the first step's call.
        let messages: Vec<Value> = (0..3).flat_map(|i| chat_step(i, "{\"command\":\"ls\"}", "same")).collect();
        assert_eq!(verdict(&chat(messages), LoopGuardSettings::default()).unwrap().finding.streak, 3);
    }

    #[test]
    fn arguments_that_do_not_parse_are_compared_as_sent() {
        let same: Vec<Value> = (0..3).flat_map(|i| chat_step(i, "{not json", "same")).collect();
        assert_eq!(verdict(&chat(same), LoopGuardSettings::default()).unwrap().finding.streak, 3);
        // Two different malformed spellings are two different calls.
        let alternating: Vec<Value> =
            (0..4).flat_map(|i| chat_step(i, if i % 2 == 0 { "{a" } else { "{b" }, "same")).collect();
        let v = verdict(&chat(alternating), settings(LoopGuardMode::Observe, 2, 4)).unwrap();
        assert_eq!((v.finding.streak, v.finding.cycle_len), (2, 2));
    }

    #[test]
    fn a_blank_text_beside_a_result_is_not_another_step() {
        let mut req = anthropic(&repeat(&ls(), 3), None, None);
        let ApiRequest::AnthropicMessages(r) = &mut req else { unreachable!() };
        // A whitespace-only text block on the second step's results only.
        let crate::api::messages::AnthropicContent::Blocks(blocks) = &mut r.messages[4].content else { unreachable!() };
        blocks.push(serde_json::from_value(json!({"type": "text", "text": "  \n"})).unwrap());
        assert_eq!(verdict(&req, LoopGuardSettings::default()).unwrap().finding.streak, 3);
    }

    #[test]
    fn responses_an_output_given_as_parts_gets_the_note_as_a_part() {
        let mut req = ApiRequest::Responses(serde_json::from_value(json!({
            "model": "m",
            "input": [
                {"type": "function_call", "call_id": "c1", "name": "bash", "arguments": "{}"},
                {"type": "function_call_output", "call_id": "c1", "output": [{"type": "input_text", "text": "same"}]},
            ],
        })).unwrap());
        assert_eq!(apply(&mut req, &nudged()).0.len(), 1);
        let body = serialized(&req);
        let parts = body["input"][1]["output"].as_array().unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0]["text"], "same");
        assert!(parts[1]["text"].as_str().unwrap().starts_with("[Gateway notice]"));
    }

    #[test]
    fn a_loop_longer_than_the_walk_is_reported_as_a_floor() {
        // stop_at 4: the walk reads at most 5 × (4 + 1) + 1 = 26 steps.
        let v = verdict(&anthropic(&repeat(&ls(), 40), None, None), settings(LoopGuardMode::Stop, 2, 4)).unwrap();
        assert!(v.finding.capped);
        assert_eq!(v.finding.streak, 26);
        assert!(note_for(&v).unwrap().contains("The last 26 or more steps"), "{:?}", note_for(&v));
        // A loop the walk reads whole is not.
        let v = verdict(&anthropic(&repeat(&ls(), 6), None, None), settings(LoopGuardMode::Stop, 2, 4)).unwrap();
        assert!(!v.finding.capped);
        assert!(note_for(&v).unwrap().contains("The last 6 steps"));
    }

    #[test]
    fn a_reminder_inside_a_result_does_not_break_the_cycle() {
        let steps: Vec<Step> = (0..3)
            .map(|i| step("bash", json!({"command": "ls"}), &format!("error: no such file\n<system-reminder>turn {i}</system-reminder>")))
            .collect();
        let v = verdict(&anthropic(&steps, None, None), LoopGuardSettings::default()).unwrap();
        assert_eq!(v.finding.streak, 3);
        // Positive control: a result whose own text changes is another result.
        let steps: Vec<Step> = (0..3).map(|i| step("bash", json!({"command": "ls"}), &format!("error {i}"))).collect();
        assert_eq!(verdict(&anthropic(&steps, None, None), LoopGuardSettings::default()).unwrap().finding.streak, 1);
    }

    #[test]
    fn a_server_tool_answered_in_its_own_turn_is_not_pending() {
        let mut req = anthropic(&repeat(&ls(), 3), None, None);
        let ApiRequest::AnthropicMessages(r) = &mut req else { unreachable!() };
        let crate::api::messages::AnthropicContent::Blocks(blocks) = &mut r.messages[5].content else { unreachable!() };
        blocks.push(serde_json::from_value(json!({"type": "server_tool_use", "id": "srvtoolu_1", "name": "web_search", "input": {}})).unwrap());
        blocks.push(serde_json::from_value(json!({"type": "web_search_tool_result", "tool_use_id": "srvtoolu_1", "content": []})).unwrap());
        // Answered: the note is a block of its own after the results.
        assert_eq!(apply(&mut req, &nudged()).0[0].0, "messages[6].content[1]");
    }

    #[test]
    fn a_long_loop_is_counted_whole() {
        // The walk's early exit must never cut a loop it is still inside.
        let v = verdict(&anthropic(&repeat(&ls(), 30), None, None), settings(LoopGuardMode::Observe, 3, 50)).unwrap();
        assert_eq!(v.finding.streak, 30);
    }

    #[test]
    fn a_human_message_breaks_the_cycle() {
        let mut req = anthropic(&repeat(&ls(), 2), None, None);
        let ApiRequest::AnthropicMessages(r) = &mut req else { unreachable!() };
        // The human answers after the second step, then the model repeats twice more.
        let tail = anthropic(&repeat(&ls(), 2), None, None);
        let ApiRequest::AnthropicMessages(t) = tail else { unreachable!() };
        r.messages.push(serde_json::from_value(json!({"role": "user", "content": "Try another directory."})).unwrap());
        r.messages.extend(t.messages.into_iter().skip(1));
        // Two user messages in a row are one turn on the wire; the cycle after
        // the human's text is two long, below every threshold.
        assert_eq!(verdict(&req, LoopGuardSettings::default()), None);
    }

    #[test]
    fn the_same_auto_continue_text_each_step_keeps_the_cycle() {
        let req = anthropic(&repeat(&ls(), 3), Some("Continue."), None);
        assert_eq!(verdict(&req, LoopGuardSettings::default()).expect("detected").finding.streak, 3);
    }

    #[test]
    fn an_injected_reminder_beside_the_result_does_not_break_the_cycle() {
        // A reminder that changes every step but is volatile client injection.
        let steps = repeat(&ls(), 3);
        let mut req = anthropic(&steps, None, None);
        let ApiRequest::AnthropicMessages(r) = &mut req else { unreachable!() };
        let mut i = 0;
        for m in r.messages.iter_mut().filter(|m| m.role == "user").skip(1) {
            let crate::api::messages::AnthropicContent::Blocks(blocks) = &mut m.content else { continue };
            blocks.push(serde_json::from_value(json!({"type": "text", "text": format!("<system-reminder>turn {i}</system-reminder>")})).unwrap());
            i += 1;
        }
        assert_eq!(verdict(&req, LoopGuardSettings::default()).expect("detected").finding.streak, 3);
    }

    #[test]
    fn the_nudge_threshold_is_met_at_its_value_and_not_one_below() {
        let s = settings(LoopGuardMode::Nudge, 4, 8);
        let below = verdict(&anthropic(&repeat(&ls(), 3), None, None), s).expect("recorded");
        assert_eq!(below.action, ToolLoopAction::Detected);
        let at = verdict(&anthropic(&repeat(&ls(), 4), None, None), s).expect("nudged");
        assert_eq!(at.action, ToolLoopAction::Nudged);
    }

    #[test]
    fn the_stop_threshold_is_met_at_its_value_and_not_one_below() {
        let s = settings(LoopGuardMode::Stop, 3, 6);
        assert_eq!(verdict(&anthropic(&repeat(&ls(), 5), None, None), s).unwrap().action, ToolLoopAction::Nudged);
        assert_eq!(verdict(&anthropic(&repeat(&ls(), 6), None, None), s).unwrap().action, ToolLoopAction::Stopped);
    }

    #[test]
    fn nudge_mode_never_stops() {
        let v = verdict(&anthropic(&repeat(&ls(), 9), None, None), settings(LoopGuardMode::Nudge, 3, 5)).unwrap();
        assert_eq!(v.action, ToolLoopAction::Nudged);
    }

    #[test]
    fn observe_records_what_stop_would_do_and_off_records_nothing() {
        let req = anthropic(&repeat(&ls(), 8), None, None);
        let v = verdict(&req, settings(LoopGuardMode::Observe, 3, 8)).unwrap();
        assert_eq!((v.action, v.would), (ToolLoopAction::Detected, Some(ToolLoopAction::Stopped)));
        assert_eq!(note_for(&v), None);
        assert_eq!(verdict(&req, settings(LoopGuardMode::Off, 3, 8)), None);
    }

    #[test]
    fn a_forced_tool_choice_turns_the_stop_into_a_nudge() {
        for forced in [json!({"type": "any"}), json!({"type": "tool", "name": "bash"})] {
            let mut req = anthropic(&repeat(&ls(), 8), None, Some(forced.clone()));
            let v = verdict(&req, settings(LoopGuardMode::Stop, 3, 8)).unwrap();
            assert_eq!(v.action, ToolLoopAction::StopSkipped, "{forced}");
            let changes = apply(&mut req, &v).0;
            assert_eq!(changes.len(), 1, "only the note: {changes:?}");
            let ApiRequest::AnthropicMessages(r) = &req else { unreachable!() };
            assert_eq!(r.tool_choice.as_ref(), Some(&forced), "the client's choice is kept");
        }
        // Positive control: `auto` is stopped.
        let mut req = anthropic(&repeat(&ls(), 8), None, Some(json!({"type": "auto"})));
        let v = verdict(&req, settings(LoopGuardMode::Stop, 3, 8)).unwrap();
        assert_eq!(v.action, ToolLoopAction::Stopped);
        assert_eq!(apply(&mut req, &v).0.len(), 2);
        let ApiRequest::AnthropicMessages(r) = &req else { unreachable!() };
        assert_eq!(r.tool_choice, Some(json!({"type": "none"})));
    }

    #[test]
    fn a_stop_with_no_tool_declared_is_a_nudge() {
        let mut messages: Vec<Value> = (0..3).flat_map(|i| chat_step(i, "{}", "same")).collect();
        messages.insert(0, json!({"role": "user", "content": "go"}));
        let mut req = chat(messages);
        let (changes, action) = apply(&mut req, &stopped());
        assert_eq!(action, ToolLoopAction::Nudged);
        assert_eq!(changes.len(), 1, "no tool choice written: {changes:?}");
        let body = serialized(&req);
        assert!(body.get("tool_choice").is_none());
        assert!(!body.to_string().contains("Tool calls are disabled"));
    }

    #[test]
    fn a_tool_forced_after_detection_turns_the_stop_into_a_nudge() {
        // The client sent `auto`; a transform forced a tool before the guard writes.
        let mut req = anthropic(&repeat(&ls(), 8), None, None);
        let v = verdict(&req, settings(LoopGuardMode::Stop, 3, 8)).unwrap();
        assert_eq!(v.action, ToolLoopAction::Stopped);
        let ApiRequest::AnthropicMessages(r) = &mut req else { unreachable!() };
        r.tool_choice = Some(json!({"type": "any"}));
        let (changes, action) = apply(&mut req, &v);
        assert_eq!(action, ToolLoopAction::StopSkipped);
        assert_eq!(changes.len(), 1);
        let ApiRequest::AnthropicMessages(r) = &req else { unreachable!() };
        assert_eq!(r.tool_choice, Some(json!({"type": "any"})));
    }

    #[test]
    fn observe_previews_what_a_rewrite_would_really_do() {
        // No tool declared: a stop would be a nudge.
        let mut messages: Vec<Value> = (0..8).flat_map(|i| chat_step(i, "{}", "same")).collect();
        messages.insert(0, json!({"role": "user", "content": "go"}));
        let mut req = chat(messages.clone());
        let v = verdict(&req, settings(LoopGuardMode::Observe, 3, 8)).unwrap();
        assert_eq!(v.would, Some(ToolLoopAction::Stopped));
        let before = serialized(&req);
        let (settled, changes) = settle(&mut req, &v);
        assert_eq!((settled.action, settled.would), (ToolLoopAction::Detected, Some(ToolLoopAction::Nudged)));
        assert!(changes.is_empty());
        assert_eq!(serialized(&req), before, "observe never writes");
        // A request with no tool result after its last assistant turn (the
        // model answered): nothing would be written. (Detection itself finds
        // no loop there; the verdict is the one above.)
        messages.push(json!({"role": "assistant", "content": "Done."}));
        let mut req = chat(messages);
        assert_eq!(settle(&mut req, &v).0.would, None);
        // A rewriting mode with no place to write records what was due.
        let (settled, changes) = settle(&mut req, &LoopVerdict { action: ToolLoopAction::Nudged, would: None, ..v.clone() });
        assert_eq!((settled.action, settled.would, changes.len()), (ToolLoopAction::Detected, Some(ToolLoopAction::Nudged), 0));
    }

    #[test]
    fn a_loop_read_whole_at_the_budget_is_exact() {
        // stop_at 4: budget 26 steps; the task message and exactly 26 steps.
        let v = verdict(&anthropic(&repeat(&ls(), 26), None, None), settings(LoopGuardMode::Stop, 2, 4)).unwrap();
        assert_eq!(v.finding.streak, 26);
        assert!(!v.finding.capped);
        // One step more and the count is a floor.
        let v = verdict(&anthropic(&repeat(&ls(), 27), None, None), settings(LoopGuardMode::Stop, 2, 4)).unwrap();
        assert!(v.finding.capped);
    }

    #[test]
    fn out_of_bounds_settings_are_read_at_their_nearest_valid_value() {
        let v = verdict(&anthropic(&repeat(&ls(), 4), None, None), settings(LoopGuardMode::Stop, 0, 0)).unwrap();
        // nudge_at 0 reads as 2, stop_at as 4: four repetitions stop.
        assert_eq!(v.action, ToolLoopAction::Stopped);
    }

    // ── Rewrites, per protocol ──

    fn nudged() -> LoopVerdict {
        LoopVerdict {
            finding: LoopFinding { streak: 3, call_streak: 3, cycle_len: 1, tools: vec!["bash".into()], capped: false },
            action: ToolLoopAction::Nudged,
            would: None,
        }
    }

    fn stopped() -> LoopVerdict {
        LoopVerdict { action: ToolLoopAction::Stopped, ..nudged() }
    }

    fn serialized(req: &ApiRequest) -> Value {
        serde_json::from_slice(&req.serialize().expect("serialize")).expect("json")
    }

    #[test]
    fn anthropic_the_note_is_a_block_after_the_results_outside_the_cache_breakpoint() {
        let mut req = anthropic(&repeat(&ls(), 3), Some("Continue."), None);
        // The client's breakpoint on the last result, as Claude Code puts it.
        let ApiRequest::AnthropicMessages(r) = &mut req else { unreachable!() };
        let crate::api::messages::AnthropicContent::Blocks(blocks) = &mut r.messages[6].content else { unreachable!() };
        let crate::api::messages::ContentBlock::ToolResult { cache_control, .. } = &mut blocks[0] else { unreachable!() };
        *cache_control = serde_json::from_value(json!({"type": "ephemeral"})).unwrap();
        let changes = apply(&mut req, &nudged()).0;
        assert_eq!(changes[0].0, "messages[6].content[2]");
        let body = serialized(&req);
        let last = body["messages"][6]["content"].as_array().unwrap();
        assert_eq!(last.len(), 3);
        // The result and its breakpoint are as the client sent them.
        assert_eq!(last[0]["content"], "error: no such file");
        assert_eq!(last[0]["cache_control"]["type"], "ephemeral");
        assert_eq!(last[1]["text"], "Continue.");
        assert_eq!(last[2]["type"], "text");
        assert!(last[2].get("cache_control").is_none());
        assert!(last[2]["text"].as_str().unwrap().starts_with("[Gateway notice] The last 3 steps"));
    }

    #[test]
    fn anthropic_the_note_goes_inside_the_last_result_while_a_server_tool_is_pending() {
        let mut req = anthropic(&repeat(&ls(), 3), None, None);
        let ApiRequest::AnthropicMessages(r) = &mut req else { unreachable!() };
        let crate::api::messages::AnthropicContent::Blocks(blocks) = &mut r.messages[5].content else { unreachable!() };
        blocks.push(serde_json::from_value(json!({"type": "server_tool_use", "id": "srvtoolu_1", "name": "web_search", "input": {}})).unwrap());
        let changes = apply(&mut req, &nudged()).0;
        assert_eq!(changes[0].0, "messages[6].content[0].content");
        let body = serialized(&req);
        let last = body["messages"][6]["content"].as_array().unwrap();
        assert_eq!(last.len(), 1, "only the result: no text block beside a pending server tool");
        assert!(last[0]["content"].as_str().unwrap().starts_with("error: no such file\n\n[Gateway notice]"));
    }

    #[test]
    fn the_thresholds_acted_at_are_held_within_their_bounds() {
        let t = |nudge_at, stop_at| effective_thresholds(&settings(LoopGuardMode::Stop, nudge_at, stop_at));
        assert_eq!(t(3, 8), (3, 8));
        assert_eq!(t(2, 4), (2, 4));
        assert_eq!(t(48, 50), (48, 50));
        // Each bound, one past it.
        assert_eq!(t(1, 8), (2, 8));
        assert_eq!(t(0, 0), (2, 4));
        assert_eq!(t(3, 4), (3, 5));
        assert_eq!(t(3, 51), (3, 50));
        assert_eq!(t(49, 50), (48, 50));
        assert_eq!(t(u32::MAX, u32::MAX), (48, 50));
    }

    #[test]
    fn chat_the_note_goes_inside_the_last_tool_message_and_stop_narrows_the_choice() {
        let mut req = ApiRequest::ChatCompletions(serde_json::from_value(json!({
            "model": "m",
            "tools": [{"type": "function", "function": {"name": "bash", "parameters": {"type": "object"}}}],
            "tool_choice": "auto",
            "messages": [
                {"role": "user", "content": "go"},
                {"role": "assistant", "content": null, "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "bash", "arguments": "{}"}}]},
                {"role": "tool", "tool_call_id": "c1", "content": "same"},
            ],
        })).unwrap());
        let changes = apply(&mut req, &stopped()).0;
        assert_eq!(changes.iter().map(|c| c.0.as_str()).collect::<Vec<_>>(), ["messages[2].content", "tool_choice"]);
        let body = serialized(&req);
        assert!(body["messages"][2]["content"].as_str().unwrap().contains("Tool calls are disabled for this reply"));
        assert_eq!(body["messages"].as_array().unwrap().len(), 3, "no message added");
        assert_eq!(body["tool_choice"], "none");
        assert!(body["tools"].as_array().is_some_and(|t| t.len() == 1), "tools stay declared");
    }

    #[test]
    fn responses_the_note_goes_inside_the_last_function_call_output() {
        let mut req = ApiRequest::Responses(serde_json::from_value(json!({
            "model": "m",
            "tools": [{"type": "function", "name": "bash", "parameters": {"type": "object"}}],
            "input": [
                {"role": "user", "content": "go"},
                {"type": "function_call", "call_id": "c1", "name": "bash", "arguments": "{}"},
                {"type": "function_call_output", "call_id": "c1", "output": "same"},
            ],
        })).unwrap());
        apply(&mut req, &stopped());
        let body = serialized(&req);
        assert_eq!(body["input"].as_array().unwrap().len(), 3, "no item added");
        assert!(body["input"][2]["output"].as_str().unwrap().starts_with("same\n\n[Gateway notice]"));
        assert_eq!(body["tool_choice"], "none");
    }

    #[test]
    fn gemini_the_note_is_a_member_of_the_last_function_response() {
        let mut req = ApiRequest::GoogleGemini(serde_json::from_value(json!({
            "tools": [{"functionDeclarations": [{"name": "bash"}]}],
            "contents": [
                {"role": "user", "parts": [{"text": "go"}]},
                {"role": "model", "parts": [{"functionCall": {"name": "bash", "args": {}}}]},
                {"role": "user", "parts": [{"functionResponse": {"name": "bash", "response": {"output": "same"}}}]},
            ],
        })).unwrap());
        apply(&mut req, &stopped());
        let body = serialized(&req);
        let parts = body["contents"][2]["parts"].as_array().unwrap();
        assert_eq!(parts.len(), 1, "no part added");
        assert_eq!(parts[0]["functionResponse"]["response"]["output"], "same");
        assert!(parts[0]["functionResponse"]["response"]["gateway_notice"].as_str().unwrap().contains("Tool calls are disabled"));
        assert_eq!(body["toolConfig"]["functionCallingConfig"]["mode"], "NONE");
    }

    #[test]
    fn responses_a_custom_tool_output_carries_the_note_too() {
        let mut req = ApiRequest::Responses(serde_json::from_value(json!({
            "model": "m",
            "input": [
                {"role": "user", "content": "go"},
                {"type": "custom_tool_call", "call_id": "c1", "name": "apply_patch", "input": "*** Begin Patch"},
                {"type": "custom_tool_call_output", "call_id": "c1", "output": "patch failed"},
            ],
        })).unwrap());
        assert_eq!(apply(&mut req, &nudged()).0.len(), 1);
        let body = serialized(&req);
        assert!(body["input"][2]["output"].as_str().unwrap().starts_with("patch failed\n\n[Gateway notice]"));
    }

    #[test]
    fn an_auto_continue_after_the_result_still_carries_the_note_on_every_protocol() {
        // Chat: the note goes into the tool message, the user's text stays last.
        let mut messages: Vec<Value> = (0..3).flat_map(|i| chat_step(i, "{}", "same")).collect();
        messages.push(json!({"role": "user", "content": "continue"}));
        let mut req = chat(messages);
        assert_eq!(apply(&mut req, &nudged()).0[0].0, "messages[5].content");
        let body = serialized(&req);
        assert!(body["messages"][5]["content"].as_str().unwrap().contains("[Gateway notice]"));
        assert_eq!(body["messages"][6]["content"], "continue");

        // Responses: into the last output before the user's message.
        let mut req = ApiRequest::Responses(serde_json::from_value(json!({"model": "m", "input": [
            {"type": "function_call", "call_id": "c1", "name": "bash", "arguments": "{}"},
            {"type": "function_call_output", "call_id": "c1", "output": "same"},
            {"role": "user", "content": "continue"},
        ]})).unwrap());
        assert_eq!(apply(&mut req, &nudged()).0[0].0, "input[1].output");

        // Gemini: into the last functionResponse before the user's text.
        let mut req = ApiRequest::GoogleGemini(serde_json::from_value(json!({"contents": [
            {"role": "model", "parts": [{"functionCall": {"name": "bash", "args": {}}}]},
            {"role": "user", "parts": [{"functionResponse": {"name": "bash", "response": {"output": "same"}}}]},
            {"role": "user", "parts": [{"text": "continue"}]},
        ]})).unwrap());
        assert_eq!(apply(&mut req, &nudged()).0[0].0, "contents[1].parts[0].functionResponse.response.gateway_notice");

        // Anthropic: a block at the end of the user's own message.
        let mut req = anthropic(&repeat(&ls(), 3), None, None);
        let ApiRequest::AnthropicMessages(r) = &mut req else { unreachable!() };
        r.messages.push(serde_json::from_value(json!({"role": "user", "content": [{"type": "text", "text": "continue"}]})).unwrap());
        assert_eq!(apply(&mut req, &nudged()).0[0].0, "messages[7].content[1]");
    }

    #[test]
    fn a_result_before_the_last_assistant_turn_is_not_written() {
        // The model answered after the results: nothing of this turn to annotate.
        let mut messages: Vec<Value> = (0..3).flat_map(|i| chat_step(i, "{}", "same")).collect();
        messages.push(json!({"role": "assistant", "content": "Done."}));
        assert!(apply(&mut chat(messages), &nudged()).0.is_empty());
    }

    #[test]
    fn the_floor_is_said_only_for_the_key_still_repeating() {
        // The same call 60 times; its result settled only for the last 9.
        let steps: Vec<Step> = (0..60)
            .map(|i| step("bash", json!({"command": "poll"}), &if i < 51 { format!("pending {i}") } else { "done".to_string() }))
            .collect();
        let v = verdict(&anthropic(&steps, None, None), settings(LoopGuardMode::Observe, 3, 8)).unwrap();
        assert_eq!(v.finding.streak, 9);
        assert!(!v.finding.capped, "the results' streak is exact");
        // Positive control: the calls alone are still repeating where the walk stops.
        let steps: Vec<Step> = (0..60).map(|i| step("bash", json!({"command": "poll"}), &format!("pending {i}"))).collect();
        let v = verdict(&anthropic(&steps, None, None), settings(LoopGuardMode::Observe, 3, 8)).unwrap();
        assert_eq!(v.finding.streak, 1);
        assert!(v.finding.capped, "the calls' streak is a floor");
    }

    #[test]
    fn nothing_is_written_when_the_request_does_not_end_with_a_tool_result() {
        let mut req = ApiRequest::ChatCompletions(serde_json::from_value(json!({
            "model": "m",
            "messages": [{"role": "user", "content": "go"}],
        })).unwrap());
        assert!(apply(&mut req, &stopped()).0.is_empty());
    }

    #[test]
    fn detection_reads_every_protocol_alike() {
        let chat_step = |i: usize| vec![
            json!({"role": "assistant", "content": null, "tool_calls": [{"id": format!("c{i}"), "type": "function", "function": {"name": "bash", "arguments": "{\"command\":\"ls\"}"}}]}),
            json!({"role": "tool", "tool_call_id": format!("c{i}"), "content": "same"}),
        ];
        let mut messages = vec![json!({"role": "user", "content": "go"})];
        (0..3).for_each(|i| messages.extend(chat_step(i)));
        let chat = ApiRequest::ChatCompletions(serde_json::from_value(json!({"model": "m", "messages": messages})).unwrap());
        assert_eq!(verdict(&chat, LoopGuardSettings::default()).unwrap().finding.streak, 3);

        let mut input = vec![json!({"role": "user", "content": "go"})];
        for i in 0..3 {
            input.push(json!({"type": "function_call", "call_id": format!("c{i}"), "name": "bash", "arguments": "{\"command\":\"ls\"}"}));
            input.push(json!({"type": "function_call_output", "call_id": format!("c{i}"), "output": "same"}));
        }
        let responses = ApiRequest::Responses(serde_json::from_value(json!({"model": "m", "input": input})).unwrap());
        assert_eq!(verdict(&responses, LoopGuardSettings::default()).unwrap().finding.streak, 3);

        let mut contents = vec![json!({"role": "user", "parts": [{"text": "go"}]})];
        for _ in 0..3 {
            contents.push(json!({"role": "model", "parts": [{"functionCall": {"name": "bash", "args": {"command": "ls"}}}]}));
            contents.push(json!({"role": "user", "parts": [{"functionResponse": {"name": "bash", "response": {"output": "same"}}}]}));
        }
        let gemini = ApiRequest::GoogleGemini(serde_json::from_value(json!({"contents": contents})).unwrap());
        assert_eq!(verdict(&gemini, LoopGuardSettings::default()).unwrap().finding.streak, 3);
    }

    #[test]
    fn parallel_calls_are_one_step_whatever_their_order() {
        let mut messages = vec![json!({"role": "user", "content": "go"})];
        for i in 0..3 {
            let (a, b) = if i % 2 == 0 { ("a", "b") } else { ("b", "a") };
            messages.push(json!({"role": "assistant", "content": [
                {"type": "tool_use", "id": format!("x{i}"), "name": "read", "input": {"path": a}},
                {"type": "tool_use", "id": format!("y{i}"), "name": "read", "input": {"path": b}},
            ]}));
            messages.push(json!({"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": format!("x{i}"), "content": format!("file {a}")},
                {"type": "tool_result", "tool_use_id": format!("y{i}"), "content": format!("file {b}")},
            ]}));
        }
        let req = ApiRequest::AnthropicMessages(serde_json::from_value(json!({"model": "m", "max_tokens": 1, "messages": messages})).unwrap());
        let v = verdict(&req, LoopGuardSettings::default()).unwrap();
        assert_eq!((v.finding.streak, v.finding.cycle_len), (3, 1));
    }

    // ── Properties ──

    fn arb_steps(distinct_results: bool) -> impl Strategy<Value = Vec<(u8, u8)>> {
        // (call, result) pairs over a small alphabet, so repeats are common.
        let result = if distinct_results { Just(0u8).boxed() } else { (0u8..3).boxed() };
        prop::collection::vec((0u8..3, result), 0..24)
    }

    fn history(pairs: &[(u8, u8)], distinct_results: bool) -> ApiRequest {
        let steps: Vec<Step> = pairs
            .iter()
            .enumerate()
            .map(|(i, (c, r))| {
                let result = if distinct_results { format!("unique {i}") } else { format!("r{r}") };
                step("bash", json!({"command": format!("c{c}")}), &result)
            })
            .collect();
        anthropic(&steps, None, None)
    }

    proptest! {
        /// Every step answered differently: nothing ever rewrites.
        #[test]
        fn a_history_whose_results_never_repeat_is_never_rewritten(pairs in arb_steps(true)) {
            let req = history(&pairs, true);
            if let Some(v) = verdict(&req, settings(LoopGuardMode::Stop, 2, 4)) {
                prop_assert_eq!(v.action, ToolLoopAction::Detected);
                prop_assert_eq!(v.finding.streak, 1);
            }
        }

        /// One more repetition of the last cycle never lowers the streak.
        #[test]
        fn repeating_the_cycle_again_never_lowers_the_streak(pairs in arb_steps(false)) {
            let before = verdict(&history(&pairs, false), settings(LoopGuardMode::Observe, 2, 50));
            let Some(before) = before else { return Ok(()) };
            let k = before.finding.cycle_len as usize;
            let mut longer = pairs.clone();
            longer.extend_from_slice(&pairs[pairs.len() - k..]);
            let after = verdict(&history(&longer, false), settings(LoopGuardMode::Observe, 2, 50)).expect("still detected");
            prop_assert!(after.finding.streak >= before.finding.streak);
            prop_assert!(after.finding.call_streak >= before.finding.call_streak);
        }

        /// The streak never exceeds what the history can hold.
        #[test]
        fn the_streak_is_bounded_by_the_steps(pairs in arb_steps(false)) {
            if let Some(v) = verdict(&history(&pairs, false), settings(LoopGuardMode::Observe, 2, 50)) {
                prop_assert!((v.finding.streak as usize) * (v.finding.cycle_len as usize) <= pairs.len());
                prop_assert!((v.finding.call_streak as usize) <= pairs.len());
            }
        }
    }
}

//! Every reader of a streamed tool call ends with the same calls, and every
//! client's stream ends once.
//!
//! A tool-call stream is read by several parties at once: the audit
//! (`TransformState`, fed the stream parser's events), response tool policy
//! (the block accumulator, when a policy holds calls), and the client — through
//! whichever builder speaks its protocol, or the pass-through leg. Each keeps
//! calls apart by its own rule, and a defect in any one of them is silent: the
//! stream still parses, the audit row still renders, and the client runs a call
//! the audit never saw, or the audit records one the client never got.
//!
//! The property drives generated upstream streams — every protocol's tool-call
//! grammar, calls sequential or interleaved, several calls in one chunk, the id
//! before or after the name, names repeated, a Chat call's later deltas
//! restating its id at another call's index or at none, custom (freeform)
//! calls, a Responses call's arguments completed by its done events (or
//! stated there as something else), Responses items interleaved and each
//! event naming its item by place and id, place alone or id alone (or naming
//! two), an item opened without its place, pieces after a call's end (custom text, and a function call's JSON
//! continued after other content, empty ones included), arguments of no call
//! (alone, beside text, beside a call's opening), usage on every chunk, text
//! after the finish, the input of a server tool the upstream runs (an
//! Anthropic block, a Responses MCP call), an upstream error mid-stream (a
//! Responses `response.failed` too, one after the finish, and an upstream
//! going on after its error), streams cut short (mid-call too), several
//! responses read by one parser — through the
//! per-frame sequence the streaming pipeline runs (parse → audit → accumulator
//! → emitter, then the parser's, the accumulator's and the emitter's ends, the
//! audit's records of them, and the truncation guard), with and without a
//! policy holding calls, into every client protocol, pass-through included.
//! Each client's output is read the way its SDK reads it (Chat calls by
//! `index`, Anthropic by content block, Responses by output item, Gemini by
//! part), and the claim is:
//!
//! - the audit records exactly the calls the upstream made, each as far as the
//!   stream carried it and apart from every other — a server tool's input
//!   recorded as that server tool's call, marked as one, no delta of no call
//!   merged into one;
//! - every client ends with exactly the client's calls, each with the name the
//!   upstream gave it and an id — the upstream's, or one the audit row says the
//!   client was given; a Chat client's indexes run 0, 1, 2 … in the order its
//!   calls first appear, one call per index; every custom call's input is
//!   closed exactly once;
//! - a client's copy of a call equals the audit's as policy rewrote it — or
//!   stops short of it only where the call's later bytes were withheld;
//! - every withheld call — cut short for this client, or a piece after its end
//!   — is recorded ONCE on the audit row and told to the client ONCE; a call
//!   nothing was withheld from (a delta carrying no bytes) is neither; so are
//!   arguments of no call, which no client is sent, raw or rendered;
//! - every client's stream ends exactly once: its finish, the gateway's close
//!   of a translated Anthropic stream cut short, or an upstream error — and
//!   nothing follows an error; an Anthropic client's every opened block is
//!   stopped once, before its message stops.
//!
//! Deliberately NOT claimed:
//! - anything about a Responses client of a stream cut short: its builder
//!   announces a call once identified and closes items only at the response's
//!   end, and a stream with no end is never given one;
//! - that a Chat or Gemini client, or a pass-through one, of a stream cut short
//!   is given an end: only a translated Anthropic stream is closed by the
//!   gateway (the truncation guard);
//! - the calls of a stream an upstream error ended: every SDK discards them;
//! - a Gemini client's id where the upstream sent none (Gemini's call id is
//!   optional), or its arguments where they were cut short (a Gemini call's
//!   `args` is an object; a cut-short one is whatever its builder makes of it);
//! - a call the stream cut before naming it: no client can run it;
//! - streams of several responses on a pass-through leg: across agent-loop
//!   rounds that leg is shaped by the loop's replay, which is not driven here;
//! - a pass-through Responses client of an upstream opening an item without
//!   its `output_index` (the spec requires one): that leg addresses the
//!   client's items by it.
//!
//! Seeds the property found are kept as named cases at the end.

use proptest::prelude::*;
use serde_json::{json, Value};

use crate::api::sse::ApiVersion::ChatCompletions;
use crate::api::sse::{ApiVersion, SseEvent, StreamParser};
use crate::pipeline::response::{TransformState, WITHHELD_NOTICE};
use crate::pipeline::response_blocks::{BlockAccumulator, BlockInterests, BufferedEvent};
use crate::pipeline::response_pipeline::{
    close_a_stream_that_never_ended, fast_path_frame, fold_accumulator, frame_opens_container, record_emitter_withheld,
    split_frame, EventEmitter, UnendedStream,
};

/// The custom tool every generated freeform call is to — declared custom by
/// the client, so a Chat client is sent it in the custom form.
const FREEFORM_TOOL: &str = "apply_patch";
/// Text a policy rule rewrites wherever it appears in a call's arguments.
const REWRITE_FROM: &str = "REWRITE_ME";
const REWRITE_TO: &str = "rewritten";
/// The input of every generated server-tool call.
const SERVER_TOOL_INPUT: &str = "{\"query\":\"x\"}";

#[derive(Debug, Clone, Copy, PartialEq)]
enum Opening {
    /// The first delta carries the id, the name and the first piece.
    Whole,
    /// The first delta carries the id (and the call's kind) alone.
    IdOnly,
    /// The first delta carries the name and the first piece; the id comes in
    /// the call's next delta.
    NameFirst,
}

#[derive(Debug, Clone)]
struct GenCall {
    id: String,
    name: String,
    freeform: bool,
    /// The call's text (freeform) or its JSON arguments, as the upstream cuts
    /// them into pieces.
    pieces: Vec<String>,
    opening: Opening,
    /// A custom call: text sent after the call ended (possibly empty).
    late: Option<String>,
    /// A Chat function call: its last piece — empty when it has one — is sent
    /// after other content, continuing the call after the text.
    json_tail_late: bool,
    /// A Responses call: how many of its pieces stream as deltas; the done
    /// events state the whole text.
    streamed: usize,
    /// A Responses function call whose done events state arguments that are
    /// no extension of what streamed.
    conflicting_done: bool,
    /// Gemini: whether the call part states its (optional) id.
    id_sent: bool,
}

#[derive(Debug, Clone)]
struct GenRound {
    calls: Vec<GenCall>,
    /// Chat: the order the calls' deltas are sent in, by call position.
    order: Vec<usize>,
    usage_every_chunk: bool,
    restate_name: bool,
    /// Chat: two deltas of different calls ride one chunk where they can.
    /// Responses: the items' events interleave (`noise` picks the order).
    pair_chunks: bool,
    /// Anthropic and Responses: a call the upstream runs itself — a
    /// `server_tool_use` block, an `mcp_call` item — its input streamed as
    /// deltas, opens the message.
    server_tool: bool,
    /// Chat, Responses and Anthropic: arguments of no call — sent before the
    /// round's first call opens, so no reader can give them to one.
    stray: Option<String>,
    /// Chat: once a call's id is known, each later delta restates it at an
    /// index of its own — none, or any call's (`noise`). Responses: each event
    /// names its item by place and id, place alone or id alone, and one delta
    /// names two items (one's id, the other's place).
    unstable: bool,
    noise: Vec<usize>,
    /// Responses: the upstream error is a `response.failed` (an error and the
    /// response's end in one frame).
    failed: bool,
    /// The upstream goes on after its error: the response's finish (and its
    /// usage) follows the error.
    after_error: bool,
    /// Chat: the error comes after the finish, before the usage and `[DONE]`
    /// — while a builder still holds the finish for the usage.
    error_after_finish: bool,
    /// Chat: text comes after the finish, before the usage (a lax server).
    text_after_finish: bool,
    /// Responses: the first call's item opens without its `output_index`;
    /// every later event names it by its place and its id.
    unindexed_open: bool,
    finished: bool,
    /// A stream cut short (unfinished) ends after this many of its frames
    /// (modulo their number, plus one).
    cut_at: usize,
    /// The last round: an upstream error ends the stream after this many of
    /// its frames (modulo their number, plus one).
    error_at: Option<usize>,
}

#[derive(Debug, Clone)]
struct GenStream {
    upstream: ApiVersion,
    rounds: Vec<GenRound>,
}

impl GenStream {
    fn errored(&self) -> bool {
        self.rounds.last().is_some_and(|r| r.error_at.is_some())
    }

    fn cut_short(&self) -> bool {
        self.rounds.last().is_some_and(|r| !r.finished)
    }
}

// ─── Generation ─────────────────────────────────────────────────────────────

fn cut(text: &str, at: &[prop::sample::Index]) -> Vec<String> {
    let bounds: Vec<usize> = text.char_indices().map(|(i, _)| i).skip(1).collect();
    let mut cuts: Vec<usize> =
        if bounds.is_empty() { Vec::new() } else { at.iter().map(|i| bounds[i.index(bounds.len())]).collect() };
    cuts.sort_unstable();
    cuts.dedup();
    let mut pieces = Vec::new();
    let mut from = 0;
    for c in cuts {
        pieces.push(text[from..c].to_string());
        from = c;
    }
    pieces.push(text[from..].to_string());
    pieces
}

fn call_strategy(upstream: ApiVersion) -> impl Strategy<Value = GenCall> {
    let can_be_freeform = matches!(upstream, ApiVersion::ChatCompletions | ApiVersion::Responses);
    let chat = upstream == ApiVersion::ChatCompletions;
    (
        (
            prop::bool::weighted(if can_be_freeform { 0.5 } else { 0.0 }),
            prop::sample::select(vec!["Read", "Bash", "grep"]),
            "[a-z \"\\\\é\n]{0,10}",
            prop::bool::weighted(0.3),
            prop::collection::vec(any::<prop::sample::Index>(), 0..4),
        ),
        (
            prop::sample::select(vec![Opening::Whole, Opening::IdOnly, Opening::NameFirst]),
            prop::option::weighted(0.25, "[a-z]{0,4}"),
            prop::bool::weighted(0.2),
            any::<prop::sample::Index>(),
            prop::bool::weighted(0.7),
            prop::bool::weighted(0.15),
        ),
    )
        .prop_map(move |((freeform, name, text, rewrite, at), (opening, late, json_tail_late, streamed, id_sent, conflicting))| {
            let text = if rewrite { format!("{text}{REWRITE_FROM}") } else { text };
            let (name, source) =
                if freeform { (FREEFORM_TOOL.to_string(), text) } else { (name.to_string(), json!({ "v": text }).to_string()) };
            let pieces = cut(&source, &at);
            GenCall {
                id: String::new(),
                name,
                freeform,
                streamed: streamed.index(pieces.len() + 1),
                pieces,
                opening: if chat { opening } else { Opening::Whole },
                late: late.filter(|_| freeform),
                json_tail_late: json_tail_late && chat && !freeform,
                id_sent: id_sent || upstream != ApiVersion::GoogleGemini,
                conflicting_done: conflicting && !freeform && upstream == ApiVersion::Responses,
            }
        })
}

/// A Chat call's deltas in its own order: its opening (one or two deltas),
/// then one per piece — the late tail not among them.
fn chat_delta_count(c: &GenCall) -> usize {
    let tail = usize::from(c.json_tail_late && c.pieces.len() > 1);
    c.pieces.len() - tail + usize::from(c.opening != Opening::Whole)
}

fn round_strategy(upstream: ApiVersion) -> impl Strategy<Value = GenRound> {
    (
        prop::collection::vec(call_strategy(upstream), 1..=3),
        prop::collection::vec(any::<prop::sample::Index>(), 12),
        (any::<bool>(), any::<bool>(), any::<bool>(), any::<bool>()),
        prop::bool::weighted(0.8),
        any::<usize>(),
        prop::option::weighted(0.15, any::<usize>()),
        (
            prop::option::weighted(0.2, prop::sample::select(vec!["", "{\"cmd\":\"rm -rf /\"}", "x"])),
            any::<bool>(),
            prop::collection::vec(any::<usize>(), 6),
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            prop::bool::weighted(0.2),
            prop::bool::weighted(0.15),
        ),
    )
        .prop_map(move |(calls, picks, (usage, restate, pair, server), finished, cut_at, error_at, (stray, unstable, noise, failed, after_error, after_finish, text_after_finish, unindexed_open))| {
            let chat = upstream == ApiVersion::ChatCompletions;
            // Calls interleave on a Chat stream, each call's own deltas in
            // order — except that a call's opening is whole before another
            // call's delta comes: a name-first call's id, an id-first call's
            // name, follow at once (no server starts a call, lets another
            // start, and only then says which call it was).
            let mut left: Vec<usize> = calls.iter().map(chat_delta_count).collect();
            let mut order = Vec::new();
            let mut pick = picks.iter().cycle();
            while left.iter().any(|&n| n > 0) {
                let open: Vec<usize> = (0..left.len()).filter(|&i| left[i] > 0).collect();
                let i = if chat { open[pick.next().map_or(0, |p| p.index(open.len()))] } else { open[0] };
                let first = left[i] == chat_delta_count(&calls[i]);
                let take = if chat && first && calls[i].opening != Opening::Whole { 2 } else { 1 };
                for _ in 0..take.min(left[i]) {
                    left[i] -= 1;
                    order.push(i);
                }
            }
            // An error after the finish is one a builder holding the finish
            // for its usage meets; a usage already reported lets a Gemini
            // client's stream end at the finish, before the error.
            let error_after_finish = after_finish && chat && error_at.is_some();
            GenRound {
                calls,
                order,
                usage_every_chunk: usage && chat && !error_after_finish,
                restate_name: restate && chat,
                pair_chunks: pair && (chat || upstream == ApiVersion::Responses),
                server_tool: server && matches!(upstream, ApiVersion::AnthropicMessages | ApiVersion::Responses),
                stray: stray.filter(|_| upstream != ApiVersion::GoogleGemini).map(str::to_string),
                unstable: unstable && (chat || upstream == ApiVersion::Responses),
                noise,
                failed: failed && upstream == ApiVersion::Responses,
                after_error,
                error_after_finish,
                text_after_finish: text_after_finish && chat && !error_after_finish,
                unindexed_open: unindexed_open && upstream == ApiVersion::Responses,
                finished: finished && error_at.is_none(),
                cut_at,
                error_at,
            }
        })
}

fn stream_strategy() -> impl Strategy<Value = GenStream> {
    prop::sample::select(vec![
        ApiVersion::ChatCompletions,
        ApiVersion::Responses,
        ApiVersion::AnthropicMessages,
        ApiVersion::GoogleGemini,
    ])
    .prop_flat_map(|upstream| {
        prop::collection::vec(round_strategy(upstream), 1..=2).prop_map(move |mut rounds| {
            // Ids are the stream's own; only the last response may be cut
            // short or end in an error.
            let last = rounds.len() - 1;
            for (r, round) in rounds.iter_mut().enumerate() {
                for (i, call) in round.calls.iter_mut().enumerate() {
                    call.id = format!("call_{r}_{i}");
                }
                if r < last {
                    round.finished = true;
                    round.error_at = None;
                }
            }
            GenStream { upstream, rounds }
        })
    })
}

// ─── Upstream frames, each with what it tells about which call ─────────────

/// Whose a told fact is: a generated call (by its position in the stream's
/// calls), or the server tool of a round.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Whose {
    Call(usize),
    ServerTool(usize),
}

/// What an upstream frame tells a reader about a call.
#[derive(Debug, Clone)]
enum Told {
    Id(Whose),
    Name(Whose),
    Piece(Whose, String),
    /// A piece of text sent after the call ended.
    Late(Whose, String),
    /// Arguments of no call.
    Stray(String),
}

struct Frame {
    event: SseEvent,
    told: Vec<Told>,
}

fn usage_chat() -> Value {
    json!({"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8})
}

fn error_frame(upstream: ApiVersion, failed: bool) -> SseEvent {
    let (event_type, data) = match upstream {
        ApiVersion::ChatCompletions => (None, json!({"error": {"message": "boom", "type": "server_error"}})),
        ApiVersion::Responses if failed => (Some("response.failed"), json!({"type": "response.failed",
            "response": {"id": "resp_u", "status": "failed", "error": {"code": "server_error", "message": "boom"}}})),
        ApiVersion::Responses => (Some("error"), json!({"type": "error", "code": "server_error", "message": "boom"})),
        ApiVersion::AnthropicMessages => (Some("error"), json!({"type": "error", "error": {"type": "overloaded_error", "message": "boom"}})),
        ApiVersion::GoogleGemini => (None, json!({"error": {"code": 500, "message": "boom", "status": "INTERNAL"}})),
    };
    SseEvent { event_type: event_type.map(str::to_string), data: data.to_string(), id: None }
}

/// The index an unstable Chat delta (the `k`-th of call `i`) carries: none,
/// or one of the first few — its own, another call's, or no call's.
fn unstable_index(round: &GenRound, i: usize, k: usize) -> Option<usize> {
    let pick = round.noise[(i * 5 + k) % round.noise.len()] % 5;
    (pick < 4).then_some(pick)
}

fn chat_frames(round: &GenRound, base: usize) -> Vec<Frame> {
    let chunk = |delta: Value, finish: Value, usage: bool| {
        let mut v = json!({"id": "chatcmpl-u", "object": "chat.completion.chunk", "created": 1, "model": "u",
            "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]});
        if usage {
            v["usage"] = usage_chat();
        }
        SseEvent { event_type: None, data: v.to_string(), id: None }
    };
    let body = |c: &GenCall, piece: Option<&str>, name: bool| -> Value {
        let (key, text_key) = if c.freeform { ("custom", "input") } else { ("function", "arguments") };
        let mut inner = json!({});
        if name {
            inner["name"] = json!(c.name);
        }
        if let Some(p) = piece {
            inner[text_key] = json!(p);
        }
        json!({ key: inner })
    };
    let kind = |c: &GenCall| if c.freeform { "custom" } else { "function" };
    // The upstream numbers calls in the order they start.
    let mut upstream_index = vec![usize::MAX; round.calls.len()];
    let mut next_index = 0;
    for &i in &round.order {
        if upstream_index[i] == usize::MAX {
            upstream_index[i] = next_index;
            next_index += 1;
        }
    }
    let mut queues: Vec<std::collections::VecDeque<(Value, Vec<Told>)>> = round
        .calls
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let n = Whose::Call(base + i);
            let mut q = std::collections::VecDeque::new();
            let tail = usize::from(c.json_tail_late && c.pieces.len() > 1);
            let mut pieces = c.pieces[..c.pieces.len() - tail].iter();
            let mut id_known = false;
            let mut push = |mut d: Value, told: Vec<Told>| {
                // A delta after the call's id is known may restate it at an
                // index of its own; the id is what places it.
                if round.unstable && id_known {
                    d["id"] = json!(c.id);
                    if let Some(k) = unstable_index(round, i, q.len()) {
                        d["index"] = json!(k);
                    }
                } else {
                    d["index"] = json!(upstream_index[i]);
                }
                id_known |= d.get("id").is_some();
                q.push_back((d, told));
            };
            match c.opening {
                Opening::Whole => {
                    let p = pieces.next().cloned().unwrap_or_default();
                    let mut d = body(c, Some(&p), true);
                    d["id"] = json!(c.id);
                    d["type"] = json!(kind(c));
                    push(d, vec![Told::Id(n), Told::Name(n), Told::Piece(n, p)]);
                }
                Opening::IdOnly => {
                    push(json!({"id": c.id, "type": kind(c)}), vec![Told::Id(n)]);
                    let p = pieces.next().cloned().unwrap_or_default();
                    push(body(c, Some(&p), true), vec![Told::Name(n), Told::Piece(n, p)]);
                }
                Opening::NameFirst => {
                    let p = pieces.next().cloned().unwrap_or_default();
                    let mut d = body(c, Some(&p), true);
                    d["type"] = json!(kind(c));
                    push(d, vec![Told::Name(n), Told::Piece(n, p)]);
                    let mut d = body(c, None, round.restate_name);
                    d["id"] = json!(c.id);
                    push(d, vec![Told::Id(n)]);
                }
            }
            for p in pieces {
                push(body(c, Some(p), round.restate_name), vec![Told::Piece(n, p.clone())]);
            }
            q
        })
        .collect();
    let mut frames = Vec::new();
    // Arguments of no call: in a chunk of their own, beside text, or — where
    // chunks carry two deltas — beside the first call's opening.
    let mut stray = round.stray.as_ref().map(|text| (json!({"index": 0, "function": {"arguments": text}}), Told::Stray(text.clone())));
    if !round.pair_chunks
        && let Some((d, told)) = stray.take()
    {
        let mut delta = json!({"tool_calls": [d]});
        if round.noise[0] % 2 == 1 {
            delta["content"] = json!("·");
        }
        frames.push(Frame { event: chunk(delta, Value::Null, round.usage_every_chunk), told: vec![told] });
    }
    let mut order = round.order.iter().peekable();
    while let Some(&i) = order.next() {
        let Some((d, mut told)) = queues[i].pop_front() else { continue };
        let mut deltas = vec![d];
        if let Some((d, t)) = stray.take() {
            deltas.insert(0, d);
            told.insert(0, t);
        }
        // Two calls' deltas in one chunk.
        if round.pair_chunks
            && let Some(&&j) = order.peek()
            && j != i
            && let Some((d2, told2)) = queues[j].pop_front()
        {
            order.next();
            deltas.push(d2);
            told.extend(told2);
        }
        frames.push(Frame { event: chunk(json!({"tool_calls": deltas}), Value::Null, round.usage_every_chunk), told });
    }
    // Calls continued after other content: a custom call's later text is
    // late; a function call's JSON tail continues it.
    let late = |c: &GenCall| c.late.is_some() || c.json_tail_late;
    if round.calls.iter().any(late) {
        let text_at = frames.len();
        frames.push(Frame { event: chunk(json!({"content": "·"}), Value::Null, round.usage_every_chunk), told: vec![] });
        for (i, c) in round.calls.iter().enumerate() {
            let n = Whose::Call(base + i);
            let at = |mut d: Value, k: usize| {
                if round.unstable {
                    d["id"] = json!(c.id);
                    if let Some(k) = unstable_index(round, i, k) {
                        d["index"] = json!(k);
                    }
                } else {
                    d["index"] = json!(upstream_index[i]);
                }
                json!({"tool_calls": [d]})
            };
            if let Some(text) = &c.late {
                let d = at(json!({"custom": {"input": text}}), 7);
                frames.push(Frame { event: chunk(d, Value::Null, round.usage_every_chunk), told: vec![Told::Late(n, text.clone())] });
            }
            if c.json_tail_late {
                let tail = if c.pieces.len() > 1 { c.pieces.last().cloned().unwrap_or_default() } else { String::new() };
                let d = at(json!({"function": {"arguments": tail}}), 8);
                frames.push(Frame { event: chunk(d, Value::Null, round.usage_every_chunk), told: vec![Told::Piece(n, tail)] });
            }
        }
        // Where chunks carry two pieces, the text rides with the first call
        // continued after it.
        if round.pair_chunks && frames.len() > text_at + 1 {
            frames.remove(text_at);
            let mut v: Value = serde_json::from_str(&frames[text_at].event.data).unwrap_or_default();
            v["choices"][0]["delta"]["content"] = json!("·");
            frames[text_at].event.data = v.to_string();
        }
    }
    if round.finished && round.text_after_finish {
        // The finish, then text, then the usage on a chunk of its own.
        frames.push(Frame { event: chunk(json!({}), json!("tool_calls"), false), told: vec![] });
        frames.push(Frame { event: chunk(json!({"content": "·"}), Value::Null, false), told: vec![] });
        let usage = json!({"id": "chatcmpl-u", "object": "chat.completion.chunk", "created": 1, "model": "u", "choices": [], "usage": usage_chat()});
        frames.push(Frame { event: SseEvent { event_type: None, data: usage.to_string(), id: None }, told: vec![] });
        frames.push(Frame { event: SseEvent { event_type: None, data: "[DONE]".into(), id: None }, told: vec![] });
    } else if round.finished {
        frames.push(Frame { event: chunk(json!({}), json!("tool_calls"), true), told: vec![] });
        frames.push(Frame { event: SseEvent { event_type: None, data: "[DONE]".into(), id: None }, told: vec![] });
    }
    frames
}

fn responses_frames(round: &GenRound, base: usize, r: usize) -> Vec<Frame> {
    // One queue of events per item — the server tool's first, where there is
    // one — each event without its address yet: (name, data, told, opens).
    type Step = (&'static str, Value, Vec<Told>, bool);
    let mut items: Vec<(String, std::collections::VecDeque<Step>)> = Vec::new();
    if round.server_tool {
        // A tool on a remote MCP server, which the upstream calls itself.
        let s = Whose::ServerTool(r);
        let id = format!("mcp_{r}");
        let item = |status: &str, args: &str| {
            json!({"id": id, "type": "mcp_call", "name": "web_search", "server_label": "srv", "arguments": args, "status": status})
        };
        let q = [
            ("response.output_item.added", json!({"item": item("in_progress", "")}), vec![Told::Id(s), Told::Name(s)], true),
            ("response.mcp_call_arguments.delta", json!({"delta": SERVER_TOOL_INPUT}), vec![Told::Piece(s, SERVER_TOOL_INPUT.into())], false),
            ("response.mcp_call_arguments.done", json!({"arguments": SERVER_TOOL_INPUT}), vec![], false),
            ("response.output_item.done", json!({"item": item("completed", SERVER_TOOL_INPUT)}), vec![], false),
        ];
        items.push((id.clone(), q.into_iter().collect()));
    }
    for (k, c) in round.calls.iter().enumerate() {
        let n = Whose::Call(base + k);
        let whole = c.pieces.concat();
        let (item_type, text_key, delta, done, item_id) = if c.freeform {
            ("custom_tool_call", "input", "response.custom_tool_call_input.delta", "response.custom_tool_call_input.done", format!("ctc_{k}"))
        } else {
            ("function_call", "arguments", "response.function_call_arguments.delta", "response.function_call_arguments.done", format!("fc_{k}"))
        };
        let item = |status: &str, text: &str| {
            json!({"id": item_id, "type": item_type, "call_id": c.id, "name": c.name, text_key: text, "status": status})
        };
        let mut q: std::collections::VecDeque<Step> = std::collections::VecDeque::new();
        q.push_back(("response.output_item.added", json!({"item": item("in_progress", "")}), vec![Told::Id(n), Told::Name(n)], true));
        // A call's done states its whole text: what its deltas did not
        // stream is read from there. One stating something else — no
        // extension of what streamed — tells nothing.
        let streamed = if c.conflicting_done { c.pieces.len() } else { c.streamed };
        for p in &c.pieces[..streamed] {
            q.push_back((delta, json!({"delta": p}), vec![Told::Piece(n, p.clone())], false));
        }
        let (stated, rest) = if c.conflicting_done {
            (format!("{{\"cmd\":\"rm -rf /\"}}{whole}"), String::new())
        } else {
            (whole.clone(), c.pieces[streamed..].concat())
        };
        q.push_back((done, json!({ text_key: stated }), vec![Told::Piece(n, rest)], false));
        if let Some(late) = &c.late {
            q.push_back((delta, json!({"delta": late}), vec![Told::Late(n, late.clone())], false));
        }
        q.push_back(("response.output_item.done", json!({"item": item("completed", &stated)}), vec![], false));
        items.push((item_id, q));
    }
    // Item by item — or, where the round interleaves, picked among the items
    // with events left, each item's own events in order.
    let mut steps: Vec<(usize, Step)> = Vec::new();
    let mut pick = 0;
    while let Some(first) = items.iter().position(|(_, q)| !q.is_empty()) {
        let open: Vec<usize> = (0..items.len()).filter(|&i| !items[i].1.is_empty()).collect();
        let i = if round.pair_chunks { open[round.noise[pick % round.noise.len()] % open.len()] } else { first };
        pick += 1;
        if let Some(step) = items[i].1.pop_front() {
            steps.push((i, step));
        }
    }
    // An item's `output_index` is its place in the order items opened.
    let mut output_index = vec![usize::MAX; items.len()];
    let mut opened = 0;
    for (i, (_, _, _, opens)) in &steps {
        if *opens {
            output_index[*i] = opened;
            opened += 1;
        }
    }

    let mut frames = Vec::new();
    let mut ev = |name: &str, data: Value, told: Vec<Told>| {
        frames.push(Frame { event: SseEvent { event_type: Some(name.to_string()), data: data.to_string(), id: None }, told })
    };
    ev("response.created", json!({"type": "response.created", "response": {"id": "resp_u", "status": "in_progress"}}), vec![]);
    if let Some(text) = &round.stray {
        let delta = "response.function_call_arguments.delta";
        ev(delta, json!({"type": delta, "output_index": 0, "item_id": "fc_stray", "delta": text}), vec![Told::Stray(text.clone())]);
    }
    // The first client call's item, where it opens without its place.
    let unindexed = round.unindexed_open.then_some(usize::from(round.server_tool));
    for (j, (i, (name, mut data, told, opens))) in steps.into_iter().enumerate() {
        data["type"] = json!(name);
        // An event names its item by place and id, by place alone, or by id
        // alone — every one of which a client can apply it by. An item opened
        // without its place is named by both.
        let style = if unindexed == Some(i) { 0 } else if round.unstable { round.noise[(j + 1) % round.noise.len()] % 3 } else { 0 };
        if !(opens && unindexed == Some(i)) && (opens || name == "response.output_item.done" || style != 2) {
            data["output_index"] = json!(output_index[i]);
        }
        if !opens && name != "response.output_item.done" && style != 1 {
            data["item_id"] = json!(items[i].0);
        }
        ev(name, data, told);
    }
    // A delta naming two items — one's id, the other's place — is neither's.
    if round.unstable && items.len() > 1 {
        let delta = "response.function_call_arguments.delta";
        ev(delta, json!({"type": delta, "output_index": output_index[1], "item_id": items[0].0, "delta": "x"}), vec![Told::Stray("x".into())]);
    }
    if round.finished {
        ev("response.completed", json!({"type": "response.completed", "response": {"id": "resp_u", "status": "completed", "output": [],
            "usage": {"input_tokens": 5, "output_tokens": 3, "total_tokens": 8}}}), vec![]);
    }
    frames
}

fn anthropic_frames(round: &GenRound, base: usize, r: usize) -> Vec<Frame> {
    let mut frames = Vec::new();
    let mut ev = |name: &str, data: Value, told: Vec<Told>| {
        frames.push(Frame { event: SseEvent { event_type: Some(name.to_string()), data: data.to_string(), id: None }, told })
    };
    ev("message_start", json!({"type": "message_start", "message": {"id": "msg_u", "type": "message", "role": "assistant",
        "content": [], "usage": {"input_tokens": 5, "output_tokens": 0}}}), vec![]);
    let mut block = 0;
    if let Some(text) = &round.stray {
        ev("content_block_delta", json!({"type": "content_block_delta", "index": block,
            "delta": {"type": "input_json_delta", "partial_json": text}}), vec![Told::Stray(text.clone())]);
    }
    if round.server_tool {
        let s = Whose::ServerTool(r);
        ev("content_block_start", json!({"type": "content_block_start", "index": block,
            "content_block": {"type": "server_tool_use", "id": format!("srvtoolu_{r}"), "name": "web_search", "input": {}}}),
            vec![Told::Id(s), Told::Name(s)]);
        ev("content_block_delta", json!({"type": "content_block_delta", "index": block,
            "delta": {"type": "input_json_delta", "partial_json": SERVER_TOOL_INPUT}}), vec![Told::Piece(s, SERVER_TOOL_INPUT.into())]);
        ev("content_block_stop", json!({"type": "content_block_stop", "index": block}), vec![]);
        block += 1;
    }
    for (k, c) in round.calls.iter().enumerate() {
        let n = Whose::Call(base + k);
        ev("content_block_start", json!({"type": "content_block_start", "index": block,
            "content_block": {"type": "tool_use", "id": c.id, "name": c.name, "input": {}}}), vec![Told::Id(n), Told::Name(n)]);
        for p in &c.pieces {
            ev("content_block_delta", json!({"type": "content_block_delta", "index": block,
                "delta": {"type": "input_json_delta", "partial_json": p}}), vec![Told::Piece(n, p.clone())]);
        }
        ev("content_block_stop", json!({"type": "content_block_stop", "index": block}), vec![]);
        block += 1;
    }
    if round.finished {
        ev("message_delta", json!({"type": "message_delta", "delta": {"stop_reason": "tool_use", "stop_sequence": null},
            "usage": {"output_tokens": 3}}), vec![]);
        ev("message_stop", json!({"type": "message_stop"}), vec![]);
    }
    frames
}

fn gemini_frames(round: &GenRound, base: usize) -> Vec<Frame> {
    let n_calls = round.calls.len();
    round
        .calls
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let n = Whose::Call(base + i);
            let whole = c.pieces.concat();
            let args: Value = serde_json::from_str(&whole).unwrap_or(json!({}));
            let mut call = json!({"name": c.name, "args": args});
            let mut told = vec![Told::Name(n), Told::Piece(n, whole)];
            if c.id_sent {
                call["id"] = json!(c.id);
                told.push(Told::Id(n));
            }
            let mut candidate = json!({"content": {"role": "model", "parts": [{"functionCall": call}]}, "index": 0});
            let mut v = json!({});
            if i + 1 == n_calls && round.finished {
                candidate["finishReason"] = json!("STOP");
                v["usageMetadata"] = json!({"promptTokenCount": 5, "candidatesTokenCount": 3, "totalTokenCount": 8});
            }
            v["candidates"] = json!([candidate]);
            Frame { event: SseEvent { event_type: None, data: v.to_string(), id: None }, told }
        })
        .collect()
}

/// A response's finish, with its usage, on its own.
fn finish_frames(upstream: ApiVersion) -> Vec<Frame> {
    let frame = |event_type: Option<&str>, data: Value| Frame {
        event: SseEvent { event_type: event_type.map(str::to_string), data: data.to_string(), id: None },
        told: vec![],
    };
    match upstream {
        ApiVersion::ChatCompletions => vec![
            frame(None, json!({"id": "chatcmpl-u", "object": "chat.completion.chunk", "created": 1, "model": "u",
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}], "usage": usage_chat()})),
            Frame { event: SseEvent { event_type: None, data: "[DONE]".into(), id: None }, told: vec![] },
        ],
        ApiVersion::Responses => vec![frame(Some("response.completed"), json!({"type": "response.completed",
            "response": {"id": "resp_u", "status": "completed", "output": [], "usage": {"input_tokens": 5, "output_tokens": 3, "total_tokens": 8}}}))],
        ApiVersion::AnthropicMessages => vec![
            frame(Some("message_delta"), json!({"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": null},
                "usage": {"output_tokens": 3}})),
            frame(Some("message_stop"), json!({"type": "message_stop"})),
        ],
        ApiVersion::GoogleGemini => vec![frame(None, json!({"candidates": [{"content": {"role": "model", "parts": []}, "finishReason": "STOP", "index": 0}],
            "usageMetadata": {"promptTokenCount": 5, "candidatesTokenCount": 3, "totalTokenCount": 8}}))],
    }
}

/// The round's frames — as far as the stream carries them, and an upstream
/// error where one ends it.
fn frames_of(upstream: ApiVersion, round: &GenRound, base: usize, r: usize) -> Vec<Frame> {
    if round.error_at.is_some() && round.error_after_finish {
        let finished = GenRound { finished: true, ..round.clone() };
        let mut frames = chat_frames(&finished, base);
        frames.pop();
        if let Some(finish) = frames.last_mut() {
            let mut v: Value = serde_json::from_str(&finish.event.data).unwrap_or_default();
            if let Some(o) = v.as_object_mut() {
                o.remove("usage");
            }
            finish.event.data = v.to_string();
        }
        frames.push(Frame { event: error_frame(upstream, false), told: vec![] });
        return frames;
    }
    let mut frames = match upstream {
        ApiVersion::ChatCompletions => chat_frames(round, base),
        ApiVersion::Responses => responses_frames(round, base, r),
        ApiVersion::AnthropicMessages => anthropic_frames(round, base, r),
        ApiVersion::GoogleGemini => gemini_frames(round, base),
    };
    if let Some(at) = round.error_at {
        frames.truncate(at % (frames.len() + 1));
        frames.push(Frame { event: error_frame(upstream, round.failed), told: vec![] });
        if round.after_error {
            frames.extend(finish_frames(upstream));
        }
    } else if !round.finished {
        frames.truncate(round.cut_at % (frames.len() + 1));
    }
    frames
}

/// A call as the stream carried it: what its frames told a reader.
#[derive(Debug, Clone)]
struct Carried {
    id: String,
    name: String,
    freeform: bool,
    text: String,
    /// Whether the stream sent text after the call's end — bytes nobody gets.
    late_withheld: bool,
    /// The response (agent-loop round) the call is in.
    round: usize,
    /// A server tool's call: the upstream runs it; no client is given it.
    server: bool,
}

/// What the stream carried: its calls, in the order it opened them, and
/// whether it sent arguments of no call (bytes nobody gets) — in any round,
/// and in the one the client is given.
struct CarriedStream {
    calls: Vec<Carried>,
    stray: bool,
    stray_to_client: bool,
}

fn carried(stream: &GenStream) -> CarriedStream {
    let calls: Vec<&GenCall> = stream.rounds.iter().flat_map(|r| &r.calls).collect();
    let mut told: Vec<(Whose, Carried)> = Vec::new();
    let (mut stray, mut stray_to_client) = (false, false);
    let mut base = 0;
    let last = stream.rounds.len() - 1;
    for (r, round) in stream.rounds.iter().enumerate() {
        for frame in frames_of(stream.upstream, round, base, r) {
            for t in frame.told {
                let whose = match &t {
                    Told::Id(w) | Told::Name(w) | Told::Piece(w, _) | Told::Late(w, _) => *w,
                    Told::Stray(p) => {
                        stray |= !p.is_empty();
                        stray_to_client |= !p.is_empty() && r == last;
                        continue;
                    }
                };
                let at = match told.iter().position(|(w, _)| *w == whose) {
                    Some(at) => at,
                    None => {
                        let (freeform, server) = match whose {
                            Whose::Call(n) => (calls[n].freeform, false),
                            Whose::ServerTool(_) => (false, true),
                        };
                        let fresh = Carried { id: String::new(), name: String::new(), freeform, text: String::new(), late_withheld: false, round: r, server };
                        told.push((whose, fresh));
                        told.len() - 1
                    }
                };
                let c = &mut told[at].1;
                match (t, whose) {
                    (Told::Id(_), Whose::Call(n)) => c.id.clone_from(&calls[n].id),
                    (Told::Id(_), Whose::ServerTool(r)) if stream.upstream == ApiVersion::Responses => c.id = format!("mcp_{r}"),
                    (Told::Id(_), Whose::ServerTool(r)) => c.id = format!("srvtoolu_{r}"),
                    (Told::Name(_), Whose::Call(n)) => c.name.clone_from(&calls[n].name),
                    (Told::Name(_), Whose::ServerTool(_)) => c.name = "web_search".into(),
                    (Told::Piece(_, p), _) => c.text.push_str(&p),
                    (Told::Late(_, p), _) => c.late_withheld |= !p.is_empty(),
                    (Told::Stray(_), _) => {}
                }
            }
        }
        base += round.calls.len();
    }
    CarriedStream { calls: told.into_iter().map(|(_, c)| c).collect(), stray, stray_to_client }
}

// ─── The pipeline's per-frame sequence ──────────────────────────────────────

/// A policy holding every call, rewriting `REWRITE_FROM` wherever a call's
/// arguments carry it, reading calls by `upstream`'s grammar.
fn policy(upstream: ApiVersion) -> BlockAccumulator {
    let rule = serde_json::from_value(json!({
        "id": "T-882",
        "phase": "response", "scope": "tool_calls", "match": [],
        "action": {"kind": "replace", "regex": REWRITE_FROM, "with": REWRITE_TO}, "risk": "low"
    }))
    .expect("rule");
    BlockAccumulator::new(
        BlockInterests { buffer_tool_blocks: true, buffer_text_blocks: true, buffer_thinking_blocks: false },
        vec![rule],
        Default::default(),
        vec![],
        None,
        None,
        false,
        crate::scripting::ScriptFailMode::Open,
        vec![],
        false,
        false,
        upstream,
    )
}

fn emit(chunks: Vec<bytes::Bytes>, bytes: &mut Vec<u8>) {
    chunks.iter().for_each(|c| bytes.extend_from_slice(c));
}

/// Run `stream` into `client` as the streaming pipeline does — with a policy
/// holding calls (`held`) or on the fast path — returning the audit and the
/// client's bytes. A stream of several responses is an agent loop: every
/// round is read (by the one parser, the audit and policy), and the client is
/// given the last — the earlier rounds' calls are the ones the loop ran.
fn run(stream: &GenStream, client: ApiVersion, held: bool) -> (TransformState, String) {
    let upstream = stream.upstream;
    let mut audit = TransformState::new(upstream);
    let mut parser = StreamParser::new(upstream);
    let mut acc = held.then(|| policy(upstream));
    let facts = crate::api::domain_request::ClientToolFacts { freeform: [FREEFORM_TOOL.to_string()].into(), ..Default::default() };
    let mut out = EventEmitter::new(client, upstream, "m", "req-p", None, None, 0, 0).with_client_tools(&facts);
    let mut bytes: Vec<u8> = Vec::new();
    let pass_through = client == upstream;
    let mut base = 0;
    let last = stream.rounds.len() - 1;
    for (r, round) in stream.rounds.iter().enumerate() {
        // An earlier round's output is the loop's: held, and never replayed to
        // the client.
        let to_client = r == last;
        for Frame { event: frame, .. } in frames_of(upstream, round, base, r) {
            let events = parser.parse(&frame);
            out.observe_upstream(&frame);
            match &mut acc {
                Some(acc) => {
                    let held: Vec<BufferedEvent> = if events.is_empty() {
                        let opens = frame_opens_container(&frame, upstream);
                        acc.process_raw(frame, opens)
                    } else {
                        let raws = split_frame(&frame, upstream, &events, pass_through);
                        let mut held = Vec::new();
                        for (de, raw) in events.into_iter().zip(raws) {
                            audit.process_event(&de);
                            held.extend(acc.process(de, raw));
                        }
                        held
                    };
                    if to_client {
                        held.iter().for_each(|b| emit(out.process_buffered(b), &mut bytes));
                    }
                }
                None => {
                    events.iter().for_each(|de| audit.process_event(de));
                    if to_client {
                        emit(fast_path_frame(&mut out, upstream, &events, &frame), &mut bytes);
                    }
                }
            }
        }
        for end in parser.finish() {
            audit.process_event(&end);
            match &mut acc {
                Some(acc) => {
                    let held = acc.process(end, None);
                    if to_client {
                        held.iter().for_each(|b| emit(out.process_buffered(b), &mut bytes));
                    }
                }
                None if to_client => emit(out.process_streaming_event(&end, None), &mut bytes),
                None => {}
            }
        }
        // An agent loop's round keeps what the accumulator still holds.
        if stream.rounds.len() > 1
            && let Some(acc) = &mut acc
        {
            let held = acc.flush();
            if to_client {
                held.iter().for_each(|b| emit(out.process_buffered(b), &mut bytes));
            }
        }
        base += round.calls.len();
    }
    if let Some(acc) = &mut acc {
        for b in acc.flush() {
            emit(out.process_buffered(&b), &mut bytes);
        }
    }
    emit(out.flush(), &mut bytes);
    // The pipeline's zero-token guard, then its record of the emitter's work.
    match close_a_stream_that_never_ended(&mut out) {
        UnendedStream::Ended => {}
        UnendedStream::Empty(chunks) | UnendedStream::CutShort(chunks) => emit(chunks, &mut bytes),
    }
    record_emitter_withheld(&mut audit, &mut out);
    fold_accumulator(&mut audit, acc.as_ref());
    (audit, String::from_utf8_lossy(&bytes).into_owned())
}

// ─── What each client ends with ─────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
struct ClientCall {
    id: String,
    name: String,
    /// A custom call's text (Chat custom form, Responses custom item), or the
    /// arguments string / object another client was given.
    args: Value,
}

/// A client's stream, read the way its SDK reads it.
#[derive(Debug, Default)]
struct ClientView {
    calls: Vec<ClientCall>,
    text: String,
    /// The stream's ends: its finish, the gateway's close, or an error.
    terminals: usize,
    /// Whether the (first) end was an error.
    ended_in_error: bool,
    /// Whether the stream opened a message (Anthropic `message_start`): one
    /// that did not was an empty stream.
    opened: bool,
    /// What went wrong with the stream's shape: something after its end, a
    /// block stopped twice or never, a call index out of order.
    shape: Vec<String>,
    /// Responses: call items the client was given whole (`output_item.done`)
    /// without a statement of their arguments (`…arguments.done`,
    /// `custom_tool_call_input.done`) before.
    unstated: usize,
}

/// The `data:` lines of a client's stream, each with its `event:` name.
fn frames(body: &str) -> Vec<(Option<String>, String)> {
    let mut out = Vec::new();
    let mut name = None;
    for line in body.lines() {
        if let Some(n) = line.strip_prefix("event: ") {
            name = Some(n.to_string());
        } else if let Some(d) = line.strip_prefix("data: ") {
            out.push((name.take(), d.to_string()));
        }
    }
    out
}

/// A Chat client accumulates calls by `index`, in the order indexes first
/// appear; they must run 0, 1, 2 …, one call per index, one kind per call.
/// Its stream ends at `[DONE]`, or at an error chunk (with the `[DONE]` that
/// may follow it).
fn read_chat(body: &str) -> ClientView {
    let mut view = ClientView::default();
    let mut kinds: Vec<String> = Vec::new();
    let mut finishes = 0;
    let mut after_error = false;
    for (_, data) in frames(body) {
        if view.terminals > 0 && !(after_error && data == "[DONE]") {
            view.shape.push(format!("after the end: {data}"));
            continue;
        }
        if data == "[DONE]" {
            if !after_error {
                view.terminals += 1;
            }
            after_error = false;
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(&data) else { continue };
        if v.get("error").is_some() {
            view.terminals += 1;
            view.ended_in_error = true;
            after_error = true;
            continue;
        }
        let choice = &v["choices"][0];
        if !choice["finish_reason"].is_null() {
            finishes += 1;
        }
        if let Some(t) = choice["delta"]["content"].as_str() {
            view.text.push_str(t);
        }
        for tc in choice["delta"]["tool_calls"].as_array().into_iter().flatten() {
            let Some(index) = tc["index"].as_u64() else {
                view.shape.push(format!("a call delta without an index: {tc}"));
                continue;
            };
            let index = index as usize;
            if index > view.calls.len() {
                view.shape.push(format!("index {index} first appears after {} calls", view.calls.len()));
                continue;
            }
            if index == view.calls.len() {
                view.calls.push(ClientCall { args: Value::String(String::new()), ..Default::default() });
                kinds.push(String::new());
            }
            let call = &mut view.calls[index];
            if let Some(id) = tc["id"].as_str() {
                if !call.id.is_empty() && call.id != id {
                    view.shape.push(format!("index {index} carries two ids: {} and {id}", call.id));
                }
                call.id = id.to_string();
            }
            let custom = tc.get("custom").is_some();
            if custom || tc.get("function").is_some() {
                let this = if custom { "custom" } else { "function" };
                if !kinds[index].is_empty() && kinds[index] != this {
                    view.shape.push(format!("index {index} is both {} and {this}", kinds[index]));
                }
                kinds[index] = this.to_string();
            }
            let inner = if custom { &tc["custom"] } else { &tc["function"] };
            if let Some(n) = inner["name"].as_str() {
                call.name = n.to_string();
            }
            let piece = if custom { inner["input"].as_str() } else { inner["arguments"].as_str() };
            if let (Some(p), Value::String(s)) = (piece, &mut call.args) {
                s.push_str(p);
            }
        }
    }
    if finishes > 1 {
        view.shape.push(format!("{finishes} finish reasons"));
    }
    view
}

/// An Anthropic client accumulates a call per `tool_use` block, its input
/// from the block's `input_json_delta`s. Its stream ends at `message_stop`, or
/// at an `error` event; every block it opened is stopped once, before the
/// message stops.
fn read_anthropic(body: &str) -> ClientView {
    let mut view = ClientView::default();
    let mut blocks: std::collections::BTreeMap<u64, (String, ClientCall, usize)> = Default::default();
    for (name, data) in frames(body) {
        if view.terminals > 0 {
            view.shape.push(format!("after the end: {name:?} {data}"));
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(&data) else { continue };
        let index = v["index"].as_u64().unwrap_or(u64::MAX);
        match v["type"].as_str() {
            Some("message_start") => view.opened = true,
            Some("error") => {
                view.terminals += 1;
                view.ended_in_error = true;
            }
            Some("message_stop") => {
                view.terminals += 1;
                for (i, (_, _, stops)) in &blocks {
                    if *stops == 0 {
                        view.shape.push(format!("block {i} never stopped before the message stopped"));
                    }
                }
            }
            Some("content_block_start") => {
                let kind = v["content_block"]["type"].as_str().unwrap_or_default().to_string();
                if blocks.contains_key(&index) {
                    view.shape.push(format!("block {index} started twice"));
                }
                let call = ClientCall {
                    id: v["content_block"]["id"].as_str().unwrap_or_default().to_string(),
                    name: v["content_block"]["name"].as_str().unwrap_or_default().to_string(),
                    args: Value::String(String::new()),
                };
                blocks.insert(index, (kind, call, 0));
            }
            Some("content_block_stop") => match blocks.get_mut(&index) {
                Some((_, _, stops)) => {
                    *stops += 1;
                    if *stops > 1 {
                        view.shape.push(format!("block {index} stopped twice"));
                    }
                }
                None => view.shape.push(format!("block {index} stopped, never started")),
            },
            Some("content_block_delta") => {
                let Some((kind, call, stops)) = blocks.get_mut(&index) else {
                    view.shape.push(format!("delta for block {index}, never started"));
                    continue;
                };
                if *stops > 0 {
                    view.shape.push(format!("delta for block {index} after it stopped"));
                }
                if let Some(t) = v["delta"]["text"].as_str() {
                    view.text.push_str(t);
                }
                if let Some(p) = v["delta"]["partial_json"].as_str() {
                    if kind != "tool_use" && kind != "server_tool_use" {
                        view.shape.push(format!("input for a {kind} block {index}"));
                    }
                    if let Value::String(s) = &mut call.args {
                        s.push_str(p);
                    }
                }
            }
            _ => {}
        }
    }
    view.calls = blocks.into_values().filter(|(k, ..)| k == "tool_use").map(|(_, c, _)| c).collect();
    view
}

/// A Responses client keeps each call item as its `output_item.done` states
/// it. Its stream ends at `response.completed` / `.incomplete` / `.failed`, or
/// at an `error` event. Every statement of a call's whole arguments names an
/// item the client holds, and says what that item's done does.
fn read_responses(body: &str) -> ClientView {
    let mut view = ClientView::default();
    let mut items: std::collections::HashMap<u64, String> = Default::default();
    let mut stated: Vec<(u64, Value)> = Vec::new();
    let mut finals: std::collections::HashMap<u64, Value> = Default::default();
    for (_, data) in frames(body) {
        if view.terminals > 0 {
            view.shape.push(format!("after the end: {data}"));
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(&data) else { continue };
        let kind = v["type"].as_str().unwrap_or_default();
        if kind == "response.output_item.added"
            && let Some(oi) = v["output_index"].as_u64()
        {
            items.insert(oi, v["item"]["id"].as_str().unwrap_or_default().to_string());
        }
        if matches!(kind, "response.function_call_arguments.done" | "response.custom_tool_call_input.done" | "response.mcp_call_arguments.done") {
            let oi = v["output_index"].as_u64().or_else(|| {
                let id = v["item_id"].as_str()?;
                items.iter().find(|(_, known)| known.as_str() == id).map(|(oi, _)| *oi)
            });
            let text = if kind == "response.custom_tool_call_input.done" { v["input"].clone() } else { v["arguments"].clone() };
            match oi.filter(|oi| items.contains_key(oi)) {
                Some(oi) => stated.push((oi, text)),
                None => view.shape.push(format!("a statement about an item the client never got: {data}")),
            }
        }
        if kind == "response.output_item.done"
            && let Some(oi) = v["output_index"].as_u64()
        {
            let item = &v["item"];
            let text = if item["type"] == "custom_tool_call" { item["input"].clone() } else { item["arguments"].clone() };
            if matches!(item["type"].as_str(), Some("function_call" | "custom_tool_call")) && !stated.iter().any(|(s, _)| *s == oi) {
                view.unstated += 1;
            }
            finals.insert(oi, text);
        }
        match v["type"].as_str() {
            Some("response.completed" | "response.incomplete") => view.terminals += 1,
            Some("response.failed") => {
                view.terminals += 1;
                view.ended_in_error = true;
            }
            Some("error") => {
                view.terminals += 1;
                view.ended_in_error = true;
            }
            Some("response.output_text.delta") => view.text.push_str(v["delta"].as_str().unwrap_or_default()),
            Some("response.output_item.done") => {
                let item = &v["item"];
                let args = match item["type"].as_str() {
                    Some("function_call") => item["arguments"].clone(),
                    Some("custom_tool_call") => item["input"].clone(),
                    _ => continue,
                };
                view.calls.push(ClientCall {
                    id: item["call_id"].as_str().unwrap_or_default().to_string(),
                    name: item["name"].as_str().unwrap_or_default().to_string(),
                    args,
                });
            }
            _ => {}
        }
    }
    for (oi, text) in stated {
        if let Some(done) = finals.get(&oi)
            && *done != text
        {
            view.shape.push(format!("item {oi}'s arguments are stated as {text} and as {done}"));
        }
    }
    view
}

/// A Gemini client takes each `functionCall` part as one call. Its stream ends
/// at the candidate carrying a `finishReason`, or at an error.
fn read_gemini(body: &str) -> ClientView {
    let mut view = ClientView::default();
    for (_, data) in frames(body) {
        if view.terminals > 0 {
            view.shape.push(format!("after the end: {data}"));
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(&data) else { continue };
        if v.get("error").is_some() {
            view.terminals += 1;
            view.ended_in_error = true;
            continue;
        }
        for part in v["candidates"][0]["content"]["parts"].as_array().into_iter().flatten() {
            if let Some(t) = part["text"].as_str() {
                view.text.push_str(t);
            }
            if let Some(fc) = part.get("functionCall") {
                view.calls.push(ClientCall {
                    id: fc["id"].as_str().unwrap_or_default().to_string(),
                    name: fc["name"].as_str().unwrap_or_default().to_string(),
                    args: fc["args"].clone(),
                });
            }
        }
        if v["candidates"][0].get("finishReason").is_some() {
            view.terminals += 1;
        }
    }
    view
}

fn read_client(client: ApiVersion, body: &str) -> ClientView {
    match client {
        ApiVersion::ChatCompletions => read_chat(body),
        ApiVersion::AnthropicMessages => read_anthropic(body),
        ApiVersion::Responses => read_responses(body),
        ApiVersion::GoogleGemini => read_gemini(body),
    }
}

// ─── The claim ──────────────────────────────────────────────────────────────

/// A call's arguments as a reader holds them: a custom call's text, or a
/// function call's arguments as JSON (or as the raw string where they are not
/// whole JSON).
#[derive(Debug, Clone, PartialEq)]
enum Args {
    Text(String),
    Json(Value),
    Raw(String),
}

fn args_of(freeform: bool, v: &Value) -> Args {
    let parsed = match v {
        Value::String(s) => serde_json::from_str::<Value>(s).ok(),
        other => Some(other.clone()),
    };
    if freeform {
        // The custom form states the text itself; every other states it as
        // the domain's `{"input": <text>}`.
        if let Some(t) = parsed.as_ref().and_then(|p| p.get("input")).and_then(Value::as_str) {
            return Args::Text(t.to_string());
        }
        return match v {
            Value::String(s) => Args::Text(s.clone()),
            other => Args::Raw(other.to_string()),
        };
    }
    match (parsed, v) {
        (Some(p), _) => Args::Json(p),
        (None, Value::String(s)) => Args::Raw(s.clone()),
        (None, other) => Args::Raw(other.to_string()),
    }
}

/// The arguments `text` stands for, as a reader holds them — rewritten where
/// a policy holding calls rewrites them: a custom call's text, or arguments
/// that are whole JSON (policy rewrites fields; arguments the stream cut
/// before they were JSON have none).
fn carried_args(freeform: bool, text: &str, held: bool) -> Args {
    let args = if freeform { Args::Text(text.to_string()) } else { args_of(false, &Value::String(text.to_string())) };
    match args {
        Args::Raw(_) => args,
        _ if held => {
            let text = text.replace(REWRITE_FROM, REWRITE_TO);
            if freeform { Args::Text(text) } else { args_of(false, &Value::String(text)) }
        }
        _ => args,
    }
}

fn rewritten(text: &str, held: bool) -> String {
    if held { text.replace(REWRITE_FROM, REWRITE_TO) } else { text.to_string() }
}

/// Whether `got` is `whole` cut short (policy read the call, or the client's
/// block closed, before its later bytes came), as policy rewrote it.
fn is_cut_short(got: &Args, whole: &str, freeform: bool, held: bool, client: ApiVersion) -> bool {
    let prefixes = whole.char_indices().map(|(i, _)| &whole[..i]);
    match got {
        Args::Text(t) if freeform => prefixes.map(|p| rewritten(p, held)).any(|p| p == *t),
        // Policy rewrites fields: a prefix that is not yet JSON has none.
        Args::Raw(s) => prefixes.map(|p| (p, rewritten(p, held))).any(|(p, r)| p == s || r == *s),
        // A Gemini call's `args` is an object: a cut-short one is whatever its
        // builder makes of it.
        Args::Json(_) | Args::Text(_) => client == ApiVersion::GoogleGemini,
    }
}

fn check(stream: &GenStream, client: ApiVersion, held: bool) -> Result<(), String> {
    let (audit, body) = run(stream, client, held);
    let CarriedStream { calls: expected, stray, stray_to_client } = carried(stream);

    // The audit: exactly the calls the stream carried — server tools' too —
    // each whole and apart.
    let recorded = &audit.accumulated_tool_calls;
    if recorded.len() != expected.len() {
        return Err(format!("audit recorded {} calls, the stream carried {}: {recorded:?}", recorded.len(), expected.len()));
    }
    for (r, want) in recorded.iter().zip(&expected) {
        let args = if want.freeform { crate::api::domain_request::freeform_call_input(&want.text).to_string() } else { want.text.clone() };
        if r.id != want.id
            || r.function_name != want.name
            || r.server_tool != want.server
            || args_of(want.freeform, &Value::String(r.arguments.clone())) != args_of(want.freeform, &Value::String(args))
        {
            return Err(format!("audit holds {r:?} for {want:?}"));
        }
    }
    let withheld_records = |n: usize| {
        let record = TransformState::arguments_withheld(n);
        audit.response_injection_blocks.iter().filter(|b| b.transform == record.transform && b.content == record.content).count()
    };

    let view = read_client(client, &body);
    let pass_through = client == stream.upstream;
    if !view.shape.is_empty() {
        return Err(format!("the client's stream is misshapen: {:?}\n{body}", view.shape));
    }
    // A pass-through Responses client is given every call item's statement of
    // its arguments, as the upstream sent one for each.
    if pass_through && client == ApiVersion::Responses && view.unstated > 0 {
        return Err(format!("{} call items reached the client without their done statement\n{body}", view.unstated));
    }
    // The stream's end: exactly one, or none where the stream was cut short
    // and no one closes it.
    let closes_cut_short = client == ApiVersion::AnthropicMessages && !pass_through;
    let ends = if stream.errored() || !stream.cut_short() || closes_cut_short { 1..=1 } else { 0..=1 };
    if client == ApiVersion::Responses && stream.cut_short() && !stream.errored() {
        return Ok(());
    }
    // A translated Anthropic stream that gave the client nothing ends in the
    // gateway's `overloaded_error`.
    let empty = client == ApiVersion::AnthropicMessages && !pass_through && !view.opened;
    if empty && !stream.errored() {
        return if view.terminals == 1 && view.ended_in_error && view.calls.is_empty() {
            Ok(())
        } else {
            Err(format!("an empty stream reached the client as {} ends\n{body}", view.terminals))
        };
    }
    if !ends.contains(&view.terminals) || view.ended_in_error != stream.errored() {
        return Err(format!("the client's stream ended {} times (in error: {}), expected {ends:?} (upstream error: {})\n{body}",
            view.terminals, view.ended_in_error, stream.errored()));
    }
    if stream.errored() {
        return Ok(());
    }

    // The client is given the last round's calls — those the stream named: a
    // call cut short before its name is no call a client can run (a Chat or
    // Anthropic client is given it unnamed, a Gemini client not at all).
    let last = stream.rounds.len() - 1;
    let theirs = |c: &Carried| c.round == last && !c.server;
    let offered: Vec<usize> = (0..expected.len()).filter(|&i| theirs(&expected[i]) && !expected[i].name.is_empty()).collect();
    let unnamed = (0..expected.len()).filter(|&i| theirs(&expected[i]) && expected[i].name.is_empty()).count();
    let mut calls = view.calls.clone();
    let given_unnamed = calls.iter().filter(|c| c.name.is_empty()).count();
    if given_unnamed > unnamed {
        return Err(format!("client has {given_unnamed} unnamed calls, the stream cut {unnamed} before naming them\n{body}"));
    }
    calls.retain(|c| !c.name.is_empty());
    if calls.len() != offered.len() {
        return Err(format!("client has {} calls, the stream offered it {}: {calls:?}\n{body}", calls.len(), offered.len()));
    }
    // A client's call is the upstream's call of its id — or, where the client
    // was given another id, the call the audit row says it was given that id.
    let minted_for = |id: &str| {
        offered.iter().copied().find(|&i| {
            let record = TransformState::client_id(recorded[i].index, id);
            audit.response_injection_blocks.iter().any(|b| b.transform == record.transform && b.content == record.content)
        })
    };
    let mut withheld: Vec<usize> = Vec::new();
    let mut matched: Vec<usize> = Vec::new();
    for got in &calls {
        let at = offered.iter().copied().find(|&i| !expected[i].id.is_empty() && expected[i].id == got.id).or_else(|| minted_for(&got.id));
        let at = match at {
            Some(at) => at,
            // A pass-through client reads the upstream's frames, and a Gemini
            // call's id is optional: a call the upstream never identified is
            // theirs without one.
            None if got.id.is_empty() && (pass_through || client == ApiVersion::GoogleGemini) => {
                match offered.iter().copied().find(|&i| expected[i].id.is_empty() && !matched.contains(&i) && expected[i].name == got.name) {
                    Some(at) => at,
                    None => return Err(format!("client call {got:?} is no call the stream carried\n{body}")),
                }
            }
            None => return Err(format!("client call {got:?} is no call the stream carried, and no record says it was given that id\n{body}")),
        };
        if matched.contains(&at) {
            return Err(format!("client has {} twice\n{body}", expected[at].id));
        }
        matched.push(at);
        let want = &expected[at];
        if got.name != want.name {
            return Err(format!("client names {got:?}, the stream {:?}\n{body}", want.name));
        }
        let have = args_of(want.freeform, &got.args);
        let carried = carried_args(want.freeform, &want.text, held);
        if want.late_withheld {
            withheld.push(at);
        }
        if have == carried {
            continue;
        }
        // A Gemini call's `args` is an object: a function call the stream cut
        // before its arguments were whole JSON has none to give, so whether
        // its later bytes were withheld is the audit row's to say.
        if client == ApiVersion::GoogleGemini && matches!(carried, Args::Raw(_)) {
            if withheld_records(recorded[at].index) == 1 && !withheld.contains(&at) {
                withheld.push(at);
            }
            continue;
        }
        if !is_cut_short(&have, &want.text, want.freeform, held, client) {
            return Err(format!("client holds {have:?} for {}, the audit {:?}\n{body}", want.id, want.text));
        }
        if !withheld.contains(&at) {
            withheld.push(at);
        }
    }
    // Every withheld call is recorded once and told once; no other is either.
    // Arguments of no call are recorded once, whatever round sent them, and
    // told to the client once where its round is the client's.
    if withheld_records(crate::api::domain::DomainEvent::NO_CALL) != usize::from(stray) {
        return Err(format!("arguments of no call are recorded withheld {} times, the stream sent them: {stray}: {:?}\n{body}",
            withheld_records(crate::api::domain::DomainEvent::NO_CALL), audit.response_injection_blocks));
    }
    for &at in &offered {
        let n = recorded[at].index;
        let want = usize::from(withheld.contains(&at));
        if withheld_records(n) != want {
            return Err(format!("{} is recorded withheld {} times, expected {want}: {:?}\n{body}", expected[at].id, withheld_records(n), audit.response_injection_blocks));
        }
    }
    let told = view.text.matches(WITHHELD_NOTICE.trim()).count();
    let owed = withheld.len() + usize::from(stray_to_client);
    if told != owed {
        return Err(format!("the client was told of {told} withheld calls, {owed} were withheld\n{body}"));
    }
    Ok(())
}

fn clients() -> [ApiVersion; 4] {
    [ApiVersion::ChatCompletions, ApiVersion::Responses, ApiVersion::AnthropicMessages, ApiVersion::GoogleGemini]
}

/// Check `stream` into every client, held and not — an agent loop (several
/// rounds) runs only where a policy holds calls, and reaches translated
/// clients only; an upstream opening an item without its place reaches
/// translated clients only (see the module's doc).
fn check_everywhere(stream: &GenStream) -> Result<(), String> {
    let several = stream.rounds.len() > 1;
    let unindexed = stream.rounds.iter().any(|r| r.unindexed_open);
    for client in clients() {
        let pass_through = client == stream.upstream;
        if pass_through && unindexed {
            continue;
        }
        if !several {
            check(stream, client, false).map_err(|e| format!("{client:?}, no policy holding calls: {e}"))?;
        }
        if !(pass_through && several) {
            check(stream, client, true).map_err(|e| format!("{client:?}, a policy holding calls: {e}"))?;
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn every_reader_ends_with_the_calls_the_upstream_made(stream in stream_strategy()) {
        if let Err(e) = check_everywhere(&stream) {
            prop_assert!(false, "{e}\n{stream:#?}");
        }
    }
}

// ─── Seeds the property found, kept as cases ───────────────────────────────

fn gen_call(id: &str, name: &str, freeform: bool, pieces: &[&str], opening: Opening, late: Option<&str>) -> GenCall {
    GenCall {
        id: id.to_string(),
        name: name.to_string(),
        freeform,
        streamed: pieces.len(),
        pieces: pieces.iter().map(|p| (*p).to_string()).collect(),
        opening,
        late: late.map(str::to_string),
        json_tail_late: false,
        id_sent: true,
        conflicting_done: false,
    }
}

fn gen_round(calls: Vec<GenCall>, order: Vec<usize>) -> GenRound {
    GenRound {
        calls,
        order,
        usage_every_chunk: false,
        restate_name: false,
        pair_chunks: false,
        server_tool: false,
        stray: None,
        unstable: false,
        noise: vec![0],
        failed: false,
        after_error: false,
        error_after_finish: false,
        text_after_finish: false,
        unindexed_open: false,
        finished: true,
        cut_at: 0,
        error_at: None,
    }
}

fn holds(stream: &GenStream) {
    if let Err(e) = check_everywhere(stream) {
        panic!("{e}\n{stream:#?}");
    }
}

/// An Anthropic `server_tool_use` block's input is its server tool's call on
/// the audit row — never another call's arguments, never dropped.
#[test]
fn a_server_tool_input_is_its_own_call() {
    let mut round = gen_round(vec![gen_call("call_0_0", "grep", false, &[r#"{"v":""}"#], Opening::Whole, None)], vec![0]);
    round.server_tool = true;
    holds(&GenStream { upstream: ApiVersion::AnthropicMessages, rounds: vec![round] });
}

/// A call whose id comes after its name reaches an Anthropic client under
/// that id, never `""`.
#[test]
fn an_id_after_the_name_reaches_an_anthropic_client() {
    let mut round = gen_round(vec![gen_call("call_0_0", "Read", false, &[r#"{"v":""}"#], Opening::NameFirst, None)], vec![0, 0]);
    round.usage_every_chunk = true;
    holds(&GenStream { upstream: ChatCompletions, rounds: vec![round] });
}

/// A call policy rewrote is written to a Chat pass-through client in the
/// index space of the upstream frames around it.
#[test]
fn a_rewritten_call_keeps_the_chat_index_space() {
    let calls = vec![
        gen_call("call_0_0", "Bash", false, &[r#"{"v":"t k"}"#], Opening::NameFirst, None),
        gen_call("call_0_1", "grep", false, &[r#"{"v":"REWRITE_ME"}"#], Opening::Whole, None),
    ];
    let mut round = gen_round(calls, vec![1, 0, 0]);
    round.usage_every_chunk = true;
    holds(&GenStream { upstream: ChatCompletions, rounds: vec![round] });
}

/// A piece after a custom call's end is recorded once for the call and told
/// once to every client — a pass-through client is not sent it either.
#[test]
fn a_late_piece_is_recorded_and_told_once() {
    let round = gen_round(vec![gen_call("call_0_0", FREEFORM_TOOL, true, &["m"], Opening::Whole, Some("r"))], vec![0]);
    holds(&GenStream { upstream: ApiVersion::Responses, rounds: vec![round] });
}

/// A call held for its id (a Gemini call states none) reaches a Chat client
/// of a stream cut short, under an id the audit row says it was given.
#[test]
fn a_held_call_reaches_a_chat_client_of_a_cut_short_stream() {
    let mut call = gen_call("call_0_0", "Read", false, &[r#"{"v":"a"}"#], Opening::Whole, None);
    call.id_sent = false;
    let mut round = gen_round(vec![call], vec![0]);
    round.finished = false;
    round.cut_at = usize::MAX;
    holds(&GenStream { upstream: ApiVersion::GoogleGemini, rounds: vec![round] });
}

/// A stream cut short after it reported usage (vLLM's continuous usage)
/// still closes an Anthropic client's message, the call it held for its name
/// included.
#[test]
fn a_stream_cut_short_after_usage_closes_an_anthropic_client() {
    let mut round = gen_round(vec![gen_call("call_0_0", "Read", false, &[r#"{"v":"#, r#""a"}"#], Opening::NameFirst, None)], vec![0, 0, 0]);
    round.usage_every_chunk = true;
    round.finished = false;
    round.cut_at = 1;
    holds(&GenStream { upstream: ChatCompletions, rounds: vec![round] });
}

/// An upstream error ends an Anthropic client's stream: nothing follows it —
/// no length close after the error.
#[test]
fn nothing_follows_an_upstream_error() {
    let mut round = gen_round(vec![gen_call("call_0_0", "Read", false, &[r#"{"v":"a"}"#], Opening::Whole, None)], vec![0]);
    round.finished = false;
    round.error_at = Some(1);
    holds(&GenStream { upstream: ChatCompletions, rounds: vec![round] });
}

/// A delta for a closed call carrying no bytes (a trailing `arguments: ""`)
/// withholds nothing: no record, no notice.
#[test]
fn a_delta_without_bytes_withholds_nothing() {
    let mut call = gen_call("call_0_0", "Read", false, &[r#"{"v":"a"}"#], Opening::Whole, None);
    call.json_tail_late = true;
    holds(&GenStream { upstream: ChatCompletions, rounds: vec![gen_round(vec![call], vec![0])] });
}


/// The usage a stream reports after its finish reaches a Chat client before
/// the stream's end — a usage chunk after `data: [DONE]` is one no client
/// reads.
#[test]
fn usage_after_the_finish_reaches_a_chat_client_before_its_end() {
    let round = gen_round(vec![gen_call("call_0_0", "Read", false, &[r#"{"v":""}"#], Opening::Whole, None)], vec![0]);
    holds(&GenStream { upstream: ApiVersion::GoogleGemini, rounds: vec![round] });
}

/// A Gemini client is given the calls it held before an upstream error ends
/// its stream — never after it.
#[test]
fn a_gemini_client_is_given_its_calls_before_an_error() {
    let mut round = gen_round(vec![gen_call("call_0_0", "Read", false, &[r#"{"v":"a"}"#], Opening::Whole, None)], vec![0]);
    round.finished = false;
    round.error_at = Some(4);
    holds(&GenStream { upstream: ApiVersion::AnthropicMessages, rounds: vec![round] });
}

/// A call the upstream never identified (Gemini's id is optional) reaches an
/// Anthropic, Chat or Responses client under an id minted for it, and the
/// audit row says which.
#[test]
fn a_minted_id_is_on_the_audit_row() {
    let mut call = gen_call("call_0_0", "Read", false, &[r#"{"v":"a"}"#], Opening::Whole, None);
    call.id_sent = false;
    holds(&GenStream { upstream: ApiVersion::GoogleGemini, rounds: vec![gen_round(vec![call], vec![0])] });
}

/// A function call continued after text — its item already closed on a
/// Responses client — has its later bytes withheld, recorded and told once.
#[test]
fn a_call_continued_after_its_item_closed_is_withheld_and_said_so() {
    let mut call = gen_call("call_0_0", "Read", false, &[r#"{"v":"a"#, r#""}"#], Opening::Whole, None);
    call.json_tail_late = true;
    holds(&GenStream { upstream: ChatCompletions, rounds: vec![gen_round(vec![call], vec![0])] });
}

/// An agent loop whose final round gave the client nothing ends a translated
/// Anthropic stream in the gateway's `overloaded_error` — never an empty body.
#[test]
fn an_empty_final_round_ends_in_an_overloaded_error() {
    let first = gen_round(vec![gen_call("call_0_0", "Read", false, &[r#"{"v":"a"}"#], Opening::Whole, None)], vec![0]);
    let mut last = gen_round(vec![gen_call("call_1_0", "Read", false, &[r#"{"v":"b"}"#], Opening::Whole, None)], vec![0]);
    last.finished = false;
    last.cut_at = 0;
    holds(&GenStream { upstream: ApiVersion::Responses, rounds: vec![first, last] });
}

/// Arguments sent before any call opened belong to no call: no client is sent
/// them, raw or rendered — a Chat client merging deltas by index would run
/// them as the call that opens next at that index — and they are recorded and
/// told once.
#[test]
fn arguments_of_no_call_never_reach_a_client() {
    let mut round = gen_round(vec![gen_call("call_0_0", "Bash", false, &[""], Opening::Whole, None)], vec![0]);
    round.stray = Some("{\"cmd\":\"rm -rf /\"}".into());
    holds(&GenStream { upstream: ChatCompletions, rounds: vec![round.clone()] });
    holds(&GenStream { upstream: ApiVersion::AnthropicMessages, rounds: vec![round.clone()] });
    holds(&GenStream { upstream: ApiVersion::Responses, rounds: vec![round] });
}

/// A `response.failed` is an error and the response's end in one frame: the
/// error ends every client's stream, and the end after it writes nothing.
#[test]
fn nothing_follows_a_failed_response() {
    let mut round = gen_round(vec![gen_call("call_0_0", "Read", false, &[r#"{"v":"a"}"#], Opening::Whole, None)], vec![0]);
    round.finished = false;
    round.error_at = Some(3);
    round.failed = true;
    holds(&GenStream { upstream: ApiVersion::Responses, rounds: vec![round] });
}

/// A Chat delta restating its call's id at another call's index — or at
/// none — is its own call's, for the audit, policy and every client: a Chat
/// pass-through client is sent it at its call's index.
#[test]
fn a_delta_restating_its_id_elsewhere_stays_its_calls() {
    let calls = vec![
        gen_call("call_0_0", "Read", false, &[r#"{"v":"#, r#""a"}"#], Opening::Whole, None),
        gen_call("call_0_1", "Bash", false, &[r#"{"v":"#, r#""b"}"#], Opening::Whole, None),
    ];
    let mut round = gen_round(calls, vec![0, 1, 0, 1]);
    round.unstable = true;
    // Call 0's second delta lands at call 1's index, call 1's at none.
    round.noise = vec![0, 1, 4, 4, 4, 0, 4];
    holds(&GenStream { upstream: ChatCompletions, rounds: vec![round] });
}

/// A Responses `mcp_call` is a tool the upstream runs on a remote MCP server:
/// the audit records it as that server tool's call, and no translated client
/// is given it to run.
#[test]
fn an_mcp_call_is_the_upstreams_to_run() {
    let mut round = gen_round(vec![gen_call("call_0_0", "Read", false, &[r#"{"v":"a"}"#], Opening::Whole, None)], vec![0]);
    round.server_tool = true;
    holds(&GenStream { upstream: ApiVersion::Responses, rounds: vec![round] });
}

/// An upstream that goes on after its error — a finish and its usage after
/// the error — ends every client's stream at the error, pass-through clients
/// included: nothing is written or forwarded after it.
#[test]
fn nothing_follows_an_error_the_upstream_goes_on_after() {
    for upstream in clients() {
        let mut round = gen_round(vec![gen_call("call_0_0", "Read", false, &[r#"{"v":"a"}"#], Opening::Whole, None)], vec![0]);
        round.finished = false;
        round.error_at = Some(2);
        round.after_error = true;
        holds(&GenStream { upstream, rounds: vec![round] });
    }
}

/// An error after the finish, while a builder holds the finish for its
/// usage, ends the stream: the held finish is never written after it.
#[test]
fn an_error_after_the_finish_ends_the_stream() {
    let mut round = gen_round(vec![gen_call("call_0_0", "Read", false, &[r#"{"v":"a"}"#], Opening::Whole, None)], vec![0]);
    round.finished = false;
    round.error_at = Some(0);
    round.error_after_finish = true;
    holds(&GenStream { upstream: ChatCompletions, rounds: vec![round] });
}

/// Text after the finish (a lax server, before its usage) is closed with the
/// rest of an Anthropic client's message: every block it opens is stopped
/// before the message stops.
#[test]
fn text_after_the_finish_is_closed_before_the_message_ends() {
    let mut round = gen_round(vec![gen_call("call_0_0", "Read", false, &[r#"{"v":"a"}"#], Opening::Whole, None)], vec![0]);
    round.text_after_finish = true;
    holds(&GenStream { upstream: ChatCompletions, rounds: vec![round] });
}

/// What the accumulator still holds when an agent-loop round's stream ends —
/// text after the finish, and the usage behind it — stays with that round:
/// it never reaches the client inside the next round's answer (where a usage
/// already given lets a Gemini client's stream end before the error ending
/// the round it reads).
#[test]
fn a_rounds_held_content_stays_with_its_round() {
    let mut first = gen_round(vec![gen_call("call_0_0", "Read", false, &[r#"{"v":"a"}"#], Opening::Whole, None)], vec![0]);
    first.text_after_finish = true;
    first.usage_every_chunk = true;
    let mut last = gen_round(vec![gen_call("call_1_0", "Read", false, &[r#"{"v":"b"}"#], Opening::Whole, None)], vec![0]);
    last.finished = false;
    last.error_at = Some(0);
    last.error_after_finish = true;
    holds(&GenStream { upstream: ChatCompletions, rounds: vec![first, last] });
}

/// A client call's arguments sent after a server tool's item opened are the
/// client call's — for the audit, policy and every client — never the server
/// tool's, which no policy reads: each Responses event is placed on the item
/// it names.
#[test]
fn a_client_calls_delta_after_a_server_tool_opens_is_its_own() {
    let mut round = gen_round(vec![gen_call("call_0_0", "Bash", false, &[r#"{"v":"rm -rf /"}"#], Opening::Whole, None)], vec![0]);
    round.server_tool = true;
    round.pair_chunks = true;
    // The client call opens, then the server tool, then the call's arguments.
    round.noise = vec![1, 0, 1, 1, 1, 1];
    holds(&GenStream { upstream: ApiVersion::Responses, rounds: vec![round] });
}

/// A Responses call whose arguments are stated whole only in its done events
/// is read with them — by the audit and policy as by every client.
#[test]
fn a_call_stated_only_in_its_done_is_read_whole() {
    let mut call = gen_call("call_0_0", "Bash", false, &[r#"{"v":"#, r#""rm -rf /"}"#], Opening::Whole, None);
    call.streamed = 0;
    holds(&GenStream { upstream: ApiVersion::Responses, rounds: vec![gen_round(vec![call], vec![0])] });
}

/// A Responses call's done events stating arguments other than those that
/// streamed never hand a client bytes no policy read: the client is given
/// what streamed.
#[test]
fn a_done_stating_other_arguments_gives_what_streamed() {
    let mut call = gen_call("call_0_0", "Bash", false, &[r#"{"v":"a"}"#], Opening::Whole, None);
    call.conflicting_done = true;
    holds(&GenStream { upstream: ApiVersion::Responses, rounds: vec![gen_round(vec![call], vec![0])] });
}

/// A Responses event naming its item by id alone is placed on that item, by
/// the stream and by a pass-through client's final statements alike.
#[test]
fn an_event_naming_its_item_by_id_alone_is_its_items() {
    let mut round = gen_round(vec![gen_call("call_0_0", "Read", false, &[r#"{"v":"#, r#""a"}"#], Opening::Whole, None)], vec![0]);
    round.unstable = true;
    round.noise = vec![2];
    round.stray = Some("x".into());
    holds(&GenStream { upstream: ApiVersion::Responses, rounds: vec![round] });
}

/// An item a Responses upstream opened without its `output_index`, then
/// named by its place and id, is that call's — its arguments are never
/// withheld as no call's.
#[test]
fn an_item_opened_without_its_place_is_read_by_the_place_later_named() {
    let calls = vec![
        gen_call("call_0_0", "Read", false, &[r#"{"v":"#, r#""a"}"#], Opening::Whole, None),
        gen_call("call_0_1", "Bash", false, &[r#"{"v":"b"}"#], Opening::Whole, None),
    ];
    let mut round = gen_round(calls, vec![0, 1]);
    round.unindexed_open = true;
    holds(&GenStream { upstream: ApiVersion::Responses, rounds: vec![round] });
}

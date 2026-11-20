//! How every client's stream ends: `end_the_clients_stream`, driven the way
//! the pipeline drives it — the upstream's frames read by the stream parser
//! and handed through `fast_path_frame`, then the emitter's flush, then the
//! end — for each client protocol, pass-through and translated.
//!
//! The expected frames are the providers' own (Anthropic `event: error` and
//! `message_stop`, the Chat error chunk and `[DONE]`, the Responses `error`
//! event with its `sequence_number`, Gemini's AIP-193 chunk), written from
//! their specs, not from the code.

use serde_json::{json, Value};

use crate::api::sse::{ApiVersion, SseEvent, StreamParser};
use crate::pipeline::response_blocks::{BlockAccumulator, BlockInterests, BufferedEvent};
use crate::pipeline::response_pipeline::{
    chat_usage_admit, end_the_clients_stream, fast_path_frame, flush_the_emitter, frame_opens_container, read_upstream_frame, split_frame,
    ends_the_stream, stall_cut_the_answer, Admit, ClientEnd, EventEmitter,
};

const ALL: [ApiVersion; 4] =
    [ApiVersion::ChatCompletions, ApiVersion::AnthropicMessages, ApiVersion::Responses, ApiVersion::GoogleGemini];

fn data(event: Option<&str>, data: Value) -> SseEvent {
    SseEvent { event_type: event.map(str::to_string), data: data.to_string(), id: None }
}

/// One whole answer, "Hello", as each upstream streams it.
fn upstream_answer(api: ApiVersion) -> Vec<SseEvent> {
    match api {
        ApiVersion::ChatCompletions => {
            let chunk = |delta: Value, finish: Value| {
                data(None, json!({"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "m",
                    "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}))
            };
            vec![
                chunk(json!({"role": "assistant", "content": "Hel"}), Value::Null),
                chunk(json!({"content": "lo"}), Value::Null),
                chunk(json!({}), json!("stop")),
                data(None, json!({"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "m", "choices": [],
                    "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7}})),
                SseEvent { event_type: None, data: "[DONE]".to_string(), id: None },
            ]
        }
        ApiVersion::AnthropicMessages => vec![
            data(Some("message_start"), json!({"type": "message_start", "message": {"id": "msg_1", "type": "message",
                "role": "assistant", "model": "m", "content": [], "stop_reason": null, "stop_sequence": null,
                "usage": {"input_tokens": 5, "output_tokens": 1}}})),
            data(Some("content_block_start"), json!({"type": "content_block_start", "index": 0,
                "content_block": {"type": "text", "text": ""}})),
            data(Some("content_block_delta"), json!({"type": "content_block_delta", "index": 0,
                "delta": {"type": "text_delta", "text": "Hel"}})),
            data(Some("content_block_delta"), json!({"type": "content_block_delta", "index": 0,
                "delta": {"type": "text_delta", "text": "lo"}})),
            data(Some("content_block_stop"), json!({"type": "content_block_stop", "index": 0})),
            data(Some("message_delta"), json!({"type": "message_delta",
                "delta": {"stop_reason": "end_turn", "stop_sequence": null}, "usage": {"output_tokens": 2}})),
            data(Some("message_stop"), json!({"type": "message_stop"})),
        ],
        ApiVersion::Responses => {
            let item = json!({"type": "message", "id": "msg_1", "status": "completed", "role": "assistant",
                "content": [{"type": "output_text", "text": "Hello", "annotations": []}]});
            let e = |kind: &str, n: u64, mut body: Value| {
                body["type"] = json!(kind);
                body["sequence_number"] = json!(n);
                data(Some(kind), body)
            };
            vec![
                e("response.created", 0, json!({"response": {"id": "resp_1", "object": "response", "status": "in_progress", "output": []}})),
                e("response.output_item.added", 1, json!({"output_index": 0, "item": {"type": "message", "id": "msg_1",
                    "status": "in_progress", "role": "assistant", "content": []}})),
                e("response.content_part.added", 2, json!({"item_id": "msg_1", "output_index": 0, "content_index": 0,
                    "part": {"type": "output_text", "text": "", "annotations": []}})),
                e("response.output_text.delta", 3, json!({"item_id": "msg_1", "output_index": 0, "content_index": 0, "delta": "Hel"})),
                e("response.output_text.delta", 4, json!({"item_id": "msg_1", "output_index": 0, "content_index": 0, "delta": "lo"})),
                e("response.output_text.done", 5, json!({"item_id": "msg_1", "output_index": 0, "content_index": 0, "text": "Hello"})),
                e("response.output_item.done", 6, json!({"output_index": 0, "item": item})),
                e("response.completed", 7, json!({"response": {"id": "resp_1", "object": "response", "status": "completed",
                    "output": [item], "usage": {"input_tokens": 5, "output_tokens": 2, "total_tokens": 7}}})),
            ]
        }
        ApiVersion::GoogleGemini => vec![
            data(None, json!({"candidates": [{"content": {"role": "model", "parts": [{"text": "Hel"}]}, "index": 0}]})),
            data(None, json!({"candidates": [{"content": {"role": "model", "parts": [{"text": "lo"}]}, "index": 0,
                "finishReason": "STOP"}], "usageMetadata": {"promptTokenCount": 5, "candidatesTokenCount": 2, "totalTokenCount": 7}})),
        ],
    }
}

/// Frames of the answer up to the end of its first text piece ("Hel") — a
/// stream stopped mid-answer.
fn mid_answer(api: ApiVersion) -> usize {
    match api {
        ApiVersion::ChatCompletions | ApiVersion::GoogleGemini => 1,
        ApiVersion::AnthropicMessages => 3,
        ApiVersion::Responses => 4,
    }
}

/// The upstream a translated client of `client` reads in these cases.
fn other(client: ApiVersion) -> ApiVersion {
    if client == ApiVersion::ChatCompletions { ApiVersion::AnthropicMessages } else { ApiVersion::ChatCompletions }
}

/// Which end the stream got, by name — `ClientEnd` carries no `Debug`.
fn kind(end: &ClientEnd) -> &'static str {
    match end {
        ClientEnd::Ended => "ended",
        ClientEnd::EndOnly(_) => "end_only",
        ClientEnd::TimedOut(_) => "timed_out",
        ClientEnd::Empty(_) => "empty",
        ClientEnd::CutShort(_) => "cut_short",
        ClientEnd::Incomplete(_) => "incomplete",
    }
}

/// A response-phase policy holding every text and call block, so the stream
/// takes the buffered path: the accumulator holds content and hands it back
/// later, the way a policy rewrite does.
fn holding_policy(upstream: ApiVersion) -> BlockAccumulator {
    BlockAccumulator::new(
        BlockInterests { buffer_tool_blocks: true, buffer_text_blocks: true, buffer_thinking_blocks: false },
        vec![],
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

/// What the client is handed for `frames`, read as the pipeline reads them —
/// through the fast path, or with `held` through a holding policy's
/// accumulator and its flush — then the emitter's flush and the stream's end,
/// with the idle timeout having fired (`stalled`) or the upstream having closed.
fn drive(client: ApiVersion, upstream: ApiVersion, frames: Vec<SseEvent>, stalled: bool, held: bool) -> (Vec<(String, Value)>, &'static str) {
    let mut emitter = EventEmitter::new(client, upstream, "m", "req-1", None, None, 0, 0).with_chat_usage(true);
    let mut parser = StreamParser::new(upstream);
    let mut acc = held.then(|| holding_policy(upstream));
    let pass_through = client == upstream;
    let mut bytes = Vec::new();
    // As the pipeline reads it: a stall is the timeout only before the
    // upstream's own end or its own error.
    let mut upstream_ended = false;
    for mut frame in frames {
        upstream_ended |= read_upstream_frame(&mut frame, upstream);
        emitter.observe_upstream(&frame);
        let events = parser.parse(&frame);
        upstream_ended |= events.iter().any(|e| matches!(e, crate::api::domain::DomainEvent::Error { .. }));
        match &mut acc {
            Some(acc) => {
                let out: Vec<BufferedEvent> = if events.is_empty() {
                    let opens = frame_opens_container(&frame, upstream);
                    acc.process_raw(frame, opens)
                } else {
                    let raws = split_frame(&frame, upstream, &events, pass_through);
                    events.into_iter().zip(raws).flat_map(|(de, raw)| acc.process(de, raw)).collect()
                };
                out.iter().for_each(|b| bytes.extend(emitter.process_buffered(b)));
            }
            None => bytes.extend(fast_path_frame(&mut emitter, upstream, &events, &frame)),
        }
    }
    for end in parser.finish() {
        match &mut acc {
            Some(acc) => acc.process(end, None).iter().for_each(|b| bytes.extend(emitter.process_buffered(b))),
            None => bytes.extend(emitter.process_streaming_event(&end, None)),
        }
    }
    if let Some(acc) = &mut acc {
        acc.flush().iter().for_each(|b| bytes.extend(emitter.process_buffered(b)));
    }
    let stalled = stalled && !upstream_ended;
    bytes.extend(flush_the_emitter(&mut emitter, stalled));
    let end = end_the_clients_stream(&mut emitter, stalled.then_some(300));
    let name = kind(&end);
    bytes.extend(end.chunks());
    // Nothing reaches a pass-through client after the error the gateway
    // ended its stream with.
    if name == "timed_out" && pass_through {
        let late = crate::api::domain::DomainEvent::TextDelta("late".into());
        assert!(emitter.process_streaming_event(&late, None).is_empty(), "{client:?}: written after the error");
    }
    (decode(&bytes), name)
}

/// [`drive`] over the first `upto` frames of the whole answer, on the fast path.
fn run(client: ApiVersion, upstream: ApiVersion, upto: usize, stalled: bool) -> (Vec<(String, Value)>, &'static str) {
    drive(client, upstream, upstream_answer(upstream).into_iter().take(upto).collect(), stalled, false)
}

/// `(event name, data)` per frame; `[DONE]` is the string "[DONE]".
fn decode(chunks: &[bytes::Bytes]) -> Vec<(String, Value)> {
    let text: String = chunks.iter().map(|c| String::from_utf8_lossy(c).into_owned()).collect();
    text.split("\n\n")
        .filter(|f| !f.trim().is_empty())
        .map(|f| {
            let name = f.lines().find_map(|l| l.strip_prefix("event: ")).unwrap_or_default();
            let raw: String = f.lines().filter_map(|l| l.strip_prefix("data: ")).collect();
            let value = serde_json::from_str(&raw).unwrap_or(Value::String(raw));
            (name.to_string(), value)
        })
        .collect()
}

fn text_of(frames: &[(String, Value)]) -> String {
    frames.iter().map(|(_, v)| v.to_string()).collect()
}

/// The frame that is `client`'s error, if `frame` is one, as `(message, class)`
/// — the class in that grammar's own vocabulary.
fn error_in(client: ApiVersion, (name, v): &(String, Value)) -> Option<(String, String)> {
    let s = |v: &Value| v.as_str().map(str::to_string);
    match client {
        // Anthropic: `event: error`, `{"type":"error","error":{"type","message"}}`.
        ApiVersion::AnthropicMessages => (name == "error" && v["type"] == "error")
            .then(|| Some((s(&v["error"]["message"])?, s(&v["error"]["type"])?)))
            .flatten(),
        // Chat: the HTTP error object — `error` an object with a string `message`.
        ApiVersion::ChatCompletions => v["error"]
            .is_object()
            .then(|| Some((s(&v["error"]["message"])?, s(&v["error"]["code"])?)))
            .flatten(),
        // Responses: `event: error`, its members flat beside `type`, numbered.
        ApiVersion::Responses => (name == "error" && v["type"] == "error" && v["sequence_number"].is_u64())
            .then(|| Some((s(&v["message"])?, s(&v["code"])?)))
            .flatten(),
        // Gemini: AIP-193 — `{"error":{"code","message","status"}}`.
        ApiVersion::GoogleGemini => (v["error"]["code"].is_u64())
            .then(|| Some((s(&v["error"]["message"])?, s(&v["error"]["status"])?)))
            .flatten(),
    }
}

/// The timeout's class in each grammar: a deadline, never the generic fault.
fn timeout_class(client: ApiVersion) -> &'static str {
    match client {
        ApiVersion::AnthropicMessages => "timeout_error",
        ApiVersion::ChatCompletions | ApiVersion::Responses => "server_error",
        ApiVersion::GoogleGemini => "DEADLINE_EXCEEDED",
    }
}

/// The frames that may follow an error: a Chat stream's `[DONE]`, nothing else.
fn after_error_is_allowed(client: ApiVersion, rest: &[(String, Value)]) -> bool {
    match client {
        ApiVersion::ChatCompletions => rest.len() == 1 && rest[0].1 == "[DONE]",
        _ => rest.is_empty(),
    }
}

/// A stream the upstream stalled on mid-answer ends with the gateway's
/// timeout error in the client's own grammar — after the text the client was
/// already given, and with nothing but a Chat `[DONE]` after it — on every
/// client protocol, pass-through and translated, on the fast path and with a
/// policy holding the content until the end.
#[test]
fn a_stall_mid_answer_ends_with_the_timeout_error_in_the_clients_grammar() {
    for client in ALL {
        for upstream in [client, other(client)] {
          for held in [false, true] {
            let mid: Vec<SseEvent> = upstream_answer(upstream).into_iter().take(mid_answer(upstream)).collect();
            let (frames, end) = drive(client, upstream, mid, true, held);
            assert_eq!(end, "timed_out", "{client:?} from {upstream:?} held={held}");
            let at = frames
                .iter()
                .position(|f| error_in(client, f).is_some())
                .unwrap_or_else(|| panic!("{client:?} from {upstream:?}: no error in {frames:?}"));
            let (message, class) = error_in(client, &frames[at]).unwrap();
            assert_eq!(message, "stream idle timeout after 300s");
            assert_eq!(class, timeout_class(client), "{client:?} from {upstream:?}");
            assert!(after_error_is_allowed(client, &frames[at + 1..]), "{client:?} from {upstream:?}: {frames:?}");
            assert!(text_of(&frames[..at]).contains("Hel"), "{client:?} from {upstream:?} held={held}: the text first: {frames:?}");
          }
        }
    }
}

/// The client's error frame and where it is, or a panic naming the stream.
fn the_error(client: ApiVersion, frames: &[(String, Value)]) -> (usize, String) {
    let at = frames
        .iter()
        .position(|f| error_in(client, f).is_some())
        .unwrap_or_else(|| panic!("{client:?}: no error in {frames:?}"));
    (at, error_in(client, &frames[at]).unwrap().1)
}

/// A stall before the upstream sent a byte is the same error, with nothing
/// but its grammar's framing around it (a translated client may be opened
/// first — Anthropic `message_start`, Responses `response.created` — as the
/// APIs themselves do; Chat ends with `[DONE]`) — a valid stream in every
/// grammar.
#[test]
fn a_stall_before_the_first_byte_is_the_error_alone() {
    for client in ALL {
        for upstream in [client, other(client)] {
            let (frames, end) = run(client, upstream, 0, true);
            assert_eq!(end, "timed_out", "{client:?} from {upstream:?}");
            let (at, _) = the_error(client, &frames);
            assert!(frames[..at].iter().all(|(name, _)| matches!(name.as_str(), "message_start" | "response.created")), "{client:?} from {upstream:?}: {frames:?}");
            assert!(after_error_is_allowed(client, &frames[at + 1..]), "{client:?} from {upstream:?}: {frames:?}");
        }
    }
}

/// A Responses pass-through client's error is numbered in its own sequence:
/// the next number after the last event it was handed.
#[test]
fn a_responses_pass_through_error_carries_the_next_sequence_number() {
    let (frames, _) = run(ApiVersion::Responses, ApiVersion::Responses, mid_answer(ApiVersion::Responses), true);
    let numbers: Vec<u64> = frames.iter().filter_map(|(_, v)| v["sequence_number"].as_u64()).collect();
    assert_eq!(numbers, (0..numbers.len() as u64).collect::<Vec<_>>(), "{frames:?}");
    assert_eq!(frames.last().unwrap().0, "error");
}

/// A stall after the answer's finish, before its stream's end (the Chat usage
/// chunk and `[DONE]`, the Anthropic `message_stop`), is never an error — the
/// SDKs raise on one and lose the whole answer: the client is given the end
/// alone. A translated client's emitter writes its end at its flush.
#[test]
fn a_stall_after_the_finish_gives_the_end_and_never_an_error() {
    for client in ALL {
        for upstream in [client, other(client)] {
            if matches!(upstream, ApiVersion::Responses | ApiVersion::GoogleGemini) {
                continue; // Their finish is their end: no gap to stall in.
            }
          for held in [false, true] {
            let all_but_end: Vec<SseEvent> = {
                let mut f = upstream_answer(upstream);
                f.pop();
                f
            };
            let (frames, _) = drive(client, upstream, all_but_end, true, held);
            assert!(frames.iter().all(|f| error_in(client, f).is_none()), "{client:?} from {upstream:?}: {frames:?}");
            let last = frames.last().unwrap();
            match client {
                ApiVersion::ChatCompletions => assert_eq!(last.1, "[DONE]", "{upstream:?}: {frames:?}"),
                ApiVersion::AnthropicMessages => assert_eq!(last.0, "message_stop", "{upstream:?}: {frames:?}"),
                ApiVersion::Responses => assert_eq!(last.0, "response.completed", "{upstream:?}: {frames:?}"),
                ApiVersion::GoogleGemini => assert!(last.1["candidates"][0]["finishReason"].is_string(), "{frames:?}"),
            }
            assert_eq!(
                frames.iter().filter(|(n, v)| n == "message_stop" || *v == "[DONE]").count(),
                usize::from(matches!(client, ApiVersion::ChatCompletions | ApiVersion::AnthropicMessages)),
                "{client:?} from {upstream:?}: the end, once: {frames:?}"
            );
          }
        }
    }
}

/// A stream that ended — whether the upstream then stalled or closed — gets
/// nothing more.
#[test]
fn an_ended_stream_gets_nothing_more() {
    for client in ALL {
        for upstream in [client, other(client)] {
            for stalled in [true, false] {
                let whole = upstream_answer(upstream).len();
                let (_, end) = run(client, upstream, whole, stalled);
                assert_eq!(end, "ended", "{client:?} from {upstream:?} stalled={stalled}");
            }
        }
    }
}

/// An upstream that CLOSED mid-answer is not a timeout: no error is written.
/// The Anthropic-translated client keeps its `max_tokens` close, the
/// Responses-translated one its `incomplete` close, and a pass-through client
/// is left as its upstream left it.
#[test]
fn an_upstream_close_mid_answer_is_not_a_timeout() {
    for client in ALL {
        for upstream in [client, other(client)] {
            let (frames, end) = run(client, upstream, mid_answer(upstream), false);
            assert!(frames.iter().all(|f| error_in(client, f).is_none()), "{client:?} from {upstream:?}: {frames:?}");
            match (client, client == upstream) {
                (ApiVersion::AnthropicMessages, false) => {
                    assert_eq!(end, "cut_short");
                    assert_eq!(frames.last().unwrap().0, "message_stop");
                    assert!(text_of(&frames).contains("max_tokens"), "{frames:?}");
                }
                (ApiVersion::Responses, false) => {
                    assert_eq!(end, "incomplete");
                    assert_eq!(frames.last().unwrap().0, "response.incomplete");
                }
                // A translated Chat or Gemini client's answer is closed as
                // truncated, as its own server closes one at its token limit.
                (ApiVersion::ChatCompletions, false) => {
                    assert_eq!(end, "cut_short");
                    let finish = frames.iter().rev().find_map(|(_, v)| v["choices"][0]["finish_reason"].as_str());
                    assert_eq!(finish, Some("length"), "{upstream:?}: {frames:?}");
                    assert_eq!(frames.last().unwrap().1, "[DONE]", "{upstream:?}: {frames:?}");
                }
                (ApiVersion::GoogleGemini, false) => {
                    assert_eq!(end, "cut_short");
                    let last = &frames.last().unwrap().1;
                    assert_eq!(last["candidates"][0]["finishReason"], "MAX_TOKENS", "{upstream:?}: {frames:?}");
                }
                _ => assert_eq!(end, "ended", "{client:?} from {upstream:?}"),
            }
        }
    }
}

/// An Anthropic-translated client the upstream closed on before anything was
/// sent keeps its `overloaded_error` retry; one it STALLED on gets the timeout.
#[test]
fn an_empty_anthropic_stream_is_overloaded_when_closed_and_timed_out_when_stalled() {
    let (frames, end) = run(ApiVersion::AnthropicMessages, ApiVersion::ChatCompletions, 0, false);
    assert_eq!(end, "empty");
    assert_eq!(the_error(ApiVersion::AnthropicMessages, &frames).1, "overloaded_error");
    let (frames, _) = run(ApiVersion::AnthropicMessages, ApiVersion::ChatCompletions, 0, true);
    assert_eq!(the_error(ApiVersion::AnthropicMessages, &frames).1, "timeout_error");
}

/// A Chat chunk carrying usage the client did not ask for loses its `usage`,
/// and one carrying nothing else is dropped — but not one carrying an error,
/// which is the stream's last word to the client (positive control: the
/// usage-only chunk is still dropped).
#[test]
fn a_usage_chunk_carrying_an_error_is_not_dropped() {
    let usage = json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2});
    let usage_only = data(None, json!({"id": "c", "choices": [], "usage": usage}));
    assert!(matches!(chat_usage_admit(true, &usage_only), Admit::Drop));
    let with_error = data(None, json!({"error": {"message": "boom", "type": "server_error"}, "usage": usage}));
    match chat_usage_admit(true, &with_error) {
        Admit::Rewrite(body) => {
            let v: Value = serde_json::from_str(&body).unwrap();
            assert_eq!(v["error"]["message"], "boom");
            assert!(v.get("usage").is_none(), "{v}");
        }
        _ => panic!("an error chunk must reach the client"),
    }
}

/// An upstream's own failure is the upstream's, however it reaches the
/// emitter: a pass-through Responses client with a policy holding the stream
/// is handed the upstream's `response.failed` — its terminal event, carrying
/// the response — and never a gateway error in its place (positive control:
/// the fast path hands the same frame).
#[test]
fn a_held_upstream_failure_reaches_the_client_as_the_upstreams_own_frame() {
    let mut frames: Vec<SseEvent> = upstream_answer(ApiVersion::Responses).into_iter().take(4).collect();
    frames.push(data(Some("response.failed"), json!({"type": "response.failed", "sequence_number": 4,
        "response": {"id": "resp_1", "object": "response", "status": "failed", "output": [],
            "error": {"code": "server_error", "message": "upstream broke"}}})));
    for held in [false, true] {
        let (out, end) = drive(ApiVersion::Responses, ApiVersion::Responses, frames.clone(), false, held);
        assert_eq!(end, "ended", "held={held}");
        let failed: Vec<&Value> = out.iter().filter(|(n, _)| n == "response.failed").map(|(_, v)| v).collect();
        assert_eq!(failed.len(), 1, "held={held}: {out:?}");
        assert_eq!(failed[0]["response"]["error"]["message"], "upstream broke");
        assert!(out.iter().all(|(n, v)| n != "error" || v["message"] == "upstream broke"), "held={held}: {out:?}");
        assert!(!text_of(&out).contains("stream idle timeout"), "held={held}: {out:?}");
    }
}

/// The audit row says the stream timed out only when the stall cut the
/// answer: before the finish, or between the finish and the usage the row's
/// counts come from — never after a whole answer, nor after the upstream's
/// own end (an upstream that sends no usage and keeps its connection open).
/// Which frames are a stream's own end is each protocol's.
#[test]
fn the_row_is_a_timeout_only_when_the_stall_cut_the_answer() {
    assert!(stall_cut_the_answer(true, false, false), "a stall before the whole answer");
    assert!(!stall_cut_the_answer(true, false, true), "a stall after the whole answer");
    assert!(!stall_cut_the_answer(true, true, false), "a stall after the upstream's own end");
    assert!(!stall_cut_the_answer(false, false, false), "an upstream close is not a timeout");
    for upstream in [ApiVersion::ChatCompletions, ApiVersion::AnthropicMessages, ApiVersion::Responses] {
        let frames = upstream_answer(upstream);
        let (last, body) = frames.split_last().unwrap();
        assert!(ends_the_stream(last), "{upstream:?}: its last frame is its end");
        assert!(!body.iter().any(ends_the_stream), "{upstream:?}: nothing before it is");
    }
    assert!(!upstream_answer(ApiVersion::GoogleGemini).iter().any(ends_the_stream));
}

/// A stall mid-call ends the stream with the error alone: the call the
/// client was being given is not closed before it (a client running a call at
/// its block's close would run cut-off arguments) — a failed response holds no
/// call to run, as the providers' own mid-stream errors leave it.
#[test]
fn a_stall_mid_call_closes_no_call_before_the_error() {
    let call = |args: &str, id: Value, name: Value| {
        data(None, json!({"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "m",
            "choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": id, "type": "function",
                "function": {"name": name, "arguments": args}}]}, "finish_reason": null}]}))
    };
    let frames = vec![call("", json!("call_1"), json!("read")), call(r#"{"p":"#, Value::Null, Value::Null)];
    let (out, end) = drive(ApiVersion::AnthropicMessages, ApiVersion::ChatCompletions, frames.clone(), true, false);
    assert_eq!(end, "timed_out");
    let (at, _) = the_error(ApiVersion::AnthropicMessages, &out);
    assert!(out[..at].iter().all(|(n, _)| n != "content_block_stop" && n != "message_delta"), "{out:?}");
    let (out, _) = drive(ApiVersion::Responses, ApiVersion::ChatCompletions, frames.clone(), true, false);
    let at = out.iter().position(|(n, _)| n == "error").unwrap_or_else(|| panic!("{out:?}"));
    assert!(out[..at].iter().all(|(n, _)| n != "response.output_item.done"), "{out:?}");
    // A Gemini client's builder holds every call until the finish: none is
    // written before the error, where its cut-off arguments would read `{}`.
    // Positive control: the same call, whole and finished, is written.
    let (out, end) = drive(ApiVersion::GoogleGemini, ApiVersion::ChatCompletions, frames.clone(), true, false);
    assert_eq!(end, "timed_out");
    let (at, _) = the_error(ApiVersion::GoogleGemini, &out);
    assert!(!text_of(&out[..at]).contains("functionCall"), "{out:?}");
    let mut whole = vec![call("", json!("call_1"), json!("read")), call(r#"{"p":1}"#, Value::Null, Value::Null)];
    whole.push(data(None, json!({"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "m",
        "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]})));
    let (out, _) = drive(ApiVersion::GoogleGemini, ApiVersion::ChatCompletions, whole, false, false);
    assert!(text_of(&out).contains("functionCall"), "{out:?}");
}

/// A Chat pass-through whose upstream sent its own error chunk and then no
/// `[DONE]` is handed the `[DONE]` — as after every other Chat error — and no
/// timeout error after the upstream's, whether the upstream then closed or
/// stalled; on the fast path and with a policy holding the stream.
#[test]
fn a_chat_upstreams_own_error_without_its_done_still_ends_with_done() {
    let mut frames: Vec<SseEvent> = upstream_answer(ApiVersion::ChatCompletions).into_iter().take(1).collect();
    frames.push(data(None, json!({"error": {"message": "boom", "type": "server_error", "code": "server_error"}})));
    for stalled in [false, true] {
        for held in [false, true] {
            let (out, end) =
                drive(ApiVersion::ChatCompletions, ApiVersion::ChatCompletions, frames.clone(), stalled, held);
            let ctx = format!("stalled={stalled} held={held}: {out:?}");
            assert_eq!(end, "end_only", "{ctx}");
            let (at, _) = the_error(ApiVersion::ChatCompletions, &out);
            assert_eq!(error_in(ApiVersion::ChatCompletions, &out[at]).map(|(m, _)| m).as_deref(), Some("boom"), "{ctx}");
            assert!(after_error_is_allowed(ApiVersion::ChatCompletions, &out[at + 1..]), "{ctx}");
        }
    }
    // An error the client was handed no frame of (one held or synthesized
    // without its frame) ends nothing cleanly: no bare `[DONE]`.
    let mut emitter = EventEmitter::new(ApiVersion::ChatCompletions, ApiVersion::ChatCompletions, "m", "req-1", None, None, 0, 0);
    let mut parser = StreamParser::new(ApiVersion::ChatCompletions);
    let answer = upstream_answer(ApiVersion::ChatCompletions);
    let events = parser.parse(&answer[0]);
    let _ = fast_path_frame(&mut emitter, ApiVersion::ChatCompletions, &events, &answer[0]);
    let error = crate::api::domain::DomainEvent::Error { message: "boom".into(), code: None };
    let _ = emitter.process_streaming_event(&error, None);
    // The next frame the upstream sends is no error's.
    let events = parser.parse(&answer[1]);
    let _ = fast_path_frame(&mut emitter, ApiVersion::ChatCompletions, &events, &answer[1]);
    let end = end_the_clients_stream(&mut emitter, None);
    assert_ne!(kind(&end), "end_only");
    assert!(!decode(&end.chunks()).iter().any(|(_, v)| v == "[DONE]"));
    // Positive control: an upstream that sent its `[DONE]` gets no second one.
    frames.push(SseEvent { event_type: None, data: "[DONE]".to_string(), id: None });
    let (out, end) = drive(ApiVersion::ChatCompletions, ApiVersion::ChatCompletions, frames, false, false);
    assert_eq!(end, "ended");
    assert_eq!(out.iter().filter(|(_, v)| v == "[DONE]").count(), 1, "{out:?}");
}

/// An upstream's error chunk whose `error` the client's grammar refuses — a
/// bare message string — reaches a Chat or Gemini pass-through client as its
/// protocol's error object, built from the error the parser read, with the
/// chunk's other members kept; on the fast path and held. Positive control: a
/// well-formed error chunk is forwarded as the upstream sent it.
#[test]
fn an_upstream_error_chunk_the_clients_grammar_refuses_is_restated() {
    for api in [ApiVersion::ChatCompletions, ApiVersion::GoogleGemini] {
        for held in [false, true] {
            let mut frames: Vec<SseEvent> = upstream_answer(api).into_iter().take(1).collect();
            frames.push(data(None, json!({"error": "upstream broke", "id": "kept"})));
            // An object missing a member the grammar requires keeps the rest.
            let mut partial: Vec<SseEvent> = upstream_answer(api).into_iter().take(1).collect();
            partial.push(data(None, json!({"error": {"status": "UNAVAILABLE", "details": [{"retryDelay": "30s"}]}})));
            let (out, _) = drive(api, api, frames, false, held);
            let ctx = format!("{api:?} held={held}: {out:?}");
            let restated = out.iter().find(|(_, v)| v.get("error").is_some()).unwrap_or_else(|| panic!("{ctx}"));
            assert_eq!(error_in(api, restated).map(|(m, _)| m).as_deref(), Some("upstream broke"), "{ctx}");
            assert_eq!(restated.1["id"], "kept", "{ctx}");
            let (out, _) = drive(api, api, partial, false, held);
            let restated = out.iter().find(|(_, v)| v.get("error").is_some()).unwrap_or_else(|| panic!("{ctx}"));
            assert!(error_in(api, restated).is_some(), "{api:?}: {out:?}");
            assert_eq!(restated.1["error"]["details"][0]["retryDelay"], "30s", "{api:?}: {out:?}");
        }
        let sent = match api {
            ApiVersion::GoogleGemini => {
                json!({"error": {"code": 503, "message": "busy", "status": "UNAVAILABLE", "details": []}})
            }
            _ => json!({"error": {"message": "busy", "type": "server_error", "param": null, "code": "x_own"}}),
        };
        let mut frames: Vec<SseEvent> = upstream_answer(api).into_iter().take(1).collect();
        frames.push(data(None, sent.clone()));
        let (out, _) = drive(api, api, frames, false, false);
        assert!(out.iter().any(|(_, v)| *v == sent), "{api:?}: {out:?}");
    }
}

/// A Gemini client of a stream cut short mid-call is never written the call
/// with its cut-off arguments (read `{}`): the call is recorded withheld, and
/// the answer closes `MAX_TOKENS`. Positive control: a whole call before the
/// cut is written.
#[test]
fn a_cut_short_call_never_reaches_a_gemini_client_as_empty_arguments() {
    let call = |args: &str, id: Value, name: Value| {
        data(None, json!({"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "m",
            "choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": id, "type": "function",
                "function": {"name": name, "arguments": args}}]}, "finish_reason": null}]}))
    };
    let cut = vec![call("", json!("call_1"), json!("read")), call(r#"{"p":"#, Value::Null, Value::Null)];
    let (out, _) = drive(ApiVersion::GoogleGemini, ApiVersion::ChatCompletions, cut, false, false);
    assert!(!text_of(&out).contains("functionCall"), "{out:?}");
    assert!(text_of(&out).contains("did not complete"), "told in its place: {out:?}");
    assert_eq!(out.last().unwrap().1["candidates"][0]["finishReason"], "MAX_TOKENS", "{out:?}");
    let whole = vec![call("", json!("call_1"), json!("read")), call(r#"{"p":1}"#, Value::Null, Value::Null)];
    let (out, _) = drive(ApiVersion::GoogleGemini, ApiVersion::ChatCompletions, whole, false, false);
    assert!(text_of(&out).contains("functionCall"), "{out:?}");
    // A Chat call cut before any argument (a Chat server writes a call of
    // none as `{}`) is cut off too.
    let (out, _) = drive(ApiVersion::GoogleGemini, ApiVersion::ChatCompletions, vec![call("", json!("call_1"), json!("read"))], false, false);
    assert!(!text_of(&out).contains("functionCall"), "{out:?}");
    // An Anthropic call opens with no argument bytes: when the stream is cut,
    // nothing says one with none was whole, so it is dropped and told too.
    let mut anthropic: Vec<SseEvent> = upstream_answer(ApiVersion::AnthropicMessages).into_iter().take(1).collect();
    anthropic.push(data(Some("content_block_start"), json!({"type": "content_block_start", "index": 0,
        "content_block": {"type": "tool_use", "id": "toolu_1", "name": "now", "input": {}}})));
    anthropic.push(data(Some("content_block_stop"), json!({"type": "content_block_stop", "index": 0})));
    let (out, _) = drive(ApiVersion::GoogleGemini, ApiVersion::AnthropicMessages, anthropic, false, false);
    assert!(!text_of(&out).contains("functionCall") && text_of(&out).contains("did not complete"), "{out:?}");
    // A call cut by the upstream's own token limit (a finish, not a cut
    // stream) is never written with its cut-off arguments either.
    let mut limited: Vec<SseEvent> = upstream_answer(ApiVersion::AnthropicMessages).into_iter().take(1).collect();
    limited.push(data(Some("content_block_start"), json!({"type": "content_block_start", "index": 0,
        "content_block": {"type": "tool_use", "id": "toolu_1", "name": "read", "input": {}}})));
    limited.push(data(Some("content_block_delta"), json!({"type": "content_block_delta", "index": 0,
        "delta": {"type": "input_json_delta", "partial_json": "{\"path\":\"/et"}})));
    limited.push(data(Some("message_delta"), json!({"type": "message_delta",
        "delta": {"stop_reason": "max_tokens", "stop_sequence": null}, "usage": {"output_tokens": 9}})));
    limited.push(data(Some("message_stop"), json!({"type": "message_stop"})));
    let (out, _) = drive(ApiVersion::GoogleGemini, ApiVersion::AnthropicMessages, limited, false, false);
    assert!(!text_of(&out).contains("functionCall"), "{out:?}");
    assert_eq!(out.last().unwrap().1["candidates"][0]["finishReason"], "MAX_TOKENS", "{out:?}");
}

/// A finish in a word the gateway does not know (Anthropic `pause_turn`) is
/// no failure: an error after it leaves the client its answer.
#[test]
fn an_error_after_an_unknown_finish_word_leaves_the_client_its_answer() {
    let mut frames: Vec<SseEvent> = upstream_answer(ApiVersion::AnthropicMessages).into_iter().take(5).collect();
    frames.push(data(Some("message_delta"), json!({"type": "message_delta", "delta": {"stop_reason": "pause_turn", "stop_sequence": null}})));
    frames.push(data(Some("error"), json!({"type": "error", "error": {"type": "overloaded_error", "message": "late"}})));
    for client in [ApiVersion::ChatCompletions, ApiVersion::GoogleGemini] {
        let (out, _) = drive(client, ApiVersion::AnthropicMessages, frames.clone(), false, false);
        assert!(out.iter().all(|f| error_in(client, f).is_none()), "{client:?}: {out:?}");
    }
}

/// An upstream's error after the answer's finish leaves every client the
/// whole answer and its end, never the error — an SDK raising on it would
/// lose the answer, as a stall at the same point never does — pass-through
/// and translated, on the fast path and held.
#[test]
fn an_error_after_a_finished_answer_leaves_the_client_its_answer() {
    for client in ALL {
        for upstream in [ApiVersion::ChatCompletions, ApiVersion::AnthropicMessages] {
            for held in [false, true] {
                // The answer's finish without its usage or end: every builder
                // still holds the finish when the error comes.
                let mut frames = upstream_answer(upstream);
                frames.pop();
                if upstream == ApiVersion::ChatCompletions {
                    frames.pop();
                } else if let Some(delta) = frames.last_mut() {
                    delta.data = json!({"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": null}}).to_string();
                }
                frames.push(match upstream {
                    ApiVersion::AnthropicMessages => data(Some("error"),
                        json!({"type": "error", "error": {"type": "overloaded_error", "message": "late"}})),
                    _ => data(None, json!({"error": {"message": "late", "type": "server_error"}})),
                });
                let (out, _) = drive(client, upstream, frames, false, held);
                let ctx = format!("{client:?} from {upstream:?} held={held}: {out:?}");
                assert!(out.iter().all(|f| error_in(client, f).is_none()), "{ctx}");
                assert!(text_of(&out).contains("Hel") && text_of(&out).contains("lo"), "{ctx}");
                let last = out.last().unwrap();
                match client {
                    ApiVersion::ChatCompletions => assert_eq!(last.1, "[DONE]", "{ctx}"),
                    ApiVersion::AnthropicMessages => assert_eq!(last.0, "message_stop", "{ctx}"),
                    ApiVersion::Responses => assert_eq!(last.0, "response.completed", "{ctx}"),
                    ApiVersion::GoogleGemini => assert!(last.1["candidates"][0]["finishReason"].is_string(), "{ctx}"),
                }
            }
        }
    }
}

/// An Anthropic or Responses upstream that writes its frames as data alone
/// (no `event:` line) is read as if each named its kind: every client gets
/// the whole answer and its end, and the stream's own end is seen as one;
/// any other protocol's frame is left as it came.
#[test]
fn a_frame_naming_its_kind_only_in_its_data_is_read_as_that_kind() {
    for upstream in [ApiVersion::AnthropicMessages, ApiVersion::Responses] {
        let bare: Vec<SseEvent> = upstream_answer(upstream)
            .into_iter()
            .map(|f| SseEvent { event_type: None, ..f })
            .collect();
        let mut last = bare.last().unwrap().clone();
        assert!(!ends_the_stream(&last), "the raw frame names no kind");
        last.name_from_data(upstream);
        assert!(ends_the_stream(&last), "{upstream:?}: named, it is the stream's end");
        for client in ALL {
            let (out, end) = drive(client, upstream, bare.clone(), true, false);
            let ctx = format!("{client:?} from {upstream:?}: {out:?}");
            assert!(out.iter().all(|f| error_in(client, f).is_none()), "{ctx}");
            assert!(text_of(&out).contains("Hel"), "{ctx}");
            assert_ne!(end, "timed_out", "{ctx}");
        }
    }
    // Any other protocol's frame is left as it came.
    let mut chat = upstream_answer(ApiVersion::ChatCompletions).remove(0);
    chat.name_from_data(ApiVersion::ChatCompletions);
    assert!(chat.event_type.is_none());
}

/// An upstream error after a FAILED finish (a Responses `response.failed`
/// with no error of its own, a Chat `finish_reason: "error"`) is no whole
/// answer's: the client is handed the error.
#[test]
fn an_error_after_a_failed_finish_reaches_the_client() {
    let mut frames: Vec<SseEvent> = upstream_answer(ApiVersion::ChatCompletions).into_iter().take(2).collect();
    frames.push(data(None, json!({"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "m",
        "choices": [{"index": 0, "delta": {}, "finish_reason": "error"}]})));
    frames.push(data(None, json!({"error": {"message": "late", "type": "server_error", "code": "server_error"}})));
    for client in ALL {
        let (out, _) = drive(client, ApiVersion::ChatCompletions, frames.clone(), false, false);
        assert!(out.iter().any(|f| error_in(client, f).is_some()), "{client:?}: {out:?}");
    }
}

/// A Chat pass-through client that asked for several choices: the parser
/// reads the first alone, so its finish is not the whole answer's, and an
/// upstream error after it is still the client's. Positive control: with one
/// choice, the same error after the finish is the audit's alone.
#[test]
fn an_error_after_the_first_of_several_choices_reaches_the_client() {
    let mut frames = upstream_answer(ApiVersion::ChatCompletions);
    frames.truncate(3);
    frames.push(data(None, json!({"error": {"message": "late", "type": "server_error", "code": "server_error"}})));
    for (choices, told) in [(2, true), (1, false)] {
        let mut emitter = EventEmitter::new(ApiVersion::ChatCompletions, ApiVersion::ChatCompletions, "m", "req-1", None, None, 0, 0)
            .with_chat_choices(choices);
        let mut parser = StreamParser::new(ApiVersion::ChatCompletions);
        let mut bytes = Vec::new();
        for frame in &frames {
            let events = parser.parse(frame);
            bytes.extend(fast_path_frame(&mut emitter, ApiVersion::ChatCompletions, &events, frame));
        }
        bytes.extend(end_the_clients_stream(&mut emitter, None).chunks());
        let out = decode(&bytes);
        assert_eq!(out.iter().any(|f| error_in(ApiVersion::ChatCompletions, f).is_some()), told, "n={choices}: {out:?}");
        assert_eq!(out.last().unwrap().1, "[DONE]", "n={choices}: {out:?}");
    }
}

/// A translated client of an upstream that closed before any of the answer
/// gets the retryable `overloaded_error`, as an Anthropic one does — never a
/// silent empty stream, nor an empty `response.incomplete`.
#[test]
fn a_translated_client_of_an_empty_answer_is_told_to_retry() {
    let opened: Vec<SseEvent> = upstream_answer(ApiVersion::AnthropicMessages).into_iter().take(1).collect();
    for client in [ApiVersion::ChatCompletions, ApiVersion::GoogleGemini, ApiVersion::Responses] {
        let (out, end) = drive(client, ApiVersion::AnthropicMessages, opened.clone(), false, false);
        assert_eq!(end, "empty", "{client:?}: {out:?}");
        let (_, class) = the_error(client, &out);
        assert!(class.contains("overload") || class == "server_error" || class == "UNAVAILABLE", "{client:?}: {class}");
    }
}

/// Once a pass-through upstream's error after the whole answer is withheld,
/// nothing it sends after it reaches the client but the stream's end.
#[test]
fn nothing_follows_a_withheld_error_but_the_end() {
    let mut frames: Vec<SseEvent> = upstream_answer(ApiVersion::ChatCompletions).into_iter().take(3).collect();
    frames.push(data(None, json!({"error": {"message": "late", "type": "server_error", "code": "server_error"}})));
    frames.push(data(None, json!({"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "m",
        "choices": [{"index": 0, "delta": {"content": "AFTER"}, "finish_reason": null}]})));
    frames.push(SseEvent { event_type: None, data: "[DONE]".to_string(), id: None });
    let (out, _) = drive(ApiVersion::ChatCompletions, ApiVersion::ChatCompletions, frames, false, false);
    assert!(!text_of(&out).contains("AFTER"), "{out:?}");
    assert_eq!(out.last().unwrap().1, "[DONE]", "{out:?}");
}

/// A lax server's chunk carrying content AND an error after its finish: the
/// client keeps its whole answer, with no error after it (the parser reads
/// such a chunk as its error; `fast_path_frame` also withholds an error
/// frame whatever its first event).
#[test]
fn an_error_riding_a_content_chunk_after_the_finish_is_withheld() {
    let mut frames: Vec<SseEvent> = upstream_answer(ApiVersion::ChatCompletions).into_iter().take(3).collect();
    frames.push(data(None, json!({"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "m",
        "choices": [{"index": 0, "delta": {"content": "x"}, "finish_reason": null}],
        "error": {"message": "late", "type": "server_error", "code": "server_error"}})));
    let (out, _) = drive(ApiVersion::ChatCompletions, ApiVersion::ChatCompletions, frames, false, false);
    assert!(out.iter().all(|f| error_in(ApiVersion::ChatCompletions, f).is_none()), "{out:?}");
    assert_eq!(out.last().unwrap().1, "[DONE]", "{out:?}");
}

/// Every reader of the parser reads a data-only frame as its kind — not only
/// the read loop, which names it first.
#[test]
fn the_parser_reads_a_data_only_frame_as_its_kind() {
    let bare = SseEvent { event_type: None, ..upstream_answer(ApiVersion::AnthropicMessages)[2].clone() };
    let events = crate::api::sse::parse_domain_event(&bare, ApiVersion::AnthropicMessages);
    assert!(events.iter().any(|e| matches!(e, crate::api::domain::DomainEvent::TextDelta(t) if t == "Hel")), "{events:?}");
}

/// A Gemini pass-through client that asked for several candidates: the
/// parser reads each chunk's first, so one candidate's finish is not the whole
/// stream's, and an upstream error after it is still the client's. Positive
/// control: with one candidate, the same error is the audit's alone.
#[test]
fn an_error_after_one_of_several_gemini_candidates_reaches_the_client() {
    let mut frames = upstream_answer(ApiVersion::GoogleGemini);
    frames.push(data(None, json!({"error": {"code": 500, "message": "late", "status": "INTERNAL"}})));
    for (candidates, told) in [(2, true), (1, false)] {
        let mut emitter = EventEmitter::new(ApiVersion::GoogleGemini, ApiVersion::GoogleGemini, "m", "req-1", None, None, 0, 0)
            .with_chat_choices(candidates);
        let mut parser = StreamParser::new(ApiVersion::GoogleGemini);
        let mut bytes = Vec::new();
        for frame in &frames {
            let events = parser.parse(frame);
            bytes.extend(fast_path_frame(&mut emitter, ApiVersion::GoogleGemini, &events, frame));
        }
        let out = decode(&bytes);
        assert_eq!(out.iter().any(|f| error_in(ApiVersion::GoogleGemini, f).is_some()), told, "candidates={candidates}: {out:?}");
    }
}

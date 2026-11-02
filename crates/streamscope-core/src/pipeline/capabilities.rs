//! Capability validation — reject requests that require capabilities the
//! resolved upstream model does not support.
//!
//! Called after routing (so we know the target's capabilities) and before
//! request transforms. Returns `AppError::bad_request` with a clear message
//! when a capability mismatch is detected.

use crate::api::domain::{ContentPart, MessageContent, ResponseInput};
use crate::api::messages::{AnthropicContent, ContentBlock, ImageSource, ToolResultBlock, ToolResultContent};
use crate::api::ApiRequest;
use crate::error::AppError;
use crate::proxy::routing::ModelCapabilities;

/// Validate that the request only uses capabilities the upstream model supports.
pub fn validate_capabilities(
    request: &ApiRequest,
    capabilities: &ModelCapabilities,
    dialect: crate::api::mistral::ChatDialect,
) -> Result<(), AppError> {
    check_function_calling(request, capabilities)?;
    check_vision(request, capabilities)?;
    check_audio_input(request, capabilities)?;
    check_video_input(request, capabilities)?;
    check_pdf_input(request, capabilities, dialect)?;
    check_unclassified_media(request, capabilities)?;
    check_system_messages(request, capabilities)?;
    check_response_schema(request, capabilities)?;
    // Note: supports_caching and supports_reasoning are NOT validated here.
    // Both are optimization hints / config that the proxy strips during
    // protocol translation (Anthropic → ChatCompletions). Rejecting would
    // break clients like Claude Code that always send cache_control blocks
    // and thinking config. The capability flags are still useful for UI
    // display and future per-protocol enforcement.
    Ok(())
}

fn check_function_calling(
    request: &ApiRequest,
    caps: &ModelCapabilities,
) -> Result<(), AppError> {
    if caps.function_calling {
        return Ok(());
    }
    if !request.tool_names().is_empty() {
        return Err(AppError::BadRequest(
            "Model does not support function calling. Remove tools or route to a capable model.".into(),
        ));
    }
    Ok(())
}

/// A PDF smuggled through the image channel arrives as a `data:application/pdf`
/// URI. Anchored at the scheme on purpose: an ordinary remote image URL that
/// merely *contains* the string (`https://cdn/application/pdf/cover.png`) is an
/// image, not a document.
///
/// This is the single classifier for the `image_url` channel — [`check_vision`]
/// and [`check_pdf_input`] both branch on it, so they partition that space
/// exactly. Keep them complementary: a part matched by neither is unguarded, and
/// one matched by both needs two capabilities to send one file.
fn is_pdf_data_uri(url: &str) -> bool {
    url.starts_with("data:application/pdf")
}

fn check_vision(request: &ApiRequest, caps: &ModelCapabilities) -> Result<(), AppError> {
    if caps.vision {
        return Ok(());
    }
    if has_content_type(request, |part| {
        matches!(part, ContentPart::ImageUrl { image_url } if !is_pdf_data_uri(&image_url.url))
            // Responses spells it `input_image`, with `image_url` as a PLAIN
            // STRING rather than the Chat object — so it lands in the `Unknown`
            // arm and is invisible to the typed match above.
            || matches!(part, ContentPart::Unknown(v) if {
                // `input_image` is the Responses spelling; an `image_url` that
                // reached `Unknown` is Mistral's bare-string form, which the
                // parser reads as an image all the same.
                matches!(v.get("type").and_then(|t| t.as_str()), Some("input_image" | "image_url"))
                    && !v.get("image_url")
                        .and_then(|u| u.as_str().or_else(|| u.get("url").and_then(|u| u.as_str())))
                        .is_some_and(is_pdf_data_uri)
            })
    }) {
        return Err(AppError::BadRequest(
            "Model does not support vision/image input.".into(),
        ));
    }
    Ok(())
}

fn check_audio_input(request: &ApiRequest, caps: &ModelCapabilities) -> Result<(), AppError> {
    if caps.audio_input {
        return Ok(());
    }
    if has_content_type(request, |part| {
        matches!(part, ContentPart::InputAudio { .. })
        || matches!(part, ContentPart::Unknown(v) if v.get("type").and_then(|t| t.as_str()) == Some("input_audio"))
    }) {
        return Err(AppError::BadRequest(
            "Model does not support audio input.".into(),
        ));
    }
    Ok(())
}

fn check_video_input(request: &ApiRequest, caps: &ModelCapabilities) -> Result<(), AppError> {
    if caps.video_input {
        return Ok(());
    }
    if has_content_type(request, |part| {
        matches!(part, ContentPart::Unknown(v) if v.get("type").and_then(|t| t.as_str()) == Some("video") || v.get("type").and_then(|t| t.as_str()) == Some("input_video"))
    }) {
        return Err(AppError::BadRequest(
            "Model does not support video input.".into(),
        ));
    }
    Ok(())
}

fn check_pdf_input(
    request: &ApiRequest,
    caps: &ModelCapabilities,
    dialect: crate::api::mistral::ChatDialect,
) -> Result<(), AppError> {
    let mistral = dialect == crate::api::mistral::ChatDialect::Mistral;
    if caps.pdf_input {
        return Ok(());
    }
    if has_content_type(request, |part| {
        // A PDF reaches us either as its own block (`document` / `file`) or
        // smuggled through the image channel as a data URI — which arrives as a
        // well-formed `image_url` part, so it must be matched on the TYPED
        // variant, not only in the `Unknown` catch-all.
        matches!(part, ContentPart::ImageUrl { image_url } if is_pdf_data_uri(&image_url.url))
            || matches!(part, ContentPart::Unknown(v) if {
                let ct_type = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
                // `input_file` / `input_image` are the Responses spellings of
                // the same two channels; without them a Responses client's PDF
                // reached the walks against a model that declares no PDF support.
                // Mistral's `document_url` and its uploaded file (`file` with a
                // top-level `file_id`; OpenAI's nests `file`) are exempt on a
                // Mistral target only: no Mistral model publishes a document
                // capability (its model list has no such leaf, nor does any
                // catalog row), so gating them there would refuse Mistral's own
                // document questions on every model. Elsewhere they are
                // documents, gated like any other.
                let nested_file = v.get("file").is_some_and(serde_json::Value::is_object);
                // A `text`-sourced document is text on every walk, never a PDF.
                let source_type = v.pointer("/source/type").and_then(|t| t.as_str());
                match ct_type {
                    // A document by URL is Mistral's own `document_url` on a
                    // Mistral target, whichever client spelled it.
                    "document" => source_type != Some("text") && !(mistral && source_type == Some("url")),
                    "input_file" => !(mistral && v.get("file_url").is_some() && v.get("file_data").is_none()),
                    "file" => nested_file || !mistral,
                    "document_url" => !mistral,
                    "image_url" => v
                        .get("image_url")
                        .and_then(|u| u.as_str().or_else(|| u.get("url").and_then(|u| u.as_str())))
                        .is_some_and(is_pdf_data_uri),
                    "input_image" => v.get("image_url").and_then(|u| u.as_str()).is_some_and(is_pdf_data_uri),
                    _ => false,
                }
            })
    }) {
        return Err(AppError::BadRequest(
            "Model does not support PDF/document input.".into(),
        ));
    }
    Ok(())
}

/// Gemini's `fileData` may omit `mimeType` — the Files API resolves the type
/// from the referenced resource — so such a part carries media we cannot
/// classify, and the typed checks above see nothing to match.
///
/// A model with NO media capability at all cannot accept any of them, whatever
/// they turn out to be, so refuse rather than forward blind (otherwise dropping
/// one optional field walks around every modality check). A model that supports
/// at least one modality is forwarded and the upstream resolves the type: we
/// can't tell a video from an image here, and refusing on a maybe would break
/// legitimate Files API use.
fn check_unclassified_media(request: &ApiRequest, caps: &ModelCapabilities) -> Result<(), AppError> {
    if caps.vision || caps.audio_input || caps.video_input || caps.pdf_input {
        return Ok(());
    }
    let ApiRequest::GoogleGemini(req) = request else {
        return Ok(());
    };
    let has_untyped_media = req.contents.iter().any(|c| {
        c.parts.iter().any(|part| {
            matches!(
                part,
                crate::api::gemini::GeminiPart::FileData { file_data }
                    if file_data.mime_type.is_none()
            )
        })
    });
    if has_untyped_media {
        return Err(AppError::BadRequest(
            "Model does not support file/media input.".into(),
        ));
    }
    Ok(())
}

fn check_system_messages(request: &ApiRequest, caps: &ModelCapabilities) -> Result<(), AppError> {
    if caps.system_messages {
        return Ok(());
    }
    let has_system = match request {
        ApiRequest::ChatCompletions(req) => req.messages.iter().any(|m| m.role == "system"),
        ApiRequest::Responses(req) => req.instructions.is_some(),
        ApiRequest::AnthropicMessages(req) => req.system.is_some(),
        ApiRequest::GoogleGemini(req) => req.system_instruction.is_some(),
    };
    if has_system {
        return Err(AppError::BadRequest(
            "Model does not support system messages.".into(),
        ));
    }
    Ok(())
}

fn check_response_schema(request: &ApiRequest, caps: &ModelCapabilities) -> Result<(), AppError> {
    if caps.response_schema {
        return Ok(());
    }
    let has_schema = match request {
        ApiRequest::ChatCompletions(req) => req
            .response_format
            .as_ref()
            .is_some_and(|rf| rf.r#type == "json_schema"),
        ApiRequest::Responses(req) => req
            .extra
            .get("text")
            .and_then(|t| t.get("format"))
            .and_then(|f| f.get("type"))
            .and_then(|t| t.as_str())
            .is_some_and(|t| t == "json_schema"),
        ApiRequest::AnthropicMessages(_) => false, // Anthropic doesn't have this
        ApiRequest::GoogleGemini(req) => req
            .generation_config
            .as_ref()
            .is_some_and(|gc| gc.response_mime_type.as_deref() == Some("application/json")),
    };
    if has_schema {
        return Err(AppError::BadRequest(
            "Model does not support structured output (response_format json_schema).".into(),
        ));
    }
    Ok(())
}

/// Check if any message in the request has a content part matching the predicate.
fn has_content_type(request: &ApiRequest, pred: impl Fn(&ContentPart) -> bool) -> bool {
    match request {
        ApiRequest::ChatCompletions(req) => req.messages.iter().any(|msg| match &msg.content {
            Some(MessageContent::Parts(parts)) => parts.iter().any(&pred),
            _ => false,
        }),
        ApiRequest::Responses(req) => {
            // Check Responses API input messages for content parts
            match &req.input {
                ResponseInput::Messages(msgs) => msgs.iter().any(|msg| match &msg.content {
                    MessageContent::Parts(parts) => parts.iter().any(&pred),
                    _ => false,
                }),
                // A `Raw` item is any Responses input item — a message, a
                // `function_call_output`, … — and the whole input degrades to
                // this variant as soon as ONE item is not a plain message,
                // which is what a conversation becomes the moment it carries a
                // tool result. Leaving it unscanned put every capability check
                // outside the gate for exactly the requests most likely to be
                // multimodal. `ContentPart` has an untagged `Unknown` arm, so
                // the parse always succeeds and unknown parts still reach the
                // predicate. A tool result's `output` array carries the same
                // parts as a message's `content`, and reaches the model too.
                ResponseInput::Raw(items) => items.iter().any(|item| {
                    ["content", "output"].iter().any(|key| {
                        item.get(key)
                            .and_then(|c| c.as_array())
                            .is_some_and(|parts| {
                                parts.iter().any(|p| {
                                    <ContentPart as serde::Deserialize>::deserialize(p).is_ok_and(|cp| pred(&cp))
                                })
                            })
                    })
                }),
                ResponseInput::Text(_) => false,
            }
        }
        ApiRequest::AnthropicMessages(req) => {
            // Anthropic Image block = vision content.
            let image = || {
                pred(&ContentPart::ImageUrl {
                    image_url: crate::api::domain::ImageUrl {
                        url: String::new(),
                        detail: None,
                    },
                })
            };
            // Document block = PDF input (use Unknown with type=document),
            // with how it is sourced.
            let document = |source: &ImageSource| {
                pred(&ContentPart::Unknown(serde_json::json!({"type": "document", "source": {"type": source.r#type}})))
            };
            let unknown = |v: &serde_json::Value| serde_json::from_value::<ContentPart>(v.clone()).is_ok_and(|part| pred(&part));
            req.messages.iter().any(|msg| match &msg.content {
                AnthropicContent::Blocks(blocks) => blocks.iter().any(|block| match block {
                    ContentBlock::Image { .. } => image(),
                    ContentBlock::Document { source, .. } => document(source),
                    ContentBlock::Unknown(v) => unknown(v),
                    // A tool result's images and documents reach the model too.
                    ContentBlock::ToolResult { content: Some(ToolResultContent::Blocks(inner)), .. } => {
                        inner.iter().any(|b| match b {
                            ToolResultBlock::Image { .. } => image(),
                            ToolResultBlock::Document { source, .. } => document(source),
                            ToolResultBlock::Unknown(v) => unknown(v),
                            ToolResultBlock::Text { .. } => false,
                        })
                    }
                    _ => false,
                }),
                _ => false,
            })
        }
        ApiRequest::GoogleGemini(req) => req.contents.iter().any(|c| {
            c.parts.iter().any(|part| {
                // Gemini carries every modality as a MIME type, on either an
                // inline payload or a Files-API/GCS reference. Both channels feed
                // the same mapping — a media type reachable through only one of
                // them would be a hole in the modality check. A `fileData` whose
                // `mimeType` is absent can't be classified here at all; that case
                // belongs to `check_unclassified_media`.
                let mime = match part {
                    crate::api::gemini::GeminiPart::InlineData { inline_data } => {
                        Some(inline_data.mime_type.as_str())
                    }
                    crate::api::gemini::GeminiPart::FileData { file_data } => {
                        file_data.mime_type.as_deref()
                    }
                    // A function response's blobs reach the model too.
                    crate::api::gemini::GeminiPart::FunctionResponse { function_response } => {
                        return function_response.parts.iter().any(|p| {
                            p.pointer("/inlineData/mimeType")
                                .and_then(|m| m.as_str())
                                .is_some_and(|mime| gemini_mime_matches(mime, &pred))
                        });
                    }
                    _ => None,
                };
                mime.is_some_and(|mime| gemini_mime_matches(mime, &pred))
            })
        }),
    }
}

/// Map a Gemini MIME type onto the protocol-agnostic content part the capability
/// checks match against. An unclassifiable MIME matches nothing (the request is
/// forwarded and the upstream decides), but every modality we DO gate on must be
/// mapped here — a missing arm silently disables that check for Gemini clients.
fn gemini_mime_matches(mime: &str, pred: &impl Fn(&ContentPart) -> bool) -> bool {
    if mime.starts_with("image/") {
        pred(&ContentPart::ImageUrl {
            image_url: crate::api::domain::ImageUrl {
                url: String::new(),
                detail: None,
            },
        })
    } else if mime.starts_with("audio/") {
        pred(&ContentPart::InputAudio {
            input_audio: crate::api::domain::InputAudioData {
                data: String::new(),
                format: String::new(),
            },
        })
    } else if mime.starts_with("video/") {
        pred(&ContentPart::Unknown(serde_json::json!({"type": "video"})))
    } else if mime == "application/pdf" {
        pred(&ContentPart::Unknown(serde_json::json!({"type": "document"})))
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use std::assert_matches;

    use super::*;
    use crate::api::chat::ChatCompletionsRequest;
    use crate::api::gemini::GeminiRequest;
    use crate::api::messages::MessagesRequest;
    use crate::api::responses::ResponsesRequest;

    // -----------------------------------------------------------------------
    // Request builders — each protocol parsed from its own wire shape, so the
    // tests exercise the same deserialization the proxy runs on inbound bodies.
    // -----------------------------------------------------------------------

    fn chat(body: serde_json::Value) -> ApiRequest {
        ApiRequest::ChatCompletions(
            serde_json::from_value::<ChatCompletionsRequest>(body).expect("chat wire shape"),
        )
    }

    /// A ChatCompletions request whose single user message carries `parts`.
    fn chat_parts(parts: serde_json::Value) -> ApiRequest {
        chat(serde_json::json!({
            "model": "m",
            "messages": [{ "role": "user", "content": parts }],
        }))
    }

    fn responses(body: serde_json::Value) -> ApiRequest {
        ApiRequest::Responses(
            serde_json::from_value::<ResponsesRequest>(body).expect("responses wire shape"),
        )
    }

    fn anthropic(body: serde_json::Value) -> ApiRequest {
        ApiRequest::AnthropicMessages(
            serde_json::from_value::<MessagesRequest>(body).expect("anthropic wire shape"),
        )
    }

    /// An Anthropic request whose single user message carries `blocks`.
    fn anthropic_blocks(blocks: serde_json::Value) -> ApiRequest {
        anthropic(serde_json::json!({
            "model": "m",
            "max_tokens": 16,
            "messages": [{ "role": "user", "content": blocks }],
        }))
    }

    fn gemini(body: serde_json::Value) -> ApiRequest {
        ApiRequest::GoogleGemini(
            serde_json::from_value::<GeminiRequest>(body).expect("gemini wire shape"),
        )
    }

    /// A Gemini request with one inline-data part of the given MIME type.
    fn gemini_inline(mime_type: &str) -> ApiRequest {
        gemini(serde_json::json!({
            "contents": [{
                "role": "user",
                "parts": [{ "inlineData": { "mimeType": mime_type, "data": "AAAA" } }],
            }],
        }))
    }

    /// Capabilities with everything off — the strictest model, so each check is
    /// exercised in isolation by the request that should trip it.
    fn nothing_supported() -> ModelCapabilities {
        ModelCapabilities::default()
    }

    fn assert_rejected(request: &ApiRequest, caps: &ModelCapabilities) {
        assert_matches!(
            validate_capabilities(request, caps, crate::api::mistral::ChatDialect::Compatible),
            Err(AppError::BadRequest(_))
        );
    }

    fn assert_accepted(request: &ApiRequest, caps: &ModelCapabilities) {
        assert_matches!(validate_capabilities(request, caps, crate::api::mistral::ChatDialect::Compatible), Ok(()));
    }

    // -----------------------------------------------------------------------
    // The default (nothing declared) capability contract
    // -----------------------------------------------------------------------

    /// An undiscovered, uncataloged model resolves to the STANDARD TEXT-LLM set,
    /// not fail-open and not fail-closed: tools, system prompts and structured
    /// output are allowed; every modality is refused until declared.
    #[test]
    fn default_capabilities_allow_the_standard_text_llm_contract() {
        let caps = ModelCapabilities::default_when_unknown();

        assert_accepted(
            &chat(serde_json::json!({
                "model": "m",
                "messages": [
                    { "role": "system", "content": "be brief" },
                    { "role": "user", "content": "hi" },
                ],
                "tools": [{
                    "type": "function",
                    "function": { "name": "get_weather", "parameters": {} },
                }],
                "response_format": { "type": "json_schema" },
            })),
            &caps,
        );

        // …but every modality is off by default.
        assert_rejected(
            &chat_parts(
                serde_json::json!([{ "type": "image_url", "image_url": { "url": "https://x/y.png" } }]),
            ),
            &caps,
        );
    }

    // -----------------------------------------------------------------------
    // Function calling
    // -----------------------------------------------------------------------

    #[test]
    fn tools_require_function_calling_support() {
        let request = chat(serde_json::json!({
            "model": "m",
            "messages": [{ "role": "user", "content": "hi" }],
            "tools": [{
                "type": "function",
                "function": { "name": "get_weather", "parameters": {} },
            }],
        }));

        assert_rejected(&request, &nothing_supported());
        assert_accepted(
            &request,
            &ModelCapabilities { function_calling: true, ..nothing_supported() },
        );
    }

    #[test]
    fn a_toolless_request_never_trips_function_calling() {
        assert_accepted(
            &chat(serde_json::json!({
                "model": "m",
                "messages": [{ "role": "user", "content": "hi" }],
            })),
            &nothing_supported(),
        );
    }

    // -----------------------------------------------------------------------
    // Modalities — each protocol carries the modality in its own wire shape
    // -----------------------------------------------------------------------

    #[test]
    fn image_input_requires_vision_across_protocols() {
        let caps = nothing_supported();
        let with_vision = ModelCapabilities { vision: true, ..nothing_supported() };

        let requests = [
            chat_parts(
                serde_json::json!([{ "type": "image_url", "image_url": { "url": "https://x/y.png" } }]),
            ),
            // Mistral's bare-string spelling, which the parser reads as an image.
            chat_parts(serde_json::json!([{ "type": "image_url", "image_url": "https://x/y.png" }])),
            responses(serde_json::json!({
                "model": "m",
                "input": [{
                    "role": "user",
                    "content": [{ "type": "image_url", "image_url": { "url": "https://x/y.png" } }],
                }],
            })),
            anthropic_blocks(serde_json::json!([{
                "type": "image",
                "source": { "type": "base64", "media_type": "image/png", "data": "AAAA" },
            }])),
            gemini_inline("image/png"),
        ];

        for request in &requests {
            assert_rejected(request, &caps);
            assert_accepted(request, &with_vision);
        }
    }

    /// A tool's output reaches the model like a message's content, so its
    /// images and documents are held to the same capabilities.
    #[test]
    fn a_tool_results_media_is_gated_like_a_messages() {
        let image = || {
            [
                anthropic(serde_json::json!({"model": "m", "max_tokens": 1, "messages": [{"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "c1", "content": [
                        {"type": "text", "text": "shot"},
                        {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"}},
                    ]},
                ]}]})),
                responses(serde_json::json!({"model": "m", "input": [
                    {"type": "function_call_output", "call_id": "c1", "output": [
                        {"type": "input_image", "image_url": "https://x/y.png"},
                    ]},
                ]})),
                gemini(serde_json::json!({"contents": [{"role": "user", "parts": [{"functionResponse": {
                    "name": "shot", "response": {}, "parts": [{"inlineData": {"mimeType": "image/png", "data": "AAAA"}}],
                }}]}]})),
            ]
        };
        let with_vision = ModelCapabilities { vision: true, ..nothing_supported() };
        for request in &image() {
            assert_rejected(request, &nothing_supported());
            assert_accepted(request, &with_vision);
        }

        let pdf = anthropic(serde_json::json!({"model": "m", "max_tokens": 1, "messages": [{"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "c1", "content": [
                {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": "AAAA"}},
            ]},
        ]}]}));
        assert_rejected(&pdf, &with_vision);
        assert_accepted(&pdf, &ModelCapabilities { pdf_input: true, ..nothing_supported() });

        // A `text`-sourced document is text on every walk: no PDF capability
        // asked. A file's bytes are text only once decoded, so a file stays
        // gated whatever type its data URI states.
        let text_doc = anthropic(serde_json::json!({"model": "m", "max_tokens": 1, "messages": [{"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "c1", "content": [
                {"type": "document", "source": {"type": "text", "media_type": "text/plain", "data": "notes"}},
            ]},
        ]}]}));
        assert_accepted(&text_doc, &nothing_supported());
        let text_file = responses(serde_json::json!({"model": "m", "input": [
            {"type": "function_call_output", "call_id": "c1", "output": [
                {"type": "input_file", "filename": "a.txt", "file_data": "data:text/plain;base64,bm90ZXM="},
            ]},
        ]}));
        assert_rejected(&text_file, &nothing_supported());
        // A text result asks for nothing.
        let text = anthropic(serde_json::json!({"model": "m", "max_tokens": 1, "messages": [{"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "c1", "content": [{"type": "text", "text": "ok"}]},
        ]}]}));
        assert_accepted(&text, &nothing_supported());
    }

    #[test]
    fn audio_input_requires_audio_support() {
        let caps = nothing_supported();
        let with_audio = ModelCapabilities { audio_input: true, ..nothing_supported() };

        let requests = [
            chat_parts(serde_json::json!([{
                "type": "input_audio",
                "input_audio": { "data": "AAAA", "format": "wav" },
            }])),
            gemini_inline("audio/wav"),
        ];

        for request in &requests {
            assert_rejected(request, &caps);
            assert_accepted(request, &with_audio);
        }
    }

    #[test]
    fn video_input_requires_video_support() {
        let caps = nothing_supported();
        let with_video = ModelCapabilities { video_input: true, ..nothing_supported() };

        for request in [
            // OpenAI-family protocols don't model video natively — it arrives as
            // an unrecognized part, which is why the check reads the raw `type`.
            chat_parts(serde_json::json!([{ "type": "video", "video": { "url": "https://x/y.mp4" } }])),
            chat_parts(serde_json::json!([{ "type": "input_video", "input_video": { "data": "AAAA" } }])),
            // Gemini carries it as a MIME type on an inline payload.
            gemini_inline("video/mp4"),
        ] {
            assert_rejected(&request, &caps);
            assert_accepted(&request, &with_video);
        }
    }

    /// Gemini can reference media by URI (Files API / GCS) instead of inlining it.
    /// That channel is gated exactly like inline data — otherwise a `fileData`
    /// part would be a free pass around every modality check.
    #[test]
    fn gemini_file_references_are_gated_like_inline_data() {
        let file_part = |mime: &str| {
            gemini(serde_json::json!({
                "contents": [{
                    "role": "user",
                    "parts": [{ "fileData": {
                        "mimeType": mime,
                        "fileUri": "gs://bucket/object",
                    }}],
                }],
            }))
        };

        for (mime, granted) in [
            ("image/png", ModelCapabilities { vision: true, ..nothing_supported() }),
            ("audio/wav", ModelCapabilities { audio_input: true, ..nothing_supported() }),
            ("video/mp4", ModelCapabilities { video_input: true, ..nothing_supported() }),
            ("application/pdf", ModelCapabilities { pdf_input: true, ..nothing_supported() }),
        ] {
            assert_rejected(&file_part(mime), &nothing_supported());
            assert_accepted(&file_part(mime), &granted);
        }
    }

    /// `mimeType` is optional on a Gemini file reference (the Files API resolves it
    /// from the resource), so the typed modality checks have nothing to match —
    /// omitting it must not be a way around them. A model with NO media capability
    /// refuses it outright; a model with any modality is forwarded, since we cannot
    /// tell here which one it carries and refusing on a maybe would break the
    /// legitimate Files API flow.
    #[test]
    fn a_gemini_file_reference_without_a_mime_type_cannot_walk_past_the_checks() {
        let untyped = gemini(serde_json::json!({
            "contents": [{
                "role": "user",
                "parts": [{ "fileData": { "fileUri": "gs://bucket/clip.mp4" } }],
            }],
        }));

        assert_rejected(&untyped, &nothing_supported());
        assert_rejected(&untyped, &ModelCapabilities::default_when_unknown());
        assert_accepted(
            &untyped,
            &ModelCapabilities { vision: true, ..nothing_supported() },
        );
    }

    /// An Anthropic block the typed enum does not model still has to reach the
    /// modality checks. Claude Code and other clients send forward-compatible
    /// block types, and a request carrying one that IS a known modality must be
    /// gated on it rather than waved through as "unrecognised".
    #[test]
    fn an_unrecognised_anthropic_block_is_still_classified() {
        let video = anthropic(serde_json::json!({
            "model": "claude-3", "max_tokens": 64,
            "messages": [{ "role": "user", "content": [
                { "type": "input_video", "data": "AAAA" }
            ]}],
        }));
        assert_rejected(&video, &nothing_supported());
        assert_accepted(
            &video,
            &ModelCapabilities { video_input: true, ..nothing_supported() },
        );
    }

    /// The Responses spellings differ from the Chat ones, and a check that knows
    /// only the Chat spelling is a gate with a door in it. `input_video` and
    /// `input_audio` were already matched; `input_image` and `input_file` were
    /// not, so a Responses client's picture or PDF reached the upstream against
    /// a model declaring neither capability.
    #[test]
    fn the_responses_spellings_are_gated_like_the_chat_ones() {
        let picture = responses(serde_json::json!({
            "model": "m",
            "input": [{ "role": "user", "content": [
                { "type": "input_image", "image_url": "data:image/png;base64,AAAA" }
            ]}],
        }));
        assert_rejected(&picture, &nothing_supported());
        assert_accepted(&picture, &ModelCapabilities { vision: true, ..nothing_supported() });

        let pdf = responses(serde_json::json!({
            "model": "m",
            "input": [{ "role": "user", "content": [
                { "type": "input_file", "filename": "a.pdf",
                  "file_data": "data:application/pdf;base64,AAAA" }
            ]}],
        }));
        assert_rejected(&pdf, &nothing_supported());
        assert_accepted(&pdf, &ModelCapabilities { pdf_input: true, ..nothing_supported() });
    }

    /// The whole `input` degrades to the `Raw` variant as soon as ONE item is
    /// not a plain message — which is what a conversation becomes the moment it
    /// carries a tool result. Leaving `Raw` unscanned put every capability check
    /// outside the gate for precisely the requests most likely to be multimodal.
    #[test]
    fn a_raw_responses_input_is_scanned_like_a_message_one() {
        let with_tool_result = responses(serde_json::json!({
            "model": "m",
            "input": [
                { "type": "function_call_output", "call_id": "c1", "output": "done" },
                { "role": "user", "content": [
                    { "type": "input_image", "image_url": "data:image/png;base64,AAAA" }
                ]}
            ],
        }));
        assert_rejected(&with_tool_result, &nothing_supported());
        assert_accepted(
            &with_tool_result,
            &ModelCapabilities { vision: true, ..nothing_supported() },
        );
    }

    #[test]
    fn pdf_input_requires_pdf_support() {
        let caps = nothing_supported();
        let with_pdf = ModelCapabilities { pdf_input: true, ..nothing_supported() };

        let requests = [
            chat_parts(serde_json::json!([{ "type": "file", "file": { "file_data": "AAAA" } }])),
            // A PDF smuggled through the image_url channel as a data URI —
            // in Mistral's bare-string spelling too.
            chat_parts(serde_json::json!([{ "type": "image_url", "image_url": "data:application/pdf;base64,AAAA" }])),
            chat_parts(serde_json::json!([{
                "type": "image_url",
                "image_url": { "url": "data:application/pdf;base64,AAAA" },
            }])),
            anthropic_blocks(serde_json::json!([{
                "type": "document",
                "source": { "type": "base64", "media_type": "application/pdf", "data": "AAAA" },
            }])),
            gemini_inline("application/pdf"),
        ];

        for request in &requests {
            assert_rejected(request, &caps);
            assert_accepted(request, &with_pdf);
        }
    }

    /// Mistral's document parts are not held to `pdf_input`: no Mistral model
    /// publishes a document capability, so gating them would refuse Mistral's
    /// own document questions on every model — on a Mistral target. OpenAI's
    /// nested file still is, and elsewhere so are they.
    #[test]
    fn mistrals_document_parts_are_not_held_to_pdf_support() {
        use crate::api::mistral::ChatDialect;
        let caps = nothing_supported();
        let mistral_docs = [
            chat_parts(serde_json::json!([{ "type": "document_url", "document_url": "https://x/a.pdf" }])),
            chat_parts(serde_json::json!([{ "type": "file", "file_id": "f-1" }])),
        ];
        for request in &mistral_docs {
            // On a Mistral target they pass…
            assert_matches!(validate_capabilities(request, &caps, ChatDialect::Mistral), Ok(()));
            // …and anywhere else they are documents, gated like any other.
            assert_rejected(request, &caps);
        }
        let openai_file = chat_parts(serde_json::json!([{ "type": "file", "file": { "file_id": "f-1" } }]));
        assert_matches!(validate_capabilities(&openai_file, &caps, ChatDialect::Mistral), Err(_));
        // Another client's document BY URL is the same `document_url` there;
        // one carrying its bytes is still a PDF the model must declare.
        let by_url = anthropic_blocks(serde_json::json!([{
            "type": "document", "source": { "type": "url", "url": "https://x/a.pdf" } }]));
        assert_matches!(validate_capabilities(&by_url, &caps, ChatDialect::Mistral), Ok(()));
        assert_rejected(&by_url, &caps);
        let inline = anthropic_blocks(serde_json::json!([{
            "type": "document", "source": { "type": "base64", "media_type": "application/pdf", "data": "AAAA" } }]));
        assert_matches!(validate_capabilities(&inline, &caps, ChatDialect::Mistral), Err(_));
    }

    /// A PDF data URI trips the PDF check, not the vision check — so granting
    /// vision alone does not smuggle a document into a text-only model.
    #[test]
    fn a_pdf_data_uri_is_not_laundered_by_vision_support() {
        assert_rejected(
            &chat_parts(serde_json::json!([{
                "type": "image_url",
                "image_url": { "url": "data:application/pdf;base64,AAAA" },
            }])),
            &ModelCapabilities { vision: true, ..nothing_supported() },
        );
    }

    /// The PDF classifier is anchored at the `data:` scheme. A remote image whose
    /// URL merely CONTAINS the string is an image: it must be gated by vision (and
    /// must not be refused as a document), or the two checks stop partitioning the
    /// image channel — one way round an image reaches a non-vision model, the other
    /// a plain PNG is refused as a PDF.
    #[test]
    fn a_remote_url_containing_the_pdf_string_is_still_an_image() {
        let request = chat_parts(serde_json::json!([{
            "type": "image_url",
            "image_url": { "url": "https://cdn.example.com/application/pdf/cover.png" },
        }]));

        // Gated by vision…
        assert_rejected(
            &request,
            &ModelCapabilities { pdf_input: true, ..nothing_supported() },
        );
        // …and NOT by the document check.
        assert_accepted(
            &request,
            &ModelCapabilities { vision: true, ..nothing_supported() },
        );
    }

    // -----------------------------------------------------------------------
    // System messages — one carrier per protocol
    // -----------------------------------------------------------------------

    #[test]
    fn system_prompts_require_system_message_support() {
        let caps = nothing_supported();
        let with_system = ModelCapabilities { system_messages: true, ..nothing_supported() };

        let requests = [
            chat(serde_json::json!({
                "model": "m",
                "messages": [
                    { "role": "system", "content": "be brief" },
                    { "role": "user", "content": "hi" },
                ],
            })),
            responses(serde_json::json!({
                "model": "m",
                "input": "hi",
                "instructions": "be brief",
            })),
            anthropic(serde_json::json!({
                "model": "m",
                "max_tokens": 16,
                "system": "be brief",
                "messages": [{ "role": "user", "content": "hi" }],
            })),
            gemini(serde_json::json!({
                "contents": [{ "role": "user", "parts": [{ "text": "hi" }] }],
                "systemInstruction": { "parts": [{ "text": "be brief" }] },
            })),
        ];

        for request in &requests {
            assert_rejected(request, &caps);
            assert_accepted(request, &with_system);
        }
    }

    // -----------------------------------------------------------------------
    // Structured output
    // -----------------------------------------------------------------------

    #[test]
    fn json_schema_output_requires_response_schema_support() {
        let caps = nothing_supported();
        let with_schema = ModelCapabilities { response_schema: true, ..nothing_supported() };

        let requests = [
            chat(serde_json::json!({
                "model": "m",
                "messages": [{ "role": "user", "content": "hi" }],
                "response_format": { "type": "json_schema" },
            })),
            responses(serde_json::json!({
                "model": "m",
                "input": "hi",
                "text": { "format": { "type": "json_schema" } },
            })),
            gemini(serde_json::json!({
                "contents": [{ "role": "user", "parts": [{ "text": "hi" }] }],
                "generationConfig": { "responseMimeType": "application/json" },
            })),
        ];

        for request in &requests {
            assert_rejected(request, &caps);
            assert_accepted(request, &with_schema);
        }
    }

    /// `response_format: {"type": "json_object"}` is not a schema — it must not
    /// trip the structured-output check.
    #[test]
    fn json_object_mode_is_not_a_response_schema() {
        assert_accepted(
            &chat(serde_json::json!({
                "model": "m",
                "messages": [{ "role": "user", "content": "hi" }],
                "response_format": { "type": "json_object" },
            })),
            &nothing_supported(),
        );
    }

    // -----------------------------------------------------------------------
    // The deliberate non-checks
    // -----------------------------------------------------------------------

    /// Caching and reasoning are NOT validated: the proxy strips both during
    /// translation, and rejecting would break clients (Claude Code always sends
    /// `cache_control` + thinking config). A model with neither capability must
    /// still accept a request carrying both.
    #[test]
    fn caching_and_reasoning_hints_are_never_rejected() {
        assert_accepted(
            &anthropic(serde_json::json!({
                "model": "m",
                "max_tokens": 16,
                "thinking": { "type": "enabled", "budget_tokens": 1024 },
                "messages": [{
                    "role": "user",
                    "content": [{
                        "type": "text",
                        "text": "hi",
                        "cache_control": { "type": "ephemeral" },
                    }],
                }],
            })),
            &nothing_supported(),
        );
    }
}

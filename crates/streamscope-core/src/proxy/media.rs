//! Media proxy handlers for non-chat endpoints (embeddings, audio, images, video).
//!
//! These handlers follow the same auth + route + forward + audit pattern as the
//! chat proxy handlers, but simplified: no streaming, no transforms, no session
//! detection. The request body is forwarded as-is to the upstream provider.
//!
//! Multipart endpoints (audio transcription/translation, image edits/variations)
//! forward the original Content-Type header so the upstream receives the correct
//! boundary string.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::response::Response;
use sha2::{Digest, Sha256};

use crate::api::media::{MediaType, MAX_MEDIA_BODY_SIZE, MAX_MEDIA_RESPONSE_SIZE};
use crate::audit::{AuditRecord, BlobType};
use crate::auth;
use crate::error::AppError;
use crate::middleware::attribution;

use super::{AppState, ForwardAuthContext, TenantRequestCtx, send_audit};

// Blob size limit is configured via TenantConfig.media_blob_max_size_mb.

// ---------------------------------------------------------------------------
// MediaEndpoint — maps request paths to endpoint metadata
// ---------------------------------------------------------------------------

/// Known media endpoint, identified from the request path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaEndpoint {
    Embeddings,
    AudioSpeech,
    AudioTranscriptions,
    AudioTranslations,
    ImagesGenerations,
    ImagesEdits,
    ImagesVariations,
    VideosGenerations,
}

impl MediaEndpoint {
    /// Parse endpoint from the request path suffix.
    ///
    /// Accepts paths like `/v1/embeddings` or `/fwd/{key}/v1/embeddings`.
    pub fn from_path(path: &str) -> Option<Self> {
        // Strip optional `/fwd/{key}` prefix to get the canonical path.
        let canonical = if path.starts_with("/fwd/") {
            // /fwd/{key}/v1/... -> find "/v1/" and take from there
            if let Some(idx) = path.find("/v1/") {
                &path[idx..]
            } else {
                path
            }
        } else {
            path
        };

        match canonical {
            "/v1/embeddings" => Some(Self::Embeddings),
            "/v1/audio/speech" => Some(Self::AudioSpeech),
            "/v1/audio/transcriptions" => Some(Self::AudioTranscriptions),
            "/v1/audio/translations" => Some(Self::AudioTranslations),
            "/v1/images/generations" => Some(Self::ImagesGenerations),
            "/v1/images/edits" => Some(Self::ImagesEdits),
            "/v1/images/variations" => Some(Self::ImagesVariations),
            "/v1/videos/generations" => Some(Self::VideosGenerations),
            _ => None,
        }
    }

    /// The upstream path to forward to (always the canonical OpenAI path).
    pub fn upstream_path(&self) -> &'static str {
        match self {
            Self::Embeddings => "/v1/embeddings",
            Self::AudioSpeech => "/v1/audio/speech",
            Self::AudioTranscriptions => "/v1/audio/transcriptions",
            Self::AudioTranslations => "/v1/audio/translations",
            Self::ImagesGenerations => "/v1/images/generations",
            Self::ImagesEdits => "/v1/images/edits",
            Self::ImagesVariations => "/v1/images/variations",
            Self::VideosGenerations => "/v1/videos/generations",
        }
    }

    /// The high-level media type for audit classification.
    pub fn media_type(&self) -> MediaType {
        match self {
            Self::Embeddings => MediaType::Embedding,
            Self::AudioSpeech | Self::AudioTranscriptions | Self::AudioTranslations => {
                MediaType::Audio
            }
            Self::ImagesGenerations | Self::ImagesEdits | Self::ImagesVariations => {
                MediaType::Image
            }
            Self::VideosGenerations => MediaType::Video,
        }
    }

    /// The media direction for analytics: "generation", "speech", "transcription", "encode", "edit".
    pub fn direction(&self) -> &'static str {
        match self {
            Self::Embeddings => "encode",
            Self::AudioSpeech => "speech",
            Self::AudioTranscriptions => "transcription",
            Self::AudioTranslations => "translation",
            Self::ImagesGenerations => "generation",
            Self::ImagesEdits | Self::ImagesVariations => "edit",
            Self::VideosGenerations => "generation",
        }
    }

    /// Whether this endpoint expects a multipart/form-data body.
    pub fn is_multipart(&self) -> bool {
        matches!(
            self,
            Self::AudioTranscriptions
                | Self::AudioTranslations
                | Self::ImagesEdits
                | Self::ImagesVariations
        )
    }

    /// Default model name when the client omits the `model` field.
    pub fn default_model(&self) -> Option<&'static str> {
        match self {
            Self::ImagesGenerations | Self::ImagesEdits | Self::ImagesVariations => {
                Some("dall-e-2")
            }
            _ => None,
        }
    }
}

impl From<MediaEndpoint> for crate::api::domain_request::DomainMediaEndpoint {
    fn from(e: MediaEndpoint) -> Self {
        match e {
            MediaEndpoint::Embeddings => Self::Embeddings,
            MediaEndpoint::AudioSpeech => Self::Speech,
            MediaEndpoint::AudioTranscriptions => Self::Transcription,
            MediaEndpoint::AudioTranslations => Self::Translation,
            MediaEndpoint::ImagesGenerations => Self::ImageGeneration,
            MediaEndpoint::ImagesEdits => Self::ImageEdit,
            MediaEndpoint::ImagesVariations => Self::ImageVariation,
            MediaEndpoint::VideosGenerations => Self::VideoGeneration,
        }
    }
}

// ---------------------------------------------------------------------------
// Minimal model extractor (avoids full parse — just grabs the model field)
// ---------------------------------------------------------------------------

/// Minimal struct to extract just the `model` field from a JSON request body.
#[derive(serde::Deserialize)]
struct ModelExtract {
    #[serde(default)]
    model: Option<String>,
}

/// Extract the model name from a JSON body, or `None` if body is not JSON
/// or the model field is missing.
fn extract_model_from_json(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<ModelExtract>(body)
        .ok()
        .and_then(|m| m.model)
}

/// Extract model name from the request body, handling both JSON and multipart.
fn extract_model(body: &[u8], content_type: &str) -> Option<String> {
    if content_type.starts_with("multipart/form-data") {
        super::forward_body::multipart_field(body, content_type, "model")
    } else {
        extract_model_from_json(body)
    }
}

/// Extract input text for audit logging (from JSON or multipart bodies).
fn extract_input_text(body: &[u8], endpoint: MediaEndpoint, content_type: &str) -> Option<String> {
    // For multipart endpoints, extract text fields from the multipart body
    if endpoint.is_multipart() && content_type.starts_with("multipart/") {
        return match endpoint {
            // Image edits send "prompt" as a form field
            MediaEndpoint::ImagesEdits => {
                extract_text_field_from_multipart(body, content_type, "prompt")
                    .map(|s| truncate_text(&s, 500))
            }
            // Transcription/translation/variations have no meaningful text input
            _ => None,
        };
    }

    // JSON body extraction
    #[derive(serde::Deserialize)]
    struct InputExtract {
        #[serde(default)]
        input: Option<serde_json::Value>,
        #[serde(default)]
        prompt: Option<String>,
    }

    let parsed: InputExtract = serde_json::from_slice(body).ok()?;

    match endpoint {
        MediaEndpoint::Embeddings => {
            match parsed.input? {
                serde_json::Value::String(s) => Some(truncate_text(&s, 500)),
                serde_json::Value::Array(arr) => {
                    arr.first()
                        .and_then(|v| v.as_str())
                        .map(|s| truncate_text(s, 500))
                }
                _ => None,
            }
        }
        MediaEndpoint::AudioSpeech => {
            parsed.input
                .and_then(|v| match v {
                    serde_json::Value::String(s) => Some(truncate_text(&s, 500)),
                    _ => None,
                })
        }
        MediaEndpoint::ImagesGenerations
        | MediaEndpoint::ImagesEdits
        | MediaEndpoint::VideosGenerations => {
            parsed.prompt.map(|s| truncate_text(&s, 500))
        }
        _ => None,
    }
}

/// Extract all base64-encoded images from an OpenAI images response JSON.
/// Response format: `{"data": [{"b64_json": "..."}, ...]}` — decode each entry
/// to raw bytes. Entries missing / not decodable are skipped (best-effort);
/// order is preserved to match the caller's `n` prompt semantics.
fn extract_b64_from_image_response(resp: &[u8]) -> Vec<bytes::Bytes> {
    use base64::Engine;
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(resp) else {
        return Vec::new();
    };
    let Some(arr) = v.get("data").and_then(|d| d.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|entry| {
            let b64 = entry.get("b64_json")?.as_str()?;
            base64::engine::general_purpose::STANDARD
                .decode(b64)
                .ok()
                .map(bytes::Bytes::from)
        })
        .collect()
}



/// The field name in multipart uploads that contains the primary file.
fn multipart_file_field(endpoint: MediaEndpoint) -> &'static str {
    match endpoint {
        MediaEndpoint::AudioTranscriptions | MediaEndpoint::AudioTranslations => "file",
        MediaEndpoint::ImagesEdits | MediaEndpoint::ImagesVariations => "image",
        _ => "file",
    }
}

/// Extract the file content and its MIME type from a multipart/form-data body.
/// Returns `(file_bytes, mime_type)` for the primary file field.
fn extract_file_from_multipart(body: &[u8], content_type: &str, endpoint: MediaEndpoint) -> Option<(bytes::Bytes, String)> {
    // Parse boundary from Content-Type header
    let boundary = content_type
        .split("boundary=")
        .nth(1)
        .map(|b| b.trim().trim_matches('"'))?;

    let field_name = multipart_file_field(endpoint);
    let boundary_bytes = format!("--{boundary}").into_bytes();

    // Split body by boundary
    let mut parts = Vec::new();
    let mut start = 0;
    while let Some(pos) = find_subsequence(&body[start..], &boundary_bytes) {
        if start > 0 {
            parts.push(&body[start..start + pos]);
        }
        start += pos + boundary_bytes.len();
        // Skip \r\n after boundary
        if start < body.len() && body[start] == b'\r' { start += 1; }
        if start < body.len() && body[start] == b'\n' { start += 1; }
    }

    for part in parts {
        if part.is_empty() || part == b"--\r\n" || part == b"--" {
            continue;
        }

        // Find the header/body separator (\r\n\r\n) — skip malformed parts
        let Some(header_end) = find_subsequence(part, b"\r\n\r\n") else { continue; };
        let Ok(headers_str) = std::str::from_utf8(&part[..header_end]) else { continue; };

        // Check if this part has our target field name
        if !headers_str.contains(&format!("name=\"{field_name}\"")) {
            continue;
        }

        // Extract Content-Type from part headers
        let mut part_mime = match endpoint {
            MediaEndpoint::AudioTranscriptions | MediaEndpoint::AudioTranslations => "audio/mpeg",
            MediaEndpoint::ImagesEdits | MediaEndpoint::ImagesVariations => "image/png",
            _ => "application/octet-stream",
        };
        for line in headers_str.lines() {
            if let Some(ct) = line.strip_prefix("Content-Type:").or_else(|| line.strip_prefix("content-type:")) {
                part_mime = ct.trim();
                break;
            }
        }

        // Body starts after \r\n\r\n, ends before trailing \r\n
        let body_start = header_end + 4;
        let mut body_end = part.len();
        // Strip trailing \r\n before next boundary
        if body_end >= 2 && part[body_end - 2] == b'\r' && part[body_end - 1] == b'\n' {
            body_end -= 2;
        }

        if body_start < body_end {
            return Some((
                bytes::Bytes::copy_from_slice(&part[body_start..body_end]),
                part_mime.to_string(),
            ));
        }
    }
    None
}

/// Extract a text field value from a multipart/form-data body.
fn extract_text_field_from_multipart(body: &[u8], content_type: &str, field_name: &str) -> Option<String> {
    let boundary = content_type
        .split("boundary=")
        .nth(1)
        .map(|b| b.trim().trim_matches('"'))?;

    let boundary_bytes = format!("--{boundary}").into_bytes();

    let mut parts = Vec::new();
    let mut start = 0;
    while let Some(pos) = find_subsequence(&body[start..], &boundary_bytes) {
        if start > 0 {
            parts.push(&body[start..start + pos]);
        }
        start += pos + boundary_bytes.len();
        if start < body.len() && body[start] == b'\r' { start += 1; }
        if start < body.len() && body[start] == b'\n' { start += 1; }
    }

    for part in parts {
        if part.is_empty() || part == b"--\r\n" || part == b"--" {
            continue;
        }
        let Some(header_end) = find_subsequence(part, b"\r\n\r\n") else { continue; };
        let Ok(headers_str) = std::str::from_utf8(&part[..header_end]) else { continue; };

        // Check for target field name (text fields have no filename)
        if !headers_str.contains(&format!("name=\"{field_name}\"")) {
            continue;
        }
        // Skip file fields (they have a filename)
        if headers_str.contains("filename=") {
            continue;
        }

        let body_start = header_end + 4;
        let mut body_end = part.len();
        if body_end >= 2 && part[body_end - 2] == b'\r' && part[body_end - 1] == b'\n' {
            body_end -= 2;
        }
        if body_start < body_end {
            return std::str::from_utf8(&part[body_start..body_end])
                .ok()
                .map(|s| s.to_string());
        }
    }
    None
}

/// Find the first occurrence of `needle` in `haystack`.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Compute SHA-256 hex digest of a byte slice.
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Truncate text at a valid UTF-8 boundary and append the `…` surface marker
/// when truncation occurs. Re-export of [`crate::proxy::truncate_with_marker`]
/// kept under the old name so module-local call sites don't need to change.
fn truncate_text(s: &str, max_chars: usize) -> String {
    crate::proxy::truncate_with_marker(s, max_chars)
}

/// How many output units the upstream produced, for the audit row's rendered
/// label — vectors returned, images generated, one job. This answers "what came
/// back", NOT "what is billable": for embeddings those differ, and conflating
/// them bills a request for the number of vectors rather than the tokens behind
/// them. Cost uses [`extract_billable_units`].
///
/// - Embeddings: number of embedding vectors in the response
/// - Images: number of images generated (`data` array length)
/// - Audio speech (TTS): 1 (per request)
/// - Audio transcription/translation: 1 (per request)
/// - Video: 1 (per request)
fn extract_media_output_units(resp_bytes: &[u8], endpoint: MediaEndpoint) -> i32 {
    match endpoint {
        MediaEndpoint::Embeddings => {
            // Response: { "data": [ { "embedding": [...] }, ... ] }
            #[derive(serde::Deserialize)]
            struct EmbeddingResp {
                #[serde(default)]
                data: Vec<serde_json::Value>,
            }
            serde_json::from_slice::<EmbeddingResp>(resp_bytes)
                .map(|r| r.data.len() as i32)
                .unwrap_or(1)
        }
        MediaEndpoint::ImagesGenerations | MediaEndpoint::ImagesEdits | MediaEndpoint::ImagesVariations => {
            // Response: { "data": [ { "url": "..." }, ... ] }
            #[derive(serde::Deserialize)]
            struct ImageResp {
                #[serde(default)]
                data: Vec<serde_json::Value>,
            }
            serde_json::from_slice::<ImageResp>(resp_bytes)
                .map(|r| r.data.len().max(1) as i32)
                .unwrap_or(1)
        }
        MediaEndpoint::AudioSpeech => 1,
        MediaEndpoint::AudioTranscriptions | MediaEndpoint::AudioTranslations => 1,
        MediaEndpoint::VideosGenerations => 1,
    }
}

/// What the response says the request consumed, as named billing units.
///
/// Deliberately NOT [`extract_media_output_units`], and deliberately not a bare
/// number: an embeddings request is priced per token but returns one vector per
/// input, so charging the vector count bills a 10,000-token document as three
/// tokens. Naming the unit is what makes that class of mistake impossible —
/// there is no number whose meaning a later reader has to infer.
///
/// Read from the response wherever the provider reports it there, and from the
/// **request** for the two dimensions no response carries: the text a
/// text-to-speech call is billed on, and the duration a video generation was
/// asked for. Those are still the provider's own numbers — the literal string
/// and the literal parameter it was invoiced against, not a re-derivation of
/// something it already counted.
///
/// A unit neither side carries is simply absent. The caller records that as a
/// measurement gap rather than as a free request, because a figure we cannot
/// measure must not be reported as zero.
fn extract_billable_units(
    resp_bytes: &[u8],
    req_bytes: &[u8],
    endpoint: MediaEndpoint,
) -> crate::pricing::Units {
    use crate::pricing::{Unit, Units};
    let mut units = Units::new();
    match endpoint {
        MediaEndpoint::Embeddings => {
            // Priced per token → the unit is the token count the provider
            // reports. Every OpenAI-compatible embeddings endpoint returns
            // `usage`; one that doesn't leaves no basis to charge.
            // Response: { "data": [...], "usage": { "prompt_tokens": N, "total_tokens": N } }
            #[derive(serde::Deserialize)]
            struct EmbeddingUsage {
                #[serde(default)]
                prompt_tokens: Option<i64>,
                #[serde(default)]
                total_tokens: Option<i64>,
            }
            #[derive(serde::Deserialize)]
            struct EmbeddingResp {
                #[serde(default)]
                usage: Option<EmbeddingUsage>,
            }
            let tokens = serde_json::from_slice::<EmbeddingResp>(resp_bytes)
                .ok()
                .and_then(|r| r.usage)
                .and_then(|u| u.prompt_tokens.or(u.total_tokens))
                .unwrap_or(0);
            units.add(Unit::InputToken, tokens.max(0) as u64);
        }
        MediaEndpoint::ImagesGenerations
        | MediaEndpoint::ImagesEdits
        | MediaEndpoint::ImagesVariations => {
            let images = extract_media_output_units(resp_bytes, endpoint);
            units.add(Unit::ImageOutput, images.max(0) as u64);
        }
        MediaEndpoint::AudioTranscriptions | MediaEndpoint::AudioTranslations => {
            // Two shapes, in order of authority. A transcription response may
            // carry an explicit `usage` block naming what it was billed in —
            // seconds of source audio, or tokens for the token-priced models —
            // and that is the provider stating its own basis. Failing that, the
            // verbose response format reports a top-level `duration`. A plain
            // `json` response carries neither, and inventing one second per
            // request would bill a one-hour recording as a one-second one.
            //
            // A `usage` this build cannot interpret must fall through to the
            // `duration`, never suppress it — see `TranscriptionResp::usage`.
            #[derive(serde::Deserialize)]
            struct TokenDetails {
                #[serde(default)]
                audio_tokens: Option<i64>,
            }
            #[derive(serde::Deserialize)]
            #[serde(tag = "type")]
            enum TranscriptionUsage {
                #[serde(rename = "duration")]
                Duration {
                    #[serde(default)]
                    seconds: Option<f64>,
                },
                #[serde(rename = "tokens")]
                Tokens {
                    #[serde(default)]
                    input_tokens: Option<i64>,
                    #[serde(default)]
                    input_token_details: Option<TokenDetails>,
                    #[serde(default)]
                    output_tokens: Option<i64>,
                },
                /// A basis named by a `type` this build does not know.
                #[serde(other)]
                Unrecognised,
            }
            #[derive(serde::Deserialize)]
            struct TranscriptionResp {
                #[serde(default)]
                duration: Option<f64>,
                /// Held as raw JSON and interpreted separately, NOT typed as
                /// `Option<TranscriptionUsage>` directly. A `usage` this build
                /// cannot name — an unknown `type`, no `type` at all (the
                /// chat-shaped `{prompt_tokens,…}` some OpenAI-compatible
                /// upstreams attach), or not an object — would otherwise fail the
                /// whole response parse and take the top-level `duration` sitting
                /// beside it down with it, silently billing nothing for a
                /// response that plainly says how long the audio was.
                #[serde(default)]
                usage: Option<serde_json::Value>,
            }
            let parsed = serde_json::from_slice::<TranscriptionResp>(resp_bytes).ok();
            let usage = parsed
                .as_ref()
                .and_then(|r| r.usage.as_ref())
                .and_then(|v| serde_json::from_value::<TranscriptionUsage>(v.clone()).ok());
            match usage.as_ref() {
                Some(TranscriptionUsage::Duration { seconds }) => {
                    if let Some(s) = seconds.filter(|d| d.is_finite() && *d > 0.0) {
                        units.add(Unit::AudioSecond, s.ceil() as u64);
                    }
                }
                Some(TranscriptionUsage::Tokens {
                    input_tokens,
                    input_token_details,
                    output_tokens,
                }) => {
                    // `input_tokens` is inclusive of the audio tokens inside it,
                    // which is exactly the partition the fold subtracts — so add
                    // both counts as reported and let it do the carving.
                    units.add(Unit::InputToken, input_tokens.unwrap_or(0).max(0) as u64);
                    units.add(
                        Unit::AudioInputToken,
                        input_token_details
                            .as_ref()
                            .and_then(|d| d.audio_tokens)
                            .unwrap_or(0)
                            .max(0) as u64,
                    );
                    units.add(Unit::OutputToken, output_tokens.unwrap_or(0).max(0) as u64);
                }
                // Mistral's chat-shaped `usage` (no `type`) states the seconds
                // of audio it bills by (`prompt_audio_seconds`); its token
                // counts are not a price basis there.
                Some(TranscriptionUsage::Unrecognised) | None
                    if let Some(seconds) = parsed
                        .as_ref()
                        .and_then(|r| r.usage.as_ref())
                        .and_then(|u| u.get("prompt_audio_seconds"))
                        .and_then(serde_json::Value::as_f64)
                        .filter(|s| s.is_finite() && *s > 0.0) =>
                {
                    // A fraction is billed as the whole second, as on chat.
                    units.add(Unit::AudioSecond, seconds.ceil() as u64);
                }
                Some(TranscriptionUsage::Unrecognised) | None => {
                    if let Some(seconds) = parsed
                        .as_ref()
                        .and_then(|r| r.duration)
                        .filter(|d| d.is_finite() && *d > 0.0)
                    {
                        units.add(Unit::AudioSecond, seconds.ceil() as u64);
                    }
                }
            }
        }
        MediaEndpoint::AudioSpeech => {
            // Priced on the text that was spoken. The response is audio and
            // carries no usage at all, so the request's own `input` is the only
            // measurement there is — and it is the literal string the provider
            // charged for, not a re-derivation of something it counted.
            //
            // Read here rather than through `extract_input_text`, which
            // truncates to 500 characters for the audit rendering: billing off
            // that would silently under-charge every request longer than a
            // paragraph, and read exactly right on the short ones a test writes.
            if let Some(chars) = extract_speech_input_chars(req_bytes) {
                units.add(Unit::InputCharacter, chars);
            }
        }
        MediaEndpoint::VideosGenerations => {
            // Priced per second of generated video, and the response reports no
            // duration — the request asked for one, and that is what the job
            // renders and the provider invoices.
            if let Some(seconds) = extract_requested_video_seconds(req_bytes) {
                units.add(Unit::VideoSecond, seconds);
            }
        }
    }
    units
}

/// Characters of text a speech request asked to be spoken.
///
/// Counted in Unicode scalar values, never bytes: a French or Japanese prompt
/// runs two to three bytes per character, and billing its UTF-8 length would
/// over-charge it by that factor against a rate quoted per character. A body
/// with no `input` string leaves the call unmeasured — `/v1/audio/speech` is
/// JSON-only, so there is no multipart shape to miss.
fn extract_speech_input_chars(req_bytes: &[u8]) -> Option<u64> {
    #[derive(serde::Deserialize)]
    struct SpeechReq {
        #[serde(default)]
        input: Option<String>,
    }
    let text = serde_json::from_slice::<SpeechReq>(req_bytes).ok()?.input?;
    let chars = text.chars().count() as u64;
    (chars > 0).then_some(chars)
}

/// The video duration a generation request asked for, in whole seconds.
///
/// Spelled differently by each vendor and typed differently by the same one:
/// OpenAI's `seconds` is a string enum, Google's `durationSeconds` a number.
/// Read every spelling we forward to, in one place, and accept either JSON type
/// — a request that names none leaves the call unmeasured rather than billed
/// for a duration nobody asked for.
fn extract_requested_video_seconds(req_bytes: &[u8]) -> Option<u64> {
    const KEYS: [&str; 4] = ["seconds", "duration", "duration_seconds", "durationSeconds"];
    // A day of generated video, against a state of the art measured in seconds.
    // Unlike every other measurement here, this one is a number the CLIENT chose
    // and no body size bounds it, so `{"seconds": 1e18}` on an upstream that
    // accepts the request and ignores the field would bill a fantasy — enough to
    // exhaust a workspace budget, and now the organisation's with it. Beyond this
    // the honest answer is that we cannot measure the call, which records nothing
    // and badges the row; a fabricated charge that moves a real budget is worse
    // than an admitted gap.
    const MAX_PLAUSIBLE_SECONDS: f64 = 86_400.0;
    let body: serde_json::Value = serde_json::from_slice(req_bytes).ok()?;
    let obj = body.as_object()?;
    for key in KEYS {
        let raw = match obj.get(key) {
            Some(v) => v,
            None => continue,
        };
        let seconds = match raw {
            serde_json::Value::Number(n) => n.as_f64(),
            serde_json::Value::String(s) => s.trim().parse::<f64>().ok(),
            _ => None,
        };
        if let Some(s) = seconds.filter(|s| s.is_finite() && *s > 0.0 && *s <= MAX_PLAUSIBLE_SECONDS)
        {
            return Some(s.ceil() as u64);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Canonical capture — build a `DomainMediaCall` from raw request/response bytes.
// Mirrors the render-side arrangement so round-trips through the `media_call`
// JSONB column preserve endpoint-appropriate block kinds.
// ---------------------------------------------------------------------------

use crate::api::domain_request::{
    DomainContentBlock, DomainMediaCall, DomainMediaEndpoint, DomainMediaJob, DomainMediaParams,
};

/// Raw blob metadata the capture path has already computed (hash + MIME + size).
/// Kept separate from body bytes because the hashes are sized against
/// `media_blob_max_size_mb` at the same call site that hashes them.
///
/// `stored = false` signals the payload exceeded the tenant's size cap and
/// was intentionally dropped from the blob pipeline — the canonical
/// `media_call` still carries the metadata via a `Stripped` block so the UI
/// can surface "oversized — not stored" without dropping the entry entirely.
pub struct CapturedBlob {
    pub content_hash: String,
    pub media_type: String,
    pub size_bytes: u64,
    pub stored: bool,
}

/// Inputs to [`build_media_call`] — single argument bundle so the constructor
/// stays under clippy's `too_many_arguments` limit and new fields can be added
/// without churning every call site.
pub struct MediaCaptureCtx<'a> {
    pub endpoint: MediaEndpoint,
    pub model: &'a str,
    pub request_bytes: &'a [u8],
    pub request_content_type: &'a str,
    pub response_bytes: &'a [u8],
    pub upstream_success: bool,
    pub request_blob: Option<CapturedBlob>,
    /// All response blobs in upstream order. For image endpoints with `n>1`,
    /// every returned image becomes a `BlobRef` block in `output` so nothing is
    /// silently dropped. For single-blob endpoints (TTS, single-image) the Vec
    /// holds one entry; for endpoints without a binary response it is empty.
    pub response_blobs: Vec<CapturedBlob>,
    /// Upper bound on the persisted size of any one media artifact, in bytes.
    /// Derived from the tenant's `media_blob_max_size_mb` setting — unified
    /// cap for both binary blobs (audio/image bytes) and structured JSON output
    /// (`verbose_json` from Whisper). Oversized payloads are dropped with a
    /// warning rather than inflating `audit_log.media_call` JSONB.
    pub max_artifact_bytes: usize,
}

/// Build the canonical [`DomainMediaCall`] for a completed media request.
///
/// Assembles the per-endpoint `input` / `output` block arrangement the render
/// side reads. Multipart text fields (`language`, `temperature`, `size`, `n`,
/// ...) are captured into [`DomainMediaParams`] so transcription / image-edit
/// params survive capture.
pub fn build_media_call(ctx: MediaCaptureCtx<'_>) -> DomainMediaCall {
    let MediaCaptureCtx {
        endpoint,
        model,
        request_bytes,
        request_content_type,
        response_bytes,
        upstream_success,
        request_blob,
        response_blobs,
        max_artifact_bytes,
    } = ctx;
    let domain_endpoint: DomainMediaEndpoint = endpoint.into();
    let params = extract_domain_params(endpoint, request_bytes, request_content_type);

    let mut input: Vec<DomainContentBlock> = Vec::new();
    let mut output: Vec<DomainContentBlock> = Vec::new();
    let mut output_structured: Option<serde_json::Value> = None;
    let mut job: Option<DomainMediaJob> = None;

    let text_block = |text: String| DomainContentBlock::Text {
        text,
        cache_control: None,
    };
    // When the blob is `stored=true`, emit a BlobRef that resolves to the
    // stored bytes. When dropped for size, emit a `Stripped` placeholder so
    // the UI can show the endpoint + size without a broken download link.
    let blob_block = |b: CapturedBlob, blob_type: BlobType| -> DomainContentBlock {
        if b.stored {
            DomainContentBlock::BlobRef {
                content_hash: b.content_hash,
                media_type: b.media_type,
                size_bytes: Some(b.size_bytes),
                blob_type: Some(blob_type),
                cache_control: None,
            }
        } else {
            DomainContentBlock::Stripped {
                media_type: Some(b.media_type),
                size_bytes: Some(b.size_bytes),
                reason: Some("oversized".to_string()),
            }
        }
    };

    match endpoint {
        MediaEndpoint::Embeddings => {
            if let Some(prompt) = extract_input_text(request_bytes, endpoint, request_content_type) {
                input.push(text_block(prompt));
            }
            // Embeddings output has no renderable content (a vector of floats).
            // The count lives on `output_units` — the UI shows it as "N embedding
            // vector(s)". Pushing a redundant Text block here made the number
            // render twice (once white, once green) in session replay.
        }
        MediaEndpoint::AudioSpeech => {
            if let Some(prompt) = extract_input_text(request_bytes, endpoint, request_content_type) {
                input.push(text_block(prompt));
            }
            for b in response_blobs {
                output.push(blob_block(b, BlobType::ResponseBody));
            }
        }
        MediaEndpoint::AudioTranscriptions | MediaEndpoint::AudioTranslations => {
            if let Some(b) = request_blob {
                input.push(blob_block(b, BlobType::RequestUpload));
            }
            if upstream_success
                && let Some(text) = extract_transcription_text(response_bytes)
            {
                output.push(text_block(truncate_text(&text, 1000)));
            }
            // Whisper's verbose_json variant carries language/duration/segments —
            // surface it as `output_structured` so render / transforms can consume
            // the full payload without re-parsing.
            if upstream_success
                && let Some(v) = parse_verbose_json(response_bytes, max_artifact_bytes)
            {
                output_structured = Some(v);
            }
        }
        MediaEndpoint::ImagesGenerations => {
            if let Some(prompt) = extract_input_text(request_bytes, endpoint, request_content_type) {
                input.push(text_block(prompt));
            }
            for b in response_blobs {
                output.push(blob_block(b, BlobType::ResponseBody));
            }
        }
        MediaEndpoint::ImagesEdits | MediaEndpoint::ImagesVariations => {
            if let Some(b) = request_blob {
                input.push(blob_block(b, BlobType::RequestUpload));
            }
            if let Some(prompt) = extract_input_text(request_bytes, endpoint, request_content_type) {
                input.push(text_block(prompt));
            }
            for b in response_blobs {
                output.push(blob_block(b, BlobType::ResponseBody));
            }
        }
        MediaEndpoint::VideosGenerations => {
            if let Some(prompt) = extract_input_text(request_bytes, endpoint, request_content_type) {
                input.push(text_block(prompt));
            }
            if upstream_success
                && let Some(j) = parse_video_job(response_bytes)
            {
                job = Some(j);
            }
            for b in response_blobs {
                output.push(blob_block(b, BlobType::ResponseBody));
            }
        }
    }

    let output_units = if upstream_success {
        let units = extract_media_output_units(response_bytes, endpoint);
        if units > 0 { Some(units as u32) } else { None }
    } else {
        None
    };

    DomainMediaCall {
        endpoint: domain_endpoint,
        model: model.to_string(),
        input,
        output,
        output_structured,
        job,
        params,
        output_units,
    }
}

/// Projection of raw request body onto `DomainMediaParams`. Covers JSON bodies
/// (speech/embeddings/image-gen) and multipart form fields (transcription,
/// image edits) — the multipart branch is what the prior ad-hoc path dropped.
fn extract_domain_params(
    endpoint: MediaEndpoint,
    body: &[u8],
    content_type: &str,
) -> DomainMediaParams {
    let mut p = DomainMediaParams::default();
    if content_type.starts_with("multipart/form-data") {
        let get = |name: &str| extract_text_field_from_multipart(body, content_type, name);
        p.language = get("language");
        p.temperature = get("temperature").and_then(|s| s.parse::<f32>().ok());
        p.size = get("size");
        p.n = get("n").and_then(|s| s.parse::<u32>().ok());
        p.format = get("response_format").or_else(|| get("format"));
        return p;
    }

    let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
        return p;
    };
    let Some(obj) = v.as_object() else {
        return p;
    };
    let get_str = |k: &str| obj.get(k).and_then(|v| v.as_str()).map(String::from);
    let get_u = |k: &str| obj.get(k).and_then(|v| v.as_u64()).map(|u| u as u32);
    let get_f = |k: &str| obj.get(k).and_then(|v| v.as_f64()).map(|f| f as f32);

    p.voice = get_str("voice");
    p.format = obj
        .get("response_format")
        .or_else(|| obj.get("format"))
        .and_then(|v| v.as_str())
        .map(String::from);
    p.size = get_str("size");
    p.n = get_u("n");
    p.language = get_str("language");
    p.temperature = get_f("temperature");

    // Keep other known-optional keys in `extra` so analytics / transforms can
    // inspect them without losing fidelity. Claim list matches the typed fields
    // plus any endpoint-irrelevant keys we intentionally skip (`input`, `prompt`
    // are carried as input blocks, not params).
    let claimed: &[&str] = &[
        "voice",
        "response_format",
        "format",
        "size",
        "n",
        "language",
        "temperature",
        "model",
        "input",
        "prompt",
    ];
    let param_keys: &[&str] = match endpoint {
        MediaEndpoint::Embeddings => &["encoding_format", "dimensions"],
        MediaEndpoint::AudioSpeech => &["speed"],
        MediaEndpoint::ImagesGenerations => &["quality", "style"],
        MediaEndpoint::ImagesEdits | MediaEndpoint::ImagesVariations => &[],
        MediaEndpoint::VideosGenerations => &["seconds", "duration"],
        MediaEndpoint::AudioTranscriptions | MediaEndpoint::AudioTranslations => &[],
    };
    for k in param_keys {
        if let Some(v) = obj.get(*k)
            && !v.is_null()
        {
            p.extra.insert((*k).to_string(), v.clone());
        }
    }
    // Preserve any other unmodeled keys (future-proof).
    for (k, v) in obj {
        if !claimed.contains(&k.as_str())
            && !param_keys.contains(&k.as_str())
            && !v.is_null()
        {
            p.extra.insert(k.clone(), v.clone());
        }
    }
    p
}

/// The `data:` payloads of a server-sent-event body, or `None` when the body
/// is not one (it does not open with an SSE field).
fn sse_payloads(body: &[u8]) -> Option<Vec<serde_json::Value>> {
    use tokio_util::codec::Decoder;
    let start = std::str::from_utf8(body).ok()?.trim_start();
    if !(start.starts_with("event:") || start.starts_with("data:") || start.starts_with(':')) {
        return None;
    }
    // The one SSE decoder the proxy reads streams with: a `data:` field
    // spread over several lines is one event's data.
    let mut decoder = crate::api::sse::SseDecoder::new();
    let mut buf = bytes::BytesMut::from(body);
    let mut events = Vec::new();
    while let Ok(Some(event)) = decoder.decode_eof(&mut buf) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&event.data) {
            events.push(v);
        }
    }
    Some(events)
}

/// What a media answer states, as the JSON body the non-streamed answer would
/// be. A streamed transcription (`stream: true` — OpenAI's
/// `transcript.text.done`, Mistral's `transcription.done`) states its result
/// and `usage` in its final event; read as JSON, the whole SSE body parses as
/// nothing and the request would bill — and audit — nothing.
fn media_result(endpoint: MediaEndpoint, resp: &bytes::Bytes) -> bytes::Bytes {
    if !matches!(endpoint, MediaEndpoint::AudioTranscriptions | MediaEndpoint::AudioTranslations) {
        return resp.clone();
    }
    let Some(events) = sse_payloads(resp) else { return resp.clone() };
    events
        .iter()
        .rev()
        .find(|e| e.get("usage").is_some())
        .or_else(|| events.iter().rev().find(|e| e.get("text").is_some()))
        .and_then(|e| serde_json::to_vec(e).ok())
        .map(bytes::Bytes::from)
        .unwrap_or_else(|| resp.clone())
}

/// The audio a speech answer carries, decoded: the body itself (OpenAI), or
/// the base64 `audio_data` of Mistral's JSON answer — or of each of its
/// streamed `speech.audio.delta` events, in order. Stored as anything else, the
/// blob would be the JSON or SSE text, which no player plays.
fn speech_audio(resp: &bytes::Bytes) -> bytes::Bytes {
    use base64::Engine;
    // Mistral's `audio_data`; OpenAI's streamed `speech.audio.delta` says `audio`.
    let decode = |v: &serde_json::Value| {
        v.get("audio_data")
            .or_else(|| v.get("audio"))
            .and_then(serde_json::Value::as_str)
            .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
    };
    if let Some(events) = sse_payloads(resp) {
        let audio: Vec<u8> = events.iter().filter_map(decode).flatten().collect();
        if !audio.is_empty() {
            return bytes::Bytes::from(audio);
        }
    } else if resp.first() == Some(&b'{')
        && let Ok(v) = serde_json::from_slice::<serde_json::Value>(resp)
        && let Some(audio) = decode(&v)
    {
        return bytes::Bytes::from(audio);
    }
    resp.clone()
}

fn extract_transcription_text(resp_bytes: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct TranscriptionResponse {
        #[serde(default)]
        text: Option<String>,
    }
    serde_json::from_slice::<TranscriptionResponse>(resp_bytes)
        .ok()
        .and_then(|r| r.text)
}

/// Build a placeholder value for structured output that was dropped for size.
/// Preserves the size + reason so the UI can surface the omission instead of
/// leaving the field blank.
fn truncated_structured_placeholder(bytes: usize, cap: usize) -> serde_json::Value {
    serde_json::json!({
        "truncated": true,
        "reason": "oversized",
        "bytes": bytes,
        "cap_bytes": cap,
    })
}

/// Return the transcription response as structured output iff it genuinely
/// carries Whisper `verbose_json`-shaped metadata (`segments` or `words`).
/// When the payload exceeds the caller-supplied `max_bytes` cap
/// (tenant-configured via `media_blob_max_size_mb`) a
/// [`truncated_structured_placeholder`] is returned so `media_call.output_structured`
/// still carries the metadata without inflating the audit row. Plain `{text}`
/// and non-verbose `{text, duration, language}` shapes return `None` — their
/// scalar fields are already carried elsewhere (params / output text block)
/// and don't need to be persisted verbatim.
fn parse_verbose_json(resp_bytes: &[u8], max_bytes: usize) -> Option<serde_json::Value> {
    if resp_bytes.len() > max_bytes {
        tracing::warn!(
            bytes = resp_bytes.len(),
            cap = max_bytes,
            "oversized verbose_json; keeping metadata-only placeholder on media_call.output_structured"
        );
        return Some(truncated_structured_placeholder(resp_bytes.len(), max_bytes));
    }
    let v: serde_json::Value = serde_json::from_slice(resp_bytes).ok()?;
    let obj = v.as_object()?;
    // Require one of the array-valued structural fields — `duration` /
    // `language` alone appear on non-verbose responses and aren't worth
    // storing as structured output.
    let has_structured_arrays = obj
        .get("segments")
        .or_else(|| obj.get("words"))
        .is_some_and(|f| f.is_array());
    if !has_structured_arrays {
        return None;
    }
    // Double-check the serialized form fits the cap (JSON parsing can compact
    // whitespace; also a defensive belt in case of re-serialization).
    let serialized_len = serde_json::to_vec(&v).ok()?.len();
    if serialized_len > max_bytes {
        tracing::warn!(
            bytes = serialized_len,
            cap = max_bytes,
            "oversized verbose_json; keeping metadata-only placeholder on media_call.output_structured"
        );
        return Some(truncated_structured_placeholder(serialized_len, max_bytes));
    }
    Some(v)
}

/// Best-effort parse of a Sora-style video generation response into a
/// [`DomainMediaJob`]. Absent fields fall back to conservative defaults so the
/// canonical shape is never silently lost.
fn parse_video_job(resp_bytes: &[u8]) -> Option<DomainMediaJob> {
    let v: serde_json::Value = serde_json::from_slice(resp_bytes).ok()?;
    let obj = v.as_object()?;
    let job_id = obj.get("id").and_then(|v| v.as_str())?.to_string();
    let status = obj
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("queued")
        .to_string();
    let progress = obj
        .get("progress")
        .and_then(|v| v.as_f64())
        .map(|f| f as f32);
    let eta = obj
        .get("eta")
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc));
    Some(DomainMediaJob {
        job_id,
        status,
        progress,
        eta,
    })
}

// ---------------------------------------------------------------------------
// Error audit context (mirrors proxy/mod.rs pattern)
// ---------------------------------------------------------------------------

/// Context available at the point of failure, used to enrich error audit records.
struct MediaErrorAuditCtx<'a> {
    request_id: uuid::Uuid,
    user_id: uuid::Uuid,
    tenant_id: uuid::Uuid,
    /// The key's workspace once authenticated; nil before.
    workspace_id: uuid::Uuid,
    key_id: Option<uuid::Uuid>,
    model_requested: &'a str,
    model_used: Option<&'a str>,
    provider: Option<&'a str>,
    app_id: Option<&'a str>,
    /// How `app_id` was recognised.
    detection_method: Option<&'a str>,
    /// The client's User-Agent as stored.
    user_agent: Option<&'a str>,
    endpoint: Option<MediaEndpoint>,
    /// The upstream the request was last sent to.
    attempted: super::AttemptedUpstream,
    /// The replicas and targets the request moved on from, and the one under way.
    attempts: super::AttemptLog,
}

/// Send an error audit record with media-specific fields populated.
async fn send_media_error_audit(state: &AppState, ctx: &MediaErrorAuditCtx<'_>, error: &AppError) {
    let mut record = AuditRecord::error_record(
        ctx.request_id,
        ctx.user_id,
        ctx.tenant_id,
        ctx.workspace_id,
        ctx.key_id,
        error,
    );
    record.model_requested = ctx.model_requested.to_string();
    if let Some(m) = ctx.model_used {
        record.model_used = m.to_string();
    }
    if let Some(p) = ctx.provider {
        record.provider = p.to_string();
    }
    // After the primary's model and provider: the upstream last attempted
    // names its own, so the row never pairs one target's server with
    // another's model.
    ctx.attempted.stamp(&mut record);
    record.moved_on_from = ctx.attempts.moved_on_from().to_vec();
    record.app_id = ctx.app_id.map(|s| s.to_string());
    record.detection_method = ctx.detection_method.map(|s| s.to_string());
    record.user_agent = ctx.user_agent.map(|s| s.to_string());
    if let Some(ep) = ctx.endpoint {
        // Even on pre-request errors we tag the canonical endpoint so analytics
        // can classify the failure; input/output are empty because the body was
        // never successfully forwarded.
        record.media_call = Some(crate::api::domain_request::DomainMediaCall {
            endpoint: ep.into(),
            model: ctx.model_requested.to_string(),
            input: Vec::new(),
            output: Vec::new(),
            output_structured: None,
            job: None,
            params: Default::default(),
            output_units: None,
        });
    }
    send_audit(&state.audit_tx, record, &ctx.request_id.to_string()).await;
}

// ---------------------------------------------------------------------------
// Public handlers
// ---------------------------------------------------------------------------

/// Media proxy handler — standard auth via `Authorization: Bearer` or `x-api-key`.
pub async fn media_handler(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> Result<Response, AppError> {
    let http_version = req.version();
    let (parts, body) = req.into_parts();
    media_handler_inner(state, parts.headers, parts.uri.path().to_string(), body, http_version, None, None).await
}

/// BYOK forward-auth media handler.
///
/// Extracts the virtual key from the URL path (`/fwd/{key}/v1/...`) for proxy auth,
/// and preserves the client's `Authorization`/`x-api-key` header for upstream forwarding.
pub async fn fwd_media_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(key): axum::extract::Path<String>,
    req: Request<Body>,
) -> Result<Response, AppError> {
    let http_version = req.version();
    let (parts, body) = req.into_parts();
    let headers = parts.headers;
    let path = parts.uri.path().to_string();

    // Extract the client's credential (header, or Gemini's `?key=` query param).
    let fwd_auth = super::extract_forward_auth_context(&headers, parts.uri.query())?;

    // Authenticate using the path key.
    // The registry guard is released here, never held across an error audit.
    let authenticated = auth::authenticate_forward(&key, &state.tenant_registry.load());
    let ctx = match authenticated {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(key_prefix = %crate::auth::credential_prefix(&key, 6), "fwd media auth failed");
            return Err(e);
        }
    };

    media_handler_inner(state, headers, path, body, http_version, Some(fwd_auth), Some(ctx)).await
}

// ---------------------------------------------------------------------------
// Inner implementation
// ---------------------------------------------------------------------------

/// Shared media handler implementation: auth -> rate limit -> route -> forward -> audit.
#[allow(clippy::too_many_arguments)]
async fn media_handler_inner(
    state: Arc<AppState>,
    headers: axum::http::HeaderMap,
    path: String,
    body: Body,
    _http_version: axum::http::Version,
    fwd_auth: Option<ForwardAuthContext>,
    pre_authenticated: Option<TenantRequestCtx>,
) -> Result<Response, AppError> {
    let request_id = crate::ids::mint_request_id();
    let request_started_at = std::time::Instant::now();

    // Track request stats.
    state.proxy_stats.inc_requests();

    // Identify endpoint from path.
    let endpoint = MediaEndpoint::from_path(&path).ok_or_else(|| {
        AppError::BadRequest(format!("unknown media endpoint: {path}"))
    })?;

    // Log path with key redacted for /fwd/ routes.
    let log_path = if path.starts_with("/fwd/") {
        if let Some(rest) = path.splitn(4, '/').nth(3) {
            format!("/fwd/[redacted]/{rest}")
        } else {
            "/fwd/[redacted]".to_string()
        }
    } else {
        path.clone()
    };
    tracing::info!(
        request_id = %request_id,
        path = %log_path,
        endpoint = ?endpoint,
        "media_handler invoked"
    );

    // Error audit context — enriched incrementally.
    let mut err_ctx = MediaErrorAuditCtx {
        request_id,
        user_id: uuid::Uuid::nil(),
        tenant_id: uuid::Uuid::from_u128(1), // SYSTEM default for pre-auth errors
        workspace_id: uuid::Uuid::nil(),
        key_id: None,
        model_requested: "",
        model_used: None,
        provider: None,
        app_id: None,
        detection_method: None,
        user_agent: None,
        endpoint: Some(endpoint),
        attempted: super::AttemptedUpstream::default(),
        attempts: super::AttemptLog::default(),
    };

    // --- Auth --- the key and its tenant's configuration, from one registry load.
    let ctx = if let Some(ctx) = pre_authenticated {
        ctx
    } else {
        let bearer = match auth::extract_api_token(&headers) {
            Ok(b) => b,
            Err(e) => {
                send_media_error_audit(&state, &err_ctx, &e).await;
                state.proxy_stats.inc_errors();
                return Err(e);
            }
        };
        let authenticated = auth::authenticate_proxy(&bearer, &state.tenant_registry.load());
        match authenticated {
            Ok(c) => c,
            Err(e) => {
                send_media_error_audit(&state, &err_ctx, &e).await;
                state.proxy_stats.inc_errors();
                return Err(e);
            }
        }
    };

    // Enrich error context with user info.
    err_ctx.user_id = ctx.user.user_id;
    err_ctx.tenant_id = ctx.user.tenant_id;
    err_ctx.workspace_id = ctx.user.workspace_id;
    err_ctx.key_id = ctx.user.key_id;

    // --- Rate limit (RPM only for media) — no-op unless a cap is configured ---
    if let Err(e) = crate::middleware::rate_limit::check_rate_limit(&ctx.user, &state.usage) {
        send_media_error_audit(&state, &err_ctx, &e).await;
        state.proxy_stats.inc_errors();
        return Err(e);
    }

    // --- Budget check (daily + monthly) ---
    if let Err(e) = crate::middleware::rate_limit::check_budget(
        &ctx.user,
        &state.usage,
        ctx.config.pricing.accounting_currency,
    ) {
        send_media_error_audit(&state, &err_ctx, &e).await;
        state.proxy_stats.inc_errors();
        return Err(e);
    }

    // --- Buffer request body ---
    let body_bytes = match axum::body::to_bytes(body, MAX_MEDIA_BODY_SIZE).await {
        Ok(b) => b,
        Err(e) => {
            let err = AppError::BadRequest(format!("failed to read media body: {e}"));
            send_media_error_audit(&state, &err_ctx, &err).await;
            state.proxy_stats.inc_errors();
            return Err(err);
        }
    };

    // --- Extract content type ---
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();

    // --- MIME validation: check Content-Type matches endpoint expectations ---
    let is_multipart_request = content_type.starts_with("multipart/form-data");
    if endpoint.is_multipart() && !is_multipart_request {
        let err = AppError::BadRequest(format!(
            "endpoint {} expects multipart/form-data, got {}",
            endpoint.upstream_path(),
            content_type
        ));
        send_media_error_audit(&state, &err_ctx, &err).await;
        state.proxy_stats.inc_errors();
        return Err(err);
    }
    if !endpoint.is_multipart() && is_multipart_request {
        let err = AppError::BadRequest(format!(
            "endpoint {} does not accept multipart/form-data",
            endpoint.upstream_path()
        ));
        send_media_error_audit(&state, &err_ctx, &err).await;
        state.proxy_stats.inc_errors();
        return Err(err);
    }

    // --- Extract model from body ---
    let model_from_body = extract_model(&body_bytes, &content_type);
    if model_from_body.is_none() && content_type.starts_with("multipart") {
        tracing::warn!(
            content_type = %content_type,
            body_len = body_bytes.len(),
            "media: failed to extract model from multipart body"
        );
    }
    let model_requested = model_from_body
        .clone()
        .or_else(|| endpoint.default_model().map(|s| s.to_string()))
        .unwrap_or_default();

    if model_requested.is_empty() {
        let err = AppError::BadRequest("missing 'model' field in request body".to_string());
        send_media_error_audit(&state, &err_ctx, &err).await;
        state.proxy_stats.inc_errors();
        return Err(err);
    }

    // Reject an oversized model identifier before routing or any audit write —
    // same bound as the LLM path, covering BYOK pass-through and unknown models.
    // Sits before `err_ctx.model_requested` is set so the rejection's own
    // error-audit row never stores the oversized value.
    if model_requested.len() > super::MAX_MODEL_NAME_LEN {
        let err = AppError::BadRequest(format!(
            "model name exceeds {} bytes",
            super::MAX_MODEL_NAME_LEN
        ));
        send_media_error_audit(&state, &err_ctx, &err).await;
        state.proxy_stats.inc_errors();
        return Err(err);
    }

    // --- Attribution ---
    let attr = attribution::extract_attribution(&headers, ctx.user.user_id, &ctx.config.app_patterns, ctx.user.inline_ai);
    err_ctx.model_requested = &model_requested;
    err_ctx.app_id = attr.app_id.as_deref();
    err_ctx.detection_method = attr.detection_method.as_deref();
    err_ctx.user_agent = attr.user_agent.as_deref();

    // --- Resolve upstream target ---
    // Session-pin upstream selection (preserves the provider prompt cache across
    // a session's turns for multi-target LB-group aliases; no session id → RR).
    let resolved = super::routing::origin_host(&headers, &ctx.user).and_then(|origin_host| {
        super::routing::resolve_all_upstreams_by_model(
            &model_requested,
            &ctx.user,
            &ctx.config.credentials,
            &state.lb_counters,
            attr.session_id.as_deref(),
            crate::api::sse::ApiVersion::from_path(&path),
            origin_host,
            &ctx.config.endpoints,
            true,
        )
    });
    let all_targets = match resolved {
        Ok(t) => super::order_by_health(&state, t),
        Err(e) => {
            let e = e.for_model(err_ctx.model_requested);
            send_media_error_audit(&state, &err_ctx, &e).await;
            state.proxy_stats.inc_errors();
            return Err(e);
        }
    };

    let upstream_target = match all_targets.first() {
        Some(t) => t.clone(),
        None => {
            let e = AppError::ModelNotFound("no upstream target available for media".into());
            send_media_error_audit(&state, &err_ctx, &e).await;
            state.proxy_stats.inc_errors();
            return Err(e);
        }
    };

    err_ctx.model_used = Some(&upstream_target.model);
    err_ctx.provider = Some(&upstream_target.provider);

    // --- Forward to upstream with failover ---
    let upstream_path = endpoint.upstream_path();
    let mut actual_target = upstream_target.clone();
    let mut upstream_response = None;
    let mut last_err = None;
    // What the forward removed from the client's body — the same on every
    // target, so the first preparation's record stands for the row.
    let mut forward_diff = None;

    // Routes whose replica gave an answer no other replica would change (a
    // client error): their remaining replicas are skipped, their fallbacks are
    // not. A set — the breaker reorder can interleave one route's replicas
    // with another route's.
    let mut settled_slots: Vec<usize> = Vec::new();
    for (i, target) in all_targets.iter().enumerate() {
        if settled_slots.contains(&target.route_slot) {
            continue;
        }
        if i > 0 {
            actual_target = target.clone();
        }
        // Per target: a routed target's body names THIS target's upstream
        // model, never the client's alias (a pass-through keeps the client's
        // own); no body carries a gateway-owned field.
        // An attempt begins here: the one before it, if any, is one the
        // request moved on from.
        err_ctx.attempts.begin();
        let prepared = match super::forward_body::prepare(&body_bytes, &content_type, target.forward_model()) {
            Ok(p) => p,
            Err(e) => {
                // The body could not be prepared for this target, so the
                // request was never offered to it: the row names no upstream
                // (its failure is not a server's), and the previous target's
                // failure, if any, is one it moved on from.
                err_ctx.attempted = super::AttemptedUpstream::default();
                send_media_error_audit(&state, &err_ctx, &e).await;
                state.proxy_stats.inc_errors();
                return Err(e);
            }
        };
        if i == 0 {
            forward_diff = prepared.audit_diff();
        }
        // A target with another endpoint of its route still to try gets no
        // retries: the next attempt goes to that replica, not this URL again.
        // Anywhere later in the list, not only next: the health reorder can put
        // another route's target between two replicas of one.
        let spill_next = all_targets[i + 1..]
            .iter()
            .any(|later| later.same_route_as(target) && !settled_slots.contains(&later.route_slot));
        let max_retries = if spill_next { 0 } else if i == 0 { 2 } else { 1 };
        // BYOK credential rule: forward the client's credential ONLY when this
        // target has no stored credential (pass-through / keyless route). A
        // target WITH a stored key (e.g. an override route to an on-prem
        // upstream) uses ITS key — the client's credential never leaks to it.
        let auth_override = if target.has_stored_credential {
            None
        } else {
            fwd_auth.as_ref()
        };

        match state.http_client.forward_media_with_retry(
            target.endpoint(),
            prepared.bytes,
            &headers,
            upstream_path,
            &content_type,
            max_retries,
            auth_override,
        ).await {
            Ok(resp) => {
                super::note_forward_outcome(&state, ctx.user.tenant_id, target, Ok(()));
                upstream_response = Some(resp);
                break;
            }
            Err(e) => {
                // Media is never gated, so an attempt waits for nothing.
                if !super::record_failed_attempt(
                    &state,
                    ctx.user.tenant_id,
                    target,
                    &e,
                    std::time::Duration::ZERO,
                    &mut err_ctx.attempted,
                    &mut err_ctx.attempts,
                ) {
                    settled_slots.push(target.route_slot);
                }
                if all_targets.len() > 1 {
                    tracing::warn!(
                        target = i,
                        model = %target.model,
                        provider = %target.provider,
                        error = %e,
                        "media upstream target failed, trying next"
                    );
                }
                last_err = Some(e);
            }
        }
    }

    let upstream_resp = match upstream_response {
        Some(r) => r,
        None => {
            let e = last_err
                .unwrap_or_else(|| {
                    AppError::Internal("no upstream targets available for media".into())
                })
                .for_model(err_ctx.model_requested);
            send_media_error_audit(&state, &err_ctx, &e).await;
            state.proxy_stats.inc_errors();
            return Err(e);
        }
    };
    let moved_on_from = std::mem::take(&mut err_ctx.attempts).into_moved_on_from();

    let latency_total_ms = request_started_at.elapsed().as_millis() as u64;
    let upstream_status = upstream_resp.status();

    tracing::info!(
        request_id = %request_id,
        model = %actual_target.model,
        provider = %actual_target.provider,
        endpoint = ?endpoint,
        status = upstream_status.as_u16(),
        latency_ms = latency_total_ms,
        "media request completed"
    );

    // --- Read upstream response ---
    let resp_content_type = upstream_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let resp_headers = upstream_resp.headers().clone();
    let resp_bytes = crate::http_body::read_body_capped(upstream_resp, MAX_MEDIA_RESPONSE_SIZE as u64)
        .await
        .map_err(|e| AppError::Internal(format!("failed to read upstream media response: {e}")))?;
    // What the answer states, for billing and the audit: the body, or a
    // streamed answer's final result event. The client is sent the body.
    let result_bytes = media_result(endpoint, &resp_bytes);

    // --- Blob extraction (decoded final binary + hash + MIME) ---
    // Response blobs: TTS raw, image b64_json decoded. Request blobs: multipart file.
    // Hashes feed the BlobRef entries inside `media_call`; bytes ride through the
    // transient `media_*_blob_data` fields to the blob sync pipeline.
    let max_blob_bytes = ctx.config.media_blob_max_size_mb as usize * 1024 * 1024;
    let capture_blobs = ctx.config.content_logging_enabled
        && ctx.config.media_blob_storage_enabled
        && upstream_status.is_success();

    // Per-endpoint response-blob extraction. Image endpoints with `n>1` return
    // multiple b64_json entries — capture all of them; everything else yields
    // zero or one blob.
    let extracted_blobs: Vec<bytes::Bytes> = if !capture_blobs || resp_bytes.is_empty() {
        Vec::new()
    } else {
        match endpoint {
            MediaEndpoint::AudioSpeech => vec![speech_audio(&resp_bytes)],
            MediaEndpoint::ImagesGenerations
            | MediaEndpoint::ImagesEdits
            | MediaEndpoint::ImagesVariations => {
                let imgs = extract_b64_from_image_response(&resp_bytes);
                if imgs.is_empty() {
                    // Response didn't parse as the canonical `{data:[{b64_json}]}`
                    // shape — fall back to storing the raw body so operators can
                    // still retrieve something.
                    vec![resp_bytes.clone()]
                } else {
                    imgs
                }
            }
            // Video POST: async job — no binary to capture here (see TODO on
            // video catch-all content capture). Transcription / translation /
            // embeddings: JSON text, no binary blob.
            MediaEndpoint::VideosGenerations
            | MediaEndpoint::AudioTranscriptions
            | MediaEndpoint::AudioTranslations
            | MediaEndpoint::Embeddings => Vec::new(),
        }
    };

    // Hash + size-check each blob individually. Oversized entries emit
    // metadata (hash, mime, size, reason="oversized") into the canonical
    // `media_call.output` via a `Stripped` block — the UI shows the entry
    // with "not stored" so operators see the omission instead of a silent
    // drop. In-cap entries: the first rides through `media_response_blob_data`
    // (paired with the media call's first blob reference when the edge
    // buffers it); extras are pushed into `message_blobs` so they ship
    // alongside chat-turn media.
    let mut response_blobs_meta: Vec<CapturedBlob> = Vec::new();
    let mut response_blob_data: Option<bytes::Bytes> = None;
    let mut extra_response_blobs: Vec<(CapturedBlob, bytes::Bytes)> = Vec::new();
    let mime = endpoint.media_type().default_response_mime().to_string();
    for data in extracted_blobs {
        let size_bytes = data.len() as u64;
        let hash = sha256_hex(&data);
        let stored = data.len() <= max_blob_bytes;
        if !stored {
            tracing::warn!(
                bytes = data.len(),
                cap_mb = ctx.config.media_blob_max_size_mb,
                "media response blob exceeds cap; surfacing as Stripped placeholder"
            );
            response_blobs_meta.push(CapturedBlob {
                content_hash: hash,
                media_type: mime.clone(),
                size_bytes,
                stored: false,
            });
            continue;
        }
        let meta = CapturedBlob {
            content_hash: hash,
            media_type: mime.clone(),
            size_bytes,
            stored: true,
        };
        if response_blob_data.is_none() {
            response_blob_data = Some(data);
            response_blobs_meta.push(CapturedBlob {
                content_hash: meta.content_hash.clone(),
                media_type: meta.media_type.clone(),
                size_bytes: meta.size_bytes,
                stored: true,
            });
        } else {
            extra_response_blobs.push((
                CapturedBlob {
                    content_hash: meta.content_hash.clone(),
                    media_type: meta.media_type.clone(),
                    size_bytes: meta.size_bytes,
                    stored: true,
                },
                data,
            ));
            response_blobs_meta.push(meta);
        }
    }

    let mut request_blob_data: Option<bytes::Bytes> = None;
    let mut request_blob_meta: Option<CapturedBlob> = None;
    if capture_blobs && endpoint.is_multipart() && !body_bytes.is_empty()
        && let Some((file_data, mime)) = extract_file_from_multipart(&body_bytes, &content_type, endpoint)
    {
        let size_bytes = file_data.len() as u64;
        let hash = sha256_hex(&file_data);
        if file_data.len() <= max_blob_bytes {
            request_blob_meta = Some(CapturedBlob {
                content_hash: hash,
                media_type: mime,
                size_bytes,
                stored: true,
            });
            request_blob_data = Some(file_data);
        } else {
            tracing::warn!(
                bytes = file_data.len(),
                cap_mb = ctx.config.media_blob_max_size_mb,
                "media request upload exceeds cap; surfacing as Stripped placeholder"
            );
            request_blob_meta = Some(CapturedBlob {
                content_hash: hash,
                media_type: mime,
                size_bytes,
                stored: false,
            });
        }
    }

    // --- Canonical media call (source of truth — serialized to audit_log.media_call) ---
    let media_call = build_media_call(MediaCaptureCtx {
        endpoint,
        model: &actual_target.model,
        request_bytes: &body_bytes,
        request_content_type: &content_type,
        response_bytes: &result_bytes,
        upstream_success: upstream_status.is_success(),
        request_blob: request_blob_meta,
        response_blobs: response_blobs_meta,
        max_artifact_bytes: max_blob_bytes,
    });

    // --- Build audit record ---
    let estimated_input_tokens =
        crate::middleware::tokens::estimate_input_tokens_from_bytes(body_bytes.len(), None);
    let mut record = AuditRecord {
        request_id,
        timestamp: chrono::Utc::now(),
        user_id: ctx.user.user_id,
        tenant_id: ctx.user.tenant_id,
        workspace_id: ctx.user.workspace_id,
        key_id: ctx.user.key_id,
        app_id: attr.app_id,
        user_agent: attr.user_agent,
        client_ip: attr.client_ip,
        end_user: attr.end_user,
        end_user_groups: attr.end_user_groups,
        detection_method: attr.detection_method,
        model_requested,
        model_used: actual_target.model.clone(),
        provider: actual_target.provider.clone(),
        api_version: crate::api::sse::ApiVersion::ChatCompletions, // Media uses OpenAI format
        stream: false,
        prompt_tokens: estimated_input_tokens,
        completion_tokens: 0,
        finish_reason: if upstream_status.is_success() {
            "stop".to_string()
        } else {
            "error".to_string()
        },
        latency_total_ms,
        latency_ttft_ms: latency_total_ms, // No streaming, TTFT = total
        upstream_server_id: actual_target
            .upstream_server_id
            .as_deref()
            .and_then(|s| uuid::Uuid::parse_str(s).ok()),
        endpoint_id: actual_target.endpoint_id,
        endpoint_url: actual_target.endpoint_id.map(|_| actual_target.url.clone()),
        moved_on_from,
        upstream_model_id: actual_target
            .upstream_model_id
            .as_deref()
            .and_then(|s| uuid::Uuid::parse_str(s).ok()),
        media_call: Some(media_call),
        media_blob_data: request_blob_data,
        media_response_blob_data: response_blob_data,
        // Error fields (if upstream returned non-2xx)
        status_code: if !upstream_status.is_success() {
            Some(upstream_status.as_u16())
        } else {
            None
        },
        error_category: if !upstream_status.is_success() {
            Some("upstream".to_string())
        } else {
            None
        },
        error_detail: if !upstream_status.is_success() {
            // Sanitize: don't expose raw upstream error body to audit
            Some(format!("upstream returned {}", upstream_status.as_u16()))
        } else {
            None
        },
        // Media endpoints have 0 completion tokens by design — not an error.
        zero_completion: false,
        ..Default::default()
    };
    if let Some(diff) = forward_diff {
        record.transform_diff = Some(diff);
        record.badges.push(crate::audit::AuditBadge::Modified);
    }

    // For image endpoints with `n>1`, extra response images (beyond the first
    // carried by `media_response_blob_data`) ride on `message_blobs` so the
    // blob sync pipeline streams them to admin-api. Their BlobRef entries
    // already live in `media_call.output`.
    for (meta, data) in extra_response_blobs {
        let size_bytes = data.len();
        record.message_blobs.push(crate::audit::MessageBlobEntry {
            content_hash: meta.content_hash,
            blob_type: BlobType::ResponseBody,
            media_type: meta.media_type,
            data,
            size_bytes,
        });
    }

    // Gateway session id: hash the raw `X-Session-Id` into the same
    // `session_id_from_client` UUID form every other `gateway_audit.session_id`
    // producer (LLM, MCP, A2A) stores, so media rows correlate cross-protocol.
    record.session_id = attr
        .session_id
        .as_deref()
        .map(|sid| super::content::session_id_from_client(sid, ctx.user.tenant_id, ctx.user.user_id));

    // --- Session detection ---
    // Media requests have no message content, so pass empty hashes.
    // With a client X-Session-Id, detect() will link to an existing session.
    // Without one, detect() with empty hashes creates a new session.
    let key_id = ctx.user.key_id.unwrap_or(uuid::Uuid::nil());
    let empty_hashes: Vec<String> = Vec::new();
    let session_info = state.session_detector.detect(
        ctx.user.user_id,
        key_id,
        ctx.user.tenant_id,
        &empty_hashes,
        attr.session_id.as_deref(),
    );
    state.session_detector.record(
        ctx.user.user_id,
        key_id,
        request_id,
        &session_info,
        empty_hashes,
        attr.session_id.clone(),
    );
    record.conversation_session_id = Some(session_info.session_id);
    record.turn_number = Some(session_info.turn_number);
    record.parent_request_id = session_info.parent_request_id;
    record.is_baseline = Some(session_info.is_baseline);

    // --- Calculate media cost from resolved pricing ---
    if upstream_status.is_success() {
        let rates = &actual_target.pricing;
        let media_units = extract_billable_units(&result_bytes, &body_bytes, endpoint);
        let billing = rates.bill(
            &media_units,
            ctx.config.pricing.accounting_currency,
            &ctx.config.pricing.fx,
        );
        record.cost = billing.amount();
        record.cost_currency = billing.accounting;
        record.source_cost = billing.source.amount;
        record.source_currency = billing.source.currency;
        record.fx_rate = billing.fx_rate;
        record.billed_units = billing.accounted_lines();
        // Same rule as the chat path: the cost above is a floor of zero rather
        // than a measurement, and the budget accrual below is skipped. Badge it —
        // a media request billed at $0 is otherwise indistinguishable from a free
        // one, which is exactly the state this badge exists to prevent.
        //
        // Unlike the chat path, an empty measurement is badged too: a successful
        // media call did work the provider will invoice, so a response carrying
        // no meterable unit is a gap in what we can measure, not a free request.
        // Traffic the client funded on its own account is the one exception —
        // there the zero is the whole point.
        if !billing.is_known() || (media_units.is_empty() && !rates.zero_rated) {
            record.badges.push(crate::audit::AuditBadge::Unpriced);
        }
    }

    let media_cost = record.cost;
    // /metrics outcome: media requests carry the upstream's actual status
    // (record.status_code is only set on failure).
    state.proxy_stats.record_request_outcome(upstream_status.as_u16(), Some(latency_total_ms));
    send_audit(&state.audit_tx, record, &request_id.to_string()).await;

    // --- Budget accrual (post-response) ---
    if media_cost > 0.0 {
        crate::middleware::rate_limit::update_budget_usage(
            ctx.user.tenant_id,
            ctx.user.tenant_budget.is_some(),
            ctx.user.workspace_id,
            ctx.user.user_id,
            ctx.user.user_rate_override.is_some(),
            ctx.user.key_budget.as_ref().and(ctx.user.key_id),
            media_cost,
            &state.usage,
        );
    }

    // --- Validate response Content-Type for binary endpoints (audio/speech) ---
    let sanitized_resp_content_type = if endpoint == MediaEndpoint::AudioSpeech
        && upstream_status.is_success()
    {
        // Speech responses are audio/* or application/octet-stream, or
        // Mistral's JSON / SSE carrying base64 `audio_data`. Anything else
        // (e.g. text/html) is logged.
        if !resp_content_type.starts_with("audio/")
            && !resp_content_type.starts_with("application/octet-stream")
            && !resp_content_type.starts_with("application/json")
            && !resp_content_type.starts_with("text/event-stream")
        {
            tracing::warn!(
                request_id = %request_id,
                resp_content_type = %resp_content_type,
                "unexpected content-type on audio/speech response"
            );
        }
        resp_content_type.clone()
    } else {
        resp_content_type.clone()
    };

    // --- Build client response ---
    let mut response = Response::builder().status(upstream_status);

    // Forward content-type from upstream (sanitized).
    response = response.header("content-type", &sanitized_resp_content_type);

    // Forward select response headers — strip unexpected headers from binary responses.
    let allowed_response_headers: &[&str] = &[
        "x-request-id",
        "openai-organization",
        "openai-processing-ms",
        "x-ratelimit-limit-requests",
        "x-ratelimit-remaining-requests",
    ];
    for key in allowed_response_headers {
        if let Some(value) = resp_headers.get(*key) {
            response = response.header(*key, value);
        }
    }

    response
        .body(Body::from(resp_bytes))
        .map_err(|e| AppError::Internal(format!("failed to build media response: {e}")))
}

// ---------------------------------------------------------------------------
// Catch-all proxy handlers
// ---------------------------------------------------------------------------

use crate::settings::core_settings;

/// Extract the canonical `/v1/...` path from a request path.
///
/// Handles both direct paths (`/v1/batches/123`) and BYOK paths
/// (`/fwd/{key}/v1/batches/123`).
fn extract_catchall_path(path: &str) -> Option<String> {
    if path.starts_with("/fwd/") {
        // /fwd/{key}/v1/... -> /v1/...
        path.find("/v1/").map(|idx| path[idx..].to_string())
    } else if path.starts_with("/v1/") {
        Some(path.to_string())
    } else {
        None
    }
}

/// Error audit context for catch-all requests.
struct CatchallErrorAuditCtx {
    request_id: uuid::Uuid,
    user_id: uuid::Uuid,
    tenant_id: uuid::Uuid,
    /// The key's workspace once authenticated; nil before.
    workspace_id: uuid::Uuid,
    key_id: Option<uuid::Uuid>,
    path: String,
    method: String,
    /// The upstream the request was sent to, once it was.
    attempted: super::AttemptedUpstream,
}

/// Send an error audit record for a catch-all request.
async fn send_catchall_error_audit(state: &AppState, ctx: &CatchallErrorAuditCtx, error: &AppError) {
    let mut record = AuditRecord::error_record(
        ctx.request_id,
        ctx.user_id,
        ctx.tenant_id,
        ctx.workspace_id,
        ctx.key_id,
        error,
    );
    ctx.attempted.stamp(&mut record);
    record.badges = vec![crate::audit::AuditBadge::Catchall];
    record.catchall_path = Some(ctx.path.clone());
    record.catchall_method = Some(ctx.method.clone());
    send_audit(&state.audit_tx, record, &ctx.request_id.to_string()).await;
}

/// Catch-all proxy handler — forwards unmatched `/v1/{*path}` requests as-is.
///
/// Auth via `Authorization: Bearer` or `x-api-key`. Route must be enabled by a
/// matching [`RoutePolicy`] for the key's downstream provider.
pub async fn catchall_handler(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> Result<Response, AppError> {
    let method = req.method().clone();
    let (parts, body) = req.into_parts();
    catchall_handler_inner(state, parts.headers, parts.uri.path().to_string(), method, body, None, None).await
}

/// BYOK catch-all proxy handler — forwards unmatched `/fwd/{key}/v1/{*path}` requests.
pub async fn fwd_catchall_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path((key, _path)): axum::extract::Path<(String, String)>,
    req: Request<Body>,
) -> Result<Response, AppError> {
    let method = req.method().clone();
    let (parts, body) = req.into_parts();
    let headers = parts.headers;
    let path = parts.uri.path().to_string();

    // Extract the client's credential (header, or Gemini's `?key=` query param).
    let fwd_auth = super::extract_forward_auth_context(&headers, parts.uri.query())?;

    // Authenticate using the path key.
    // The registry guard is released here, never held across an error audit.
    let authenticated = auth::authenticate_forward(&key, &state.tenant_registry.load());
    let ctx = match authenticated {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(key_prefix = %crate::auth::credential_prefix(&key, 6), "fwd catchall auth failed");
            return Err(e);
        }
    };

    catchall_handler_inner(state, headers, path, method, body, Some(fwd_auth), Some(ctx)).await
}

/// Shared catch-all handler: auth -> policy check -> rate limit -> forward -> audit.
#[allow(clippy::too_many_arguments)]
async fn catchall_handler_inner(
    state: Arc<AppState>,
    headers: axum::http::HeaderMap,
    path: String,
    method: axum::http::Method,
    body: Body,
    fwd_auth: Option<super::ForwardAuthContext>,
    pre_authenticated: Option<TenantRequestCtx>,
) -> Result<Response, AppError> {
    let request_id = crate::ids::mint_request_id();
    let request_started_at = std::time::Instant::now();

    // Track request stats.
    state.proxy_stats.inc_requests();

    // Extract canonical path (strip /fwd/{key} prefix if present).
    let canonical_path = match extract_catchall_path(&path) {
        Some(p) => p,
        None => {
            return Err(AppError::BadRequest(format!("invalid catch-all path: {path}")));
        }
    };

    // Log path with key redacted for /fwd/ routes.
    let log_path = if path.starts_with("/fwd/") {
        if let Some(rest) = path.splitn(4, '/').nth(3) {
            format!("/fwd/[redacted]/{rest}")
        } else {
            "/fwd/[redacted]".to_string()
        }
    } else {
        path.clone()
    };
    tracing::info!(
        request_id = %request_id,
        path = %log_path,
        method = %method,
        "catchall_handler invoked"
    );

    // Error audit context — enriched incrementally.
    let mut err_ctx = CatchallErrorAuditCtx {
        request_id,
        user_id: uuid::Uuid::nil(),
        tenant_id: uuid::Uuid::from_u128(1), // SYSTEM default for pre-auth errors
        workspace_id: uuid::Uuid::nil(),
        key_id: None,
        path: canonical_path.clone(),
        method: method.to_string(),
        attempted: super::AttemptedUpstream::default(),
    };

    // --- Auth --- the key and its tenant's configuration, from one registry load.
    let ctx = if let Some(ctx) = pre_authenticated {
        ctx
    } else {
        let bearer = match auth::extract_api_token(&headers) {
            Ok(b) => b,
            Err(e) => {
                send_catchall_error_audit(&state, &err_ctx, &e).await;
                state.proxy_stats.inc_errors();
                return Err(e);
            }
        };
        let authenticated = auth::authenticate_proxy(&bearer, &state.tenant_registry.load());
        match authenticated {
            Ok(c) => c,
            Err(e) => {
                send_catchall_error_audit(&state, &err_ctx, &e).await;
                state.proxy_stats.inc_errors();
                return Err(e);
            }
        }
    };

    // Enrich error context with user info.
    err_ctx.user_id = ctx.user.user_id;
    err_ctx.tenant_id = ctx.user.tenant_id;
    err_ctx.workspace_id = ctx.user.workspace_id;
    err_ctx.key_id = ctx.user.key_id;

    // --- Route policy check ---
    // A workspace key may reach several providers; pick the allowed provider
    // whose enabled route policy matches this path. Every key (the agent
    // included) is bounded by its workspace's explicit provider grants. A path
    // carrying an origin host is served by the provider that host names or by
    // none: the client addressed that provider, and its data must not reach
    // another. Without one, the first matching provider in grant order serves,
    // unless its target would hand the client's credential to a different
    // pass-through provider (`routing::CredentialScope`).
    let origin_host = match super::routing::origin_host(&headers, &ctx.user) {
        Ok(h) => h,
        Err(e) => {
            send_catchall_error_audit(&state, &err_ctx, &e).await;
            state.proxy_stats.inc_errors();
            return Err(e);
        }
    };
    let path_matches: Vec<(uuid::Uuid, &crate::config::RoutePolicy)> = ctx
        .user
        .allowed_provider_ids
        .iter()
        .filter_map(|pid| {
            let policies = ctx.config.route_policies.get(pid)?;
            crate::config::find_matching_policy(policies, &canonical_path).map(|p| (*pid, p))
        })
        .collect();
    let (downstream_id, policy) = match super::routing::forwarded_path_provider(&ctx.user, origin_host, &path_matches) {
        Ok((pid, policy)) => (*pid, (*policy).clone()),
        Err(refusal) => {
            use super::routing::ForwardedPathRefusal as R;
            let reason = match refusal {
                R::NoPolicy => "route not enabled for this provider",
                R::NotTheAddressedProvider => "the provider this request addresses does not forward this path",
                R::CredentialUnattributed => {
                    "this key holds several pass-through providers and the request names none of them \
                     (no origin host), so the path cannot be forwarded with its credential"
                }
            };
            tracing::debug!(
                request_id = %request_id,
                path = %canonical_path,
                origin_host = origin_host.unwrap_or("-"),
                ?refusal,
                "forwarded path refused"
            );
            let e = AppError::ModelNotFound(format!("{reason}: {canonical_path}"));
            send_catchall_error_audit(&state, &err_ctx, &e).await;
            state.proxy_stats.inc_errors();
            return Err(e);
        }
    };

    // --- Rate limit (RPM from policy or key default) — no-op unless capped ---
    if let Err(e) = crate::middleware::rate_limit::check_rate_limit(&ctx.user, &state.usage) {
        send_catchall_error_audit(&state, &err_ctx, &e).await;
        state.proxy_stats.inc_errors();
        return Err(e);
    }

    // --- Budget check (daily + monthly) ---
    if let Err(e) = crate::middleware::rate_limit::check_budget(
        &ctx.user,
        &state.usage,
        ctx.config.pricing.accounting_currency,
    ) {
        send_catchall_error_audit(&state, &err_ctx, &e).await;
        state.proxy_stats.inc_errors();
        return Err(e);
    }

    // --- Buffer request body (respecting policy max_body_bytes) ---
    let max_body = if policy.max_body_bytes > 0 {
        policy.max_body_bytes as usize
    } else {
        core_settings().max_body_size
    };

    let body_bytes = match axum::body::to_bytes(body, max_body).await {
        Ok(b) => b,
        Err(e) => {
            // Over the size cap, or not received within the body deadline:
            // the error names which.
            let err = AppError::BadRequest(format!(
                "could not read the request body (at most {max_body} bytes): {e}"
            ));
            send_catchall_error_audit(&state, &err_ctx, &err).await;
            state.proxy_stats.inc_errors();
            return Err(err);
        }
    };

    // --- Extract content type ---
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();

    // --- Resolve upstream target ---
    // Pick the upstream that backs the route-policy-matched provider
    // (`downstream_id`), not an arbitrary `model_map` entry — a wildcard
    // (default) workspace key spans several providers, so HashMap iteration
    // order would otherwise route to the wrong upstream. Among the matched
    // provider's targets we take the highest `priority` (deterministic in the
    // provider; equal-priority targets on the provider's servers are
    // interchangeable load-balancing peers). A pass-through of this key is
    // forwarded to its bound endpoint, override routes or not
    // (`routing::forwarded_path_target`); any other provider with no target has
    // nowhere to go and is refused — there is no fallback host.
    let downstream_id_str = downstream_id.to_string();
    let resolved = {
        match super::routing::forwarded_path_target(&ctx.user, &downstream_id_str) {
            // A catch-all path names no model, so it has no replica set to
            // spread over: it goes to the server's primary endpoint.
            Some(target) => match target
                .upstream_server_id
                .as_deref()
                .and_then(|s| uuid::Uuid::parse_str(s).ok())
                .and_then(|server| ctx.config.endpoints.members(server, None))
                .and_then(|eps| eps.first().map(|e| (e.id, e.url.clone())))
            {
                Some((endpoint_id, url)) => {
                    let api_key = super::routing::route_credential(target, &ctx.user, &ctx.config.credentials);
                    let server_id = target.upstream_server_id.clone();
                    Ok((url, api_key, server_id, target.has_credential, target.transport, Some(endpoint_id)))
                }
                None => Err(super::routing::no_serving_endpoint(target.upstream_model_id.as_deref())),
            },
            None => match ctx.user.byok_passthrough.iter()
                .find(|pt| pt.downstream_provider_id == downstream_id_str)
            {
                // Keyless pass-through: the client's own credential rides
                // `fwd_auth` below, never a stored one.
                Some(pt) => Ok((
                    pt.upstream_url.clone(),
                    ctx.user.real_api_key.clone(),
                    None,
                    false,
                    pt.transport,
                    None,
                )),
                None => Err(super::routing::no_route_target(&downstream_id_str)),
            },
        }
    };
    let (upstream_url, upstream_api_key, upstream_server_id, target_has_stored_cred, transport, endpoint_id) =
        match resolved {
            Ok(r) => r,
            Err(e) => {
                send_catchall_error_audit(&state, &err_ctx, &e).await;
                state.proxy_stats.inc_errors();
                return Err(e);
            }
        };

    // --- Forward to upstream ---
    let reqwest_method = match method.as_str() {
        "GET" => reqwest::Method::GET,
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "DELETE" => reqwest::Method::DELETE,
        "PATCH" => reqwest::Method::PATCH,
        "HEAD" => reqwest::Method::HEAD,
        "OPTIONS" => reqwest::Method::OPTIONS,
        _ => reqwest::Method::POST,
    };

    // BYOK credential rule: forward the client's credential only when the
    // resolved target has no stored credential (pure pass-through); an override
    // route with a stored key uses ITS key — the client's never leaks to it.
    let auth_override = if target_has_stored_cred { None } else { fwd_auth.as_ref() };
    // The catch-all has no model routing, so only the gateway-owned fields
    // are removed; the path decides everything else.
    let prepared = match super::forward_body::prepare(&body_bytes, &content_type, None) {
        Ok(p) => p,
        Err(e) => {
            send_catchall_error_audit(&state, &err_ctx, &e).await;
            state.proxy_stats.inc_errors();
            return Err(e);
        }
    };
    let forward_diff = prepared.audit_diff();
    let upstream_resp = state.http_client.forward_catchall_with_retry(
        crate::proxy::client::UpstreamEndpoint { url: &upstream_url, api_key: &upstream_api_key, transport },
        reqwest_method,
        prepared.bytes,
        &headers,
        &canonical_path,
        &content_type,
        1, // max_retries
        auth_override,
    ).await;
    // Answered, so this gateway routes there and is served: it has its say in
    // whether the server is down. Only an ANSWER counts here — this path feeds
    // no breaker, so a transport failure would state the endpoint in rotation
    // with nothing ever to take it out.
    if let Some(endpoint_id) = endpoint_id
        && super::ReplicaSignal::of(upstream_resp.as_ref().map(|_| ())) == super::ReplicaSignal::Answered
    {
        state.circuit_breaker.note_reached(&endpoint_id.to_string(), ctx.user.tenant_id, endpoint_id, &upstream_url);
    }
    let upstream_resp = match upstream_resp {
        Ok(resp) => resp,
        Err(e) => {
            // A request that never left names no replica.
            let reached = super::ReplicaSignal::of(Err(&e)) != super::ReplicaSignal::NotReached;
            err_ctx.attempted = super::AttemptedUpstream::new(
                upstream_server_id.as_deref(),
                endpoint_id.filter(|_| reached),
                &upstream_url,
            );
            send_catchall_error_audit(&state, &err_ctx, &e).await;
            state.proxy_stats.inc_errors();
            return Err(e);
        }
    };

    let latency_total_ms = request_started_at.elapsed().as_millis() as u64;
    let upstream_status = upstream_resp.status();

    tracing::info!(
        request_id = %request_id,
        path = %canonical_path,
        method = %method,
        status = upstream_status.as_u16(),
        latency_ms = latency_total_ms,
        "catchall request completed"
    );

    // --- Read upstream response ---
    let resp_content_type = upstream_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let resp_headers = upstream_resp.headers().clone();
    let resp_bytes = crate::http_body::read_body_capped(upstream_resp, MAX_MEDIA_RESPONSE_SIZE as u64)
        .await
        .map_err(|e| AppError::Internal(format!("failed to read upstream catchall response: {e}")))?;

    // --- Build audit record (minimal — path, status, latency, body size) ---
    // Forwarded end-client identity is honored only from an inline key (the
    // /fwd BYOK path), never a normal key.
    let attr = attribution::extract_attribution(&headers, ctx.user.user_id, &ctx.config.app_patterns, ctx.user.inline_ai);
    let mut record = AuditRecord {
        request_id,
        timestamp: chrono::Utc::now(),
        user_id: ctx.user.user_id,
        tenant_id: ctx.user.tenant_id,
        workspace_id: ctx.user.workspace_id,
        key_id: ctx.user.key_id,
        app_id: attr.app_id,
        // How the app was named and the evidence it was named from.
        detection_method: attr.detection_method,
        user_agent: attr.user_agent,
        client_ip: attr.client_ip,
        end_user: attr.end_user,
        end_user_groups: attr.end_user_groups,
        latency_total_ms,
        latency_ttft_ms: latency_total_ms,
        badges: vec![crate::audit::AuditBadge::Catchall],
        catchall_path: Some(canonical_path.clone()),
        catchall_method: Some(method.to_string()),
        upstream_server_id: upstream_server_id
            .as_deref()
            .and_then(|s| uuid::Uuid::parse_str(s).ok()),
        endpoint_id,
        endpoint_url: endpoint_id.map(|_| upstream_url.clone()),
        // Error fields (if upstream returned non-2xx)
        status_code: if !upstream_status.is_success() {
            Some(upstream_status.as_u16())
        } else {
            None
        },
        error_category: if !upstream_status.is_success() {
            Some("upstream".to_string())
        } else {
            None
        },
        error_detail: if !upstream_status.is_success() {
            Some(format!("upstream returned {}", upstream_status.as_u16()))
        } else {
            None
        },
        finish_reason: if upstream_status.is_success() {
            "stop".to_string()
        } else {
            "error".to_string()
        },
        ..Default::default()
    };
    if let Some(diff) = forward_diff {
        record.transform_diff = Some(diff);
        record.badges.push(crate::audit::AuditBadge::Modified);
    }

    // Optionally capture body in audit if policy says so.
    if policy.audit_body && !body_bytes.is_empty()
        && let Ok(body_json) = serde_json::from_slice::<serde_json::Value>(&body_bytes)
    {
        record.request_messages = Some(body_json);
    }
    if policy.audit_body && !resp_bytes.is_empty()
        && let Ok(resp_json) = serde_json::from_slice::<serde_json::Value>(&resp_bytes)
    {
        record.response_content = Some(
            serde_json::to_string(&resp_json)
                .unwrap_or_default()
                .chars()
                .take(2000)
                .collect()
        );
    }

    // /metrics outcome: same single-completion-point rule as the JSON media path.
    state.proxy_stats.record_request_outcome(upstream_status.as_u16(), Some(latency_total_ms));
    super::send_audit(&state.audit_tx, record, &request_id.to_string()).await;

    // --- Build client response ---
    let mut response = Response::builder().status(upstream_status);

    // Forward content-type from upstream.
    response = response.header("content-type", &resp_content_type);

    // Forward select response headers.
    for key in &[
        "x-request-id",
        "openai-organization",
        "openai-processing-ms",
        "x-ratelimit-limit-requests",
        "x-ratelimit-remaining-requests",
    ] {
        if let Some(value) = resp_headers.get(*key) {
            response = response.header(*key, value);
        }
    }

    response
        .body(Body::from(resp_bytes))
        .map_err(|e| AppError::Internal(format!("failed to build catchall response: {e}")))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_from_path_standard() {
        assert_eq!(
            MediaEndpoint::from_path("/v1/embeddings"),
            Some(MediaEndpoint::Embeddings)
        );
        assert_eq!(
            MediaEndpoint::from_path("/v1/audio/speech"),
            Some(MediaEndpoint::AudioSpeech)
        );
        assert_eq!(
            MediaEndpoint::from_path("/v1/audio/transcriptions"),
            Some(MediaEndpoint::AudioTranscriptions)
        );
        assert_eq!(
            MediaEndpoint::from_path("/v1/images/generations"),
            Some(MediaEndpoint::ImagesGenerations)
        );
        assert_eq!(
            MediaEndpoint::from_path("/v1/videos/generations"),
            Some(MediaEndpoint::VideosGenerations)
        );
    }

    #[test]
    fn endpoint_from_path_fwd() {
        assert_eq!(
            MediaEndpoint::from_path("/fwd/vk-abc123/v1/embeddings"),
            Some(MediaEndpoint::Embeddings)
        );
        assert_eq!(
            MediaEndpoint::from_path("/fwd/vk-abc123/v1/audio/transcriptions"),
            Some(MediaEndpoint::AudioTranscriptions)
        );
    }

    #[test]
    fn endpoint_from_path_unknown() {
        assert_eq!(MediaEndpoint::from_path("/v1/chat/completions"), None);
        assert_eq!(MediaEndpoint::from_path("/v1/unknown"), None);
    }

    #[test]
    fn endpoint_media_type() {
        assert_eq!(MediaEndpoint::Embeddings.media_type(), MediaType::Embedding);
        assert_eq!(MediaEndpoint::AudioSpeech.media_type(), MediaType::Audio);
        assert_eq!(
            MediaEndpoint::ImagesGenerations.media_type(),
            MediaType::Image
        );
        assert_eq!(
            MediaEndpoint::VideosGenerations.media_type(),
            MediaType::Video
        );
    }

    #[test]
    fn endpoint_is_multipart() {
        assert!(!MediaEndpoint::Embeddings.is_multipart());
        assert!(!MediaEndpoint::AudioSpeech.is_multipart());
        assert!(MediaEndpoint::AudioTranscriptions.is_multipart());
        assert!(MediaEndpoint::AudioTranslations.is_multipart());
        assert!(MediaEndpoint::ImagesEdits.is_multipart());
        assert!(MediaEndpoint::ImagesVariations.is_multipart());
        assert!(!MediaEndpoint::ImagesGenerations.is_multipart());
        assert!(!MediaEndpoint::VideosGenerations.is_multipart());
    }

    #[test]
    fn extract_model_from_json_body() {
        let body = br#"{"model":"text-embedding-3-small","input":"hello"}"#;
        assert_eq!(
            extract_model_from_json(body),
            Some("text-embedding-3-small".to_string())
        );
    }

    #[test]
    fn extract_model_from_json_missing() {
        let body = br#"{"input":"hello"}"#;
        assert_eq!(extract_model_from_json(body), None);
    }

    #[test]
    fn extract_model_multipart() {
        let ct = "multipart/form-data; boundary=----WebKitFormBoundary";
        let body = "------WebKitFormBoundary\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nwhisper-1\r\n------WebKitFormBoundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"audio.mp3\"\r\nContent-Type: audio/mpeg\r\n\r\n<binary>\r\n------WebKitFormBoundary--\r\n";
        assert_eq!(extract_model(body.as_bytes(), ct), Some("whisper-1".to_string()));
        // A file whose NAME is not `model` is never read as the model, however
        // its filename or content reads.
        let decoy = "------WebKitFormBoundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"model\"\r\n\r\nname=\"model\"\r\n------WebKitFormBoundary--\r\n";
        assert_eq!(extract_model(decoy.as_bytes(), ct), None);
    }

    #[test]
    fn extract_model_dispatch() {
        let body = br#"{"model":"dall-e-3","prompt":"A cat"}"#;
        assert_eq!(
            extract_model(body, "application/json"),
            Some("dall-e-3".to_string())
        );
    }

    #[test]
    fn truncate_text_short() {
        assert_eq!(truncate_text("hello", 10), "hello");
    }

    #[test]
    fn truncate_text_long() {
        let long = "a".repeat(600);
        let result = truncate_text(&long, 500);
        assert!(result.ends_with('…'));
        // 500 ASCII 'a' bytes + 3 UTF-8 bytes for '…' = 503 bytes.
        assert!(result.len() <= 503);
    }

    #[test]
    fn extract_input_text_embeddings() {
        let body = br#"{"model":"emb","input":"hello world"}"#;
        assert_eq!(
            extract_input_text(body, MediaEndpoint::Embeddings, "application/json"),
            Some("hello world".to_string())
        );
    }

    #[test]
    fn extract_input_text_image_gen() {
        let body = br#"{"model":"dall-e-3","prompt":"A sunset"}"#;
        assert_eq!(
            extract_input_text(body, MediaEndpoint::ImagesGenerations, "application/json"),
            Some("A sunset".to_string())
        );
    }

    #[test]
    fn extract_domain_params_image_gen() {
        let body = br#"{"model":"dall-e-3","prompt":"cat","n":2,"size":"1024x1024","quality":"hd"}"#;
        let p = extract_domain_params(MediaEndpoint::ImagesGenerations, body, "application/json");
        assert_eq!(p.n, Some(2));
        assert_eq!(p.size.as_deref(), Some("1024x1024"));
        assert_eq!(p.extra.get("quality"), Some(&serde_json::json!("hd")));
        // `prompt` is an input block, not a param.
        assert!(!p.extra.contains_key("prompt"));
    }

    #[test]
    fn extract_domain_params_multipart_transcription() {
        let boundary = "----abc";
        let body = format!(
            "--{b}\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nwhisper-1\r\n--{b}\r\nContent-Disposition: form-data; name=\"language\"\r\n\r\nfr\r\n--{b}\r\nContent-Disposition: form-data; name=\"temperature\"\r\n\r\n0.3\r\n--{b}--\r\n",
            b = boundary
        );
        let ct = format!("multipart/form-data; boundary={boundary}");
        let p = extract_domain_params(MediaEndpoint::AudioTranscriptions, body.as_bytes(), &ct);
        assert_eq!(p.language.as_deref(), Some("fr"));
        assert_eq!(p.temperature, Some(0.3));
    }

    #[test]
    fn build_media_call_embeddings_roundtrip() {
        let body = br#"{"model":"text-embedding-3-small","input":"hello world"}"#;
        let resp = br#"{"data":[{"embedding":[0.1,0.2]},{"embedding":[0.3,0.4]}]}"#;
        let call = build_media_call(MediaCaptureCtx {
            endpoint: MediaEndpoint::Embeddings,
            model: "text-embedding-3-small",
            request_bytes: body,
            request_content_type: "application/json",
            response_bytes: resp,
            upstream_success: true,
            request_blob: None,
            response_blobs: Vec::new(),
            max_artifact_bytes: 10 * 1024 * 1024,
        });
        let json = serde_json::to_value(&call).unwrap();
        assert_eq!(json["endpoint"], "embeddings");
        assert_eq!(json["input"][0]["type"], "text");
        // Embeddings have no renderable output blocks — the vector count is
        // carried on `output_units` and rendered by the UI as a derived label.
        assert_eq!(json["output_units"], 2);
        assert!(call.output.is_empty(), "embeddings output should be empty, got: {:?}", call.output);
        // Round-trip through serde preserves shape.
        let back: DomainMediaCall = serde_json::from_value(json).unwrap();
        assert_eq!(back.endpoint, DomainMediaEndpoint::Embeddings);
        assert_eq!(back.input.len(), 1);
        assert_eq!(back.output.len(), 0);
        assert_eq!(back.output_units, Some(2));
    }

    /// Embeddings are priced per TOKEN but return one vector per input, so the
    /// count the audit row renders and the count the bill is computed from are
    /// different numbers. Charging the vector count prices a long document at a
    /// few tokens — a silent 1000× under-bill that looks like an ordinary cheap
    /// request.
    #[test]
    fn embeddings_bill_on_tokens_not_vector_count() {
        use crate::pricing::{Currency, FxTable, Rate, Rates, Unit};
        let resp = br#"{"data":[{"embedding":[0.1]},{"embedding":[0.2]},{"embedding":[0.3]}],
                        "usage":{"prompt_tokens":10000,"total_tokens":10000}}"#;
        // Three vectors produced, ten thousand tokens consumed.
        assert_eq!(extract_media_output_units(resp, MediaEndpoint::Embeddings), 3);
        let units = extract_billable_units(resp, b"{}", MediaEndpoint::Embeddings);
        assert_eq!(units.get(Unit::InputToken), 10_000);

        let rates = Rates::from_units(
            std::collections::BTreeMap::from([(Unit::InputToken, Rate::Flat(2.0))]),
            Currency::USD,
        );
        let cost = rates.bill(&units, Currency::USD, &FxTable::default()).amount();
        assert!((cost - 0.02).abs() < 1e-9, "expected $0.02, got {cost}");
    }

    /// A provider that reports no usage leaves nothing to charge against. Record
    /// nothing rather than inventing a unit count from the response shape.
    #[test]
    fn embeddings_without_usage_bill_nothing() {
        let resp = br#"{"data":[{"embedding":[0.1]},{"embedding":[0.2]}]}"#;
        assert!(extract_billable_units(resp, b"{}", MediaEndpoint::Embeddings).is_empty());
    }

    /// Images are charged per image produced, so the displayed count and the
    /// billed count agree — and because the unit is named rather than inferred
    /// from the endpoint, they cannot drift into meaning different things.
    #[test]
    fn images_bill_the_images_they_produced() {
        use crate::pricing::Unit;
        let images = br#"{"data":[{"url":"a"},{"url":"b"}]}"#;
        for ep in [
            MediaEndpoint::ImagesGenerations,
            MediaEndpoint::ImagesEdits,
            MediaEndpoint::ImagesVariations,
        ] {
            let units = extract_billable_units(images, b"{}", ep);
            assert_eq!(units.get(Unit::ImageOutput), 2, "{ep:?}");
            assert_eq!(
                units.get(Unit::ImageOutput) as i32,
                extract_media_output_units(images, ep),
                "{ep:?} bills a different count than it produced"
            );
        }
    }

    /// Transcription is priced per second of source audio, which only the
    /// verbose response format carries. Charging one second per request would
    /// bill an hour-long recording as a one-second one, so an absent duration
    /// measures nothing and the caller badges the row instead.
    #[test]
    fn transcription_bills_reported_seconds_and_never_invents_them() {
        use crate::pricing::Unit;
        for ep in [
            MediaEndpoint::AudioTranscriptions,
            MediaEndpoint::AudioTranslations,
        ] {
            let verbose = br#"{"text":"hello","duration":93.4}"#;
            // Rounded up: a provider billing whole seconds never bills fewer.
            assert_eq!(
                extract_billable_units(verbose, b"{}", ep).get(Unit::AudioSecond),
                94,
                "{ep:?}"
            );
            let plain = br#"{"text":"hello"}"#;
            assert!(
                extract_billable_units(plain, b"{}", ep).is_empty(),
                "{ep:?} invented a duration the response never reported"
            );
            let nonsense = br#"{"text":"hello","duration":-5.0}"#;
            assert!(extract_billable_units(nonsense, b"{}", ep).is_empty(), "{ep:?}");
        }
    }

    /// A transcription response that names its own billing basis is believed
    /// over the shape we would otherwise infer. The token variant reports an
    /// `input_tokens` INCLUSIVE of the audio tokens inside it, which is exactly
    /// the partition the fold carves — so both go in as reported.
    #[test]
    fn transcription_reads_the_usage_block_the_provider_sent() {
        use crate::pricing::Unit;
        for ep in [
            MediaEndpoint::AudioTranscriptions,
            MediaEndpoint::AudioTranslations,
        ] {
            let by_duration = br#"{"text":"hi","usage":{"type":"duration","seconds":9.2}}"#;
            let units = extract_billable_units(by_duration, b"{}", ep);
            assert_eq!(units.get(Unit::AudioSecond), 10, "{ep:?}");
            assert_eq!(units.get(Unit::InputToken), 0, "{ep:?}");

            let by_tokens = br#"{"text":"hi","usage":{"type":"tokens","input_tokens":14,
                                  "input_token_details":{"text_tokens":0,"audio_tokens":14},
                                  "output_tokens":45,"total_tokens":59}}"#;
            let units = extract_billable_units(by_tokens, b"{}", ep);
            assert_eq!(units.get(Unit::InputToken), 14, "{ep:?}");
            assert_eq!(units.get(Unit::AudioInputToken), 14, "{ep:?}");
            assert_eq!(units.get(Unit::OutputToken), 45, "{ep:?}");
            assert_eq!(units.get(Unit::AudioSecond), 0, "{ep:?} billed seconds it was not sent");

            // A usage block naming a basis it then fails to fill measures
            // nothing, rather than falling back to a duration that is about a
            // different basis entirely.
            let empty_usage = br#"{"text":"hi","duration":93.4,"usage":{"type":"duration"}}"#;
            assert!(
                extract_billable_units(empty_usage, b"{}", ep).is_empty(),
                "{ep:?}"
            );
        }
    }

    /// A `usage` this build cannot interpret must fall through to the verbose
    /// `duration`, never suppress it.
    ///
    /// The shapes below all fail to parse as a `TranscriptionUsage`, and typing
    /// the field as one directly would have failed the WHOLE response parse and
    /// discarded the `duration` sitting next to it — billing nothing for a
    /// response that plainly says how long the audio was. The chat-shaped block
    /// is the live case: several OpenAI-compatible transcription upstreams
    /// attach one, and it carries no `type` at all.
    #[test]
    fn a_usage_block_this_build_cannot_read_does_not_suppress_the_duration() {
        use crate::pricing::Unit;
        for ep in [
            MediaEndpoint::AudioTranscriptions,
            MediaEndpoint::AudioTranslations,
        ] {
            for body in [
                // No `type` key at all.
                &br#"{"text":"hi","duration":93.4,"usage":{"prompt_tokens":9,"total_tokens":9}}"#[..],
                // A `type` published after this build.
                &br#"{"text":"hi","duration":93.4,"usage":{"type":"characters","count":40}}"#[..],
                // Not an object.
                &br#"{"text":"hi","duration":93.4,"usage":7}"#[..],
            ] {
                assert_eq!(
                    extract_billable_units(body, b"{}", ep).get(Unit::AudioSecond),
                    94,
                    "{ep:?} discarded the duration beside an unreadable usage block: {}",
                    String::from_utf8_lossy(body)
                );
            }
        }
    }

    /// Mistral's transcription answers with a chat-shaped `usage` (no `type`)
    /// whose `prompt_audio_seconds` is the basis it bills (per audio minute);
    /// its token counts are not. Live shape, 2026-10-05.
    #[test]
    fn mistral_transcription_bills_its_reported_audio_seconds() {
        use crate::pricing::Unit;
        let body = br#"{"model":"voxtral-mini-latest","text":"","language":null,"segments":[],
            "usage":{"prompt_audio_seconds":3,"prompt_tokens":3,"total_tokens":379,"completion_tokens":1,
            "prompt_tokens_details":{"cached_tokens":0,"audio_tokens":375}}}"#;
        let units = extract_billable_units(body, b"{}", MediaEndpoint::AudioTranscriptions);
        assert_eq!(units.get(Unit::AudioSecond), 3);
        assert_eq!(units.get(Unit::InputToken), 0);
        assert_eq!(units.get(Unit::AudioInputToken), 0);
        // A fraction is billed as the whole second.
        let fraction = br#"{"text":"","usage":{"prompt_audio_seconds":3.4,"prompt_tokens":3}}"#;
        assert_eq!(extract_billable_units(fraction, b"{}", MediaEndpoint::AudioTranscriptions).get(Unit::AudioSecond), 4);
        // A top-level `duration` the seconds outrank: the provider's own basis.
        let both = br#"{"text":"","duration":9.0,"usage":{"prompt_audio_seconds":3}}"#;
        assert_eq!(extract_billable_units(both, b"{}", MediaEndpoint::AudioTranscriptions).get(Unit::AudioSecond), 3);
    }

    /// `stream: true` answers SSE; the final event states the result and its
    /// usage, so that event is what is billed and audited — on OpenAI's stream
    /// and Mistral's alike; a JSON answer is its own result.
    #[test]
    fn a_streamed_transcription_is_billed_and_audited_from_its_final_event() {
        use crate::pricing::Unit;
        let mistral = bytes::Bytes::from_static(
            b"event: transcription.text.delta\ndata: {\"type\":\"transcription.text.delta\",\"text\":\"Hel\"}\n\n\
event: transcription.done\ndata: {\"model\":\"voxtral-mini-latest\",\"text\":\"Hello\",\"usage\":{\"prompt_audio_seconds\":3,\"prompt_tokens\":3},\"type\":\"transcription.done\"}\n\n",
        );
        let result = media_result(MediaEndpoint::AudioTranscriptions, &mistral);
        assert_eq!(extract_billable_units(&result, b"{}", MediaEndpoint::AudioTranscriptions).get(Unit::AudioSecond), 3);
        assert_eq!(extract_transcription_text(&result).as_deref(), Some("Hello"));

        let openai = bytes::Bytes::from_static(
            b"data: {\"type\":\"transcript.text.delta\",\"delta\":\"Hi\"}\n\n\
data: {\"type\":\"transcript.text.done\",\"text\":\"Hi there\",\"usage\":{\"type\":\"tokens\",\"input_tokens\":14,\"input_token_details\":{\"audio_tokens\":14},\"output_tokens\":4}}\n\n",
        );
        let result = media_result(MediaEndpoint::AudioTranslations, &openai);
        let units = extract_billable_units(&result, b"{}", MediaEndpoint::AudioTranslations);
        assert_eq!((units.get(Unit::InputToken), units.get(Unit::OutputToken)), (14, 4));
        assert_eq!(extract_transcription_text(&result).as_deref(), Some("Hi there"));

        // A JSON answer is its own result; other endpoints are untouched.
        let json = bytes::Bytes::from_static(br#"{"text":"x","duration":2.0}"#);
        assert_eq!(media_result(MediaEndpoint::AudioTranscriptions, &json), json);
        assert_eq!(media_result(MediaEndpoint::AudioSpeech, &mistral), mistral);
    }

    /// The speech blob is the audio itself: OpenAI's raw body, or the decoded
    /// `audio_data` of Mistral's JSON answer or of its streamed deltas in
    /// order. Live shapes, 2026-10-05.
    #[test]
    fn speech_stores_the_decoded_audio_whatever_the_answer_carries_it_in() {
        let raw = bytes::Bytes::from_static(b"ID3\x04\x00raw-mp3");
        assert_eq!(speech_audio(&raw), raw);
        let json = bytes::Bytes::from_static(br#"{"audio_data":"SUQzBABtcDM="}"#);
        assert_eq!(&speech_audio(&json)[..], b"ID3\x04\x00mp3");
        let sse = bytes::Bytes::from_static(
            b"event: speech.audio.delta\ndata: {\"type\":\"speech.audio.delta\",\"audio_data\":\"SUQz\"}\n\n\
event: speech.audio.delta\ndata: {\"type\":\"speech.audio.delta\",\"audio_data\":\"BABtcDM=\"}\n\n\
event: speech.audio.done\ndata: {\"type\":\"speech.audio.done\",\"usage\":{\"prompt_tokens\":3}}\n\n",
        );
        assert_eq!(&speech_audio(&sse)[..], b"ID3\x04\x00mp3");
        // OpenAI's streamed speech (`stream_format: "sse"`) names it `audio`.
        let openai_sse = bytes::Bytes::from_static(
            b"data: {\"type\":\"speech.audio.delta\",\"audio\":\"SUQz\"}\n\n\
data: {\"type\":\"speech.audio.delta\",\"audio\":\"BABtcDM=\"}\n\n\
data: {\"type\":\"speech.audio.done\",\"usage\":{\"input_tokens\":3}}\n\n",
        );
        assert_eq!(&speech_audio(&openai_sse)[..], b"ID3\x04\x00mp3");
        // A JSON body without audio (an error object) is stored as it came.
        let err = bytes::Bytes::from_static(br#"{"error":"x"}"#);
        assert_eq!(speech_audio(&err), err);
    }

    /// Text-to-speech is priced on the text it was asked to speak, which the
    /// audio response cannot carry — so the request is the measurement. Counted
    /// in characters, not bytes: a rate quoted per character applied to a UTF-8
    /// length over-bills every non-ASCII language by two to three times.
    #[test]
    fn speech_bills_the_characters_it_was_asked_to_speak() {
        use crate::pricing::Unit;
        let ascii = br#"{"model":"tts-1","input":"hello","voice":"alloy"}"#;
        assert_eq!(
            extract_billable_units(b"<binary audio>", ascii, MediaEndpoint::AudioSpeech)
                .get(Unit::InputCharacter),
            5
        );
        let text = "éèêëà";
        assert_eq!(text.chars().count(), 5);
        assert_eq!(text.len(), 10, "fixture must be multi-byte or this proves nothing");
        let accented = format!(r#"{{"model":"tts-1","input":"{text}","voice":"alloy"}}"#);
        assert_eq!(
            extract_billable_units(b"<binary audio>", accented.as_bytes(), MediaEndpoint::AudioSpeech)
                .get(Unit::InputCharacter),
            5,
            "billed UTF-8 bytes instead of characters"
        );
        // Longer than the 500-character audit truncation: billing must read the
        // whole string, not the rendered excerpt.
        let long = format!(r#"{{"model":"tts-1","input":"{}"}}"#, "a".repeat(1200));
        assert_eq!(
            extract_billable_units(b"<binary audio>", long.as_bytes(), MediaEndpoint::AudioSpeech)
                .get(Unit::InputCharacter),
            1200
        );
        for empty in [&br#"{"model":"tts-1"}"#[..], &br#"{"input":""}"#[..]] {
            assert!(
                extract_billable_units(b"", empty, MediaEndpoint::AudioSpeech).is_empty(),
                "invented characters nobody sent"
            );
        }
    }

    /// Video generation is priced per second of the video asked for, and the
    /// response reports no duration — so the request parameter is the
    /// measurement. Vendors spell and type it differently; all the spellings we
    /// forward read the same.
    #[test]
    fn video_bills_the_duration_the_request_asked_for() {
        use crate::pricing::Unit;
        let cases: [(&[u8], u64); 5] = [
            (br#"{"model":"sora-2","prompt":"a dog","seconds":"8"}"#, 8),
            (br#"{"model":"sora-2","prompt":"a dog","seconds":12}"#, 12),
            (br#"{"model":"veo","prompt":"a dog","durationSeconds":6}"#, 6),
            (br#"{"model":"x","prompt":"a dog","duration":4.0}"#, 4),
            // Rounded up, like audio seconds: a provider billing whole seconds
            // never bills fewer than one.
            (br#"{"model":"x","prompt":"a dog","duration":7.2}"#, 8),
        ];
        for (body, expected) in cases {
            assert_eq!(
                extract_billable_units(br#"{"id":"job_1"}"#, body, MediaEndpoint::VideosGenerations)
                    .get(Unit::VideoSecond),
                expected,
                "{}",
                String::from_utf8_lossy(body)
            );
        }
        for absent in [
            &br#"{"model":"sora-2","prompt":"a dog"}"#[..],
            &br#"{"prompt":"a dog","seconds":"auto"}"#[..],
            &br#"{"prompt":"a dog","seconds":-3}"#[..],
            // Beyond any video a model could render: a number the client made
            // up, not a charge. Unlike every other measurement here this one is
            // client-chosen with no body size bounding it, so billing it would
            // invent a figure large enough to exhaust a budget — and a
            // workspace's spend rolls into the organisation's.
            &br#"{"prompt":"a dog","seconds":1e18}"#[..],
            &br#"{"prompt":"a dog","duration":100000}"#[..],
        ] {
            assert!(
                extract_billable_units(br#"{"id":"job_1"}"#, absent, MediaEndpoint::VideosGenerations)
                    .is_empty(),
                "invented a duration from {}",
                String::from_utf8_lossy(absent)
            );
        }
    }

    #[test]
    fn build_media_call_video_extracts_job() {
        let body = br#"{"model":"sora","prompt":"a dog"}"#;
        let resp = br#"{"id":"job_123","status":"queued","progress":0.25}"#;
        let call = build_media_call(MediaCaptureCtx {
            endpoint: MediaEndpoint::VideosGenerations,
            model: "sora",
            request_bytes: body,
            request_content_type: "application/json",
            response_bytes: resp,
            upstream_success: true,
            request_blob: None,
            response_blobs: Vec::new(),
            max_artifact_bytes: 10 * 1024 * 1024,
        });
        let job = call.job.expect("video job");
        assert_eq!(job.job_id, "job_123");
        assert_eq!(job.status, "queued");
        assert_eq!(job.progress, Some(0.25));
    }

    #[test]
    fn default_model_for_images() {
        assert_eq!(
            MediaEndpoint::ImagesGenerations.default_model(),
            Some("dall-e-2")
        );
        assert_eq!(MediaEndpoint::Embeddings.default_model(), None);
        assert_eq!(MediaEndpoint::AudioSpeech.default_model(), None);
    }

    // ── Catch-all path extraction tests ──

    #[test]
    fn extract_catchall_path_standard() {
        assert_eq!(
            extract_catchall_path("/v1/batches/123"),
            Some("/v1/batches/123".to_string())
        );
        assert_eq!(
            extract_catchall_path("/v1/completions"),
            Some("/v1/completions".to_string())
        );
    }

    #[test]
    fn extract_catchall_path_fwd() {
        assert_eq!(
            extract_catchall_path("/fwd/vk-abc123/v1/batches/123"),
            Some("/v1/batches/123".to_string())
        );
        assert_eq!(
            extract_catchall_path("/fwd/vk-abc123/v1/files"),
            Some("/v1/files".to_string())
        );
    }

    #[test]
    fn extract_catchall_path_invalid() {
        assert_eq!(extract_catchall_path("/api/v1/admin"), None);
        assert_eq!(extract_catchall_path("/health"), None);
    }

    // ── Route policy matching tests ──

    #[test]
    fn route_policy_exact_match() {
        let policy = crate::config::RoutePolicy {
            path_pattern: "/v1/completions".to_string(),
            enabled: true,
            rate_limit_rpm: None,
            max_body_bytes: 1024,
            audit_body: false,
        };
        assert!(policy.matches("/v1/completions"));
        assert!(!policy.matches("/v1/completions/extra"));
        assert!(!policy.matches("/v1/complete"));
    }

    #[test]
    fn route_policy_wildcard_match() {
        let policy = crate::config::RoutePolicy {
            path_pattern: "/v1/batches/*".to_string(),
            enabled: true,
            rate_limit_rpm: None,
            max_body_bytes: 1024,
            audit_body: false,
        };
        assert!(policy.matches("/v1/batches/123"));
        assert!(policy.matches("/v1/batches/123/cancel"));
        assert!(!policy.matches("/v1/batches"));  // No trailing slash
        assert!(!policy.matches("/v1/batch/123"));
    }

    #[test]
    fn route_policy_disabled_never_matches() {
        let policy = crate::config::RoutePolicy {
            path_pattern: "/v1/completions".to_string(),
            enabled: false,
            rate_limit_rpm: None,
            max_body_bytes: 1024,
            audit_body: false,
        };
        assert!(!policy.matches("/v1/completions"));
    }

    #[test]
    fn find_matching_policy_returns_first_match() {
        let policies = vec![
            crate::config::RoutePolicy {
                path_pattern: "/v1/batches/*".to_string(),
                enabled: true,
                rate_limit_rpm: Some(10),
                max_body_bytes: 1024,
                audit_body: false,
            },
            crate::config::RoutePolicy {
                path_pattern: "/v1/files".to_string(),
                enabled: true,
                rate_limit_rpm: Some(30),
                max_body_bytes: 2048,
                audit_body: true,
            },
        ];
        let p = crate::config::find_matching_policy(&policies, "/v1/batches/abc");
        assert!(p.is_some());
        assert_eq!(p.unwrap().rate_limit_rpm, Some(10));

        let p2 = crate::config::find_matching_policy(&policies, "/v1/files");
        assert!(p2.is_some());
        assert_eq!(p2.unwrap().rate_limit_rpm, Some(30));

        let p3 = crate::config::find_matching_policy(&policies, "/v1/unknown");
        assert!(p3.is_none());
    }
}

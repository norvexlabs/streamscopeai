//! Multimodal media types for non-chat API endpoints.
//!
//! Covers embeddings, audio (speech, transcription, translation), image
//! (generation, edit, variation), and video generation. Each request type
//! mirrors the OpenAI wire format; multipart endpoints (audio transcription,
//! image edit/variation) use raw [`bytes::Bytes`] instead of Serde for file
//! payloads.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::sync::LazyLock;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum allowed request body size for media uploads (25 MB).
pub const MAX_MEDIA_BODY_SIZE: usize = 25 * 1024 * 1024;

/// Maximum allowed response body size for media responses (50 MB).
pub const MAX_MEDIA_RESPONSE_SIZE: usize = 50 * 1024 * 1024;

// ---------------------------------------------------------------------------
// MIME allowlists
// ---------------------------------------------------------------------------

/// Accepted MIME types for audio uploads.
pub static AUDIO_MIME_TYPES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        "audio/mpeg",
        "audio/wav",
        "audio/webm",
        "audio/mp4",
        "audio/ogg",
        "audio/flac",
        "audio/m4a",
        "audio/aac",
    ])
});

/// Accepted MIME types for image uploads.
pub static IMAGE_MIME_TYPES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        "image/png",
        "image/jpeg",
        "image/gif",
        "image/webp",
        "image/avif",
    ])
});

/// Accepted MIME types for video uploads.
pub static VIDEO_MIME_TYPES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        "video/mp4",
        "video/webm",
        "video/mpeg",
        "video/quicktime",
    ])
});

// ---------------------------------------------------------------------------
// MediaType
// ---------------------------------------------------------------------------

/// High-level media modality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaType {
    Text,
    Embedding,
    Audio,
    Image,
    Video,
}

impl MediaType {
    /// Stable string representation (matches serde `rename_all`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Embedding => "embedding",
            Self::Audio => "audio",
            Self::Image => "image",
            Self::Video => "video",
        }
    }

    /// Default MIME type for response blobs of this media type.
    /// Used when the actual content format is unknown.
    pub fn default_response_mime(&self) -> &'static str {
        match self {
            Self::Audio => "audio/mpeg",
            Self::Image => "image/png",
            Self::Video => "video/mp4",
            Self::Embedding => "application/json",
            Self::Text => "text/plain",
        }
    }

    /// Parse from a string slice (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "text" => Some(Self::Text),
            "embedding" | "embeddings" => Some(Self::Embedding),
            "audio" => Some(Self::Audio),
            "image" => Some(Self::Image),
            "video" => Some(Self::Video),
            _ => None,
        }
    }
}

impl fmt::Display for MediaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// EmbeddingInput
// ---------------------------------------------------------------------------

/// Input variants for the embeddings endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EmbeddingInput {
    /// A single text string.
    Single(String),
    /// A batch of text strings.
    Batch(Vec<String>),
    /// Pre-tokenized input (list of token-ID lists).
    TokenIds(Vec<Vec<i32>>),
}

// ---------------------------------------------------------------------------
// Request structs
// ---------------------------------------------------------------------------

/// Embeddings request (`POST /v1/embeddings`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingsRequest {
    pub model: String,
    pub input: EmbeddingInput,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding_format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dimensions: Option<u32>,
    /// Forward-compat: capture unknown fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Text-to-speech request (`POST /v1/audio/speech`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioSpeechRequest {
    pub model: String,
    pub input: String,
    pub voice: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub speed: Option<f32>,
}

/// Audio transcription request (`POST /v1/audio/transcriptions`).
///
/// This is a multipart endpoint, so it does NOT derive `Serialize`/`Deserialize`.
/// Fields are populated from multipart form parsing.
#[derive(Debug, Clone)]
pub struct AudioTranscriptionRequest {
    pub model: String,
    pub file_bytes: Bytes,
    pub file_name: String,
    pub file_mime: String,
    #[allow(dead_code)]
    pub language: Option<String>,
    #[allow(dead_code)]
    pub prompt: Option<String>,
    #[allow(dead_code)]
    pub response_format: Option<String>,
    #[allow(dead_code)]
    pub temperature: Option<f32>,
    #[allow(dead_code)]
    pub timestamp_granularities: Option<Vec<String>>,
}

/// Audio translation request (`POST /v1/audio/translations`).
///
/// Multipart endpoint — no `Serialize`/`Deserialize`.
#[derive(Debug, Clone)]
pub struct AudioTranslationRequest {
    pub model: String,
    pub file_bytes: Bytes,
    pub file_name: String,
    pub file_mime: String,
    #[allow(dead_code)]
    pub prompt: Option<String>,
    #[allow(dead_code)]
    pub response_format: Option<String>,
    #[allow(dead_code)]
    pub temperature: Option<f32>,
}

/// Image generation request (`POST /v1/images/generations`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageGenerationRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub prompt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quality: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub style: Option<String>,
}

/// Image edit request (`POST /v1/images/edits`).
///
/// Multipart endpoint — does NOT derive `Serialize`.
#[derive(Debug, Clone, Deserialize)]
pub struct ImageEditRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub prompt: String,
    #[serde(skip)]
    pub file_bytes: Bytes,
    #[serde(skip)]
    pub file_name: String,
    #[serde(skip)]
    pub file_mime: String,
    #[serde(skip)]
    pub mask_bytes: Option<Bytes>,
    #[serde(skip)]
    pub mask_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_format: Option<String>,
}

/// Image variation request (`POST /v1/images/variations`).
///
/// Multipart endpoint — does NOT derive `Serialize`.
#[derive(Debug, Clone, Deserialize)]
pub struct ImageVariationRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip)]
    pub file_bytes: Bytes,
    #[serde(skip)]
    pub file_name: String,
    #[serde(skip)]
    pub file_mime: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_format: Option<String>,
}

/// Video generation request (`POST /v1/video/generations`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VideoGenerationRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub prompt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<u32>,
    /// Forward-compat: capture unknown fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

// ---------------------------------------------------------------------------
// MediaRequest dispatch enum
// ---------------------------------------------------------------------------

/// Unified media request — dispatched by endpoint.
#[derive(Debug, Clone)]
pub enum MediaRequest {
    Embeddings(EmbeddingsRequest),
    AudioSpeech(AudioSpeechRequest),
    AudioTranscription(AudioTranscriptionRequest),
    AudioTranslation(AudioTranslationRequest),
    ImageGeneration(ImageGenerationRequest),
    ImageEdit(ImageEditRequest),
    ImageVariation(ImageVariationRequest),
    VideoGeneration(VideoGenerationRequest),
}

impl MediaRequest {
    /// Get the model name from the request.
    ///
    /// Returns `None` for endpoints where the model is optional and not set
    /// (e.g. image generation defaults to `dall-e-2` server-side).
    pub fn model(&self) -> Option<&str> {
        match self {
            Self::Embeddings(r) => Some(&r.model),
            Self::AudioSpeech(r) => Some(&r.model),
            Self::AudioTranscription(r) => Some(&r.model),
            Self::AudioTranslation(r) => Some(&r.model),
            Self::ImageGeneration(r) => r.model.as_deref(),
            Self::ImageEdit(r) => r.model.as_deref(),
            Self::ImageVariation(r) => r.model.as_deref(),
            Self::VideoGeneration(r) => r.model.as_deref(),
        }
    }

    /// Set the model name on the request.
    pub fn set_model(&mut self, model: String) {
        match self {
            Self::Embeddings(r) => r.model = model,
            Self::AudioSpeech(r) => r.model = model,
            Self::AudioTranscription(r) => r.model = model,
            Self::AudioTranslation(r) => r.model = model,
            Self::ImageGeneration(r) => r.model = Some(model),
            Self::ImageEdit(r) => r.model = Some(model),
            Self::ImageVariation(r) => r.model = Some(model),
            Self::VideoGeneration(r) => r.model = Some(model),
        }
    }

    /// The high-level media modality for this request.
    pub fn media_type(&self) -> MediaType {
        match self {
            Self::Embeddings(_) => MediaType::Embedding,
            Self::AudioSpeech(_) | Self::AudioTranscription(_) | Self::AudioTranslation(_) => {
                MediaType::Audio
            }
            Self::ImageGeneration(_) | Self::ImageEdit(_) | Self::ImageVariation(_) => {
                MediaType::Image
            }
            Self::VideoGeneration(_) => MediaType::Video,
        }
    }

    /// Extract the primary text input from the request, if any.
    ///
    /// Useful for audit logging and content-policy checks. Returns `None` for
    /// requests that have no meaningful text input (e.g. image variations).
    pub fn input_text(&self) -> Option<&str> {
        match self {
            Self::Embeddings(r) => match &r.input {
                EmbeddingInput::Single(s) => Some(s),
                EmbeddingInput::Batch(v) => v.first().map(|s| s.as_str()),
                EmbeddingInput::TokenIds(_) => None,
            },
            Self::AudioSpeech(r) => Some(&r.input),
            Self::AudioTranscription(r) => r.prompt.as_deref(),
            Self::AudioTranslation(r) => r.prompt.as_deref(),
            Self::ImageGeneration(r) => Some(&r.prompt),
            Self::ImageEdit(r) => Some(&r.prompt),
            Self::ImageVariation(_) => None,
            Self::VideoGeneration(r) => Some(&r.prompt),
        }
    }

    /// Rough estimate of input tokens for budget/rate-limit purposes.
    ///
    /// Uses the ~4 chars/token heuristic for text inputs. For binary uploads,
    /// returns 0 (binary content is billed differently by providers).
    pub fn estimated_input_tokens(&self) -> usize {
        match self {
            Self::Embeddings(r) => match &r.input {
                EmbeddingInput::Single(s) => s.len() / 4,
                EmbeddingInput::Batch(v) => {
                    v.iter().map(|s| s.len()).sum::<usize>() / 4
                }
                EmbeddingInput::TokenIds(v) => {
                    v.iter().map(|ids| ids.len()).sum()
                }
            },
            Self::AudioSpeech(r) => r.input.len() / 4,
            Self::AudioTranscription(_) | Self::AudioTranslation(_) => 0,
            Self::ImageGeneration(r) => r.prompt.len() / 4,
            Self::ImageEdit(r) => r.prompt.len() / 4,
            Self::ImageVariation(_) => 0,
            Self::VideoGeneration(r) => r.prompt.len() / 4,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_type_as_str_roundtrip() {
        for mt in &[
            MediaType::Text,
            MediaType::Embedding,
            MediaType::Audio,
            MediaType::Image,
            MediaType::Video,
        ] {
            let s = mt.as_str();
            let parsed = MediaType::parse(s).expect("should parse");
            assert_eq!(*mt, parsed);
        }
    }

    #[test]
    fn media_type_display() {
        assert_eq!(MediaType::Audio.to_string(), "audio");
        assert_eq!(MediaType::Image.to_string(), "image");
    }

    #[test]
    fn media_type_from_str_case_insensitive() {
        assert_eq!(MediaType::parse("AUDIO"), Some(MediaType::Audio));
        assert_eq!(MediaType::parse("Embeddings"), Some(MediaType::Embedding));
        assert_eq!(MediaType::parse("unknown"), None);
    }

    #[test]
    fn media_type_serde_roundtrip() {
        let mt = MediaType::Video;
        let json = serde_json::to_string(&mt).unwrap();
        assert_eq!(json, "\"video\"");
        let parsed: MediaType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, mt);
    }

    #[test]
    fn embeddings_request_model_and_tokens() {
        let req = MediaRequest::Embeddings(EmbeddingsRequest {
            model: "text-embedding-3-small".to_string(),
            input: EmbeddingInput::Single("hello world".to_string()),
            encoding_format: None,
            dimensions: None,
            extra: BTreeMap::new(),
        });
        assert_eq!(req.model(), Some("text-embedding-3-small"));
        assert_eq!(req.media_type(), MediaType::Embedding);
        assert_eq!(req.input_text(), Some("hello world"));
        // "hello world" = 11 chars / 4 = 2
        assert_eq!(req.estimated_input_tokens(), 2);
    }

    #[test]
    fn embeddings_batch_tokens() {
        let req = MediaRequest::Embeddings(EmbeddingsRequest {
            model: "text-embedding-3-small".to_string(),
            input: EmbeddingInput::Batch(vec![
                "hello".to_string(),
                "world".to_string(),
            ]),
            encoding_format: None,
            dimensions: None,
            extra: BTreeMap::new(),
        });
        // 5 + 5 = 10 chars / 4 = 2
        assert_eq!(req.estimated_input_tokens(), 2);
        // input_text returns first element
        assert_eq!(req.input_text(), Some("hello"));
    }

    #[test]
    fn embeddings_token_ids_count() {
        let req = MediaRequest::Embeddings(EmbeddingsRequest {
            model: "text-embedding-3-small".to_string(),
            input: EmbeddingInput::TokenIds(vec![vec![1, 2, 3], vec![4, 5]]),
            encoding_format: None,
            dimensions: None,
            extra: BTreeMap::new(),
        });
        // 3 + 2 = 5 tokens
        assert_eq!(req.estimated_input_tokens(), 5);
        assert_eq!(req.input_text(), None);
    }

    #[test]
    fn audio_speech_fields() {
        let req = MediaRequest::AudioSpeech(AudioSpeechRequest {
            model: "tts-1".to_string(),
            input: "Hello there.".to_string(),
            voice: "alloy".to_string(),
            response_format: Some("mp3".to_string()),
            speed: Some(1.0),
        });
        assert_eq!(req.model(), Some("tts-1"));
        assert_eq!(req.media_type(), MediaType::Audio);
        assert_eq!(req.input_text(), Some("Hello there."));
        assert_eq!(req.estimated_input_tokens(), 3); // 12 / 4
    }

    #[test]
    fn image_generation_optional_model() {
        let mut req = MediaRequest::ImageGeneration(ImageGenerationRequest {
            model: None,
            prompt: "A sunset over mountains".to_string(),
            n: Some(1),
            size: Some("1024x1024".to_string()),
            quality: None,
            response_format: None,
            style: None,
        });
        assert_eq!(req.model(), None);
        assert_eq!(req.media_type(), MediaType::Image);
        assert_eq!(req.input_text(), Some("A sunset over mountains"));

        req.set_model("dall-e-3".to_string());
        assert_eq!(req.model(), Some("dall-e-3"));
    }

    #[test]
    fn image_variation_no_text() {
        let req = MediaRequest::ImageVariation(ImageVariationRequest {
            model: None,
            file_bytes: Bytes::from_static(b"fake-png"),
            file_name: "image.png".to_string(),
            file_mime: "image/png".to_string(),
            n: Some(2),
            size: None,
            response_format: None,
        });
        assert_eq!(req.input_text(), None);
        assert_eq!(req.estimated_input_tokens(), 0);
        assert_eq!(req.media_type(), MediaType::Image);
    }

    #[test]
    fn video_generation_fields() {
        let req = MediaRequest::VideoGeneration(VideoGenerationRequest {
            model: Some("sora".to_string()),
            prompt: "A cat playing piano".to_string(),
            size: Some("1920x1080".to_string()),
            duration: Some(5.0),
            n: Some(1),
            extra: BTreeMap::new(),
        });
        assert_eq!(req.model(), Some("sora"));
        assert_eq!(req.media_type(), MediaType::Video);
        assert_eq!(req.input_text(), Some("A cat playing piano"));
    }

    #[test]
    fn set_model_on_required_field() {
        let mut req = MediaRequest::Embeddings(EmbeddingsRequest {
            model: "old-model".to_string(),
            input: EmbeddingInput::Single("test".to_string()),
            encoding_format: None,
            dimensions: None,
            extra: BTreeMap::new(),
        });
        req.set_model("new-model".to_string());
        assert_eq!(req.model(), Some("new-model"));
    }

    #[test]
    fn audio_transcription_zero_tokens() {
        let req = MediaRequest::AudioTranscription(AudioTranscriptionRequest {
            model: "whisper-1".to_string(),
            file_bytes: Bytes::from_static(b"fake-audio"),
            file_name: "recording.mp3".to_string(),
            file_mime: "audio/mpeg".to_string(),
            language: Some("en".to_string()),
            prompt: None,
            response_format: None,
            temperature: None,
            timestamp_granularities: None,
        });
        assert_eq!(req.estimated_input_tokens(), 0);
        assert_eq!(req.input_text(), None);
        assert_eq!(req.media_type(), MediaType::Audio);
    }

    #[test]
    fn mime_allowlists_contain_expected_types() {
        assert!(AUDIO_MIME_TYPES.contains("audio/mpeg"));
        assert!(AUDIO_MIME_TYPES.contains("audio/flac"));
        assert!(!AUDIO_MIME_TYPES.contains("audio/midi"));

        assert!(IMAGE_MIME_TYPES.contains("image/png"));
        assert!(IMAGE_MIME_TYPES.contains("image/avif"));
        assert!(!IMAGE_MIME_TYPES.contains("image/bmp"));

        assert!(VIDEO_MIME_TYPES.contains("video/mp4"));
        assert!(VIDEO_MIME_TYPES.contains("video/quicktime"));
        assert!(!VIDEO_MIME_TYPES.contains("video/avi"));
    }

    #[test]
    fn constants_are_sane() {
        assert_eq!(MAX_MEDIA_BODY_SIZE, 25 * 1024 * 1024);
        assert_eq!(MAX_MEDIA_RESPONSE_SIZE, 50 * 1024 * 1024);
        // Compile-time check that response limit > upload limit.
        const { assert!(MAX_MEDIA_RESPONSE_SIZE > MAX_MEDIA_BODY_SIZE) };
    }

    #[test]
    fn embeddings_serde_roundtrip() {
        let req = EmbeddingsRequest {
            model: "text-embedding-3-small".to_string(),
            input: EmbeddingInput::Single("test input".to_string()),
            encoding_format: Some("float".to_string()),
            dimensions: Some(256),
            extra: BTreeMap::new(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: EmbeddingsRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.model, "text-embedding-3-small");
        assert_eq!(parsed.dimensions, Some(256));
    }

    #[test]
    fn image_generation_serde_roundtrip() {
        let json = r#"{"prompt":"A cat","n":2,"size":"512x512"}"#;
        let req: ImageGenerationRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.model, None);
        assert_eq!(req.prompt, "A cat");
        assert_eq!(req.n, Some(2));
    }

    #[test]
    fn video_generation_preserves_extra_fields() {
        let json = r#"{"model":"sora","prompt":"test","fps":30}"#;
        let req: VideoGenerationRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.extra.get("fps"), Some(&serde_json::json!(30)));
    }
}

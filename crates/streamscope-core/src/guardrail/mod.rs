//! Inline injection guardrail — screens untrusted content for prompt-injection
//! on two surfaces: the web search/fetch results folded back on the substitution
//! loop's re-forward (response phase, P0), and the inbound prompt — the user's
//! own message (P2) plus untrusted content the client folds into a message as a
//! tool-result (P1) — on the request phase.
//!
//! Module layout:
//! - [`settings`] — [`GuardrailSettings`], the typed projection of the
//!   `system_settings.guardrail` key, carried on
//!   [`crate::config::TenantConfig::guardrail`].
//! - [`classifier`] — the batch-first [`GuardrailDetector`] transport trait,
//!   its standard-protocol adapters ([`HttpClassifier`]), windowing, and the
//!   [`Verdict`] type.
//! - [`scan`] — the surface-agnostic verdict → audit-badge / trace-step fold
//!   (observe + enforce) shared by both hops, parameterized by
//!   [`scan::GuardrailSurface`].
//!
//! The *timing* of classification (overlap with the re-forward in observe mode,
//! serial-before-fold in enforce) and the content mutation are each caller's
//! concern at the substitution-loop / request-pipeline layer; this module owns
//! the reusable detector transport, the per-tenant configuration, and the shared
//! fold.

pub mod classifier;
pub mod pii;
pub mod pii_recognizers;
pub mod scan;
pub mod screened;
pub mod settings;

pub use classifier::{
    classify_texts, classify_with_shared_client, windows,
    ClassifierConfig, GuardrailCategory, GuardrailDetector, GuardrailError, HttpClassifier,
    ScanResult, Verdict,
};
pub use pii::{
    detect_pii, redact, run_pii_enforce, run_pii_observe, PiiEnforceOutcome, PiiFinding,
    PiiObserveOutcome,
};
pub use scan::{
    run_enforce, run_observe, GuardrailEnforceOutcome, GuardrailInput, GuardrailObserveOutcome,
    GuardrailSurface, INCOMPLETE_SCAN_REASON,
};
pub use settings::{
    ClassifierProtocol, GuardrailBackendSettings, GuardrailFailMode, GuardrailMode, GuardrailPolicy,
    GuardrailSettings, PiiSettings, PII_ENTITY_TYPES,
};

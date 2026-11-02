//! Per-tenant guardrail settings — typed projection of the
//! `system_settings.guardrail` key (one nested JSON object, same pattern as
//! `web` / `tool_rules`).
//!
//! Lives on [`crate::config::TenantConfig::guardrail`]; populated by the
//! proxy's config-sync loop from the admin-pushed snapshot. Defaults are
//! **inert until a classifier is available**: `enabled = true` but
//! `classifier_url = None`, so [`is_active`](GuardrailSettings::is_active) is
//! false and the hook is a no-op until the tenant has a classifier URL (an
//! install connected to a classifier sets it on the tenant it creates). So a
//! classifier URL alone activates the guardrail (observe mode) with no other
//! settings step; an admin can set `enabled = false` to opt out.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Posture applied to a flagged verdict.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailMode {
    /// Scan, badge, and audit — content is left untouched. The default and the
    /// false-positive bake posture: the operator sees what *would* have been
    /// blocked without risking a legitimate page.
    #[default]
    Observe,
    /// Strip flagged content to a visible human-readable placeholder before the
    /// model ever sees it. Opt-in; lands after the observe bake validates the
    /// false-positive rate.
    Enforce,
}

/// How a detector failure (timeout / transport / parse error) is handled.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailFailMode {
    /// Pass the content through on a detector error and stamp a
    /// `GuardrailError` badge. Availability over strictness — mirrors the
    /// `rhai_fail_mode` default.
    #[default]
    Open,
    /// Treat a detector error as a block (enforce mode only — in observe mode
    /// there is nothing to block, so the error is still surfaced as a badge).
    Closed,
}

/// Wire protocol the configured classifier endpoint speaks. Lets one
/// `classifier_url` target the classifier extension **or** another service
/// without per-vendor code.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ClassifierProtocol {
    /// HuggingFace text-classification `/predict` — the de-facto shape spoken
    /// by TEI, HF Inference Endpoints, and the `transformers` pipeline. The
    /// classifier extension serves this.
    #[default]
    HfTextClassification,
    /// OpenAI `/v1/moderations` — the most widely-adopted external guardrail
    /// shape (OpenAI / Azure / various vendors). Unlocks hosted
    /// guardrails with zero per-vendor code.
    OpenaiModerations,
}

/// Per-tenant configuration for the inline injection guardrail.
///
/// Backed by `system_settings.guardrail`; synced through the config-sync
/// sweeper. Default = enabled but no classifier → [`is_active`](Self::is_active)
/// is false and the hook short-circuits until a classifier URL resolves.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct GuardrailSettings {
    /// Master toggle. Defaults **on** so that setting `classifier_url` lights
    /// the guardrail up with no other settings step —
    /// [`is_active`](Self::is_active) still requires a `classifier_url`, so a
    /// tenant WITHOUT a classifier stays inert. An admin can explicitly set it
    /// `false` to opt out.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Observe (default) vs enforce. See [`GuardrailMode`].
    #[serde(default)]
    pub mode: GuardrailMode,

    /// Also screen the **inbound prompt** — the user's own latest message (P2:
    /// direct injection / jailbreak) plus any untrusted content the client
    /// folded into the messages as a tool-result (P1: indirect injection via
    /// RAG / tool output). Opt-in (`false` by default) and **independent of the
    /// always-on web-content surface**: a tenant that enabled the guardrail only
    /// to screen web search/fetch results is never surprised by inbound
    /// blocking. `mode` / `fail_mode` / `threshold` / `timeout_ms` are shared
    /// with the web surface. Inert unless [`is_active`](Self::is_active).
    #[serde(default)]
    pub scan_inbound: bool,

    /// Classifier endpoint base URL. `None` (default) = inert.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classifier_url: Option<String>,

    /// Which wire shape `classifier_url` speaks.
    #[serde(default)]
    pub protocol: ClassifierProtocol,

    /// Label that signals a positive (injection) classification in the
    /// `hf_text_classification` response. ProtectAI's model emits `INJECTION`;
    /// another model may use `malicious` / `LABEL_1`. Ignored by
    /// `openai_moderations` (which carries an explicit `flagged` field).
    /// Never hardcode the label at the call site — it rides here.
    #[serde(default = "default_positive_label")]
    pub positive_label: String,

    /// Confidence at or above which a verdict counts as flagged.
    #[serde(default = "default_threshold")]
    pub threshold: f32,

    /// Per-request detector budget in milliseconds. Bounded so the hook is never
    /// an unbounded wait, but wide enough for a CPU classifier's forward pass over
    /// a large prompt; on expiry the detector returns
    /// [`super::GuardrailError::Timeout`] and `fail_mode` decides the outcome.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,

    /// Detector-error handling. See [`GuardrailFailMode`].
    #[serde(default)]
    pub fail_mode: GuardrailFailMode,

    /// Wrap each fetched tool-result in explicit spotlight datamarking
    /// delimiters before fold-in (cheap, local; Microsoft arXiv 2403.14720).
    /// On by default — applies in both observe and enforce.
    #[serde(default = "default_true")]
    pub spotlight: bool,

    /// Maximum number of bounded sliding windows a single long **prose** input
    /// (the inbound prompt, the model's own response) is split into before
    /// classification. Caps the batch a giant prompt can generate. `0` is
    /// treated as `1`.
    #[serde(default = "default_max_windows")]
    pub max_windows: u32,

    /// Same cap for **third-party content the gateway itself fetched** — a web
    /// search/fetch result, a peer A2A agent's reply. Higher than
    /// [`max_windows`](Self::max_windows) because that content is both the P0
    /// injection surface and by far the largest: a page whose text exceeds the
    /// cap has its tail classified by nothing, which is why this side buys more
    /// coverage than the caller's own prose. `0` is treated as `1`.
    #[serde(default = "default_max_windows_content")]
    pub max_windows_content: u32,

    /// Emit a daily notification when verdicts are flagged in **observe** mode.
    /// Default off: observe mode is the noisy false-positive bake phase, so the
    /// alarm is opt-in — the badge on each flagged audit row and the dashboard
    /// attention tile are the always-on signal. Consumed by the leader-elected
    /// guardrail-detection alert producer.
    #[serde(default)]
    pub notify_on_detection: bool,

    /// In-process PII detection / redaction (independent of the injection
    /// classifier above — no `classifier_url` required, the detector is always
    /// in-process). Inert by default ([`PiiSettings::enabled`] is `false`).
    #[serde(default)]
    pub pii: PiiSettings,
}

/// All PII entity types the v1 detector recognizes. The default
/// [`PiiSettings::entities`] allowlist when PII is enabled; also the closed set
/// the admin UI offers. Keep in sync with `seeds/pii/recognizers.json`.
pub const PII_ENTITY_TYPES: &[&str] = &[
    // Generic / US (country-agnostic high-volume DLP entities).
    "EMAIL_ADDRESS",
    "CREDIT_CARD",
    "US_SSN",
    "IBAN_CODE",
    "PHONE_NUMBER",
    "IP_ADDRESS",
    "CRYPTO",
    "US_BANK_NUMBER",
    // France.
    "FR_NIR",
    "FR_VAT",
    "FR_TAX_NUMBER",
    "FR_PASSPORT",
    "FR_DRIVER_LICENSE",
    "FR_POSTAL_CODE",
    // Germany.
    "DE_TAX_ID",
    "DE_VAT",
    "DE_STEUERNUMMER",
    "DE_ID_CARD",
    "DE_DRIVER_LICENSE",
    "DE_PASSPORT",
    "DE_POSTAL_CODE",
    // Italy.
    "IT_FISCAL_CODE",
    "IT_VAT_CODE",
    "IT_DRIVER_LICENSE",
    "IT_IDENTITY_CARD",
    "IT_PASSPORT",
    "IT_POSTAL_CODE",
    // Spain.
    "ES_NIF",
    "ES_NIE",
    "ES_CIF",
    "ES_PASSPORT",
    "ES_POSTAL_CODE",
    // United Kingdom.
    "UK_NINO",
    "UK_NHS",
    "UK_VAT",
    "UK_UTR",
    "UK_DRIVING_LICENCE",
    "UK_PASSPORT",
    "UK_POSTCODE",
];

/// Per-tenant configuration for the in-process PII detector. Lives under
/// `system_settings.guardrail.pii`; synced through the same config-sync path as
/// the rest of [`GuardrailSettings`]. Defaults to **observe** on the inbound
/// request — like the injection classifier, detection is on out of the box, but
/// observe mode only badges/audits and never mutates content (enforce and
/// response scanning are the opt-ins).
///
/// Unlike the injection classifier, the PII detector is purely in-process, so it
/// has no transport / endpoint / timeout and cannot "fail" as a unit — a
/// recognizer-script error fails safe per-candidate (the candidate is dropped).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct PiiSettings {
    /// Master toggle. Default **on** (observe) — like the injection classifier.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Observe (default) vs enforce. See [`GuardrailMode`]. Enforce masks each
    /// finding in place (`[REDACTED:US_SSN]`).
    #[serde(default)]
    pub mode: GuardrailMode,

    /// Scan the **inbound** request — the user's own latest message (P5: DLP
    /// egress, stopping PII from leaving for the upstream model). Default **on**.
    #[serde(default = "default_true")]
    pub scan_request: bool,

    /// Scan the **model response** (P3: leakage — PII the model emitted). Opt-in
    /// (the default-on observe covers the inbound request surface only).
    #[serde(default)]
    pub scan_response: bool,

    /// Entity types to detect. Defaults to all of [`PII_ENTITY_TYPES`]. An entity
    /// not in this list is never flagged.
    #[serde(default = "default_pii_entities")]
    pub entities: Vec<String>,

    /// Score at or above which a finding surfaces. Native-validated entities
    /// (card/SSN/IBAN) score high; pattern-only entities lean on a context
    /// boost to clear this.
    #[serde(default = "default_pii_threshold")]
    pub threshold: f32,

    /// Replacement for a masked finding in enforce mode. `{entity}` is
    /// substituted with the entity type.
    #[serde(default = "default_pii_placeholder")]
    pub redaction_placeholder: String,

    /// Reserved for parity with the injection guardrail's fail-mode. The
    /// in-process detector cannot fail as a unit (script errors fail safe
    /// per-candidate), so this is currently unused; kept so the wire shape and
    /// admin surface match the classifier's.
    #[serde(default)]
    pub fail_mode: GuardrailFailMode,
}

fn default_pii_entities() -> Vec<String> {
    PII_ENTITY_TYPES.iter().map(|s| s.to_string()).collect()
}

fn default_pii_threshold() -> f32 {
    0.5
}

fn default_pii_placeholder() -> String {
    "[REDACTED:{entity}]".to_string()
}

impl Default for PiiSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: GuardrailMode::default(),
            scan_request: true,
            scan_response: false,
            entities: default_pii_entities(),
            threshold: default_pii_threshold(),
            redaction_placeholder: default_pii_placeholder(),
            fail_mode: GuardrailFailMode::default(),
        }
    }
}

impl PiiSettings {
    /// Whether enforce mode masks findings (vs observe, which only badges).
    pub fn enforces(&self) -> bool {
        matches!(self.mode, GuardrailMode::Enforce)
    }
}

fn default_positive_label() -> String {
    "INJECTION".to_string()
}

fn default_threshold() -> f32 {
    0.9
}

fn default_timeout_ms() -> u64 {
    // The classifier extension runs on CPU: a DeBERTa forward
    // pass over the injection windows exceeds a 500 ms budget on a large prompt
    // (a 25k-token agent turn), and — since the hook is observe + fail-open by
    // default — a timeout there silently skips injection scanning on exactly the
    // biggest prompts. A healthy (GPU / warm) classifier answers well under this
    // ceiling, so it only ever bites a genuinely slow detector.
    2000
}

fn default_true() -> bool {
    true
}

fn default_max_windows() -> u32 {
    // ~11 KB of the caller's own prose at the classifier's window size, which
    // clears the 10K-character ceiling the comparable hosted prompt-attack
    // detectors accept for one user prompt — so an ordinary long paste is read
    // end-to-end rather than screened head-first and passed on trust.
    6
}

fn default_max_windows_content() -> u32 {
    // ~58 KB of extracted text at the classifier's window size — a long article
    // or reference page read end-to-end, where the prose cap (~11 KB) stops a
    // fifth of the way in and leaves the tail unclassified, and above the ~55K
    // characters hosted detectors accept for retrieved grounding material. Equal
    // to `MAX_CLIENT_BATCH_WINDOWS`, so one fetched document costs at most one
    // detector round-trip and one `timeout_ms` budget; keep the two in step, and
    // note the per-round ceiling in `classify_texts` bounds a many-result round
    // regardless.
    32
}

impl Default for GuardrailSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: GuardrailMode::default(),
            scan_inbound: false,
            classifier_url: None,
            protocol: ClassifierProtocol::default(),
            positive_label: default_positive_label(),
            threshold: default_threshold(),
            timeout_ms: default_timeout_ms(),
            fail_mode: GuardrailFailMode::default(),
            spotlight: true,
            max_windows: default_max_windows(),
            max_windows_content: default_max_windows_content(),
            notify_on_detection: false,
            pii: PiiSettings::default(),
        }
    }
}

impl GuardrailSettings {
    /// A fully-inert guardrail: `enabled = false` (so [`is_active`](Self::is_active)
    /// is always false) and PII detection off. Returned for a workspace that has
    /// explicitly turned its guardrail **off** ([`crate::config::WorkspaceProfile::Off`]),
    /// distinct from the resolved tenant *default* which may carry an enabled
    /// policy (PII observe-on). No detector ever runs and inbound prose is never
    /// mutated — the property the agent's own analysis traffic relies on.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            // `PiiSettings::default()` is `enabled: true` (kept inert by the
            // master gate); force it off too so an explicit-Off guardrail is
            // unambiguously dead — no PII scan even if the gate logic changes.
            pii: PiiSettings {
                enabled: false,
                ..PiiSettings::default()
            },
            ..Self::default()
        }
    }

    /// `true` when the guardrail is both enabled and has a resolved classifier
    /// URL — the only state in which the hook actually calls a detector. A
    /// tenant that flips `enabled` on without a classifier stays inert rather
    /// than failing requests.
    pub fn is_active(&self) -> bool {
        self.enabled
            && self
                .classifier_url
                .as_deref()
                .map(str::trim)
                .is_some_and(|u| !u.is_empty())
    }

    /// Whether the inbound hop screens a request: the injection check on the
    /// request, or the PII check on it.
    pub fn screens_inbound(&self) -> bool {
        (self.is_active() && self.scan_inbound) || (self.pii.enabled && self.pii.scan_request)
    }

    /// Whether a flagged verdict should mutate content (enforce) or only badge
    /// it (observe).
    pub fn enforces(&self) -> bool {
        matches!(self.mode, GuardrailMode::Enforce)
    }

    /// Fold the tenant-wide [`GuardrailBackendSettings`] and a per-profile
    /// [`GuardrailPolicy`] into the flat struct the detector dispatch consumes.
    /// This is the ONLY place the two halves recombine — the proxy builds one
    /// resolved `GuardrailSettings` per reachable guardrail profile at snapshot
    /// load, so the hot path never re-folds.
    ///
    /// Invariant: `resolve(&BackendDefault, &PolicyDefault) == GuardrailSettings::default()`
    /// and `resolve` preserves [`is_active`](Self::is_active) — a profile with
    /// `enabled = false` stays inert even when the backend has a classifier URL.
    pub fn resolve(backend: &GuardrailBackendSettings, policy: &GuardrailPolicy) -> Self {
        Self {
            // ── per-profile policy ──
            enabled: policy.enabled,
            mode: policy.mode,
            scan_inbound: policy.scan_inbound,
            threshold: policy.threshold,
            fail_mode: policy.fail_mode,
            pii: policy.pii.clone(),
            // ── tenant-wide backend ──
            classifier_url: backend.classifier_url.clone(),
            protocol: backend.protocol,
            positive_label: backend.positive_label.clone(),
            timeout_ms: backend.timeout_ms,
            spotlight: backend.spotlight,
            max_windows: backend.max_windows,
            max_windows_content: backend.max_windows_content,
            notify_on_detection: backend.notify_on_detection,
        }
    }
}

/// Tenant-wide guardrail **backend** config — the classifier deployment shared
/// by every guardrail profile in the tenant. Backed by `system_settings.guardrail`.
/// Never per-workspace: one classifier endpoint, one alert producer. Combined
/// with a per-profile [`GuardrailPolicy`] via [`GuardrailSettings::resolve`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct GuardrailBackendSettings {
    /// Classifier endpoint base URL. `None` (default) = inert.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classifier_url: Option<String>,
    /// Which wire shape `classifier_url` speaks.
    #[serde(default)]
    pub protocol: ClassifierProtocol,
    /// Label that signals a positive (injection) classification for
    /// `hf_text_classification`. Ignored by `openai_moderations`.
    #[serde(default = "default_positive_label")]
    pub positive_label: String,
    /// Per-request detector budget in milliseconds.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Maximum bounded sliding windows a single long **prose** input (inbound
    /// prompt / model response) is split into. `0`→`1`.
    #[serde(default = "default_max_windows")]
    pub max_windows: u32,
    /// Same cap for gateway-fetched **third-party content** (web results, peer
    /// agent replies) — the P0 surface, so it gets more coverage. `0`→`1`.
    #[serde(default = "default_max_windows_content")]
    pub max_windows_content: u32,
    /// Wrap each fetched tool-result in spotlight datamarking delimiters.
    #[serde(default = "default_true")]
    pub spotlight: bool,
    /// Emit a daily notification when verdicts are flagged in observe mode.
    /// Tenant-wide (the alert producer is leader-elected and tenant-scoped), not
    /// per-profile.
    #[serde(default)]
    pub notify_on_detection: bool,
}

impl Default for GuardrailBackendSettings {
    fn default() -> Self {
        Self {
            classifier_url: None,
            protocol: ClassifierProtocol::default(),
            positive_label: default_positive_label(),
            timeout_ms: default_timeout_ms(),
            max_windows: default_max_windows(),
            max_windows_content: default_max_windows_content(),
            spotlight: true,
            notify_on_detection: false,
        }
    }
}

/// Per-profile guardrail **policy** — the posture a workspace's selected profile
/// applies. Backed by `system_settings.guardrail_profiles` keyed by profile id;
/// an absent entry resolves to [`GuardrailPolicy::default()`]. Combined with the
/// tenant [`GuardrailBackendSettings`] via [`GuardrailSettings::resolve`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct GuardrailPolicy {
    /// Master toggle. Default **on** (still inert without a resolved backend
    /// `classifier_url`, mirroring [`GuardrailSettings::is_active`]).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Observe (default) vs enforce.
    #[serde(default)]
    pub mode: GuardrailMode,
    /// Also screen the inbound prompt (P1/P2). Opt-in.
    #[serde(default)]
    pub scan_inbound: bool,
    /// Confidence at or above which a verdict counts as flagged.
    #[serde(default = "default_threshold")]
    pub threshold: f32,
    /// Detector-error handling.
    #[serde(default)]
    pub fail_mode: GuardrailFailMode,
    /// In-process PII detection / redaction (no backend — fully per-profile).
    #[serde(default)]
    pub pii: PiiSettings,
}

impl Default for GuardrailPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: GuardrailMode::default(),
            scan_inbound: false,
            threshold: default_threshold(),
            fail_mode: GuardrailFailMode::default(),
            pii: PiiSettings::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_inert() {
        let s = GuardrailSettings::default();
        // Enabled by default, but inert without a classifier URL — a tenant
        // admin setting `classifier_url` is what activates it.
        assert!(s.enabled);
        assert!(!s.is_active());
        assert!(!s.enforces());
        assert_eq!(s.mode, GuardrailMode::Observe);
        assert_eq!(s.fail_mode, GuardrailFailMode::Open);
        assert_eq!(s.protocol, ClassifierProtocol::HfTextClassification);
        assert_eq!(s.positive_label, "INJECTION");
        assert_eq!(s.threshold, 0.9);
        assert_eq!(s.timeout_ms, 2000);
        assert!(s.spotlight);
        assert_eq!(s.max_windows, 6);
        // Gateway-fetched third-party content (the P0 surface) gets the wider cap.
        assert_eq!(s.max_windows_content, 32);
        assert!(!s.notify_on_detection);
        // PII defaults to observe on the inbound request (like the classifier,
        // on out of the box) — active but non-mutating; response scanning and
        // enforce stay opt-in.
        assert!(s.pii.enabled);
        assert!(s.pii.scan_request);
        assert!(!s.pii.scan_response);
        assert!(!s.pii.enforces());
        assert_eq!(s.pii.mode, GuardrailMode::Observe);
        assert_eq!(s.pii.threshold, 0.5);
        assert_eq!(s.pii.redaction_placeholder, "[REDACTED:{entity}]");
        assert_eq!(s.pii.entities.len(), PII_ENTITY_TYPES.len());
    }

    #[test]
    fn empty_json_yields_defaults() {
        let s: GuardrailSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(s, GuardrailSettings::default());
    }

    #[test]
    fn enabled_without_classifier_is_not_active() {
        let s = GuardrailSettings {
            enabled: true,
            ..Default::default()
        };
        assert!(!s.is_active());
    }

    #[test]
    fn blank_classifier_url_is_not_active() {
        let s = GuardrailSettings {
            enabled: true,
            classifier_url: Some("   ".to_string()),
            ..Default::default()
        };
        assert!(!s.is_active());
    }

    #[test]
    fn enabled_with_classifier_is_active() {
        let s = GuardrailSettings {
            enabled: true,
            classifier_url: Some("http://classifier:8000".to_string()),
            ..Default::default()
        };
        assert!(s.is_active());
    }

    #[test]
    fn round_trips_through_json() {
        let s = GuardrailSettings {
            enabled: true,
            mode: GuardrailMode::Enforce,
            scan_inbound: true,
            classifier_url: Some("http://c:8000".to_string()),
            protocol: ClassifierProtocol::OpenaiModerations,
            positive_label: "malicious".to_string(),
            threshold: 0.75,
            timeout_ms: 300,
            fail_mode: GuardrailFailMode::Closed,
            spotlight: false,
            max_windows: 8,
            max_windows_content: 24,
            notify_on_detection: true,
            pii: PiiSettings {
                enabled: true,
                mode: GuardrailMode::Enforce,
                scan_request: true,
                scan_response: true,
                entities: vec!["US_SSN".to_string(), "EMAIL_ADDRESS".to_string()],
                threshold: 0.7,
                redaction_placeholder: "<{entity}>".to_string(),
                fail_mode: GuardrailFailMode::Closed,
            },
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: GuardrailSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn pii_defaults_observe_request_with_full_entity_list() {
        // An empty object fills via serde defaults — PII is observe-on for the
        // inbound request (response scanning + enforce opt-in), all entities.
        let p: PiiSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(p, PiiSettings::default());
        assert!(p.enabled);
        assert!(p.scan_request);
        assert!(!p.scan_response);
        assert!(!p.enforces());
        assert_eq!(p.entities.len(), PII_ENTITY_TYPES.len());
    }

    #[test]
    fn classifier_url_omitted_when_none() {
        let json = serde_json::to_value(GuardrailSettings::default()).unwrap();
        assert!(json.get("classifier_url").is_none());
    }

    // ── backend / policy split (generic profile model) ──

    #[test]
    fn resolve_defaults_equal_flat_default() {
        // The default backend and the default policy resolve to exactly the
        // default flat settings — the proxy fallback (`guardrail_default`) for a
        // tenant with no stored policy.
        let resolved = GuardrailSettings::resolve(
            &GuardrailBackendSettings::default(),
            &GuardrailPolicy::default(),
        );
        assert_eq!(resolved, GuardrailSettings::default());
    }

    #[test]
    fn resolve_preserves_is_active_and_enforce() {
        let backend = GuardrailBackendSettings {
            classifier_url: Some("http://classifier:8000".to_string()),
            ..Default::default()
        };
        // enabled profile + backend url ⇒ active.
        let on = GuardrailSettings::resolve(&backend, &GuardrailPolicy::default());
        assert!(on.is_active());

        // A profile that opts out stays inert EVEN WITH a backend url present —
        // the one place the split could leak (Review finding #2 / Regression #2).
        let off = GuardrailSettings::resolve(
            &backend,
            &GuardrailPolicy { enabled: false, ..Default::default() },
        );
        assert!(!off.is_active());

        // enforce posture rides the policy.
        let enforce = GuardrailSettings::resolve(
            &backend,
            &GuardrailPolicy { mode: GuardrailMode::Enforce, ..Default::default() },
        );
        assert!(enforce.enforces());
    }

    #[test]
    fn backend_keeps_classifier_fields_drops_policy() {
        let backend = GuardrailBackendSettings {
            classifier_url: Some("http://c:8000".to_string()),
            protocol: ClassifierProtocol::OpenaiModerations,
            positive_label: "malicious".to_string(),
            timeout_ms: 250,
            max_windows: 8,
            max_windows_content: 24,
            spotlight: false,
            notify_on_detection: true,
        };
        let policy = GuardrailPolicy {
            enabled: true,
            mode: GuardrailMode::Enforce,
            scan_inbound: true,
            threshold: 0.42,
            fail_mode: GuardrailFailMode::Closed,
            pii: PiiSettings { scan_response: true, ..Default::default() },
        };
        let r = GuardrailSettings::resolve(&backend, &policy);
        // backend half
        assert_eq!(r.classifier_url.as_deref(), Some("http://c:8000"));
        assert_eq!(r.protocol, ClassifierProtocol::OpenaiModerations);
        assert_eq!(r.positive_label, "malicious");
        assert_eq!(r.timeout_ms, 250);
        assert_eq!(r.max_windows, 8);
        assert_eq!(r.max_windows_content, 24);
        assert!(!r.spotlight);
        assert!(r.notify_on_detection);
        // policy half
        assert!(r.enforces());
        assert!(r.scan_inbound);
        assert_eq!(r.threshold, 0.42);
        assert_eq!(r.fail_mode, GuardrailFailMode::Closed);
        assert!(r.pii.scan_response);
    }

    #[test]
    fn policy_empty_json_yields_defaults() {
        let p: GuardrailPolicy = serde_json::from_str("{}").unwrap();
        assert_eq!(p, GuardrailPolicy::default());
    }

    #[test]
    fn backend_empty_json_yields_defaults() {
        let b: GuardrailBackendSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(b, GuardrailBackendSettings::default());
    }
}

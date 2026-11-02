//! Classifier transport — batch-first detector behind a [`GuardrailDetector`]
//! trait so the classifier extension and any other service swap in without
//! touching call sites.
//!
//! Two standard wire shapes ship today, selected by
//! [`super::ClassifierProtocol`]:
//!
//! - `hf_text_classification` — TEI `/predict`. **Batch is the NESTED array**
//!   `{"inputs":[["a"],["b"]]}` → `[[{label,score}]…]` (one distribution per
//!   input). The flat `{"inputs":["a","b"]}` form is *pair* classification, not
//!   batching — never use it here.
//! - `openai_moderations` — `POST /v1/moderations {input} →
//!   {results:[{flagged,category_scores}]}`.
//!
//! The endpoint is the tenant's `classifier_url`, reached through the shared
//! SSRF guard ([`crate::extension_http`]): an internal address only when the
//! platform's `extensions` egress list lists it, never a redirect. The
//! client is a warm keep-alive pool with `tcp_nodelay` on the small JSON
//! bodies; a plaintext URL speaks HTTP/1.1, an `https` one negotiates over TLS.

use std::pin::Pin;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::settings::{ClassifierProtocol, GuardrailSettings};

/// Approximate per-window byte budget. ~512 tokens at ~4 bytes/token — the
/// DeBERTa context window. A conservative bound for multibyte text (fewer
/// tokens than bytes), which is the safe direction.
const WINDOW_BYTES: usize = 2000;

/// Overlap between adjacent windows so an injection straddling a split boundary
/// still lands wholly inside at least one window.
const WINDOW_OVERLAP_BYTES: usize = 200;

/// Maximum windows sent to the detector in ONE HTTP request. TEI's own
/// `--max-client-batch-size` defaults to 32 and rejects a larger batch outright
/// (HTTP 413), which on a fail-open guardrail would silently leave the whole
/// round unscreened — so [`HttpClassifier::classify_batch`] splits a bigger
/// round into sequential chunks of this size rather than trusting the caller to
/// stay under it. Keep at-or-below the smallest limit of any supported detector.
const MAX_CLIENT_BATCH_WINDOWS: usize = 32;

/// Maximum windows one [`classify_texts`] round may spend across ALL its inputs.
/// A **hard** bound, and load-bearing on two axes: the detector CPU a single
/// request can command, and the worst-case wait — `timeout_ms` is a
/// per-HTTP-request budget, so a round costs at most
/// `ceil(MAX_ROUND_WINDOWS / MAX_CLIENT_BATCH_WINDOWS)` × that budget. Input
/// *count* is caller-influenced (the inbound hop builds one input per folded
/// tool result), so a per-input floor here would let the round — and that
/// worst-case wait — grow without limit; [`allocate_windows`] therefore grants
/// zero windows to the surplus rather than one each. The per-input cap
/// (`max_windows` / `max_windows_content`) applies first, so this only bites on a
/// round whose total demand overruns the budget. Whatever it trims is reported as
/// `fully_scanned == false`, never as a clean scan.
const MAX_ROUND_WINDOWS: usize = 128;

/// Category of a guardrail finding. Append-only — never rename a variant.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailCategory {
    /// Indirect prompt injection in third-party content (the P0 surface).
    PromptInjection,
    /// Direct jailbreak / system-prompt-override attempt.
    Jailbreak,
    /// Personally-identifiable information detected by the in-process PII
    /// detector (the specific entity types ride as data on the trace step's
    /// `entities`, keeping this enum small and the badge aggregation simple).
    Pii,
}

impl GuardrailCategory {
    /// Every variant — the iteration source for category-exhaustive consumers
    /// (e.g. the per-category operator notifications). Adding a variant to the
    /// enum + here is the only place a new category's identity is declared; the
    /// exhaustive `match` in [`Self::badge_str`] forces it to be handled.
    pub const ALL: &'static [GuardrailCategory] = &[
        GuardrailCategory::PromptInjection,
        GuardrailCategory::Jailbreak,
        GuardrailCategory::Pii,
    ];

    /// The canonical wire string for this category — the exact token stored in
    /// an audit badge's `categories` array. Kept in lockstep with the
    /// `#[serde(rename_all = "snake_case")]` form by the `badge_str_matches_serde`
    /// test. Use this anywhere a category is matched as a string (badge-JSON
    /// queries, deep-link filters) instead of re-spelling the literal.
    pub fn badge_str(self) -> &'static str {
        match self {
            GuardrailCategory::PromptInjection => "prompt_injection",
            GuardrailCategory::Jailbreak => "jailbreak",
            GuardrailCategory::Pii => "pii",
        }
    }
}

/// One classifier verdict over one input.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Verdict {
    pub category: GuardrailCategory,
    /// Positive-class confidence in `[0, 1]`.
    pub confidence: f32,
    /// `confidence >= threshold`.
    pub flagged: bool,
}

impl Verdict {
    /// A clean (not-flagged) verdict at zero confidence — the result for an
    /// empty input or a window the detector scored below threshold.
    pub fn clean(category: GuardrailCategory) -> Self {
        Self {
            category,
            confidence: 0.0,
            flagged: false,
        }
    }
}

/// One input's [`classify_texts`] outcome: its folded [`Verdict`] plus whether
/// the verdict actually *covers* the whole input.
///
/// `fully_scanned` is `false` when the input was empty / whitespace-only
/// (nothing was sent to the detector) or its text needed more windows than the
/// round allowed (the tail was dropped — see [`MAX_ROUND_WINDOWS`]). A `clean`
/// verdict with `fully_scanned == false` therefore means **"the scanned portion
/// was clean, but part of the input was never screened"** — not "the whole input
/// is safe". Enforce mode treats such an input as *unscreened* and routes it
/// through the tenant's `fail_mode` (a fail-closed withhold; a visible fail-open
/// pass), closing the inject-past-the-window-cap and empty-extraction evasion
/// gaps. Observe mode mutates nothing, so it cannot withhold — but it reports
/// the same coverage gap as a visible `incomplete_scan` step + badge, so an
/// observe bake never reads a partially-screened input as clean.
#[derive(Debug, Clone, PartialEq)]
pub struct ScanResult {
    pub verdict: Verdict,
    pub fully_scanned: bool,
}

/// Failure of a classifier call. The caller maps this onto the tenant's
/// `fail_mode` (open = pass + badge, closed = block).
#[derive(Debug, thiserror::Error)]
pub enum GuardrailError {
    /// The per-request `timeout_ms` budget elapsed.
    #[error("classifier timed out after {0}ms")]
    Timeout(u64),
    /// Network / connection error reaching the classifier, or a non-2xx
    /// status. Carries a sanitized description (never an upstream body).
    #[error("classifier transport error: {0}")]
    Transport(String),
    /// The classifier responded but its body did not match the expected shape.
    #[error("classifier response parse error: {0}")]
    Parse(String),
    /// The configured `classifier_url` could not be turned into a request URL.
    #[error("invalid classifier url: {0}")]
    InvalidUrl(String),
}

impl GuardrailError {
    /// Short, stable, body-free token for the `GuardrailError` badge `reason`.
    /// The Display strings carry sanitized detail for logs; the badge UI shows
    /// only this token, so it must stay identical across every surface that
    /// emits the badge (substitution fold-back and direct `/mcp/web`).
    pub fn reason_token(&self) -> &'static str {
        match self {
            Self::Timeout(_) => "timeout",
            Self::Transport(_) => "transport",
            Self::Parse(_) => "parse",
            Self::InvalidUrl(_) => "invalid_url",
        }
    }
}

/// Batch-first injection detector. One round of web tool-calls is classified in
/// one `classify_batch` call (TEI dynamic-batches → few forward passes); an
/// implementation may split that into as many HTTP requests as its endpoint's
/// batch limit needs, but the call is one logical round.
/// `classify_batch(&[])` returns `Ok(vec![])`.
///
/// The manual `Pin<Box<dyn Future>>` return keeps the trait object-safe without
/// pulling in `async-trait` — same pattern as
/// [`crate::web::WebAuditForwarderTrait`].
pub trait GuardrailDetector: Send + Sync {
    /// Classify each input independently. The returned vector has the same
    /// length and order as `inputs`; `inputs[i]` ↦ `verdicts[i]`.
    fn classify_batch<'a>(
        &'a self,
        inputs: &'a [&'a str],
    ) -> Pin<
        Box<dyn std::future::Future<Output = Result<Vec<Verdict>, GuardrailError>> + Send + 'a>,
    >;
}

/// Resolved classifier connection config, derived from [`GuardrailSettings`].
#[derive(Debug, Clone)]
pub struct ClassifierConfig {
    pub url: String,
    pub protocol: ClassifierProtocol,
    pub positive_label: String,
    pub threshold: f32,
    pub timeout_ms: u64,
    /// Per-input window cap for prose (inbound prompt, model response).
    pub max_windows: u32,
    /// Per-input window cap for gateway-fetched third-party content (web
    /// results, peer agent replies). Selected per scan surface — see
    /// `GuardrailSurface::window_cap`.
    pub max_windows_content: u32,
}

impl ClassifierConfig {
    /// Build a connection config from tenant settings, or `None` when the
    /// guardrail is inert (disabled / no classifier URL).
    pub fn from_settings(s: &GuardrailSettings) -> Option<Self> {
        if !s.is_active() {
            return None;
        }
        let url = s.classifier_url.as_deref()?.trim().trim_end_matches('/');
        if url.is_empty() {
            return None;
        }
        Some(Self {
            url: url.to_string(),
            protocol: s.protocol,
            positive_label: s.positive_label.clone(),
            threshold: s.threshold,
            timeout_ms: s.timeout_ms,
            max_windows: s.max_windows,
            max_windows_content: s.max_windows_content,
        })
    }
}

/// HTTP-backed detector over a shared reqwest client.
pub struct HttpClassifier {
    client: reqwest::Client,
    cfg: ClassifierConfig,
}

impl HttpClassifier {
    /// Wrap an externally-owned (shared, pooled) client. Preferred on the
    /// proxy hot path so the connection pool is reused across requests.
    pub fn new(client: reqwest::Client, cfg: ClassifierConfig) -> Self {
        Self { client, cfg }
    }

    fn endpoint(&self) -> String {
        match self.cfg.protocol {
            ClassifierProtocol::HfTextClassification => {
                format!("{}/predict", self.cfg.url)
            }
            ClassifierProtocol::OpenaiModerations => {
                format!("{}/v1/moderations", self.cfg.url)
            }
        }
    }

    async fn post_json(
        &self,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, GuardrailError> {
        let url = self.endpoint();
        // `.json()` sets the request body and the `application/json`
        // Content-Type in one call.
        let fut = self.client.post(&url).json(&body).send();
        let resp = tokio::time::timeout(
            Duration::from_millis(self.cfg.timeout_ms.max(1)),
            fut,
        )
        .await
        .map_err(|_| GuardrailError::Timeout(self.cfg.timeout_ms))?
        .map_err(|e| GuardrailError::Transport(sanitize_reqwest(&e)))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(GuardrailError::Transport(format!(
                "classifier returned HTTP {}",
                status.as_u16()
            )));
        }
        // Classifier verdicts are tiny JSON; cap the read so a hostile/misbehaving
        // classifier can't OOM the shared edge (the request timeout bounds latency,
        // not size).
        const CLASSIFIER_MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
        let body_fut = async {
            let bytes = crate::http_body::read_body_capped(resp, CLASSIFIER_MAX_RESPONSE_BYTES)
                .await
                .map_err(|e| match e {
                    crate::http_body::CappedReadError::Oversized { limit_bytes } => {
                        GuardrailError::Transport(format!(
                            "classifier response exceeds {limit_bytes} bytes"
                        ))
                    }
                    crate::http_body::CappedReadError::Transport(e) => {
                        GuardrailError::Transport(sanitize_reqwest(&e))
                    }
                })?;
            serde_json::from_slice::<serde_json::Value>(&bytes)
                .map_err(|e| GuardrailError::Parse(e.to_string()))
        };
        tokio::time::timeout(Duration::from_millis(self.cfg.timeout_ms.max(1)), body_fut)
            .await
            .map_err(|_| GuardrailError::Timeout(self.cfg.timeout_ms))?
    }

    fn parse_hf(&self, value: &serde_json::Value) -> Result<Vec<Verdict>, GuardrailError> {
        // `[[{label,score}]…]` — one distribution per input.
        let rows = value.as_array().ok_or_else(|| {
            GuardrailError::Parse("expected a JSON array of distributions".to_string())
        })?;
        rows.iter()
            .map(|dist| {
                let entries = dist.as_array().ok_or_else(|| {
                    GuardrailError::Parse(
                        "expected each input's distribution to be an array".to_string(),
                    )
                })?;
                // Score of the configured positive label; absent label = 0.
                let confidence = entries
                    .iter()
                    .find(|e| {
                        e.get("label").and_then(|l| l.as_str())
                            == Some(self.cfg.positive_label.as_str())
                    })
                    .and_then(|e| e.get("score").and_then(serde_json::Value::as_f64))
                    .unwrap_or(0.0) as f32;
                Ok(self.verdict(GuardrailCategory::PromptInjection, confidence))
            })
            .collect()
    }

    fn parse_moderations(
        &self,
        value: &serde_json::Value,
        expected: usize,
    ) -> Result<Vec<Verdict>, GuardrailError> {
        // `{results:[{flagged,category_scores}]}`.
        let results = value
            .get("results")
            .and_then(|r| r.as_array())
            .ok_or_else(|| {
                GuardrailError::Parse("expected a `results` array".to_string())
            })?;
        if results.len() != expected {
            return Err(GuardrailError::Parse(format!(
                "moderations returned {} results for {} inputs",
                results.len(),
                expected
            )));
        }
        Ok(results
            .iter()
            .map(|r| {
                let flagged = r.get("flagged").and_then(|f| f.as_bool()).unwrap_or(false);
                // Confidence = the highest category score; fall back to a hard
                // 1.0 when the endpoint flags without numeric scores.
                let max_score = r
                    .get("category_scores")
                    .and_then(|s| s.as_object())
                    .map(|m| {
                        m.values()
                            .filter_map(serde_json::Value::as_f64)
                            .fold(0.0_f64, f64::max)
                    })
                    .unwrap_or(0.0) as f32;
                let confidence = if flagged && max_score == 0.0 { 1.0 } else { max_score };
                // Flag when the endpoint says so OR the score clears our
                // threshold — the endpoint's own `flagged=true` wins even when
                // its score is below `threshold`.
                Verdict {
                    category: GuardrailCategory::PromptInjection,
                    confidence,
                    flagged: flagged || confidence >= self.cfg.threshold,
                }
            })
            .collect())
    }

    /// One detector round-trip over a batch the endpoint is known to accept
    /// (≤ [`MAX_CLIENT_BATCH_WINDOWS`]). Callers go through
    /// [`GuardrailDetector::classify_batch`], which does the chunking.
    async fn classify_one_batch(
        &self,
        inputs: &[&str],
    ) -> Result<Vec<Verdict>, GuardrailError> {
        match self.cfg.protocol {
            ClassifierProtocol::HfTextClassification => {
                // Nested array — the batch form. Flat is pair-classification.
                let nested: Vec<[&str; 1]> = inputs.iter().map(|s| [*s]).collect();
                let v = self
                    .post_json(serde_json::json!({ "inputs": nested }))
                    .await?;
                self.parse_hf(&v)
            }
            ClassifierProtocol::OpenaiModerations => {
                let v = self.post_json(serde_json::json!({ "input": inputs })).await?;
                self.parse_moderations(&v, inputs.len())
            }
        }
    }

    fn verdict(&self, category: GuardrailCategory, confidence: f32) -> Verdict {
        Verdict {
            category,
            confidence,
            flagged: confidence >= self.cfg.threshold,
        }
    }
}

impl GuardrailDetector for HttpClassifier {
    fn classify_batch<'a>(
        &'a self,
        inputs: &'a [&'a str],
    ) -> Pin<
        Box<dyn std::future::Future<Output = Result<Vec<Verdict>, GuardrailError>> + Send + 'a>,
    > {
        Box::pin(async move {
            if inputs.is_empty() {
                return Ok(Vec::new());
            }
            // Detectors cap how many inputs one request may carry (TEI's
            // `--max-client-batch-size`, default 32) and reject an oversized
            // batch wholesale, so split into chunks the smallest supported limit
            // accepts. Sequential: the detector dynamic-batches internally, so
            // parallel POSTs would only queue behind the same forward passes
            // while multiplying its peak memory. Each chunk carries the full
            // `timeout_ms` budget — the round total is bounded by the window
            // ceiling in `classify_texts`.
            let mut out = Vec::with_capacity(inputs.len());
            for chunk in inputs.chunks(MAX_CLIENT_BATCH_WINDOWS) {
                let verdicts = self.classify_one_batch(chunk).await?;
                if verdicts.len() != chunk.len() {
                    return Err(GuardrailError::Parse(format!(
                        "classifier returned {} verdicts for {} inputs",
                        verdicts.len(),
                        chunk.len()
                    )));
                }
                out.extend(verdicts);
            }
            Ok(out)
        })
    }
}

/// Split `text` into at most `max_windows` bounded, overlapping windows along
/// UTF-8 boundaries, returning `(windows, truncated)`. `truncated` is `true`
/// when the text was long enough to need more than `max_windows` windows — its
/// tail was dropped (and logged), so the windows do **not** cover the whole
/// input. An empty input yields no windows and `truncated = false`.
fn window_split(text: &str, max_windows: u32) -> (Vec<&str>, bool) {
    let max = max_windows.max(1) as usize;
    if text.is_empty() {
        return (Vec::new(), false);
    }
    if text.len() <= WINDOW_BYTES {
        return (vec![text], false);
    }
    let n = text.len();
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut truncated = false;
    loop {
        if start >= n {
            break;
        }
        if out.len() >= max {
            truncated = true;
            break;
        }
        let start_b = text.floor_char_boundary(start);
        // `WINDOW_BYTES` (2000) dwarfs the 4-byte max UTF-8 char, so the floored
        // end is always strictly past `start_b` — forward progress is assured.
        let end_b = text.floor_char_boundary((start_b + WINDOW_BYTES).min(n));
        out.push(&text[start_b..end_b]);
        if end_b >= n {
            break;
        }
        start = end_b.saturating_sub(WINDOW_OVERLAP_BYTES).max(start_b + 1);
    }
    if truncated {
        tracing::warn!(
            text_bytes = n,
            window_cap = max,
            "guardrail input exceeded its window cap — tail not classified"
        );
    }
    (out, truncated)
}

/// Split `text` into at most `max_windows` bounded, overlapping windows along
/// UTF-8 boundaries. Short text → a single window (or none, when empty). When
/// the text is long enough to exceed `max_windows`, the tail is dropped and the
/// truncation is logged (never silently capped) — use [`classify_texts`]'s
/// per-input `fully_scanned` flag when the *coverage* matters.
pub fn windows(text: &str, max_windows: u32) -> Vec<&str> {
    window_split(text, max_windows).0
}

/// Share `budget` windows across per-input `demands` (0 = nothing to scan),
/// max-min fair: every input is funded in full if the round fits, and otherwise
/// no input gets its Nth window before every other input has its (N-1)th. So a
/// long page can't starve the short results beside it, a short one can't force a
/// long one to truncate while the budget still has room, and the whole budget is
/// spent. Returns each input's granted window count; `Σ grants ≤ budget` always
/// — with more inputs than budget, the surplus is granted zero (the caller
/// reports those as unscreened, never as scanned-clean).
fn allocate_windows(demands: &[usize], budget: usize) -> Vec<usize> {
    let mut grants = vec![0usize; demands.len()];
    let mut left = budget;
    // One window per pass per unsatisfied input. Bounded work: the outer loop
    // can only run while it hands out a window, and it hands out at most
    // `budget` (≤ MAX_ROUND_WINDOWS) of them.
    let mut granted_this_pass = true;
    while left > 0 && granted_this_pass {
        granted_this_pass = false;
        for (grant, demand) in grants.iter_mut().zip(demands) {
            if left == 0 {
                break;
            }
            if *grant < *demand {
                *grant += 1;
                left -= 1;
                granted_this_pass = true;
            }
        }
    }
    grants
}

/// Fold per-window verdicts into a single verdict for the original input:
/// max confidence, flagged if any window flagged, category from the
/// highest-confidence window.
fn fold_windows(verdicts: &[Verdict]) -> Verdict {
    verdicts
        .iter()
        .fold(Verdict::clean(GuardrailCategory::PromptInjection), |acc, v| {
            let category = if v.confidence > acc.confidence { v.category } else { acc.category };
            Verdict {
                category,
                confidence: acc.confidence.max(v.confidence),
                flagged: acc.flagged || v.flagged,
            }
        })
}

/// Classify each text with windowing: split long texts into bounded windows,
/// flatten **all** windows across **all** texts into one `classify_batch`
/// round, then fold the per-window verdicts back to one verdict per text.
/// Empty / whitespace-only texts short-circuit to a clean verdict with no model
/// call. The returned vector aligns 1:1 with `texts`; each [`ScanResult`] also
/// carries whether that input was *fully* scanned (see the type docs — empty or
/// truncated inputs are `fully_scanned == false`).
///
/// `max_windows` is the per-input cap the *surface* asked for; the round's total
/// is additionally bounded by [`MAX_ROUND_WINDOWS`], allocated by
/// [`allocate_windows`] — every input that fits is funded in full, and only a
/// round that genuinely overruns the budget is trimmed. The bound is hard: a
/// round with more inputs than the budget has windows leaves the surplus with
/// zero windows, reported as unscreened rather than quietly scanned in part.
/// [`classify_texts`] over the process-wide guarded client pair
/// ([`crate::extension_http::classifier_clients`]) — the shape every production
/// surface wants. Folding the client build and the SSRF refusal into the same
/// `Result` keeps both on the tenant's `fail_mode` path (open = pass + badge,
/// closed = block): a caller matching on this cannot handle a scan failure
/// while letting a client failure or a refused endpoint through unscanned.
pub async fn classify_with_shared_client(
    cfg: ClassifierConfig,
    texts: &[&str],
    max_windows: u32,
) -> Result<Vec<ScanResult>, GuardrailError> {
    let clients =
        crate::extension_http::classifier_clients().map_err(GuardrailError::Transport)?;
    let client = clients.for_endpoint(&cfg.url).map_err(|e| {
        GuardrailError::Transport(format!("endpoint refused by the SSRF guard: {e}"))
    })?;
    let endpoint = url::Url::parse(&cfg.url).ok();
    let detector = HttpClassifier::new(client, cfg);
    classify_texts(&detector, texts, max_windows).await.map_err(|e| {
        // A refusal by the guard inside the resolver reaches `post_json` as a
        // generic connect error; name it.
        match (&e, endpoint.as_ref().and_then(|u| clients.take_refusal(u))) {
            (GuardrailError::Transport(_), Some(refusal)) => GuardrailError::Transport(format!(
                "endpoint refused by the SSRF guard: {refusal}"
            )),
            _ => e,
        }
    })
}

pub async fn classify_texts(
    detector: &dyn GuardrailDetector,
    texts: &[&str],
    max_windows: u32,
) -> Result<Vec<ScanResult>, GuardrailError> {
    // Split every scannable input at its surface cap. `None` = nothing to send the
    // detector (empty / whitespace-only) — unscreened, not "safe".
    let mut split: Vec<Option<(Vec<&str>, bool)>> = texts
        .iter()
        .map(|t| (!t.trim().is_empty()).then(|| window_split(t, max_windows)))
        .collect();

    // Trim to the round budget only when the round actually overruns it. Windows
    // are prefix-deterministic (window N's bounds don't depend on the cap), so
    // truncating the split IS the same as re-splitting at the smaller grant.
    let demands: Vec<usize> = split
        .iter()
        .map(|e| e.as_ref().map_or(0, |(w, _)| w.len()))
        .collect();
    if demands.iter().sum::<usize>() > MAX_ROUND_WINDOWS {
        let grants = allocate_windows(&demands, MAX_ROUND_WINDOWS);
        for (entry, grant) in split.iter_mut().zip(&grants) {
            if let Some((w, truncated)) = entry
                && *grant < w.len()
            {
                w.truncate(*grant);
                *truncated = true;
            }
        }
    }

    // Flatten, remembering each input's window span (to re-fold after the batch
    // call) and whether the windows covered it.
    let mut flat: Vec<&str> = Vec::new();
    let mut spans: Vec<std::ops::Range<usize>> = Vec::with_capacity(texts.len());
    let mut fully: Vec<bool> = Vec::with_capacity(texts.len());
    for entry in &split {
        let start = flat.len();
        let scanned = match entry {
            None => false,
            Some((w, truncated)) => {
                flat.extend(w.iter().copied());
                !*truncated
            }
        };
        fully.push(scanned);
        spans.push(start..flat.len());
    }

    if flat.is_empty() {
        return Ok(fully
            .into_iter()
            .map(|fully_scanned| ScanResult {
                verdict: Verdict::clean(GuardrailCategory::PromptInjection),
                fully_scanned,
            })
            .collect());
    }

    let verdicts = detector.classify_batch(&flat).await?;
    if verdicts.len() != flat.len() {
        return Err(GuardrailError::Parse(format!(
            "detector returned {} verdicts for {} windows",
            verdicts.len(),
            flat.len()
        )));
    }

    Ok(spans
        .into_iter()
        .zip(fully)
        .map(|(range, fully_scanned)| {
            let verdict = if range.is_empty() {
                Verdict::clean(GuardrailCategory::PromptInjection)
            } else {
                fold_windows(&verdicts[range])
            };
            ScanResult {
                verdict,
                fully_scanned,
            }
        })
        .collect())
}

/// Reduce a reqwest error to a short, body-free description safe to surface in
/// a `GuardrailError`.
fn sanitize_reqwest(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "timeout".to_string()
    } else if e.is_connect() {
        "connection failed".to_string()
    } else if e.is_decode() {
        "decode error".to_string()
    } else {
        "request failed".to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    /// An unguarded client for the in-process mock listeners below, which bind
    /// loopback — the production path goes through the SSRF guard instead.
    fn build_tuned_client() -> Result<reqwest::Client, reqwest::Error> {
        reqwest::Client::builder().tcp_nodelay(true).build()
    }

    #[test]
    fn badge_str_matches_serde_for_every_category() {
        // Drift guard: `badge_str` is matched against the serialized badge JSON
        // (e.g. in the operator-notification queries), so it MUST equal the
        // serde `snake_case` form. A new variant without a `badge_str` arm fails
        // to compile; a renamed serialization fails here.
        for &c in GuardrailCategory::ALL {
            assert_eq!(
                serde_json::to_value(c).unwrap(),
                serde_json::Value::String(c.badge_str().to_string()),
            );
        }
    }

    /// Deterministic in-memory detector: flags any window containing the
    /// substring `IGNORE`, scoring it `0.95`; everything else `0.10`.
    struct MockDetector {
        threshold: f32,
    }

    impl GuardrailDetector for MockDetector {
        fn classify_batch<'a>(
            &'a self,
            inputs: &'a [&'a str],
        ) -> Pin<
            Box<dyn std::future::Future<Output = Result<Vec<Verdict>, GuardrailError>> + Send + 'a>,
        > {
            Box::pin(async move {
                Ok(inputs
                    .iter()
                    .map(|s| {
                        let confidence = if s.contains("IGNORE") { 0.95 } else { 0.10 };
                        Verdict {
                            category: GuardrailCategory::PromptInjection,
                            confidence,
                            flagged: confidence >= self.threshold,
                        }
                    })
                    .collect())
            })
        }
    }

    fn cfg() -> ClassifierConfig {
        ClassifierConfig {
            url: "http://c:8000".to_string(),
            protocol: ClassifierProtocol::HfTextClassification,
            positive_label: "INJECTION".to_string(),
            threshold: 0.9,
            timeout_ms: 500,
            max_windows: 4,
            max_windows_content: 16,
        }
    }

    #[test]
    fn config_from_inert_settings_is_none() {
        assert!(ClassifierConfig::from_settings(&GuardrailSettings::default()).is_none());
    }

    #[test]
    fn reason_token_is_stable_per_variant() {
        // The badge UI renders this token verbatim and it must stay identical
        // across every surface that emits the badge — pin each variant's string
        // (append-only contract, like the AuditBadge codes).
        assert_eq!(GuardrailError::Timeout(10).reason_token(), "timeout");
        assert_eq!(GuardrailError::Transport("x".into()).reason_token(), "transport");
        assert_eq!(GuardrailError::Parse("x".into()).reason_token(), "parse");
        assert_eq!(GuardrailError::InvalidUrl("x".into()).reason_token(), "invalid_url");
    }

    #[test]
    fn config_strips_trailing_slash() {
        let s = GuardrailSettings {
            enabled: true,
            classifier_url: Some("http://c:8000/".to_string()),
            ..Default::default()
        };
        let c = ClassifierConfig::from_settings(&s).unwrap();
        assert_eq!(c.url, "http://c:8000");
    }

    #[test]
    fn hf_endpoint_path() {
        let c = HttpClassifier::new(build_tuned_client().unwrap(), cfg());
        assert_eq!(c.endpoint(), "http://c:8000/predict");
    }

    #[test]
    fn moderations_endpoint_path() {
        let mut config = cfg();
        config.protocol = ClassifierProtocol::OpenaiModerations;
        let c = HttpClassifier::new(build_tuned_client().unwrap(), config);
        assert_eq!(c.endpoint(), "http://c:8000/v1/moderations");
    }

    #[test]
    fn parse_hf_takes_positive_label_score() {
        let c = HttpClassifier::new(build_tuned_client().unwrap(), cfg());
        let body = serde_json::json!([
            [{"label": "INJECTION", "score": 0.97}, {"label": "SAFE", "score": 0.03}],
            [{"label": "INJECTION", "score": 0.20}, {"label": "SAFE", "score": 0.80}],
        ]);
        let v = c.parse_hf(&body).unwrap();
        assert_eq!(v.len(), 2);
        assert!((v[0].confidence - 0.97).abs() < 1e-5);
        assert!(v[0].flagged);
        assert!((v[1].confidence - 0.20).abs() < 1e-5);
        assert!(!v[1].flagged);
    }

    #[test]
    fn parse_hf_absent_label_scores_zero() {
        let c = HttpClassifier::new(build_tuned_client().unwrap(), cfg());
        let body = serde_json::json!([[{"label": "SAFE", "score": 0.80}]]);
        let v = c.parse_hf(&body).unwrap();
        assert_eq!(v[0].confidence, 0.0);
        assert!(!v[0].flagged);
    }

    #[test]
    fn parse_hf_rejects_non_array() {
        let c = HttpClassifier::new(build_tuned_client().unwrap(), cfg());
        assert!(c.parse_hf(&serde_json::json!({"oops": true})).is_err());
    }

    #[test]
    fn parse_moderations_uses_flagged_and_max_score() {
        let mut config = cfg();
        config.protocol = ClassifierProtocol::OpenaiModerations;
        let c = HttpClassifier::new(build_tuned_client().unwrap(), config);
        let body = serde_json::json!({
            "results": [
                {"flagged": true, "category_scores": {"harassment": 0.1, "violence": 0.88}},
                {"flagged": false, "category_scores": {"harassment": 0.01}},
            ]
        });
        let v = c.parse_moderations(&body, 2).unwrap();
        assert!(v[0].flagged);
        assert!((v[0].confidence - 0.88).abs() < 1e-5);
        assert!(!v[1].flagged);
    }

    #[test]
    fn parse_moderations_length_mismatch_errors() {
        let mut config = cfg();
        config.protocol = ClassifierProtocol::OpenaiModerations;
        let c = HttpClassifier::new(build_tuned_client().unwrap(), config);
        let body = serde_json::json!({ "results": [{"flagged": false}] });
        assert!(c.parse_moderations(&body, 2).is_err());
    }

    #[test]
    fn windows_short_text_single_window() {
        assert_eq!(windows("hello", 4), vec!["hello"]);
    }

    #[test]
    fn windows_empty_text_no_windows() {
        assert!(windows("", 4).is_empty());
    }

    #[test]
    fn windows_long_text_splits_with_overlap_and_covers() {
        let text = "a".repeat(WINDOW_BYTES * 3);
        let w = windows(&text, 16);
        assert!(w.len() >= 3);
        // Reassembled (de-overlapped) coverage reaches the end.
        assert!(w.last().unwrap().ends_with('a'));
        // Every window respects the byte budget.
        assert!(w.iter().all(|s| s.len() <= WINDOW_BYTES));
    }

    #[test]
    fn windows_caps_at_max_windows() {
        let text = "a".repeat(WINDOW_BYTES * 10);
        let w = windows(&text, 2);
        assert_eq!(w.len(), 2);
    }

    #[test]
    fn windows_utf8_safe_on_multibyte() {
        let text = "é".repeat(WINDOW_BYTES); // 2 bytes each → > budget
        let w = windows(&text, 8);
        // Every window must be valid UTF-8 (slicing on boundaries) — the fact
        // that we got `&str`s back already proves it; assert non-empty.
        assert!(!w.is_empty());
        assert!(w.iter().all(|s| !s.is_empty()));
    }

    #[tokio::test]
    async fn classify_texts_flags_injection_and_folds_windows() {
        let d = MockDetector { threshold: 0.9 };
        let long_injection =
            format!("{}IGNORE ALL{}", "x".repeat(WINDOW_BYTES), "y".repeat(WINDOW_BYTES));
        let texts = vec!["benign text", long_injection.as_str(), "also clean"];
        let v = classify_texts(&d, &texts, 8).await.unwrap();
        assert_eq!(v.len(), 3);
        assert!(!v[0].verdict.flagged);
        assert!(v[0].fully_scanned, "short clean text is fully scanned");
        assert!(v[1].verdict.flagged, "windowed injection must fold to flagged");
        assert!((v[1].verdict.confidence - 0.95).abs() < 1e-5);
        assert!(v[1].fully_scanned, "8 windows cover the 2-window injection");
        assert!(!v[2].verdict.flagged);
    }

    #[tokio::test]
    async fn classify_texts_truncated_input_is_not_fully_scanned() {
        let d = MockDetector { threshold: 0.9 };
        // 10 windows' worth of text but a cap of 2 → tail dropped.
        let long = "z".repeat(WINDOW_BYTES * 10);
        let v = classify_texts(&d, &[long.as_str()], 2).await.unwrap();
        assert_eq!(v.len(), 1);
        assert!(!v[0].fully_scanned, "truncated input must report partial coverage");
    }

    #[tokio::test]
    async fn classify_texts_skips_empty_without_model_call() {
        let d = MockDetector { threshold: 0.9 };
        let texts = vec!["", "   "];
        let v = classify_texts(&d, &texts, 8).await.unwrap();
        assert_eq!(v.len(), 2);
        assert!(v.iter().all(|x| !x.verdict.flagged && x.verdict.confidence == 0.0));
        // Empty inputs were never sent to the detector → unscreened, not "safe".
        assert!(v.iter().all(|x| !x.fully_scanned));
    }

    #[tokio::test]
    async fn classify_texts_empty_input_is_empty_output() {
        let d = MockDetector { threshold: 0.9 };
        let v = classify_texts(&d, &[], 8).await.unwrap();
        assert!(v.is_empty());
    }

    /// Detector that records the size of every batch it was handed, so the
    /// round-budget and transport-chunking contracts are assertable.
    #[derive(Default)]
    struct CountingDetector {
        batches: std::sync::Mutex<Vec<usize>>,
    }

    impl CountingDetector {
        fn batches(&self) -> Vec<usize> {
            self.batches.lock().expect("batch log poisoned").clone()
        }

        fn total_windows(&self) -> usize {
            self.batches().iter().sum()
        }
    }

    impl GuardrailDetector for CountingDetector {
        fn classify_batch<'a>(
            &'a self,
            inputs: &'a [&'a str],
        ) -> Pin<
            Box<dyn std::future::Future<Output = Result<Vec<Verdict>, GuardrailError>> + Send + 'a>,
        > {
            Box::pin(async move {
                self.batches.lock().expect("batch log poisoned").push(inputs.len());
                Ok(vec![Verdict::clean(GuardrailCategory::PromptInjection); inputs.len()])
            })
        }
    }

    #[tokio::test]
    async fn classify_texts_bounds_total_windows_per_round() {
        // Many big inputs each asking for the full content cap: the round budget
        // must hold, and the trimming must be reported rather than hidden.
        let d = CountingDetector::default();
        let long = "z".repeat(WINDOW_BYTES * 40);
        let texts: Vec<&str> = std::iter::repeat_n(long.as_str(), 20).collect();
        let v = classify_texts(&d, &texts, 16).await.unwrap();
        assert_eq!(v.len(), 20);
        assert!(
            d.total_windows() <= MAX_ROUND_WINDOWS,
            "round sent {} windows, ceiling is {MAX_ROUND_WINDOWS}",
            d.total_windows()
        );
        assert!(
            v.iter().all(|r| !r.fully_scanned),
            "every trimmed input must report partial coverage"
        );
    }

    #[tokio::test]
    async fn classify_texts_spends_the_whole_budget_when_it_overruns() {
        // 20 oversized inputs: the budget is shared, and all of it is used —
        // leaving windows unspent would truncate content the round could cover.
        let d = CountingDetector::default();
        let long = "z".repeat(WINDOW_BYTES * 40);
        let texts: Vec<&str> = std::iter::repeat_n(long.as_str(), 20).collect();
        classify_texts(&d, &texts, 16).await.unwrap();
        assert_eq!(d.total_windows(), MAX_ROUND_WINDOWS);
    }

    #[tokio::test]
    async fn classify_texts_ceiling_holds_with_more_inputs_than_budget() {
        // The adversarial shape: input COUNT is caller-controlled (the inbound hop
        // builds one input per folded tool result). A per-input floor of one window
        // would make the round grow with the input count — unbounded detector CPU
        // and up to N/32 sequential POSTs on the request path.
        let d = CountingDetector::default();
        let n = MAX_ROUND_WINDOWS * 4;
        let texts: Vec<&str> = std::iter::repeat_n("short but scannable", n).collect();
        let v = classify_texts(&d, &texts, 4).await.unwrap();
        assert_eq!(v.len(), n);
        assert_eq!(d.total_windows(), MAX_ROUND_WINDOWS, "the ceiling must be hard");
        // The surplus was granted nothing, so it must read as unscreened.
        let unscreened = v.iter().filter(|r| !r.fully_scanned).count();
        assert_eq!(unscreened, n - MAX_ROUND_WINDOWS);
    }

    #[tokio::test]
    async fn classify_texts_leaves_the_per_input_cap_alone_when_the_round_fits() {
        // Few inputs ⇒ the surface's cap is what applies, untouched by the ceiling.
        let d = CountingDetector::default();
        let long = "z".repeat(WINDOW_BYTES * 40);
        classify_texts(&d, &[long.as_str(), long.as_str()], 16).await.unwrap();
        assert_eq!(d.total_windows(), 32);
    }

    #[tokio::test]
    async fn classify_texts_small_inputs_do_not_shrink_a_large_one() {
        // A realistic substitution round: nine one-window snippets beside a long
        // article. Sharing the budget by input COUNT would hand the article 12
        // windows (128/10) instead of its full 16-window cap — cutting coverage
        // with >100 windows of the round budget left unused.
        let d = CountingDetector::default();
        let article = "z".repeat(WINDOW_BYTES * 40);
        let mut texts: Vec<&str> = std::iter::repeat_n("a short snippet", 9).collect();
        texts.push(article.as_str());
        let v = classify_texts(&d, &texts, 16).await.unwrap();
        assert!(v[..9].iter().all(|r| r.fully_scanned), "snippets fit trivially");
        assert_eq!(d.total_windows(), 9 + 16, "the article keeps its whole cap");
    }

    #[test]
    fn allocate_windows_funds_every_input_when_the_round_fits() {
        assert_eq!(allocate_windows(&[3, 1, 0, 8], 128), vec![3, 1, 0, 8]);
    }

    #[test]
    fn allocate_windows_is_max_min_fair() {
        // The greedy input takes only what the others left.
        assert_eq!(allocate_windows(&[1, 1, 1, 100], 10), vec![1, 1, 1, 7]);
        // Equal demand ⇒ equal grant, remainder to the earliest (deterministic).
        assert_eq!(allocate_windows(&[5, 5, 5], 10), vec![4, 3, 3]);
    }

    #[test]
    fn allocate_windows_never_exceeds_the_budget() {
        let demands = vec![1; 200];
        let grants = allocate_windows(&demands, MAX_ROUND_WINDOWS);
        assert_eq!(grants.iter().sum::<usize>(), MAX_ROUND_WINDOWS);
        assert_eq!(grants.iter().filter(|g| **g == 0).count(), 200 - MAX_ROUND_WINDOWS);
    }

    #[test]
    fn allocate_windows_zero_budget_grants_nothing() {
        assert_eq!(allocate_windows(&[4, 4], 0), vec![0, 0]);
    }

    /// Minimal `hf_text_classification` endpoint that records each request's
    /// batch size and answers with one SAFE distribution per input. Returns
    /// (base url, recorded batch sizes).
    async fn spawn_recording_classifier() -> (String, Arc<std::sync::Mutex<Vec<usize>>>) {
        use axum::routing::post;

        let seen: Arc<std::sync::Mutex<Vec<usize>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = seen.clone();
        let app = axum::Router::new().route(
            "/predict",
            post(move |body: axum::Json<serde_json::Value>| {
                let log = log.clone();
                async move {
                    let n = body
                        .0
                        .get("inputs")
                        .and_then(|v| v.as_array())
                        .map(Vec::len)
                        .unwrap_or(0);
                    log.lock().expect("batch log poisoned").push(n);
                    let dist = serde_json::json!([{"label": "SAFE", "score": 0.99}]);
                    axum::Json(serde_json::Value::Array(vec![dist; n]))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test classifier");
        let addr = listener.local_addr().expect("test classifier addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{addr}"), seen)
    }

    #[tokio::test]
    async fn http_classifier_chunks_oversized_batches() {
        // A detector rejects a batch above its client-batch limit outright (TEI
        // answers HTTP 413), so a round wider than the limit must be split — else
        // a fail-open guardrail silently leaves the whole round unscreened.
        let (url, seen) = spawn_recording_classifier().await;
        let mut config = cfg();
        config.url = url;
        let c = HttpClassifier::new(build_tuned_client().unwrap(), config);

        let inputs: Vec<&str> = std::iter::repeat_n("clean text", MAX_CLIENT_BATCH_WINDOWS + 8)
            .collect();
        let v = c.classify_batch(&inputs).await.expect("chunked round succeeds");

        assert_eq!(v.len(), inputs.len(), "one verdict per input, in order");
        assert_eq!(
            *seen.lock().expect("batch log poisoned"),
            vec![MAX_CLIENT_BATCH_WINDOWS, 8],
            "split into full chunks plus the remainder"
        );
    }

    #[tokio::test]
    async fn http_classifier_sends_one_request_within_the_limit() {
        let (url, seen) = spawn_recording_classifier().await;
        let mut config = cfg();
        config.url = url;
        let c = HttpClassifier::new(build_tuned_client().unwrap(), config);

        let inputs: Vec<&str> = std::iter::repeat_n("clean text", 5).collect();
        let v = c.classify_batch(&inputs).await.expect("single round succeeds");
        assert_eq!(v.len(), 5);
        assert_eq!(*seen.lock().expect("batch log poisoned"), vec![5]);
    }
}

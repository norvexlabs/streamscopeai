//! In-process PII detection + redaction kernel.
//!
//! A pure-Rust, synchronous detector that runs the two-stage recognizer table
//! ([`super::pii_recognizers`]) over text and returns precise findings. Unlike
//! the injection [`classifier`](super::classifier) (binary, async, windowed,
//! no spans), this is sub-millisecond, span-precise, and never leaves the
//! process — the high-value DLP entities (SSN, card, email, IBAN, …) are pure
//! regex + checksum.
//!
//! Flow: the combined Stage-1 [`RegexSet`](regex::RegexSet) gate skips the whole
//! no-PII case for free; on a hit each candidate runs its Stage-2 processor
//! (native validator or AST-cached Rhai script), a context boost, the threshold,
//! and overlap resolution. [`redact`] masks findings in place
//! (`[REDACTED:US_SSN]`), splicing right-to-left so byte offsets stay stable.
//!
//! Offsets: regex yields **byte** offsets; [`PiiFinding`] exposes **char**
//! offsets (the audit/UI contract). [`redact`] re-derives byte positions from
//! char offsets so a multibyte message redacts to valid UTF-8.

use std::collections::HashMap;

use crate::audit::badge::{AuditBadge, GuardrailAction};
use crate::guardrail::settings::PiiSettings;
use crate::guardrail::{GuardrailCategory, GuardrailInput, GuardrailSurface};
use crate::proxy::content::{GuardrailStepDiff, GuardrailStepOutcome};

use super::pii_recognizers::{engine, Processor};

/// Bytes of surrounding text scanned on each side of a candidate for context
/// words (boosts pattern-only/native scores; read by script processors).
const CONTEXT_WINDOW_BYTES: usize = 48;

/// Score added when a recognizer's context word appears near a candidate.
const CONTEXT_BOOST: f32 = 0.4;

/// One detected PII span. Offsets are **char** indices into the scanned text
/// (not bytes) so the audit trail and UI render correctly over multibyte input.
#[derive(Debug, Clone, PartialEq)]
pub struct PiiFinding {
    pub entity_type: &'static str,
    pub start: usize,
    pub end: usize,
    pub score: f32,
}

/// Detect PII spans in `text`. Returns char-offset findings, overlap-resolved
/// (higher score wins, then longer span), sorted by position. Empty when the
/// detector is disabled, the entity allowlist excludes everything, or nothing
/// clears the threshold.
pub fn detect_pii(text: &str, settings: &PiiSettings) -> Vec<PiiFinding> {
    if !settings.enabled {
        return Vec::new();
    }
    let eng = engine();
    if text.is_empty() || eng.set.is_empty() {
        return Vec::new();
    }
    let matched: Vec<usize> = eng.set.matches(text).into_iter().collect();
    if matched.is_empty() {
        return Vec::new();
    }

    // Created lazily — only when a script processor is actually reached, so the
    // common native/pattern-only path pays nothing.
    let mut script_engine: Option<rhai::Engine> = None;
    // (byte_start, byte_end, entity, score)
    let mut raw: Vec<(usize, usize, &'static str, f32)> = Vec::new();

    for set_idx in matched {
        let (ri, pi) = eng.set_map[set_idx];
        let rec = &eng.recognizers[ri];
        if !settings.entities.iter().any(|e| e == &rec.entity_type) {
            continue;
        }
        let entity: &'static str = rec.entity_type.as_str();
        let pat = &rec.patterns[pi];
        for m in pat.regex.find_iter(text) {
            let candidate = &text[m.start()..m.end()];
            let context = surrounding(text, m.start(), m.end());
            let context_lc = context.to_lowercase();
            let (accept, base) = match &rec.processor {
                Processor::None => (true, pat.score),
                Processor::Native(validate) => (validate(candidate), pat.score),
                Processor::Script(ast) => {
                    let engine_ref =
                        script_engine.get_or_insert_with(crate::scripting::engine::create_engine);
                    run_script(engine_ref, ast.as_ref(), candidate, &context, pat.score)
                }
            };
            if !accept {
                continue;
            }
            // A script owns its own score (it already weighed the context); the
            // ±N context boost applies only to pattern-only / native findings.
            let mut score = base;
            if !matches!(rec.processor, Processor::Script(_))
                && has_context(&context_lc, &rec.context)
            {
                score = (score + CONTEXT_BOOST).min(1.0);
            }
            if score < settings.threshold {
                continue;
            }
            raw.push((m.start(), m.end(), entity, score));
        }
    }

    resolve_overlaps(raw, text)
}

/// Drop findings whose char span overlaps any of `byte_spans` (byte ranges
/// over the SAME `text` that produced the findings). Used to exclude PII inside
/// framework-injected volatile blocks (e.g. Claude Code's `<system-reminder>`)
/// from an inbound user-message scan — the user did not author that context, so
/// it must not be flagged or masked as their data leaving the tenant. Offsets
/// stay in the original-text coordinate system, so the surviving findings still
/// redact correctly over the full content (the injected block is preserved).
fn drop_findings_in_spans(
    findings: Vec<PiiFinding>,
    text: &str,
    byte_spans: &[(usize, usize)],
) -> Vec<PiiFinding> {
    if byte_spans.is_empty() || findings.is_empty() {
        return findings;
    }
    // Convert each byte span to a char span once (findings carry char offsets).
    let char_spans: Vec<(usize, usize)> = byte_spans
        .iter()
        .map(|&(bs, be)| (text[..bs].chars().count(), text[..be].chars().count()))
        .collect();
    findings
        .into_iter()
        .filter(|f| !char_spans.iter().any(|&(cs, ce)| f.start < ce && cs < f.end))
        .collect()
}

/// PII findings in `inp.classifiable`, excluding framework-injected volatile
/// blocks on the **inbound** surface (the user's own prose only). Other surfaces
/// scan the full text.
fn detect_inbound_aware(
    inp: &GuardrailInput,
    settings: &PiiSettings,
    surface: GuardrailSurface,
) -> Vec<PiiFinding> {
    let findings = detect_pii(&inp.classifiable, settings);
    if surface != GuardrailSurface::Inbound {
        return findings;
    }
    let spans = crate::proxy::content::volatile_byte_spans(&inp.classifiable);
    drop_findings_in_spans(findings, &inp.classifiable, &spans)
}

/// Resolve overlapping byte-span candidates (higher score, then longer span
/// wins) and convert the survivors to char-offset findings sorted by position.
fn resolve_overlaps(
    mut raw: Vec<(usize, usize, &'static str, f32)>,
    text: &str,
) -> Vec<PiiFinding> {
    // Strongest first; on a tie the longer span wins.
    raw.sort_by(|a, b| {
        b.3.partial_cmp(&a.3)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then((b.1 - b.0).cmp(&(a.1 - a.0)))
    });
    let mut accepted: Vec<(usize, usize, &'static str, f32)> = Vec::new();
    for r in raw {
        let overlaps = accepted.iter().any(|a| r.0 < a.1 && a.0 < r.1);
        if !overlaps {
            accepted.push(r);
        }
    }
    accepted.sort_by_key(|a| a.0);
    accepted
        .into_iter()
        .map(|(bs, be, entity, score)| PiiFinding {
            entity_type: entity,
            start: text[..bs].chars().count(),
            end: text[..be].chars().count(),
            score,
        })
        .collect()
}

/// Mask each finding in `text` with `placeholder_fmt` (`{entity}` → the entity
/// type). Splices right-to-left so earlier byte offsets stay valid; preserves
/// UTF-8 by mapping the findings' char offsets back to char boundaries.
pub fn redact(text: &str, findings: &[PiiFinding], placeholder_fmt: &str) -> String {
    if findings.is_empty() {
        return text.to_string();
    }
    // byte offset of each char boundary, plus a sentinel for end-of-string.
    let mut byte_at: Vec<usize> = text.char_indices().map(|(b, _)| b).collect();
    byte_at.push(text.len());

    let mut sorted: Vec<&PiiFinding> = findings.iter().collect();
    sorted.sort_by_key(|f| f.start);

    let mut result = text.to_string();
    for f in sorted.iter().rev() {
        let bs = byte_at.get(f.start).copied();
        let be = byte_at.get(f.end).copied();
        if let (Some(bs), Some(be)) = (bs, be)
            && bs <= be
            && be <= result.len()
        {
            let placeholder = placeholder_fmt.replace("{entity}", f.entity_type);
            result.replace_range(bs..be, &placeholder);
        }
    }
    result
}

/// A char-boundary-safe window of `±CONTEXT_WINDOW_BYTES` around a candidate.
fn surrounding(text: &str, byte_start: usize, byte_end: usize) -> String {
    let lo = text.floor_char_boundary(byte_start.saturating_sub(CONTEXT_WINDOW_BYTES));
    let hi = text.ceil_char_boundary((byte_end + CONTEXT_WINDOW_BYTES).min(text.len()));
    text[lo..hi].to_string()
}

/// Whether any recognizer context word appears in the (already-lowercased)
/// window.
fn has_context(window_lc: &str, words: &[String]) -> bool {
    words.iter().any(|w| window_lc.contains(&w.to_lowercase()))
}

/// Run a Stage-2 script: `process(candidate, context) -> #{ is_pii, score? }`.
/// A script error drops the candidate (fail-safe), never panics.
fn run_script(
    engine: &rhai::Engine,
    ast: &rhai::AST,
    candidate: &str,
    context: &str,
    base: f32,
) -> (bool, f32) {
    let mut scope = rhai::Scope::new();
    match engine.call_fn::<rhai::Map>(
        &mut scope,
        ast,
        "process",
        (candidate.to_string(), context.to_string()),
    ) {
        Ok(map) => {
            let is_pii = map
                .get("is_pii")
                .and_then(|v| v.as_bool().ok())
                .unwrap_or(false);
            let score = map
                .get("score")
                .and_then(|v| v.as_float().ok())
                .map(|f| f as f32)
                .unwrap_or(base);
            (is_pii, score)
        }
        Err(e) => {
            tracing::warn!(error = %e, "PII recognizer script error; dropping candidate");
            (false, base)
        }
    }
}

/// Distinct entity types in `findings`, in first-seen order.
fn distinct_entities(findings: &[PiiFinding]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for f in findings {
        if !out.iter().any(|e| e == f.entity_type) {
            out.push(f.entity_type.to_string());
        }
    }
    out
}

fn max_score(findings: &[PiiFinding]) -> f32 {
    findings.iter().map(|f| f.score).fold(0.0f32, f32::max)
}

/// One PII trace step — `guardrail:pii`, category [`GuardrailCategory::Pii`],
/// the distinct entity types as data, anchored by the input `id`.
fn pii_step(
    inp: &GuardrailInput,
    surface: GuardrailSurface,
    entities: Vec<String>,
    confidence: f32,
    outcome: GuardrailStepOutcome,
) -> GuardrailStepDiff {
    GuardrailStepDiff {
        call_id: None,
        tool_use_id: inp.id.clone(),
        name: "guardrail:pii".to_string(),
        phase: surface.phase(),
        target: inp.target.clone(),
        category: Some(GuardrailCategory::Pii),
        confidence: Some(confidence),
        outcome,
        error: None,
        entities: Some(entities),
    }
}

/// Result of a PII scan in **observe** mode — content untouched, only findings.
pub struct PiiObserveOutcome {
    pub steps: Vec<GuardrailStepDiff>,
    pub badges: Vec<AuditBadge>,
}

/// Result of a PII scan in **enforce** mode. `redactions` maps each input `id`
/// to its masked content (in-place `[REDACTED:…]`, not a whole-block
/// placeholder).
pub struct PiiEnforceOutcome {
    pub redactions: HashMap<String, String>,
    pub steps: Vec<GuardrailStepDiff>,
    pub badges: Vec<AuditBadge>,
}

/// Run the PII detector over `inputs` in **observe** mode. Returns `None` when
/// disabled, nothing to scan, or every input is clean (absence is the all-clear).
pub fn run_pii_observe(
    settings: &PiiSettings,
    inputs: &[GuardrailInput],
    surface: GuardrailSurface,
) -> Option<PiiObserveOutcome> {
    if !settings.enabled || inputs.is_empty() {
        return None;
    }
    let mut steps = Vec::new();
    let mut entities: Vec<String> = Vec::new();
    let mut overall = 0.0f32;
    for inp in inputs {
        let findings = detect_inbound_aware(inp, settings, surface);
        if findings.is_empty() {
            continue;
        }
        let conf = max_score(&findings);
        overall = overall.max(conf);
        let ents = distinct_entities(&findings);
        for e in &ents {
            if !entities.contains(e) {
                entities.push(e.clone());
            }
        }
        steps.push(pii_step(inp, surface, ents, conf, GuardrailStepOutcome::Flagged));
    }
    if steps.is_empty() {
        return None;
    }
    Some(PiiObserveOutcome {
        badges: vec![AuditBadge::Guardrail {
            categories: vec![GuardrailCategory::Pii],
            max_confidence: overall,
            action: GuardrailAction::Flag,
        }],
        steps,
    })
}

/// Run the PII detector over `inputs` in **enforce** mode — each input with
/// findings is redacted in place. Returns `None` when disabled, nothing to scan,
/// or every input is clean.
pub fn run_pii_enforce(
    settings: &PiiSettings,
    inputs: &[GuardrailInput],
    surface: GuardrailSurface,
) -> Option<PiiEnforceOutcome> {
    if !settings.enabled || inputs.is_empty() {
        return None;
    }
    let mut redactions = HashMap::new();
    let mut steps = Vec::new();
    let mut entities: Vec<String> = Vec::new();
    let mut overall = 0.0f32;
    for inp in inputs {
        let findings = detect_inbound_aware(inp, settings, surface);
        if findings.is_empty() {
            continue;
        }
        let conf = max_score(&findings);
        overall = overall.max(conf);
        let ents = distinct_entities(&findings);
        for e in &ents {
            if !entities.contains(e) {
                entities.push(e.clone());
            }
        }
        let redacted = redact(&inp.classifiable, &findings, &settings.redaction_placeholder);
        redactions.insert(inp.id.clone(), redacted);
        steps.push(pii_step(inp, surface, ents, conf, GuardrailStepOutcome::Blocked));
    }
    if steps.is_empty() {
        return None;
    }
    Some(PiiEnforceOutcome {
        redactions,
        steps,
        badges: vec![AuditBadge::Guardrail {
            categories: vec![GuardrailCategory::Pii],
            max_confidence: overall,
            action: GuardrailAction::Block,
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guardrail::settings::PiiSettings;

    fn settings() -> PiiSettings {
        PiiSettings {
            enabled: true,
            ..PiiSettings::default()
        }
    }

    #[test]
    fn detects_email_without_context() {
        let f = detect_pii("reach me at jane.doe@example.com please", &settings());
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].entity_type, "EMAIL_ADDRESS");
    }

    #[test]
    fn credit_card_luhn_gate() {
        // Valid Luhn → flagged.
        let ok = detect_pii("card 4111 1111 1111 1111 on file", &settings());
        assert!(ok.iter().any(|f| f.entity_type == "CREDIT_CARD"));
        // One digit off → Luhn fails → no CREDIT_CARD finding.
        let bad = detect_pii("card 4111 1111 1111 1112 on file", &settings());
        assert!(!bad.iter().any(|f| f.entity_type == "CREDIT_CARD"));
    }

    #[test]
    fn ssn_structural_negative_not_flagged() {
        // 000 area is structurally invalid → no US_SSN finding.
        let f = detect_pii("ssn 000-12-3456", &settings());
        assert!(!f.iter().any(|f| f.entity_type == "US_SSN"));
        let ok = detect_pii("ssn 123-45-6789", &settings());
        assert!(ok.iter().any(|f| f.entity_type == "US_SSN"));
    }

    #[test]
    fn script_recognizer_requires_context() {
        // Bare digit run with no banking context → the script rejects it.
        let bare = detect_pii("order number 12345678901", &settings());
        assert!(!bare.iter().any(|f| f.entity_type == "US_BANK_NUMBER"));
        // Same digits with banking context → the script accepts it.
        let ctx = detect_pii("my bank account number is 12345678901", &settings());
        assert!(ctx.iter().any(|f| f.entity_type == "US_BANK_NUMBER"));
    }

    #[test]
    fn entity_allowlist_drops_excluded() {
        let mut s = settings();
        s.entities = vec!["US_SSN".to_string()];
        let f = detect_pii("email a@b.com ssn 123-45-6789", &s);
        assert!(f.iter().all(|f| f.entity_type == "US_SSN"));
    }

    #[test]
    fn redaction_masks_in_place() {
        let s = settings();
        let text = "ssn 123-45-6789 here";
        let findings = detect_pii(text, &s);
        let masked = redact(text, &findings, "[REDACTED:{entity}]");
        assert_eq!(masked, "ssn [REDACTED:US_SSN] here");
        assert!(!masked.contains("123-45-6789"));
    }

    #[test]
    fn multibyte_char_spans_and_valid_utf8_redaction() {
        // Leading multibyte text shifts byte offsets away from char offsets — the
        // finding must carry char offsets and redaction must stay UTF-8-valid.
        let text = "héllo wörld ssn 123-45-6789 café";
        let findings = detect_pii(text, &settings());
        let ssn = findings
            .iter()
            .find(|f| f.entity_type == "US_SSN")
            .expect("ssn detected");
        // Char offset, not byte offset, points at the digits.
        let chars: Vec<char> = text.chars().collect();
        let slice: String = chars[ssn.start..ssn.end].iter().collect();
        assert_eq!(slice, "123-45-6789");
        let masked = redact(text, &findings, "[REDACTED:{entity}]");
        assert!(masked.contains("héllo wörld"));
        assert!(masked.contains("café"));
        assert!(masked.contains("[REDACTED:US_SSN]"));
        // Round-trips as valid UTF-8 (no panic on construction proves it).
        assert!(std::str::from_utf8(masked.as_bytes()).is_ok());
    }

    #[test]
    fn overlap_resolution_prefers_stronger() {
        // A valid card (Luhn, 0.85) overlaps the bank-number digit run; the
        // stronger CREDIT_CARD wins and the overlapping bank match is dropped.
        let s = settings();
        let f = detect_pii("bank account 4111111111111111", &s);
        let cards = f.iter().filter(|f| f.entity_type == "CREDIT_CARD").count();
        assert_eq!(cards, 1);
        // No overlapping span survives alongside it.
        for a in &f {
            for b in &f {
                if a != b {
                    assert!(a.end <= b.start || b.end <= a.start, "no overlaps survive");
                }
            }
        }
    }

    #[test]
    fn observe_produces_step_and_badge() {
        let inputs = vec![GuardrailInput {
            id: "0".to_string(),
            classifiable: "ssn 123-45-6789".to_string(),
            target: String::new(),
        }];
        let out = run_pii_observe(&settings(), &inputs, GuardrailSurface::Inbound)
            .expect("findings present");
        assert_eq!(out.steps.len(), 1);
        assert_eq!(out.steps[0].name, "guardrail:pii");
        assert_eq!(out.steps[0].entities.as_deref(), Some(&["US_SSN".to_string()][..]));
        assert_eq!(out.badges.len(), 1);
    }

    #[test]
    fn enforce_redacts_and_reports() {
        let inputs = vec![GuardrailInput {
            id: "2".to_string(),
            classifiable: "ssn 123-45-6789".to_string(),
            target: String::new(),
        }];
        let out = run_pii_enforce(&settings(), &inputs, GuardrailSurface::Inbound)
            .expect("findings present");
        assert_eq!(out.redactions.get("2").map(|s| s.as_str()), Some("ssn [REDACTED:US_SSN]"));
        assert_eq!(out.steps.len(), 1);
        assert!(matches!(out.steps[0].outcome, GuardrailStepOutcome::Blocked));
    }

    #[test]
    fn inbound_skips_pii_inside_volatile_block() {
        // Claude Code injects the user's email in a <system-reminder>; the user
        // only typed "hello". Inbound must NOT flag it (not the user's data).
        let inputs = vec![GuardrailInput {
            id: "0".to_string(),
            classifiable:
                "hello\n<system-reminder>contact jane.doe@example.com</system-reminder>"
                    .to_string(),
            target: String::new(),
        }];
        assert!(run_pii_observe(&settings(), &inputs, GuardrailSurface::Inbound).is_none());
        assert!(run_pii_enforce(&settings(), &inputs, GuardrailSurface::Inbound).is_none());
        // The same text on a non-inbound surface scans fully (no reminder there
        // to protect) — the email is flagged.
        let out = run_pii_observe(&settings(), &inputs, GuardrailSurface::Response)
            .expect("response scans the full text");
        assert_eq!(out.steps[0].entities.as_deref(), Some(&["EMAIL_ADDRESS".to_string()][..]));
    }

    #[test]
    fn inbound_redacts_prose_pii_but_preserves_volatile_block() {
        // PII in the user's own prose is still masked; the injected reminder
        // (and any PII inside it) is left intact in the forwarded content.
        let inputs = vec![GuardrailInput {
            id: "0".to_string(),
            classifiable:
                "my ssn 123-45-6789\n<system-reminder>contact a@b.com</system-reminder>"
                    .to_string(),
            target: String::new(),
        }];
        let out = run_pii_enforce(&settings(), &inputs, GuardrailSurface::Inbound)
            .expect("prose ssn detected");
        let red = out.redactions.get("0").expect("redaction present");
        assert!(red.contains("[REDACTED:US_SSN]"));
        assert!(!red.contains("123-45-6789"));
        // Reminder block (and its email) preserved verbatim.
        assert!(red.contains("<system-reminder>contact a@b.com</system-reminder>"));
    }

    #[test]
    fn disabled_is_noop() {
        let s = PiiSettings {
            enabled: false,
            ..PiiSettings::default()
        };
        assert!(detect_pii("ssn 123-45-6789", &s).is_empty());
    }
}

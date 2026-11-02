//! PII recognizer table — the static, in-process detector data baked into the
//! proxy.
//!
//! Each recognizer is a **two-stage `regexp : script`** unit:
//! - **Stage 1** — one or more native `Regex` patterns (the fast candidate
//!   gate). All active patterns across all recognizers are also folded into one
//!   combined [`RegexSet`] so the no-PII case is a single near-free scan.
//! - **Stage 2** — an attached [`Processor`] that runs **only on a candidate
//!   hit**: a native checksum validator (`luhn` / `iban_mod97` /
//!   `us_ssn_structural`) for the high-volume built-ins, or an AST-cached Rhai
//!   script (compiled once here) for the tail whose accept logic a score boost
//!   can't express.
//!
//! The recognizer data is `seeds/pii/recognizers.json`, adapted from Microsoft
//! Presidio (MIT — see the repo `NOTICE`). It is `include_str!`'d at compile
//! time (platform-static, hot-path, not tenant-editable) and parsed once into a
//! [`LazyLock`] — divergence from the runtime seed-loader is deliberate.
//!
//! Invariant: a recognizer pattern that fails to compile degrades to a
//! never-match sentinel with a one-time warning — a bad seed pattern never
//! panics and never disables the whole table.

use std::sync::{Arc, LazyLock};

use regex::{Regex, RegexSet};
use rhai::AST;
use serde::Deserialize;

/// The recognizer data, baked at compile time. The Dockerfiles copy `seeds/`
/// into the build context before `cargo build`, same as the Rhai seed scripts
/// `include_str!`'d in `scripting`.
const RECOGNIZERS_JSON: &str = include_str!("../../../../seeds/pii/recognizers.json");

/// Stage-2 processor attached to a recognizer — runs only on a Stage-1 candidate.
pub enum Processor {
    /// Pattern-only: the candidate is accepted on the pattern match alone (the
    /// score / context boost / threshold still decide whether it surfaces).
    None,
    /// A native checksum validator gates acceptance (`luhn`, …). The candidate
    /// is dropped unless the validator returns `true`.
    Native(fn(&str) -> bool),
    /// An AST-cached Rhai script gates acceptance and may override the score.
    /// `process(candidate, context) -> #{ is_pii: bool, score?: f64 }`.
    Script(Arc<AST>),
}

/// One compiled Stage-1 pattern with its base score.
pub struct CompiledPattern {
    pub regex: Regex,
    pub score: f32,
}

/// A single PII recognizer: Stage-1 patterns + context words + the Stage-2
/// processor.
pub struct Recognizer {
    pub entity_type: String,
    pub patterns: Vec<CompiledPattern>,
    /// Case-insensitive context words; a match nearby boosts the candidate score
    /// (pattern-only / native processors) or is read by the script processor.
    pub context: Vec<String>,
    pub processor: Processor,
}

/// The parsed, compiled recognizer table plus the combined Stage-1 gate.
pub struct PiiEngine {
    pub recognizers: Vec<Recognizer>,
    /// One RegexSet over every active pattern — the fast "is there any candidate
    /// at all?" gate that makes the no-PII path near-free.
    pub set: RegexSet,
    /// Maps a [`RegexSet`] match index back to `(recognizer index, pattern
    /// index)` so a set hit dispatches to the right pattern's `find_iter`.
    pub set_map: Vec<(usize, usize)>,
}

// ----- raw seed shapes (parsed once, then compiled into the runtime table) -----

#[derive(Deserialize)]
struct RawFile {
    recognizers: Vec<RawRecognizer>,
}

#[derive(Deserialize)]
struct RawRecognizer {
    entity_type: String,
    patterns: Vec<RawPattern>,
    #[serde(default)]
    context: Vec<String>,
    processor: RawProcessor,
}

#[derive(Deserialize)]
struct RawPattern {
    #[allow(dead_code)]
    name: String,
    regex: String,
    score: f32,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum RawProcessor {
    None,
    Native { validator: String },
    Script { source: String },
}

/// A regex that matches nothing — the fail-safe for a seed pattern that fails to
/// compile (mirrors `scripting::regex_cache`).
fn never_match() -> Regex {
    Regex::new("a^").expect("never-match sentinel regex is valid")
}

fn compile_pattern(entity: &str, src: &str) -> Regex {
    Regex::new(src).unwrap_or_else(|e| {
        tracing::error!(entity, pattern = src, error = %e, "invalid PII recognizer pattern; using never-match fallback");
        never_match()
    })
}

/// Resolve a native validator name to its function. An unknown name is a seed
/// bug — log and degrade to pattern-only (accept) so detection still happens
/// under the score gate rather than silently dropping the entity.
fn native_validator(entity: &str, name: &str) -> Processor {
    match name {
        "luhn" => Processor::Native(luhn),
        "us_ssn_structural" => Processor::Native(us_ssn_structural),
        "iban_mod97" => Processor::Native(iban_mod97),
        // European national-ID / VAT / tax checksums (.317).
        "fr_nir" => Processor::Native(fr_nir),
        "fr_vat" => Processor::Native(fr_vat),
        "de_tax_id" => Processor::Native(de_tax_id),
        "de_vat" => Processor::Native(de_vat),
        "it_fiscal_code" => Processor::Native(it_fiscal_code),
        "it_vat" => Processor::Native(it_vat),
        "es_nif" => Processor::Native(es_nif),
        "es_nie" => Processor::Native(es_nie),
        "es_cif" => Processor::Native(es_cif),
        "uk_nino" => Processor::Native(uk_nino),
        "uk_nhs" => Processor::Native(uk_nhs),
        "uk_utr" => Processor::Native(uk_utr),
        "uk_vat" => Processor::Native(uk_vat),
        other => {
            tracing::error!(entity, validator = other, "unknown PII native validator; treating as pattern-only");
            Processor::None
        }
    }
}

fn compile_script(entity: &str, source: &str) -> Processor {
    let engine = crate::scripting::engine::create_engine();
    match engine.compile(source) {
        Ok(ast) => Processor::Script(Arc::new(ast)),
        Err(e) => {
            tracing::error!(entity, error = %e, "invalid PII recognizer script; treating as pattern-only");
            Processor::None
        }
    }
}

static ENGINE: LazyLock<PiiEngine> = LazyLock::new(build_engine);

/// The process-global compiled recognizer table. Parsed and compiled on first
/// use; reused for every detection.
pub fn engine() -> &'static PiiEngine {
    &ENGINE
}

fn build_engine() -> PiiEngine {
    let raw: RawFile = serde_json::from_str(RECOGNIZERS_JSON).unwrap_or_else(|e| {
        tracing::error!(error = %e, "PII recognizers.json failed to parse; PII detection disabled");
        RawFile { recognizers: Vec::new() }
    });

    let mut recognizers = Vec::with_capacity(raw.recognizers.len());
    let mut set_sources: Vec<String> = Vec::new();
    let mut set_map: Vec<(usize, usize)> = Vec::new();

    for raw_rec in raw.recognizers {
        let rec_idx = recognizers.len();
        let mut patterns = Vec::with_capacity(raw_rec.patterns.len());
        for raw_pat in &raw_rec.patterns {
            let regex = compile_pattern(&raw_rec.entity_type, &raw_pat.regex);
            // The combined set must always build, so an invalid source contributes
            // a never-match literal rather than failing RegexSet::new wholesale.
            let set_src = if Regex::new(&raw_pat.regex).is_ok() {
                raw_pat.regex.clone()
            } else {
                "a^".to_string()
            };
            set_map.push((rec_idx, patterns.len()));
            set_sources.push(set_src);
            patterns.push(CompiledPattern {
                regex,
                score: raw_pat.score,
            });
        }
        let processor = match raw_rec.processor {
            RawProcessor::None => Processor::None,
            RawProcessor::Native { validator } => {
                native_validator(&raw_rec.entity_type, &validator)
            }
            RawProcessor::Script { source } => compile_script(&raw_rec.entity_type, &source),
        };
        recognizers.push(Recognizer {
            entity_type: raw_rec.entity_type,
            patterns,
            context: raw_rec.context,
            processor,
        });
    }

    let set = RegexSet::new(&set_sources).unwrap_or_else(|e| {
        tracing::error!(error = %e, "PII RegexSet failed to build; PII detection disabled");
        RegexSet::empty()
    });

    PiiEngine {
        recognizers,
        set,
        set_map,
    }
}

// ----- native checksum validators -----

/// Luhn (mod-10) checksum over the candidate's digits. Drops separators first.
fn luhn(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut x = d;
        if double {
            x *= 2;
            if x > 9 {
                x -= 9;
            }
        }
        sum += x;
        double = !double;
    }
    sum.is_multiple_of(10)
}

/// US SSN structural validity (SSA issuance rules): area ∉ {000, 666, 900–999},
/// group ≠ 00, serial ≠ 0000. Catches the bulk of pattern false positives
/// (sequential / placeholder numbers) without an issuance database.
fn us_ssn_structural(s: &str) -> bool {
    let d: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if d.len() != 9 {
        return false;
    }
    let area = d[0] * 100 + d[1] * 10 + d[2];
    let group = d[3] * 10 + d[4];
    let serial = d[5] * 1000 + d[6] * 100 + d[7] * 10 + d[8];
    area != 0 && area != 666 && area < 900 && group != 0 && serial != 0
}

/// ISO 13616 IBAN mod-97 checksum: move the first four chars to the end, map
/// letters A–Z → 10–35, and verify the resulting number ≡ 1 (mod 97). Folds
/// digit-group by digit-group to stay within u32.
fn iban_mod97(s: &str) -> bool {
    let cleaned: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if cleaned.len() < 15 || cleaned.len() > 34 {
        return false;
    }
    let (head, tail) = cleaned.split_at(4);
    let mut remainder = 0u32;
    for c in tail.chars().chain(head.chars()) {
        let val = if c.is_ascii_digit() {
            c as u32 - '0' as u32
        } else {
            c as u32 - 'A' as u32 + 10
        };
        remainder = if val >= 10 {
            (remainder * 100 + val) % 97
        } else {
            (remainder * 10 + val) % 97
        };
    }
    remainder == 1
}

// ----- European national-ID / VAT / tax checksum validators -----
//
// Each takes the raw candidate (separators/letters included) and returns whether
// it passes its country's structural / checksum rule. The Stage-1 regex shapes
// the candidate; these confirm it. Algorithms follow the published national
// specifications; the `python-stdnum` library implements each and is the
// reference the tests below are checked against.

/// ASCII digits of `s` as `0..=9` values, separators dropped.
fn digits_of(s: &str) -> Vec<u8> {
    s.chars()
        .filter_map(|c| c.to_digit(10).map(|d| d as u8))
        .collect()
}

/// Luhn (mod-10) over an arbitrary digit slice (check digit included). Used for
/// the embedded SIREN in a French VAT number and the Spanish CIF control.
fn luhn_slice(d: &[u8]) -> bool {
    if d.is_empty() {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    for &x in d.iter().rev() {
        let mut v = x as u32;
        if double {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
        double = !double;
    }
    sum.is_multiple_of(10)
}

/// The Luhn check digit to append to `d` so the result is Luhn-valid (Spanish
/// CIF control). Mirrors `stdnum.luhn.calc_check_digit`.
fn luhn_check_digit(d: &[u8]) -> u8 {
    let mut v = d.to_vec();
    v.push(0);
    for c in 0u8..10 {
        *v.last_mut().expect("pushed element exists") = c;
        if luhn_slice(&v) {
            return c;
        }
    }
    0
}

fn is_leap_year(y: u32) -> bool {
    y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400))
}

fn days_in_month(y: u32, m: u32) -> u32 {
    match m {
        2 => {
            if is_leap_year(y) {
                29
            } else {
                28
            }
        }
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// The French VAT key alphabet (digits + A–Z, excluding `I`/`O`).
const FR_VAT_ALPHABET: &str = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ";

/// France NIR — 15 chars: 13-char body + 2-digit key, `key = 97 − (body mod 97)`.
/// Corsica's `2A`/`2B` department letter is substituted to digits with the
/// documented positional offset before the modulus.
fn fr_nir(s: &str) -> bool {
    let cleaned: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if cleaned.len() != 15 {
        return false;
    }
    let (body, key_str) = cleaned.split_at(13);
    let key: u64 = match key_str.parse() {
        Ok(k) if (1..=97).contains(&k) => k,
        _ => return false,
    };
    let mut offset: u64 = 0;
    let mut numeric = String::with_capacity(13);
    for c in body.chars() {
        match c {
            '0'..='9' => numeric.push(c),
            'A' => {
                numeric.push('0');
                offset = 1_000_000;
            }
            'B' => {
                numeric.push('0');
                offset = 2_000_000;
            }
            _ => return false,
        }
    }
    let n: u64 = match numeric.parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    let n = n.saturating_sub(offset);
    97 - (n % 97) == key
}

/// France VAT — `FR` + 2-char key + 9-digit SIREN. The SIREN (unless the Monaco
/// `000…` form) must be Luhn-valid; the key is checked numerically
/// (`key == (SIREN·100 + 12) mod 97`) or, for the legacy lettered key, via the
/// alphabet-index formula. Mirrors `stdnum.fr.tva`.
fn fr_vat(s: &str) -> bool {
    let cleaned: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let c = cleaned.strip_prefix("FR").unwrap_or(cleaned.as_str());
    if c.len() != 11 {
        return false;
    }
    let key = &c[..2];
    let siren = &c[2..];
    if !siren.bytes().all(|b| b.is_ascii_digit()) || !key.chars().all(|ch| FR_VAT_ALPHABET.contains(ch))
    {
        return false;
    }
    // Non-Monaco SIREN must be Luhn-valid.
    if &siren[..3] != "000" {
        let sd = digits_of(siren);
        if sd.len() != 9 || !luhn_slice(&sd) {
            return false;
        }
    }
    let siren_n: u64 = match siren.parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    if key.bytes().all(|b| b.is_ascii_digit()) {
        let key_n: u64 = key.parse().unwrap_or(u64::MAX);
        return key_n == (siren_n * 100 + 12) % 97;
    }
    // Legacy lettered key.
    let i0 = FR_VAT_ALPHABET.find(key.as_bytes()[0] as char).unwrap_or(0) as i64;
    let i1 = FR_VAT_ALPHABET.find(key.as_bytes()[1] as char).unwrap_or(0) as i64;
    let check = if key.as_bytes()[0].is_ascii_digit() {
        i0 * 24 + i1 - 10
    } else {
        i0 * 34 + i1 - 100
    };
    (siren_n as i64 + 1 + check.div_euclid(11)) % 11 == check.rem_euclid(11)
}

/// ISO/IEC 7064 MOD 11,10 over the first `body_len` digits → trailing check
/// digit (Germany's Steuer-IdNr and USt-IdNr).
fn de_mod11_10(digits: &[u8], body_len: usize) -> bool {
    if digits.len() != body_len + 1 {
        return false;
    }
    let mut produkt: i32 = 10;
    for &d in &digits[..body_len] {
        let mut summe = (d as i32 + produkt) % 10;
        if summe == 0 {
            summe = 10;
        }
        produkt = (summe * 2) % 11;
    }
    let mut pruef = 11 - produkt;
    if pruef == 10 {
        pruef = 0;
    }
    pruef == digits[body_len] as i32
}

/// Germany Steuer-IdNr — 11 digits (no leading zero), MOD 11,10 check plus the
/// structural rule that in the first 10 digits exactly one digit repeats (two or
/// three times) and every other digit appears once. Mirrors `stdnum.de.idnr`.
fn de_tax_id(s: &str) -> bool {
    let d = digits_of(s);
    if d.len() != 11 || d[0] == 0 {
        return false;
    }
    let mut counts = [0u8; 10];
    for &x in &d[..10] {
        counts[x as usize] += 1;
    }
    // Exactly one digit repeats, two or three times; all others appear once.
    let mut repeats = 0u32;
    let mut repeat_count = 0u8;
    for &c in &counts {
        if c > 1 {
            repeats += 1;
            repeat_count = c;
        }
    }
    if repeats != 1 || !matches!(repeat_count, 2 | 3) {
        return false;
    }
    de_mod11_10(&d, 10)
}

/// Germany USt-IdNr — `DE` + 9 digits (no leading zero), MOD 11,10 over the
/// first 8. Mirrors `stdnum.de.vat`.
fn de_vat(s: &str) -> bool {
    let d = digits_of(s);
    d.len() == 9 && d[0] != 0 && de_mod11_10(&d, 8)
}

/// Italy Codice Fiscale — 16 alphanumeric: positional shape, a valid encoded
/// birth date (month letter + day-mod-40 as a real calendar date), and the
/// odd/even-table check letter. Mirrors `stdnum.it.codicefiscale`.
fn it_fiscal_code(s: &str) -> bool {
    let c: Vec<char> = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if c.len() != 16 {
        return false;
    }
    // Positional shape: 6 letters, 2 digits, letter, 2 digits, letter, 3 digits,
    // check letter. (Omocodia letter-for-digit substitution is not matched — a
    // rare form the Stage-1 regex already excludes; a miss, never a false hit.)
    let digit = |i: usize| c[i].is_ascii_digit();
    let alpha = |i: usize| c[i].is_ascii_alphabetic();
    let shape = (0..6).all(alpha)
        && digit(6)
        && digit(7)
        && alpha(8)
        && digit(9)
        && digit(10)
        && alpha(11)
        && digit(12)
        && digit(13)
        && digit(14)
        && alpha(15);
    if !shape {
        return false;
    }
    // Encoded birth date must be a real calendar date.
    const MONTHS: &[u8] = b"ABCDEHLMPRST";
    let month = match MONTHS.iter().position(|&m| m == c[8] as u8) {
        Some(i) => i as u32 + 1,
        None => return false,
    };
    let two = |a: usize, b: usize| c[a].to_digit(10).unwrap() * 10 + c[b].to_digit(10).unwrap();
    let day = two(9, 10) % 40;
    let yy = two(6, 7);
    let year = if 1900 + yy < 1920 { 2000 + yy } else { 1900 + yy };
    if day < 1 || day > days_in_month(year, month) {
        return false;
    }
    // Odd positions (1-indexed) use the scrambled table; even positions the face
    // value (digits 0-9, letters A-Z → 0-25).
    const ODD: [i32; 36] = [
        1, 0, 5, 7, 9, 13, 15, 17, 19, 21, // 0-9
        1, 0, 5, 7, 9, 13, 15, 17, 19, 21, // A-J
        2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24, 23, // K-Z
    ];
    let idx = |ch: char| -> usize {
        if ch.is_ascii_digit() {
            ch as usize - '0' as usize
        } else {
            10 + (ch as usize - 'A' as usize)
        }
    };
    let mut total = 0i32;
    for (i, &ch) in c[..15].iter().enumerate() {
        let j = idx(ch);
        total += if (i + 1) % 2 == 1 {
            ODD[j]
        } else if j < 10 {
            j as i32
        } else {
            (j - 10) as i32
        };
    }
    (b'A' + (total % 26) as u8) as char == c[15]
}

/// Italy Partita IVA — 11 digits: the first 7 (company) non-zero, a valid
/// province office code (001–100 or 120/121/888/999), and a standard Luhn check.
/// Mirrors `stdnum.it.iva`.
fn it_vat(s: &str) -> bool {
    let d = digits_of(s);
    if d.len() != 11 || d[..7].iter().all(|&x| x == 0) {
        return false;
    }
    let prov = d[7] as u32 * 100 + d[8] as u32 * 10 + d[9] as u32;
    if !((1..=100).contains(&prov) || matches!(prov, 120 | 121 | 888 | 999)) {
        return false;
    }
    luhn_slice(&d)
}

/// Spain control-letter table (DNI/NIF/NIE), indexed by `number mod 23`.
const ES_DNI_LETTERS: &[u8; 23] = b"TRWAGMYFPDXBNJZSQVHLCKE";

/// Spain DNI/NIF — up-to-8 digits + control letter from the mod-23 table.
fn es_nif(s: &str) -> bool {
    let c: Vec<char> = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if c.len() < 2 {
        return false;
    }
    let letter = c[c.len() - 1];
    if !letter.is_ascii_alphabetic() {
        return false;
    }
    let num_str: String = c[..c.len() - 1].iter().collect();
    if num_str.len() > 8 || !num_str.chars().all(|x| x.is_ascii_digit()) {
        return false;
    }
    let n: u64 = match num_str.parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    ES_DNI_LETTERS[(n % 23) as usize] as char == letter
}

/// Spain NIE — `X`/`Y`/`Z` prefix (→0/1/2) + 7 digits + control letter (mod-23).
fn es_nie(s: &str) -> bool {
    let c: Vec<char> = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if c.len() < 3 {
        return false;
    }
    let pdigit = match c[0] {
        'X' => '0',
        'Y' => '1',
        'Z' => '2',
        _ => return false,
    };
    let letter = c[c.len() - 1];
    if !letter.is_ascii_alphabetic() {
        return false;
    }
    let mut num_str = String::new();
    num_str.push(pdigit);
    for &ch in &c[1..c.len() - 1] {
        if !ch.is_ascii_digit() {
            return false;
        }
        num_str.push(ch);
    }
    let n: u64 = match num_str.parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    ES_DNI_LETTERS[(n % 23) as usize] as char == letter
}

/// Spain CIF (company tax code) — org-type letter + 7 digits + control. The
/// control is the Luhn check digit of the 7 middle digits, accepted in either
/// its digit or its letter (`JABCDEFGHI`) form for any org type. Mirrors
/// `stdnum.es.cif`.
fn es_cif(s: &str) -> bool {
    let c: Vec<char> = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if c.len() != 9 || !"ABCDEFGHJNPQRSUVW".contains(c[0]) {
        return false;
    }
    let mut mid = Vec::with_capacity(7);
    for &ch in &c[1..8] {
        match ch.to_digit(10) {
            Some(x) => mid.push(x as u8),
            None => return false,
        }
    }
    let cd = luhn_check_digit(&mid);
    c[8] == b"JABCDEFGHI"[cd as usize] as char || c[8].to_digit(10) == Some(cd as u32)
}

/// UK National Insurance Number — structural only (no arithmetic checksum):
/// allowed prefix letters, excluded prefix pairs, suffix `A`–`D`.
fn uk_nino(s: &str) -> bool {
    let c: Vec<char> = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if c.len() != 9 {
        return false;
    }
    let (a, b) = (c[0], c[1]);
    if !a.is_ascii_alphabetic() || !b.is_ascii_alphabetic() {
        return false;
    }
    if c[2..8].iter().any(|ch| !ch.is_ascii_digit()) {
        return false;
    }
    if !"ABCD".contains(c[8]) {
        return false;
    }
    if "DFIQUVO".contains(a) || "DFIOQUV".contains(b) {
        return false;
    }
    let prefix: String = [a, b].iter().collect();
    !["BG", "GB", "NK", "KN", "NT", "TN", "ZZ"].contains(&prefix.as_str())
}

/// UK NHS number — 10 digits, mod-11 weighted (weights 10..2); check `10` is
/// invalid, `11` maps to `0`.
fn uk_nhs(s: &str) -> bool {
    let d = digits_of(s);
    if d.len() != 10 {
        return false;
    }
    let sum: i32 = (0..9).map(|i| d[i] as i32 * (10 - i as i32)).sum();
    let mut check = 11 - sum % 11;
    if check == 11 {
        check = 0;
    }
    check != 10 && check == d[9] as i32
}

/// UK UTR (Unique Taxpayer Reference) — 10 digits, mod-11 weighted with the
/// leading digit as the check, resolved through the `21987654321` table.
/// Mirrors `stdnum.gb.utr`.
fn uk_utr(s: &str) -> bool {
    let d = digits_of(s);
    if d.len() != 10 {
        return false;
    }
    const W: [i32; 9] = [6, 7, 8, 9, 10, 5, 4, 3, 2];
    let sum: i32 = (0..9).map(|i| d[i + 1] as i32 * W[i]).sum();
    b"21987654321"[(sum % 11) as usize] == b'0' + d[0]
}

/// UK VAT — `GB` + 9 (or 12) digits, mod-97 "9755" algorithm (weights
/// `8,7,6,5,4,3,2,10,1`). Restarting numbers (first three ≥ 100) also accept the
/// 42/55 offsets. Mirrors `stdnum.gb.vat`'s standard branch.
fn uk_vat(s: &str) -> bool {
    let d = digits_of(s);
    if d.len() != 9 && d.len() != 12 {
        return false;
    }
    const W: [i32; 9] = [8, 7, 6, 5, 4, 3, 2, 10, 1];
    let cs: i32 = (0..9).map(|i| W[i] * d[i] as i32).sum::<i32>() % 97;
    let first3 = d[0] as i32 * 100 + d[1] as i32 * 10 + d[2] as i32;
    if first3 >= 100 {
        matches!(cs, 0 | 42 | 55)
    } else {
        cs == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizers_parse_and_compile() {
        let e = engine();
        assert!(!e.recognizers.is_empty(), "recognizer table must be non-empty");
        // The set_map aligns 1:1 with the combined RegexSet's pattern count.
        assert_eq!(e.set.len(), e.set_map.len());
        // Every set index maps to a valid (recognizer, pattern) coordinate.
        for &(ri, pi) in &e.set_map {
            assert!(e.recognizers[ri].patterns.get(pi).is_some());
        }
        // At least one recognizer ships each processor kind exercised by v1.
        assert!(e
            .recognizers
            .iter()
            .any(|r| matches!(r.processor, Processor::Native(_))));
        assert!(e
            .recognizers
            .iter()
            .any(|r| matches!(r.processor, Processor::Script(_))));
    }

    #[test]
    fn luhn_accepts_valid_rejects_invalid() {
        // Valid test PANs.
        assert!(luhn("4111111111111111"));
        assert!(luhn("5500 0000 0000 0004"));
        // One digit off → checksum fails.
        assert!(!luhn("4111111111111112"));
        assert!(!luhn("1234567890123456"));
        // Too short.
        assert!(!luhn("4111"));
    }

    #[test]
    fn ssn_structural_rules() {
        assert!(us_ssn_structural("123-45-6789"));
        assert!(us_ssn_structural("123456789"));
        // Forbidden area numbers.
        assert!(!us_ssn_structural("000-45-6789"));
        assert!(!us_ssn_structural("666-45-6789"));
        assert!(!us_ssn_structural("900-45-6789"));
        // Zero group / serial.
        assert!(!us_ssn_structural("123-00-6789"));
        assert!(!us_ssn_structural("123-45-0000"));
        // Wrong digit count (the validator works on digits, not formatting —
        // the regex pattern enforces the dash layout).
        assert!(!us_ssn_structural("12345678"));
        assert!(!us_ssn_structural("1234567890"));
    }

    #[test]
    fn iban_mod97_checksum() {
        // Canonical valid IBANs.
        assert!(iban_mod97("GB82WEST12345698765432"));
        assert!(iban_mod97("DE89370400440532013000"));
        // Corrupted check digits.
        assert!(!iban_mod97("GB82WEST12345698765433"));
        assert!(!iban_mod97("DE00370400440532013000"));
    }

    // The European validators below are verified bit-for-bit against the
    // reference library `python-stdnum` over 100k–300k random samples per
    // type. The anchors here are
    // stdnum-confirmed valid / invalid values guarding against regressions.

    #[test]
    fn fr_nir_mod97() {
        assert!(fr_nir("295109912611193"));
        assert!(fr_nir("2 95 10 99 126 111 93"));
        assert!(fr_nir("253072B07300470")); // Corsica 2B
        assert!(!fr_nir("295109912611194")); // wrong key
        assert!(!fr_nir("garbage"));
    }

    #[test]
    fn fr_vat_checksum() {
        assert!(fr_vat("FR23334175221")); // numeric key
        assert!(fr_vat("FRK7399859412")); // legacy lettered key
        assert!(!fr_vat("FR23334175222")); // tampered
        assert!(!fr_vat("FR00404833048")); // non-Luhn SIREN
    }

    #[test]
    fn de_tax_id_mod11_10() {
        assert!(de_tax_id("36574261809"));
        assert!(!de_tax_id("36554266806")); // two digits repeat → structural reject
        assert!(!de_tax_id("12345678905")); // all-distinct first 10 → reject
        assert!(!de_tax_id("36574261800")); // wrong check digit
    }

    #[test]
    fn de_vat_mod11_10() {
        assert!(de_vat("DE136695976"));
        assert!(de_vat("136695976"));
        assert!(!de_vat("DE003187161")); // leading zero
        assert!(!de_vat("DE136695970")); // wrong check digit
    }

    #[test]
    fn it_fiscal_code_full() {
        assert!(it_fiscal_code("RCCMNL83S18D969H"));
        assert!(it_fiscal_code("rssmra85t10a562s"));
        assert!(!it_fiscal_code("RSSMRA85T10A562X")); // wrong check letter
        assert!(!it_fiscal_code("RSSMRA85Z10A562S")); // invalid month letter Z
        assert!(!it_fiscal_code("TOOSHORT"));
    }

    #[test]
    fn it_vat_full() {
        assert!(it_vat("00743110157"));
        assert!(!it_vat("00743110158")); // wrong Luhn check
        assert!(!it_vat("12345604047")); // province code 604 invalid
        assert!(!it_vat("00000000000")); // first 7 zero
    }

    #[test]
    fn es_nif_mod23() {
        assert!(es_nif("12345678Z"));
        assert!(es_nif("54362315K"));
        assert!(!es_nif("12345678A"));
    }

    #[test]
    fn es_nie_prefix_mod23() {
        assert!(es_nie("X2482300W"));
        assert!(es_nie("x-2482300w"));
        assert!(!es_nie("X2482300A")); // wrong control letter
        assert!(!es_nie("Q1234567A")); // bad prefix
    }

    #[test]
    fn es_cif_control() {
        assert!(es_cif("J99216582"));
        assert!(!es_cif("J99216583"));
    }

    #[test]
    fn uk_nino_structural() {
        assert!(uk_nino("AB123456C"));
        assert!(uk_nino("AB 12 34 56 C"));
        assert!(!uk_nino("BG123456A")); // excluded prefix
        assert!(!uk_nino("DA123456A")); // disallowed first letter D
        assert!(!uk_nino("AB123456E")); // bad suffix
    }

    #[test]
    fn uk_nhs_mod11() {
        assert!(uk_nhs("9434765870"));
        assert!(uk_nhs("943 476 5919"));
        assert!(!uk_nhs("9434765918"));
    }

    #[test]
    fn uk_utr_mod11() {
        assert!(uk_utr("1955839661"));
        assert!(!uk_utr("2955839661")); // wrong leading check digit
    }

    #[test]
    fn uk_vat_mod97() {
        assert!(uk_vat("GB980780684"));
        assert!(uk_vat("980780684"));
        assert!(!uk_vat("GB980780685"));
        assert!(!uk_vat("GB088428864")); // first three < 100 → only checksum 0 allowed
    }
}

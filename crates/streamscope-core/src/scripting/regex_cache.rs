//! Bounded compiled-regex cache shared by transform-engine consumers.
//!
//! Compiling a `regex::Regex` is expensive; both the `trigger_regex` fast-find
//! gate (`execute_chain` / `execute_response_chain`) and the `redact_pattern`
//! Rhai builtin would otherwise recompile the same pattern on every call. This
//! caches compiled regexes keyed by their source string.
//!
//! Invariant: a pattern that fails to compile is cached as a **never-match**
//! sentinel and a warning is logged once (at first sight). Callers therefore
//! never see a compile error — an invalid trigger degrades to "no match" (the
//! script is skipped) and an invalid `redact_pattern` degrades to "no
//! replacement", never a panic and never an unbounded recompile loop.

use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};

use regex::Regex;

/// Hard cap on distinct cached patterns. Transform sources are bounded (seed +
/// operator scripts), so this only guards against a pathological dynamic-pattern
/// generator. On overflow the cache is cleared rather than grown without bound.
const MAX_CACHED_PATTERNS: usize = 1024;

static CACHE: LazyLock<RwLock<HashMap<String, Regex>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// A regex that matches nothing — the fail-safe for an invalid pattern.
fn never_match() -> Regex {
    // `a^` (an `a` before start-of-text) can never match. The literal is valid
    // for the `regex` crate, so this `expect` is provably infallible.
    Regex::new("a^").expect("never-match sentinel regex is valid")
}

/// Return a compiled regex for `pattern`, compiling and caching on first use.
///
/// `Regex` is internally reference-counted, so the returned clone is cheap. An
/// invalid pattern returns (and caches) a never-match regex with a single
/// load-time warning, so callers can treat the result as a normal regex.
pub fn get(pattern: &str) -> Regex {
    if let Some(re) = CACHE.read().ok().and_then(|c| c.get(pattern).cloned()) {
        return re;
    }
    let compiled = Regex::new(pattern).unwrap_or_else(|e| {
        tracing::warn!(pattern, error = %e, "invalid regex pattern; using never-match fallback");
        never_match()
    });
    if let Ok(mut c) = CACHE.write() {
        if c.len() >= MAX_CACHED_PATTERNS {
            c.clear();
        }
        c.insert(pattern.to_string(), compiled.clone());
    }
    compiled
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caches_and_matches() {
        let re = get(r"\d{3}");
        assert!(re.is_match("abc 123"));
        // Second fetch returns an equivalent (cached) regex.
        assert!(get(r"\d{3}").is_match("999"));
    }

    #[test]
    fn invalid_pattern_never_matches() {
        let re = get("[unterminated");
        assert!(!re.is_match("anything at all"));
        assert!(!re.is_match(""));
    }
}

//! Rhai engine factory — sandboxed engine with execution limits and helper functions.

use rhai::{Dynamic, Engine};

// Rhai sandbox limits
const MAX_OPERATIONS: u64 = 100_000;
const MAX_CALL_LEVELS: usize = 32;
const MAX_STRING_SIZE: usize = 1_048_576; // 1 MB
const MAX_ARRAY_SIZE: usize = 10_000;
const MAX_MAP_SIZE: usize = 1_000;
/// Max parser nesting depth for top-level and function-body expressions. Set
/// explicitly because Rhai's default differs between debug (16/32) and release
/// (32/64) builds — leaving it implicit lets a script compile in one and fail
/// in the other. Generous enough for recursive transform helpers.
const MAX_EXPR_DEPTH: usize = 64;

/// Create a sandboxed Rhai engine with execution limits and helper functions.
pub fn create_engine() -> Engine {
    let mut engine = Engine::new();

    // Sandbox limits
    engine.set_max_operations(MAX_OPERATIONS);
    engine.set_max_call_levels(MAX_CALL_LEVELS);
    engine.set_max_string_size(MAX_STRING_SIZE);
    engine.set_max_array_size(MAX_ARRAY_SIZE);
    engine.set_max_map_size(MAX_MAP_SIZE);
    engine.set_max_expr_depths(MAX_EXPR_DEPTH, MAX_EXPR_DEPTH);

    // Register helper functions
    engine.register_fn("contains_ci", contains_ci);
    engine.register_fn("matches_glob", matches_glob);
    engine.register_fn("redact_pattern", redact_pattern);
    engine.register_fn("redact_pii", redact_pii);
    engine.register_fn("parse_int", parse_int);
    engine.register_fn("parse_json", parse_json);
    engine.register_fn("to_json", to_json);

    // Array join: ["a", "b"].join(", ") → "a, b"
    engine.register_fn("join", |arr: rhai::Array, sep: &str| -> String {
        arr.iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(sep)
    });

    engine
}

/// Case-insensitive string contains.
fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

/// Simple wildcard glob match (`*` matches any sequence of characters).
fn matches_glob(input: &str, pattern: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();

    if parts.len() == 1 {
        return input == pattern;
    }

    let mut pos = 0;

    // Check prefix (before first *)
    if let Some(first) = parts.first()
        && !first.is_empty()
    {
        if !input.starts_with(*first) {
            return false;
        }
        pos = first.len();
    }

    // Check suffix (after last *)
    if let Some(last) = parts.last()
        && !last.is_empty()
        && !input.ends_with(*last)
    {
        return false;
    }

    // Check middle parts in order
    for part in &parts[1..parts.len().saturating_sub(1)] {
        if part.is_empty() {
            continue;
        }
        if let Some(found) = input[pos..].find(*part) {
            pos += found + part.len();
        } else {
            return false;
        }
    }

    true
}

/// Regex-based pattern redaction. The compiled regex is cached
/// ([`crate::scripting::regex_cache`]) so a script that calls this in a loop
/// doesn't recompile the same pattern every call; an invalid pattern degrades to
/// a never-match (the input is returned unchanged).
fn redact_pattern(input: &str, pattern: &str, replacement: &str) -> String {
    crate::scripting::regex_cache::get(pattern)
        .replace_all(input, replacement)
        .to_string()
}

/// Mask all PII the in-process detector finds, in place (`[REDACTED:US_SSN]`).
/// The sanctioned replacement for the old single-purpose email redactor — it
/// covers every v1 entity (email, card, SSN, IBAN, phone, IP, crypto, bank)
/// with checksum validation, not just emails.
fn redact_pii(input: &str) -> String {
    let settings = crate::guardrail::PiiSettings {
        enabled: true,
        ..Default::default()
    };
    let findings = crate::guardrail::detect_pii(input, &settings);
    crate::guardrail::redact(input, &findings, &settings.redaction_placeholder)
}

/// Parse string to integer (returns () on failure for Rhai compatibility).
fn parse_int(input: &str) -> Dynamic {
    match input.parse::<i64>() {
        Ok(n) => Dynamic::from(n),
        Err(_) => Dynamic::UNIT,
    }
}

/// Parse a JSON string into a Rhai value — object becomes a map, array an
/// array, and so on. Returns () on parse failure, for Rhai compatibility.
fn parse_json(input: &str) -> Dynamic {
    serde_json::from_str::<Dynamic>(input).unwrap_or(Dynamic::UNIT)
}

/// Serialize a Rhai value to a compact JSON string. Returns "" on failure.
/// Object-map keys are emitted in sorted order (Rhai maps are ordered).
fn to_json(value: Dynamic) -> String {
    serde_json::to_string(&value).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains_ci() {
        assert!(contains_ci("Hello World", "hello"));
        assert!(contains_ci("Hello World", "WORLD"));
        assert!(!contains_ci("Hello World", "foo"));
    }

    #[test]
    fn test_matches_glob() {
        assert!(matches_glob("hello.rs", "*.rs"));
        assert!(matches_glob("src/main.rs", "src/*"));
        assert!(matches_glob("test", "test"));
        assert!(!matches_glob("test.py", "*.rs"));
        assert!(matches_glob("anything", "*"));
        assert!(matches_glob("src/hello/world.rs", "src/*/world.rs"));
    }

    #[test]
    fn test_redact_pii() {
        let input = "Contact user@example.com for info";
        let result = redact_pii(input);
        assert_eq!(result, "Contact [REDACTED:EMAIL_ADDRESS] for info");
        assert!(!result.contains("user@example.com"));
    }

    #[test]
    fn test_redact_pattern() {
        let input = "SSN: 123-45-6789";
        let result = redact_pattern(input, r"\d{3}-\d{2}-\d{4}", "[REDACTED_SSN]");
        assert_eq!(result, "SSN: [REDACTED_SSN]");
    }

    #[test]
    fn test_redact_pattern_invalid_regex() {
        let input = "test";
        let result = redact_pattern(input, "[invalid", "replacement");
        assert_eq!(result, "test"); // returns original on invalid regex
    }

    #[test]
    fn test_parse_int() {
        assert_eq!(parse_int("42").as_int().unwrap(), 42);
        assert!(parse_int("not_a_number").is_unit());
    }

    #[test]
    fn test_parse_json() {
        assert!(parse_json(r#"{"a": 1}"#).is_map());
        assert!(parse_json("[1, 2, 3]").is_array());
        assert_eq!(parse_json("42").as_int().unwrap(), 42);
        assert!(parse_json("3.14").is_float());
        assert!(parse_json("null").is_unit());
        assert!(parse_json("true").as_bool().unwrap());
        assert!(parse_json("{bad json").is_unit()); // malformed → ()
        assert!(parse_json("").is_unit());
    }

    #[test]
    fn test_to_json_roundtrip() {
        let serialized = to_json(parse_json(r#"{"b": 2, "a": [1, 2]}"#));
        // Re-parse and compare structurally — map key order is not preserved.
        let reparsed: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        let expected: serde_json::Value =
            serde_json::from_str(r#"{"a": [1, 2], "b": 2}"#).unwrap();
        assert_eq!(reparsed, expected);
    }

    #[test]
    fn engine_array_join() {
        let engine = create_engine();
        let ast = engine
            .compile(
                r#"
            fn transform(ctx) {
                let arr = ["hello", "world", "!"];
                arr.join(", ")
            }
        "#,
            )
            .unwrap();

        let mut scope = rhai::Scope::new();
        let result: String = engine
            .call_fn(&mut scope, &ast, "transform", (rhai::Dynamic::UNIT,))
            .unwrap();
        assert_eq!(result, "hello, world, !");
    }

    #[test]
    fn engine_compiles_valid_script() {
        let engine = create_engine();
        let result = engine.compile(r#"
            fn transform(ctx) {
                ctx
            }
        "#);
        assert!(result.is_ok());
    }

    #[test]
    fn engine_rejects_invalid_script() {
        let engine = create_engine();
        let result = engine.compile("fn transform(ctx { broken");
        assert!(result.is_err());
    }

    #[test]
    fn engine_enforces_max_operations() {
        let engine = create_engine();
        let ast = engine
            .compile(
                r#"
            fn transform(ctx) {
                let i = 0;
                loop { i += 1; }
                ctx
            }
        "#,
            )
            .unwrap();

        let mut scope = rhai::Scope::new();
        scope.push_dynamic("ctx", rhai::Dynamic::UNIT);
        let result: Result<rhai::Dynamic, _> =
            engine.call_fn(&mut scope, &ast, "transform", (rhai::Dynamic::UNIT,));
        assert!(result.is_err());
    }

    #[test]
    fn engine_helpers_accessible_from_script() {
        let engine = create_engine();
        let ast = engine
            .compile(
                r#"
            fn transform(ctx) {
                let result = contains_ci("Hello World", "hello");
                let masked = redact_pii("test user@foo.com end");
                let n = parse_int("42");
                result
            }
        "#,
            )
            .unwrap();

        let mut scope = rhai::Scope::new();
        let result: bool = engine
            .call_fn(&mut scope, &ast, "transform", (rhai::Dynamic::UNIT,))
            .unwrap();
        assert!(result);
    }

    #[test]
    fn engine_json_helpers_from_script() {
        let engine = create_engine();
        let ast = engine
            .compile(
                r#"
            fn transform(ctx) {
                let parsed = parse_json("{\"items\": \"[1,2,3]\"}");
                let inner = parse_json(parsed["items"]);
                inner.len() == 3 && to_json(inner) == "[1,2,3]"
            }
        "#,
            )
            .unwrap();

        let mut scope = rhai::Scope::new();
        let result: bool = engine
            .call_fn(&mut scope, &ast, "transform", (rhai::Dynamic::UNIT,))
            .unwrap();
        assert!(result);
    }
}

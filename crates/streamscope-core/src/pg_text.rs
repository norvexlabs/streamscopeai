//! Making attacker-chosen text storable in Postgres.
//!
//! Postgres refuses U+0000 everywhere text lives: a `text`/`varchar` bind
//! carrying it fails with `invalid byte sequence for encoding "UTF8": 0x00`,
//! and a `jsonb` value whose string carries the `\u0000` escape fails with
//! `unsupported Unicode escape sequence`. Model output, tool results and
//! upstream bodies can carry a NUL, and one such value rejects the whole
//! statement it rides in — a bulk insert loses every row beside it.
//!
//! The scrub replaces each U+0000 with U+FFFD (the replacement character), so
//! the stored content keeps its length in characters and shows the reader
//! exactly where a character was not storable, instead of losing the value.
//!
//! Properties (locked by `scrub_properties` in this module's tests): the output
//! never contains U+0000; a value without one is returned unchanged; the
//! character count is preserved and every other character is kept in place.
//! Deliberately NOT a property: reversibility — a U+FFFD already present in
//! the input is indistinguishable from a replaced NUL.

/// The character a NUL is replaced with.
pub const NUL_REPLACEMENT: char = '\u{FFFD}';

/// Replace every U+0000 in `s` with [`NUL_REPLACEMENT`]. Returns how many
/// were replaced (0 leaves `s` untouched and allocates nothing).
pub fn scrub_nul_str(s: &mut String) -> usize {
    let n = s.matches('\0').count();
    if n > 0 {
        *s = s.replace('\0', "\u{FFFD}");
    }
    n
}

/// [`scrub_nul_str`] over every string and every object key in a JSON value.
/// Returns how many NULs were replaced in total.
pub fn scrub_nul_json(value: &mut serde_json::Value) -> usize {
    use serde_json::Value;
    match value {
        Value::String(s) => scrub_nul_str(s),
        Value::Array(items) => items.iter_mut().map(scrub_nul_json).sum(),
        Value::Object(map) => {
            let mut n = 0;
            if map.keys().any(|k| k.contains('\0')) {
                let old = std::mem::take(map);
                for (mut k, v) in old {
                    n += scrub_nul_str(&mut k);
                    // Two keys that differ only by a NUL vs. a U+FFFD collapse
                    // to one; the later one wins, as in any JSON object with a
                    // repeated key.
                    map.insert(k, v);
                }
            }
            n + map.values_mut().map(scrub_nul_json).sum::<usize>()
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => 0,
    }
}

/// `s` as Postgres can store it: borrowed unchanged when it holds no U+0000.
pub fn storable_str(s: &str) -> std::borrow::Cow<'_, str> {
    if s.contains('\0') {
        std::borrow::Cow::Owned(s.replace('\0', "\u{FFFD}"))
    } else {
        std::borrow::Cow::Borrowed(s)
    }
}

/// `value` as Postgres can store it: borrowed unchanged when no string or key
/// in it holds U+0000.
pub fn storable_json(value: &serde_json::Value) -> std::borrow::Cow<'_, serde_json::Value> {
    fn has_nul(v: &serde_json::Value) -> bool {
        match v {
            serde_json::Value::String(s) => s.contains('\0'),
            serde_json::Value::Array(a) => a.iter().any(has_nul),
            serde_json::Value::Object(m) => m.iter().any(|(k, v)| k.contains('\0') || has_nul(v)),
            _ => false,
        }
    }
    if has_nul(value) {
        let mut owned = value.clone();
        scrub_nul_json(&mut owned);
        std::borrow::Cow::Owned(owned)
    } else {
        std::borrow::Cow::Borrowed(value)
    }
}

/// Cheap pre-check on raw JSON text: whether it can decode to a string holding
/// U+0000. JSON forbids a raw control character inside a string, so a NUL can
/// only arrive as the `\u0000` escape. The check can say yes for a literal
/// backslash followed by `u0000` — it only decides whether to walk.
pub fn json_text_may_carry_nul(text: &str) -> bool {
    text.contains("\\u0000")
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    #[test]
    fn a_nul_is_replaced_in_strings_keys_and_nested_values() {
        let mut v = json!({
            "a\u{0}b": "x\u{0}y\u{0}",
            "list": ["\u{0}", 1, null, true, {"deep": "z\u{0}"}],
        });
        assert_eq!(scrub_nul_json(&mut v), 5);
        assert_eq!(
            v,
            json!({
                "a\u{FFFD}b": "x\u{FFFD}y\u{FFFD}",
                "list": ["\u{FFFD}", 1, null, true, {"deep": "z\u{FFFD}"}],
            })
        );
    }

    #[test]
    fn a_value_without_a_nul_is_left_alone() {
        let original = json!({"k": ["plain", "caf\u{e9}", "\u{FFFD}"], "n": 3});
        let mut v = original.clone();
        assert_eq!(scrub_nul_json(&mut v), 0);
        assert_eq!(v, original);
    }

    #[test]
    fn the_storable_forms_borrow_what_needs_no_change() {
        use std::assert_matches;
        use std::borrow::Cow;
        assert_matches!(storable_str("clean"), Cow::Borrowed("clean"));
        assert_eq!(storable_str("a\u{0}b"), "a\u{FFFD}b");
        let clean = json!({"k": ["v"]});
        assert_matches!(storable_json(&clean), Cow::Borrowed(_));
        assert_eq!(*storable_json(&json!({"k\u{0}": ["v\u{0}"]})), json!({"k\u{FFFD}": ["v\u{FFFD}"]}));
        // Each place a NUL can hide, on its own.
        assert_eq!(*storable_json(&json!("a\u{0}")), json!("a\u{FFFD}"));
        assert_eq!(*storable_json(&json!(["a\u{0}"])), json!(["a\u{FFFD}"]));
        assert_eq!(*storable_json(&json!({"k": "a\u{0}"})), json!({"k": "a\u{FFFD}"}));
        assert_eq!(*storable_json(&json!({"k\u{0}": 1})), json!({"k\u{FFFD}": 1}));
    }

    #[test]
    fn the_raw_text_check_sees_the_only_spelling_json_has_for_a_nul() {
        let text = serde_json::to_string(&json!({"m": "a\u{0}b"})).unwrap();
        assert!(json_text_may_carry_nul(&text));
        let clean = serde_json::to_string(&json!({"m": "a\u{1}b"})).unwrap();
        assert!(!json_text_may_carry_nul(&clean));
    }

    /// Strings biased toward NULs and the replacement character itself.
    fn text() -> impl Strategy<Value = String> {
        proptest::collection::vec(
            prop_oneof![
                Just('\u{0}'),
                Just('\u{FFFD}'),
                Just('\\'),
                any::<char>(),
            ],
            0..24,
        )
        .prop_map(|cs| cs.into_iter().collect())
    }

    fn json_value() -> impl Strategy<Value = serde_json::Value> {
        let leaf = prop_oneof![
            Just(serde_json::Value::Null),
            any::<bool>().prop_map(serde_json::Value::Bool),
            any::<i64>().prop_map(|n| json!(n)),
            text().prop_map(serde_json::Value::String),
        ];
        leaf.prop_recursive(4, 64, 6, |inner| {
            prop_oneof![
                proptest::collection::vec(inner.clone(), 0..6).prop_map(serde_json::Value::Array),
                proptest::collection::vec((text(), inner), 0..6)
                    .prop_map(|kv| serde_json::Value::Object(kv.into_iter().collect())),
            ]
        })
    }

    fn any_nul(v: &serde_json::Value) -> bool {
        match v {
            serde_json::Value::String(s) => s.contains('\0'),
            serde_json::Value::Array(a) => a.iter().any(any_nul),
            serde_json::Value::Object(m) => m.iter().any(|(k, v)| k.contains('\0') || any_nul(v)),
            _ => false,
        }
    }

    proptest! {
        #[test]
        fn scrub_properties(s in text()) {
            let mut out = s.clone();
            let n = scrub_nul_str(&mut out);
            prop_assert!(!out.contains('\0'));
            prop_assert_eq!(n, s.matches('\0').count());
            prop_assert_eq!(out.chars().count(), s.chars().count());
            for (a, b) in s.chars().zip(out.chars()) {
                prop_assert_eq!(b, if a == '\0' { NUL_REPLACEMENT } else { a });
            }
        }

        #[test]
        fn a_scrubbed_json_value_carries_no_nul_and_serializes_without_the_escape(v in json_value()) {
            let had_nul = any_nul(&v);
            let original = v.clone();
            let mut out = v;
            let n = scrub_nul_json(&mut out);
            prop_assert!(!any_nul(&out));
            prop_assert!(!json_text_may_carry_nul(&serde_json::to_string(&out).unwrap()));
            prop_assert_eq!(n > 0, had_nul);
            if !had_nul {
                prop_assert_eq!(out, original);
            }
        }

        #[test]
        fn the_storable_form_carries_no_nul_and_is_borrowed_exactly_when_there_was_none(v in json_value()) {
            let out = storable_json(&v);
            prop_assert!(!any_nul(&out));
            prop_assert_eq!(matches!(out, std::borrow::Cow::Borrowed(_)), !any_nul(&v));
        }

        #[test]
        fn the_raw_text_check_never_misses_a_nul(v in json_value()) {
            if any_nul(&v) {
                prop_assert!(json_text_may_carry_nul(&serde_json::to_string(&v).unwrap()));
            }
        }
    }
}

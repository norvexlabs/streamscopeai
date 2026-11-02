//! Limits shared by both ends of the edge ⇄ admin-api link.

/// The deepest nesting an edge request may carry. The proxy parses every
/// client body with serde_json's default limit of 128, and an ingest request
/// wraps that content a few levels deeper (request → share → record → message),
/// so admin-api must read past 128 or a request carrying one accepted client
/// body could never parse — never be answered, and stall the outbox for good. 256
/// leaves the proxy's whole range plus the wrapping, and still bounds the
/// recursion a parse of edge-supplied text can take.
pub const EDGE_ENVELOPE_MAX_DEPTH: usize = 256;

/// Whether `json`'s array/object nesting stays within `max` levels. A byte scan
/// that skips string contents (escapes included), so a bracket inside a string
/// never counts. Says nothing about validity — a parse decides that.
pub fn nesting_within(json: &str, max: usize) -> bool {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for b in json.bytes() {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'[' | b'{' => {
                depth += 1;
                if depth > max {
                    return false;
                }
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    true
}

/// Why edge-link JSON did not parse.
#[derive(Debug)]
pub enum EdgeJsonError {
    /// Nested past the bound — refused before any parse.
    TooDeep { max: usize },
    /// Not valid JSON for the expected type.
    Invalid(serde_json::Error),
}

impl std::fmt::Display for EdgeJsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EdgeJsonError::TooDeep { max } => write!(f, "nesting deeper than {max} levels"),
            EdgeJsonError::Invalid(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for EdgeJsonError {}

/// Parse edge-link JSON with the depth bound at [`EDGE_ENVELOPE_MAX_DEPTH`]
/// instead of serde_json's default of 128, which content the proxy accepted
/// can pass once the link wraps it.
pub fn from_str_bounded<T: serde::de::DeserializeOwned>(json: &str) -> Result<T, EdgeJsonError> {
    let max = EDGE_ENVELOPE_MAX_DEPTH;
    if !nesting_within(json, max) {
        return Err(EdgeJsonError::TooDeep { max });
    }
    let mut de = serde_json::Deserializer::from_str(json);
    de.disable_recursion_limit();
    let value = T::deserialize(&mut de).map_err(EdgeJsonError::Invalid)?;
    de.end().map_err(EdgeJsonError::Invalid)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::assert_matches;

    fn nested(depth: usize) -> String {
        format!("{}1{}", "[".repeat(depth), "]".repeat(depth))
    }

    #[test]
    fn the_boundary_is_inclusive_on_both_kinds_of_container() {
        assert!(nesting_within(&nested(256), 256));
        assert!(!nesting_within(&nested(257), 256));
        let objects = format!("{}1{}", "{\"k\":".repeat(3), "}".repeat(3));
        assert!(nesting_within(&objects, 3));
        assert!(!nesting_within(&objects, 2));
    }

    #[test]
    fn the_bounded_parse_reads_past_the_default_and_stops_at_the_bound() {
        assert!(serde_json::from_str::<serde_json::Value>(&nested(200)).is_err());
        assert!(from_str_bounded::<serde_json::Value>(&nested(200)).is_ok());
        assert!(from_str_bounded::<serde_json::Value>(&nested(EDGE_ENVELOPE_MAX_DEPTH)).is_ok());
        assert!(from_str_bounded::<serde_json::Value>(&nested(EDGE_ENVELOPE_MAX_DEPTH + 1)).is_err());
        assert_matches!(
            from_str_bounded::<serde_json::Value>(&nested(EDGE_ENVELOPE_MAX_DEPTH + 1)),
            Err(EdgeJsonError::TooDeep { max: EDGE_ENVELOPE_MAX_DEPTH })
        );
    }

    #[test]
    fn brackets_inside_strings_do_not_count() {
        assert!(nesting_within(r#"["[[[[[", "\"[[[[", "\\"]"#, 1));
        assert!(!nesting_within(r#"["\\", [[]]]"#, 2));
    }

    fn depth_of(v: &serde_json::Value) -> usize {
        match v {
            serde_json::Value::Array(a) => 1 + a.iter().map(depth_of).max().unwrap_or(0),
            serde_json::Value::Object(m) => 1 + m.values().map(depth_of).max().unwrap_or(0),
            _ => 0,
        }
    }

    fn json_value() -> impl Strategy<Value = serde_json::Value> {
        let text = proptest::collection::vec(
            prop_oneof![Just('['), Just(']'), Just('{'), Just('}'), Just('"'), Just('\\'), any::<char>()],
            0..8,
        )
        .prop_map(|cs| cs.into_iter().collect::<String>());
        let leaf = prop_oneof![Just(serde_json::Value::Null), text.clone().prop_map(serde_json::Value::String)];
        leaf.prop_recursive(12, 64, 4, move |inner| {
            prop_oneof![
                proptest::collection::vec(inner.clone(), 0..4).prop_map(serde_json::Value::Array),
                proptest::collection::vec((text.clone(), inner), 0..4)
                    .prop_map(|kv| serde_json::Value::Object(kv.into_iter().collect())),
            ]
        })
    }

    proptest! {
        /// The scan agrees with the parsed tree's depth on every valid document,
        /// whatever brackets and quotes its strings hold.
        #[test]
        fn the_scan_agrees_with_the_parsed_depth(v in json_value()) {
            let json = serde_json::to_string(&v).unwrap();
            let depth = depth_of(&v);
            prop_assert!(nesting_within(&json, depth));
            if depth > 0 {
                prop_assert!(!nesting_within(&json, depth - 1));
            }
        }
    }
}

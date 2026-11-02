//! `serde` helper to distinguish "absent" from "explicit null" in PATCH bodies.
//!
//! `Option<Option<T>>` is the canonical Rust shape for a PATCH field that
//! supports three states:
//!
//! - **absent in JSON** → outer `None` → leave the stored value unchanged
//! - **`null` in JSON** → `Some(None)` → clear the stored value
//! - **value in JSON** → `Some(Some(value))` → set the stored value
//!
//! Without an explicit deserializer, `serde_json`'s default behaviour
//! collapses `"x": null` into outer `None` because the outer `Option`'s
//! `Deserialize` accepts `null` as `None` first. The PATCH handler then
//! reads "absent" and silently skips clearing the field, which is a real
//! data-correctness bug for any operator who tries to drop an `app_filter`
//! / `mcp_server` / `server_type` / etc. via PATCH null.
//!
//! Apply with:
//!
//! ```ignore
//! #[serde(default, deserialize_with = "double_option::deserialize")]
//! pub app_filter: Option<Option<String>>,
//! ```
//!
//! The `default` ensures absent fields deserialize to outer `None`; the
//! `deserialize_with` wraps the inner deserialization in `Some`, so the
//! function only runs when the field is present in the payload and the
//! inner `Option<T>`'s `Deserialize` then maps `null` → inner `None`.

use serde::{Deserialize, Deserializer};

pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// For a PATCH string field whose handler already reads `""` as "clear":
/// an explicit `null` arrives as `Some("")`, so it clears too, while an absent
/// field stays `None`. Apply with `#[serde(default, deserialize_with = …)]`
/// on an `Option<String>`.
pub fn null_as_blank<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(|v| Some(v.unwrap_or_default()))
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq)]
    struct Patch {
        #[serde(default, deserialize_with = "super::deserialize")]
        app_filter: Option<Option<String>>,
        #[serde(default, deserialize_with = "super::null_as_blank")]
        title: Option<String>,
    }

    #[test]
    fn null_as_blank_reads_null_as_the_clearing_blank_and_absent_as_unchanged() {
        let p: Patch = serde_json::from_str(r#"{"title": null}"#).unwrap();
        assert_eq!(p.title, Some(String::new()));
        let p: Patch = serde_json::from_str(r#"{"title": "x"}"#).unwrap();
        assert_eq!(p.title, Some("x".to_string()));
        let p: Patch = serde_json::from_str(r#"{}"#).unwrap();
        assert_eq!(p.title, None);
    }

    /// Every `Option<Option<_>>` field of a deserialized body carries this
    /// module's deserializer. Without it serde reads `null` as absent, so the
    /// field silently cannot be cleared — the type promises three states and
    /// delivers two.
    #[test]
    fn every_three_state_field_can_actually_receive_null() {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).expect("readable src dir").flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }
        let mut files = Vec::new();
        walk(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut files);
        let (mut checked, mut violations) = (0, Vec::new());
        for file in files {
            let text = std::fs::read_to_string(&file).expect("readable source");
            let lines: Vec<&str> = text.lines().collect();
            let mut deserialized = false;
            for (i, line) in lines.iter().enumerate() {
                let t = line.trim_start();
                if t.starts_with("#[derive(") {
                    deserialized = t.contains("Deserialize");
                }
                let is_field = t.starts_with("pub ") || t.split(':').next().is_some_and(|n| {
                    !n.is_empty() && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                });
                if !(deserialized && is_field && t.contains(": Option<Option<")) {
                    continue;
                }
                checked += 1;
                let attrs = lines[..i]
                    .iter()
                    .rev()
                    .take_while(|l| {
                        let l = l.trim_start();
                        l.starts_with("#[") || l.starts_with("///") || l.starts_with("//")
                    })
                    .any(|l| l.contains("double_option::deserialize") || l.contains("super::deserialize"));
                if !attrs {
                    violations.push(format!("{}:{}", file.display(), i + 1));
                }
            }
        }
        assert!(checked > 20, "the scan found only {checked} three-state fields");
        assert!(
            violations.is_empty(),
            "`Option<Option<_>>` without `double_option::deserialize` reads `null` as absent:\n  {}",
            violations.join("\n  ")
        );
    }

    #[test]
    fn absent_field_is_outer_none() {
        let p: Patch = serde_json::from_str(r#"{}"#).unwrap();
        assert_eq!(p.app_filter, None);
    }

    #[test]
    fn null_field_is_some_none() {
        let p: Patch = serde_json::from_str(r#"{"app_filter": null}"#).unwrap();
        assert_eq!(p.app_filter, Some(None));
    }

    #[test]
    fn value_field_is_some_some() {
        let p: Patch = serde_json::from_str(r#"{"app_filter": "claude-*"}"#).unwrap();
        assert_eq!(p.app_filter, Some(Some("claude-*".to_string())));
    }

    #[test]
    fn empty_string_is_some_some_empty() {
        let p: Patch = serde_json::from_str(r#"{"app_filter": ""}"#).unwrap();
        assert_eq!(p.app_filter, Some(Some(String::new())));
    }
}

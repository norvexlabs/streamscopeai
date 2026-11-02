//! Line-preserving `KEY=VALUE` env-file merge (Gemini CLI's `~/.gemini/.env`).
//! Comments and unknown lines are kept verbatim; our keys are updated in
//! place or appended. Ownership paths are the variable names.

use anyhow::{bail, Result};

use super::MergeOutcome;
use crate::state::{sha256_hex, OwnedLeaf};

pub fn merge(
    existing: Option<&str>,
    rendered: &str,
    prev_owned: &[OwnedLeaf],
) -> Result<MergeOutcome> {
    // Parse the rendered body into ordered (key, value) pairs.
    let mut pairs: Vec<(String, String)> = Vec::new();
    for line in rendered.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            bail!("rendered env content has a non KEY=VALUE line: {line:?}");
        };
        pairs.push((k.trim().to_string(), v.trim().to_string()));
    }

    let owned: Vec<OwnedLeaf> = pairs
        .iter()
        .map(|(k, v)| OwnedLeaf {
            path: k.clone(),
            entry: None,
            value_hash: sha256_hex(v.as_bytes()),
        })
        .collect();

    let mut lines: Vec<String> = existing
        .map(|s| s.lines().map(str::to_string).collect())
        .unwrap_or_default();

    let key_of = |line: &str| -> Option<String> {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            return None;
        }
        t.split_once('=').map(|(k, _)| k.trim().to_string())
    };
    let value_of = |line: &str| -> Option<String> {
        line.trim().split_once('=').map(|(_, v)| v.trim().to_string())
    };

    // Update in place / append. A paste-me sentinel never overwrites a value
    // the user already filled in.
    for (k, v) in &pairs {
        match lines.iter_mut().find(|l| key_of(l).as_deref() == Some(k)) {
            Some(line) => {
                let current = value_of(line).unwrap_or_default();
                if !(super::is_paste_sentinel(v) && current != *v) {
                    *line = format!("{k}={v}");
                }
            }
            None => lines.push(format!("{k}={v}")),
        }
    }

    // Removal of previously-owned keys that left the render — unedited only.
    let mut kept_edited = Vec::new();
    for prev in prev_owned {
        if owned.iter().any(|o| o.path == prev.path) {
            continue;
        }
        let Some(idx) = lines
            .iter()
            .position(|l| key_of(l).as_deref() == Some(prev.path.as_str()))
        else {
            continue;
        };
        let current = value_of(&lines[idx]).unwrap_or_default();
        if sha256_hex(current.as_bytes()) == prev.value_hash {
            lines.remove(idx);
        } else {
            kept_edited.push(prev.path.clone());
        }
    }

    let mut contents = lines.join("\n");
    if !contents.is_empty() && !contents.ends_with('\n') {
        contents.push('\n');
    }
    Ok(MergeOutcome {
        contents,
        owned,
        kept_edited,
    })
}

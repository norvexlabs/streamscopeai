//! YAML deep-merge with JSON-pointer-style ownership tracking (Aider's
//! `~/.aider.conf.yml`, Continue's `~/.continue/config.yaml`).
//!
//! Mirrors the JSON writer's semantics: mappings merge recursively, scalars
//! and sequences from the render replace wholesale (a keyed sequence merges
//! entry by entry), paste-me sentinels never
//! clobber a user-filled value, and owned leaves that left the render are
//! removed only while unedited. One honest difference, surfaced in the docs:
//! the YAML round-trip is value-level (`yaml_serde`), so the user's
//! **comments and formatting are not preserved** — unlike the TOML writer,
//! which edits the document in place.

use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use yaml_serde::{Mapping, Value};
use streamscope_client_templates::{composite_identity, scalar_identity, string_entry_identity, STRING_ENTRIES};

use super::{
    escape_token, is_keyed_record, keyed_jobs, merge_entries, unescape_token, KeyedEntry, MergeOutcome,
};
use crate::state::{sha256_hex, OwnedLeaf};

pub fn merge(
    existing: Option<&str>,
    rendered: &str,
    prev_owned: &[OwnedLeaf],
    keyed_arrays: &BTreeMap<String, String>,
) -> Result<MergeOutcome> {
    let mut rendered_v: Value =
        yaml_serde::from_str(rendered).context("rendered config is not valid YAML")?;
    if !rendered_v.is_mapping() {
        bail!("rendered YAML config must be a mapping");
    }
    let mut doc: Value = match existing {
        Some(s) if !s.trim().is_empty() => yaml_serde::from_str(s).context(
            "the existing config file is not valid YAML — fix or remove it, then re-run",
        )?,
        _ => Value::Mapping(Mapping::new()),
    };
    if !doc.is_mapping() {
        bail!("the existing config file is not a YAML mapping");
    }

    // A keyed sequence leaves the render before the leaf merge, exactly as in
    // the JSON writer.
    let declared: Vec<(String, String)> =
        keyed_arrays.iter().map(|(p, k)| (p.clone(), k.clone())).collect();
    let mut keyed = Vec::new();
    for (pointer, key, is_declared) in keyed_jobs(&declared, prev_owned) {
        let entries = if !is_declared {
            Vec::new()
        } else {
            match take_pointer(&mut rendered_v, &pointer) {
                None | Some(Value::Null) => Vec::new(),
                Some(Value::Sequence(entries)) => entries,
                Some(_) => bail!("the render puts something other than a sequence at `{pointer}`"),
            }
        };
        keyed.push((pointer, key, is_declared, entries));
    }
    let keyed_paths: Vec<String> = keyed_arrays.keys().cloned().collect();

    let mut owned: Vec<OwnedLeaf> = Vec::new();
    collect_leaves("", &rendered_v, &mut owned);

    merge_value(&mut doc, &rendered_v);

    let mut kept_edited = Vec::new();
    for prev in prev_owned {
        if is_keyed_record(prev, &keyed_paths) || owned.iter().any(|o| o.path == prev.path) {
            continue;
        }
        match lookup(&doc, &prev.path) {
            None => {}
            Some(cur) => {
                if value_hash(cur) == prev.value_hash {
                    remove_pointer(&mut doc, &prev.path);
                } else {
                    kept_edited.push(prev.path.clone());
                }
            }
        }
    }

    for (pointer, key, is_declared, rendered_entries) in keyed {
        if !is_declared && owned.iter().any(|o| o.entry.is_none() && o.path == pointer) {
            continue;
        }
        let live = lookup(&doc, &pointer);
        let whole_array = prev_owned
            .iter()
            .find(|p| is_declared && p.path == pointer && p.entry.is_none())
            .and_then(|p| live.map(|v| value_hash(v) == p.value_hash));
        let existing_entries = match live {
            Some(Value::Sequence(entries)) => entries.clone(),
            // One string where a list of them is expected (`set-env: A=1`):
            // the user's single entry.
            Some(v @ Value::String(_)) if key == STRING_ENTRIES => vec![v.clone()],
            // The user's own value; with nothing of ours to place, it stays.
            Some(v) if !v.is_null() && rendered_entries.is_empty() => continue,
            _ => Vec::new(),
        };
        let was_sequence = matches!(live, Some(Value::Sequence(_)));
        let out = merge_entries(&pointer, &key, existing_entries, rendered_entries, prev_owned, whole_array)?;
        owned.extend(out.owned);
        kept_edited.extend(out.kept_edited);
        if !out.entries.is_empty() {
            set_pointer(&mut doc, &pointer, Value::Sequence(out.entries));
        } else if was_sequence && out.removed {
            remove_pointer(&mut doc, &pointer);
        }
    }

    let contents =
        yaml_serde::to_string(&doc).context("failed to serialize the merged YAML")?;
    Ok(MergeOutcome {
        contents,
        owned,
        kept_edited,
    })
}

impl KeyedEntry for Value {
    fn identity(&self, key: &str) -> Option<String> {
        // Only the identity field is read: the rest of a user's entry may hold
        // YAML that JSON cannot express (a non-string mapping key).
        if key == STRING_ENTRIES {
            return self.as_str().map(|s| string_entry_identity(s).to_string());
        }
        let map = self.as_mapping()?;
        composite_identity(key, |field| scalar_identity(&serde_json::to_value(map.get(field)?).ok()?))
    }

    fn entry_hash(&self) -> String {
        value_hash(self)
    }

    fn replace_with(&mut self, rendered: &Self) {
        let live = std::mem::replace(self, rendered.clone());
        keep_filled_sentinels(self, &live);
    }
}

/// Put back, under `new`, every value the user filled in over a paste sentinel
/// that `new` still carries — same rule as the JSON writer's.
fn keep_filled_sentinels(new: &mut Value, live: &Value) {
    let (Value::Mapping(new), Value::Mapping(live)) = (new, live) else { return };
    for (k, nv) in new.iter_mut() {
        let Some(lv) = live.get(k) else { continue };
        if nv.as_str().is_some_and(super::is_paste_sentinel) {
            if lv != nv {
                *nv = lv.clone();
            }
        } else {
            keep_filled_sentinels(nv, lv);
        }
    }
}

fn value_hash(v: &Value) -> String {
    sha256_hex(yaml_serde::to_string(v).unwrap_or_default().as_bytes())
}

/// A mapping recurses only while every key is a string (real-world tool
/// configs are string-keyed; anything fancier is treated as one opaque leaf
/// and replaced wholesale).
fn string_keyed(map: &Mapping) -> bool {
    map.keys().all(|k| k.is_string())
}

/// Whether a value merges recursively (string-keyed mapping) rather than
/// replacing wholesale.
fn mergeable(v: &Value) -> bool {
    matches!(v, Value::Mapping(m) if string_keyed(m))
}

fn collect_leaves(prefix: &str, v: &Value, out: &mut Vec<OwnedLeaf>) {
    match v {
        Value::Mapping(map) if string_keyed(map) => {
            for (k, child) in map {
                let key = k.as_str().unwrap_or_default();
                let path = format!("{prefix}/{}", escape_token(key));
                collect_leaves(&path, child, out);
            }
        }
        leaf => out.push(OwnedLeaf {
            path: prefix.to_string(),
            entry: None,
            value_hash: value_hash(leaf),
        }),
    }
}

/// String-keyed mappings merge recursively; everything else (scalars,
/// sequences, null, exotic mappings) replaces the existing value wholesale —
/// EXCEPT a paste-me sentinel, which never overwrites a value the user
/// already filled in.
fn merge_value(dst: &mut Value, src: &Value) {
    match (dst, src) {
        (Value::Mapping(d), Value::Mapping(s)) if string_keyed(s) => {
            for (k, sv) in s {
                match d.get_mut(k) {
                    Some(dv) if mergeable(dv) && mergeable(sv) => merge_value(dv, sv),
                    Some(dv)
                        if matches!(sv, Value::String(s) if super::is_paste_sentinel(s))
                            && dv != sv => {}
                    // Don't introduce an empty mapping the target lacks — it would
                    // linger untracked (`collect_leaves` records no leaf for it),
                    // mirroring the JSON writer's empty-object guard.
                    None if matches!(sv, Value::Mapping(m) if m.is_empty()) => {}
                    _ => {
                        d.insert(k.clone(), sv.clone());
                    }
                }
            }
        }
        (dst, src) => *dst = src.clone(),
    }
}

fn lookup<'a>(doc: &'a Value, pointer: &str) -> Option<&'a Value> {
    let mut cur = doc;
    for token in pointer.split('/').skip(1) {
        let key = Value::String(unescape_token(token));
        cur = cur.as_mapping()?.get(&key)?;
    }
    Some(cur)
}

/// Remove the leaf at `pointer`, then prune ancestor mappings the removal
/// emptied — same contract as the JSON writer.
fn remove_pointer(doc: &mut Value, pointer: &str) {
    let tokens: Vec<String> = pointer.split('/').skip(1).map(unescape_token).collect();
    if tokens.is_empty() {
        return;
    }
    remove_recursive(doc, &tokens);
}

fn remove_recursive(v: &mut Value, tokens: &[String]) -> bool {
    let Value::Mapping(map) = v else { return false };
    let key = Value::String(tokens[0].clone());
    if tokens.len() == 1 {
        map.remove(&key);
        return map.is_empty();
    }
    if let Some(child) = map.get_mut(&key)
        && remove_recursive(child, &tokens[1..])
    {
        map.remove(&key);
    }
    map.is_empty()
}

/// Detach and return the value at `pointer`, leaving its parents in place.
fn take_pointer(doc: &mut Value, pointer: &str) -> Option<Value> {
    let tokens: Vec<String> = pointer.split('/').skip(1).map(unescape_token).collect();
    let (last, parents) = tokens.split_last()?;
    let mut cur = doc;
    for token in parents {
        cur = cur.as_mapping_mut()?.get_mut(token.as_str())?;
    }
    cur.as_mapping_mut()?.remove(last.as_str())
}

/// Write `value` at `pointer`, creating the mappings above it — same contract
/// as the JSON writer's.
fn set_pointer(doc: &mut Value, pointer: &str, value: Value) {
    let tokens: Vec<String> = pointer.split('/').skip(1).map(unescape_token).collect();
    let Some((last, parents)) = tokens.split_last() else { return };
    let mut cur = doc;
    for token in parents {
        let Some(map) = cur.as_mapping_mut() else { return };
        let key = Value::String(token.clone());
        if !map.get(&key).is_some_and(Value::is_mapping) {
            map.insert(key.clone(), Value::Mapping(Mapping::new()));
        }
        let Some(child) = map.get_mut(&key) else { return };
        cur = child;
    }
    if let Some(map) = cur.as_mapping_mut() {
        map.insert(Value::String(last.clone()), value);
    }
}

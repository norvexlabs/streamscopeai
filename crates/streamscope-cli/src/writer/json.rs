//! JSON deep-merge with JSON-pointer ownership tracking.

use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use jsonc_parser::cst::{CstArray, CstInputValue, CstNode, CstObject, CstRootNode};
use jsonc_parser::ParseOptions;
use serde_json::{Map, Value};
use streamscope_client_templates::{keyed_entry_identity, STRING_ENTRIES};

use super::{
    escape_token, is_keyed_record, is_what_we_wrote, keyed_jobs, merge_entries, unescape_token, withdraw_from,
    KeyedEntry, MergeOutcome,
};
use crate::state::{sha256_hex, EntryRoot, OwnedLeaf};

pub fn merge(
    existing: Option<&str>,
    rendered: &str,
    prev_owned: &[OwnedLeaf],
    keyed_arrays: &BTreeMap<String, String>,
    withdraw: &[EntryRoot],
) -> Result<MergeOutcome> {
    let mut rendered_v: Value =
        serde_json::from_str(rendered).context("rendered config is not valid JSON")?;
    if !rendered_v.is_object() {
        bail!("rendered JSON config must be an object");
    }
    let existing = existing.filter(|s| !s.trim().is_empty());
    // A file strict JSON refuses but JSONC reads (comments, trailing commas)
    // is edited in place through its syntax tree, so what the user wrote
    // around our keys stays; strict JSON is re-printed whole.
    let jsonc = existing.filter(|s| serde_json::from_str::<Value>(s).is_err());
    let mut doc: Value = match existing.map(parse_jsonc).transpose().context(
        "the existing config file is not valid JSON, even allowing comments and trailing commas — fix or remove it, then re-run",
    )? {
        // Comments and nothing else: an empty config, the comments kept.
        Some(Value::Null) if jsonc.is_some() => Value::Object(Default::default()),
        Some(v) => v,
        None => Value::Object(Default::default()),
    };
    if !doc.is_object() {
        bail!("the existing config file is not a JSON object");
    }
    let before = jsonc.map(|_| doc.clone());
    let (prev_owned, withdrawn) =
        withdraw_from(streamscope_client_templates::TemplateFormat::Json, &mut doc, prev_owned, withdraw, remove_root);
    let prev_owned = prev_owned.as_slice();

    // A keyed array leaves the render before the leaf merge: its entries are
    // merged one by one below, never replaced as one leaf.
    let declared: Vec<(String, String)> =
        keyed_arrays.iter().map(|(p, k)| (p.clone(), k.clone())).collect();
    let mut keyed = Vec::new();
    for (pointer, key, is_declared) in keyed_jobs(&declared, prev_owned) {
        let entries = if !is_declared {
            Vec::new()
        } else {
            match take_pointer(&mut rendered_v, &pointer) {
                None | Some(Value::Null) => Vec::new(),
                Some(Value::Array(entries)) => entries,
                Some(_) => bail!("the render puts something other than an array at `{pointer}`"),
            }
        };
        keyed.push((pointer, key, is_declared, entries));
    }
    let keyed_paths: Vec<String> = keyed_arrays.keys().cloned().collect();

    // Collect the leaves the render contributes (arrays and scalars are
    // leaves; objects recurse).
    let mut owned: Vec<OwnedLeaf> = Vec::new();
    collect_leaves("", &rendered_v, &mut owned);

    merge_value(&mut doc, &rendered_v, "", prev_owned);

    // Remove leaves we owned that left the render — only when unedited.
    let mut kept_edited = Vec::new();
    for prev in prev_owned {
        if is_keyed_record(prev, &keyed_paths) || owned.iter().any(|o| o.path == prev.path) {
            continue;
        }
        match doc.pointer(&prev.path) {
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
        let live = doc.pointer(&pointer);
        let whole_array = prev_owned
            .iter()
            .find(|p| is_declared && p.path == pointer && p.entry.is_none())
            .and_then(|p| live.map(|v| value_hash(v) == p.value_hash));
        let existing_entries = match live {
            Some(Value::Array(entries)) => entries.clone(),
            // One string where a list of them is expected: the user's single entry.
            Some(v @ Value::String(_)) if key == STRING_ENTRIES => vec![v.clone()],
            // The user's own value; with nothing of ours to place, it stays.
            Some(v) if !v.is_null() && rendered_entries.is_empty() => continue,
            _ => Vec::new(),
        };
        let was_array = matches!(live, Some(Value::Array(_)));
        let out = merge_entries(&pointer, &key, existing_entries, rendered_entries, prev_owned, whole_array)?;
        owned.extend(out.owned);
        kept_edited.extend(out.kept_edited);
        if !out.entries.is_empty() {
            set_pointer(&mut doc, &pointer, Value::Array(out.entries));
        } else if was_array && out.removed {
            remove_pointer(&mut doc, &pointer);
        }
    }

    let contents = match (jsonc, &before) {
        (Some(text), Some(before)) => edit_in_place(text, before, &doc)?,
        _ => format!("{}\n", serde_json::to_string_pretty(&doc)?),
    };
    Ok(MergeOutcome {
        contents,
        owned,
        kept_edited,
        withdrawn,
    })
}

/// Take the entry at `root` out of `doc`; `false` when nothing stood there.
/// A keyed array emptied by it goes too, as one emptied by a re-render does.
fn remove_root(doc: &mut Value, root: &EntryRoot) -> bool {
    let Some(entry) = &root.entry else {
        if doc.pointer(&root.path).is_none() {
            return false;
        }
        remove_pointer(doc, &root.path);
        return true;
    };
    let Some(Value::Array(entries)) = doc.pointer_mut(&root.path) else { return false };
    let Some(i) = entries.iter().position(|e| e.identity(&entry.key).as_deref() == Some(entry.id.as_str())) else {
        return false;
    };
    entries.remove(i);
    if entries.is_empty() {
        remove_pointer(doc, &root.path);
    }
    true
}

/// Whether something stands at `root` in the file `existing`.
pub(super) fn holds(existing: &str, root: &EntryRoot) -> Result<bool> {
    let mut doc = parse_jsonc(existing).context("the existing config file is not valid JSON")?;
    Ok(remove_root(&mut doc, root))
}

impl KeyedEntry for Value {
    fn identity(&self, key: &str) -> Option<String> {
        keyed_entry_identity(self, key)
    }

    fn entry_hash(&self) -> String {
        value_hash(self)
    }

    fn replace_with(&mut self, rendered: &Self, keep_filled: bool) {
        let live = std::mem::replace(self, rendered.clone());
        if keep_filled {
            keep_filled_sentinels(self, &live);
        }
    }
}

/// Put back, under `new`, every value the user filled in over a paste sentinel
/// that `new` still carries — the leaf rule of [`merge_value`], for a value
/// that is replaced whole.
fn keep_filled_sentinels(new: &mut Value, live: &Value) {
    let (Value::Object(new), Value::Object(live)) = (new, live) else { return };
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
    sha256_hex(serde_json::to_string(v).unwrap_or_default().as_bytes())
}

fn collect_leaves(prefix: &str, v: &Value, out: &mut Vec<OwnedLeaf>) {
    match v {
        Value::Object(map) => {
            for (k, child) in map {
                let path = format!("{prefix}/{}", escape_token(k));
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

/// Objects merge recursively; everything else (scalars, arrays, null)
/// replaces the existing value wholesale — EXCEPT a paste-me sentinel, which
/// never overwrites a value the user already filled in: it replaces only the
/// value `prev_owned` records the last run wrote at that path (`prefix` is
/// the pointer of `dst`).
///
/// A render that contributes an EMPTY object under a key the target doesn't
/// already have (e.g. `{"mcpServers": {}}` from a client provisioned with zero
/// MCP servers) is NOT introduced: `collect_leaves` records no leaf for an empty
/// object, so a written `{}` could never be tracked and would linger in the
/// user's config forever once the block left the render. Skipping the insert
/// keeps the writers' "fully-unprovisioned block doesn't linger" contract; an
/// empty object under a key that already exists still recurses below (merging
/// nothing, preserving the user's value).
fn merge_value(dst: &mut Value, src: &Value, prefix: &str, prev_owned: &[OwnedLeaf]) {
    match (dst, src) {
        (Value::Object(d), Value::Object(s)) => {
            for (k, sv) in s {
                let path = format!("{prefix}/{}", escape_token(k));
                match d.get_mut(k) {
                    Some(dv) if dv.is_object() && sv.is_object() => merge_value(dv, sv, &path, prev_owned),
                    Some(dv)
                        if matches!(sv, Value::String(s) if super::is_paste_sentinel(s))
                            && dv != sv
                            && !is_what_we_wrote(prev_owned, &path, &value_hash(dv)) => {}
                    None if matches!(sv, Value::Object(m) if m.is_empty()) => {}
                    _ => {
                        d.insert(k.clone(), sv.clone());
                    }
                }
            }
        }
        (dst, src) => *dst = src.clone(),
    }
}

/// Remove the leaf at `pointer`, then prune ancestor objects the removal
/// emptied (so a fully-unprovisioned `mcpServers` block doesn't linger as
/// `{}`). Only ancestors along the removed path are pruned — a user's own
/// pre-existing empty objects elsewhere are untouched.
fn remove_pointer(doc: &mut Value, pointer: &str) {
    let tokens: Vec<String> = pointer.split('/').skip(1).map(unescape_token).collect();
    if tokens.is_empty() {
        return;
    }
    remove_recursive(doc, &tokens);
}

/// Returns `true` when the child was removed AND the current object became
/// empty (signal to the parent to prune it too).
fn remove_recursive(v: &mut Value, tokens: &[String]) -> bool {
    let Value::Object(map) = v else { return false };
    if tokens.len() == 1 {
        map.remove(&tokens[0]);
        return map.is_empty();
    }
    if let Some(child) = map.get_mut(&tokens[0])
        && remove_recursive(child, &tokens[1..])
    {
        map.remove(&tokens[0]);
    }
    map.is_empty()
}

/// Detach and return the value at `pointer`, leaving its parents in place.
fn take_pointer(doc: &mut Value, pointer: &str) -> Option<Value> {
    let tokens: Vec<String> = pointer.split('/').skip(1).map(unescape_token).collect();
    let (last, parents) = tokens.split_last()?;
    let mut cur = doc;
    for token in parents {
        cur = cur.get_mut(token)?;
    }
    cur.as_object_mut()?.remove(last)
}

/// Write `value` at `pointer`, creating the objects above it. A parent that is
/// not an object is replaced by one — the render decides that path's shape, as
/// it does for any leaf it contributes.
fn set_pointer(doc: &mut Value, pointer: &str, value: Value) {
    let tokens: Vec<String> = pointer.split('/').skip(1).map(unescape_token).collect();
    let Some((last, parents)) = tokens.split_last() else { return };
    let mut cur = doc;
    for token in parents {
        let Some(map) = cur.as_object_mut() else { return };
        let child = map.entry(token.clone()).or_insert_with(|| Value::Object(Default::default()));
        if !child.is_object() {
            *child = Value::Object(Default::default());
        }
        cur = child;
    }
    if let Some(map) = cur.as_object_mut() {
        map.insert(last.clone(), value);
    }
}

/// What the tools reading JSONC accept beyond JSON: comments and trailing
/// commas — nothing looser, so a file reads here as it reads in the tool.
fn jsonc_options() -> ParseOptions {
    ParseOptions {
        allow_comments: true,
        allow_trailing_commas: true,
        allow_loose_object_property_names: false,
        allow_missing_commas: false,
        allow_single_quoted_strings: false,
        allow_hexadecimal_numbers: false,
        allow_unary_plus_numbers: false,
        allow_bare_decimal_point_numbers: false,
        allow_extended_string_escapes: false,
        allow_non_finite_numbers: false,
    }
}

/// A JSON or JSONC document's value.
pub fn parse_jsonc(text: &str) -> Result<Value> {
    jsonc_parser::parse_to_serde_value(text, &jsonc_options()).map_err(|e| anyhow::anyhow!("{e}"))
}

/// `text` (whose value is `before`) edited so its value becomes `after`,
/// touching only the members that differ: comments, layout and the order of
/// the user's keys stay. The result is read back and must carry `after`
/// exactly — a key the tree cannot address the way the value does (a key
/// repeated in the file) refuses the write instead of saving something else.
fn edit_in_place(text: &str, before: &Value, after: &Value) -> Result<String> {
    let root = CstRootNode::parse(text, &jsonc_options()).map_err(|e| anyhow::anyhow!("{e}"))?;
    let (Value::Object(before), Value::Object(after)) = (before, after) else {
        bail!("the existing config file is not a JSON object");
    };
    // The root object, created among the comments of a file holding no value.
    let obj = root.object_value_or_set();
    edit_object(&obj, before, after);
    let mut out = root.to_string();
    if !out.ends_with('\n') {
        out.push('\n');
    }
    if parse_jsonc(&out).ok().as_ref() != Some(&Value::Object(after.clone())) {
        bail!("the existing config file cannot be edited in place (is a key repeated?) — fix it, then re-run");
    }
    Ok(out)
}

fn edit_object(obj: &CstObject, before: &Map<String, Value>, after: &Map<String, Value>) {
    for key in before.keys().filter(|k| !after.contains_key(*k)) {
        if let Some(prop) = obj.get(key) {
            prop.remove();
        }
    }
    for (key, new) in after {
        let prop = obj.get(key);
        match (before.get(key), prop) {
            (Some(old), Some(_)) if old == new => {}
            (Some(Value::Object(old)), Some(prop)) if new.is_object() => match (prop.object_value(), new) {
                (Some(child), Value::Object(new)) => edit_object(&child, old, new),
                _ => prop.set_value(input(new)),
            },
            (Some(Value::Array(old)), Some(prop)) if new.is_array() => match (prop.array_value(), new) {
                (Some(child), Value::Array(new)) => edit_array(&child, old, new),
                _ => prop.set_value(input(new)),
            },
            (_, Some(prop)) => prop.set_value(input(new)),
            (_, None) => {
                obj.append(key, input(new));
            }
        }
    }
}

/// `arr` (whose elements are `before`) edited to hold `after`: the longest run
/// of elements both share in order stays untouched, with its comments; between
/// two of them, elements at the same place are edited into each other when both
/// are objects or arrays, the rest removed or inserted.
fn edit_array(arr: &CstArray, before: &[Value], after: &[Value]) {
    let nodes = arr.elements();
    if nodes.len() != before.len() {
        // The tree and the value disagree (cannot happen for a parsed file);
        // the read-back check refuses whatever this writes.
        return;
    }
    // Longest common subsequence, by value.
    let (n, m) = (before.len(), after.len());
    let mut lcs = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if before[i] == after[j] { lcs[i + 1][j + 1] + 1 } else { lcs[i + 1][j].max(lcs[i][j + 1]) };
        }
    }
    let mut anchors = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if before[i] == after[j] {
            anchors.push((i, j));
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            i += 1;
        } else {
            j += 1;
        }
    }
    anchors.push((n, m));
    let mut at = 0; // the element index the next kept or written element takes
    let (mut i, mut j) = (0, 0);
    for (ai, aj) in anchors {
        let (olds, news) = (ai - i, aj - j);
        for k in 0..olds.max(news) {
            let node = (k < olds).then(|| nodes[i + k].clone());
            match (node, after.get(j + k).filter(|_| k < news)) {
                (Some(node), Some(new)) => {
                    edit_element(arr, node, &before[i + k], new, at);
                    at += 1;
                }
                (Some(node), None) => node.remove(),
                (None, Some(new)) => {
                    arr.insert(at, input(new));
                    at += 1;
                }
                (None, None) => {}
            }
        }
        if ai < n {
            at += 1; // the shared element stays as it is
        }
        (i, j) = (ai + 1, aj + 1);
    }
}

/// The element `node` (value `old`) at index `at` of `arr` turned into `new`.
fn edit_element(arr: &CstArray, node: CstNode, old: &Value, new: &Value, at: usize) {
    match (old, new, node.as_object(), node.as_array()) {
        (Value::Object(old), Value::Object(new), Some(obj), _) => edit_object(&obj, old, new),
        (Value::Array(old), Value::Array(new), _, Some(child)) => edit_array(&child, old, new),
        _ => {
            node.remove();
            arr.insert(at, input(new));
        }
    }
}

fn input(v: &Value) -> CstInputValue {
    match v {
        Value::Null => CstInputValue::Null,
        Value::Bool(b) => CstInputValue::Bool(*b),
        Value::Number(n) => CstInputValue::Number(n.to_string()),
        Value::String(s) => CstInputValue::String(s.clone()),
        Value::Array(items) => CstInputValue::Array(items.iter().map(input).collect()),
        Value::Object(map) => CstInputValue::Object(map.iter().map(|(k, v)| (k.clone(), input(v))).collect()),
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use serde_json::{json, Map, Value};

    use super::{edit_in_place, parse_jsonc};

    fn leaf() -> impl Strategy<Value = Value> {
        prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            (-1000i64..1000).prop_map(|n| json!(n)),
            "[a-z/*\" ,]{0,6}".prop_map(Value::String),
        ]
    }

    fn tree() -> impl Strategy<Value = Value> {
        leaf().prop_recursive(3, 24, 4, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..3).prop_map(Value::Array),
                prop::collection::btree_map("[a-d]", inner, 0..4)
                    .prop_map(|m| Value::Object(m.into_iter().collect::<Map<_, _>>())),
            ]
        })
    }

    fn object() -> impl Strategy<Value = Value> {
        prop::collection::btree_map("[a-d]", tree(), 0..4).prop_map(|m| Value::Object(m.into_iter().collect()))
    }

    /// JSONC text for `v`: a line comment before every member and element, a
    /// block comment after it, and a trailing comma in every container.
    fn commented(v: &Value) -> String {
        match v {
            Value::Object(m) => {
                let mut s = String::from("{\n");
                for (k, v) in m {
                    s += &format!("// about {k}\n{}: {} /* end {k} */,\n", json!(k), commented(v));
                }
                s + "}"
            }
            Value::Array(items) => {
                let mut s = String::from("[\n");
                for v in items {
                    s += &format!("// item\n{},\n", commented(v));
                }
                s + "]"
            }
            leaf => leaf.to_string(),
        }
    }

    proptest! {
        /// An element both arrays hold keeps its comments when others around
        /// it are added, removed or changed — and no comment is ever dropped:
        /// the gateway writes none, so every one is the user's.
        #[test]
        fn a_kept_array_element_keeps_its_comments(
            items in prop::collection::btree_set(0u16..50, 1..6),
            added in prop::collection::btree_set(50u16..99, 0..3),
            drop_first in any::<bool>(),
        ) {
            let items: Vec<u16> = items.into_iter().collect();
            let before = json!({"list": items.iter().map(|n| json!({"id": n})).collect::<Vec<_>>()});
            let kept: Vec<u16> = items.iter().copied().skip(usize::from(drop_first && items.len() > 1)).collect();
            let mut new: Vec<Value> = kept.iter().map(|n| json!({"id": n})).collect();
            new.extend(added.iter().map(|n| json!({"id": n})));
            let after = json!({"list": new});
            let text = commented(&before);
            let out = edit_in_place(&text, &before, &after).unwrap();
            prop_assert_eq!(parse_jsonc(&out).unwrap(), after);
            prop_assert_eq!(out.matches("// item").count(), items.len(), "{}", out);
            for n in &kept {
                let element = format!("// item\n{{\n// about id\n\"id\": {n} /* end id */,\n}}");
                prop_assert!(out.contains(&element), "element {} lost its comments:\n{}", n, out);
            }
        }

        /// The edit is exact: whatever the two values, the edited text reads
        /// back as the new one — never a merge of both, never the old one.
        #[test]
        fn an_edited_jsonc_file_reads_back_as_the_new_value(before in object(), after in object()) {
            let text = commented(&before);
            prop_assert_eq!(parse_jsonc(&text).unwrap(), before.clone());
            let out = edit_in_place(&text, &before, &after).unwrap();
            prop_assert_eq!(parse_jsonc(&out).unwrap(), after);
        }

        /// A member the edit does not change keeps its comments: only what
        /// differs is rewritten.
        #[test]
        fn an_unchanged_member_keeps_its_comments(before in object(), extra in tree()) {
            let Value::Object(map) = &before else { unreachable!() };
            let mut after = map.clone();
            after.insert("z".into(), extra);
            let text = commented(&before);
            let out = edit_in_place(&text, &before, &Value::Object(after)).unwrap();
            for k in map.keys() {
                let about = format!("// about {k}\n");
                let end = format!("/* end {k} */");
                prop_assert!(out.contains(&about) && out.contains(&end), "comments of {} lost:\n{}", k, out);
            }
        }
    }
}

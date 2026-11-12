//! TOML merge via `toml_edit` — preserves the user's comments and layout.
//! Tables merge recursively; values, inline tables, and arrays(-of-tables)
//! replace wholesale — except a keyed array of tables, merged entry by entry.
//! Ownership paths are dotted key chains.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use toml_edit::{ArrayOfTables, DocumentMut, Item, Table, TableLike};

use super::{
    is_keyed_record, is_what_we_wrote, keyed_jobs, merge_entries, unescape_token, withdraw_from, KeyedEntry,
    MergeOutcome,
};
use crate::state::{sha256_hex, EntryRoot, OwnedLeaf};

pub fn merge(
    existing: Option<&str>,
    rendered: &str,
    prev_owned: &[OwnedLeaf],
    keyed_arrays: &BTreeMap<String, String>,
    withdraw: &[EntryRoot],
) -> Result<MergeOutcome> {
    let mut rendered_doc: DocumentMut = rendered
        .parse()
        .context("rendered config is not valid TOML")?;
    let mut doc: DocumentMut = match existing {
        Some(s) if !s.trim().is_empty() => s.parse().context(
            "the existing config file is not valid TOML — fix or remove it, then re-run",
        )?,
        _ => DocumentMut::new(),
    };
    let (prev_owned, withdrawn) =
        withdraw_from(streamscope_client_templates::TemplateFormat::Toml, &mut doc, prev_owned, withdraw, remove_root);
    let prev_owned = prev_owned.as_slice();

    // A keyed array of tables leaves the render before the leaf merge: its
    // entries are merged one by one below. Declared as a JSON pointer, it is
    // recorded as the dotted path the leaves use (`providers`).
    let declared: Vec<(String, String)> = keyed_arrays
        .iter()
        .map(|(pointer, key)| {
            let segments: Vec<String> = pointer.split('/').skip(1).map(unescape_token).collect();
            (segments.join("."), key.clone())
        })
        .collect();
    let mut keyed = Vec::new();
    for (path, key, is_declared) in keyed_jobs(&declared, prev_owned) {
        let segments: Vec<String> = path.split('.').map(str::to_string).collect();
        let refs: Vec<&str> = segments.iter().map(String::as_str).collect();
        let entries = match is_declared.then(|| take_path(rendered_doc.as_table_mut(), &refs)).flatten() {
            None => Vec::new(),
            Some(item) => tables_of(&item)
                .with_context(|| format!("the render puts something other than an array of tables at `{path}`"))?,
        };
        keyed.push((segments, path, key, is_declared, entries));
    }
    let keyed_paths: Vec<String> = declared.iter().map(|(path, _)| path.clone()).collect();

    let mut owned: Vec<OwnedLeaf> = Vec::new();
    collect_leaves("", rendered_doc.as_table(), &mut owned);

    merge_table(doc.as_table_mut(), rendered_doc.as_table(), "", prev_owned, false);

    let mut kept_edited = Vec::new();
    for prev in prev_owned {
        if is_keyed_record(prev, &keyed_paths) || owned.iter().any(|o| o.path == prev.path) {
            continue;
        }
        let segments: Vec<&str> = prev.path.split('.').collect();
        match lookup(doc.as_table(), &segments) {
            None => {}
            Some(cur) => {
                if item_hash(cur) == prev.value_hash {
                    remove_path(doc.as_table_mut(), &segments);
                } else {
                    kept_edited.push(prev.path.clone());
                }
            }
        }
    }

    for (segments, path, key, is_declared, mut rendered_entries) in keyed {
        if !is_declared && owned.iter().any(|o| o.entry.is_none() && o.path == path) {
            continue;
        }
        let refs: Vec<&str> = segments.iter().map(String::as_str).collect();
        let live = lookup(doc.as_table(), &refs);
        let whole_array = prev_owned
            .iter()
            .find(|p| is_declared && p.path == path && p.entry.is_none())
            .and_then(|p| live.map(|item| item_hash(item) == p.value_hash));
        let existing_entries = match live.map(tables_of) {
            Some(Ok(tables)) => tables,
            // The user's own value; with nothing of ours to place, it stays.
            Some(Err(_)) if rendered_entries.is_empty() => continue,
            _ => Vec::new(),
        };
        let was_array = !existing_entries.is_empty() || live.is_some_and(Item::is_array_of_tables);
        // The user's inline form (`providers = [{ … }]`) is written back inline,
        // with its trailing comment: the layout is theirs.
        let inline_decor = match live {
            Some(Item::Value(toml_edit::Value::Array(array))) => Some(array.decor().clone()),
            _ => None,
        };
        // Tables print in document-position order: an entry of ours appended
        // after the live ones takes the last one's position, so it prints with
        // its array rather than wherever it sat in the render.
        if let Some(pos) = existing_entries.last().and_then(Table::position) {
            for table in &mut rendered_entries {
                table.set_position(Some(pos));
            }
        }
        let out = merge_entries(&path, &key, existing_entries, rendered_entries, prev_owned, whole_array)?;
        owned.extend(out.owned);
        kept_edited.extend(out.kept_edited);
        if !out.entries.is_empty() {
            let item = match inline_decor {
                Some(decor) => {
                    let mut array = toml_edit::Array::new();
                    for table in out.entries {
                        array.push(table.into_inline_table());
                    }
                    *array.decor_mut() = decor;
                    Item::Value(toml_edit::Value::Array(array))
                }
                None => {
                    let mut array = ArrayOfTables::new();
                    for table in out.entries {
                        array.push(table);
                    }
                    Item::ArrayOfTables(array)
                }
            };
            set_path(doc.as_table_mut(), &refs, item);
        } else if was_array && out.removed {
            remove_path(doc.as_table_mut(), &refs);
        }
    }

    Ok(MergeOutcome {
        contents: doc.to_string(),
        owned,
        kept_edited,
        withdrawn,
    })
}

/// Take the entry at `root` out of `doc`; `false` when nothing stood there.
/// An array of tables emptied by it goes too, as one emptied by a re-render
/// does.
fn remove_root(doc: &mut DocumentMut, root: &EntryRoot) -> bool {
    let segments: Vec<&str> = root.path.split('.').collect();
    let Some(entry) = &root.entry else {
        if lookup(doc.as_table(), &segments).is_none() {
            return false;
        }
        remove_path(doc.as_table_mut(), &segments);
        return true;
    };
    let Some(Ok(tables)) = lookup(doc.as_table(), &segments).map(tables_of) else { return false };
    let Some(i) = tables.iter().position(|t| t.identity(&entry.key).as_deref() == Some(entry.id.as_str())) else {
        return false;
    };
    if tables.len() == 1 {
        remove_path(doc.as_table_mut(), &segments);
        return true;
    }
    match lookup_mut(doc.as_table_mut(), &segments) {
        Some(Item::ArrayOfTables(array)) => {
            array.remove(i);
        }
        Some(Item::Value(toml_edit::Value::Array(array))) => {
            array.remove(i);
        }
        _ => return false,
    }
    true
}

/// Whether something stands at `root` in the file `existing`.
pub(super) fn holds(existing: &str, root: &EntryRoot) -> Result<bool> {
    let mut doc: DocumentMut = existing.parse().context("the existing config file is not valid TOML")?;
    Ok(remove_root(&mut doc, root))
}

impl KeyedEntry for Table {
    fn identity(&self, key: &str) -> Option<String> {
        streamscope_client_templates::composite_identity(key, |field| match self.get(field)?.as_value()? {
            toml_edit::Value::String(s) => Some(s.value().clone()),
            toml_edit::Value::Integer(i) => Some(i.value().to_string()),
            toml_edit::Value::Float(f) => Some(f.value().to_string()),
            toml_edit::Value::Boolean(b) => Some(b.value().to_string()),
            _ => None,
        })
    }

    /// A table printed as an item shows its own keys only, so one holding
    /// tables is hashed with them: an edit inside `[servers.env]` is an edit
    /// of the entry.
    fn entry_hash(&self) -> String {
        if !self.iter().any(|(_, item)| item.is_table() || item.is_array_of_tables()) {
            return item_hash(&Item::Table(self.clone()));
        }
        let mut text = String::new();
        nested_text(self, &mut text);
        sha256_hex(text.as_bytes())
    }

    /// Keeps the live table's place in the document and the comment above its
    /// header; the body is the render's.
    fn replace_with(&mut self, rendered: &Self, keep_filled: bool) {
        let position = self.position();
        let decor = self.decor().clone();
        let live = std::mem::replace(self, rendered.clone());
        if keep_filled {
            keep_filled_sentinels(self, &live);
        }
        if let Some(position) = position {
            self.set_position(Some(position));
        }
        *self.decor_mut() = decor;
    }
}

/// `table` as text, the tables inside it included, each value printed
/// decor-stripped as [`item_hash`] reads it.
fn nested_text(table: &Table, out: &mut String) {
    for (key, item) in table.iter() {
        out.push_str(key);
        match item {
            Item::Table(child) => {
                out.push('{');
                nested_text(child, out);
                out.push('}');
            }
            Item::ArrayOfTables(array) => {
                out.push('[');
                for child in array.iter() {
                    out.push('{');
                    nested_text(child, out);
                    out.push('}');
                }
                out.push(']');
            }
            value => {
                out.push('=');
                out.push_str(value.to_string().trim());
                out.push('\n');
            }
        }
    }
}

/// Put back, under `new`, every value the user filled in over a paste sentinel
/// that `new` still carries — the leaf rule of [`merge_table`], through
/// sub-tables and inline tables alike: the user may hold as `env = { … }`
/// what the render writes as a table of its own.
fn keep_filled_sentinels(new: &mut dyn TableLike, live: &dyn TableLike) {
    for (key, item) in new.iter_mut() {
        let Some(live_item) = live.get(key.get()) else { continue };
        if item.as_str().is_some_and(super::is_paste_sentinel) {
            if live_item.as_str() != item.as_str()
                && let Some(theirs) = live_item.as_value()
            {
                // The value alone: the spacing around it belongs to the form
                // it was written in.
                let mut theirs = theirs.clone();
                theirs.decor_mut().clear();
                *item = Item::Value(theirs);
            }
        } else if let (Some(new_child), Some(live_child)) = (item.as_table_like_mut(), live_item.as_table_like()) {
            keep_filled_sentinels(new_child, live_child);
        }
    }
}

/// The entries of an array of tables — `[[x]]`, or an inline array of inline
/// tables (written back inline). `Err` for anything else.
fn tables_of(item: &Item) -> Result<Vec<Table>> {
    match item {
        Item::ArrayOfTables(array) => Ok(array.iter().cloned().collect()),
        Item::Value(toml_edit::Value::Array(array)) => array
            .iter()
            .map(|v| {
                v.as_inline_table()
                    .map(|t| t.clone().into_table())
                    .context("an entry is not a table")
            })
            .collect(),
        _ => anyhow::bail!("not an array of tables"),
    }
}

/// Detach and return the item at `segments`, leaving its parents in place.
fn take_path(table: &mut Table, segments: &[&str]) -> Option<Item> {
    let (head, rest) = segments.split_first()?;
    if rest.is_empty() {
        return table.remove(head);
    }
    match table.get_mut(head)? {
        Item::Table(child) => take_path(child, rest),
        _ => None,
    }
}

/// Write `item` at `segments`, creating the tables above it — a parent that is
/// not a table is replaced by one, as the render decides that path's shape.
fn set_path(table: &mut Table, segments: &[&str], item: Item) {
    let Some((head, rest)) = segments.split_first() else { return };
    if rest.is_empty() {
        match table.get_mut(head) {
            Some(existing) => *existing = item,
            None => {
                table.insert(head, item);
            }
        }
        return;
    }
    if !table.get(head).is_some_and(Item::is_table) {
        let mut child = Table::new();
        child.set_implicit(true);
        table.insert(head, Item::Table(child));
    }
    if let Some(Item::Table(child)) = table.get_mut(head) {
        set_path(child, rest, item);
    }
}

/// Hash of an item's VALUE, decor-stripped — the same item re-read from the
/// merged document hashes identically even though toml_edit attaches
/// surrounding whitespace/comments as decor.
fn item_hash(item: &Item) -> String {
    sha256_hex(item.to_string().trim().as_bytes())
}

fn collect_leaves(prefix: &str, table: &Table, out: &mut Vec<OwnedLeaf>) {
    for (key, item) in table.iter() {
        let path = if prefix.is_empty() {
            key.to_string()
        } else {
            format!("{prefix}.{key}")
        };
        match item {
            Item::Table(t) => collect_leaves(&path, t, out),
            leaf => out.push(OwnedLeaf {
                path,
                entry: None,
                value_hash: item_hash(leaf),
            }),
        }
    }
}

/// `prefix` is the dotted path of `dst`, the grammar `prev_owned` records in.
///
/// A sub-table and an inline table hold the same data, and which one a file
/// uses is its author's choice: where the render and the file disagree on the
/// form (`[x.env]` against `env = { … }`, either way round) the two merge
/// leaf by leaf, into the form the file has. Only an inline table rendered
/// over an inline table is one value, replaced whole.
///
/// `inline`: `dst` is an inline table, or sits inside one. Everything
/// written under it is then a value — a rendered table goes in as an inline
/// table — because a `[table]` inside an inline table has no spelling and is
/// not printed.
fn merge_table(dst: &mut dyn TableLike, src: &dyn TableLike, prefix: &str, prev_owned: &[OwnedLeaf], inline: bool) {
    for (key, item) in src.iter() {
        let path = if prefix.is_empty() { key.to_string() } else { format!("{prefix}.{key}") };
        let live = dst.get(key);
        let leaf_by_leaf = (item.is_table() && live.is_some_and(Item::is_table_like))
            || (item.is_inline_table() && live.is_some_and(Item::is_table));
        if leaf_by_leaf {
            let inline = inline || live.is_some_and(Item::is_inline_table);
            if let (Some(d), Some(s)) = (dst.get_mut(key).and_then(Item::as_table_like_mut), item.as_table_like()) {
                merge_table(d, s, &path, prev_owned, inline);
            }
            continue;
        }
        match dst.get_mut(key) {
            // A paste-me sentinel never overwrites a value the user already
            // filled in (BYOK upstream keys): it replaces only the value the
            // last run wrote there.
            Some(existing)
                if item.as_str().is_some_and(super::is_paste_sentinel)
                    && existing.as_str() != item.as_str()
                    && !is_what_we_wrote(prev_owned, &path, &item_hash(existing)) => {}
            // In-place assignment keeps the existing key's decor (the user's
            // comment above the line); `insert` would drop it.
            Some(existing) => *existing = held_by(item, inline),
            None => {
                dst.insert(key, held_by(item, inline));
            }
        }
    }
}

/// `item` in the form its parent can hold: as it is under a table, as a value
/// (a table as an inline table, an array of tables as an array of them) under
/// an inline one.
fn held_by(item: &Item, inline_parent: bool) -> Item {
    if !inline_parent {
        return item.clone();
    }
    match item.clone().into_value() {
        Ok(mut value) => {
            // The spacing of a `[table]` header is not a value's.
            value.decor_mut().clear();
            Item::Value(value)
        }
        Err(original) => original,
    }
}

fn lookup_mut<'a>(table: &'a mut dyn TableLike, segments: &[&str]) -> Option<&'a mut Item> {
    let (head, rest) = segments.split_first()?;
    let item = table.get_mut(head)?;
    if rest.is_empty() {
        Some(item)
    } else {
        lookup_mut(item.as_table_like_mut()?, rest)
    }
}

/// The item at `segments`, through sub-tables and inline tables alike.
fn lookup<'a>(table: &'a dyn TableLike, segments: &[&str]) -> Option<&'a Item> {
    let (head, rest) = segments.split_first()?;
    let item = table.get(head)?;
    if rest.is_empty() {
        Some(item)
    } else {
        lookup(item.as_table_like()?, rest)
    }
}

/// Remove the leaf, pruning ancestor tables emptied by the removal. Returns
/// `true` when the table became empty.
fn remove_path(table: &mut dyn TableLike, segments: &[&str]) -> bool {
    let Some((head, rest)) = segments.split_first() else {
        return false;
    };
    if rest.is_empty() {
        table.remove(head);
    } else if let Some(child) = table.get_mut(head).and_then(Item::as_table_like_mut)
        && remove_path(child, rest)
    {
        table.remove(head);
    }
    table.is_empty()
}

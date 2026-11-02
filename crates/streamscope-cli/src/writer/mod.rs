//! Structured merge of rendered client configs into live files.
//!
//! The merge is format-aware and ownership-tracked:
//!   * objects/tables merge recursively; scalars and arrays from the
//!     rendered body REPLACE the existing value wholesale — except an array
//!     the template declares KEYED (`keyed_arrays`: pointer → identity field),
//!     which merges entry by entry ([`merge_entries`]): the user's own entries
//!     stay where they are, ours are updated in place or appended;
//!   * every key the user has that the render doesn't mention is untouched;
//!   * each leaf the render contributes is recorded in the manifest with the
//!     hash of the written value, so a later run removes leaves we own that
//!     dropped out of the render — but ONLY when their live value still
//!     matches what we wrote (a user-edited value is kept, with a warning);
//!   * writes are atomic (same-dir temp + rename) with a pre-write backup.

pub(crate) mod envfile;
pub mod json;
mod toml;
mod yaml;

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::state::{sha256_hex, OwnedEntry, OwnedLeaf};
use streamscope_client_templates::{TemplateFormat, STRING_ENTRIES};

pub struct MergeOutcome {
    /// Final file contents (not yet written).
    pub contents: String,
    /// Leaves this render owns in the file, with written-value hashes.
    pub owned: Vec<OwnedLeaf>,
    /// Leaves we previously owned whose live value was user-edited — kept in
    /// place; surfaced so the caller can warn.
    pub kept_edited: Vec<String>,
}

/// Merge `rendered` into the current contents of `existing` (None = file
/// absent) per `format`. `prev_owned` is what we wrote last time (empty on
/// first provision); `keyed_arrays` is the template's pointer → identity map.
pub fn merge(
    format: TemplateFormat,
    existing: Option<&str>,
    rendered: &str,
    prev_owned: &[OwnedLeaf],
    keyed_arrays: &BTreeMap<String, String>,
) -> Result<MergeOutcome> {
    match format {
        TemplateFormat::Json => json::merge(existing, rendered, prev_owned, keyed_arrays),
        TemplateFormat::Toml => toml::merge(existing, rendered, prev_owned, keyed_arrays),
        // Value-level YAML round-trip: the user's comments/formatting are NOT
        // preserved (yaml_serde has no in-place editor the way toml_edit
        // is for TOML) — the merge semantics are otherwise identical.
        TemplateFormat::Yaml => yaml::merge(existing, rendered, prev_owned, keyed_arrays),
        // Env-style KEY=VALUE files are produced by tool quirks (Gemini's
        // ~/.gemini/.env), not by template formats — but the writer speaks
        // the format so quirks reuse the same pipeline. They have no arrays.
        TemplateFormat::Shell => {
            if !keyed_arrays.is_empty() {
                bail!("an env file has no arrays to merge by key");
            }
            envfile::merge(existing, rendered, prev_owned)
        }
        TemplateFormat::Text => {
            bail!("structured merge for {format:?} files is not supported")
        }
    }
}

/// One entry of a keyed array, as each format's writer reads it.
pub(crate) trait KeyedEntry: Clone {
    /// The entry's identity — `keyed_entry_identity` for JSON and YAML, the
    /// same reading the save-time check applies.
    fn identity(&self, key: &str) -> Option<String>;
    /// Hash of the entry's value — the hash the writer records for a leaf.
    fn entry_hash(&self) -> String;
    /// Replace the live entry of this identity with the rendered one: the
    /// entry is ours, so a field the render no longer carries goes with it (a
    /// capability a model lost must not stay advertised). The one exception is
    /// a paste sentinel the user filled in, which keeps their value — the rule
    /// every leaf follows.
    fn replace_with(&mut self, rendered: &Self);
}

/// A keyed array after the merge.
pub(crate) struct KeyedOutcome<E> {
    /// The array as it must now read.
    pub entries: Vec<E>,
    /// One record per entry the render contributed.
    pub owned: Vec<OwnedLeaf>,
    /// Entries of ours that left the render but were edited since — kept.
    pub kept_edited: Vec<String>,
    /// Whether an entry was removed: an array emptied by removals is dropped,
    /// one the user left empty is not.
    pub removed: bool,
}

/// Merge the `rendered` entries of the keyed array at `path` (the writer's own
/// record grammar) into the `existing` ones, identified by their `key` field.
///
/// The user's entries stay where they are; an entry of ours replaces the live
/// entry of the same identity ([`KeyedEntry::replace_with`]), or is appended; an entry we recorded that left
/// the render is removed only while its value is still what we wrote — the
/// same rule the writers apply to a leaf.
///
/// `whole_array` is set when `prev_owned` holds a record of the WHOLE array (a
/// manifest from before the array was keyed): `Some(true)` when the live array
/// is still exactly what we wrote, so every entry in it is ours and those the
/// render dropped go; `Some(false)` when it was edited since, so ours cannot be
/// told from the user's and nothing is removed.
/// How a message names one entry of a keyed array: `name=gw-a`, or the bare
/// name of a string entry (`ANTHROPIC_API_BASE`).
fn entry_label(key: &str, id: &str) -> String {
    if key == STRING_ENTRIES {
        id.to_string()
    } else {
        format!("{key}={id}")
    }
}

pub(crate) fn merge_entries<E: KeyedEntry>(
    path: &str,
    key: &str,
    existing: Vec<E>,
    rendered: Vec<E>,
    prev_owned: &[OwnedLeaf],
    whole_array: Option<bool>,
) -> Result<KeyedOutcome<E>> {
    let mut ids: Vec<String> = Vec::with_capacity(rendered.len());
    for entry in &rendered {
        let Some(id) = entry.identity(key) else {
            if key == STRING_ENTRIES {
                bail!("an entry of the keyed array `{path}` is not a string, so it has no name to identify it by");
            }
            bail!("an entry of the keyed array `{path}` has no `{key}` to identify it by");
        };
        if ids.contains(&id) {
            bail!("two entries of the keyed array `{path}` share {}", entry_label(key, &id));
        }
        ids.push(id);
    }
    let position = |entries: &[E], id: &str| {
        entries.iter().position(|e| e.identity(key).as_deref() == Some(id))
    };

    let mut kept_edited = Vec::new();
    // Every entry of an unedited whole-array record is ours.
    let mut ours_before: Vec<String> = match whole_array {
        Some(true) => existing.iter().filter_map(|e| e.identity(key)).collect(),
        Some(false) => {
            kept_edited.push(path.to_string());
            Vec::new()
        }
        None => Vec::new(),
    };

    // A rendered entry missing from the file goes right before the next
    // rendered entry the file already holds, else at the end: the render's
    // own entries keep the render's order, which matters where the client
    // reads the array in order (the last matching OpenCode policy wins).
    let mut entries = existing;
    for (n, (entry, id)) in rendered.iter().zip(&ids).enumerate() {
        match position(&entries, id) {
            Some(i) => entries[i].replace_with(entry),
            None => {
                let before = ids[n + 1..].iter().find_map(|later| position(&entries, later));
                entries.insert(before.unwrap_or(entries.len()), entry.clone());
            }
        }
    }
    let mut removed = false;
    for prev in prev_owned.iter().filter(|p| p.path == path) {
        let Some(OwnedEntry { key: prev_key, id }) = &prev.entry else { continue };
        if prev_key != key || ids.contains(id) {
            continue;
        }
        let Some(i) = position(&entries, id) else { continue };
        if entries[i].entry_hash() == prev.value_hash {
            entries.remove(i);
            removed = true;
        } else {
            kept_edited.push(format!("{path}[{}]", entry_label(key, id)));
        }
    }
    ours_before.retain(|id| !ids.contains(id));
    for id in &ours_before {
        if let Some(i) = position(&entries, id) {
            entries.remove(i);
            removed = true;
        }
    }

    let owned = rendered
        .iter()
        .zip(ids)
        .map(|(entry, id)| OwnedLeaf {
            path: path.to_string(),
            entry: Some(OwnedEntry { key: key.to_string(), id }),
            value_hash: entry.entry_hash(),
        })
        .collect();
    Ok(KeyedOutcome { entries, owned, kept_edited, removed })
}

/// Every keyed array a writer settles this run, as `(path, key, declared)`.
/// First each `(path, key)` a previous entry record names that the template no
/// longer declares — merged with no rendered entries, so ours are removed
/// while unedited instead of lingering untracked — then the declared ones.
/// That order matters when only the identity FIELD changed: the entries the
/// old field recorded go first, and the declared job then writes the render's
/// under the new one, rather than writing them and having the old field's job
/// remove them. A writer skips an undeclared job its render still carries as a
/// leaf: the array is then written whole, and its entries are the render's.
pub(crate) fn keyed_jobs(declared: &[(String, String)], prev_owned: &[OwnedLeaf]) -> Vec<(String, String, bool)> {
    let mut jobs: Vec<(String, String, bool)> = Vec::new();
    for prev in prev_owned {
        let Some(entry) = &prev.entry else { continue };
        let named = |(path, key): &(String, String)| *path == prev.path && *key == entry.key;
        if !declared.iter().any(named)
            && !jobs.iter().any(|(path, key, _)| *path == prev.path && *key == entry.key)
        {
            jobs.push((prev.path.clone(), entry.key.clone(), false));
        }
    }
    jobs.extend(declared.iter().map(|(path, key)| (path.clone(), key.clone(), true)));
    jobs
}

/// Whether a previous record belongs to a keyed array — an entry, or the whole
/// array as an older manifest recorded it — and so is settled by
/// [`merge_entries`], not by a writer's leaf removal.
pub(crate) fn is_keyed_record(prev: &OwnedLeaf, keyed_paths: &[String]) -> bool {
    prev.entry.is_some() || keyed_paths.contains(&prev.path)
}

/// JSON-pointer token escaping (RFC 6901) — the one grammar both the JSON
/// and YAML writers record ownership paths in. Paths persist in the
/// manifest, so the two writers MUST share these (a divergence would break
/// round-tripping of previously recorded owned leaves).
pub(crate) fn escape_token(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

pub(crate) fn unescape_token(token: &str) -> String {
    token.replace("~1", "/").replace("~0", "~")
}

/// Substitution sentinels the render leaves for the USER to fill in by hand
/// (BYOK upstream API keys, BYOT MCP bearers — `<paste-your-…-here>`). When a
/// re-render carries one of these and the live file already holds a different
/// value, the user's pasted secret wins — overwriting it with the sentinel
/// would silently break the tool.
pub(crate) fn is_paste_sentinel(s: &str) -> bool {
    s.starts_with("<paste-your-") && s.ends_with("-here>")
}

/// Atomically install `contents` at `path`: backup the original (when the
/// caller passed a backup `(base, run_stamp)`), write a same-dir temp file,
/// fsync, rename. `base` is the scope's state dir, so a project install's
/// backups land under its `.streamscopeai/`. The temp file is CREATED 0600 (these
/// configs carry the gateway key — no default-umask window); an existing file
/// keeps its own owner bits after rename, with group and other always dropped.
pub fn write_atomic(path: &Path, contents: &str, backup: Option<(&Path, &str)>) -> Result<String> {
    if let Some((base, stamp)) = backup {
        crate::state::backup_file(base, stamp, path)
            .with_context(|| format!("backup of {}", path.display()))?;
    }
    let dir = path.parent().context("target path has no parent")?;
    std::fs::create_dir_all(dir)?;

    // Keep an existing file's mode, but never widen past the owner. These
    // configs hold a live gateway key, and a tool that shipped its own config
    // at 0644 — most do — would otherwise have that key made world-readable by
    // the act of provisioning it. Preserving the *narrowing* part of the mode
    // (setgid, sticky, an owner already restricted to read-only) while
    // dropping group and other is the honest reading of "keeps its own mode":
    // what the file's owner chose, minus what they cannot have meant.
    #[cfg(unix)]
    let mode: u32 = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o700)
            .unwrap_or(0o600)
    };

    let tmp = dir.join(format!(
        ".{}.streamscope-tmp-{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("config"),
        std::process::id()
    ));
    {
        use std::io::Write;
        let mut f = crate::state::create_private_file(&tmp)?;
        f.write_all(contents.as_bytes())?;
        f.sync_all()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode & 0o777))?;
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("install {}", path.display()))?;
    Ok(sha256_hex(contents.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No keyed arrays: the leaf contract every format shares.
    static NONE: BTreeMap<String, String> = BTreeMap::new();

    // ----- file modes -----

    /// Most tools ship their config at 0644. Provisioning writes a live gateway
    /// key into it, so preserving that mode verbatim would be the act that
    /// exposes the key to every account on the machine.
    #[cfg(unix)]
    #[test]
    fn writing_a_world_readable_config_narrows_it_to_the_owner() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("ss-writer-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        std::fs::write(&path, "{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        write_atomic(&path, "{\"key\":\"sk-secret\"}", None).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & 0o077, 0, "group/other must lose access, got {mode:o}");
        assert_eq!(mode & 0o700, 0o600, "the owner's own bits are kept: {mode:o}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A file the owner had already restricted keeps that restriction — this
    /// narrows, it does not normalise.
    #[cfg(unix)]
    #[test]
    fn writing_an_owner_read_only_config_keeps_its_owner_bits() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("ss-writer-ro-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        std::fs::write(&path, "{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();

        write_atomic(&path, "{\"key\":\"sk-secret\"}", None).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o400, "expected the owner's read-only mode, got {mode:o}");
        std::fs::remove_dir_all(&dir).ok();
    }

    // ----- JSON -----

    #[test]
    fn json_merge_preserves_foreign_keys() {
        let existing = r#"{"theme": "dark", "env": {"FOO": "bar"}}"#;
        let rendered = r#"{"env": {"ANTHROPIC_BASE_URL": "https://gw", "ANTHROPIC_AUTH_TOKEN": "sk-x"}}"#;
        let out = merge(TemplateFormat::Json, Some(existing), rendered, &[], &NONE).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out.contents).unwrap();
        assert_eq!(v["theme"], "dark");
        assert_eq!(v["env"]["FOO"], "bar");
        assert_eq!(v["env"]["ANTHROPIC_BASE_URL"], "https://gw");
        assert_eq!(out.owned.len(), 2);
    }

    #[test]
    fn json_merge_into_missing_file() {
        let rendered = r#"{"env": {"A": "1"}}"#;
        let out = merge(TemplateFormat::Json, None, rendered, &[], &NONE).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out.contents).unwrap();
        assert_eq!(v["env"]["A"], "1");
    }

    #[test]
    fn json_rerun_is_idempotent() {
        let rendered = r#"{"env": {"A": "1", "B": "2"}}"#;
        let first = merge(TemplateFormat::Json, None, rendered, &[], &NONE).unwrap();
        let second =
            merge(TemplateFormat::Json, Some(&first.contents), rendered, &first.owned, &NONE).unwrap();
        assert_eq!(first.contents, second.contents);
        assert!(second.kept_edited.is_empty());
    }

    /// VS Code's `settings.json` (Cline), Gemini CLI's and Qwen Code's take
    /// comments and trailing commas: provisioning merges into such a file and
    /// keeps them, and taking our keys out again leaves the user's text as
    /// it was.
    #[test]
    fn json_merge_keeps_the_comments_of_a_jsonc_file() {
        let existing = "{\n  // my editor\n  \"editor.fontSize\": 14, /* big */\n  \"env\": {\n    \"FOO\": \"bar\", // mine\n  },\n}\n";
        let rendered = r#"{"env": {"GW": "https://gw"}, "model": "m"}"#;
        let out = merge(TemplateFormat::Json, Some(existing), rendered, &[], &NONE).unwrap();
        for kept in ["// my editor", "/* big */", "// mine"] {
            assert!(out.contents.contains(kept), "{kept} lost:\n{}", out.contents);
        }
        let v = json::parse_jsonc(&out.contents).unwrap();
        assert_eq!(v, serde_json::json!({"editor.fontSize": 14, "env": {"FOO": "bar", "GW": "https://gw"}, "model": "m"}));

        let again = merge(TemplateFormat::Json, Some(&out.contents), rendered, &out.owned, &NONE).unwrap();
        assert_eq!(again.contents, out.contents, "a re-run changes nothing");

        let removed = merge(TemplateFormat::Json, Some(&out.contents), "{}", &out.owned, &NONE).unwrap();
        assert_eq!(json::parse_jsonc(&removed.contents).unwrap(), json::parse_jsonc(existing).unwrap());
        for kept in ["// my editor", "/* big */", "// mine"] {
            assert!(removed.contents.contains(kept), "{kept} lost on removal:\n{}", removed.contents);
        }
    }

    /// Switching a client's variant re-renders the same file with other
    /// keys: the previous variant's keys — the gateway key among them — leave
    /// with it, and the user's own settings stay.
    #[test]
    fn json_switching_variant_drops_the_previous_variants_keys() {
        let existing = r#"{"editor.fontSize": 14}"#;
        let anthropic = r#"{"cline.apiProvider": "anthropic", "cline.anthropicApiKey": "sk-a", "cline.anthropicBaseUrl": "https://gw"}"#;
        let openai = r#"{"cline.apiProvider": "openai", "cline.openAiApiKey": "sk-a", "cline.openAiBaseUrl": "https://gw/v1"}"#;
        let first = merge(TemplateFormat::Json, Some(existing), anthropic, &[], &NONE).unwrap();
        let second = merge(TemplateFormat::Json, Some(&first.contents), openai, &first.owned, &NONE).unwrap();
        let v: serde_json::Value = serde_json::from_str(&second.contents).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"editor.fontSize": 14, "cline.apiProvider": "openai", "cline.openAiApiKey": "sk-a", "cline.openAiBaseUrl": "https://gw/v1"})
        );
    }

    /// A file holding only comments is an empty config: the gateway's keys
    /// are added and the comments stay.
    #[test]
    fn json_merge_into_a_file_of_comments_keeps_them() {
        let existing = "// set up by my team\n/* nothing yet */\n";
        let out = merge(TemplateFormat::Json, Some(existing), r#"{"model": "m"}"#, &[], &NONE).unwrap();
        assert!(out.contents.contains("// set up by my team") && out.contents.contains("/* nothing yet */"), "{}", out.contents);
        assert_eq!(json::parse_jsonc(&out.contents).unwrap(), serde_json::json!({"model": "m"}));
    }

    /// JSONC's comments and trailing commas are the only syntax beyond JSON
    /// accepted: what the tool itself would not read is not guessed at.
    #[test]
    fn json_merge_refuses_what_jsonc_does_not_allow() {
        for bad in ["{'a': 1}", "{a: 1}", "{\"a\": 1 \"b\": 2}", "{\"a\": 0x1F}"] {
            assert!(merge(TemplateFormat::Json, Some(bad), "{}", &[], &NONE).is_err(), "{bad} accepted");
        }
    }

    /// A key written twice reads as its last value in the tool but the tree
    /// edits its first: the merge refuses rather than write the wrong one.
    #[test]
    fn json_merge_refuses_a_jsonc_file_with_a_repeated_key() {
        let existing = "{\n  // dup\n  \"model\": \"a\",\n  \"model\": \"b\",\n}";
        let Err(err) = merge(TemplateFormat::Json, Some(existing), r#"{"model": "m"}"#, &[], &NONE) else {
            panic!("a repeated key was edited");
        };
        assert!(format!("{err:#}").contains("repeated"), "{err:#}");
    }

    #[test]
    fn json_removes_owned_leaf_that_left_the_render() {
        let rendered_v1 = r#"{"env": {"A": "1", "OLD": "x"}}"#;
        let first = merge(TemplateFormat::Json, None, rendered_v1, &[], &NONE).unwrap();
        let rendered_v2 = r#"{"env": {"A": "1"}}"#;
        let second =
            merge(TemplateFormat::Json, Some(&first.contents), rendered_v2, &first.owned, &NONE).unwrap();
        let v: serde_json::Value = serde_json::from_str(&second.contents).unwrap();
        assert!(v["env"].get("OLD").is_none());
        assert_eq!(v["env"]["A"], "1");
    }

    #[test]
    fn json_keeps_user_edited_leaf_on_removal() {
        let rendered_v1 = r#"{"env": {"OLD": "ours"}}"#;
        let first = merge(TemplateFormat::Json, None, rendered_v1, &[], &NONE).unwrap();
        // User edits the value we wrote…
        let edited = first.contents.replace("ours", "user-changed");
        // …then the new render no longer carries the leaf.
        let second = merge(TemplateFormat::Json, Some(&edited), r#"{"other": 1}"#, &first.owned, &NONE)
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&second.contents).unwrap();
        assert_eq!(v["env"]["OLD"], "user-changed");
        assert_eq!(second.kept_edited, vec!["/env/OLD".to_string()]);
    }

    /// A template whose body moves its leaves to new paths (`provider` →
    /// `providers`, `mcp.<slug>` → `mcp.servers.<slug>`) is re-provisioned
    /// over the file the CLI wrote from the earlier body. Every old leaf of ours
    /// goes, the user's own keys stay, and an old leaf the user edited is kept
    /// and reported rather than silently dropped.
    #[test]
    fn json_reprovision_into_a_new_shape_removes_every_old_leaf_of_ours() {
        let v1 = r#"{"$schema": "https://opencode.ai/config.json", "autoupdate": false,
            "provider": {"ss_t_p": {"npm": "@ai-sdk/anthropic", "options": {"apiKey": "sk-1", "baseURL": "https://gw/v1"},
                "models": {"m": {"name": "m", "tool_call": true, "reasoning": true}}}},
            "model": "ss_t_p/m", "enabled_providers": ["ss_t_p"],
            "mcp": {"fs": {"type": "remote", "url": "https://gw/mcp/fs", "enabled": true},
                    "web": {"type": "remote", "url": "https://gw/mcp/web", "enabled": true}}}"#;
        let first = merge(TemplateFormat::Json, None, v1, &[], &NONE).unwrap();
        // The user adds a key of their own and edits one of our v1 leaves.
        let mut live: serde_json::Value = serde_json::from_str(&first.contents).unwrap();
        live["theme"] = "dark".into();
        live["mcp"]["web"]["url"] = "https://user-chosen/mcp".into();
        let live = serde_json::to_string(&live).unwrap();

        let v2 = r#"{"providers": {"ss_t_p": {"package": "@opencode/ai/providers/anthropic",
                "settings": {"apiKey": "sk-1", "baseURL": "https://gw/v1"},
                "models": {"m": {"name": "m", "capabilities": {"tools": true, "input": ["text"], "output": ["text"]}}}}},
            "model": "ss_t_p/m", "experimental": {"policies": [{"action": "provider.use", "resource": "*", "effect": "deny"}]},
            "mcp": {"servers": {"fs": {"type": "remote", "url": "https://gw/mcp/fs", "oauth": false, "codemode": false}}}}"#;
        let second = merge(TemplateFormat::Json, Some(&live), v2, &first.owned, &NONE).unwrap();
        let v: serde_json::Value = serde_json::from_str(&second.contents).unwrap();

        for gone in ["$schema", "autoupdate", "provider", "enabled_providers"] {
            assert!(v.get(gone).is_none(), "v1 key {gone} survived: {v}");
        }
        assert!(v["mcp"].get("fs").is_none(), "v1 mcp.fs survived: {v}");
        assert_eq!(v["mcp"]["servers"]["fs"]["codemode"], false);
        assert_eq!(v["providers"]["ss_t_p"]["settings"]["apiKey"], "sk-1");
        assert_eq!(v["theme"], "dark", "the user's own key is kept");
        // The edited leaf stays; its unedited siblings of ours go.
        assert_eq!(v["mcp"]["web"], serde_json::json!({"url": "https://user-chosen/mcp"}));
        assert_eq!(second.kept_edited, vec!["/mcp/web/url".to_string()]);
    }

    /// OpenCode's project pin is a policy array read last-match-wins, merged
    /// entry by entry on `action` + `resource`: a user's own policies stay (a
    /// tool deny of theirs is never taken for ours), and a pin entry put back
    /// lands in the render's order — a `deny *` after the `allow` would hide
    /// the provisioned provider.
    #[test]
    fn json_policy_entries_merge_by_action_and_resource_in_render_order() {
        let keyed: BTreeMap<String, String> =
            [("/experimental/policies".to_string(), "action+resource".to_string())].into();
        let pin = r#"{"experimental": {"policies": [
            {"action": "provider.use", "resource": "*", "effect": "deny"},
            {"action": "provider.use", "resource": "ss_b", "effect": "allow"}]}}"#;
        // The user's own entries, one sharing our `resource` under another action.
        let existing = r#"{"experimental": {"policies": [
            {"action": "tool.use", "resource": "*", "effect": "deny"},
            {"action": "provider.use", "resource": "ss_b", "effect": "allow"}]}}"#;
        let out = merge(TemplateFormat::Json, Some(existing), pin, &[], &keyed).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out.contents).unwrap();
        let got: Vec<(String, String)> = v["experimental"]["policies"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| (p["action"].as_str().unwrap().into(), p["resource"].as_str().unwrap().into()))
            .collect();
        let pair = |a: &str, r: &str| (a.to_string(), r.to_string());
        assert_eq!(
            got,
            [pair("tool.use", "*"), pair("provider.use", "*"), pair("provider.use", "ss_b")],
            "the user's tool deny is kept and the re-added deny sits before the allow"
        );
        // Unprovisioning removes only ours.
        let gone = merge(TemplateFormat::Json, Some(&out.contents), "{}", &out.owned, &keyed).unwrap();
        let v: serde_json::Value = serde_json::from_str(&gone.contents).unwrap();
        assert_eq!(v["experimental"]["policies"], serde_json::json!([{"action": "tool.use", "resource": "*", "effect": "deny"}]));
    }

    #[test]
    fn json_prunes_emptied_parents_after_removal() {
        let first = merge(TemplateFormat::Json, None, r#"{"mcpServers": {"web": {"url": "u"}}}"#, &[], &NONE)
            .unwrap();
        let second =
            merge(TemplateFormat::Json, Some(&first.contents), r#"{"a": 1}"#, &first.owned, &NONE).unwrap();
        let v: serde_json::Value = serde_json::from_str(&second.contents).unwrap();
        assert!(v.get("mcpServers").is_none(), "emptied parent should be pruned: {v}");
    }

    #[test]
    fn json_empty_container_is_not_written_into_fresh_file() {
        // A client provisioned with zero MCP servers renders `mcpServers: {}` —
        // the writer must not introduce the empty container (it would linger
        // untracked forever once the block leaves the render).
        let rendered = r#"{"theme": "x", "mcpServers": {}}"#;
        let out = merge(TemplateFormat::Json, None, rendered, &[], &NONE).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out.contents).unwrap();
        assert_eq!(v["theme"], "x");
        assert!(v.get("mcpServers").is_none(), "empty container must not be written: {v}");
    }

    #[test]
    fn json_empty_container_does_not_clobber_user_content() {
        // The user already has their own entry under the key the render leaves
        // empty — merging an empty object preserves it.
        let existing = r#"{"mcpServers": {"mine": {"url": "u"}}}"#;
        let rendered = r#"{"mcpServers": {}}"#;
        let out = merge(TemplateFormat::Json, Some(existing), rendered, &[], &NONE).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out.contents).unwrap();
        assert_eq!(v["mcpServers"]["mine"]["url"], "u");
    }

    #[test]
    fn json_arrays_replace_wholesale() {
        let existing = r#"{"list": [1, 2, 3]}"#;
        let rendered = r#"{"list": ["a"]}"#;
        let out = merge(TemplateFormat::Json, Some(existing), rendered, &[], &NONE).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out.contents).unwrap();
        assert_eq!(v["list"], serde_json::json!(["a"]));
    }

    #[test]
    fn json_garbage_existing_file_errors() {
        let out = merge(TemplateFormat::Json, Some("not json{"), r#"{"a":1}"#, &[], &NONE);
        assert!(out.is_err());
    }

    // ----- TOML -----

    #[test]
    fn toml_merge_preserves_comments_and_foreign_keys() {
        let existing = "# my codex config\nmodel = \"old\"\nfavorite = true\n";
        let rendered =
            "model = \"claude\"\n\n[model_providers.streamscope]\nbase_url = \"https://gw\"\n";
        let out = merge(TemplateFormat::Toml, Some(existing), rendered, &[], &NONE).unwrap();
        assert!(out.contents.contains("# my codex config"));
        assert!(out.contents.contains("favorite = true"));
        assert!(out.contents.contains("model = \"claude\""));
        assert!(out.contents.contains("base_url = \"https://gw\""));
    }

    #[test]
    fn toml_removes_owned_leaf_and_prunes_empty_table() {
        let rendered_v1 = "[model_providers.streamscope]\nbase_url = \"https://gw\"\n";
        let first = merge(TemplateFormat::Toml, None, rendered_v1, &[], &NONE).unwrap();
        let second = merge(TemplateFormat::Toml, Some(&first.contents), "other = 1\n", &first.owned, &NONE)
            .unwrap();
        assert!(!second.contents.contains("model_providers"));
        assert!(second.contents.contains("other = 1"));
    }

    #[test]
    fn toml_keeps_user_edited_leaf() {
        let first = merge(TemplateFormat::Toml, None, "a = \"ours\"\n", &[], &NONE).unwrap();
        let edited = first.contents.replace("ours", "user");
        let second = merge(TemplateFormat::Toml, Some(&edited), "b = 1\n", &first.owned, &NONE).unwrap();
        assert!(second.contents.contains("a = \"user\""));
        assert_eq!(second.kept_edited, vec!["a".to_string()]);
    }

    // ----- YAML -----

    #[test]
    fn yaml_merge_preserves_foreign_keys() {
        let existing = "dark-mode: true\nopenai-api-key: old\n";
        let rendered =
            "openai-api-base: https://gw/v1\nopenai-api-key: sk-new\nmodel: openai/claude\n";
        let out = merge(TemplateFormat::Yaml, Some(existing), rendered, &[], &NONE).unwrap();
        let v: yaml_serde::Value = yaml_serde::from_str(&out.contents).unwrap();
        assert_eq!(v["dark-mode"], yaml_serde::Value::Bool(true));
        assert_eq!(v["openai-api-key"], "sk-new");
        assert_eq!(v["openai-api-base"], "https://gw/v1");
        assert_eq!(out.owned.len(), 3);
    }

    #[test]
    fn yaml_nested_mappings_merge_and_sequences_replace() {
        let existing = "models:\n  - name: mine\nrules:\n  keep: true\n";
        let rendered = "models:\n  - name: gateway\nrules:\n  add: '1'\n";
        let out = merge(TemplateFormat::Yaml, Some(existing), rendered, &[], &NONE).unwrap();
        let v: yaml_serde::Value = yaml_serde::from_str(&out.contents).unwrap();
        // Sequences replace wholesale (same contract as JSON arrays)…
        assert_eq!(v["models"].as_sequence().unwrap().len(), 1);
        assert_eq!(v["models"][0]["name"], "gateway");
        // …while mappings merge per key.
        assert_eq!(v["rules"]["keep"], yaml_serde::Value::Bool(true));
        assert_eq!(v["rules"]["add"], "1");
    }

    #[test]
    fn yaml_removes_owned_leaf_and_prunes_emptied_parent() {
        let first = merge(TemplateFormat::Yaml, None, "mcp:\n  web:\n    url: u\n", &[], &NONE).unwrap();
        let second =
            merge(TemplateFormat::Yaml, Some(&first.contents), "a: 1\n", &first.owned, &NONE).unwrap();
        let v: yaml_serde::Value = yaml_serde::from_str(&second.contents).unwrap();
        assert!(v.get("mcp").is_none(), "emptied parent should be pruned: {v:?}");
        assert_eq!(v["a"], 1);
    }

    #[test]
    fn yaml_keeps_user_edited_leaf_on_removal() {
        let first = merge(TemplateFormat::Yaml, None, "old: ours\n", &[], &NONE).unwrap();
        let edited = first.contents.replace("ours", "user-changed");
        let second = merge(TemplateFormat::Yaml, Some(&edited), "other: 1\n", &first.owned, &NONE).unwrap();
        let v: yaml_serde::Value = yaml_serde::from_str(&second.contents).unwrap();
        assert_eq!(v["old"], "user-changed");
        assert_eq!(second.kept_edited, vec!["/old".to_string()]);
    }

    #[test]
    fn yaml_rerun_is_idempotent_and_sentinel_respected() {
        let rendered = "key: <paste-your-upstream-api-key-here>\nbase: https://gw\n";
        let first = merge(TemplateFormat::Yaml, None, rendered, &[], &NONE).unwrap();
        let second =
            merge(TemplateFormat::Yaml, Some(&first.contents), rendered, &first.owned, &NONE).unwrap();
        assert_eq!(first.contents, second.contents);

        let pasted = first.contents.replace("<paste-your-upstream-api-key-here>", "real");
        let third = merge(TemplateFormat::Yaml, Some(&pasted), rendered, &first.owned, &NONE).unwrap();
        let v: yaml_serde::Value = yaml_serde::from_str(&third.contents).unwrap();
        assert_eq!(v["key"], "real");
    }

    #[test]
    fn yaml_empty_mapping_is_not_written_into_fresh_file() {
        let rendered = "theme: x\nmcp: {}\n";
        let out = merge(TemplateFormat::Yaml, None, rendered, &[], &NONE).unwrap();
        let v: yaml_serde::Value = yaml_serde::from_str(&out.contents).unwrap();
        assert_eq!(v["theme"], "x");
        assert!(v.get("mcp").is_none(), "empty mapping must not be written: {v:?}");
    }

    #[test]
    fn yaml_garbage_existing_file_errors() {
        let out = merge(TemplateFormat::Yaml, Some("foo: [unclosed"), "a: 1\n", &[], &NONE);
        assert!(out.is_err());
    }

    // ----- env files -----

    #[test]
    fn env_merge_preserves_comments_and_foreign_lines() {
        let existing = "# gemini env\nMY_VAR=keep\nGEMINI_API_KEY=old\n";
        let rendered = "GEMINI_API_KEY=sk-new\nGOOGLE_GEMINI_BASE_URL=https://gw\n";
        let out = merge(TemplateFormat::Shell, Some(existing), rendered, &[], &NONE).unwrap();
        assert!(out.contents.contains("# gemini env"));
        assert!(out.contents.contains("MY_VAR=keep"));
        assert!(out.contents.contains("GEMINI_API_KEY=sk-new"));
        assert!(out.contents.contains("GOOGLE_GEMINI_BASE_URL=https://gw"));
        assert!(!out.contents.contains("GEMINI_API_KEY=old"));
    }

    #[test]
    fn env_removal_respects_user_edits() {
        let first = merge(TemplateFormat::Shell, None, "OURS=1\n", &[], &NONE).unwrap();
        let second = merge(TemplateFormat::Shell, Some(&first.contents), "OTHER=2\n", &first.owned, &NONE)
            .unwrap();
        assert!(!second.contents.contains("OURS=1"));

        let first = merge(TemplateFormat::Shell, None, "OURS=1\n", &[], &NONE).unwrap();
        let edited = first.contents.replace("OURS=1", "OURS=edited");
        let third = merge(TemplateFormat::Shell, Some(&edited), "OTHER=2\n", &first.owned, &NONE).unwrap();
        assert!(third.contents.contains("OURS=edited"));
        assert_eq!(third.kept_edited, vec!["OURS".to_string()]);
    }

    // ----- ownership hashes feed removal decisions -----

    #[test]
    fn paste_sentinel_never_clobbers_user_filled_value() {
        // BYOK flow: the render carries the upstream-key sentinel; the user
        // pastes their real key over it; a later re-render must keep it.
        let rendered =
            r#"{"env": {"ANTHROPIC_AUTH_TOKEN": "<paste-your-upstream-api-key-here>"}}"#;
        let first = merge(TemplateFormat::Json, None, rendered, &[], &NONE).unwrap();
        let v: serde_json::Value = serde_json::from_str(&first.contents).unwrap();
        assert_eq!(v["env"]["ANTHROPIC_AUTH_TOKEN"], "<paste-your-upstream-api-key-here>");

        let pasted = first
            .contents
            .replace("<paste-your-upstream-api-key-here>", "sk-ant-real-key");
        let second = merge(TemplateFormat::Json, Some(&pasted), rendered, &first.owned, &NONE).unwrap();
        let v: serde_json::Value = serde_json::from_str(&second.contents).unwrap();
        assert_eq!(v["env"]["ANTHROPIC_AUTH_TOKEN"], "sk-ant-real-key");

        // Same contract for TOML and env files.
        let rendered_toml = "key = \"<paste-your-upstream-api-key-here>\"\n";
        let first = merge(TemplateFormat::Toml, None, rendered_toml, &[], &NONE).unwrap();
        let pasted = first.contents.replace("<paste-your-upstream-api-key-here>", "real");
        let second = merge(TemplateFormat::Toml, Some(&pasted), rendered_toml, &first.owned, &NONE).unwrap();
        assert!(second.contents.contains("key = \"real\""));

        let rendered_env = "UPSTREAM=<paste-your-upstream-api-key-here>\n";
        let first = merge(TemplateFormat::Shell, None, rendered_env, &[], &NONE).unwrap();
        let pasted = first.contents.replace("<paste-your-upstream-api-key-here>", "real");
        let second = merge(TemplateFormat::Shell, Some(&pasted), rendered_env, &first.owned, &NONE).unwrap();
        assert!(second.contents.contains("UPSTREAM=real"));
    }

    // ----- keyed arrays -----

    fn keyed(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(p, k)| (p.to_string(), k.to_string())).collect()
    }

    fn yaml_names(contents: &str, key: &str) -> Vec<String> {
        let v: yaml_serde::Value = yaml_serde::from_str(contents).unwrap();
        v[key]
            .as_sequence()
            .map(|s| s.iter().map(|e| e["name"].as_str().unwrap().to_string()).collect())
            .unwrap_or_default()
    }

    /// Continue's `models`: the user's own model survives a provision, ours is
    /// appended after it, and a later render replaces only ours.
    #[test]
    fn yaml_keyed_sequence_keeps_the_users_entries_beside_ours() {
        let k = keyed(&[("/models", "name")]);
        let existing = "name: mine\nmodels:\n  - name: local-llama\n    provider: ollama\n";
        let first = merge(TemplateFormat::Yaml, Some(existing), "models:\n  - name: gw-a\n    provider: openai\n", &[], &k)
            .unwrap();
        assert_eq!(yaml_names(&first.contents, "models"), ["local-llama", "gw-a"]);
        assert_eq!(first.owned.len(), 1);
        assert_eq!(first.owned[0].entry.as_ref().map(|e| e.id.as_str()), Some("gw-a"));

        // The gateway now offers gw-b instead of gw-a: ours is swapped, theirs stays first.
        let second = merge(
            TemplateFormat::Yaml,
            Some(&first.contents),
            "models:\n  - name: gw-b\n    provider: openai\n",
            &first.owned,
            &k,
        )
        .unwrap();
        assert_eq!(yaml_names(&second.contents, "models"), ["local-llama", "gw-b"]);
        assert!(second.kept_edited.is_empty());
        // Same render again changes nothing.
        let third = merge(
            TemplateFormat::Yaml,
            Some(&second.contents),
            "models:\n  - name: gw-b\n    provider: openai\n",
            &second.owned,
            &k,
        )
        .unwrap();
        assert_eq!(second.contents, third.contents);
    }

    /// Aider's `set-env`: an entry is a `NAME=value` string identified by its
    /// name, so ours replaces the user's entry for that name, their other
    /// entries stay, and one the render dropped goes while unedited.
    #[test]
    fn yaml_string_entries_merge_by_the_name_before_the_equals_sign() {
        let k = keyed(&[("/set-env", streamscope_client_templates::STRING_ENTRIES)]);
        let env = |contents: &str| -> Vec<String> {
            let v: yaml_serde::Value = yaml_serde::from_str(contents).unwrap();
            v["set-env"]
                .as_sequence()
                .map(|s| s.iter().map(|e| e.as_str().unwrap().to_string()).collect())
                .unwrap_or_default()
        };
        let existing = "set-env:\n  - AWS_REGION=eu-west-1\n  - ANTHROPIC_API_BASE=https://old\n";
        let first = merge(TemplateFormat::Yaml, Some(existing), "set-env:\n  - ANTHROPIC_API_BASE=https://gw\n", &[], &k)
            .unwrap();
        assert_eq!(env(&first.contents), ["AWS_REGION=eu-west-1", "ANTHROPIC_API_BASE=https://gw"]);

        let second = merge(TemplateFormat::Yaml, Some(&first.contents), "model: x\n", &first.owned, &k).unwrap();
        assert_eq!(env(&second.contents), ["AWS_REGION=eu-west-1"]);

        // A single string the user wrote is their one entry, kept beside ours;
        // a spaced name is the same variable.
        let out = merge(TemplateFormat::Yaml, Some("set-env: AWS_REGION=eu-west-1\n"), "set-env:\n  - A=1\n", &[], &k)
            .unwrap();
        assert_eq!(env(&out.contents), ["AWS_REGION=eu-west-1", "A=1"]);
        let out = merge(TemplateFormat::Yaml, Some("set-env:\n  - A = 0\n"), "set-env:\n  - A=1\n", &[], &k).unwrap();
        assert_eq!(env(&out.contents), ["A=1"]);
    }

    /// The same mode in JSON, where an entry with no `=` is its own name.
    #[test]
    fn json_string_entries_without_an_equals_sign_are_their_own_name() {
        let k = keyed(&[("/p", streamscope_client_templates::STRING_ENTRIES)]);
        let out = merge(TemplateFormat::Json, Some(r#"{"p": ["mine"]}"#), r#"{"p": ["gw"]}"#, &[], &k).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out.contents).unwrap();
        assert_eq!(v["p"], serde_json::json!(["mine", "gw"]));
    }

    /// The render is authoritative for an entry of ours: a field it stopped
    /// rendering goes (a capability the model lost), and so does one the user
    /// added. An entry edited SINCE the last write is kept when the render
    /// drops it, and named in the warning.
    #[test]
    fn yaml_keyed_entry_is_replaced_by_the_render_and_kept_if_edited_when_dropped() {
        let k = keyed(&[("/models", "name")]);
        let first = merge(
            TemplateFormat::Yaml,
            None,
            "models:\n  - name: gw-a\n    capabilities:\n      - image_input\n",
            &[],
            &k,
        )
        .unwrap();
        let updated = merge(TemplateFormat::Yaml, Some(&first.contents), "models:\n  - name: gw-a\n    provider: openai\n", &first.owned, &k)
            .unwrap();
        let v: yaml_serde::Value = yaml_serde::from_str(&updated.contents).unwrap();
        assert!(v["models"][0].get("capabilities").is_none(), "a field the render dropped stayed: {v:?}");
        assert_eq!(v["models"][0]["provider"], "openai");

        let mut doc = v;
        doc["models"][0]["temperature"] = yaml_serde::Value::from(0.2);
        let edited = yaml_serde::to_string(&doc).unwrap();
        let dropped = merge(TemplateFormat::Yaml, Some(&edited), "name: x\n", &updated.owned, &k).unwrap();
        assert_eq!(yaml_names(&dropped.contents, "models"), ["gw-a"]);
        assert_eq!(dropped.kept_edited, vec!["/models[name=gw-a]".to_string()]);
    }

    /// A template that stops keying an array but still renders it owns the
    /// array whole again: what it just wrote is not removed as a leftover.
    #[test]
    fn an_array_no_longer_keyed_but_still_rendered_is_written_whole() {
        let k = keyed(&[("/models", "name")]);
        let rendered = "models:\n  - name: gw-a\n";
        let first = merge(TemplateFormat::Yaml, None, rendered, &[], &k).unwrap();
        let second = merge(TemplateFormat::Yaml, Some(&first.contents), rendered, &first.owned, &NONE).unwrap();
        assert_eq!(yaml_names(&second.contents, "models"), ["gw-a"]);
        assert!(second.owned.iter().any(|o| o.path == "/models" && o.entry.is_none()));
    }

    /// Only the identity field changed: the render's entries are written once,
    /// under the new field, not written and then removed as the old field's.
    #[test]
    fn changing_the_identity_field_keeps_the_rendered_entries() {
        let rendered = "models:\n  - name: gw-a\n    id: a\n";
        let first = merge(TemplateFormat::Yaml, Some("models:\n  - name: mine\n"), rendered, &[], &keyed(&[("/models", "name")]))
            .unwrap();
        let second =
            merge(TemplateFormat::Yaml, Some(&first.contents), rendered, &first.owned, &keyed(&[("/models", "id")])).unwrap();
        assert_eq!(yaml_names(&second.contents, "models"), ["mine", "gw-a"]);
        assert!(second.owned.iter().all(|o| o.entry.as_ref().is_none_or(|e| e.key == "id")));
    }

    /// A numeric-looking alias parses as a number: it still identifies its entry.
    #[test]
    fn a_numeric_identity_still_identifies_its_entry() {
        let k = keyed(&[("/models", "name")]);
        let first = merge(TemplateFormat::Yaml, Some("models:\n  - name: mine\n"), "models:\n  - name: 42\n", &[], &k).unwrap();
        let second = merge(TemplateFormat::Yaml, Some(&first.contents), "models:\n  - name: 3.5\n", &first.owned, &k).unwrap();
        let v: yaml_serde::Value = yaml_serde::from_str(&second.contents).unwrap();
        let names: Vec<String> =
            v["models"].as_sequence().unwrap().iter().map(|e| yaml_serde::to_string(&e["name"]).unwrap().trim().to_string()).collect();
        assert_eq!(names, ["mine", "3.5"]);
    }

    /// The render stops carrying the array (no MCP server selected any more):
    /// ours go, the user's stay, and an array that only held ours is removed.
    #[test]
    fn yaml_keyed_sequence_left_empty_by_the_render_removes_only_ours() {
        let k = keyed(&[("/mcpServers", "name")]);
        let first = merge(TemplateFormat::Yaml, Some("mcpServers:\n  - name: mine\n"), "mcpServers:\n  - name: web\n", &[], &k)
            .unwrap();
        let second = merge(TemplateFormat::Yaml, Some(&first.contents), "name: x\n", &first.owned, &k).unwrap();
        assert_eq!(yaml_names(&second.contents, "mcpServers"), ["mine"]);

        let only_ours = merge(TemplateFormat::Yaml, None, "mcpServers:\n  - name: web\n", &[], &k).unwrap();
        let gone = merge(TemplateFormat::Yaml, Some(&only_ours.contents), "name: x\n", &only_ours.owned, &k).unwrap();
        let v: yaml_serde::Value = yaml_serde::from_str(&gone.contents).unwrap();
        assert!(v.get("mcpServers").is_none(), "an emptied array should go: {v:?}");
    }

    /// A manifest written while the array was still one owned leaf recorded
    /// the whole array. Unedited since, every entry in it is ours; edited, the
    /// user's cannot be told from ours, so nothing is removed.
    #[test]
    fn a_whole_array_record_from_an_older_manifest_is_settled_by_entry() {
        let k = keyed(&[("/models", "name")]);
        let old = merge(TemplateFormat::Yaml, None, "models:\n  - name: gw-a\n  - name: gw-b\n", &[], &NONE).unwrap();
        assert_eq!(old.owned.len(), 1, "the old rule records the array as one leaf");
        assert!(old.owned[0].entry.is_none());

        let unedited = merge(TemplateFormat::Yaml, Some(&old.contents), "models:\n  - name: gw-b\n", &old.owned, &k).unwrap();
        assert_eq!(yaml_names(&unedited.contents, "models"), ["gw-b"]);
        assert!(unedited.kept_edited.is_empty());
        assert!(unedited.owned.iter().all(|o| o.entry.is_some()));

        let mut doc: yaml_serde::Value = yaml_serde::from_str(&old.contents).unwrap();
        let mine: yaml_serde::Value = yaml_serde::from_str("name: mine").unwrap();
        doc["models"].as_sequence_mut().unwrap().push(mine);
        let edited = yaml_serde::to_string(&doc).unwrap();
        let kept = merge(TemplateFormat::Yaml, Some(&edited), "models:\n  - name: gw-b\n", &old.owned, &k).unwrap();
        assert_eq!(yaml_names(&kept.contents, "models"), ["gw-a", "gw-b", "mine"]);
        assert_eq!(kept.kept_edited, vec!["/models".to_string()]);
    }

    /// The template writing a file stops keying an array — Continue switched
    /// from its combined template to MCP-only. Our entries there are still
    /// ours: removed while unedited, never left behind untracked.
    #[test]
    fn entries_of_an_array_the_template_stopped_keying_are_still_removed() {
        let both = keyed(&[("/models", "name"), ("/mcpServers", "name")]);
        let mcp_only = keyed(&[("/mcpServers", "name")]);
        let existing = "models:\n  - name: mine\n";
        let first = merge(
            TemplateFormat::Yaml,
            Some(existing),
            "models:\n  - name: gw-a\nmcpServers:\n  - name: web\n",
            &[],
            &both,
        )
        .unwrap();
        assert_eq!(yaml_names(&first.contents, "models"), ["mine", "gw-a"]);

        let second =
            merge(TemplateFormat::Yaml, Some(&first.contents), "mcpServers:\n  - name: web\n", &first.owned, &mcp_only)
                .unwrap();
        assert_eq!(yaml_names(&second.contents, "models"), ["mine"]);
        assert_eq!(yaml_names(&second.contents, "mcpServers"), ["web"]);
        assert!(second.owned.iter().all(|o| o.path != "/models"), "{:?}", second.owned);

        // Same with no keyed array declared at all, and for TOML.
        let toml_first =
            merge(TemplateFormat::Toml, None, "[[models]]\nname = \"gw-a\"\n", &[], &keyed(&[("/models", "name")])).unwrap();
        let toml_second = merge(TemplateFormat::Toml, Some(&toml_first.contents), "a = 1\n", &toml_first.owned, &NONE).unwrap();
        assert!(!toml_second.contents.contains("gw-a"), "{}", toml_second.contents);
    }

    #[test]
    fn a_keyed_render_without_unique_string_identities_is_refused() {
        let k = keyed(&[("/models", "name")]);
        let dup = merge(TemplateFormat::Yaml, None, "models:\n  - name: a\n  - name: a\n", &[], &k);
        assert!(dup.is_err_and(|e| e.to_string().contains("share")));
        let missing = merge(TemplateFormat::Yaml, None, "models:\n  - provider: x\n", &[], &k);
        assert!(missing.is_err_and(|e| e.to_string().contains("to identify it by")));
        let not_array = merge(TemplateFormat::Json, None, r#"{"models": {"a": 1}}"#, &[], &k);
        assert!(not_array.is_err());
    }

    #[test]
    fn json_keyed_array_keeps_the_users_entries_and_sentinels() {
        let k = keyed(&[("/servers", "name")]);
        let existing = r#"{"servers": [{"name": "mine", "url": "u"}]}"#;
        let rendered = r#"{"servers": [{"name": "gw", "key": "<paste-your-upstream-api-key-here>"}]}"#;
        let first = merge(TemplateFormat::Json, Some(existing), rendered, &[], &k).unwrap();
        let pasted = first.contents.replace("<paste-your-upstream-api-key-here>", "sk-real");
        let second = merge(TemplateFormat::Json, Some(&pasted), rendered, &first.owned, &k).unwrap();
        let v: serde_json::Value = serde_json::from_str(&second.contents).unwrap();
        assert_eq!(v["servers"][0]["name"], "mine");
        assert_eq!(v["servers"][1]["key"], "sk-real", "a filled paste sentinel survives: {v}");
    }

    /// Vibe's `[[providers]]` + `[[models]]`: the user's own provider and model
    /// survive, their comment too, and a re-run is byte-identical.
    #[test]
    fn toml_keyed_arrays_of_tables_keep_the_users_entries() {
        let k = keyed(&[("/providers", "name"), ("/models", "name")]);
        let existing = "active_model = \"mine\"\n\n# my own provider\n[[providers]]\nname = \"local\"\napi_base = \"http://localhost\"\n\n[[models]]\nname = \"mine\"\nprovider = \"local\"\n";
        let rendered = "active_model = \"gw-a\"\n\n[[providers]]\nname = \"streamscope\"\napi_base = \"https://gw\"\n\n[[models]]\nname = \"gw-a\"\nprovider = \"streamscope\"\n";
        let first = merge(TemplateFormat::Toml, Some(existing), rendered, &[], &k).unwrap();
        let names = |key: &str, contents: &str| -> Vec<String> {
            let doc: toml_edit::DocumentMut = contents.parse().unwrap();
            doc[key]
                .as_array_of_tables()
                .unwrap()
                .iter()
                .map(|t| t["name"].as_str().unwrap().to_string())
                .collect()
        };
        assert_eq!(names("providers", &first.contents), ["local", "streamscope"]);
        assert_eq!(names("models", &first.contents), ["mine", "gw-a"]);
        assert!(first.contents.contains("# my own provider"), "{}", first.contents);
        assert!(first
            .owned
            .iter()
            .any(|o| o.path == "providers" && o.entry.as_ref().is_some_and(|e| e.id == "streamscope")));

        let again = merge(TemplateFormat::Toml, Some(&first.contents), rendered, &first.owned, &k).unwrap();
        assert_eq!(first.contents, again.contents);
        assert!(again.kept_edited.is_empty());

        let swapped = rendered.replace("gw-a", "gw-b");
        let second = merge(TemplateFormat::Toml, Some(&first.contents), &swapped, &first.owned, &k).unwrap();
        assert_eq!(names("models", &second.contents), ["mine", "gw-b"]);
        assert!(second.kept_edited.is_empty(), "{:?}", second.kept_edited);
    }

    /// A user who wrote the array inline keeps that layout and its comment.
    #[test]
    fn toml_keyed_inline_array_stays_inline() {
        let k = keyed(&[("/providers", "name")]);
        let existing = "providers = [{ name = \"local\", api_base = \"http://localhost\" }] # mine\n";
        let out = merge(TemplateFormat::Toml, Some(existing), "[[providers]]\nname = \"streamscope\"\n", &[], &k).unwrap();
        assert!(out.contents.starts_with("providers = ["), "{}", out.contents);
        assert!(out.contents.contains("# mine"), "{}", out.contents);
        assert!(!out.contents.contains("[[providers]]"), "{}", out.contents);
        let doc: toml_edit::DocumentMut = out.contents.parse().unwrap();
        let names: Vec<&str> =
            doc["providers"].as_array().unwrap().iter().map(|v| v.as_inline_table().unwrap()["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["local", "streamscope"]);
    }

    #[test]
    fn toml_keyed_array_of_ours_alone_is_removed_with_its_last_entry() {
        let k = keyed(&[("/providers", "name")]);
        let first = merge(TemplateFormat::Toml, None, "[[providers]]\nname = \"streamscope\"\n", &[], &k).unwrap();
        let second = merge(TemplateFormat::Toml, Some(&first.contents), "other = 1\n", &first.owned, &k).unwrap();
        assert!(!second.contents.contains("providers"), "{}", second.contents);
        assert!(second.contents.contains("other = 1"));
    }

    #[test]
    fn owned_leaf_hash_matches_written_value() {
        let out = merge(TemplateFormat::Json, None, r#"{"k": "v"}"#, &[], &NONE).unwrap();
        assert_eq!(out.owned[0].path, "/k");
        assert_eq!(out.owned[0].value_hash, sha256_hex(b"\"v\""));
    }
}

//! The shipped credential *path* rules (`ASI02-02` read, `ASI02-04` write),
//! against the shipped field profiles, on paths an agent actually opens.
//!
//! These are the sibling of `ASI02-05` (`seeded_shell_credential_rule.rs`) and
//! carry the same hazard for the same reason: both block by default, so a
//! false positive is not noise — it deletes a tool call out of a finished
//! response and the caller loses the turn. Their needles are file references
//! matched inside a path, and an alternative with no right-hand boundary runs
//! on into whatever follows it: `\.key` matches inside `release.keystore`,
//! `\.env` inside `.environment/`, `\.pem` inside `.pemberton`.
//!
//! The exposure is narrower than `ASI02-05`'s — a path is not the haystack of
//! identifiers a whole shell command is — but the class is identical, and the
//! fix has the same two halves: add the boundary AND name the credential
//! stores whose suffix runs past the stem, so tightening costs no coverage.
//!
//! Both directions are asserted per rule. A rule that stopped firing entirely
//! would pass a false-positive test on its own.
//!
//! The seeds are read from disk rather than restated here, so a needle edit
//! that breaks either direction fails this test instead of shipping.

use std::path::{Path, PathBuf};

use serde_json::json;
use streamscope_core::config::tool_rules::{
    FieldProfile, FieldProfileSet, Rule, classify_tool_call,
};

/// The app the seeded `Read` / `Write` profiles are filtered to
/// (`claude-code|claude*`).
const APP: Option<&str> = Some("claude-code");
const READ_RULE: &str = "ASI02-02";
const WRITE_RULE: &str = "ASI02-04";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate is two levels below the repo root")
        .to_path_buf()
}

fn seed<T: serde::de::DeserializeOwned>(name: &str) -> Vec<T> {
    let path = repo_root().join("seeds/tool-policy").join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// Run one path through the shipped rule — the real seed entry, the real field
/// profiles, the real path normaliser — and return the id that fired.
///
/// The ruleset is narrowed to the rule under test for the same reason its
/// shell sibling does it: evaluation returns the FIRST matching rule, so
/// against the full seed a neighbour could answer in either direction — a
/// positive passing on someone else's match, or a negative reporting this rule
/// innocent of a block another rule made.
fn fired_rule(rule: &str, tool: &str, path: &str) -> Option<String> {
    let rules: Vec<Rule> = seed::<Rule>("rules.json")
        .into_iter()
        .filter(|r| r.id == rule)
        .collect();
    assert_eq!(rules.len(), 1, "{rule} is not in the shipped ruleset exactly once");
    let profiles = FieldProfileSet::new(seed::<FieldProfile>("tool_field_profiles.json"));
    // The seeded Claude profiles read the path from `file_path`, not `path`.
    let args = json!({ "file_path": path });
    let result = classify_tool_call(&rules, None, APP, Some(&profiles), tool, Some(&args));
    // The profile must resolve, or every assertion below passes vacuously.
    assert!(
        result.tool_id.is_some(),
        "the seeded {tool} profile no longer resolves — every case here would pass for the wrong reason"
    );
    result.id
}

/// Paths that contain a needle as a bare substring and nothing else. Each one
/// is a real name an agent opens: the boundary is what separates them from the
/// credential store whose stem they share.
const INNOCENT: &[&str] = &[
    "/home/u/.environment/notes.md",
    "/srv/.pemberton/app.conf",
    "/home/u/project/docs/api.keyword",
    "/home/u/project/src/.envision/config.toml",
    "/home/u/project/keymap.json",
];

/// Real credential references, including the four whose suffix runs past the
/// `.env` / `.pem` / `.key` stem. The right-hand boundary that stops
/// `api.keyword` also stops these, so each is named in the pattern rather than
/// caught by accident — drop a name and this test says so.
const CREDENTIALS: &[&str] = &[
    "/home/u/.ssh/id_rsa",
    "/home/u/.ssh/id_ed25519",
    "/home/u/.aws/credentials",
    "/etc/ssl/server.pem",
    "/home/u/deploy.key",
    "/home/u/project/.env",
    "/home/u/project/.env.local",
    "/srv/app/.envrc",
    "/home/u/Library/Keychains/login.keychain-db",
    "/opt/app/release.keystore",
    "/home/u/.gnupg/secring.keyring",
];

#[test]
fn an_ordinary_path_that_merely_contains_a_needle_is_not_a_credential_read() {
    for path in INNOCENT {
        assert_ne!(
            fired_rule(READ_RULE, "Read", path).as_deref(),
            Some(READ_RULE),
            "credential-read rule fired on an ordinary path: {path}"
        );
    }
}

#[test]
fn a_real_credential_path_still_blocks_a_read() {
    // The positive control. Without it the test above goes on passing after the
    // rule stops matching anything at all.
    for path in CREDENTIALS {
        assert_eq!(
            fired_rule(READ_RULE, "Read", path).as_deref(),
            Some(READ_RULE),
            "credential-read rule did not fire on a real credential path: {path}"
        );
    }
}

#[test]
fn an_ordinary_path_that_merely_contains_a_needle_is_not_a_credential_write() {
    for path in INNOCENT {
        assert_ne!(
            fired_rule(WRITE_RULE, "Write", path).as_deref(),
            Some(WRITE_RULE),
            "credential-write rule fired on an ordinary path: {path}"
        );
    }
}

#[test]
fn a_real_credential_path_still_blocks_a_write() {
    for path in CREDENTIALS {
        // `ASI02-04` deliberately carries no `.aws/` or `.gnupg/` alternative —
        // it names the stores a write would tamper with, and those two
        // directories are covered on the read side. Assert only what this rule
        // claims, or the test pins a scope decision it did not make.
        if path.contains("/.aws/") || path.contains("/.gnupg/") {
            continue;
        }
        assert_eq!(
            fired_rule(WRITE_RULE, "Write", path).as_deref(),
            Some(WRITE_RULE),
            "credential-write rule did not fire on a real credential path: {path}"
        );
    }
}

/// Codex also applies a patch through its `shell` function, which intercepts
/// the command rather than running it — as an argv, or a heredoc under
/// `bash -lc`, either given as an argv or as one string. That call answers for
/// the patch tool too, so the write rule reads every file the patch touches.
/// Both directions: an innocent edit and a command that only names a
/// credential file without applying a patch stay allowed.
#[test]
fn a_patch_applied_through_the_shell_is_read_by_the_write_rule() {
    let rules: Vec<Rule> = seed::<Rule>("rules.json")
        .into_iter()
        .filter(|r| r.id == WRITE_RULE)
        .collect();
    let profiles = FieldProfileSet::new(seed::<FieldProfile>("tool_field_profiles.json"));
    let fired = |command: serde_json::Value| {
        let args = json!({ "command": command });
        classify_tool_call(&rules, None, Some("codex"), Some(&profiles), "shell", Some(&args)).id
    };
    let patch = |file: &str| format!("*** Begin Patch\n*** Update File: {file}\n@@\n-a\n+b\n*** End Patch\n");
    let spellings = |file: &str| {
        let heredoc = format!("apply_patch <<'EOF'\n{}EOF\n", patch(file));
        [
            json!(["apply_patch", patch(file)]),
            json!(["applypatch", patch(file)]),
            json!(["bash", "-lc", heredoc]),
            json!(heredoc),
        ]
    };
    for command in spellings("/home/u/.ssh/authorized_keys") {
        assert_eq!(fired(command.clone()).as_deref(), Some(WRITE_RULE), "{command}");
    }
    // Changing directory first does not hide the file: the patch's relative
    // path is read where it is applied.
    let in_ssh = format!("cd /home/u/.ssh && apply_patch <<'EOF'\n{}EOF\n", patch("authorized_keys"));
    assert_eq!(fired(json!(["bash", "-lc", in_ssh])).as_deref(), Some(WRITE_RULE));
    // So does running the call in it.
    let args = json!({ "command": ["apply_patch", patch("authorized_keys")], "workdir": "/home/u/.ssh" });
    assert_eq!(
        classify_tool_call(&rules, None, Some("codex"), Some(&profiles), "shell", Some(&args)).id.as_deref(),
        Some(WRITE_RULE)
    );
    // A Responses built-in shell call holding the one heredoc script.
    let args = json!({ "commands": [format!("apply_patch <<'EOF'\n{}EOF\n", patch("/home/u/.ssh/authorized_keys"))] });
    assert_eq!(
        classify_tool_call(&rules, None, None, Some(&profiles), "shell_call", Some(&args)).id.as_deref(),
        Some(WRITE_RULE)
    );
    for command in spellings("src/main.rs") {
        assert_eq!(fired(command.clone()), None, "{command}");
    }
    assert_eq!(fired(json!(["cat", "/home/u/.ssh/id_rsa"])), None);
    // A script that runs anything beside the patch is not intercepted: Codex
    // runs it, so it is read as the shell command it is, never as an edit.
    let and_more = format!("apply_patch <<'EOF'\n{}EOF\nrm -rf ~\n", patch("/home/u/.ssh/authorized_keys"));
    assert_eq!(fired(json!(["bash", "-lc", and_more])), None);
}

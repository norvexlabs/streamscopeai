//! The shipped "credential access via shell" rule (`ASI02-05`), against the
//! shipped field profiles, on commands an agent actually runs.
//!
//! This rule blocks by default, so a false positive is not noise — it deletes a
//! tool call out of a finished response, and the caller loses the turn. Its
//! needles are file references (`.ssh/`, `.env`, `.pem`, `.key`, …) matched
//! inside a whole shell command, which is a haystack full of identifiers: a
//! plain substring scan for `.key` also fires on `o.keys()`, and did, blocking
//! a Claude Code session that was reading the keys of a dictionary.
//!
//! A rule that reads attacker-chosen text belongs at this level, not at the
//! system tier: the cases that matter are the ones nobody thinks to send
//! through a live gateway. Both directions are asserted — a rule that stops
//! firing entirely would pass a false-positive test alone.
//!
//! The seeds are read from disk rather than restated here, so a needle edit
//! that breaks either direction fails this test instead of shipping.

use std::path::{Path, PathBuf};

use serde_json::json;
use streamscope_core::config::tool_rules::{
    FieldProfile, FieldProfileSet, Rule, classify_tool_call,
};

/// The app the seeded `Bash` profile is filtered to (`claude-code|claude*`).
const APP: Option<&str> = Some("claude-code");
const RULE: &str = "ASI02-05";

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

/// Run one shell command through the shipped rule — the real seed entry, the
/// real field profiles, the real shell normaliser — and return the id that
/// fired.
///
/// The ruleset is narrowed to `ASI02-05` on purpose. Evaluation returns the
/// FIRST matching rule, so against the full seed a sibling could answer for it
/// in either direction: a positive would pass on someone else's match, and a
/// negative would report this rule innocent of a block another rule made. One
/// rule in, one rule asserted.
fn fired_rule(command: &str) -> Option<String> {
    let rules: Vec<Rule> = seed::<Rule>("rules.json")
        .into_iter()
        .filter(|r| r.id == RULE)
        .collect();
    assert_eq!(rules.len(), 1, "{RULE} is not in the shipped ruleset exactly once");
    let profiles = FieldProfileSet::new(seed::<FieldProfile>("tool_field_profiles.json"));
    let args = json!({ "command": command });
    let result = classify_tool_call(&rules, None, APP, Some(&profiles), "Bash", Some(&args));
    // The profile must resolve, or every assertion below passes vacuously.
    assert_eq!(
        result.tool_id.as_deref(),
        Some("shell_exec"),
        "the seeded Bash profile no longer resolves — every case here would pass for the wrong reason"
    );
    result.id
}

/// The command from the session this rule broke. Kept verbatim: the substring
/// that fired is `.key` inside `o.keys()`, and paraphrasing it loses the case.
const INCIDENT: &str = r#"f=/home/u/.claude/projects/-home-u-Projects-p/abc.jsonl
echo "=== size ==="; ls -lh "$f" | awk '{print $5, $9}'
echo "=== keys per entry type ==="; python3 -c "
import json, collections
c = collections.Counter()
types = collections.defaultdict(lambda: [])
for line in open('$f'):
    o = json.loads(line)
    c[o.get('type','?')] += 1
    types[o.get('type','?')].append(sorted(o.keys()))
for t, n in c.most_common():
    print(f'{t}: {n} entries, keys={types[t][0]}')
""#;

#[test]
fn ordinary_code_that_merely_contains_a_needle_is_not_credential_access() {
    for command in [
        INCIDENT,
        // Each of these contains a needle as a bare substring and nothing else.
        r#"python3 -c "print(sorted(o.keys()))""#,
        "jq '.keys[]' data.json",
        "grep -r '.keyword' src/",
        "npm run build --keystore",
        "cat .environment_notes.md",
        "echo .pemberton > /tmp/name",
    ] {
        assert_ne!(
            fired_rule(command).as_deref(),
            Some(RULE),
            "credential rule fired on ordinary code: {command}"
        );
    }
}

#[test]
fn a_real_credential_reference_still_blocks() {
    // The positive control. Without it the test above goes on passing after the
    // rule stops matching anything at all.
    for command in [
        "cat ~/.ssh/id_rsa",
        "cat /home/u/.aws/credentials",
        "openssl x509 -in /etc/ssl/server.pem -noout",
        "cp server.key /tmp/",
        "cat deploy.key.bak",
        "cat .env",
        "cat .env.local",
        "gpg --homedir ~/.gnupg/ --list-keys",
        "cat /root/token",
        "ssh-keygen -y -f ~/.ssh/id_ed25519",
        // Credential stores whose suffix runs past the `.key` / `.env` stem.
        // The right-hand boundary that stops `o.keys()` also stops these, so
        // each is named in the pattern rather than caught by accident — drop a
        // name and this test says so.
        "security find-certificate ~/Library/Keychains/login.keychain-db",
        "keytool -list -keystore /opt/app/release.keystore",
        "cat ~/.gnupg/secring.keyring",
        "cat /srv/app/.envrc",
    ] {
        assert_eq!(
            fired_rule(command).as_deref(),
            Some(RULE),
            "credential rule did not fire on a real credential reference: {command}"
        );
    }
}

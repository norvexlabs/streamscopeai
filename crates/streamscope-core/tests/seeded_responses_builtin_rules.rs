//! The shipped tool rules, against the shipped field profiles, on calls to the
//! Responses built-in tools a client runs itself — `local_shell_call`,
//! `shell_call`, `apply_patch_call`, `computer_call`.
//!
//! Such a call is an output item of its own type, not a `function_call`. It
//! reaches policy through the one reader of a tool call (`tool_call_item`),
//! named by its item type and with its payload as its arguments; a rule reaches
//! it only through a field profile for that name. So each case here starts from
//! the item as the upstream sends it, reads it the way the gateway does, and
//! asserts the shipped rule both fires on the dangerous call and stays silent
//! on an ordinary one — a profile that stopped resolving would pass the
//! negative alone.
//!
//! The seeds are read from disk rather than restated here, so a profile or
//! needle edit that breaks either direction fails this test.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use streamscope_core::api::domain::tool_call_item;
use streamscope_core::config::tool_rules::{FieldProfile, FieldProfileSet, Rule, ToolCallResolver, classify_tool_call, patch_block};

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

/// Read `item` as the gateway reads a call, and run it through the one shipped
/// rule `rule` and the shipped profiles: the tool id the call resolved to, and
/// the rule that fired. The ruleset is narrowed to `rule` so a sibling cannot
/// answer for it in either direction.
fn read_through(rule: &str, item: &Value) -> (Option<String>, Option<String>) {
    let rules: Vec<Rule> = seed::<Rule>("rules.json").into_iter().filter(|r| r.id == rule).collect();
    assert_eq!(rules.len(), 1, "{rule} is not in the shipped ruleset exactly once");
    let profiles = FieldProfileSet::new(seed::<FieldProfile>("tool_field_profiles.json"));
    let call = tool_call_item(item).expect("a built-in tool's call item is read as a call");
    assert!(call.builtin.is_some(), "read as a built-in tool's call: {item}");
    let args: Value = serde_json::from_str(&call.arguments).expect("a built-in call's arguments are its JSON payload");
    // No app: the built-in calls are the protocol's own, whichever client runs them.
    let result = classify_tool_call(&rules, None, None, Some(&profiles), call.name, Some(&args));
    (result.tool_id, result.id)
}

fn local_shell(argv: &[&str]) -> Value {
    json!({"type": "local_shell_call", "id": "lsh_1", "call_id": "call_1", "status": "completed",
           "action": {"type": "exec", "command": argv, "env": {}}})
}

fn shell(commands: &[&str]) -> Value {
    json!({"type": "shell_call", "id": "sh_1", "call_id": "call_1", "status": "completed",
           "action": {"commands": commands, "timeout_ms": 10_000}})
}

fn apply_patch(path: &str) -> Value {
    json!({"type": "apply_patch_call", "id": "ap_1", "call_id": "call_1", "status": "completed",
           "operation": {"type": "update_file", "path": path, "diff": "@@\n-a\n+b\n"}})
}

#[test]
fn a_destructive_command_in_a_built_in_shell_call_is_blocked() {
    const RULE: &str = "ASI02-06";
    for item in [
        local_shell(&["bash", "-lc", "rm -rf /"]),
        // An argv: the command is its words, never its JSON text.
        local_shell(&["rm", "-rf", "/"]),
        shell(&["ls -la", "rm -rf /"]),
    ] {
        let (tool_id, fired) = read_through(RULE, &item);
        assert_eq!(tool_id.as_deref(), Some("shell_exec"), "the profile no longer resolves for {item}");
        assert_eq!(fired.as_deref(), Some(RULE), "the rule did not fire on {item}");
    }
}

#[test]
fn an_ordinary_command_in_a_built_in_shell_call_is_not_blocked() {
    // The negative beside the positive above: the profiles resolve, the rule
    // reads the command, and an ordinary one passes.
    const RULE: &str = "ASI02-06";
    for item in [local_shell(&["bash", "-lc", "ls -la"]), shell(&["ls -la", "git status"])] {
        let (tool_id, fired) = read_through(RULE, &item);
        assert_eq!(tool_id.as_deref(), Some("shell_exec"), "the profile no longer resolves for {item}");
        assert_eq!(fired, None, "the rule fired on an ordinary command: {item}");
    }
}

#[test]
fn a_patch_to_a_credential_file_is_blocked_and_one_to_source_is_not() {
    const RULE: &str = "ASI02-04";
    let (tool_id, fired) = read_through(RULE, &apply_patch("/home/u/.ssh/authorized_keys"));
    assert_eq!(tool_id.as_deref(), Some("edit_file"), "the apply_patch_call profile no longer resolves");
    assert_eq!(fired.as_deref(), Some(RULE));
    let (tool_id, fired) = read_through(RULE, &apply_patch("src/main.rs"));
    assert_eq!(tool_id.as_deref(), Some("edit_file"));
    assert_eq!(fired, None, "the rule fired on an ordinary source file");
}

#[test]
fn a_computer_call_resolves_to_a_tool_a_rule_can_name() {
    // No shipped rule targets a computer action; an operator's can, only
    // because the profile gives the call a tool id.
    let profiles = FieldProfileSet::new(seed::<FieldProfile>("tool_field_profiles.json"));
    let item = json!({"type": "computer_call", "id": "cu_1", "call_id": "call_1", "status": "completed",
                      "pending_safety_checks": [], "action": {"type": "keypress", "keys": ["CTRL", "L"]}});
    let call = tool_call_item(&item).expect("read as a call");
    let args: Value = serde_json::from_str(&call.arguments).expect("JSON payload");
    let result = classify_tool_call(&[], None, None, Some(&profiles), call.name, Some(&args));
    assert_eq!(result.tool_id.as_deref(), Some("browser_action"));
}

#[test]
fn a_clients_own_shell_function_keeps_its_profile() {
    // A built-in call is named by its item type precisely so its profiles never
    // answer for a client's tool of the tool's own name (Codex's `shell`
    // function): the client's tool resolves as it did, and the rule still
    // reads its arguments.
    let (tool_id, fired) = {
        let rules: Vec<Rule> = seed::<Rule>("rules.json").into_iter().filter(|r| r.id == "ASI02-06").collect();
        let profiles = FieldProfileSet::new(seed::<FieldProfile>("tool_field_profiles.json"));
        let args = json!({"command": ["bash", "-lc", "rm -rf /"]});
        let result = classify_tool_call(&rules, None, None, Some(&profiles), "shell", Some(&args));
        (result.tool_id, result.id)
    };
    assert_eq!(tool_id.as_deref(), Some("shell_exec"));
    assert_eq!(fired.as_deref(), Some("ASI02-06"));
}

#[test]
fn a_shell_functions_argv_is_read_as_the_command_it_runs() {
    // Codex's `shell` function takes its command as an argv. Read as its JSON
    // text (`["rm","-rf","/"]`), no word is next to the one after it and the
    // shipped needle `rm -rf /` never matched; read as the command line it
    // spells, it does — and an ordinary argv still passes.
    let rules: Vec<Rule> = seed::<Rule>("rules.json").into_iter().filter(|r| r.id == "ASI02-06").collect();
    let profiles = FieldProfileSet::new(seed::<FieldProfile>("tool_field_profiles.json"));
    let fired = |argv: Value| {
        let args = json!({ "command": argv });
        classify_tool_call(&rules, None, None, Some(&profiles), "shell", Some(&args)).id
    };
    assert_eq!(fired(json!(["rm", "-rf", "/"])).as_deref(), Some("ASI02-06"));
    assert_eq!(fired(json!(["ls", "-la", "/"])), None);
}

/// A patch envelope naming `files`, each updated, the way Codex's
/// `apply_patch` and OpenCode's `patch` send it.
fn patch_text(files: &[&str]) -> String {
    let mut text = String::from("*** Begin Patch\n");
    for file in files {
        text.push_str(&format!("*** Update File: {file}\n@@\n-a\n+b\n"));
    }
    text.push_str("*** End Patch\n");
    text
}

/// The shipped rule `rule` against a client's own patch tool: the tool id the
/// call resolved to and the rule that fired.
fn client_patch(rule: &str, app: Option<&str>, tool: &str, args: &Value) -> (Option<String>, Option<String>) {
    let rules: Vec<Rule> = seed::<Rule>("rules.json").into_iter().filter(|r| r.id == rule).collect();
    assert_eq!(rules.len(), 1, "{rule} is not in the shipped ruleset exactly once");
    let profiles = FieldProfileSet::new(seed::<FieldProfile>("tool_field_profiles.json"));
    let result = classify_tool_call(&rules, None, app, Some(&profiles), tool, Some(args));
    (result.tool_id, result.id)
}

#[test]
fn a_patch_tool_is_read_by_the_files_it_touches() {
    // Codex's `apply_patch` custom tool and OpenCode's `patch` name their files
    // inside the patch text. A path rule reads each of them: the system file
    // second in the patch is what fires, and a patch to source alone passes —
    // the profile resolving with the rule silent is the negative's positive
    // control. The rule is an anchored glob on purpose: it matches a whole
    // path, never the patch text around one, so only the files read out of
    // the patch can satisfy it.
    const RULE: &str = "ASI02-03";
    let dangerous = patch_text(&["src/main.rs", "/etc/hosts"]);
    let ordinary = patch_text(&["src/main.rs", "README.md"]);
    // `apply_patch` is read whichever client sends it — Codex, or an agent built
    // on the OpenAI tool whose app is not recognised.
    let cases = [
        (Some("codex"), "apply_patch", "input"),
        (None, "apply_patch", "input"),
        (Some("opencode"), "patch", "patchText"),
    ];
    for (app, tool, wire) in cases {
        let (tool_id, fired) = client_patch(RULE, app, tool, &json!({ wire: dangerous }));
        assert_eq!(tool_id.as_deref(), Some("edit_file"), "{app:?}'s {tool} profile no longer resolves");
        assert_eq!(fired.as_deref(), Some(RULE), "{app:?}'s {tool} hid the system file it patches");
        let (tool_id, fired) = client_patch(RULE, app, tool, &json!({ wire: ordinary }));
        assert_eq!(tool_id.as_deref(), Some("edit_file"));
        assert_eq!(fired, None, "{app:?}'s {tool}: the rule fired on a patch to source");
    }
}

#[test]
fn a_command_codex_runs_through_bash_lc_is_offered_at_argv_0() {
    // Codex runs every command as `bash -lc "<command>"`. An operator's rule
    // on the command's head reads the command inside the wrapper, and stays
    // silent on another head.
    let rule: Rule = serde_json::from_value(json!({
        "id": "op-no-shutdown", "risk": "danger", "phase": "response", "scope": "tool_calls", "action": {"kind": "block"},
        "match": [{"target": "argv[0]", "op": "in", "value": ["shutdown"]}],
    }))
    .expect("a valid rule");
    let profiles = FieldProfileSet::new(seed::<FieldProfile>("tool_field_profiles.json"));
    let fired = |argv: Value| {
        let args = json!({ "command": argv });
        classify_tool_call(std::slice::from_ref(&rule), None, None, Some(&profiles), "shell", Some(&args)).id
    };
    assert_eq!(fired(json!(["bash", "-lc", "shutdown -h now"])).as_deref(), Some("op-no-shutdown"));
    assert_eq!(fired(json!(["bash", "-lc", "ls -la"])), None);
}

#[test]
fn a_patch_tools_text_is_still_read_by_any_arg() {
    // A patch's files are its `path`; its text stays a field of its own, so an
    // `any_arg` rule finds what the patch writes — a crontab entry added to a
    // script — and stays silent on an ordinary edit.
    const RULE: &str = "ASI02-22";
    let writes = |line: &str| format!("*** Begin Patch\n*** Add File: deploy.sh\n+{line}\n*** End Patch\n");
    let cases = [(Some("codex"), "apply_patch", "input"), (Some("opencode"), "patch", "patchText")];
    for (app, tool, wire) in cases {
        let (_, fired) = client_patch(RULE, app, tool, &json!({ wire: writes("echo job | crontab -u root -") }));
        assert_eq!(fired.as_deref(), Some(RULE), "{app:?}'s {tool}: the patch text is no longer read");
        let (_, fired) = client_patch(RULE, app, tool, &json!({ wire: writes("echo hello") }));
        assert_eq!(fired, None, "{app:?}'s {tool}: the rule fired on an ordinary patch");
    }
}

#[test]
fn codexs_string_command_tools_are_read_as_shell_commands() {
    // Codex's `exec_command` takes its script in `cmd`, its legacy
    // `shell_command` in `command`, each as one string, and `write_stdin`
    // types into a running one in `chars`. A destructive command
    // fires the shipped rule and an ordinary one passes — the profile resolving
    // with the rule silent is the negative's positive control.
    const RULE: &str = "ASI02-06";
    for (tool, wire) in [("exec_command", "cmd"), ("shell_command", "command"), ("write_stdin", "chars")] {
        for app in [Some("codex"), None] {
            let (tool_id, fired) = client_patch(RULE, app, tool, &json!({ wire: "rm -rf /", "workdir": "/repo" }));
            assert_eq!(tool_id.as_deref(), Some("shell_exec"), "{app:?}'s {tool} profile no longer resolves");
            assert_eq!(fired.as_deref(), Some(RULE), "{app:?}'s {tool} hid the command it runs");
            let (tool_id, fired) = client_patch(RULE, app, tool, &json!({ wire: "ls -la", "workdir": "/repo" }));
            assert_eq!(tool_id.as_deref(), Some("shell_exec"));
            assert_eq!(fired, None, "{app:?}'s {tool}: the rule fired on an ordinary command");
        }
    }
}

#[test]
fn a_patch_codex_applies_through_exec_command_is_read_by_the_files_it_touches() {
    // A heredoc fed to `apply_patch` through `exec_command` is the patch tool:
    // a path rule on it blocks a patch to a credential file, relative to the
    // call's `workdir`, and passes one to source.
    const RULE: &str = "ASI02-01b";
    let rules: Vec<Rule> = seed::<Rule>("rules.json").into_iter().filter(|r| r.id == RULE).collect();
    let rules: Vec<&Rule> = rules.iter().collect();
    let profiles = FieldProfileSet::new(seed::<FieldProfile>("tool_field_profiles.json"));
    let blocked = |files: &[&str], workdir: &str| {
        let args = json!({ "cmd": format!("apply_patch <<'EOF'\n{}EOF\n", patch_text(files)), "workdir": workdir });
        let call = ToolCallResolver {
            name: "exec_command",
            arguments: Some(&args),
            field_profiles: Some(&profiles),
            app_id: Some("codex"),
            mcp_server: None,
            tool_id: None,
        };
        patch_block(&rules, &call).map(|r| r.id.clone())
    };
    assert_eq!(blocked(&["src/main.rs", "/etc/shadow"], "/repo").as_deref(), Some(RULE));
    assert_eq!(blocked(&["shadow"], "/etc").as_deref(), Some(RULE), "the workdir no longer anchors a relative file");
    assert_eq!(blocked(&["src/main.rs", "README.md"], "/repo"), None);
}

//! Native macOS confinement via Seatbelt (`sandbox-exec`): deny-by-default,
//! read the runtime + CA store, write only the project, and allow network
//! egress only to the loopback guard port. The guard (started by the caller)
//! enforces the gateway-only origin; Seatbelt restricts the agent to the
//! single localhost port the guard listens on.
//!
//! # What this enforces vs. Linux native confinement
//!
//! Seatbelt operates at the MAC framework level (the same plumbing used by
//! Safari and Chrome's renderer sandboxes), not the syscall table. So
//! relative to Linux native confinement (Landlock + seccomp + the egress
//! guard), macOS native confinement enforces every row on FS and IP egress,
//! and most syscall-level denials still apply through kernel-side hardening:
//!
//! | Capability                                          | macOS native outcome |
//! | --------------------------------------------------- | -------------------- |
//! | FS read allow + targeted deny (secret subpaths)     | **enforced** (`file-read*` clauses); preferences readable through cfprefsd's shared memory (`apple.cfprefs.` segments), never writable |
//! | FS write confined to the project + agent state dirs | **enforced** (`file-write*` clauses) — every temp variable names the run's private scratch dir (`sandbox::scratch`); the per-user folders tree runtimes reach through `confstr` is pinned to the *current user's* `/private/var/folders/<2>/<8>` subtree (parent of canonicalized `$TMPDIR`), not the whole per-host parent |
//! | TCP egress pinned to one loopback guard port        | **enforced** at `connect()` (EPERM) |
//! | UDP egress pinned to one loopback guard port        | **enforced** at `sendto()` (EPERM) — `socket(AF_INET, SOCK_DGRAM)` itself is permitted, irrelevant since no packet escapes |
//! | ptrace / `task_for_pid` introspection               | **enforced** by macOS kernel + Seatbelt `process-info*` combine (measured: PT_ATTACH(self) → EPERM) |
//! | AF_UNIX socket creation (`socketpair`)              | **NOT enforced** — Seatbelt has no operation gating AF_UNIX socket creation. Real gap vs Linux native confinement. Mitigation: the egress guard still pins network traffic to the gateway, so AF_UNIX matters only when a sibling unprivileged process on the same host is the adversary (talking to a launchd-published service, for example). Closing this on macOS needs a DYLD_INSERT_LIBRARIES interposer mirror of `sandbox/interposer.rs`. |
//!
//! Seatbelt matches `(subpath …)` against the **canonical resolved path**
//! (`/private/var/folders/…`, not the `/var/folders/…` alias), so every
//! `LaunchSpec.project_root` / `LaunchSpec.cwd` value MUST be canonicalized
//! upstream — otherwise a project under `/tmp` or any symlinked checkout
//! silently misenforces. `commands::run::resolve_real_root` does that.
//!
//! `sandbox-exec` has carried a `__attribute__((deprecated))` warning since
//! macOS 10.15 but remains shipped, supported, and used by Apple's own
//! browser sandboxes. There is no first-party replacement that doesn't
//! require an entitlement + signed app bundle, which is impractical for a
//! CLI tool. If Apple ever removes it, this backend has to fall through to
//! the unconfined `off` mode (matching the existing fall-through for hosts
//! without Landlock).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::protect::{Guard, ProjectGrants};
use super::{profiles, LaunchSpec};
use crate::state::expand_tilde;

/// macOS native confinement is enabled when `/usr/bin/sandbox-exec` is on the
/// host and has at least one execute bit set — every shipping macOS release
/// carries it. The contract this backend enforces, and where it diverges from
/// Linux native confinement, is the module doc table above.
pub fn confinement_supported() -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata("/usr/bin/sandbox-exec")
        .map(|m| m.is_file() && (m.permissions().mode() & 0o111) != 0)
        .unwrap_or(false)
}

/// Build a Seatbelt profile string for `spec`, pinning egress to the guard port.
///
/// Each deny / allow entry emits BOTH `(literal …)` and `(subpath …)` clauses so
/// the same `SECRET_DENY` / `state_dirs` table covers files (`~/.netrc`,
/// `~/.claude.json`) AND directory subtrees (`~/.aws`, `~/.claude`) without the
/// caller having to know the shape ahead of time. `SECRET_DENY` also emits a
/// `(regex #"^<prefix>")` clause so prefix-style entries (`~/.ssh/id_` covering
/// `id_rsa`, `id_ed25519`, …) and entries naming a directory LEVEL with a `*`
/// (a version manager's per-version `etc/npmrc`) match — a wildcard entry emits
/// that clause alone. Every interpolated path is escaped for the SBPL string
/// literal (only `"` and `\` matter); regex patterns also escape POSIX-regex
/// metacharacters in the path.
///
/// `SEATBELT_ONLY_DENY` is applied here too: last-match-wins lets a deny sit
/// inside an allowed tree, which Landlock's allow-only grants cannot express.
///
/// **`SECRET_DENY` is fail-closed.** A `~/`-prefixed entry that fails to expand
/// (`HOME` unset — `sudo` without `-E`, launchd context) is propagated as an
/// error instead of silently dropped. Silent drop here would be fail-OPEN:
/// missing deny clauses leave `~/.aws`, `~/.ssh/id_…` readable through the
/// broad `(allow file-read*)`, and Seatbelt is last-match-wins. Linux native
/// confinement is fail-closed by Landlock's allow-only design (the deny list is
/// unused), so this asymmetry is OK.
///
/// Egress is pinned to `localhost:<port>` for each of `connect_ports` (the
/// guard's, plus an engine-backed client's engine). Seatbelt's
/// `(remote ip "…:…")` parser only accepts `*` or `localhost` as the host
/// part — IP literals are rejected at profile-parse time — and Seatbelt
/// resolves `localhost` to the IPv4 loopback `127.0.0.1` that
/// `guard::start` binds to. Validated against the real `sandbox-exec` by
/// `sandbox_native_macos.sh`.
///
/// `scratch` is the run's private temp dir (`sandbox::scratch`), writable like
/// the project. Exec needs no clause of its own: `(allow process*)` covers
/// exec, and a library written to a write-allowed dir maps executable under
/// `(allow file-read*)`.
fn profile(spec: &LaunchSpec, connect_ports: &[u16], scratch: &Path, project: &ProjectGrants) -> Result<String> {
    profile_with_ttys(spec, connect_ports, scratch, project, &controlling_ttys())
}

/// The terminal devices this process's stdin/stdout/stderr are (`ttyname`),
/// which the client inherits: the only terminals it may set up.
fn controlling_ttys() -> Vec<String> {
    let mut ttys = Vec::new();
    for fd in 0..3 {
        let mut buf = [0 as libc::c_char; 256];
        // SAFETY: isatty/ttyname_r only read the descriptor; ttyname_r writes
        // a NUL-terminated name into `buf`, whose length it is given.
        let name = unsafe {
            if libc::isatty(fd) != 1 || libc::ttyname_r(fd, buf.as_mut_ptr(), buf.len()) != 0 {
                continue;
            }
            std::ffi::CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned()
        };
        if !ttys.contains(&name) {
            ttys.push(name);
        }
    }
    ttys
}

/// [`profile`] granting terminal setup on `ttys` (plus `/dev/tty`).
fn profile_with_ttys(
    spec: &LaunchSpec,
    connect_ports: &[u16],
    scratch: &Path,
    project: &ProjectGrants,
    ttys: &[String],
) -> Result<String> {
    let mut p = String::from("(version 1)\n(deny default)\n(allow process*)\n(allow sysctl-read)\n(allow mach-lookup)\n");
    p.push_str("(allow file-read*)\n");
    // cfprefsd hands preferences to a process through POSIX shared memory:
    // without reading its segments a client that reads its managed
    // preferences fails to start (Codex: "Failed to synchronize managed
    // preferences"). Only cfprefsd's segments, read only; every preference
    // file is already readable above, and writing one stays denied.
    p.push_str("(allow ipc-posix-shm-read-data (ipc-posix-name-prefix \"apple.cfprefs.\"))\n");
    // A TUI puts its terminal in raw mode (`tcsetattr`, an ioctl): without
    // this a full-screen client fails at start ("setRawMode failed with errno:
    // 1"). Only the run's own terminal — never another of the user's sessions.
    p.push_str("(allow file-ioctl (literal \"/dev/tty\"))\n");
    for tty in ttys {
        p.push_str(&format!("(allow file-ioctl (literal \"{}\"))\n", sbpl_escape(tty)));
    }
    // Never TIOCSTI (0x80017472): it pushes bytes into the terminal's input,
    // which the user's shell runs once the client exits. The Linux backend
    // refuses it in seccomp. Last match wins, so this follows the allow.
    p.push_str("(deny file-ioctl (ioctl-command 2147578994))\n");
    for s in profiles::SECRET_DENY.iter().chain(profiles::SEATBELT_ONLY_DENY) {
        let path = expand_tilde(s).with_context(|| {
            format!(
                "the native sandbox can't expand the secret-deny path {s:?} (HOME may be unset) — \
                 set HOME, or pass `--sandbox off` to launch unconfined"
            )
        })?;
        let path_str = path.to_string_lossy();
        push_deny_read(&mut p, &path_str);
    }
    let mut writes: Vec<String> = vec![
        spec.project_root.to_string_lossy().into_owned(),
        "/private/tmp".to_string(),
        scratch.to_string_lossy().into_owned(),
        per_user_folders_root().to_string_lossy().into_owned(),
    ];
    if let Some(agent) = profiles::agent_for(&spec.command) {
        writes.extend(agent.state_dirs.iter().filter_map(|d| {
            expand_tilde(d).ok().map(|p| p.to_string_lossy().into_owned())
        }));
    }
    writes.extend(project.extra_rw.iter().map(|d| d.to_string_lossy().into_owned()));
    for w in writes {
        push_allow_write(&mut p, &w);
    }
    // What the agent must not change inside the writable project (`protect`):
    // after every write allow, since the last match wins.
    // Every protected path, an absent file included: Seatbelt denies a
    // write to a path that does not exist yet, so a link file the agent
    // would create (a `commondir`) is held here too.
    for held in &project.protected {
        let esc = sbpl_escape(&held.path.to_string_lossy());
        match held.guard {
            Guard::Tree => p.push_str(&format!("(deny file-write* (subpath \"{esc}\"))\n")),
            // The node alone: a write to a path inside a folder is checked
            // against that path, so a Node's contents stay writable.
            Guard::File | Guard::Node => p.push_str(&format!("(deny file-write* (literal \"{esc}\"))\n")),
        }
    }
    for port in connect_ports {
        p.push_str(&format!("(allow network-outbound (remote ip \"localhost:{port}\"))\n"));
    }
    // Listening is not restricted on loopback, as on Linux: an engine-backed
    // client's engine, a dev server or an OAuth callback binds and accepts
    // there (`network-inbound` is what lets a listener take a connection).
    p.push_str("(allow network-bind (local ip \"localhost:*\"))\n");
    p.push_str("(allow network-inbound (local ip \"localhost:*\"))\n");
    Ok(p)
}

/// Resolve the current user's per-user folders root, e.g.
/// `/private/var/folders/<2>/<8>` — the parent of `DARWIN_USER_TEMP_DIR` (and
/// also the parent of `DARWIN_USER_CACHE_DIR` and the `0/` per-user dir).
///
/// Many agent runtimes (Python ssl cache, xcode-select shim cache, log writers)
/// touch this tree — through `confstr(_CS_DARWIN_USER_CACHE_DIR)` and its
/// siblings, which no temp variable redirects — and `EPERM` there breaks the
/// run, so it has to be writable
/// — but only the *current* user's subtree. Falling back to the whole
/// `/private/var/folders` parent would also write-allow every other user's
/// per-user state plus system-wide DARWIN_USER_DIR consumers (Mail
/// attachments, WebKit caches, signed-receipt state).
///
/// **Bounded fallback.** The result is always under `/private/var/folders`.
/// If `$TMPDIR` points outside that tree (custom override, `/tmp`, `$HOME/.tmp`,
/// …) or canonicalize fails, fall back to the per-host parent — never to the
/// `$TMPDIR` parent itself, which on `/tmp` would write-allow `/private` and on
/// `$HOME/.tmp` would write-allow the home directory (sidestepping
/// `SECRET_DENY`). A loud `eprintln!` surfaces the fallback so an operator
/// on an exotic `$TMPDIR` knows their scratch tree lost the narrowing.
fn per_user_folders_root() -> PathBuf {
    const FALLBACK: &str = "/private/var/folders";
    let tmp = std::env::temp_dir();
    let canon = match std::fs::canonicalize(&tmp) {
        Ok(c) => c,
        Err(_) => {
            eprintln!(
                "ssai: notice — could not canonicalize $TMPDIR {tmp:?}; \
                 native-sandbox scratch writes pinned to {FALLBACK}"
            );
            return PathBuf::from(FALLBACK);
        }
    };
    let Some(parent) = canon.parent() else {
        return PathBuf::from(FALLBACK);
    };
    if parent.starts_with(FALLBACK) && parent != std::path::Path::new(FALLBACK) {
        parent.to_path_buf()
    } else {
        eprintln!(
            "ssai: notice — $TMPDIR {tmp:?} resolves outside {FALLBACK} \
             (parent={parent:?}); native-sandbox scratch writes pinned to {FALLBACK}"
        );
        PathBuf::from(FALLBACK)
    }
}

/// Emit `(deny file-read* …)` clauses covering a single file (`literal`), a
/// directory subtree (`subpath`), AND a path prefix (`regex`). Seatbelt is
/// last-match-wins, so all three lines after the broad `(allow file-read*)`
/// shadow it whichever shape the path turns out to be.
///
/// An entry carrying a `*` names a level rather than a path, so only the regex
/// clause can express it — a `literal` or `subpath` would match a directory
/// actually called `*`.
fn push_deny_read(p: &mut String, path: &str) {
    if !path.contains('*') {
        let esc = sbpl_escape(path);
        p.push_str(&format!("(deny file-read* (literal \"{esc}\"))\n"));
        p.push_str(&format!("(deny file-read* (subpath \"{esc}\"))\n"));
    }
    p.push_str(&format!(
        "(deny file-read* (regex #\"^{}\"))\n",
        profiles::seatbelt_deny_regex(path)
    ));
}

/// Emit `(allow file-write* …)` clauses covering both an exact file and a
/// directory subtree at the given path.
fn push_allow_write(p: &mut String, path: &str) {
    let esc = sbpl_escape(path);
    p.push_str(&format!("(allow file-write* (literal \"{esc}\"))\n"));
    p.push_str(&format!("(allow file-write* (subpath \"{esc}\"))\n"));
}

/// Escape `"` and `\` for embedding inside a Seatbelt SBPL string literal.
/// Without this, a project path containing either character (legal on Apple
/// filesystems) would either crash sandbox-exec at parse or, with a crafted
/// path, close the string early and inject additional SBPL clauses.
fn sbpl_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// The command that runs `spec.command` with `args` confined via
/// `sandbox-exec`. `env` already carries the proxy vars + CA + per-agent env.
pub fn command(
    spec: &LaunchSpec,
    connect_ports: &[u16],
    scratch: &Path,
    project: &ProjectGrants,
    args: &[String],
    env: &[(String, String)],
) -> Result<tokio::process::Command> {
    let prof = profile(spec, connect_ports, scratch, project)?;
    let mut cmd = tokio::process::Command::new("/usr/bin/sandbox-exec");
    cmd.arg("-p").arg(prof).arg(&spec.command).args(args).current_dir(&spec.cwd);
    for (k, v) in env {
        cmd.env(k, v);
    }
    Ok(cmd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serialize tests that mutate process-global env (`HOME`, `TMPDIR`). Held
    /// for the whole test body so other tests reading the same vars don't race.
    /// Scope is THIS module only — any new test in this crate that reads or
    /// mutates `HOME`/`TMPDIR` MUST acquire this same lock (or move it to a
    /// shared `test_support` module) to stay race-free against these tests.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    const SCRATCH: &str = "/private/tmp/fake-home/.cache/streamscopeai/tmp/42-ab";

    /// The project's holds follow every write allow (last match wins), a
    /// linked worktree's git dir is writable, and a Node holds only itself.
    #[test]
    fn the_projects_holds_follow_its_write_allows() {
        use super::super::protect::Protected;
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: serialized via ENV_LOCK.
        unsafe { std::env::set_var("HOME", "/private/tmp/fake-home"); }
        let project = ProjectGrants {
            extra_rw: vec![PathBuf::from("/Users/me/main/.git")],
            stat_only: vec![],
            protected: vec![
                Protected { path: PathBuf::from("/Users/me/main/.git/hooks"), guard: Guard::Tree },
                Protected { path: PathBuf::from("/Users/me/main/.git"), guard: Guard::Node },
            ],
        };
        let prof = profile(&sample_spec(), &[1], Path::new(SCRATCH), &project).unwrap();
        let allow = prof.find("(allow file-write* (subpath \"/Users/me/main/.git\"))").expect("worktree git dir writable");
        let tree = prof.find("(deny file-write* (subpath \"/Users/me/main/.git/hooks\"))").expect("hooks held");
        let node = prof.find("(deny file-write* (literal \"/Users/me/main/.git\"))").expect("git dir held");
        let last_allow = prof.rfind("(allow file-write*").unwrap();
        assert!(allow < tree && last_allow < tree && last_allow < node, "{prof}");
        assert!(!prof.contains("(deny file-write* (subpath \"/Users/me/main/.git\"))"), "{prof}");
    }

    #[test]
    fn profile_lets_the_client_write_its_runs_scratch_dir_only() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: serialized via ENV_LOCK.
        unsafe { std::env::set_var("HOME", "/private/tmp/fake-home"); }
        let prof = profile(&sample_spec(), &[12345], Path::new(SCRATCH), &ProjectGrants::default()).unwrap();
        assert!(prof.contains(&format!("(allow file-write* (subpath \"{SCRATCH}\"))")), "{prof}");
        // Never the cache the run's dir lives in.
        assert!(!prof.contains("(subpath \"/private/tmp/fake-home/.cache/streamscopeai/tmp\")"), "{prof}");
        assert!(!prof.contains("(subpath \"/private/tmp/fake-home/.cache\")"), "{prof}");
    }

    #[test]
    fn profile_lets_a_tui_set_its_terminal_and_no_other_device() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: serialized via ENV_LOCK.
        unsafe { std::env::set_var("HOME", "/private/tmp/fake-home"); }
        let prof =
            profile_with_ttys(&sample_spec(), &[12345], Path::new(SCRATCH), &ProjectGrants::default(), &["/dev/ttys003".into()]).unwrap();
        let ioctl: Vec<&str> = prof.lines().filter(|l| l.contains("file-ioctl")).collect();
        assert_eq!(
            ioctl,
            [
                "(allow file-ioctl (literal \"/dev/tty\"))",
                "(allow file-ioctl (literal \"/dev/ttys003\"))",
                // TIOCSTI, after the allow: Seatbelt is last-match-wins.
                "(deny file-ioctl (ioctl-command 2147578994))",
            ]
        );
    }

    fn sample_spec() -> LaunchSpec {
        LaunchSpec {
            command: "claude".into(),
            args: vec![],
            project_root: PathBuf::from("/private/tmp/proj"),
            cwd: PathBuf::from("/private/tmp/proj"),
            proxy_origins: vec![],
            destinations: Default::default(),
            env: vec![],
            ca_files: vec![],
            ca_bundle: None,
            home_files: vec![],
            client_files: vec![],
            private_project: false,
        }
    }

    #[test]
    fn per_user_folders_root_is_bounded_to_var_folders() {
        let r = per_user_folders_root();
        let p = r.to_string_lossy();
        assert!(
            p == "/private/var/folders" || p.starts_with("/private/var/folders/"),
            "per_user_folders_root must stay under /private/var/folders; got {p:?}"
        );
    }

    #[test]
    fn per_user_folders_root_falls_back_on_off_tree_tmpdir() {
        // A `$TMPDIR` outside /private/var/folders MUST fall back to the
        // per-host parent — never to its own parent, which on `/tmp` would
        // write-allow `/private`.
        let _guard = ENV_LOCK.lock().unwrap();
        let saved = std::env::var_os("TMPDIR");
        // SAFETY: serialized via ENV_LOCK against other tests in this module
        // that touch process-global env.
        unsafe { std::env::set_var("TMPDIR", "/tmp"); }
        let r = per_user_folders_root();
        match saved {
            Some(v) => unsafe { std::env::set_var("TMPDIR", v); },
            None => unsafe { std::env::remove_var("TMPDIR"); },
        }
        assert_eq!(
            r,
            PathBuf::from("/private/var/folders"),
            "off-tree TMPDIR must collapse to the per-host parent; got {r:?}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn per_user_folders_root_narrows_on_macos_when_tmpdir_resolvable() {
        // Reads process-global `$TMPDIR`, so it MUST hold ENV_LOCK to serialize
        // against the fallback test that sets `TMPDIR=/tmp` — otherwise it can
        // observe that mutated value mid-flight and see the bounded fallback.
        let _guard = ENV_LOCK.lock().unwrap();
        let r = per_user_folders_root();
        assert_ne!(
            r,
            PathBuf::from("/private/var/folders"),
            "per_user_folders_root() must be a proper subpath of /private/var/folders \
             when launchd's $TMPDIR is in effect; got {r:?}"
        );
        assert!(
            r.starts_with("/private/var/folders/"),
            "per_user_folders_root() escaped the per-host parent: {r:?}"
        );
    }

    /// Each connect port gets its own outbound clause and no other port does —
    /// the guard plus, for an engine-backed client, its engine.
    #[test]
    fn profile_allows_outbound_only_to_the_connect_ports() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: serialized via ENV_LOCK.
        unsafe { std::env::set_var("HOME", "/private/tmp/fake-home"); }
        let prof = profile(&sample_spec(), &[4100, 4200], Path::new(SCRATCH), &ProjectGrants::default()).unwrap();
        let outbound: Vec<&str> = prof.lines().filter(|l| l.contains("network-outbound")).collect();
        assert_eq!(
            outbound,
            [
                "(allow network-outbound (remote ip \"localhost:4100\"))",
                "(allow network-outbound (remote ip \"localhost:4200\"))",
            ]
        );
        assert!(prof.contains("(allow network-inbound (local ip \"localhost:*\"))"), "{prof}");
    }

    #[test]
    fn profile_is_fail_closed_when_home_is_missing() {
        // SECRET_DENY entries reference `~/`; if `HOME` is unset, expand_tilde
        // errors. profile() MUST refuse to launch rather than silently emit
        // a SECRET_DENY-less profile (the broad allow would leave the secret
        // paths readable).
        let _guard = ENV_LOCK.lock().unwrap();
        let saved = std::env::var_os("HOME");
        // SAFETY: serialized via ENV_LOCK.
        unsafe { std::env::remove_var("HOME"); }
        let result = profile(&sample_spec(), &[12345], Path::new(SCRATCH), &ProjectGrants::default());
        if let Some(v) = saved {
            unsafe { std::env::set_var("HOME", v); }
        }
        assert!(
            result.is_err(),
            "profile() must fail-closed when SECRET_DENY tilde entries can't expand; got Ok"
        );
    }

    #[test]
    fn profile_emits_secret_deny_clauses_when_home_is_set() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: serialized via ENV_LOCK.
        unsafe { std::env::set_var("HOME", "/private/tmp/fake-home"); }
        let prof = profile(&sample_spec(), &[12345], Path::new(SCRATCH), &ProjectGrants::default()).expect("profile builds with HOME set");
        for tail in [".ssh/id_", ".gnupg", ".aws", ".config/gcloud", ".netrc", ".npmrc"] {
            let expected = format!("/private/tmp/fake-home/{tail}");
            assert!(
                prof.contains(&format!("(deny file-read* (literal \"{expected}\"))")),
                "profile missing deny-literal clause for ~/{tail}; profile=\n{prof}"
            );
        }
        // A version manager's per-version npm config is named by level, so it
        // rides the regex clause alone — including Volta's, which only Seatbelt
        // can deny inside a tree the tool needs whole.
        for expected in [
            "(deny file-read* (regex #\"^/private/tmp/fake-home/\\.nvm/versions/node/[^/]+/etc/npmrc\"))",
            "(deny file-read* (regex #\"^/private/tmp/fake-home/\\.volta/tools/image/node/[^/]+/etc/npmrc\"))",
        ] {
            assert!(prof.contains(expected), "profile missing {expected}; profile=\n{prof}");
        }
        assert!(
            !prof.contains("(literal \"/private/tmp/fake-home/.nvm/versions/node/*"),
            "a wildcard entry must not be emitted as a literal path; profile=\n{prof}"
        );
        // Preferences: read through cfprefsd's shared memory, never written.
        assert!(prof.contains("(allow ipc-posix-shm-read-data (ipc-posix-name-prefix \"apple.cfprefs.\"))\n"), "{prof}");
        assert_eq!(prof.matches("ipc-posix-shm").count(), 1, "only cfprefsd's segments, read only: {prof}");
        assert!(!prof.contains("user-preference-write"), "{prof}");
    }
}

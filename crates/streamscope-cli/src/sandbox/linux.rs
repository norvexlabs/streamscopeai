//! Native Linux confinement: Landlock (filesystem + TCP-connect) and a seccomp
//! filter that closes the non-TCP egress paths Landlock can't, plus a
//! dangerous-syscall denylist. Applied by the re-exec trampoline to its own
//! single-threaded process, then it `execvp`s the client.

use std::collections::BTreeMap;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use landlock::{
    path_beneath_rules, ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, NetPort,
    Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
};

use super::scratch::ScratchDir;
use super::allowlist::{self, dedup, learned_override_dirs, override_file_path, own_trees};
use super::state_dirs::{dir_touches_secret, secret_deny};
use super::{LaunchSpec, SandboxPolicy};
use crate::state::home_dir;

/// Landlock ABI we target: v4 added TCP bind/connect (kernel ≥6.7), which the
/// egress confinement needs.
const ABI_V4: ABI = ABI::V4;

/// Can this kernel enforce native confinement (Landlock FS + TCP-connect, fully)? Probes by
/// building a hard-required ruleset without restricting self.
pub fn confinement_supported() -> bool {
    Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI_V4))
        .and_then(|r| r.handle_access(AccessNet::ConnectTcp))
        .and_then(|r| r.create())
        .is_ok()
}

/// Build the filesystem policy for `spec`: base + per-agent + per-toolchain
/// allowlists, never `/home` wholesale. Paths are expanded and absolute. The
/// network lists come back empty — the launcher fills them once it knows the
/// guard (and any engine) port. `scratch` is the run's private temp dir
/// ([`super::scratch`]).
pub fn build_policy(spec: &LaunchSpec, scratch: &Path) -> Result<SandboxPolicy> {
    build_policy_in(&home_dir()?, spec, scratch)
}

/// [`build_policy`] for the user whose home is `home`: the shared allow-list
/// ([`allowlist::build_in`]) as Landlock's policy.
fn build_policy_in(home: &Path, spec: &LaunchSpec, scratch: &Path) -> Result<SandboxPolicy> {
    let list = allowlist::build_in(home, spec, scratch);
    Ok(SandboxPolicy { net_connect: Vec::new(), fs_rw: list.rw, fs_ro: list.ro, fs_deny: list.deny, learn_record: None })
}


/// Make this process (the unconfined `ssai run` parent) the child
/// subreaper of everything it launches: a process the client leaves running —
/// a daemon an agent's shell tool spawned, an engine that detached — is
/// reparented here instead of to init, so [`reap_orphans`] can stop it when
/// the run ends. Best-effort: on failure such a process outlives the run, as
/// it would without the sandbox. An orphan that exits on its own during the
/// run stays a zombie until the run ends: not a running process, but it still
/// counts toward the user's process limit (`RLIMIT_NPROC`, a cgroup's
/// `pids.max`) until then.
pub fn become_child_subreaper() {
    // SAFETY: prctl(PR_SET_CHILD_SUBREAPER) sets a process attribute; no memory.
    unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
}

/// Stop and reap every remaining child of this process — after the client has
/// exited, only what it left behind (reparented here by
/// [`become_child_subreaper`]). SIGTERM, a short grace period, then SIGKILL;
/// repeated while killing a child reparents its own children here.
pub fn reap_orphans() {
    for _ in 0..8 {
        let children = children_of(std::process::id());
        if children.is_empty() {
            return;
        }
        for &pid in &children {
            // SAFETY: kill(2) on our own child.
            unsafe { libc::kill(pid, libc::SIGTERM) };
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut alive = children.clone();
        while !alive.is_empty() && std::time::Instant::now() < deadline {
            alive.retain(|&pid| {
                let mut status = 0;
                // SAFETY: waitpid on our own child; WNOHANG never blocks.
                unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) == 0 }
            });
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        for &pid in &alive {
            // SAFETY: kill(2) on our own child.
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
        // SIGKILL lands once a process leaves an uninterruptible sleep; the
        // wait for it is bounded, and one still stuck is left to init.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !alive.is_empty() && std::time::Instant::now() < deadline {
            alive.retain(|&pid| {
                let mut status = 0;
                // SAFETY: waitpid on our own child; WNOHANG never blocks.
                unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) == 0 }
            });
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        if !alive.is_empty() {
            return;
        }
    }
}

/// The pids whose parent is `ppid`, read from `/proc/<pid>/stat`.
fn children_of(ppid: u32) -> Vec<libc::pid_t> {
    let Ok(entries) = std::fs::read_dir("/proc") else { return Vec::new() };
    entries
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse::<libc::pid_t>().ok())
        .filter(|pid| {
            std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|stat| parent_in_stat(&stat))
                == Some(ppid)
        })
        .collect()
}

/// The parent pid in a `/proc/<pid>/stat` line: the field after the state,
/// which follows the `)` closing the command name (a name may hold spaces and
/// parentheses, so the LAST `)` is the delimiter).
fn parent_in_stat(stat: &str) -> Option<u32> {
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(1)?.parse().ok()
}

/// Apply the policy to THIS process and `execvp` the client. Never returns on
/// success. Order: no_new_privs → Landlock → seccomp → (best-effort connect()
/// address interposer) → exec.
///
/// MUST run single-threaded: the interposer `fork()`s a supervisor, and forking
/// a multithreaded process then allocating in the child is unsafe. The
/// `__run-confined` trampoline is dispatched before the tokio runtime starts, so
/// it is.
pub fn apply_and_exec(policy: &SandboxPolicy, command: &str, args: &[String]) -> Result<()> {
    set_no_new_privs()?;
    if policy.learn_record.is_some() {
        return learn_and_exec(policy, command, args);
    }
    apply_landlock(policy)?;
    apply_seccomp(false)?;

    // Pin connect() to 127.0.0.1:<allowed port> via a seccomp user-notification
    // supervisor (Landlock-net only pins the port, not the address). Best-effort:
    // if the kernel won't give a listener, fall through to a plain exec — the
    // Landlock-net port pin still holds, so this never regresses availability.
    if let Some(notify_fd) = super::interposer::try_install() {
        // SAFETY: single-threaded here (see the doc comment), so fork is safe.
        match unsafe { libc::fork() } {
            -1 => {
                // fork failed — drop the listener and run without the address pin.
                unsafe { libc::close(notify_fd) };
            }
            0 => {
                // Child = the agent. It inherited the connect filter; drop the
                // listener (the supervisor holds it) and exec.
                unsafe { libc::close(notify_fd) };
                let err = std::process::Command::new(command).args(args).exec();
                return Err(err).with_context(|| format!("exec {command}"));
            }
            child => {
                // Parent = the supervisor. Services connect notifications until
                // the agent exits, then exits with its code. Never returns.
                super::interposer::supervise(notify_fd, &policy.net_connect, child);
            }
        }
    }

    // `exec` replaces the process image (preserving the inherited env the parent
    // set, incl. HTTPS_PROXY) — it only returns on failure.
    let err = std::process::Command::new(command).args(args).exec();
    Err(err).with_context(|| format!("exec {command}"))
}

/// Learn pass: enforce ONLY egress (Landlock-net port pin + the seccomp socket
/// denials), leave the filesystem unrestricted, and route `openat` to a
/// user-notification supervisor that records every non-secret `$HOME` path the
/// client opens. This is deliberately NOT an enforcing filesystem sandbox — it
/// observes what a client needs so `--sandbox native` can then confine it.
///
/// MUST run single-threaded (it `fork()`s a supervisor) — same invariant as
/// `apply_and_exec`; the `__run-confined` trampoline satisfies it.
fn learn_and_exec(policy: &SandboxPolicy, command: &str, args: &[String]) -> Result<()> {
    apply_landlock_net_only(policy)?;

    let record = policy
        .learn_record
        .clone()
        .expect("learn_and_exec entered without a learn_record");
    // Open the record file NOW, before the seccomp filter diverts `openat`: once
    // the filter is live the supervisor can't `open()` anything without trapping
    // into its own listener (deadlock), so it must hold every fd it needs up
    // front and write through it. `home_dir()` likewise reads env only.
    let record_fd = open_record_file(&record);
    let home = home_dir().unwrap_or_else(|_| PathBuf::from("/nonexistent"));

    // Learn seccomp allows `process_vm_readv` so the supervisor can read the
    // child's `openat` path argument without an `open()` of its own.
    apply_seccomp(true)?;

    // Divert connect() (egress pin, as always) AND openat() (path recording) to
    // the supervisor. Best-effort: without a listener the client still runs — it
    // just learns nothing this pass, and egress stays port-pinned by Landlock-net.
    if let Some(notify_fd) = super::interposer::try_install_learn() {
        // SAFETY: single-threaded here (see the doc comment), so fork is safe.
        match unsafe { libc::fork() } {
            -1 => unsafe {
                libc::close(notify_fd);
                if record_fd >= 0 {
                    libc::close(record_fd);
                }
            },
            0 => {
                unsafe { libc::close(notify_fd) };
                if record_fd >= 0 {
                    unsafe { libc::close(record_fd) };
                }
                let err = std::process::Command::new(command).args(args).exec();
                return Err(err).with_context(|| format!("exec {command}"));
            }
            child => {
                super::interposer::supervise_learn(
                    notify_fd,
                    &policy.net_connect,
                    child,
                    record_fd,
                    &home,
                    &policy.fs_deny,
                );
            }
        }
    }

    // Reached only when the listener couldn't be installed: run the client anyway
    // (egress still port-pinned by Landlock-net), recording nothing. Close the
    // pre-opened record fd so it isn't inherited by the exec'd client.
    if record_fd >= 0 {
        unsafe { libc::close(record_fd) };
    }
    let err = std::process::Command::new(command).args(args).exec();
    Err(err).with_context(|| format!("exec {command}"))
}

/// Open (create/truncate) the learn record file, returning a raw fd, or `-1` when
/// it can't be opened (the pass then records nothing but still runs the client).
fn open_record_file(record: &Path) -> libc::c_int {
    use std::os::unix::ffi::OsStrExt;
    let mut bytes = record.as_os_str().as_bytes().to_vec();
    bytes.push(0);
    // SAFETY: `bytes` is NUL-terminated and outlives the call.
    unsafe {
        libc::open(
            bytes.as_ptr() as *const libc::c_char,
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        )
    }
}

/// Egress-only Landlock for the learn pass: the same TCP-connect pin as the
/// enforcing path, but NO filesystem rules — the filesystem is intentionally
/// unrestricted so the recorder can observe everything the client would
/// otherwise be denied.
fn apply_landlock_net_only(policy: &SandboxPolicy) -> Result<()> {
    let le = |e: landlock::RulesetError| anyhow::anyhow!("landlock: {e:?}");
    let rs = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessNet::ConnectTcp)
        .map_err(le)?
        .create()
        .map_err(le)?;
    let rs = add_net_rules(rs, policy)?;
    let status = rs.restrict_self().map_err(le)?;
    if status.ruleset != RulesetStatus::FullyEnforced {
        bail!(
            "Landlock did not fully enforce egress for the learn pass (status {:?}) — refusing to \
             run; pass --sandbox off to launch unconfined",
            status.ruleset
        );
    }
    Ok(())
}

fn apply_landlock(policy: &SandboxPolicy) -> Result<()> {
    let ro = AccessFs::from_read(ABI_V4);
    let rw = AccessFs::from_all(ABI_V4);
    let le = |e: landlock::RulesetError| anyhow::anyhow!("landlock: {e:?}");

    let mut rs = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI_V4))
        .map_err(le)?
        .handle_access(AccessNet::ConnectTcp)
        .map_err(le)?
        .create()
        .map_err(le)?;

    // Only existing paths — a listed dir a client never created is skipped.
    let rw_paths: Vec<&Path> = policy.fs_rw.iter().filter(|p| p.exists()).map(|p| p.as_path()).collect();
    let ro_paths: Vec<&Path> = policy.fs_ro.iter().filter(|p| p.exists()).map(|p| p.as_path()).collect();
    rs = rs.add_rules(path_beneath_rules(rw_paths, rw)).map_err(le)?;
    rs = rs.add_rules(path_beneath_rules(ro_paths, ro)).map_err(le)?;
    let rs = add_net_rules(rs, policy)?;

    let status = rs.restrict_self().map_err(le)?;
    if status.ruleset != RulesetStatus::FullyEnforced {
        bail!(
            "Landlock did not fully enforce the sandbox (status {:?}) — refusing to run \
             unconfined; pass --sandbox off to override",
            status.ruleset
        );
    }
    Ok(())
}

/// The TCP rule both Landlock rulesets share: connect only to the policy's
/// ports (the guard, plus an engine-backed client's engine) — the interposer
/// pins those to loopback. Listening is not restricted: a dev server or an
/// OAuth callback the agent starts in normal work keeps its port.
fn add_net_rules(
    mut rs: landlock::RulesetCreated,
    policy: &SandboxPolicy,
) -> Result<landlock::RulesetCreated> {
    let le = |e: landlock::RulesetError| anyhow::anyhow!("landlock: {e:?}");
    for &port in &policy.net_connect {
        rs = rs.add_rule(NetPort::new(port, AccessNet::ConnectTcp)).map_err(le)?;
    }
    Ok(rs)
}

fn set_no_new_privs() -> Result<()> {
    // SAFETY: prctl(PR_SET_NO_NEW_PRIVS) is a thread-local, irreversible flag set.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        bail!("prctl(PR_SET_NO_NEW_PRIVS) failed: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

/// Install the seccomp filter: default-allow, with the egress-closing socket
/// denials and the dangerous-syscall + TIOCSTI denylist returning EPERM.
fn apply_seccomp(learn: bool) -> Result<()> {
    use seccompiler::{
        SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule,
    };

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    // Unconditional denials (empty rule vec ⇒ always matches ⇒ match_action).
    // The learn supervisor reads the child's `openat` path via `process_vm_readv`,
    // so it is allowed in learn mode only (learn is an observation pass, not an
    // enforcing sandbox).
    let mut deny: Vec<i64> = vec![
        libc::SYS_ptrace,
        libc::SYS_process_vm_writev,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_personality,
        libc::SYS_userfaultfd,
        libc::SYS_perf_event_open,
        libc::SYS_bpf,
        libc::SYS_kexec_load,
        libc::SYS_kexec_file_load,
        libc::SYS_reboot,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_sethostname,
        libc::SYS_setdomainname,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        // Namespace-escape vectors (Landlock survives them, but deny anyway).
        libc::SYS_unshare,
        libc::SYS_setns,
    ];
    if !learn {
        // Cross-process memory read — the enforcing sandbox denies it; the learn
        // supervisor needs it to read the child's `openat` path argument.
        deny.push(libc::SYS_process_vm_readv);
    }
    #[cfg(target_arch = "x86_64")]
    {
        deny.push(libc::SYS_ioperm);
        deny.push(libc::SYS_iopl);
    }
    for nr in deny {
        rules.insert(nr, vec![]);
    }

    // socket(): deny non-TCP inet egress + the non-IP families (no `connect()`
    // address filtering is possible — seccomp can't deref the sockaddr pointer —
    // so we deny at socket creation, where domain+type are scalar args).
    let dword = || SeccompCmpArgLen::Dword;
    let mut socket_rules: Vec<SeccompRule> = Vec::new();
    for af in [libc::AF_INET, libc::AF_INET6] {
        for ty in [libc::SOCK_DGRAM, libc::SOCK_RAW] {
            socket_rules.push(
                SeccompRule::new(vec![
                    SeccompCondition::new(0, dword(), SeccompCmpOp::Eq, af as u64)?,
                    // type carries SOCK_CLOEXEC/NONBLOCK flags — mask to the type bits.
                    SeccompCondition::new(1, dword(), SeccompCmpOp::MaskedEq(0xf), ty as u64)?,
                ])
                .context("seccomp socket rule")?,
            );
        }
    }
    for af in [libc::AF_PACKET, libc::AF_NETLINK, libc::AF_UNIX] {
        socket_rules.push(
            SeccompRule::new(vec![SeccompCondition::new(0, dword(), SeccompCmpOp::Eq, af as u64)?])
                .context("seccomp socket family rule")?,
        );
    }
    rules.insert(libc::SYS_socket, socket_rules);

    // ioctl(fd, TIOCSTI, …) — terminal-input injection. TIOCSTI is `c_ulong` on
    // glibc (cast is a no-op) but `c_int` on musl (cast required) — the `allow`
    // covers the glibc false-positive without breaking the musl build.
    #[allow(clippy::unnecessary_cast)]
    let tiocsti = libc::TIOCSTI as u64;
    rules.insert(
        libc::SYS_ioctl,
        vec![SeccompRule::new(vec![SeccompCondition::new(
            1,
            dword(),
            SeccompCmpOp::Eq,
            tiocsti,
        )?])
        .context("seccomp ioctl rule")?],
    );

    let arch = target_arch()?;
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,                       // default: allow
        SeccompAction::Errno(libc::EPERM as u32),   // matched: deny with EPERM
        arch,
    )
    .context("build seccomp filter")?;
    let prog: seccompiler::BpfProgram = filter.try_into().context("compile seccomp filter")?;
    seccompiler::apply_filter(&prog).context("install seccomp filter")?;
    Ok(())
}

fn target_arch() -> Result<seccompiler::TargetArch> {
    #[cfg(target_arch = "x86_64")]
    {
        Ok(seccompiler::TargetArch::x86_64)
    }
    #[cfg(target_arch = "aarch64")]
    {
        Ok(seccompiler::TargetArch::aarch64)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        bail!("seccomp filter not supported on this architecture")
    }
}









/// Reduce an observed file path to the client-specific directory worth
/// allow-listing: `~/.config/<x>`, `~/.cache/<x>`, `~/.local/{share,state}/<x>`,
/// else the first component under `$HOME` (`~/.opencode`). Returns `None` for a
/// path outside `$HOME` or one that would reduce to a bare, too-broad root
/// (`~`, `~/.config`, …) — those must never be auto-allowed.
fn reduce_to_profile_dir(home: &Path, path: &Path) -> Option<PathBuf> {
    use std::path::Component;
    let rel = path.strip_prefix(home).ok()?;
    let comps: Vec<&std::ffi::OsStr> = rel
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s),
            _ => None,
        })
        .collect();
    if comps.is_empty() {
        return None;
    }
    let first = comps[0].to_string_lossy();
    let take = match first.as_ref() {
        ".config" | ".cache" => 2,
        ".local" => {
            let second = comps.get(1).map(|s| s.to_string_lossy());
            match second.as_deref() {
                Some("share") | Some("state") => 3,
                _ => 2,
            }
        }
        _ => 1,
    };
    if comps.len() < take {
        return None; // e.g. a bare `~/.config` open — too broad to allow-list.
    }
    let mut dir = home.to_path_buf();
    for c in &comps[..take] {
        dir.push(c);
    }
    Some(dir)
}


/// True when `p` equals or sits beneath any prefix in `prefixes` (component-wise;
/// correct for the built-in ALLOW prefixes, which are always full directories).
fn is_under_any(p: &Path, prefixes: &[PathBuf]) -> bool {
    prefixes.iter().any(|pre| p.starts_with(pre))
}

/// The directory a path observed in a learn pass would add to the profile
/// ([`reduce_to_profile_dir`]), never one inside or above the CLI's own trees
/// (`own`, [`own_trees`]): it would grant the CLI's cache (engine logs, other
/// runs' scratch dirs) or config (login tokens) to every later run.
fn learnable_dir(home: &Path, observed: &Path, own: &[PathBuf]) -> Option<PathBuf> {
    if !observed.is_absolute() || own.iter().any(|o| observed.starts_with(o)) {
        return None;
    }
    reduce_to_profile_dir(home, observed).filter(|dir| !dir_touches_secret(dir, own))
}

/// Fold the paths observed during a learn pass into the global profile. Reads the
/// recorded file paths, reduces each to a client-specific directory, drops any
/// already covered by the built-in policy or under a secret prefix, unions the
/// rest into the profile file, and reports what was added.
pub fn apply_learned(spec: &LaunchSpec, scratch: &ScratchDir, record: &Path) -> Result<()> {
    let home = home_dir()?;
    let observed = match std::fs::read_to_string(record) {
        Ok(s) => s,
        Err(_) => return Ok(()), // nothing recorded (no listener / no opens)
    };

    // What the built-in policy already grants — don't re-record those.
    let base = build_policy(spec, scratch.path())?;
    let mut allowed: Vec<PathBuf> = base.fs_rw.clone();
    allowed.extend(base.fs_ro.iter().cloned());
    let deny = secret_deny(&home);
    let existing = learned_override_dirs(&home);
    let own = own_trees(Some(scratch.root()));

    let mut candidates: Vec<PathBuf> = Vec::new();
    for line in observed.lines() {
        let observed = Path::new(line.trim());
        // A path the policy already grants needs nothing learned: one under a
        // writable grant, or a file granted by name — whose reduction (a CA
        // bundle in the user's `$TMPDIR` → that whole dir) would grant far
        // more than it. A path inside a read-only tree may be a write, and
        // is learned.
        if is_under_any(observed, &base.fs_rw) || base.fs_ro.iter().any(|f| f == observed) {
            continue;
        }
        let Some(dir) = learnable_dir(&home, observed, &own) else { continue };
        if dir_touches_secret(&dir, &deny) || is_under_any(&dir, &allowed) || is_under_any(&dir, &existing) {
            continue;
        }
        if !candidates.contains(&dir) {
            candidates.push(dir);
        }
    }

    if candidates.is_empty() {
        eprintln!(
            "ssai: learn — no new paths to add; `{}` already runs confined under the \
             built-in profile.",
            spec.command
        );
        return Ok(());
    }

    let mut merged = existing;
    merged.extend(candidates.iter().cloned());
    merged = dedup(merged);
    write_override(&merged)?;

    eprintln!(
        "ssai: learn — added {} path(s) to the global sandbox profile:",
        candidates.len()
    );
    for d in &candidates {
        eprintln!("  + {}", d.display());
    }
    eprintln!("ssai: `ssai run --sandbox native {}` will now allow them.", spec.command);
    Ok(())
}

/// Write the learned directory set to the profile file (creating the config
/// directory). Stored as absolute paths under `fs_rw`.
fn write_override(dirs: &[PathBuf]) -> Result<()> {
    let path = override_file_path().context("resolve sandbox profile path")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let fs_rw: Vec<String> = dirs.iter().map(|p| p.to_string_lossy().into_owned()).collect();
    let doc = serde_json::json!({ "fs_rw": fs_rw });
    let body = serde_json::to_vec_pretty(&doc).context("serialize sandbox profile")?;
    std::fs::write(&path, body).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod learn_tests {
    use super::*;
    use crate::sandbox::allowlist::user_tool_dirs;
    use crate::sandbox::profiles;
    use crate::sandbox::state_dirs::{create_package_caches, create_state_dirs, package_caches, Create};

    #[test]
    fn reduce_config_cache_local_and_bare() {
        let home = PathBuf::from("/home/u");
        let r = |p: &str| reduce_to_profile_dir(&home, &PathBuf::from(p));
        assert_eq!(r("/home/u/.config/opencode/config.json"), Some("/home/u/.config/opencode".into()));
        assert_eq!(r("/home/u/.cache/opencode/x/y"), Some("/home/u/.cache/opencode".into()));
        assert_eq!(r("/home/u/.local/share/opencode/db"), Some("/home/u/.local/share/opencode".into()));
        assert_eq!(r("/home/u/.local/state/opencode/s"), Some("/home/u/.local/state/opencode".into()));
        assert_eq!(r("/home/u/.opencode.json"), Some("/home/u/.opencode.json".into()));
        // Too-broad roots reduce to None — never auto-allow the whole config dir.
        assert_eq!(r("/home/u/.config"), None);
        assert_eq!(r("/home/u"), None);
        // Outside $HOME → None.
        assert_eq!(r("/etc/passwd"), None);
    }

    #[test]
    fn a_learn_pass_never_learns_the_clis_own_trees() {
        let home = Path::new("/home/u");
        let own = [PathBuf::from("/xdg/streamscopeai/tmp"), PathBuf::from("/home/u/.cache/streamscopeai"),
            PathBuf::from("/home/u/.config/streamscopeai")];
        let learn = |p: &str| learnable_dir(home, Path::new(p), &own);
        assert_eq!(learn("/xdg/streamscopeai/tmp/42-ab/.bun-1.so"), None);
        assert_eq!(learn("/home/u/.cache/streamscopeai/engine-logs/x.log"), None);
        assert_eq!(learn("/home/u/.config/streamscopeai/gateway-bundle.pem"), None);
        // A reduction that would contain one of them is refused too.
        let own = [PathBuf::from("/home/u/dotfiles/config/streamscopeai")];
        assert_eq!(learnable_dir(home, Path::new("/home/u/dotfiles/foo"), &own), None);
        assert_eq!(learn("relative/path"), None);
        // Positive control: the same reduction learns a client's own cache.
        assert_eq!(learn("/home/u/.cache/opencode/x"), Some(PathBuf::from("/home/u/.cache/opencode")));
    }

    #[test]
    fn the_runs_scratch_dir_is_granted_rwx_and_tmp_stays_writable() {
        let home = PathBuf::from("/home/u");
        let scratch = PathBuf::from("/home/u/.cache/streamscopeai/tmp/42-ab");
        let spec = LaunchSpec {
            command: "opencode".into(),
            args: vec![],
            project_root: home.join("proj"),
            cwd: home.join("proj"),
            proxy_origins: vec![],
            destinations: Default::default(),
            network: None,
            default_image: None,
            env: vec![],
            ca_files: vec![],
            ca_bundle: None,
            home_files: vec![],
            client_files: vec![],
            private_root: false,
            opencode: None,
            tool_clients: Vec::new(),
        };
        let policy = build_policy_in(&home, &spec, &scratch).unwrap();
        // `fs_rw` is applied with `AccessFs::from_all`: write AND execute.
        assert!(policy.fs_rw.contains(&scratch), "{:?}", policy.fs_rw);
        assert!(policy.fs_rw.contains(&PathBuf::from("/tmp")), "{:?}", policy.fs_rw);
        // Only the run's own dir, never the cache it lives in.
        for broad in ["/home/u/.cache", "/home/u/.cache/streamscopeai", "/home/u/.cache/streamscopeai/tmp"] {
            assert!(!policy.fs_rw.contains(&PathBuf::from(broad)), "{broad} granted");
        }
    }

    #[test]
    fn secret_dirs_are_never_allow_listed() {
        // SECRET_DENY carries a filename-PREFIX entry (`~/.ssh/id_`) plus whole-dir
        // entries — a directory allow-list grants the whole subtree, so a candidate
        // must be rejected whether it sits UNDER a secret or CONTAINS one.
        let deny: Vec<PathBuf> = [
            "/home/u/.ssh/id_",
            "/home/u/.gnupg",
            "/home/u/.aws",
            "/home/u/.config/gcloud",
            "/home/u/.netrc",
            "/home/u/.npmrc",
        ]
        .iter()
        .map(PathBuf::from)
        .collect();
        let touches = |p: &str| dir_touches_secret(&PathBuf::from(p), &deny);
        // `~/.ssh` is an ANCESTOR of the `~/.ssh/id_` key prefix → must be rejected
        // (the bug: reducing `~/.ssh/known_hosts` to `~/.ssh` would expose id_rsa).
        assert!(touches("/home/u/.ssh"));
        // A direct key file sits UNDER the filename prefix (string, not component).
        assert!(touches("/home/u/.ssh/id_rsa"));
        assert!(touches("/home/u/.gnupg"));
        assert!(touches("/home/u/.aws"));
        assert!(touches("/home/u/.config/gcloud"));
        assert!(touches("/home/u/.netrc"));
        // Beneath a denied directory, and beneath a key prefix although no
        // component equals it.
        assert!(touches("/home/u/.aws/sso"));
        assert!(touches("/home/u/.ssh/id_rsa.d"));
        // Every ancestor of a secret: the home itself, and `/`.
        assert!(touches("/home/u"));
        assert!(touches("/"));
        // Benign client dirs are NOT flagged.
        assert!(!touches("/home/u/.config/opencode"));
        assert!(!touches("/home/u/.cache/opencode"));
        assert!(!touches("/home/u/.local/share/opencode"));
        // A directory whose NAME a secret's name begins with is a sibling, not an
        // ancestor: npm's cache beside `~/.npmrc`, n's prefix beside `~/.netrc`.
        assert!(!touches("/home/u/.npm"));
        assert!(!touches("/home/u/.n"));
        assert!(!touches("/home/u/.ssh-agent"));
        // The other side of that boundary: the directory that IS the parent.
        assert!(touches("/home/u/.ssh"));
    }

    #[test]
    fn a_first_run_in_a_fresh_home_is_granted_the_clients_own_state_dirs() {
        let home = std::env::temp_dir().join(format!("ss-fresh-home-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(home.join("proj")).unwrap();
        let spec = LaunchSpec {
            command: "opencode".into(),
            args: vec![],
            project_root: home.join("proj"),
            cwd: home.join("proj"),
            proxy_origins: vec![],
            destinations: Default::default(),
            network: None,
            default_image: None,
            env: vec![],
            ca_files: vec![],
            ca_bundle: None,
            home_files: vec![],
            client_files: vec![],
            private_root: false,
            opencode: None,
            tool_clients: Vec::new(),
        };
        let agent = profiles::agent_for(&spec.command).unwrap();
        create_state_dirs(&home, agent.state_dirs, &secret_deny(&home), Create::Dir);
        let policy = build_policy_in(&home, &spec, &home.join(".cache/streamscopeai/tmp/run")).unwrap();
        for dir in [".local/share/opencode", ".local/state/opencode", ".config/opencode", ".cache/opencode"] {
            let dir = home.join(dir);
            assert!(dir.is_dir(), "{} not created", dir.display());
            assert!(policy.fs_rw.contains(&dir), "{} not granted: {:?}", dir.display(), policy.fs_rw);
        }
        // Outside the XDG bases nothing is created: `~/.opencode.json` is a file
        // the client writes itself, and `~/.opencode` is the client's to make.
        assert!(!home.join(".opencode.json").exists());
        assert!(!home.join(".opencode").exists());
        let _ = std::fs::remove_dir_all(&home);
    }

    /// A client the agent may run as a tool is granted its state directories
    /// as the launched client is (positive: Open Code Review's under an
    /// OpenCode run; negative: the same run without it), filtered the same
    /// way: a tool's directory holding a secret is not granted, its other
    /// one is.
    #[test]
    fn a_tool_client_is_granted_its_state_dirs_except_where_a_secret_is() {
        static REVIEWER: profiles::AgentProfile = profiles::AgentProfile {
            names: &["reviewer"],
            state_dirs: &["~/.config/gh", "~/.reviewer"],
            env: &[],
            engine: None,
            config_dir_env: None,
            npm_package: None,
            windows_config: &[],
            windows_args: &[],
            windows_seed: &[],
        };
        let home = std::env::temp_dir().join(format!("ss-tool-home-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        for dir in ["proj", ".opencodereview", ".config/gh", ".reviewer"] {
            std::fs::create_dir_all(home.join(dir)).unwrap();
        }
        std::fs::write(home.join(".opencodereview/config.json"), "{}").unwrap();
        std::fs::write(home.join(".config/gh/hosts.yml"), "oauth_token: t").unwrap();
        let tool = |profile: &'static profiles::AgentProfile| crate::sandbox::ToolClient {
            client_id: profile.names[0].to_string(),
            profile,
            files: vec![],
        };
        let spec = |tool_clients| LaunchSpec {
            command: "opencode".into(),
            args: vec![],
            project_root: home.join("proj"),
            cwd: home.join("proj"),
            proxy_origins: vec![],
            destinations: Default::default(),
            network: None,
            default_image: None,
            env: vec![],
            ca_files: vec![],
            ca_bundle: None,
            home_files: vec![],
            client_files: vec![],
            private_root: false,
            opencode: None,
            tool_clients,
        };
        let scratch = home.join(".cache/streamscopeai/tmp/run");
        // Grants under this home only: the fixture's home is under `/tmp`, granted to every run.
        let covered = |policy: &SandboxPolicy, p: &Path| policy.fs_rw.iter().any(|g| g.starts_with(&home) && p.starts_with(g));
        let ocr = home.join(".opencodereview");
        let policy = build_policy_in(&home, &spec(vec![tool(profiles::agent_for("open-code-review").unwrap())]), &scratch).unwrap();
        assert!(policy.fs_rw.contains(&ocr), "{:?}", policy.fs_rw);
        let policy = build_policy_in(&home, &spec(vec![]), &scratch).unwrap();
        assert!(!covered(&policy, &ocr), "{:?}", policy.fs_rw);
        let policy = build_policy_in(&home, &spec(vec![tool(&REVIEWER)]), &scratch).unwrap();
        assert!(policy.fs_rw.contains(&home.join(".reviewer")), "{:?}", policy.fs_rw);
        assert!(!covered(&policy, &home.join(".config/gh/hosts.yml")), "{:?}", policy.fs_rw);
        let _ = std::fs::remove_dir_all(&home);
    }

    /// An `npx` or `uvx` child inherits its client's domain, so every client
    /// — a Rust one (codex), a Node one (opencode), a Python one (aider) — is
    /// granted the package caches, created on a first run when their tool is
    /// on PATH; uv's logins and interpreters are granted to none of them.
    #[test]
    fn every_client_is_granted_every_package_cache_and_no_other_runtimes_data() {
        let home = std::env::temp_dir().join(format!("ss-caches-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(home.join("proj")).unwrap();
        std::fs::create_dir_all(home.join(".local/share/uv/credentials")).unwrap();
        let caches = package_caches(&home, &secret_deny(&home));
        // Neither tool on PATH: nothing is created.
        create_package_caches(&caches, &|_| false);
        assert!(!home.join(".npm").exists() && !home.join(".cache/uv").exists());
        // `uvx` alone on PATH: only uv's folders are created.
        create_package_caches(&caches, &|t| t == "uvx");
        assert!(home.join(".cache/uv").is_dir() && home.join(".local/share/uv/tools").is_dir());
        assert!(!home.join(".npm").exists());
        create_package_caches(&caches, &|t| t == "npx");
        assert!(home.join(".npm").is_dir());
        std::fs::create_dir_all(home.join(".local/share/uv/python/cpython-3.13")).unwrap();
        for command in ["codex", "opencode", "aider"] {
            let spec = LaunchSpec {
                command: command.into(),
                args: vec![],
                project_root: home.join("proj"),
                cwd: home.join("proj"),
                proxy_origins: vec![],
                destinations: Default::default(),
                network: None,
                default_image: None,
                env: vec![],
                ca_files: vec![],
                ca_bundle: None,
                home_files: vec![],
                client_files: vec![],
                private_root: false,
                opencode: None,
                tool_clients: Vec::new(),
            };
            let policy = build_policy_in(&home, &spec, &home.join(".cache/streamscopeai/tmp/run")).unwrap();
            for dir in [home.join(".npm"), home.join(".cache/uv"), home.join(".local/share/uv/tools")] {
                assert!(policy.fs_rw.contains(&dir), "{command}: {} not granted: {:?}", dir.display(), policy.fs_rw);
            }
            // The Pythons uv installed: read and run, never written.
            let pythons = home.join(".local/share/uv/python");
            assert!(policy.fs_ro.contains(&pythons), "{command}: uv's Pythons not readable: {:?}", policy.fs_ro);
            if command != "aider" {
                // Grants under this home only: the fixture's home is under `/tmp`, granted to every run.
                for kept in [home.join(".local/share/uv/credentials"), home.join(".local/share/uv/python")] {
                    // Reached by none but a Python client (whose toolchain holds uv's folder).
                    let covers = |g: &PathBuf| g.starts_with(&home) && kept.starts_with(g);
                    assert!(!policy.fs_rw.iter().any(covers), "{command}: {} granted: {:?}", kept.display(), policy.fs_rw);
                }
            }
        }
        let _ = std::fs::remove_dir_all(&home);
    }

    /// A grant follows a symlink: a cache folder — or a folder above it — that
    /// is a link inside the home is neither created nor granted, wherever it
    /// leads (here `~/.ssh`, and a harmless folder); a real one is (the positive
    /// control).
    #[test]
    fn a_package_cache_behind_a_link_is_neither_created_nor_granted() {
        let home = std::env::temp_dir().join(format!("ss-cache-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        for dir in [".ssh", ".local/share/uv", "elsewhere", ".npm"] {
            std::fs::create_dir_all(home.join(dir)).unwrap();
        }
        std::os::unix::fs::symlink(home.join(".ssh"), home.join(".local/share/uv/tools")).unwrap();
        // `~/.cache` itself a link: `~/.cache/uv` would be made inside its target.
        std::os::unix::fs::symlink(home.join("elsewhere"), home.join(".cache")).unwrap();
        let caches = package_caches(&home, &secret_deny(&home));
        create_package_caches(&caches, &|_| true);
        let kept: Vec<PathBuf> = caches.into_iter().map(|(d, _)| d).collect();
        assert_eq!(kept, [home.join(".npm")], "only the real cache is kept");
        assert!(!home.join("elsewhere/uv").exists(), "a cache was created through a linked folder");
        // uv's Pythons made a link onto `~/.ssh`: not granted either; a real one is.
        std::os::unix::fs::symlink(home.join(".ssh"), home.join(".local/share/uv/python")).unwrap();
        let spec = |home: &Path| LaunchSpec {
            command: "codex".into(),
            args: vec![],
            project_root: home.join("proj"),
            cwd: home.join("proj"),
            proxy_origins: vec![],
            destinations: Default::default(),
            network: None,
            default_image: None,
            env: vec![],
            ca_files: vec![],
            ca_bundle: None,
            home_files: vec![],
            client_files: vec![],
            private_root: false,
            opencode: None,
            tool_clients: Vec::new(),
        };
        let policy = build_policy_in(&home, &spec(&home), &home.join("scratch")).unwrap();
        let pythons = home.join(".local/share/uv/python");
        assert!(!policy.fs_ro.contains(&pythons) && !policy.fs_rw.contains(&pythons), "{:?}", policy.fs_ro);
        std::fs::remove_file(&pythons).unwrap();
        std::fs::create_dir_all(&pythons).unwrap();
        let policy = build_policy_in(&home, &spec(&home), &home.join("scratch")).unwrap();
        assert!(policy.fs_ro.contains(&pythons), "{:?}", policy.fs_ro);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_node_client_writes_its_packages_but_never_npms_config() {
        // What `npm i -g` needs (the version's `bin`, `lib`, `share`) and the package
        // managers' caches are writable; no grant covers a file holding a
        // token — npm's config (the user's `~/.npmrc`, a version's global
        // `etc/npmrc`), Yarn's `.yarnrc.yml`, pnpm's `rc`, a CLI's
        // configstore, gh's hosts. (Volta is the one tree granted whole, by
        // decision — see the toolchain list — so it has no fixture here.)
        let home = std::env::temp_dir().join(format!("ss-node-rw-{}", std::process::id()));
        let nvm = home.join(".nvm/versions/node/v24.0.0");
        let fnm = home.join(".local/share/fnm/node-versions/v22.1.0/installation");
        for root in [&nvm, &fnm] {
            for sub in ["bin", "lib/node_modules", "share/man/man1", "etc"] {
                std::fs::create_dir_all(root.join(sub)).unwrap();
            }
        }
        std::fs::create_dir_all(home.join(".npm/_cacache")).unwrap();
        std::fs::create_dir_all(home.join(".yarn/berry")).unwrap();
        std::fs::create_dir_all(home.join(".config/configstore")).unwrap();
        std::fs::create_dir_all(home.join(".config/gh")).unwrap();
        std::fs::create_dir_all(home.join(".config/pnpm")).unwrap();
        std::fs::write(home.join(".config/pnpm/rc"), "//registry.npmjs.org/:_authToken=t").unwrap();
        std::fs::create_dir_all(home.join(".config/npm")).unwrap();
        std::fs::write(home.join(".config/npm/npmrc"), "//registry.npmjs.org/:_authToken=t").unwrap();
        std::fs::write(home.join(".npmrc"), "//registry.npmjs.org/:_authToken=t").unwrap();
        std::fs::write(home.join(".yarnrc.yml"), "npmAuthToken: t").unwrap();
        std::fs::write(home.join(".config/configstore/firebase-tools.json"), "{}").unwrap();
        std::fs::write(home.join(".config/gh/hosts.yml"), "oauth_token: t").unwrap();
        let spec = LaunchSpec {
            command: "opencode".into(),
            args: vec![],
            project_root: home.join("proj"),
            cwd: home.join("proj"),
            proxy_origins: vec![],
            destinations: Default::default(),
            network: None,
            default_image: None,
            env: vec![],
            ca_files: vec![],
            ca_bundle: None,
            home_files: vec![],
            client_files: vec![],
            private_root: false,
            opencode: None,
            tool_clients: Vec::new(),
        };
        let policy = build_policy_in(&home, &spec, &home.join(".cache/streamscopeai/tmp/run")).unwrap();
        for dir in [
            nvm.join("bin"),
            nvm.join("lib"),
            nvm.join("share"),
            fnm.join("bin"),
            fnm.join("lib"),
            fnm.join("share"),
            home.join(".npm"),
            home.join(".yarn"),
        ] {
            assert!(policy.fs_rw.contains(&dir), "{} not writable: {:?}", dir.display(), policy.fs_rw);
        }
        // A grant covers its whole subtree, so the question is whether any grant
        // under this home is a secret's ANCESTOR, not whether one equals it.
        let granted: Vec<&PathBuf> =
            policy.fs_rw.iter().chain(&policy.fs_ro).filter(|d| d.starts_with(&home)).collect();
        for secret in [
            home.join(".npmrc"),
            nvm.join("etc/npmrc"),
            fnm.join("etc/npmrc"),
            home.join(".yarnrc.yml"),
            home.join(".config/configstore/firebase-tools.json"),
            home.join(".config/gh/hosts.yml"),
            home.join(".config/pnpm/rc"),
            home.join(".config/npm/npmrc"),
        ] {
            assert!(
                !granted.iter().any(|d| secret.starts_with(d)),
                "{} is reachable: {granted:?}",
                secret.display()
            );
        }
        let deny = secret_deny(&home);
        for dir in &granted {
            assert!(!dir_touches_secret(dir, &deny), "{} touches a secret", dir.display());
        }
        // A version's global npm config is named by the deny list itself — the
        // `*` resolves to the versions installed — so a grant that ever reached
        // one is refused instead of silently allowed.
        for secret in [nvm.join("etc/npmrc"), fnm.join("etc/npmrc")] {
            assert!(deny.contains(&secret), "{} is not denied: {deny:?}", secret.display());
        }
        // The GitHub CLI's own settings stay readable beside its token.
        assert!(policy.fs_ro.contains(&home.join(".config/gh/config.yml")), "{:?}", policy.fs_ro);
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn the_users_own_tools_are_reachable_and_expose_no_secret() {
        let home = PathBuf::from("/home/u");
        let dirs = user_tool_dirs(&home, &secret_deny(&home));
        // Every fixed entry survives the secret filter: none of them is, or
        // holds, a denied path (the filter itself is
        // `secret_dirs_are_never_allow_listed`). Per-version entries name
        // nothing under a home that does not exist.
        let fixed = profiles::USER_TOOL_READ.iter().filter(|e| !e.contains('*')).count();
        assert_eq!(dirs.len(), fixed, "{dirs:?}");
        for tool in ["/home/u/.local/bin", "/home/u/.cargo/bin", "/home/u/go/bin", "/nix"] {
            assert!(dirs.contains(&PathBuf::from(tool)), "{tool} missing from {dirs:?}");
        }
        // Never the roots beside them — `~/.cargo` holds registry credentials,
        // `~/.local` and `~/.config` every other application's state.
        for root in ["/home/u", "/home/u/.local", "/home/u/.cargo", "/home/u/.config", "/home/u/.nvm"] {
            assert!(!dirs.contains(&PathBuf::from(root)), "{root} granted");
        }
    }

    #[test]
    fn a_node_version_is_granted_its_binaries_and_libraries_but_not_npms_global_config() {
        // nvm's layout: npm writes its GLOBAL config — registry tokens included —
        // to `<version>/etc/npmrc`, so the version root must not be granted whole.
        let home = std::env::temp_dir().join(format!("ss-tools-{}", std::process::id()));
        for sub in ["bin", "lib/node_modules/npm", "etc"] {
            std::fs::create_dir_all(home.join(".nvm/versions/node/v24.0.0").join(sub)).unwrap();
        }
        std::fs::create_dir_all(home.join(".nvm/versions/node/v22.0.0/bin")).unwrap();
        let dirs = user_tool_dirs(&home, &secret_deny(&home));
        let version = home.join(".nvm/versions/node/v24.0.0");
        assert!(dirs.contains(&version.join("bin")), "{dirs:?}");
        assert!(dirs.contains(&version.join("lib")), "{dirs:?}");
        // Every installed version, not only the one on PATH now.
        assert!(dirs.contains(&home.join(".nvm/versions/node/v22.0.0/bin")), "{dirs:?}");
        // A directory grant covers its whole subtree, so no granted path may be
        // `etc/npmrc`'s ancestor — the version root, `~/.nvm`, or `etc` itself.
        let npmrc = version.join("etc").join("npmrc");
        assert!(
            !dirs.iter().any(|d| npmrc.starts_with(d)),
            "npm's global config is reachable: {dirs:?}"
        );
        std::fs::remove_dir_all(&home).ok();
    }
}

#[cfg(test)]
mod reaper_tests {
    use super::*;

    #[test]
    fn the_parent_is_read_past_a_command_name_with_spaces_and_parens() {
        assert_eq!(parent_in_stat("42 (bash) S 7 42 42 0"), Some(7));
        assert_eq!(parent_in_stat("42 (a b) c)) R 99 1 1"), Some(99));
        assert_eq!(parent_in_stat("garbage"), None);
    }

    /// A process the launched child leaves running is reparented to the
    /// subreaper and stopped by `reap_orphans` — the run leaves nothing behind.
    /// The subreaper flag and the reap act on the whole process, so they run in
    /// a re-executed copy of this test binary that runs only
    /// [`subreaper_child`], never beside the harness's other tests.
    #[test]
    fn an_orphaned_daemon_is_reaped_after_the_run() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "sandbox::linux::reaper_tests::subreaper_child", "--ignored", "--nocapture"])
            .env("STREAMSCOPE_SUBREAPER_CHILD", "1")
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("1 passed"), "the subreaper child failed:\n{text}\n{}", String::from_utf8_lossy(&out.stderr));
    }

    /// The body of [`an_orphaned_daemon_is_reaped_after_the_run`]; does nothing
    /// unless that test re-executed it.
    #[test]
    #[ignore = "run by an_orphaned_daemon_is_reaped_after_the_run"]
    fn subreaper_child() {
        if std::env::var_os("STREAMSCOPE_SUBREAPER_CHILD").is_none() {
            return;
        }
        become_child_subreaper();
        // `sh` backgrounds a long sleep and exits at once: the sleep is the orphan.
        let launched = std::process::Command::new("sh")
            .args(["-c", "sleep 300 >/dev/null 2>&1 & exit 0"])
            .status()
            .unwrap();
        assert!(launched.success());
        // Positive control: the orphan reached this process before the reap.
        assert_eq!(children_of(std::process::id()).len(), 1, "no orphan was reparented here");
        reap_orphans();
        assert!(children_of(std::process::id()).is_empty(), "an orphan survived the reap");
    }
}

#[cfg(test)]
mod runtime_tests {
    use crate::sandbox::allowlist::runtime_of;
    use crate::sandbox::profiles;

    /// Each client gets its runtime's toolchain grants: a Python tool (uv or
    /// pipx installs it) the Python ones, a Node tool Node's — under each
    /// name its profile answers to.
    #[test]
    fn each_client_gets_its_own_runtimes_toolchain() {
        for (command, runtime) in [
            ("aider", "python"),
            ("vibe", "python"),
            ("ocr", "node"),
            ("open-code-review", "node"),
            ("opencode", "node"),
            ("claude", "node"),
        ] {
            assert_eq!(runtime_of(command), runtime, "{command}");
            assert!(profiles::toolchain_for(&runtime_of(command)).is_some(), "{command}");
        }
    }
}

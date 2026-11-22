//! `ssai sandbox setup|--check|revoke|uninstall` on FreeBSD: install, check
//! and remove the jail daemon — a root-owned copy of this binary started by
//! an rc.d script. Setup and uninstall run as root (`sudo`), once per machine.

use std::path::Path;

use anyhow::{bail, Context, Result};

const LIBEXEC: &str = "/usr/local/libexec/ssai";
const BINARY: &str = "/usr/local/libexec/ssai/ssai-jaild";
const RC_SCRIPT: &str = "/usr/local/etc/rc.d/ssai_jaild";

/// The rc.d script: `daemon(8)` keeps the daemon running, restarts it, and
/// sends what it prints to syslog (tag `ssai-jaild`, `/var/log/messages`).
const RC: &str = r#"#!/bin/sh
#
# PROVIDE: ssai_jaild
# REQUIRE: LOGIN FILESYSTEMS
# KEYWORD: shutdown
#
# The `ssai run` sandbox daemon: builds one jail per sandboxed run.
# Installed by `sudo ssai sandbox setup`; removed by `sudo ssai sandbox uninstall`.

. /etc/rc.subr

name=ssai_jaild
rcvar=ssai_jaild_enable
load_rc_config $name
: ${ssai_jaild_enable:=NO}

pidfile=/var/run/${name}.pid
procname=/usr/sbin/daemon
command=/usr/sbin/daemon
command_args="-f -S -T ssai-jaild -r -P ${pidfile} -t ssai-jaild /usr/local/libexec/ssai/ssai-jaild __jaild"

run_rc_command "$1"
"#;

fn require_root(verb: &str) -> Result<()> {
    // SAFETY: geteuid cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        bail!("`ssai sandbox {verb}` changes the machine: run it as root (`sudo ssai sandbox {verb}`)");
    }
    Ok(())
}

fn run(program: &str, args: &[&str]) -> Result<()> {
    let status = std::process::Command::new(program).args(args).status().with_context(|| format!("run {program}"))?;
    if !status.success() {
        bail!("{program} {} failed", args.join(" "));
    }
    Ok(())
}

/// Install (or update) the daemon and start it.
pub fn setup() -> Result<()> {
    require_root("setup")?;
    if super::sys::sysctl_int(c"kern.features.vimage") != Some(1) {
        bail!("this kernel has no VIMAGE, which the sandbox's vnet jails need (GENERIC has it)");
    }
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new().recursive(true).mode(0o755).create(LIBEXEC)?;
    let exe = std::env::current_exe().context("locate ssai")?;
    let staged = Path::new(LIBEXEC).join("ssai-jaild.new");
    std::fs::copy(&exe, &staged).with_context(|| format!("copy {} to {}", exe.display(), staged.display()))?;
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o555))?;
    std::os::unix::fs::chown(&staged, Some(0), Some(0))?;
    std::fs::rename(&staged, BINARY)?;
    std::fs::write(RC_SCRIPT, RC).with_context(|| format!("write {RC_SCRIPT}"))?;
    std::fs::set_permissions(RC_SCRIPT, std::fs::Permissions::from_mode(0o555))?;
    run("/usr/sbin/sysrc", &["-q", "ssai_jaild_enable=YES"])?;
    run("/usr/sbin/service", &["ssai_jaild", "restart"])?;
    // Up once its socket answers with our protocol.
    for _ in 0..50 {
        if super::exec::connect().is_ok() {
            println!("ssai: the sandbox is set up — `ssai run` confines clients in a jail on this machine");
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    bail!("the sandbox daemon did not start — see `service ssai_jaild status` and /var/log/messages")
}

/// Check the sandbox can run, changing nothing.
pub fn check() -> Result<()> {
    match super::probe() {
        Ok(()) => {
            println!("ssai: the sandbox is set up and ready");
            Ok(())
        }
        Err(e) => bail!("the sandbox is not ready: {e}"),
    }
}

/// FreeBSD grants nothing per project: say so.
pub fn revoke() -> Result<()> {
    println!("ssai: on FreeBSD the sandbox keeps no grant on a project — each run's jail goes with the run");
    Ok(())
}

/// Stop and remove the daemon.
pub fn uninstall() -> Result<()> {
    require_root("uninstall")?;
    if Path::new(RC_SCRIPT).exists() {
        let _ = run("/usr/sbin/service", &["ssai_jaild", "onestop"]);
    }
    let _ = run("/usr/sbin/sysrc", &["-q", "-x", "ssai_jaild_enable"]);
    for f in [RC_SCRIPT, BINARY] {
        match std::fs::remove_file(f) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("remove {f}")),
        }
    }
    let _ = std::fs::remove_dir(LIBEXEC);
    println!("ssai: the sandbox daemon is removed (a run still going keeps its jail until it ends)");
    Ok(())
}

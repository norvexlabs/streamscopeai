//! The FreeBSD native sandbox: each run's client in a vnet jail that a root
//! daemon (`ssai-jaild`, installed by `ssai sandbox setup`) builds from the
//! run's allow-list ([`super::allowlist`], the Linux backend's) and removes
//! when the run ends. Every process of the run is started in the jail by the
//! daemon through `ssai __jail-exec` ([`exec`]); its network is the jail's
//! own loopback, where `ssai __jail-relay` passes connections to the egress
//! guard's unix socket.

pub mod proto;
pub mod record;
pub mod request;

#[cfg(target_os = "freebsd")]
pub mod daemon;
#[cfg(target_os = "freebsd")]
pub mod exec;
#[cfg(target_os = "freebsd")]
pub mod setup;
#[cfg(target_os = "freebsd")]
mod sys;

use std::path::{Path, PathBuf};

use super::protect::{Guard, Protected};
use request::{grantable, Grant, Held, RunRequest, SYSTEM_MOUNTS};

/// The port the relay listens on in the jail's loopback: the proxy the
/// client's variables name. Any port does — the loopback is the jail's own.
#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
pub const RELAY_PORT: u16 = 3128;

/// The jail's grants from a run's allow-list: each path as it really is
/// (`canon`, absent ones dropped) — and, where the path is spelled through a
/// link (itself, or a folder above it in the home), mounted at that place
/// too — the folders the jail provides itself dropped (the
/// system is mounted whole — but a path under it in the folder holding the
/// homes, which the jail covers, is kept), writable only where it is the
/// developer's own (`mine`), and every held path inside a writable grant.
/// `project` (canonical) must come out writable and outside every read-only
/// grant (the jail shows a path inside a grant as that grant does): a project
/// the jail cannot give the agent to write is refused, not run read-only.
pub fn build_request(
    project: &Path,
    rw: &[PathBuf],
    ro: &[PathBuf],
    held: &[&Protected],
    home: &Path,
    canon: &dyn Fn(&Path) -> Option<PathBuf>,
    mine: &dyn Fn(&Path) -> bool,
) -> Result<RunRequest, String> {
    let real_home = canon(home).unwrap_or_else(|| home.to_path_buf());
    let real_home = real_home.as_path();
    let homes = real_home.parent().unwrap_or(real_home).to_path_buf();
    let kept = |p: &Path| grantable(p).is_ok() && !(SYSTEM_MOUNTS.iter().any(|m| p.starts_with(m)) && !p.starts_with(&homes));
    let mut grants: Vec<Grant> = Vec::new();
    let all = rw.iter().map(|p| (p, true)).chain(ro.iter().map(|p| (p, false)));
    for (given, write) in all {
        let Some(path) = canon(given) else { continue };
        let write = write && mine(&path);
        // Where the client looks for it: the path as given, its home part
        // as the home really is (the jail's home is that real folder); else
        // its folder as it really is with its own name. When that place is
        // not the real path — the path is a link, or a folder above it in
        // the home is — the real path is mounted there too.
        let place = match given.strip_prefix(home).ok().or_else(|| given.strip_prefix(real_home).ok()) {
            Some(rel) => Some(real_home.join(rel)),
            None => given.parent().zip(given.file_name()).and_then(|(dir, name)| Some(canon(dir)?.join(name))),
        }
        .filter(|at| *at != path && kept(at));
        // The real path itself, unless the jail provides it already (a link
        // into the system is still mounted at its own place).
        let own = kept(&path).then_some(None);
        for at in own.into_iter().chain(place.map(Some)) {
            match grants.iter_mut().find(|g| g.path == path && g.at == at) {
                Some(g) => g.write |= write,
                None => grants.push(Grant { path: path.clone(), write, at }),
            }
        }
    }
    let held = held
        .iter()
        .filter(|h| grants.iter().any(|g| g.write && h.path.starts_with(g.target()) && h.path != g.target()))
        .map(|h| Held { path: h.path.clone(), node: h.guard == Guard::Node })
        .collect();
    let refuse = |why: &str| {
        Err(format!(
            "the sandbox cannot give the agent {} to write: {why} — move it under your home, or pass --sandbox off",
            project.display()
        ))
    };
    if !grants.iter().any(|g| g.write && g.target() == project) {
        return refuse(
            "a project under a system folder (/usr, /etc — the folder holding the homes excepted) or not owned by you \
             is not one the FreeBSD sandbox runs in",
        );
    }
    if let Some(g) = shown_by(&grants, project).filter(|g| !g.write) {
        return refuse(&format!("it is inside {}, which the sandbox shows read-only", g.target().display()));
    }
    Ok(RunRequest { grants, held })
}

/// The writable grants the jail shows read-only: those inside a read-only
/// grant, which the jail shows as that grant shows it (Linux's Landlock
/// grants the union) — for the run to say so.
pub fn read_only_inside(req: &RunRequest) -> Vec<(PathBuf, PathBuf)> {
    req.grants
        .iter()
        .filter(|g| g.write)
        .filter_map(|g| {
            let outer = shown_by(&req.grants, g.target()).filter(|o| !o.write)?;
            Some((g.target().to_path_buf(), outer.target().to_path_buf()))
        })
        .collect()
}

/// The grant the jail shows `target` through, when another contains it: the
/// shallowest — the daemon mounts ancestors first and shows whatever lies
/// inside a mounted grant as that grant does.
pub fn shown_by<'a>(grants: &'a [Grant], target: &Path) -> Option<&'a Grant> {
    grants
        .iter()
        .filter(|o| target.starts_with(o.target()) && o.target() != target)
        .min_by_key(|o| o.target().components().count())
}

#[cfg(target_os = "freebsd")]
pub use live::*;

#[cfg(target_os = "freebsd")]
mod live {
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};

    use anyhow::{bail, Context, Result};

    use super::proto::{self, FromDaemon, ToDaemon};
    use super::request::PROTOCOL;
    use super::{exec, sys};
    use crate::sandbox::protect::ProjectGrants;
    use crate::sandbox::LaunchSpec;

    /// Whether the jail sandbox can run here, and if not, why.
    pub fn probe() -> std::result::Result<(), String> {
        if sys::sysctl_int(c"kern.features.vimage") != Some(1) {
            return Err("the kernel has no VIMAGE, which the sandbox's vnet jails need".into());
        }
        exec::connect().map(drop).map_err(|e| format!("{e:#}"))
    }

    /// A run's jail, held for the run: the daemon removes it when this
    /// connection closes.
    pub struct Jail {
        conn: UnixStream,
        pub run: String,
    }

    impl Jail {
        /// Ask the daemon for this run's jail (blocking).
        pub fn open(spec: &LaunchSpec, scratch: &Path, project: &ProjectGrants) -> Result<Self> {
            let home = crate::state::home_dir()?;
            let list = crate::sandbox::allowlist::build_in(&home, spec, scratch);
            let rw: Vec<PathBuf> = list.rw.iter().chain(&project.extra_rw).cloned().collect();
            // The folder `PATH` finds the client in, read-only: a launcher
            // there may be a link into its install folder (npm's `bin`),
            // which the jail must hold at the path the link is found at.
            let mut ro = list.ro.clone();
            // Filtered as the client's install folder is: never the home or
            // `~/.local` whole, never a folder touching a secret.
            let path = spec.env.iter().rev().find(|(k, _)| k == "PATH").map(|(_, v)| std::ffi::OsStr::new(v.as_str()));
            ro.extend(
                crate::program::find_on(&spec.command, path, None)
                    .and_then(|p| p.parent().map(Path::to_path_buf))
                    .filter(|d| !crate::sandbox::allowlist::too_broad_or_secret(&home, d)),
            );
            let held: Vec<_> = project.held().collect();
            // SAFETY: geteuid cannot fail.
            let me = unsafe { libc::geteuid() };
            let req = super::build_request(
                &spec.project_root,
                &rw,
                &ro,
                &held,
                &home,
                &|p| std::fs::canonicalize(p).ok(),
                &|p| std::fs::metadata(p).is_ok_and(|m| std::os::unix::fs::MetadataExt::uid(&m) == me),
            )
            .map_err(anyhow::Error::msg)?;
            for (path, inside) in super::read_only_inside(&req) {
                eprintln!("ssai: note — {} is read-only in the sandbox: it is inside {}, which it shows read-only", path.display(), inside.display());
            }
            let conn = exec::connect()?;
            // A build takes seconds; a daemon that never answers must not
            // hold the run forever.
            // As long as the daemon's own worst case for this request: its
            // walk, its mount helper's budget (which grows with the paths),
            // and a wait for the mount lock behind another run's build.
            let paths = (req.grants.len() + 2 * req.held.len()) as u64;
            let budget = std::time::Duration::from_secs(900) + std::time::Duration::from_millis(200 * paths);
            conn.set_read_timeout(Some(budget))?;
            proto::send(&conn, &ToDaemon::Open { protocol: PROTOCOL, request: req }, &[])?;
            let answer = proto::recv::<FromDaemon>(&conn)
                .context("the sandbox daemon did not build the run's jail in time (see `ssai-jaild` in /var/log/messages)")?;
            match answer {
                Some((FromDaemon::Ready { run }, _)) => {
                    conn.set_read_timeout(None)?;
                    Ok(Self { conn, run })
                }
                Some((FromDaemon::Refused { message }, _)) => bail!("the sandbox refused the run: {message}"),
                _ => bail!("the sandbox daemon ended the run before it started"),
            }
        }

        /// End the run and wait until the daemon removed the jail.
        pub fn close(self) -> Result<()> {
            self.conn.shutdown(std::net::Shutdown::Write)?;
            // Long enough for the daemon's worst case: the mount lock held by
            // another run's build, a dying jail, busy unmounts retried.
            self.conn.set_read_timeout(Some(std::time::Duration::from_secs(900)))?;
            loop {
                match proto::recv::<FromDaemon>(&self.conn) {
                    Ok(Some(_)) => {}
                    Ok(None) => return Ok(()),
                    Err(e) => return Err(e).context("wait for the sandbox to be removed"),
                }
            }
        }
    }

    /// The command running `program args` in run `run`'s jail, through
    /// `ssai __jail-exec`.
    pub fn command(run: &str, program: &str, args: &[String], cwd: &Path, env: &[(String, String)]) -> Result<tokio::process::Command> {
        let exe = std::env::current_exe().context("locate ssai")?;
        let mut cmd = tokio::process::Command::new(exe);
        cmd.arg("__jail-exec").arg(run).arg("--").arg(program).args(args).current_dir(cwd);
        for (k, v) in env {
            cmd.env(k, v);
        }
        Ok(cmd)
    }

    /// `ssai __jail-relay <guard socket> <port> [--engine <socket> <port>]`,
    /// in the jail: the relay to the guard, and the engine's probe socket.
    pub fn relay_main(guard: &Path, port: u16, engine: Option<(&Path, u16)>) -> Result<()> {
        crate::sandbox::relay::relay(std::net::Ipv4Addr::LOCALHOST, port, guard.to_string_lossy().into_owned())?;
        if let Some((sock, engine_port)) = engine {
            crate::sandbox::relay::reverse(sock, engine_port)?;
        }
        println!("ready");
        loop {
            std::thread::park();
        }
    }

    /// The developer's terminal settings at the start of a run, put back at
    /// its end — whatever a killed helper left in raw mode.
    pub struct TerminalGuard(Option<libc::termios>);

    impl TerminalGuard {
        pub fn save() -> Self {
            // SAFETY: tcgetattr into a struct we own.
            // Only in the foreground: a background job setting the terminal
            // at its end would be stopped (SIGTTOU), and never took it.
            unsafe {
                let mut t: libc::termios = std::mem::zeroed();
                let foreground = libc::isatty(0) == 1 && libc::tcgetpgrp(0) == libc::getpgrp();
                Self((foreground && libc::tcgetattr(0, &mut t) == 0).then_some(t))
            }
        }
    }

    impl Drop for TerminalGuard {
        fn drop(&mut self) {
            // (Still the foreground: one moved to the background meanwhile
            // leaves the terminal alone.)
            // SAFETY: tcgetpgrp/getpgrp only read.
            if let Some(t) = &self.0
                && unsafe { libc::tcgetpgrp(0) == libc::getpgrp() }
            {
                // SAFETY: restoring settings read from the same terminal.
                // TCSANOW: what is typed meanwhile is kept.
                unsafe { libc::tcsetattr(0, libc::TCSANOW, t) };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(p: &str, guard: Guard) -> Protected {
        Protected { path: PathBuf::from(p), guard }
    }

    #[test]
    fn the_request_keeps_what_the_jail_does_not_provide_and_writes_only_what_is_yours() {
        let rw: Vec<PathBuf> =
            ["/home/u/p", "/tmp", "/dev/null", "/home/u/.claude", "/home/u/.cache/root-owned", "/home/u/gone"]
                .iter()
                .map(PathBuf::from)
                .collect();
        let ro: Vec<PathBuf> = ["/usr", "/usr/local/lib/node_modules", "/etc", "/home/u/.gitconfig", "/home/u/p"]
            .iter()
            .map(PathBuf::from)
            .collect();
        let h = [held("/home/u/p/.git", Guard::Node), held("/home/u/p/.git/config", Guard::File), held("/elsewhere/x", Guard::File)];
        let refs: Vec<&Protected> = h.iter().collect();
        let req = build_request(
            Path::new("/home/u/p"),
            &rw,
            &ro,
            &refs,
            Path::new("/home/u"),
            &|p| (!p.ends_with("gone")).then(|| p.to_path_buf()),
            &|p| !p.ends_with("root-owned"),
        )
        .unwrap();
        let got: Vec<(&str, bool)> = req.grants.iter().map(|g| (g.path.to_str().unwrap(), g.write)).collect();
        assert_eq!(
            got,
            [("/home/u/p", true), ("/home/u/.claude", true), ("/home/u/.cache/root-owned", false), ("/home/u/.gitconfig", false)]
        );
        assert_eq!(
            req.held,
            [Held { path: "/home/u/p/.git".into(), node: true }, Held { path: "/home/u/p/.git/config".into(), node: false }]
        );
        assert_eq!(request::check_shape(&req), Ok(()));
    }

    #[test]
    fn a_path_in_the_covered_homes_folder_under_usr_is_kept() {
        let ro = [PathBuf::from("/usr/home/u/.npm-global"), PathBuf::from("/usr/local/bin")];
        let rw = [PathBuf::from("/usr/home/u/p")];
        let req = build_request(Path::new("/usr/home/u/p"), &rw, &ro, &[], Path::new("/usr/home/u"), &|p| Some(p.to_path_buf()), &|_| true)
            .unwrap();
        assert_eq!(
            req.grants,
            [
                Grant { path: "/usr/home/u/p".into(), write: true, at: None },
                Grant { path: "/usr/home/u/.npm-global".into(), write: false, at: None }
            ]
        );
    }

    #[test]
    fn a_project_the_jail_cannot_make_writable_is_refused() {
        let canon = |p: &Path| Some(p.to_path_buf());
        // Under a system folder: dropped, so refused.
        let rw = [PathBuf::from("/usr/local/src/x")];
        assert!(build_request(Path::new("/usr/local/src/x"), &rw, &[], &[], Path::new("/home/u"), &canon, &|_| true).is_err());
        // Not the developer's: read-only, so refused.
        let rw = [PathBuf::from("/home/u/shared")];
        assert!(build_request(Path::new("/home/u/shared"), &rw, &[], &[], Path::new("/home/u"), &canon, &|_| false).is_err());
        // The positive control: the developer's own, under the home.
        assert!(build_request(Path::new("/home/u/shared"), &rw, &[], &[], Path::new("/home/u"), &canon, &|_| true).is_ok());
        // Inside a read-only grant (a project under `~/bin`): refused.
        let rw = [PathBuf::from("/home/u/bin/p")];
        let ro = [PathBuf::from("/home/u/bin")];
        assert!(build_request(Path::new("/home/u/bin/p"), &rw, &ro, &[], Path::new("/home/u"), &canon, &|_| true).is_err());
    }

    #[test]
    fn a_link_is_mounted_where_it_points_and_where_it_is() {
        // `~/.claude` → /data/u/claude; `~/.gitconfig` → ~/dotfiles/gitconfig.
        let canon = |p: &Path| {
            Some(match p.to_str().unwrap() {
                "/home/u/.claude" => PathBuf::from("/data/u/claude"),
                "/home/u/.gitconfig" => PathBuf::from("/home/u/dotfiles/gitconfig"),
                other => PathBuf::from(other),
            })
        };
        let rw = [PathBuf::from("/home/u/p"), PathBuf::from("/home/u/.claude")];
        let ro = [PathBuf::from("/home/u/.gitconfig")];
        let req = build_request(Path::new("/home/u/p"), &rw, &ro, &[], Path::new("/home/u"), &canon, &|_| true).unwrap();
        let got: Vec<(&str, bool, Option<&str>)> =
            req.grants.iter().map(|g| (g.path.to_str().unwrap(), g.write, g.at.as_deref().and_then(Path::to_str))).collect();
        assert_eq!(
            got,
            [
                ("/home/u/p", true, None),
                ("/data/u/claude", true, None),
                ("/data/u/claude", true, Some("/home/u/.claude")),
                ("/home/u/dotfiles/gitconfig", false, None),
                ("/home/u/dotfiles/gitconfig", false, Some("/home/u/.gitconfig")),
            ]
        );
        assert_eq!(request::check_shape(&req), Ok(()));
    }

    #[test]
    fn the_shallowest_grant_decides_what_a_nested_path_shows() {
        // rw a, ro a/b, rw a/b/c: the jail mounts only a (writable), so c is
        // writable — no note, and a project at c runs.
        let canon = |p: &Path| Some(p.to_path_buf());
        let rw = [PathBuf::from("/home/u/a"), PathBuf::from("/home/u/a/b/c")];
        let ro = [PathBuf::from("/home/u/a/b")];
        let req = build_request(Path::new("/home/u/a/b/c"), &rw, &ro, &[], Path::new("/home/u"), &canon, &|_| true).unwrap();
        assert!(read_only_inside(&req).is_empty());
    }

    #[test]
    fn a_writable_grant_inside_a_read_only_one_is_named() {
        let canon = |p: &Path| Some(p.to_path_buf());
        let rw = [PathBuf::from("/home/u/p"), PathBuf::from("/home/u/go/pkg/mod")];
        let ro = [PathBuf::from("/home/u/go")];
        let req = build_request(Path::new("/home/u/p"), &rw, &ro, &[], Path::new("/home/u"), &canon, &|_| true).unwrap();
        assert_eq!(read_only_inside(&req), [(PathBuf::from("/home/u/go/pkg/mod"), PathBuf::from("/home/u/go"))]);
        // The positive control: nothing inside a read-only grant, nothing named.
        let req = build_request(Path::new("/home/u/p"), &rw[..1], &ro, &[], Path::new("/home/u"), &canon, &|_| true).unwrap();
        assert!(read_only_inside(&req).is_empty());
    }

    #[test]
    fn a_path_under_a_linked_folder_or_linking_into_the_system_keeps_its_place() {
        // `~/.config` → /data/cfg; `~/ca.pem` → a system certificate.
        let canon = |p: &Path| {
            Some(match p.to_str().unwrap() {
                "/home/u/.config/claude" => PathBuf::from("/data/cfg/claude"),
                "/home/u/.config" => PathBuf::from("/data/cfg"),
                "/home/u/ca.pem" => PathBuf::from("/usr/local/share/certs/ca.pem"),
                other => PathBuf::from(other),
            })
        };
        let rw = [PathBuf::from("/home/u/p"), PathBuf::from("/home/u/.config/claude")];
        let ro = [PathBuf::from("/home/u/ca.pem")];
        let req = build_request(Path::new("/home/u/p"), &rw, &ro, &[], Path::new("/home/u"), &canon, &|_| true).unwrap();
        let got: Vec<(&str, Option<&str>)> =
            req.grants.iter().map(|g| (g.path.to_str().unwrap(), g.at.as_deref().and_then(Path::to_str))).collect();
        assert_eq!(
            got,
            [
                ("/home/u/p", None),
                ("/data/cfg/claude", None),
                ("/data/cfg/claude", Some("/home/u/.config/claude")),
                ("/usr/local/share/certs/ca.pem", Some("/home/u/ca.pem")),
            ]
        );
        assert_eq!(request::check_shape(&req), Ok(()));
    }
}

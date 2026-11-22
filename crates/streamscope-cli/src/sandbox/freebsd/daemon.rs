//! `ssai-jaild` (`ssai __jaild`, as root, started by its rc.d script): builds
//! one vnet jail per `ssai run` and removes it when the run's connection
//! closes.
//!
//! The main process accepts on a socket every local user may connect to and
//! forks a single-threaded worker per connection; the peer's uid comes from
//! the kernel (`getpeereid`), never from the request. A run worker holds its
//! run's record locked for the run's life, so a sweep — at start and before
//! every new run — undoes only runs no worker holds.
//!
//! Build order, each step recorded before it is taken ([`super::record`]):
//! the root tmpfs, the system mounts (read-only, nosuid, from the host), the
//! jail, its loopback and firewall rule, its securelevel — and only then
//! what the user asked for, mounted from inside the jail root (a chroot), so
//! a link the user planted can only land a mount inside the jail. After the
//! first user mount no root code runs a program in the jail, and root opens
//! a path there only through the no-follow walk (or `mkdirat` beneath it);
//! an exec makes only credential calls as root after `jail_attach`.

use std::io::Write as _;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use super::proto::{self, FromDaemon, ToDaemon};
use super::record::{self, Line, Step};
use super::request::{self, Grant, Kind, Meta, RunRequest, PROTOCOL, STATE_DIR, SYSTEM_MOUNTS};
use super::sys;

/// The daemon's socket.
pub const SOCKET: &str = "/var/run/ssai/jaild.sock";
const RUNS: &str = "/var/run/ssai/runs";
const JAILS: &str = "/var/run/ssai/jails";
/// The devfs ruleset the daemon defines for its jails.
const DEVFS_RULESET: &str = "4747";
/// Live runs per user, and connections per user (runs and execs).
const MAX_RUNS: usize = 8;
const MAX_CONNECTIONS: usize = 64;
/// How long a connection may take to say what it wants.
const HANDSHAKE: std::time::Duration = std::time::Duration::from_secs(10);
/// Taken around every build and teardown: two runs mounting or unmounting
/// over the same tree at once can wedge nullfs in the kernel.
const MOUNT_LOCK: &str = "/var/run/ssai/mounts.lock";
/// tmpfs sizes: the jail's root (folders and a few files), the home cover,
/// and `/tmp`.
const ROOT_SIZE: &str = "32m";
const COVER_SIZE: &str = "16m";
const TMP_SIZE: &str = "2g";
/// How long a build waits for the machine-wide mount lock behind other runs,
/// all its takes together.
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(300);

/// What is left until `deadline`.
fn left(deadline: std::time::Instant) -> std::time::Duration {
    deadline.saturating_duration_since(std::time::Instant::now())
}

/// Run the daemon. Returns only on a setup failure.
pub fn main() -> Result<()> {
    // SAFETY: geteuid cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        bail!("the sandbox daemon runs as root (its rc.d script starts it)");
    }
    // SAFETY: plain disposition changes at start, single-threaded.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        libc::umask(0o022);
    }
    for (dir, mode) in [(STATE_DIR, 0o755), (RUNS, 0o700), (JAILS, 0o700)] {
        make_root_dir(Path::new(dir), mode)?;
    }
    define_devfs_ruleset()?;
    sweep(std::time::Instant::now() + LOCK_WAIT);
    let _ = std::fs::remove_file(SOCKET);
    let listener = UnixListener::bind(SOCKET).with_context(|| format!("listen on {SOCKET}"))?;
    // Never blocking in accept: a connection aborted between the poll and
    // the accept must not stall the reaping of finished workers.
    listener.set_nonblocking(true)?;
    std::fs::set_permissions(SOCKET, std::os::unix::fs::PermissionsExt::from_mode(0o666))?;
    let mut live: Vec<(libc::pid_t, libc::uid_t)> = Vec::new();
    loop {
        reap(&mut live);
        let mut pfd = libc::pollfd { fd: listener.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        // SAFETY: poll on one descriptor we own.
        if unsafe { libc::poll(&mut pfd, 1, 1000) } <= 0 {
            continue;
        }
        let conn = match listener.accept() {
            Ok((conn, _)) => conn,
            Err(e) => {
                // Out of descriptors: a pause, not a spin on the queued one.
                if !matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::ConnectionAborted) {
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
                continue;
            }
        };
        if conn.set_nonblocking(false).is_err() {
            continue;
        }
        let Some((uid, _gid)) = peer(&conn) else { continue };
        if at_cap(live.iter().filter(|(_, u)| *u == uid).count(), MAX_CONNECTIONS) {
            // Bounded: a peer that never reads must not stall the main loop.
            let _ = conn.set_write_timeout(Some(std::time::Duration::from_millis(200)));
            // In place of the Hello: the caller's first read says why.
            let _ = proto::send(&conn, &FromDaemon::Refused { message: "too many sandbox connections of yours".into() }, &[]);
            continue;
        }
        // SAFETY: the main process is single-threaded; the child runs the
        // worker and exits.
        match unsafe { libc::fork() } {
            0 => {
                drop(listener);
                let code = match worker(conn, uid) {
                    Ok(()) => 0,
                    Err(_) => 1,
                };
                // SAFETY: leave without running the parent's exit handlers.
                unsafe { libc::_exit(code) };
            }
            pid if pid > 0 => live.push((pid, uid)),
            _ => {}
        }
    }
}

/// Whether `n` already reaches `cap` (so one more is refused).
fn at_cap(n: usize, cap: usize) -> bool {
    n >= cap
}

fn make_root_dir(dir: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let _ = std::fs::DirBuilder::new().mode(mode).create(dir);
    let meta = std::fs::symlink_metadata(dir).with_context(|| format!("create {}", dir.display()))?;
    if !meta.is_dir() || meta.uid() != 0 {
        bail!("{} is not a folder owned by root", dir.display());
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

/// The jails' devfs ruleset: everything hidden but the devices a shell and
/// its tools use.
fn define_devfs_ruleset() -> Result<()> {
    let devfs = |args: &[&str]| -> Result<()> {
        let status = std::process::Command::new("/sbin/devfs")
            .args(["rule", "-s", DEVFS_RULESET])
            .args(args)
            .env_clear()
            .status()
            .context("run devfs")?;
        if !status.success() {
            bail!("devfs rule {} failed", args.join(" "));
        }
        Ok(())
    };
    // `pts` too: devfs shows a jailed process only the terminals made in its
    // jail and its own controlling one — never the developer's others
    // (measured) — so a tool in the jail can open a terminal of its own.
    const SHOWN: [&str; 13] =
        ["null", "zero", "random", "urandom", "fd", "fd/*", "stdin", "stdout", "stderr", "ptmx", "pts", "pts/*", "tty"];
    // Already defined as wanted (a restart): left as it is — redefining it
    // would leave live jails' devfs with no rules for a moment, and a node
    // made then (a new terminal) would show in them.
    let expected: String = std::iter::once("100 hide".to_string())
        .chain(SHOWN.iter().enumerate().map(|(i, p)| format!("{} path {p} unhide", (i + 2) * 100)))
        .map(|l| l + "\n")
        .collect();
    let shown = std::process::Command::new("/sbin/devfs").args(["rule", "-s", DEVFS_RULESET, "show"]).env_clear().output();
    if shown.is_ok_and(|o| o.status.success() && o.stdout == expected.as_bytes()) {
        return Ok(());
    }
    devfs(&["delset"])?;
    devfs(&["add", "hide"])?;
    for path in SHOWN {
        devfs(&["add", "path", path, "unhide"])?;
    }
    Ok(())
}

fn peer(conn: &UnixStream) -> Option<(libc::uid_t, libc::gid_t)> {
    let (mut uid, mut gid) = (0, 0);
    // SAFETY: getpeereid on a connected unix socket we own.
    (unsafe { libc::getpeereid(conn.as_raw_fd(), &mut uid, &mut gid) } == 0).then_some((uid, gid))
}

fn reap(live: &mut Vec<(libc::pid_t, libc::uid_t)>) {
    loop {
        let mut status = 0;
        // SAFETY: a non-blocking wait for any child.
        let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if pid <= 0 {
            return;
        }
        live.retain(|(p, _)| *p != pid);
    }
}

/// One connection, in its own process.
fn worker(conn: UnixStream, uid: libc::uid_t) -> Result<()> {
    // SAFETY: back to default dispositions for the children this worker waits on.
    unsafe { libc::signal(libc::SIGCHLD, libc::SIG_DFL) };
    proto::send(&conn, &FromDaemon::Hello { protocol: PROTOCOL }, &[])?;
    // The whole first frame within HANDSHAKE, however it trickles in: the
    // alarm's default action ends this worker.
    // SAFETY: alarm(2) on this process.
    unsafe { libc::alarm(HANDSHAKE.as_secs() as u32) };
    let first = proto::recv::<ToDaemon>(&conn);
    // SAFETY: as above.
    unsafe { libc::alarm(0) };
    let refuse = |message: String| {
        let _ = proto::send(&conn, &FromDaemon::Refused { message }, &[]);
    };
    let first = match first {
        Ok(first) => first,
        Err(e) => {
            refuse(format!("{e:#}"));
            return Err(e);
        }
    };
    let Some((msg, fds)) = first else { return Ok(()) };
    // Whatever stops the run is said to the caller (a second answer after
    // one already sent is never read).
    let outcome = match msg {
        ToDaemon::Open { protocol, .. } | ToDaemon::Exec { protocol, .. } if protocol != PROTOCOL => {
            refuse(format!(
                "this ssai speaks sandbox protocol {protocol}, the installed sandbox daemon {PROTOCOL} — run `sudo ssai sandbox setup` to update it"
            ));
            Ok(())
        }
        ToDaemon::Open { request, .. } => run(&conn, uid, request),
        ToDaemon::Exec { run, argv, env, cwd, core, .. } => exec(&conn, uid, &run, Started { argv, env, cwd: cwd.into(), core }, fds),
        ToDaemon::Signal { .. } => {
            refuse("nothing to signal".into());
            Ok(())
        }
    };
    if let Err(e) = &outcome {
        refuse(format!("{e:#}"));
    }
    outcome
}

// ── runs ────────────────────────────────────────────────────────────────

/// The descriptor holding this worker's record lock, which every forked
/// helper closes first: a helper that outlives the worker (stuck in the
/// kernel) must not keep the run counted as live, and the walk as the user
/// must not hold a root-only file.
static RECORD_LOCK_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

/// In a forked helper: close the worker's record lock descriptor.
fn drop_record_lock() {
    let fd = RECORD_LOCK_FD.load(std::sync::atomic::Ordering::Relaxed);
    if fd >= 0 {
        // SAFETY: closing a descriptor this child inherited.
        unsafe { libc::close(fd) };
    }
}

/// A run's record, open and locked by its worker (or, from [`Record::writer`],
/// another handle on it that holds no lock).
struct Record {
    file: std::fs::File,
    path: PathBuf,
}

impl Record {
    /// Created under a hidden name (the sweep skips those), locked, its
    /// owner written, and only then given its name: a sweep never finds a
    /// record its worker does not hold yet.
    fn create(run: &str, uid: libc::uid_t) -> Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        let staged = Path::new(RUNS).join(format!(".{run}"));
        let path = Path::new(RUNS).join(run);
        let file = std::fs::OpenOptions::new()
            .append(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&staged)
            .with_context(|| format!("create {}", staged.display()))?;
        // SAFETY: flock on our own descriptor.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let _ = std::fs::remove_file(&staged);
            bail!("lock {}", staged.display());
        }
        let r = Self { file, path };
        let named = r
            .line(&Line::Owner { uid, boot: sys::boot_id() })
            .and_then(|()| std::fs::rename(&staged, &r.path).with_context(|| format!("name {}", r.path.display())));
        if let Err(e) = named {
            let _ = std::fs::remove_file(&staged);
            return Err(e);
        }
        RECORD_LOCK_FD.store(r.file.as_raw_fd(), std::sync::atomic::Ordering::Relaxed);
        Ok(r)
    }

    /// Each line starts on a line of its own: a writer killed mid-line
    /// (the mount helper, at its timeout) never swallows the next one.
    fn line(&self, line: &Line) -> Result<()> {
        let text = format!("\n{}\n", serde_json::to_string(line)?);
        (&self.file).write_all(text.as_bytes()).context("write the run's record")
    }

    /// Another handle on the record, holding no lock: what a forked helper
    /// writes through after closing the locked one.
    fn writer(&self) -> Result<Self> {
        let file = file_for_append(&self.path).with_context(|| format!("open {}", self.path.display()))?;
        Ok(Self { file, path: self.path.clone() })
    }

    fn begin(&self, step: Step) -> Result<()> {
        self.line(&Line::Begin(step))
    }
}

/// The host as the teardown acts on it.
struct RealHost;

impl record::Host for RealHost {
    fn mounts(&mut self) -> Vec<record::MountEntry> {
        sys::mounts()
    }
    fn mounted_in(&mut self, root: &Path, target: &Path) -> Option<record::MountEntry> {
        // Reached without following a link, as every path root opens there.
        in_chroot(root, std::time::Duration::from_secs(30), || {
            let (fd, _) = request::walk(&mut OpenAt, &Grant { path: target.to_path_buf(), ..Grant::default() }, 0)
                .map_err(|e| anyhow::anyhow!("{}", e.0))?;
            sys::fstatfs(fd.as_raw_fd()).map(|fs| fs.entry).ok_or_else(|| anyhow::anyhow!("fstatfs"))
        })
        .ok()
    }
    fn unmount(&mut self, fsid: [i32; 2]) -> Result<(), bool> {
        // In a helper, bounded: an unmount over a filesystem that stopped
        // answering must not hold the machine-wide lock (its run is left
        // for a later sweep).
        let done = in_child(None, std::time::Duration::from_secs(30), || {
            // A jail just removed may still hold its mounts for a moment.
            for _ in 0..20 {
                match sys::unmount_fsid(fsid) {
                    Ok(()) => return Ok(0u8),
                    Err(e) if e.raw_os_error() == Some(libc::EBUSY) => {
                        std::thread::sleep(std::time::Duration::from_millis(100))
                    }
                    Err(e) if e.raw_os_error() == Some(libc::ENOENT) || e.raw_os_error() == Some(libc::EINVAL) => {
                        return Ok(0);
                    }
                    Err(_) => return Ok(2),
                }
            }
            Ok(1)
        });
        match done {
            Ok(0) => Ok(()),
            Ok(2) => Err(false),
            _ => Err(true),
        }
    }
    fn remove_jail(&mut self, name: &str) -> Result<(), String> {
        sys::jail_remove(name).map_err(|e| format!("remove jail {name}: {e}"))
    }
    fn remove_dir(&mut self, path: &Path) -> Result<(), String> {
        match std::fs::remove_dir(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("remove {}: {e}", path.display())),
        }
    }
}

/// The machine-wide mount lock, held until dropped.
struct MountLock(#[allow(dead_code, reason = "held for its lock, released when dropped")] std::fs::File);

impl MountLock {
    /// Take it, waiting at most `wait`; `None` when it stayed held. A record
    /// lock (fcntl), not flock: a forked child does not hold it, so a helper
    /// killed or stuck in the kernel never keeps it.
    fn try_take(wait: std::time::Duration) -> Option<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        let f = match std::fs::OpenOptions::new().create(true).append(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(MOUNT_LOCK) {
            Ok(f) => f,
            Err(e) => {
                // Said where an operator looks: a caller reports only that
                // it could not go on.
                eprintln!("ssai-jaild: cannot open {MOUNT_LOCK}: {e}");
                return None;
            }
        };
        let lock = libc::flock { l_start: 0, l_len: 0, l_pid: 0, l_type: libc::F_WRLCK, l_whence: libc::SEEK_SET as i16, l_sysid: 0 };
        let deadline = std::time::Instant::now() + wait;
        loop {
            // SAFETY: a non-blocking fcntl lock on our own descriptor.
            if unsafe { libc::fcntl(f.as_raw_fd(), libc::F_SETLK, &lock) } == 0 {
                return Some(Self(f));
            }
            if std::time::Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}

/// Undo every run no worker holds, then remove the jail folders no record
/// names (an empty one: a mounted folder is busy and stays).
fn sweep(deadline: std::time::Instant) {
    let Some(_lock) = MountLock::try_take(left(deadline)) else { return };
    let Ok(entries) = std::fs::read_dir(RUNS) else { return };
    for entry in entries.flatten() {
        // A hidden name is a record being created — held by its creator from
        // the start; one no creator holds is a creation that failed.
        if entry.file_name().to_string_lossy().starts_with('.') {
            if let Ok(f) = std::fs::OpenOptions::new().read(true).custom_flags_nofollow().open(entry.path())
                // SAFETY: flock on our own descriptor.
                && unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0
            {
                let _ = std::fs::remove_file(entry.path());
            }
            continue;
        }
        let path = entry.path();
        let Ok(file) = std::fs::OpenOptions::new().read(true).custom_flags_nofollow().open(&path) else { continue };
        // A held lock is a live run.
        // SAFETY: flock on our own descriptor.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            continue;
        }
        // Its helpers close this descriptor, as a worker's close its own: one
        // stuck in the kernel must not keep the dead run looking live.
        RECORD_LOCK_FD.store(file.as_raw_fd(), std::sync::atomic::Ordering::Relaxed);
        let out = file_for_append(&path);
        append(&out, &Line::Ending);
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let mut note = |m: &record::MountEntry, before: bool| append(&out, &unmount_line(m, before));
        match record::teardown(&mut RealHost, &record::parse(&text), &sys::boot_id(), &mut note) {
            Ok(()) => {
                let _ = std::fs::remove_file(&path);
            }
            Err(e) => eprintln!("ssai-jaild: the sandbox run {} is not removed yet: {e}", path.display()),
        }
        RECORD_LOCK_FD.store(-1, std::sync::atomic::Ordering::Relaxed);
    }
    let Ok(jails) = std::fs::read_dir(JAILS) else { return };
    for entry in jails.flatten() {
        let name = entry.file_name();
        if !Path::new(RUNS).join(&name).exists() && !Path::new(RUNS).join(format!(".{}", name.to_string_lossy())).exists() {
            let _ = std::fs::remove_dir(entry.path());
        }
    }
}

trait NoFollow {
    fn custom_flags_nofollow(&mut self) -> &mut Self;
}

impl NoFollow for std::fs::OpenOptions {
    fn custom_flags_nofollow(&mut self) -> &mut Self {
        use std::os::unix::fs::OpenOptionsExt;
        self.custom_flags(libc::O_NOFOLLOW)
    }
}

/// The record at `path` opened to append to (a sweep's), if it can be.
fn file_for_append(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().append(true).custom_flags_nofollow().open(path)
}

/// The line a teardown writes about `m`: before unmounting it (`before`), or
/// when that failed.
fn unmount_line(m: &record::MountEntry, before: bool) -> Line {
    let (fsid, fstype, on) = (m.fsid, m.fstype.clone(), m.on.clone());
    if before { Line::Unmounted { fsid, fstype, on } } else { Line::Kept { fsid, fstype, on } }
}

/// Write `line` to the record `file`.
fn append(file: &std::io::Result<std::fs::File>, line: &Line) {
    if let Ok(f) = file
        && let Ok(json) = serde_json::to_string(line)
    {
        let text = format!("\n{json}\n");
        let _ = (&*f).write_all(text.as_bytes());
    }
}

/// How many runs `uid` has live: records it owns that a worker holds.
fn live_runs(uid: libc::uid_t) -> usize {
    let Ok(entries) = std::fs::read_dir(RUNS) else { return 0 };
    entries
        .flatten()
        .filter(|e| {
            let text = std::fs::read_to_string(e.path()).unwrap_or_default();
            if record::owner(&record::parse(&text)) != Some(uid) {
                return false;
            }
            let Ok(f) = std::fs::File::open(e.path()) else { return false };
            // SAFETY: flock on our own descriptor; a shared lock we take is
            // released with it.
            unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) != 0 }
        })
        .count()
}

fn run_id() -> String {
    let mut bytes = [0u8; 8];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut bytes);
    hex::encode(bytes)
}

/// A run: build the jail, say so, hold it until the connection closes, then
/// remove it.
fn run(conn: &UnixStream, uid: libc::uid_t, req: RunRequest) -> Result<()> {
    let refuse = |message: String| {
        let _ = proto::send(conn, &FromDaemon::Refused { message }, &[]);
    };
    if let Err(r) = request::check_shape(&req) {
        refuse(r.0);
        return Ok(());
    }
    // One wait for the mount lock across the whole build (its sweep, its
    // count, its two mounting phases), so the CLI's wait covers it.
    let deadline = std::time::Instant::now() + LOCK_WAIT;
    sweep(deadline);
    // Counted and created under one lock, so runs started at once cannot
    // all pass the cap.
    let (id, rec) = {
        let Some(_lock) = MountLock::try_take(left(deadline)) else {
            refuse("the sandbox is busy building or removing other runs: try again".into());
            return Ok(());
        };
        if at_cap(live_runs(uid), MAX_RUNS) {
            refuse(format!("you have {MAX_RUNS} sandboxed runs already"));
            return Ok(());
        }
        let id = run_id();
        let rec = Record::create(&id, uid)?;
        (id, rec)
    };
    let built = build(&rec, &id, uid, &req, deadline);
    let outcome = match built {
        // A caller gone before the answer (killed while the jail was built)
        // ends the run like one gone later: the teardown below.
        Ok(()) => match rec.line(&Line::Ready).and_then(|()| proto::send(conn, &FromDaemon::Ready { run: id.clone() }, &[])) {
            Ok(()) => {
                // Held until the connection closes (the CLI's run ended, or
                // it was killed): anything read before that is ignored.
                while let Ok(Some(_)) = proto::recv::<ToDaemon>(conn) {}
                Ok(())
            }
            Err(e) => Err(e),
        },
        Err(e) => {
            refuse(format!("{e:#}"));
            Err(e)
        }
    };
    // From here nothing new starts in the run.
    let _ = rec.line(&Line::Ending);
    // Its processes end now (removing a jail needs no lock), whatever the
    // wait for the lock the unmounts need; the teardown finds it gone.
    if let Err(e) = sys::jail_remove(&format!("ssai-{id}")) {
        eprintln!("ssai-jaild: the sandbox run {id}'s jail could not be removed yet: {e}");
    }
    let text = std::fs::read_to_string(&rec.path).unwrap_or_default();
    // Never unmount without the lock: the record stays for a sweep.
    let Some(lock) = MountLock::try_take(LOCK_WAIT) else {
        eprintln!("ssai-jaild: the sandbox run {id}'s mounts are left to the next sweep: the mount lock could not be taken");
        return outcome;
    };
    let mut note = |m: &record::MountEntry, before: bool| {
        let _ = rec.line(&unmount_line(m, before));
    };
    match record::teardown(&mut RealHost, &record::parse(&text), &sys::boot_id(), &mut note) {
        Ok(()) => {
            let _ = std::fs::remove_file(&rec.path);
        }
        Err(e) => eprintln!("ssai-jaild: the sandbox run {id} is not removed yet: {e}"),
    }
    drop(lock);
    drop(rec);
    outcome
}

/// A path as the walk opened it, as the user: the folder mounted from (for a
/// file, its parent folder) and, for a file, its name and identity.
struct Opened {
    path: PathBuf,
    /// Where it is mounted in the jail.
    at: PathBuf,
    write: bool,
    dir: OwnedFd,
    file: Option<(std::ffi::OsString, Ident)>,
}

/// A file's identity as the walk opened it: its inode and birth time — what
/// a file mounted by name is checked against, so a name swapped for a link
/// in between is caught. (Not the generation number: nullfs does not pass
/// it through, measured. On a filesystem with no birth time, the inode
/// alone: a residual — two files of one inode number on two filesystems.)
type Ident = (u64, i64, i64);

/// What the walking child answers for one path.
#[derive(serde::Serialize, serde::Deserialize)]
enum Walked {
    /// A folder; its descriptor beside the frame.
    Dir,
    /// A regular file: its folder's descriptor beside the frame.
    File { name: std::ffi::OsString, ident: Ident },
    /// A grant refused.
    Refused(String),
}

/// Build the jail of run `id` for `uid` (see the module doc for the order).
fn build(rec: &Record, id: &str, uid: libc::uid_t, req: &RunRequest, deadline: std::time::Instant) -> Result<()> {
    let acct = sys::account(uid)?;
    let home = std::fs::canonicalize(&acct.home).with_context(|| format!("resolve your home {}", acct.home.display()))?;
    let home_parent = home.parent().map(Path::to_path_buf).unwrap_or_default();
    // A home at `/`, right under it, a system folder or right under one
    // would have its parent covered or shown: refused.
    if home_parent == Path::new("/")
        || home == Path::new("/")
        || SYSTEM_MOUNTS.iter().any(|m| Path::new(m) == home || Path::new(m) == home_parent)
    {
        bail!("your home {} is not one the sandbox can cover", home.display());
    }
    // Every other home is hidden.
    // Covered: the folder holding the homes where a system mount shows it —
    // `/usr/home` only: any other (`/usr/local`, `/usr/local/home`) would
    // cover a system tree, or leave other homes shown: refused.
    let under = SYSTEM_MOUNTS.iter().find(|m| home_parent.starts_with(m));
    if let Some(m) = under
        && home_parent != Path::new("/usr/home")
    {
        bail!("your home {} is not one the sandbox can cover (under {m}, only /usr/home holds homes)", home.display());
    }
    // Covered too: `/usr/home` where it holds homes and is not this one's
    // parent (an account of an older layout beside homes elsewhere).
    let mut covers: Vec<PathBuf> = under.map(|_| home_parent.clone()).into_iter().collect();
    let usr_home = Path::new("/usr/home");
    if std::fs::symlink_metadata(usr_home).is_ok_and(|m| m.is_dir()) && !covers.iter().any(|c| c == usr_home) {
        covers.push(usr_home.to_path_buf());
    }
    // No user mount lands inside a system mount (a host folder mounted
    // inside a mount of its own tree can wedge nullfs at unmount): only
    // inside the covered folder, whatever the request says.
    for g in &req.grants {
        let t = g.target();
        if SYSTEM_MOUNTS.iter().any(|m| t.starts_with(m)) && !covers.iter().any(|c| t.starts_with(c)) {
            bail!("{} is inside a folder the sandbox shows from the system", t.display());
        }
    }
    let root = Path::new(JAILS).join(id);
    // Mounting holds the machine-wide lock; the walk as the user, over
    // paths the user chose, does not (it may block on their filesystem).
    let lock = MountLock::try_take(left(deadline)).context("the sandbox is busy building or removing other runs: try again")?;
    rec.begin(Step::Dir { path: root.clone() })?;
    make_root_dir(&root, 0o700)?;
    // `optional`: a mount that cannot be made is skipped; one made that did
    // not take its options still fails the build.
    let host_mount_if = |fstype: &str, target: &Path, opts: &[(&str, Option<&[u8]>)], flags: i32, optional: bool| -> Result<()> {
        rec.begin(Step::Mount { target: target.to_path_buf(), in_jail: false })?;
        match sys::nmount(fstype, target, opts, flags | libc::MNT_NOSUID) {
            Ok(()) => {}
            Err(_) if optional => return Ok(()),
            Err(e) => return Err(e).with_context(|| format!("mount {fstype} on {}", target.display())),
        }
        let fs = sys::statfs(target)?;
        rec.line(&Line::Mounted { fsid: fs.entry.fsid, fstype: fs.entry.fstype.clone(), on: fs.entry.on.clone() })?;
        check_flags(&fs, flags & libc::MNT_RDONLY != 0, target)
    };
    let host_mount = |fstype: &str, target: &Path, opts: &[(&str, Option<&[u8]>)], flags: i32| host_mount_if(fstype, target, opts, flags, false);
    host_mount("tmpfs", &root, &[("mode", Some(b"0755")), ("size", Some(ROOT_SIZE.as_bytes()))], 0)?;
    let at = |p: &str| root.join(p.trim_start_matches('/'));
    let at_path = |p: &Path| root.join(p.strip_prefix("/").unwrap_or(p));
    for dir in ["dev", "tmp", "var/run", "var/tmp", request::STAGE] {
        std::fs::create_dir_all(at(dir))?;
    }
    set_mode(&at(request::STAGE), 0o700)?;
    set_mode(&at("var/tmp"), 0o1777)?;
    // The system, read-only.
    let linux = Path::new("/compat/linux/bin").exists();
    for m in SYSTEM_MOUNTS.iter().filter(|m| Path::new(m).is_dir() && (**m != "/compat" || linux)) {
        let src = if *m == "/compat" { "/compat/linux" } else { m };
        let target = at(src);
        std::fs::create_dir_all(&target)?;
        host_mount("nullfs", &target, &[("target", Some(src.as_bytes()))], libc::MNT_RDONLY)?;
    }
    host_mount("devfs", &at("dev"), &[("ruleset", Some(DEVFS_RULESET.as_bytes()))], 0)?;
    if at("dev/mem").exists() {
        bail!("the jail's /dev shows the host's devices: its devfs ruleset was not applied");
    }
    host_mount("fdescfs", &at("dev/fd"), &[], 0)?;
    host_mount("tmpfs", &at("tmp"), &[("mode", Some(b"1777")), ("size", Some(TMP_SIZE.as_bytes()))], 0)?;
    if linux {
        // The Linux ABI's own filesystems; a client needing one fails
        // visibly without it, so one that cannot be made is not the run's
        // failure (one made without its options is).
        for (fstype, dir, opts) in [
            ("linprocfs", "compat/linux/proc", &[][..]),
            ("linsysfs", "compat/linux/sys", &[][..]),
            ("devfs", "compat/linux/dev", &[("ruleset", Some(DEVFS_RULESET.as_bytes()))][..]),
            ("fdescfs", "compat/linux/dev/fd", &[("linrdlnk", None)][..]),
            ("tmpfs", "compat/linux/dev/shm", &[("mode", Some(&b"1777"[..])), ("size", Some(TMP_SIZE.as_bytes()))][..]),
        ] {
            // `dev/shm` is a folder made in the Linux devfs just mounted
            // (its ruleset shows none).
            if dir.ends_with("/shm") {
                let _ = std::fs::create_dir(at(dir));
            }
            if at(dir).is_dir() {
                host_mount_if(fstype, &at(dir), opts, 0, true)?;
            }
            if fstype == "devfs" && at("compat/linux/dev/mem").exists() {
                bail!("the jail's Linux /dev shows the host's devices: its devfs ruleset was not applied");
            }
        }
    }
    if let Ok(hints) = std::fs::read("/var/run/ld-elf.so.hints") {
        std::fs::write(at("var/run/ld-elf.so.hints"), hints)?;
    }
    // The covered folder (above), or else nothing but the home itself.
    for cover in &covers {
        host_mount("tmpfs", &at_path(cover), &[("mode", Some(b"0755")), ("size", Some(COVER_SIZE.as_bytes()))], 0)?;
    }
    std::fs::create_dir_all(at_path(&home))?;
    if let Ok(link) = std::fs::read_link("/home") {
        let _ = std::os::unix::fs::symlink(link, at("home"));
    }
    // The home as the account names it, where that is a link (`/home/u` →
    // `/data/u`): the same link in the jail, so `$HOME` and every path the
    // client spells through it resolve. Best effort: its folder may be one
    // the jail shows read-only.
    if acct.home != home && acct.home.is_absolute() {
        let link = at_path(&acct.home);
        if std::fs::symlink_metadata(&link).is_err() {
            if let Some(parent) = link.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::os::unix::fs::symlink(&home, &link);
        }
    }

    // The jail, and everything only root does in it, before any user mount.
    let name = format!("ssai-{id}");
    rec.begin(Step::Jail { name: name.clone() })?;
    let jid = sys::jail_create(&name, &root).context("create the jail")?;
    in_jail_as_root(jid, "/sbin/ifconfig", &["lo0", "inet", "127.0.0.1/8", "up"])?;
    if sys::sysctl_exists(c"net.inet.ip.fw.enable") {
        in_jail_as_root(jid, "/sbin/ipfw", &["-q", "add", "100", "allow", "ip", "from", "any", "to", "any", "via", "lo0"])?;
    }
    sys::jail_securelevel(jid, 3).context("raise the jail's securelevel")?;

    // What the user asked for, opened as the user only now — `jail_attach`
    // refuses a process holding an open folder — and mounted from inside the
    // jail root.
    drop(lock);
    let grants = open_as(uid, &acct, req)?;
    let _lock = MountLock::try_take(left(deadline)).context("the sandbox is busy building or removing other runs: try again")?;
    mount_user(rec, &root, &grants, &req.held)
}

/// Fail unless the mount at `target` is read-only exactly when asked, and
/// nosuid where it can hold a program (nullfs, tmpfs: devfs and fdescfs drop
/// the option and hold none).
fn check_flags(fs: &sys::Fs, ro: bool, target: &Path) -> Result<()> {
    let flags = fs.flags as i32;
    let holds_programs = matches!(fs.entry.fstype.as_str(), "nullfs" | "tmpfs");
    if (holds_programs && flags & libc::MNT_NOSUID == 0) || (flags & libc::MNT_RDONLY != 0) != ro {
        bail!("the mount on {} did not take its options", target.display());
    }
    Ok(())
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).with_context(|| format!("set the mode of {}", path.display()))
}

/// Run `program` in the jail as its root, with no environment — before any
/// user mount, so it runs only the host's binaries.
fn in_jail_as_root(jid: i32, program: &str, args: &[&str]) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new(program);
    cmd.args(args).env_clear().stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null());
    // SAFETY: jail_attach between fork and exec, an async-signal-safe syscall.
    unsafe {
        cmd.pre_exec(move || {
            if libc::jail_attach(jid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    // Bounded: it runs while the machine-wide lock is held.
    let mut child = cmd.spawn().with_context(|| format!("run {program} in the jail"))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                bail!("{program} {} failed in the jail", args.join(" "));
            }
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            // Killed, waited for a few seconds at most.
            reap_child(child.id() as libc::pid_t, true);
            bail!("{program} {} did not finish in the jail", args.join(" "));
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// Reap helper `pid`; when it failed (`kill`), SIGKILL it first and wait a
/// few seconds at most: one stuck in the kernel is left to init rather than
/// hold this worker (and the machine-wide mount lock) forever.
fn reap_child(pid: libc::pid_t, kill: bool) {
    let mut status = 0;
    if !kill {
        // SAFETY: wait for our own child.
        unsafe { libc::waitpid(pid, &mut status, 0) };
        return;
    }
    // SAFETY: a signal to our own child, then non-blocking waits on it.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    for _ in 0..50 {
        // SAFETY: as above.
        if unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } != 0 {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Run `f` in a child process chrooted into `root`; its error comes back as
/// text.
fn in_chroot<T: serde::Serialize + serde::de::DeserializeOwned>(
    root: &Path,
    timeout: std::time::Duration,
    f: impl FnOnce() -> Result<T>,
) -> Result<T> {
    in_child(Some(root), timeout, f)
}

/// Run `f` in a child process (chrooted into `root` when given), waiting
/// `timeout` at most; its error comes back as text.
fn in_child<T: serde::Serialize + serde::de::DeserializeOwned>(
    root: Option<&Path>,
    timeout: std::time::Duration,
    f: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let (a, b) = UnixStream::pair()?;
    let root_c = root.map(sys::cstr).transpose()?;
    // SAFETY: the worker is single-threaded; the child chroots, runs `f`,
    // writes its answer and exits.
    match unsafe { libc::fork() } {
        0 => {
            drop(a);
            drop_record_lock();
            let out: std::result::Result<T, String> = (|| {
                // SAFETY: chroot + chdir on a path we hold.
                if let Some(root_c) = &root_c
                    && (unsafe { libc::chroot(root_c.as_ptr()) } != 0 || unsafe { libc::chdir(c"/".as_ptr()) } != 0)
                {
                    return Err(format!("enter {}: {}", root.unwrap_or(Path::new("/")).display(), std::io::Error::last_os_error()));
                }
                f().map_err(|e| format!("{e:#}"))
            })();
            let _ = proto::send(&b, &out, &[]);
            // SAFETY: leave the child.
            unsafe { libc::_exit(0) };
        }
        pid if pid > 0 => {
            drop(b);
            // Bounded, the whole answer: a mount over a filesystem that
            // stops answering must not hold the machine-wide lock; the child
            // is killed. (The answer is one small write: once it begins, the
            // rest is there.)
            let mut p = libc::pollfd { fd: a.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
            // SAFETY: poll on a descriptor we hold.
            let ready = unsafe { libc::poll(&mut p, 1, ms) } > 0;
            if let Err(e) = a.set_read_timeout(Some(std::time::Duration::from_secs(5))) {
                reap_child(pid, true);
                return Err(e.into());
            }
            let got = if ready {
                proto::recv::<std::result::Result<T, String>>(&a)
            } else {
                Err(anyhow::anyhow!("the helper did not answer within {}s", timeout.as_secs()))
            };
            reap_child(pid, got.is_err());
            match got? {
                Some((Ok(v), _)) => Ok(v),
                Some((Err(e), _)) => bail!(e),
                None => bail!("the helper ended without an answer"),
            }
        }
        _ => Err(std::io::Error::last_os_error().into()),
    }
}

/// Open every grant AS THE USER ([`request::walk`] in a child that dropped
/// to `uid`), each passed back as an open folder. A file opens its folder,
/// its name checked there without following a link. A grant that cannot be
/// opened refuses the run.
fn open_as(uid: libc::uid_t, acct: &sys::Account, req: &RunRequest) -> Result<Vec<Opened>> {
    let (a, b) = UnixStream::pair()?;
    // SAFETY: the worker is single-threaded; the child drops to the user,
    // walks, passes each result back and exits.
    match unsafe { libc::fork() } {
        0 => {
            drop(a);
            drop_record_lock();
            let became = sys::become_user(uid, acct);
            if let Err(e) = &became {
                let _ = proto::send(&b, &Walked::Refused(format!("could not take your identity to open the run's folders: {e}")), &[]);
            }
            let code = if became.is_ok() {
                for g in &req.grants {
                    let (msg, fd) = match walk_one(g, uid) {
                        Ok((fd, None)) => (Walked::Dir, Some(fd)),
                        Ok((fd, Some((name, ident)))) => (Walked::File { name, ident }, Some(fd)),
                        Err(e) => (Walked::Refused(e), None),
                    };
                    let fds: Vec<RawFd> = fd.iter().map(|f| f.as_raw_fd()).collect();
                    if proto::send(&b, &msg, &fds).is_err() {
                        break;
                    }
                }
                0
            } else {
                1
            };
            // SAFETY: leave the child.
            unsafe { libc::_exit(code) };
        }
        pid if pid > 0 => {
            drop(b);
            // A walk that blocks (a hung filesystem the user named) ends the
            // run instead of holding it: 120 s for the whole walk, then its
            // child is killed below.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
            let answers = (|| -> Result<Vec<Opened>> {
                let mut grants = Vec::new();
                for g in &req.grants {
                    let left = deadline.saturating_duration_since(std::time::Instant::now());
                    if left.is_zero() {
                        bail!("opening the run's folders as you took too long");
                    }
                    a.set_read_timeout(Some(left))?;
                    let got = proto::recv::<Walked>(&a)?;
                    let (msg, mut fds) = got.with_context(|| format!("could not open {} as you", g.path.display()))?;
                    let mut opened = |file| -> Result<Opened> {
                        let dir = if fds.len() == 1 { fds.remove(0) } else { bail!("could not open {} as you", g.path.display()) };
                        Ok(Opened { path: g.path.clone(), at: g.target().to_path_buf(), write: g.write, dir, file })
                    };
                    let o = match msg {
                        Walked::Dir => opened(None)?,
                        Walked::File { name, ident } => opened(Some((name, ident)))?,
                        Walked::Refused(e) => bail!(e),
                    };
                    grants.push(o);
                }
                Ok(grants)
            })();
            // The child may still be writing, or blocked: our end closes
            // first, so it never blocks on a full socket, and a child still
            // walking is killed.
            drop(a);
            reap_child(pid, answers.is_err());
            answers
        }
        _ => Err(std::io::Error::last_os_error().into()),
    }
}

/// The real walker: `openat(O_PATH | O_NOFOLLOW)` one component at a time.
struct OpenAt;

impl request::Walker for OpenAt {
    type Fd = OwnedFd;
    fn root(&mut self) -> std::io::Result<OwnedFd> {
        // SAFETY: open returns a new descriptor we own.
        let fd = unsafe { libc::open(c"/".as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: a fresh descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
    fn step(&mut self, dir: &OwnedFd, name: &std::ffi::OsStr) -> std::io::Result<(OwnedFd, Meta)> {
        let c = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(name))?;
        // SAFETY: openat on a descriptor we own; the result is ours.
        let fd = unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: a fresh descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let st = fstat(fd.as_raw_fd())?;
        let kind = match st.st_mode & libc::S_IFMT {
            libc::S_IFDIR => Kind::Dir,
            libc::S_IFREG => Kind::File,
            // A link opened with O_PATH|O_NOFOLLOW is the link itself:
            // refused like the walk's O_NOFOLLOW error.
            libc::S_IFLNK => return Err(std::io::Error::from_raw_os_error(libc::EMLINK)),
            _ => Kind::Other,
        };
        Ok((fd, Meta { kind, uid: st.st_uid }))
    }
}

fn fstat(fd: RawFd) -> std::io::Result<libc::stat> {
    // SAFETY: fstat into a struct we own.
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(fd, &mut st) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(st)
    }
}

fn ident_of(st: &libc::stat) -> Ident {
    (st.st_ino, st.st_birthtime, st.st_birthtime_nsec)
}

/// Walk one path as the user: the folder to mount from, and for a file its
/// name and identity.
#[allow(clippy::type_complexity)]
fn walk_one(g: &Grant, uid: libc::uid_t) -> std::result::Result<(OwnedFd, Option<(std::ffi::OsString, Ident)>), String> {
    let (fd, meta) = request::walk(&mut OpenAt, g, uid).map_err(|r| r.0)?;
    match meta.kind {
        Kind::Dir => Ok((fd, None)),
        _ => {
            let ident = ident_of(&fstat(fd.as_raw_fd()).map_err(|e| e.to_string())?);
            // The file's folder, walked the same way (it was walked to reach
            // the file; opened again as its own path, never written).
            let parent = g.path.parent().ok_or("a file grant has a folder")?;
            let dir = open_folder(parent, uid)?;
            Ok((dir, g.path.file_name().map(|n| (n.to_os_string(), ident))))
        }
    }
}

/// Make the missing folders of `path` (and, `file`, the file itself, empty),
/// as root in the chroot, one component at a time from `/` through
/// descriptors: never following a link (one put on the way by an agent is
/// refused, not followed), never truncating, never replacing what is there.
/// A file's folder, opened by the no-follow walk — `/` itself, which no
/// grant may be, opened directly.
fn open_folder(path: &Path, uid: libc::uid_t) -> std::result::Result<OwnedFd, String> {
    if path == Path::new("/") {
        return request::Walker::root(&mut OpenAt).map_err(|e| format!("open /: {e}"));
    }
    request::walk(&mut OpenAt, &Grant { path: path.to_path_buf(), ..Grant::default() }, uid).map(|(fd, _)| fd).map_err(|r| r.0)
}

fn make_path(path: &Path, file: bool) -> Result<()> {
    let names: Vec<_> = path.components().skip(1).map(|c| c.as_os_str().to_owned()).collect();
    // SAFETY: open/openat/mkdirat/close on descriptors this function owns,
    // with NUL-terminated names it built.
    unsafe {
        let mut dir = libc::open(c"/".as_ptr(), libc::O_DIRECTORY | libc::O_CLOEXEC);
        if dir < 0 {
            bail!("open /: {}", std::io::Error::last_os_error());
        }
        for (i, name) in names.iter().enumerate() {
            let c = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(name.as_os_str()))?;
            let last = i + 1 == names.len();
            let next = if last && file {
                let fd = libc::openat(dir, c.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o644);
                if fd >= 0 {
                    fd
                } else if std::io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST) {
                    // There already: a file, never a folder or a link.
                    let mut st: libc::stat = std::mem::zeroed();
                    if libc::fstatat(dir, c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) != 0 || st.st_mode & libc::S_IFMT != libc::S_IFREG {
                        libc::close(dir);
                        bail!("{} cannot be shown as a file: something else is there", path.display());
                    }
                    -1
                } else {
                    let e = std::io::Error::last_os_error();
                    libc::close(dir);
                    bail!("create {}: {e}", path.display());
                }
            } else {
                if libc::mkdirat(dir, c.as_ptr(), 0o755) != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
                    let e = std::io::Error::last_os_error();
                    libc::close(dir);
                    bail!("create {}: {e}", path.display());
                }
                let fd = libc::openat(dir, c.as_ptr(), libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
                if fd < 0 {
                    let e = std::io::Error::last_os_error();
                    libc::close(dir);
                    bail!("{} cannot be reached without following a link: {e}", path.display());
                }
                fd
            };
            libc::close(dir);
            dir = next;
        }
        if dir >= 0 {
            libc::close(dir);
        }
    }
    Ok(())
}

/// Mount the user's grants and held paths, from inside the jail root, every
/// source a folder opened without following a link (never a path resolved
/// again): grants — opened by the user — ancestors first, a file through a
/// stage holding its folder, then checked to be the file the walk opened;
/// then each held path through a stage of its own — every `node` before any
/// read-only one, so a later folder mount never covers a held file.
fn mount_user(rec: &Record, root: &Path, opened: &[Opened], held: &[request::Held]) -> Result<()> {
    let mut order: Vec<&Opened> = opened.iter().collect();
    order.sort_by_key(|o| o.at.components().count());
    let mut held: Vec<&request::Held> = held.iter().collect();
    // Every `node` before any read-only path, each kind ancestors first.
    held.sort_by_key(|h| (!h.node, h.path.components().count()));
    // The helper closes the worker's locked handle; it writes through this one.
    let rec = &rec.writer()?;
    // 120 s, and more for a large request: each mount reads the mount table.
    let budget = std::time::Duration::from_secs(120) + std::time::Duration::from_millis(100) * (opened.len() + 2 * held.len()) as u32;
    in_chroot(root, budget, || {
        let mut stage = 0usize;
        let mut next_stage = || -> Result<PathBuf> {
            stage += 1;
            let p = Path::new(request::STAGE).join(stage.to_string());
            std::fs::create_dir(&p)?;
            Ok(p)
        };
        // No folder on the way to a mount target may be a link: one would
        // land the mount elsewhere in the jail (a link the daemon made —
        // `/home` — or one an agent put in a project).
        let no_link = |target: &Path| -> Result<()> {
            let mut at = PathBuf::from("/");
            for c in target.components().skip(1) {
                at.push(c);
                match std::fs::symlink_metadata(&at) {
                    Ok(m) if m.file_type().is_symlink() => bail!("{} goes through a link ({})", target.display(), at.display()),
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
            Ok(())
        };
        let mount = |target: &Path, source: &[u8], ro: bool| -> Result<record::MountEntry> {
            no_link(target)?;
            rec.begin(Step::Mount { target: target.to_path_buf(), in_jail: true })?;
            let flags = libc::MNT_NOSUID | if ro { libc::MNT_RDONLY } else { 0 };
            // The new mount is told by the mount table's difference: the
            // machine-wide lock is held, so nothing else mounts meanwhile —
            // its exact id and name are recorded before any check can fail,
            // wherever a link swapped in since made `nmount` land it.
            // Root's mounts only: a user's own (`vfs.usermount`) is never ours.
            let before: std::collections::HashSet<[i32; 2]> = sys::root_mounts().iter().map(|m| m.fsid).collect();
            sys::nmount("nullfs", target, &[("target", Some(source))], flags)
                .with_context(|| format!("mount {}", target.display()))?;
            // (nullfs only: a ZFS snapshot or autofs mount appearing
            // meanwhile is not the daemon's — and only it makes nullfs mounts
            // under the lock.)
            let new: Vec<record::MountEntry> =
                sys::root_mounts().into_iter().filter(|m| m.fstype == "nullfs" && !before.contains(&m.fsid)).collect();
            // Ours: the new one named for the target (host path, or the
            // jail's for a file); else, landed elsewhere, the only new one.
            // (Another nullfs mount made meanwhile — `vfs.usermount` — is
            // told apart by its name.)
            let host_name = root.join(target.strip_prefix("/").unwrap_or(target));
            let named: Vec<&record::MountEntry> =
                new.iter().filter(|m| Path::new(&m.on) == host_name || Path::new(&m.on) == target).collect();
            let made = match (named.as_slice(), new.as_slice()) {
                ([m], _) => *m,
                ([], [m]) => m,
                _ => bail!("could not tell the mount of {} in the mount table", target.display()),
            };
            rec.line(&Line::Mounted { fsid: made.fsid, fstype: made.fstype.clone(), on: made.on.clone() })?;
            // Its flags, read where it is reached without following a link:
            // reached otherwise (it landed elsewhere) it is unmounted.
            let fs = request::walk(&mut OpenAt, &Grant { path: target.to_path_buf(), ..Grant::default() }, 0)
                .ok()
                .and_then(|(fd, _)| sys::fstatfs(fd.as_raw_fd()))
                .filter(|fs| fs.entry.fsid == made.fsid);
            let Some(fs) = fs else {
                rec.line(&unmount_line(made, true))?;
                if sys::unmount_fsid(made.fsid).is_err() {
                    rec.line(&unmount_line(made, false))?;
                }
                bail!("{} changed while the sandbox was being built", target.display());
            };
            check_flags(&fs, ro, target)?;
            Ok(fs.entry)
        };
        // The folder the walk opened, at a fresh stage only root can enter.
        let stage_dir = |o: &Opened, ro: bool, next: &mut dyn FnMut() -> Result<PathBuf>| -> Result<PathBuf> {
            // SAFETY: fchdir to a folder descriptor the walk opened.
            if unsafe { libc::fchdir(o.dir.as_raw_fd()) } != 0 {
                bail!("enter {}: {}", o.path.display(), std::io::Error::last_os_error());
            }
            let st = next()?;
            mount(&st, b".", ro)?;
            std::env::set_current_dir("/")?;
            Ok(st)
        };
        // What is at `target` — reached again without following a link —
        // must be the new mount (its fsid) showing what the walk opened
        // (inode and birth time): a name swapped for a link between the walk
        // and the mount (nmount follows links) is unmounted, recorded so, and
        // the run refused.
        let verify = |target: &Path, ident: Ident, made: record::MountEntry| -> Result<()> {
            let seen = request::walk(&mut OpenAt, &Grant { path: target.to_path_buf(), ..Grant::default() }, 0)
                .ok()
                .and_then(|(fd, _)| Some((ident_of(&fstat(fd.as_raw_fd()).ok()?), sys::fstatfs_fsid(fd.as_raw_fd())?)));
            if seen != Some((ident, made.fsid)) {
                rec.line(&unmount_line(&made, true))?;
                if sys::unmount_fsid(made.fsid).is_err() {
                    rec.line(&unmount_line(&made, false))?;
                }
                bail!("{} changed while the sandbox was being built", target.display());
            }
            Ok(())
        };
        // A file from its staged folder, then verified. A grant's target is
        // made where missing (`create`); a held one must be there.
        let mount_file = |o: &Opened, st: &Path, name: &std::ffi::OsStr, ident: Ident, ro: bool, create: bool| -> Result<()> {
            no_link(&o.at)?;
            if create {
                make_path(&o.at, true)?;
            }
            let from = st.join(name);
            let made = mount(&o.at, std::os::unix::ffi::OsStrExt::as_bytes(from.as_os_str()), ro)?;
            verify(&o.at, ident, made)
        };
        let mut mounted: Vec<&Opened> = Vec::new();
        for o in &order {
            let ro = !o.write;
            // Inside a grant already mounted: shown by it as that grant
            // shows it — a writable path inside a read-only grant read-only,
            // a read-only one inside a writable grant writable (unlike
            // Linux's Landlock, which grants the union; the CLI names each
            // such path and refuses a project among them) — since a host
            // folder mounted again inside a mount of its own tree can wedge
            // nullfs at unmount. The
            // grant must be what the outer one shows there: one mounted at
            // another place than its own (a link's) whose content the outer
            // grant does not hold there is refused.
            if let Some(g) = mounted.iter().find(|g| o.at.starts_with(&g.at)) {
                let rel = o.at.strip_prefix(&g.at).unwrap_or(Path::new(""));
                if o.path != g.path.join(rel) {
                    bail!("{} cannot be shown at {}: {} is there", o.path.display(), o.at.display(), g.path.join(rel).display());
                }
                mounted.push(o);
                continue;
            }
            mounted.push(o);
            match &o.file {
                None => {
                    // SAFETY: fchdir to a folder descriptor the walk opened.
                    if unsafe { libc::fchdir(o.dir.as_raw_fd()) } != 0 {
                        bail!("enter {}: {}", o.path.display(), std::io::Error::last_os_error());
                    }
                    no_link(&o.at)?;
                    make_path(&o.at, false)?;
                    let made = mount(&o.at, b".", ro)?;
                    std::env::set_current_dir("/")?;
                    verify(&o.at, ident_of(&fstat(o.dir.as_raw_fd())?), made)?;
                }
                Some((name, ident)) => {
                    let st = stage_dir(o, ro, &mut next_stage)?;
                    mount_file(o, &st, name, *ident, ro, true)?;
                }
            }
        }
        // Each held path as the jail sees it, opened here one component at a
        // time without following a link (one swapped in by an agent of
        // another run is not held, never followed), then mounted from that
        // descriptor through a stage — the stage over the jail's own view,
        // never the host's tree a second time.
        for h in held {
            // A node is writable only where the jail shows its grant
            // writable: the grant mounted over it (the shallowest) decides.
            let shown_writable = mounted.iter().filter(|g| h.path.starts_with(&g.at)).min_by_key(|g| g.at.components().count()).is_some_and(|g| g.write);
            let ro = !(h.node && shown_writable);
            // What cannot be held is never left unheld in silence: the run
            // is refused, naming it.
            let unheld = || anyhow::anyhow!("{} cannot be held read-only in the sandbox (is it a link?)", h.path.display());
            let (fd, meta) = request::walk(&mut OpenAt, &Grant { path: h.path.clone(), ..Grant::default() }, 0).map_err(|_| unheld())?;
            let ident = ident_of(&fstat(fd.as_raw_fd())?);
            let o = match meta.kind {
                Kind::Dir => Opened { path: h.path.clone(), at: h.path.clone(), write: !ro, dir: fd, file: None },
                Kind::File => {
                    let parent = h.path.parent().ok_or_else(unheld)?;
                    let dir = open_folder(parent, 0).map_err(|_| unheld())?;
                    let name = h.path.file_name().ok_or_else(unheld)?;
                    Opened { path: h.path.clone(), at: h.path.clone(), write: !ro, dir, file: Some((name.to_os_string(), ident)) }
                }
                Kind::Other => return Err(unheld()),
            };
            let st = stage_dir(&o, ro, &mut next_stage)?;
            match &o.file {
                None => {
                    let made = mount(&o.at, std::os::unix::ffi::OsStrExt::as_bytes(st.as_os_str()), ro)?;
                    verify(&o.at, ident, made)?;
                }
                Some((name, ident)) => mount_file(&o, &st, name, *ident, ro, false)?,
            }
        }
        Ok(())
    })
}

// ── exec ────────────────────────────────────────────────────────────────

/// What an exec starts, as its caller asked.
struct Started {
    /// The caller's core-file limit, sent (its kernel copy's soft limit is 0
    /// by its own choice), clamped to the hard limit the kernel holds.
    core: (u64, u64),
    argv: Vec<String>,
    env: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    cwd: PathBuf,
}

/// Start `argv` in the user's run `run`, with the caller's stdio (a jail
/// terminal for each that is a terminal), and the umask and resource limits
/// the caller's process has (read from the kernel, never from the request:
/// they are set as root — the core-file limit alone is the request's, never
/// above the kernel's hard one), and report its end.
fn exec(conn: &UnixStream, uid: libc::uid_t, run: &str, start: Started, fds: Vec<OwnedFd>) -> Result<()> {
    let Started { argv, env, cwd, core } = start;
    let refuse = |message: String| -> Result<()> {
        let _ = proto::send(conn, &FromDaemon::Refused { message }, &[]);
        Ok(())
    };
    if !run.chars().all(|c| c.is_ascii_hexdigit()) || run.len() != 16 {
        return refuse("no such sandboxed run".into());
    }
    let text = std::fs::read_to_string(Path::new(RUNS).join(run)).unwrap_or_default();
    let lines = record::parse(&text);
    if record::owner(&lines) != Some(uid) {
        return refuse("no such sandboxed run of yours".into());
    }
    // Not while root is still building it: nothing runs in a jail before
    // its last mount.
    if !record::ready(&lines) {
        return refuse("that sandboxed run is not ready".into());
    }
    // Only while a worker holds it: an orphaned jail (its worker gone)
    // waits for the sweep, and nothing new starts in it.
    // (A worker holds it for the run's life; a sweep holds it while it
    // removes a dead run, and writes `Ending` a moment after taking it — read
    // again below. A process started in that moment is killed by the
    // sweep's removal of the jail; a probe that meets a sweep at worst makes
    // it skip a dead run until the next one.)
    let held = std::fs::File::open(Path::new(RUNS).join(run)).is_ok_and(|f| {
        // SAFETY: flock on our own descriptor; a lock we take goes with it.
        unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) != 0 }
    });
    // Read again after the probe: a teardown that began meanwhile (its
    // lock is what the probe saw) has written `Ending` first.
    let still = std::fs::read_to_string(Path::new(RUNS).join(run)).unwrap_or_default();
    let held = held && record::ready(&record::parse(&still));
    if !held {
        return refuse("that sandboxed run has ended".into());
    }
    let Some(jid) = sys::jail_id(&format!("ssai-{run}")) else { return refuse("that sandboxed run has ended".into()) };
    if fds.len() != 3 || argv.is_empty() {
        return refuse("an exec passes its stdin, stdout and stderr and a command".into());
    }
    // What each descriptor is, decided here: a folder would let the child
    // `fchdir` out of the jail.
    let mut tty = [false; 3];
    for (i, fd) in fds.iter().enumerate() {
        // SAFETY: fstat/isatty on descriptors we received.
        let (mode, is_tty) = unsafe {
            let mut st: libc::stat = std::mem::zeroed();
            if libc::fstat(fd.as_raw_fd(), &mut st) != 0 {
                return refuse("a passed descriptor is not usable".into());
            }
            (st.st_mode & libc::S_IFMT, libc::isatty(fd.as_raw_fd()) == 1)
        };
        if mode == libc::S_IFDIR {
            return refuse("a folder cannot be a process's stdin, stdout or stderr".into());
        }
        tty[i] = is_tty;
    }
    // The calling process's own, all of them, and only while it is still the
    // caller's: a process gone (its pid free, or reused by another user's)
    // would leave the daemon's limits — root's — on the jailed process.
    let caller = sys::peer_pid(conn.as_raw_fd());
    // The effective uid (as `getpeereid` gave it) and the ignored signals
    // come from one snapshot, checked last
    // so every value read before it is the same process's.
    let read = caller.and_then(|pid| Some((sys::proc_limits(pid)?, sys::proc_umask(pid)?, sys::proc_info(pid)?)));
    let Some((limits, umask, (_, ignored_set))) = read.filter(|(_, _, (euid, _))| *euid == uid) else {
        return refuse("could not read the calling process's limits".into());
    };
    // The core limit sent, never above the hard one the kernel holds for
    // the caller (the helper lowers only its soft limit).
    let hard = limits.iter().find(|(r, _)| *r == libc::RLIMIT_CORE).map(|(_, rl)| rl.rlim_max as u64).unwrap_or(0);
    let core_hard = core.1.min(hard);
    let core = libc::rlimit { rlim_cur: core.0.min(core_hard) as libc::rlim_t, rlim_max: core_hard as libc::rlim_t };
    let acct = sys::account(uid)?;
    let pty = match tty.iter().position(|t| *t) {
        Some(i) => Some(open_pty(uid, fds[i].as_raw_fd())?),
        None => None,
    };

    // Everything the child needs, built before the fork.
    let cstrings = |v: &[String]| -> Result<Vec<std::ffi::CString>> {
        v.iter().map(|s| std::ffi::CString::new(s.as_bytes()).map_err(Into::into)).collect()
    };
    let args = cstrings(&argv)?;
    use std::os::unix::ffi::OsStrExt;
    let envs: Vec<std::ffi::CString> = env
        .iter()
        .map(|(k, v)| std::ffi::CString::new([k.as_bytes(), b"=", v.as_bytes()].concat()))
        .collect::<std::result::Result<_, _>>()?;
    // The first, as the process's own getenv reads it.
    let path: &[u8] = env.iter().find(|(k, _)| k == "PATH").map(|(_, v)| v.as_bytes()).unwrap_or(b"/usr/bin:/bin");
    let program = &argv[0];
    let candidates: Vec<std::ffi::CString> = if program.contains('/') {
        vec![std::ffi::CString::new(program.as_bytes())?]
    } else {
        // An empty entry is the current folder, as `execvp` reads it.
        path.split(|b| *b == b':')
            .map(|d| if d.is_empty() { &b"."[..] } else { d })
            .filter_map(|d| std::ffi::CString::new([d, b"/", program.as_bytes()].concat()).ok())
            .collect()
    };
    let cwd_c = sys::cstr(&cwd)?;
    let mut arg_ptrs: Vec<*const libc::c_char> = args.iter().map(|a| a.as_ptr()).collect();
    arg_ptrs.push(std::ptr::null());
    // For each candidate, `sh <candidate> <args…>`: its run by `/bin/sh`.
    let sh_argvs: Vec<Vec<*const libc::c_char>> = candidates
        .iter()
        .map(|c| {
            let mut v = vec![c"sh".as_ptr(), c.as_ptr()];
            v.extend(args.iter().skip(1).map(|a| a.as_ptr()));
            v.push(std::ptr::null());
            v
        })
        .collect();
    let mut env_ptrs: Vec<*const libc::c_char> = envs.iter().map(|e| e.as_ptr()).collect();
    env_ptrs.push(std::ptr::null());
    let mut err_pipe = [0; 2];
    // SAFETY: pipe2 into an array we own.
    if unsafe { libc::pipe2(err_pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        bail!("pipe: {}", std::io::Error::last_os_error());
    }
    let slave = pty.as_ref().map(|(_, s)| s.as_raw_fd()).unwrap_or(-1);
    let stdio: Vec<RawFd> = fds.iter().zip(tty).map(|(fd, t)| if t { slave } else { fd.as_raw_fd() }).collect();
    let mut pd: RawFd = -1;
    // SAFETY: the worker is single-threaded. The child only makes syscalls
    // on data prepared above, then execs or `_exit`s.
    let pid = unsafe { libc::pdfork(&mut pd, 0) };
    if pid == 0 {
        // SAFETY: see above.
        unsafe {
            let fail = |stage: u8| -> ! {
                let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                let msg = [stage, (e & 0xff) as u8, ((e >> 8) & 0xff) as u8];
                libc::write(err_pipe[1], msg.as_ptr() as *const _, 3);
                libc::_exit(127);
            };
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigprocmask(libc::SIG_SETMASK, &set, std::ptr::null_mut());
            // Default dispositions, but the caller's ignored signals stay
            // ignored (`nohup` leaves SIGHUP so), as across an exec — SIGPIPE
            // apart: the helper is a Rust program, whose runtime ignores it,
            // and a process started from a shell has it at its default.
            for sig in 1..32 {
                let ignored = sig != libc::SIGPIPE && libc::sigismember(&ignored_set, sig) == 1;
                libc::signal(sig, if ignored { libc::SIG_IGN } else { libc::SIG_DFL });
            }
            if libc::setsid() < 0 {
                fail(1);
            }
            // The jail terminal is the controlling one only when it is stdin:
            // the helper relays what is typed only from there, so a tool
            // asking on /dev/tty otherwise fails rather than waits forever.
            if slave >= 0 && tty[0] && libc::ioctl(slave, libc::TIOCSCTTY, 0) != 0 {
                fail(2);
            }
            // Every descriptor kept is first copied above any in use, so no
            // dup2 below clobbers a source: stdio to 0..2, the error pipe to 3.
            let mut high = [0; 4];
            for (i, fd) in stdio.iter().chain(std::iter::once(&err_pipe[1])).enumerate() {
                high[i] = libc::fcntl(*fd, libc::F_DUPFD, 256);
                if high[i] < 0 {
                    fail(3);
                }
            }
            for (i, fd) in high.iter().enumerate() {
                if libc::dup2(*fd, i as i32) < 0 {
                    fail(3);
                }
            }
            let err = 3;
            libc::fcntl(err, libc::F_SETFD, libc::FD_CLOEXEC);
            libc::closefrom(4);
            let fail = |stage: u8| -> ! {
                let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                let msg = [stage, (e & 0xff) as u8, ((e >> 8) & 0xff) as u8];
                libc::write(err, msg.as_ptr() as *const _, 3);
                libc::_exit(127);
            };
            // The caller's own, read from the kernel: set as root, before the
            // ids drop, so a hard limit the caller holds is not refused — and
            // after the descriptors moved (a low open-files limit would
            // refuse the copies above).
            libc::umask(umask & 0o777);
            for (resource, rl) in &limits {
                if libc::setrlimit(*resource, if *resource == libc::RLIMIT_CORE { &core } else { rl }) != 0 {
                    fail(9);
                }
            }
            if libc::jail_attach(jid) != 0 {
                fail(4);
            }
            if libc::setgroups(acct.groups.len() as i32, acct.groups.as_ptr()) != 0 || libc::setgid(acct.gid) != 0 {
                fail(5);
            }
            libc::setlogin(acct.name.as_ptr());
            if libc::setuid(uid) != 0 {
                fail(5);
            }
            if libc::chdir(cwd_c.as_ptr()) != 0 {
                fail(6);
            }
            // As execvp: a candidate refused (EACCES) is remembered and the
            // search goes on; any other failure ends it.
            let mut stage = 7;
            let mut denied = 0;
            for (c, sh_args) in candidates.iter().zip(&sh_argvs) {
                libc::execve(c.as_ptr(), arg_ptrs.as_ptr(), env_ptrs.as_ptr());
                match std::io::Error::last_os_error().raw_os_error() {
                    Some(libc::ENOENT | libc::ENOTDIR | libc::ELOOP | libc::ENAMETOOLONG | libc::ETXTBSY) => {}
                    Some(libc::EACCES) => denied = libc::EACCES,
                    // A script with no `#!` line: run by `/bin/sh`, as
                    // execvp does.
                    Some(libc::ENOEXEC) => {
                        libc::execve(c"/bin/sh".as_ptr(), sh_args.as_ptr(), env_ptrs.as_ptr());
                        stage = 8;
                        break;
                    }
                    _ => {
                        stage = 8;
                        break;
                    }
                }
            }
            if stage == 7 && denied != 0 {
                *libc::__error() = denied;
                stage = 8;
            }
            fail(stage);
        }
    }
    // SAFETY: closing our copies of the write end and the passed descriptors.
    unsafe { libc::close(err_pipe[1]) };
    drop(fds);
    if pid < 0 {
        let e = std::io::Error::last_os_error();
        // SAFETY: closing the read end we own.
        unsafe { libc::close(err_pipe[0]) };
        bail!("start the process: {e}");
    }
    // SAFETY: pd is a fresh process descriptor.
    let pd = unsafe { OwnedFd::from_raw_fd(pd) };
    // Every way out before the process is reaped kills its whole group (the
    // descriptor's drop kills only the process).
    let mut group = KillGroup(Some(pid));
    let (master, slave) = match pty {
        Some((m, s)) => (Some(m), Some(s)),
        None => (None, None),
    };
    drop(slave);
    // The start's outcome, watching the caller meanwhile: a child stuck
    // starting (a cwd on a filesystem that stopped answering) ends with the
    // caller — returning drops the process descriptor, which kills it.
    loop {
        let mut pfds = [
            libc::pollfd { fd: err_pipe[0], events: libc::POLLIN, revents: 0 },
            // The caller sends nothing before `Started`: readable here is its
            // end (or a peer breaking the protocol) — either ends the start.
            libc::pollfd { fd: conn.as_raw_fd(), events: libc::POLLIN, revents: 0 },
        ];
        // SAFETY: poll on two descriptors we own.
        if unsafe { libc::poll(pfds.as_mut_ptr(), 2, -1) } < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            let e = std::io::Error::last_os_error();
            // SAFETY: closing the read end we own.
            unsafe { libc::close(err_pipe[0]) };
            bail!("wait for the process to start: {e}");
        }
        if pfds[0].revents != 0 {
            break;
        }
        if pfds[1].revents != 0 {
            // SAFETY: closing our read end; its group killed (the
            // descriptor's drop kills the process itself).
            unsafe {
                libc::close(err_pipe[0]);
                libc::kill(-pid, libc::SIGKILL);
            }
            return Ok(());
        }
    }
    let mut why = [0u8; 3];
    // SAFETY: read from the pipe's read end, which we own.
    let n = unsafe { libc::read(err_pipe[0], why.as_mut_ptr() as *mut _, 3) };
    // SAFETY: closing our read end.
    unsafe { libc::close(err_pipe[0]) };
    if n == 3 {
        let errno = i32::from(why[1]) | (i32::from(why[2]) << 8);
        let e = std::io::Error::from_raw_os_error(errno);
        let message = match why[0] {
            6 => format!("cannot enter {} in the sandbox: {e}", cwd.display()),
            7 => format!("`{program}` is not in the sandbox (not on its PATH, or its folder is not granted)"),
            8 => format!("cannot run `{program}` in the sandbox: {e}"),
            9 => format!("cannot give `{program}` your resource limits in the sandbox: {e}"),
            _ => format!("cannot start `{program}` in the sandbox (step {}): {e}", why[0]),
        };
        let mut status = 0;
        group.0 = None;
        // SAFETY: reap our own child.
        unsafe { libc::waitpid(pid, &mut status, 0) };
        return refuse(message);
    }
    let fds: Vec<RawFd> = master.as_ref().map(|m| vec![m.as_raw_fd()]).unwrap_or_default();
    proto::send(conn, &FromDaemon::Started { pty: master.is_some() }, &fds)?;
    // Kept: a typed signal goes to the jail terminal's foreground group.
    let fg_of = master;
    // A frame begun is read whole within moments, or the caller is taken as
    // gone: a stalled one never keeps the process's end unreported.
    conn.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    loop {
        let mut pfds = [
            libc::pollfd { fd: conn.as_raw_fd(), events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: pd.as_raw_fd(), events: libc::POLLHUP, revents: 0 },
        ];
        // SAFETY: poll on two descriptors we own.
        unsafe { libc::poll(pfds.as_mut_ptr(), 2, 200) };
        let mut status = 0;
        // SAFETY: a non-blocking wait on our own child.
        let got = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if got == pid {
            // Reaped: its id may name another group from here on.
            group.0 = None;
            let (code, signal) = if libc::WIFSIGNALED(status) {
                (None, Some(libc::WTERMSIG(status)))
            } else {
                (Some(libc::WEXITSTATUS(status)), None)
            };
            proto::send(conn, &FromDaemon::Exited { code, signal }, &[])?;
            return Ok(());
        }
        if pfds[0].revents != 0 {
            match proto::recv::<ToDaemon>(conn) {
                Ok(Some((ToDaemon::Signal { signal }, _))) if (1..32).contains(&signal) => {
                    // What is typed (Ctrl-C, Ctrl-\) goes as a terminal sends
                    // it, to the jail terminal's foreground job; anything else
                    // (a hang-up, a kill of the helper) to the process the
                    // helper stands for, and its group (it leads a session).
                    // A terminal with no foreground group answers a pid no
                    // process has: the process's own group then.
                    // SAFETY: tcgetpgrp on a descriptor we hold; a signal to
                    // a group of the jailed session.
                    unsafe {
                        let typed = matches!(signal, libc::SIGINT | libc::SIGQUIT);
                        // (The terminal's group, only while the terminal is
                        // the session's: the kernel keeps its foreground
                        // group inside it.)
                        let fg = match fg_of.as_ref() {
                            Some(m) if typed && libc::tcgetsid(m.as_raw_fd()) == pid => libc::tcgetpgrp(m.as_raw_fd()),
                            _ => -1,
                        };
                        if fg <= 0 || libc::kill(-fg, signal) != 0 {
                            libc::kill(-pid, signal);
                        }
                    }
                }
                Ok(Some(_)) => {}
                // The caller is gone: the process's group is killed (and the
                // descriptor's drop kills the process). A descendant that
                // left the group lives until the run ends.
                _ => {
                    // SAFETY: the group of our own, unreaped child.
                    unsafe { libc::kill(-pid, libc::SIGKILL) };
                    return Ok(());
                }
            }
        }
    }
}

/// Kills process group `0` when dropped, unless cleared (once its leader is
/// reaped, the id may name another group).
struct KillGroup(Option<libc::pid_t>);

impl Drop for KillGroup {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            // SAFETY: the group of our own, unreaped child.
            unsafe { libc::kill(-pid, libc::SIGKILL) };
        }
    }
}

/// A terminal for the jailed process, its slave side the user's, with the
/// window size of the caller's terminal `like`. Through libc's
/// `posix_openpt` (libutil's `openpty` would tie the binary to one FreeBSD
/// release's libutil).
fn open_pty(uid: libc::uid_t, like: RawFd) -> Result<(OwnedFd, OwnedFd)> {
    let fail = |what: &str| anyhow::anyhow!("open a terminal for the sandbox ({what}): {}", std::io::Error::last_os_error());
    // SAFETY: posix_openpt/grantpt/unlockpt/ptsname on the master we open;
    // ptsname's static buffer is copied at once; the window size is read
    // from a descriptor we hold (a failed read leaves the default).
    unsafe {
        let m = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
        if m < 0 {
            return Err(fail("posix_openpt"));
        }
        let m = OwnedFd::from_raw_fd(m);
        if libc::grantpt(m.as_raw_fd()) != 0 || libc::unlockpt(m.as_raw_fd()) != 0 {
            return Err(fail("unlockpt"));
        }
        let name = libc::ptsname(m.as_raw_fd());
        if name.is_null() {
            return Err(fail("ptsname"));
        }
        let name = std::ffi::CStr::from_ptr(name).to_owned();
        let s = libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
        if s < 0 {
            return Err(fail("open the slave"));
        }
        let s = OwnedFd::from_raw_fd(s);
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(like, libc::TIOCGWINSZ, &mut ws) == 0 {
            libc::ioctl(m.as_raw_fd(), libc::TIOCSWINSZ, &ws);
        }
        if libc::fchown(s.as_raw_fd(), uid, u32::MAX) != 0 || libc::fchmod(s.as_raw_fd(), 0o620) != 0 {
            return Err(fail("give it to you"));
        }
        Ok((m, s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cap_admits_up_to_one_below_it() {
        assert!(!at_cap(MAX_RUNS - 1, MAX_RUNS));
        assert!(at_cap(MAX_RUNS, MAX_RUNS));
        assert!(!at_cap(MAX_CONNECTIONS - 1, MAX_CONNECTIONS));
        assert!(at_cap(MAX_CONNECTIONS, MAX_CONNECTIONS));
    }
}

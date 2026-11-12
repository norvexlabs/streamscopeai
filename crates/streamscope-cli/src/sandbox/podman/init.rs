//! `ssai __sandbox-init` — PID 1 of a docker-tier container. Plain std, no
//! async runtime: a runtime's own child reaper would race the `waitpid(-1)`
//! a PID 1 must run.
//!
//! In order: take every signal it handles (blocked, then read in one loop —
//! PID 1 has no default action for a signal it does not handle); start the
//! relay (`127.0.0.1:<port>` → the guard's socket — the container's only
//! way out); with an engine inside, give it its own cgroup and start
//! `dockerd`; run the project's lifecycle commands as the image's user (the
//! create ones only when this home has not run them on this image); start
//! the agent as that user; then reap every child
//! until the agent exits, and exit with its status, written to the exit file
//! first (podman's own failures share exit codes 125–127 with the agent's).
//!
//! Init stays the container's root — the engine and the cgroup tree need it;
//! only the agent drops to its user. Signals: SIGTERM and SIGHUP are passed
//! to the agent (podman's conmon holds the terminal, which never hangs up on
//! its own). On a terminal, Ctrl-C and SIGWINCH reach the agent from the
//! terminal itself (passing them on would deliver them twice); without one,
//! podman hands SIGINT to init, which passes it on.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use super::config::Step;

/// What init starts, written by the launcher to the run dir.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Start {
    /// The agent's argv; `argv[0]` is looked up on the agent's `PATH`.
    pub argv: Vec<String>,
    /// Laid over the image's environment (init's own), last entry winning.
    pub env: Vec<(String, String)>,
    /// Where the project is mounted: where the lifecycle commands run.
    pub workspace: String,
    /// Run before the agent when the home has no marker for `create_key`,
    /// which they write once they all succeed.
    pub create_steps: Vec<Step>,
    /// Run before the agent on every run, after the create ones.
    pub start_steps: Vec<Step>,
    /// What the create commands are run for: the base image and the commands.
    pub create_key: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    /// Directories under `home` that the runtime created to mount a file
    /// into (as root, inside the home volume): the agent's own, like the
    /// home's top, or the client cannot write beside its config.
    pub home_dirs: Vec<String>,
    pub cwd: String,
    /// The guard's socket, and the loopback port the relay listens on.
    pub guard_socket: String,
    pub relay_port: u16,
    /// Start an engine (`dockerd`) inside.
    pub engine: bool,
    /// Where the agent's exit status is written.
    pub exit_file: String,
    /// A terminal is attached.
    pub tty: bool,
}

/// How long the engine may take to answer on its socket.
const ENGINE_READY: std::time::Duration = std::time::Duration::from_secs(30);
const ENGINE_SOCKET: &str = "/var/run/docker.sock";
const ENGINE_LOG: &str = "/tmp/ssai-dockerd.log";
/// How long the engine has to stop its containers before it is killed: its
/// cache (`/var/lib/docker`) is a volume the next run starts from.
const ENGINE_STOP: std::time::Duration = std::time::Duration::from_secs(20);

/// Run init with the start file at `path`. Returns only on failure; on
/// success the process exits with the agent's status.
pub fn main(path: &Path) -> Result<()> {
    if std::process::id() != 1 {
        bail!("__sandbox-init runs only as a container's init");
    }
    let start: Start = serde_json::from_str(&std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?)
        .context("read the start file")?;
    let signals = SignalSet::take(start.tty)?;
    relay(start.relay_port, start.guard_socket.clone())?;
    let mut engine = if start.engine { Some(start_engine(&start)?) } else { None };
    // An engine that started is stopped on every way out: its cache is a
    // volume the next run starts from.
    let agent = match prepare_home(&start)
        .and_then(|()| {
            if Path::new(&start.cwd).is_dir() { Ok(()) } else { bail!("the working directory {} is not in the sandbox", start.cwd) }
        })
        .and_then(|()| lifecycle(&start, &signals, &mut engine))
        .and_then(|()| {
            if signals.stop_pending(&mut engine) { bail!("the run was stopped before the agent started") } else { Ok(()) }
        })
        .and_then(|()| spawn_agent(&start))
    {
        Ok(agent) => agent,
        Err(e) => {
            if let Some(engine) = engine {
                stop(engine);
            }
            return Err(e);
        }
    };
    let code = signals.wait_for(agent, &mut engine);
    if let Some(engine) = engine {
        stop(engine);
    }
    // The exit file is what tells the agent's status from podman's own.
    write_exit(&start.exit_file, code);
    std::process::exit(code);
}

/// Write the exit code to `path`, a file in a directory the agent can write:
/// never through a symlink it put there, never blocking on a FIFO (an open
/// with no reader fails at once), only into a regular file.
fn write_exit(path: &str, code: i32) {
    use std::os::unix::fs::OpenOptionsExt;
    let Ok(mut f) = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    else {
        return;
    };
    if f.metadata().is_ok_and(|m| m.is_file()) {
        let _ = f.write_all(code.to_string().as_bytes());
    }
}

/// The signals init handles, blocked in every thread it starts.
struct SignalSet {
    set: libc::sigset_t,
    tty: bool,
    /// A stop (SIGTERM, SIGHUP, SIGINT) arrived: no lifecycle command after
    /// it, nor the agent, is started.
    stopping: std::cell::Cell<bool>,
}

impl SignalSet {
    fn take(tty: bool) -> Result<Self> {
        // SAFETY: plain sigset manipulation on a local; the mask is set before
        // any thread starts, so every thread inherits it.
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            for sig in [libc::SIGCHLD, libc::SIGTERM, libc::SIGHUP, libc::SIGINT] {
                libc::sigaddset(&mut set, sig);
            }
            if libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) != 0 {
                bail!("block init's signals");
            }
            Ok(Self { set, tty, stopping: std::cell::Cell::new(false) })
        }
    }

    /// Whether a stop arrived and waits, unread: one that came while no
    /// command ran (the engine starting, between two commands) would
    /// otherwise reach only the next one, after it started. An exited
    /// child read here is reaped.
    fn stop_pending(&self, engine: &mut Option<libc::pid_t>) -> bool {
        let none = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        loop {
            // SAFETY: sigtimedwait on the blocked set, a zero timeout.
            match unsafe { libc::sigtimedwait(&self.set, std::ptr::null_mut(), &none) } {
                libc::SIGCHLD => {
                    let _ = reap(0, engine);
                }
                sig if sig > 0 => self.stopping.set(true),
                _ => return self.stopping.get(),
            }
        }
    }

    /// Reap children and pass signals on until `agent` exits; its status as
    /// an exit code (a signal `n` = `128 + n`). `engine` is cleared when the
    /// engine is reaped first.
    fn wait_for(&self, agent: libc::pid_t, engine: &mut Option<libc::pid_t>) -> i32 {
        loop {
            let mut sig: libc::c_int = 0;
            // SAFETY: sigwait on a set of blocked signals.
            if unsafe { libc::sigwait(&self.set, &mut sig) } != 0 {
                continue;
            }
            if sig != libc::SIGCHLD {
                self.stopping.set(true);
            }
            match sig {
                libc::SIGCHLD => {
                    if let Some(code) = reap(agent, engine) {
                        return code;
                    }
                }
                // On a terminal Ctrl-C reaches the agent's foreground group
                // from the terminal itself: a second copy would read as
                // "quit now". A hang-up does not (conmon keeps the terminal
                // open), so SIGHUP is always passed on.
                libc::SIGINT if self.tty => {}
                // SAFETY: kill(2) on the agent, our child.
                other => unsafe {
                    libc::kill(agent, other);
                },
            }
        }
    }
}

/// Reap every exited child; the agent's exit code once it is among them. The
/// engine exiting before the agent is said, and `engine` cleared.
fn reap(agent: libc::pid_t, engine: &mut Option<libc::pid_t>) -> Option<i32> {
    let mut found = None;
    loop {
        let mut status = 0;
        // SAFETY: waitpid on any child, non-blocking.
        let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if pid <= 0 {
            return found;
        }
        if Some(pid) == *engine {
            *engine = None;
            eprintln!("ssai: the sandbox's docker engine stopped (status {status}) — its log is {ENGINE_LOG} in the container");
        }
        if pid == agent {
            found = Some(if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else if libc::WIFSIGNALED(status) {
                128 + libc::WTERMSIG(status)
            } else {
                1
            });
        }
    }
}

/// Listen on `127.0.0.1:<port>` and pass every connection to the guard's
/// socket, one thread pair per connection. It lives in init, so it lives as
/// long as the container.
fn relay(port: u16, socket: String) -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port)).with_context(|| format!("listen on 127.0.0.1:{port}"))?;
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            // A failed accept (out of fds, say) backs off instead of
            // spinning PID 1; a connection ending frees what it held.
            let Ok(conn) = conn else {
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            };
            let socket = socket.clone();
            // Out of threads (the pids limit): this connection is dropped,
            // the relay lives on.
            let _ = std::thread::Builder::new().spawn(move || {
                if let Ok(up) = UnixStream::connect(&socket) {
                    pipe(conn, up);
                }
            });
        }
    });
    Ok(())
}

/// Copy both ways. The client closing its side passes on to the guard; the
/// guard closing ends the connection both ways, so an idle client that never
/// closes does not hold the upload thread.
fn pipe(tcp: TcpStream, unix: UnixStream) {
    let (Ok(mut tcp_r), Ok(mut unix_r)) = (tcp.try_clone(), unix.try_clone()) else { return };
    let (mut tcp_w, mut unix_w) = (tcp, unix);
    let Ok(up) = std::thread::Builder::new().spawn(move || {
        let _ = copy(&mut tcp_r, &mut unix_w);
        let _ = unix_w.shutdown(std::net::Shutdown::Write);
    }) else {
        return;
    };
    let _ = copy(&mut unix_r, &mut tcp_w);
    let _ = tcp_w.shutdown(std::net::Shutdown::Both);
    let _ = up.join();
}

fn copy(from: &mut impl Read, to: &mut impl Write) -> std::io::Result<()> {
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = from.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        to.write_all(&buf[..n])?;
    }
}

/// Start `dockerd` in its own cgroup and its own process group (a Ctrl-C at
/// the agent's terminal, sent to the foreground group, must not stop it),
/// reaching registries through the relay, its socket the agent group's; wait
/// until it answers.
fn start_engine(start: &Start) -> Result<libc::pid_t> {
    delegate_cgroups();
    let proxy = format!("http://127.0.0.1:{}", start.relay_port);
    let log = std::fs::File::create(ENGINE_LOG).context("create the engine log")?;
    let child = std::process::Command::new("dockerd")
        .process_group(0)
        .arg(format!("--group={}", start.gid))
        .env("HTTP_PROXY", &proxy)
        .env("HTTPS_PROXY", &proxy)
        .env("NO_PROXY", "localhost,127.0.0.1,::1")
        .stdin(std::process::Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .spawn()
        .context("start dockerd — `\"docker\": true` needs an image with Docker Engine installed")?;
    let pid = child.id() as libc::pid_t;
    let deadline = std::time::Instant::now() + ENGINE_READY;
    while UnixStream::connect(ENGINE_SOCKET).is_err() {
        let mut status = 0;
        // SAFETY: a non-blocking wait on our own child.
        if unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } == pid {
            bail!("dockerd stopped as it started (status {status}) — its log is {ENGINE_LOG} in the container");
        }
        if std::time::Instant::now() >= deadline {
            stop(pid);
            bail!("dockerd did not answer within {}s (its log: {ENGINE_LOG})", ENGINE_READY.as_secs());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Ok(pid)
}

/// Move init into a child cgroup and enable every controller for the tree
/// below it — a cgroup with processes cannot delegate (cgroup v2's no
/// internal processes rule), and an inner engine's containers need the
/// controllers. Best effort: without it the engine runs with fewer limits.
fn delegate_cgroups() {
    let root = Path::new("/sys/fs/cgroup");
    let init = root.join("init");
    if std::fs::create_dir_all(&init).is_err() || std::fs::write(init.join("cgroup.procs"), "0").is_err() {
        return;
    }
    let Ok(controllers) = std::fs::read_to_string(root.join("cgroup.controllers")) else { return };
    let enable: Vec<String> = controllers.split_whitespace().map(|c| format!("+{c}")).collect();
    let _ = std::fs::write(root.join("cgroup.subtree_control"), enable.join(" "));
}

/// SIGTERM, then SIGKILL after a grace period; reaped by the signal loop or
/// by the namespace's end.
fn stop(pid: libc::pid_t) {
    // SAFETY: kill(2) on our own child.
    unsafe { libc::kill(pid, libc::SIGTERM) };
    let deadline = std::time::Instant::now() + ENGINE_STOP;
    while std::time::Instant::now() < deadline {
        let mut status = 0;
        // SAFETY: non-blocking wait on our own child.
        // Reaped now (`pid`), or not ours to wait on any more (-1: ECHILD);
        // 0 is still running.
        if unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } != 0 {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    // SAFETY: as above.
    unsafe { libc::kill(pid, libc::SIGKILL) };
}

/// The groups of the user `uid` (primary `gid` first) from an image's
/// `/etc/passwd` and `/etc/group`: the primary, then every group naming the
/// user as a member. A uid the passwd does not list has its primary only.
fn groups_of(passwd: &str, group: &str, uid: u32, gid: u32) -> Vec<libc::gid_t> {
    let mut out = vec![gid];
    let name = passwd.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() >= 3 && f[2].parse() == Ok(uid)).then(|| f[0].to_string())
    });
    let Some(name) = name else { return out };
    for l in group.lines() {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() >= 4
            && let Ok(g) = f[2].parse::<u32>()
            && f[3].split(',').any(|m| m.trim() == name)
            && !out.contains(&g)
        {
            out.push(g);
        }
    }
    out
}

/// Every directory from `home` down to `dir` is a real one, none a symlink:
/// one the agent left in its home volume on an earlier run would lead init's
/// chown elsewhere.
fn real_dirs_down(home: &str, dir: &str) -> bool {
    let Ok(rel) = Path::new(dir).strip_prefix(home) else { return false };
    let mut at = PathBuf::from(home);
    let real = |p: &Path| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir());
    real(&at)
        && rel.components().all(|c| {
            at.push(c);
            matches!(c, std::path::Component::Normal(_)) && real(&at)
        })
}

/// The agent's home, and the directories the runtime created in it, the
/// agent's own.
fn prepare_home(start: &Start) -> Result<()> {
    // A home volume the image had no directory for starts as root's: the
    // agent's own from here (its top only — what the image put below is the
    // image's).
    std::fs::create_dir_all(&start.home).with_context(|| format!("create {}", start.home))?;
    for dir in std::iter::once(&start.home).chain(&start.home_dirs) {
        if !real_dirs_down(&start.home, dir) {
            continue;
        }
        if let Ok(m) = std::fs::symlink_metadata(dir)
            && m.is_dir()
            && std::os::unix::fs::MetadataExt::uid(&m) != start.uid
        {
            std::os::unix::fs::lchown(dir, Some(start.uid), Some(start.gid))
                .with_context(|| format!("give {dir} to the agent user"))?;
        }
    }
    Ok(())
}

/// The marker a home holds once the create commands ran for `key`.
fn create_marker(home: &str, key: &str) -> (String, String) {
    let dir = format!("{}/.ssai", home.trim_end_matches('/'));
    let file = format!("{dir}/create-{key}");
    (dir, file)
}

/// Run the lifecycle commands, one after another, as the agent in the
/// workspace, each to its end. The create commands run when the home has no
/// marker for `create_key`, written once they all succeeded, under a lock on
/// the workspace (two runs on one project would otherwise install into it at
/// once); the start commands after them, unlocked, so one that never ends
/// holds only its own run. A command that fails stops the run before the
/// agent starts.
fn lifecycle(start: &Start, signals: &SignalSet, engine: &mut Option<libc::pid_t>) -> Result<()> {
    let (dir, marker) = create_marker(&start.home, &start.create_key);
    let created = || std::fs::symlink_metadata(&marker).is_ok();
    if !start.create_steps.is_empty() && !created() {
        let lock = std::fs::File::open(&start.workspace).with_context(|| format!("open {}", start.workspace))?;
        lock_workspace(&lock, signals, engine)?;
        // Another run on this home may have run them while this one waited.
        if !created() {
            for step in &start.create_steps {
                run_step(start, step, signals, engine)?;
            }
            // Unrecorded, they run again next time: a home the agent broke
            // (`~/.ssai` made a file) costs time, never the run.
            if let Err(e) = write_marker(start, &dir, &marker) {
                eprintln!("ssai: could not record that the create commands ran ({e:#}) — they run again next time");
            }
        }
    }
    for step in &start.start_steps {
        run_step(start, step, signals, engine)?;
    }
    Ok(())
}

/// Take `lock` (the workspace) exclusively, waiting for another run's create
/// commands; SIGTERM, SIGHUP or SIGINT (Ctrl-C) while waiting stops the run.
fn lock_workspace(lock: &std::fs::File, signals: &SignalSet, engine: &mut Option<libc::pid_t>) -> Result<()> {
    let fd = std::os::fd::AsRawFd::as_raw_fd(lock);
    let mut said = false;
    loop {
        // SAFETY: flock(2) on a descriptor we own.
        if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        // A filesystem without flock (some NFS and FUSE mounts): unlocked.
        if err.raw_os_error() != Some(libc::EWOULDBLOCK) {
            eprintln!("ssai: the project's folder cannot be locked ({err}) — its create commands run unlocked");
            return Ok(());
        }
        if !said {
            eprintln!("ssai: waiting for another sandbox run's create commands on this project");
            said = true;
        }
        let wait = libc::timespec { tv_sec: 0, tv_nsec: 200_000_000 };
        // SAFETY: sigtimedwait on the blocked set, a local timeout.
        match unsafe { libc::sigtimedwait(&signals.set, std::ptr::null_mut(), &wait) } {
            libc::SIGCHLD => {
                let _ = reap(0, engine);
            }
            libc::SIGTERM | libc::SIGHUP | libc::SIGINT => bail!("stopped while waiting for the workspace"),
            _ => {}
        }
    }
}

/// One lifecycle command, as the agent in the workspace, waited on through
/// the signal loop (a signal reaches it as it would the agent).
fn run_step(start: &Start, step: &Step, signals: &SignalSet, engine: &mut Option<libc::pid_t>) -> Result<()> {
    if signals.stop_pending(engine) {
        bail!("the run was stopped before the devcontainer's `{}` — the agent was not started", step.hook);
    }
    eprintln!("ssai: running {} in the sandbox", step.hook);
    let mut cmd = agent_command(start, &step.argv, &start.workspace)?;
    cmd.stdin(std::process::Stdio::null());
    let child = cmd.spawn().map_err(|e| spawn_error(e, &step.argv[0], &start.workspace))?;
    let code = signals.wait_for(child.id() as libc::pid_t, engine);
    // A stop passed on to the command is the run's too, whatever it exited with.
    if signals.stopping.get() {
        bail!("the run was stopped during the devcontainer's `{}` — the agent was not started", step.hook);
    }
    if code != 0 {
        bail!("the devcontainer's `{}` failed (exit {code}) — the agent was not started", step.hook);
    }
    Ok(())
}

/// The marker, created as the agent's: never through a symlink the agent
/// left in its home (a process a lifecycle command left running may still
/// change it), so the directory is held open, refusing a symlink, and the
/// file created in it.
fn write_marker(start: &Start, dir: &str, marker: &str) -> Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::OpenOptionsExt;
    match std::fs::create_dir(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let held = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)
        .with_context(|| format!("{dir} is not a directory"))?;
    std::os::unix::fs::fchown(&held, Some(start.uid), Some(start.gid))?;
    let name = Path::new(marker).file_name().context("the marker has no name")?;
    let name = std::ffi::CString::new(name.as_encoded_bytes()).context("the marker's name holds a NUL")?;
    // SAFETY: openat(2) on a directory we hold, a valid C name.
    let fd = unsafe {
        libc::openat(held.as_raw_fd(), name.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o644)
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("create the marker");
    }
    // SAFETY: a descriptor openat just returned, owned from here.
    let file = unsafe { OwnedFd::from_raw_fd(fd) };
    std::os::unix::fs::fchown(&file, Some(start.uid), Some(start.gid))?;
    Ok(())
}

fn spawn_error(e: std::io::Error, program: &str, cwd: &str) -> anyhow::Error {
    match e.kind() {
        std::io::ErrorKind::NotFound => anyhow::anyhow!(
            "`{program}`, or the interpreter its first line names, is not in the sandbox's image — add it to the \
             image (its Dockerfile or devcontainer.json)"
        ),
        std::io::ErrorKind::PermissionDenied => anyhow::anyhow!(
            "the agent user cannot enter {cwd} or run `{program}` — check their owner and mode in the project"
        ),
        _ => anyhow::Error::new(e).context(format!("start {program} in the sandbox")),
    }
}

/// Start the agent as `uid:gid`, with the groups its image gives it, in
/// `cwd` (entered as the agent, so one it cannot enter fails here), with the
/// image's environment overlaid by the start file's.
fn spawn_agent(start: &Start) -> Result<libc::pid_t> {
    let mut cmd = agent_command(start, &start.argv, &start.cwd)?;
    let child = cmd.spawn().map_err(|e| spawn_error(e, &start.argv[0], &start.cwd))?;
    Ok(child.id() as libc::pid_t)
}

/// `argv` as the agent user, in `cwd`, with the agent's environment.
fn agent_command(start: &Start, argv: &[String], cwd: &str) -> Result<std::process::Command> {
    let Some((program, args)) = argv.split_first() else { bail!("the start file names an empty command") };
    let mut cmd = std::process::Command::new(program);
    cmd.args(args).env("HOME", &start.home);
    for (k, v) in &start.env {
        cmd.env(k, v);
    }
    // Where it starts, as a shell would say it.
    cmd.env("PWD", cwd);
    let cwd = std::ffi::CString::new(cwd.as_bytes()).context("the working directory holds a NUL")?;
    let (uid, gid) = (start.uid, start.gid);
    // The agent user's groups as the image lists them, read before the fork.
    let read = |f: &str| std::fs::read_to_string(f).unwrap_or_default();
    let groups = groups_of(&read("/etc/passwd"), &read("/etc/group"), uid, gid);
    // SAFETY: only async-signal-safe syscalls between fork and exec, on data
    // prepared before it. The ids are dropped here, after std's own setup.
    unsafe {
        cmd.pre_exec(move || {
            if libc::setgroups(groups.len(), groups.as_ptr()) != 0
                || libc::setgid(gid) != 0
                || libc::setuid(uid) != 0
                || libc::chdir(cwd.as_ptr()) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(cmd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_start_file_round_trips() {
        let s = Start {
            argv: vec!["claude".into()],
            env: vec![("HTTPS_PROXY".into(), "http://127.0.0.1:3128".into())],
            workspace: "/workspaces/app".into(),
            create_steps: vec![Step { hook: "postCreateCommand".into(), argv: vec!["/bin/sh".into(), "-c".into(), "npm ci".into()] }],
            start_steps: vec![],
            create_key: "0123456789ab".into(),
            uid: 1000,
            gid: 1000,
            home: "/home/vscode".into(),
            home_dirs: vec!["/home/vscode/.codex".into()],
            cwd: "/workspaces/app".into(),
            guard_socket: "/run/ssai-sock/guard.sock".into(),
            relay_port: 3128,
            engine: false,
            exit_file: "/run/ssai-sock/exit".into(),
            tty: true,
        };
        let back: Start = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn init_refuses_to_run_outside_a_container() {
        // The test process is never PID 1.
        assert!(main(Path::new("/nonexistent")).is_err());
    }

    #[test]
    fn the_relay_carries_both_ways_to_the_socket() {
        let dir = std::env::temp_dir().join(format!("ssai-relay-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("g.sock");
        let echo = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        std::thread::spawn(move || {
            for mut c in echo.incoming().flatten() {
                let mut buf = [0u8; 5];
                c.read_exact(&mut buf).unwrap();
                c.write_all(&buf).unwrap();
            }
        });
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        relay(port, sock.to_string_lossy().into_owned()).unwrap();
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.write_all(b"hello").unwrap();
        let mut back = [0u8; 5];
        c.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"hello");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_guard_closing_ends_the_pipe_while_the_client_stays_open() {
        let (guard_end, relay_end) = UnixStream::pair().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            pipe(accepted, relay_end);
            let _ = done_tx.send(());
        });
        drop(guard_end);
        // The client never closes; the pipe returns anyway.
        assert!(done_rx.recv_timeout(std::time::Duration::from_secs(5)).is_ok(), "the pipe held on an open client");
        drop(client);
    }


    #[test]
    fn the_exit_code_is_written_only_into_a_regular_file() {
        let dir = std::env::temp_dir().join(format!("ssai-write-exit-{}-{}", std::process::id(), rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("exit");
        std::fs::write(&f, "").unwrap();
        write_exit(&f.to_string_lossy(), 7);
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "7");
        // Through a symlink: the target is untouched.
        let target = dir.join("target");
        std::fs::write(&target, "kept").unwrap();
        std::os::unix::fs::symlink(&target, dir.join("link")).unwrap();
        write_exit(&dir.join("link").to_string_lossy(), 3);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "kept");
        // A FIFO with no reader: returns at once instead of blocking.
        let fifo = std::ffi::CString::new(dir.join("fifo").to_string_lossy().as_bytes()).unwrap();
        // SAFETY: a valid C path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        write_exit(&dir.join("fifo").to_string_lossy(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }


    #[test]
    fn the_create_marker_is_never_written_through_a_symlink_nor_over_a_file() {
        let home = std::env::temp_dir().join(format!("ssai-marker-{}-{}", std::process::id(), rand::random::<u32>()));
        let elsewhere = home.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        let h = home.to_string_lossy().into_owned();
        // SAFETY: getuid/getgid cannot fail; the test chowns to its own ids.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let start = Start {
            argv: vec!["a".into()],
            env: vec![],
            workspace: h.clone(),
            create_steps: vec![],
            start_steps: vec![],
            create_key: "k".into(),
            uid,
            gid,
            home: h.clone(),
            home_dirs: vec![],
            cwd: h.clone(),
            guard_socket: String::new(),
            relay_port: 0,
            engine: false,
            exit_file: String::new(),
            tty: false,
        };
        let (dir, marker) = create_marker(&h, "k");
        // `~/.ssai` a symlink the agent left: refused, its target untouched.
        std::os::unix::fs::symlink(&elsewhere, &dir).unwrap();
        assert!(write_marker(&start, &dir, &marker).is_err());
        assert!(std::fs::read_dir(&elsewhere).unwrap().next().is_none(), "nothing written through the symlink");
        // A real directory: the marker is made (the positive control), and never made twice.
        std::fs::remove_file(&dir).unwrap();
        write_marker(&start, &dir, &marker).unwrap();
        assert!(std::fs::symlink_metadata(&marker).unwrap().is_file());
        assert!(write_marker(&start, &dir, &marker).is_err(), "an existing marker is not opened again");
        // The marker itself a symlink: not followed.
        std::fs::remove_file(&marker).unwrap();
        std::os::unix::fs::symlink(elsewhere.join("planted"), &marker).unwrap();
        assert!(write_marker(&start, &dir, &marker).is_err());
        assert!(!elsewhere.join("planted").exists());
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_home_dir_under_a_symlink_is_not_given_to_the_agent() {
        let home = std::env::temp_dir().join(format!("ssai-home-dirs-{}-{}", std::process::id(), rand::random::<u32>()));
        std::fs::create_dir_all(home.join(".config/goose")).unwrap();
        std::fs::create_dir_all(home.join("elsewhere/goose")).unwrap();
        std::os::unix::fs::symlink(home.join("elsewhere"), home.join(".cfg")).unwrap();
        let h = home.to_string_lossy().into_owned();
        assert!(real_dirs_down(&h, &format!("{h}/.config/goose")));
        assert!(real_dirs_down(&h, &h), "the home itself");
        assert!(!real_dirs_down(&h, &format!("{h}/.cfg/goose")), "through a symlinked parent");
        assert!(!real_dirs_down(&h, &format!("{h}/.config/missing")));
        assert!(!real_dirs_down(&h, "/etc"), "outside the home");
        let _ = std::fs::remove_dir_all(&home);
    }


    #[test]
    fn the_agent_keeps_the_groups_its_image_gives_it() {
        let passwd = "root:x:0:0::/root:/bin/sh\nvscode:x:1000:1000::/home/vscode:/bin/bash\n";
        let group = "root:x:0:\nwheel:x:10:alice,vscode\nsudo:x:27:vscode\nvscode:x:1000:\ndocker:x:999:alice\n";
        assert_eq!(groups_of(passwd, group, 1000, 1000), [1000, 10, 27]);
        // Its primary named as a member too: listed once.
        assert_eq!(groups_of(passwd, "vscode:x:1000:vscode\n", 1000, 1000), [1000]);
        // A uid the image does not list: the primary alone.
        assert_eq!(groups_of(passwd, group, 4242, 4242), [4242]);
        assert_eq!(groups_of("", "", 1000, 1000), [1000]);
    }
}

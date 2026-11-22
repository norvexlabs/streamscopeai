//! `ssai __jail-exec <run> -- <command> <args>`: one process of a run, started
//! in the run's jail by the daemon. Outside the jail, as the developer, this
//! helper stands in for the process so the launch code treats it like any
//! child: it passes its stdin, stdout and stderr (the daemon gives the jailed
//! process its own terminal for each that is one, and this helper relays
//! between that terminal and the developer's, in raw mode, the window size
//! following), and passes SIGINT, SIGTERM, SIGHUP and SIGQUIT on; the daemon gives the
//! process this helper's own umask and resource limits, read from the
//! kernel. It ends with the process's exit code — or by the signal that
//! ended it. Its own death ends the process: the daemon kills it when this
//! connection closes. Ctrl-Z does not suspend the process: the jailed
//! session's process group has no parent in its session, so the kernel
//! discards the terminal's stop signals.

use std::io::Read as _;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

use anyhow::{bail, Context, Result};

use super::proto::{self, FromDaemon, ToDaemon};
use super::request::PROTOCOL;

/// The signals the helper takes: passed on, or acted on.
const PASSED: [libc::c_int; 4] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];

/// Connect to the daemon and check it speaks our protocol.
pub fn connect() -> Result<UnixStream> {
    match connect_or_refused()? {
        Ok(conn) => Ok(conn),
        Err(message) => bail!("the sandbox refused: {message}"),
    }
}

/// [`connect`], a refusal in place of the Hello (a cap) apart: its message.
fn connect_or_refused() -> Result<std::result::Result<UnixStream, String>> {
    let conn = UnixStream::connect(super::daemon::SOCKET).with_context(|| {
        format!(
            "reach the sandbox daemon ({}) — set it up once with `sudo ssai sandbox setup`",
            super::daemon::SOCKET
        )
    })?;
    // A daemon that answers nothing (stopped, its socket left) fails here
    // instead of holding the caller.
    conn.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    let hello = proto::recv::<FromDaemon>(&conn).context("the sandbox daemon did not answer")?;
    conn.set_read_timeout(None)?;
    match hello {
        Some((FromDaemon::Hello { protocol }, _)) if protocol == PROTOCOL => Ok(Ok(conn)),
        Some((FromDaemon::Refused { message }, _)) => Ok(Err(message)),
        Some((FromDaemon::Hello { protocol }, _)) => bail!(
            "the installed sandbox daemon speaks protocol {protocol}, this ssai {PROTOCOL} — run `sudo ssai sandbox setup` to update it"
        ),
        _ => bail!("the sandbox daemon did not answer"),
    }
}

/// Whether this process may take terminal `fd`: in its foreground group, or
/// a terminal not its controlling one (no job control applies to it).
fn foreground(fd: RawFd) -> bool {
    // SAFETY: tcgetpgrp/getpgrp only read.
    unsafe {
        let pg = libc::tcgetpgrp(fd);
        pg == -1 || pg == libc::getpgrp()
    }
}

/// Saved terminal settings, put back when dropped.
struct Raw {
    fd: RawFd,
    saved: libc::termios,
}

impl Raw {
    fn enter(fd: RawFd) -> Option<Self> {
        // SAFETY: tcgetattr/tcsetattr on a terminal descriptor.
        unsafe {
            let mut saved: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut saved) != 0 {
                return None;
            }
            let mut raw = saved;
            libc::cfmakeraw(&mut raw);
            // TCSANOW: what was typed before the run started is kept.
            libc::tcsetattr(fd, libc::TCSANOW, &raw);
            Some(Self { fd, saved })
        }
    }
    fn restore(&self) {
        // SAFETY: as above. TCSANOW: what is typed meanwhile is kept.
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved) };
    }
}

impl Drop for Raw {
    fn drop(&mut self) {
        self.restore();
    }
}

fn is_tty(fd: RawFd) -> bool {
    // SAFETY: isatty only inspects the descriptor.
    unsafe { libc::isatty(fd) == 1 }
}

fn copy_winsize(from: RawFd, to: RawFd) {
    // SAFETY: window-size ioctls on descriptors we hold.
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(from, libc::TIOCGWINSZ, &mut ws) == 0 {
            libc::ioctl(to, libc::TIOCSWINSZ, &ws);
        }
    }
}

fn write_all(fd: RawFd, mut buf: &[u8]) {
    while !buf.is_empty() {
        // SAFETY: write from a buffer we own.
        let n = unsafe { libc::write(fd, buf.as_ptr() as *const _, buf.len()) };
        if n <= 0 {
            match std::io::Error::last_os_error().kind() {
                _ if n == 0 => return,
                std::io::ErrorKind::Interrupted => continue,
                // A terminal another program left non-blocking: wait until
                // it takes more.
                std::io::ErrorKind::WouldBlock => {
                    let mut p = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
                    // SAFETY: poll on a descriptor we hold.
                    unsafe { libc::poll(&mut p, 1, 1000) };
                    continue;
                }
                _ => return,
            }
        }
        buf = &buf[n as usize..];
    }
}

/// A self-pipe per signal: readable when the signal arrived.
struct Signals(Vec<(libc::c_int, UnixStream)>);

impl Signals {
    fn take(sigs: &[libc::c_int]) -> Result<Self> {
        let mut out = Vec::new();
        for &sig in sigs {
            let (r, w) = UnixStream::pair()?;
            r.set_nonblocking(true)?;
            signal_hook::low_level::pipe::register(sig, w).context("take a signal")?;
            out.push((sig, r));
        }
        Ok(Self(out))
    }
    fn drain(&self, fd: RawFd) -> Option<libc::c_int> {
        let (sig, s) = self.0.iter().find(|(_, s)| s.as_raw_fd() == fd)?;
        let mut buf = [0u8; 64];
        while matches!((&*s).read(&mut buf), Ok(n) if n > 0) {}
        Some(*sig)
    }
}

/// Whether descriptor `fd` was opened for writing.
fn writable(fd: RawFd) -> bool {
    // SAFETY: F_GETFL only reads the descriptor's flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    flags >= 0 && flags & libc::O_ACCMODE != libc::O_RDONLY
}

/// Whether `sig` reached this process ignored.
fn ignored(sig: libc::c_int) -> bool {
    // SAFETY: a null new action only reads the current disposition.
    unsafe {
        let mut old: libc::sigaction = std::mem::zeroed();
        libc::sigaction(sig, std::ptr::null(), &mut old) == 0 && old.sa_sigaction == libc::SIG_IGN
    }
}

/// Run the helper; it never returns on success (it exits as the process did).
pub fn main(run: &str, argv: &[String]) -> Result<()> {
    if argv.is_empty() {
        bail!("__jail-exec: no command given");
    }
    // No core of this helper, ever: it holds the client's whole environment,
    // the gateway key among it. Its own limit before that is the process's.
    // SAFETY: getrlimit/setrlimit on this process with structs we own.
    // Only the soft limit: the hard one stays what the kernel bounds the
    // process's by.
    let core = unsafe {
        let mut was: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_CORE, &mut was) != 0 {
            // Unread: the hard limit left as it is.
            was = libc::rlimit { rlim_cur: libc::RLIM_INFINITY, rlim_max: libc::RLIM_INFINITY };
        }
        let none = libc::rlimit { rlim_cur: 0, rlim_max: was.rlim_max };
        libc::setrlimit(libc::RLIMIT_CORE, &none);
        (was.rlim_cur as u64, was.rlim_max as u64)
    };
    // A standard descriptor closed by whoever started us is `/dev/null` to
    // the process, as the shell gives it (passing a closed one would fail) —
    // before the daemon's socket is opened, which would take its number.
    for fd in 0..3 {
        // SAFETY: F_GETFD only asks whether `fd` is open; the /dev/null we
        // open takes the lowest free number, `fd` itself when it was closed.
        unsafe {
            if libc::fcntl(fd, libc::F_GETFD) < 0 {
                let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
                if null >= 0 && null != fd {
                    libc::dup2(null, fd);
                    libc::close(null);
                }
            }
        }
    }
    // A refusal ends the helper as every refusal does: 127, its reason said.
    let conn = match connect_or_refused()? {
        Ok(conn) => conn,
        Err(message) => {
            eprintln!("ssai: {message}");
            std::process::exit(127);
        }
    };
    let cwd = std::env::current_dir().context("read the working directory")?;
    let env: Vec<(std::ffi::OsString, std::ffi::OsString)> = std::env::vars_os().collect();
    let tty = [is_tty(0), is_tty(1), is_tty(2)];
    // A signal the caller ignores (`nohup`: SIGHUP) is neither taken nor
    // passed on — the daemon keeps it ignored for the process too.
    let taken: Vec<libc::c_int> =
        [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT, libc::SIGWINCH].into_iter().filter(|s| !ignored(*s)).collect();
    let signals = Signals::take(&taken)?;
    let sent = proto::send(
        &conn,
        &ToDaemon::Exec { protocol: PROTOCOL, run: run.to_string(), argv: argv.to_vec(), env, cwd: cwd.into_os_string(), core },
        &[0, 1, 2],
    );
    if let Err(e) = sent {
        // A daemon that closed before reading the whole frame (its worker
        // refused it) may have said why: read a moment, never longer.
        let _ = conn.set_read_timeout(Some(std::time::Duration::from_secs(2)));
        if let Ok(Some((FromDaemon::Refused { message }, _))) = proto::recv::<FromDaemon>(&conn) {
            eprintln!("ssai: {message}");
            std::process::exit(127);
        }
        return Err(e);
    }
    // Until it started, a signal to this helper ends it — closing the
    // connection, which ends the start in the daemon.
    loop {
        let mut fds = vec![libc::pollfd { fd: conn.as_raw_fd(), events: libc::POLLIN, revents: 0 }];
        fds.extend(signals.0.iter().map(|(_, s)| libc::pollfd { fd: s.as_raw_fd(), events: libc::POLLIN, revents: 0 }));
        // SAFETY: poll on descriptors we hold.
        if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, -1) } < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            bail!("wait for the sandbox to start the process: {}", std::io::Error::last_os_error());
        }
        if fds[0].revents != 0 {
            break;
        }
        for p in &fds[1..] {
            if p.revents != 0
                && let Some(sig) = signals.drain(p.fd)
                && PASSED.contains(&sig)
            {
                finish(None, Some(sig));
            }
        }
    }
    let master: Option<OwnedFd> = match proto::recv::<FromDaemon>(&conn)? {
        Some((FromDaemon::Started { pty: true }, mut fds)) if fds.len() == 1 => Some(fds.remove(0)),
        Some((FromDaemon::Started { pty: false }, _)) => None,
        Some((FromDaemon::Refused { message }, _)) => {
            eprintln!("ssai: {message}");
            std::process::exit(127);
        }
        _ => bail!("the sandbox daemon did not start the process"),
    };
    // Where the jail's terminal output goes — one jail terminal stands for
    // every developer terminal the process was given: stdout if it is a
    // terminal, else stderr, else stdin when it can be written (the echo of
    // what is typed), else the controlling terminal.
    let tty_out;
    let out = if tty[1] {
        1
    } else if tty[2] {
        2
    } else if writable(0) {
        0
    } else {
        tty_out = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty").ok();
        // No terminal to write to at all: stdout, whatever it is.
        tty_out.as_ref().map_or(1, |f| f.as_raw_fd())
    };
    // What is typed reaches the jail's terminal only from stdin, when that
    // is the developer's terminal (as `ssh` does); raw mode only when stdout
    // is one too — in a pipeline (`| less`) the terminal's settings stay
    // another program's.
    let input: RawFd = if master.is_some() && tty[0] { 0 } else { -1 };
    // A background job (`… &`) neither takes nor reads the terminal until it
    // is brought to the foreground: the kernel would stop it for either
    // (SIGTTOU, SIGTTIN). Its output is relayed all the same.
    let mut raw: Option<Raw> = None;
    if let Some(m) = &master {
        // Never blocking on the jail's terminal: what is typed waits in
        // `pending` until it takes it, so its output, the daemon and the
        // signals are always served (a paste into a busy process cannot
        // deadlock the two).
        // SAFETY: F_SETFL on our own descriptor.
        unsafe { libc::fcntl(m.as_raw_fd(), libc::F_SETFL, libc::fcntl(m.as_raw_fd(), libc::F_GETFL) | libc::O_NONBLOCK) };
        copy_winsize(out, m.as_raw_fd());
    }
    let mut buf = [0u8; 16 * 1024];
    // A side that ended (read 0 or failed: the jail's terminal closed by
    // the process, the developer's hung up) leaves the poll set, or poll
    // reports it ready forever.
    let (mut master_open, mut stdin_open, mut taking) = (master.is_some(), input >= 0, false);
    // Typed input the jail's terminal has not taken yet; stdin is read only
    // while it is small.
    let mut pending: Vec<u8> = Vec::new();
    const PENDING_MAX: usize = 64 * 1024;
    loop {
        if stdin_open && !taking && foreground(input) {
            raw = if tty[1] { Raw::enter(input) } else { None };
            taking = true;
        }
        let mut fds = vec![libc::pollfd { fd: conn.as_raw_fd(), events: libc::POLLIN, revents: 0 }];
        if let Some(m) = &master
            && master_open
        {
            let out_ready = if pending.is_empty() { 0 } else { libc::POLLOUT };
            fds.push(libc::pollfd { fd: m.as_raw_fd(), events: libc::POLLIN | out_ready, revents: 0 });
        }
        if stdin_open && taking && pending.len() < PENDING_MAX {
            fds.push(libc::pollfd { fd: input, events: libc::POLLIN, revents: 0 });
        }
        for (_, s) in &signals.0 {
            fds.push(libc::pollfd { fd: s.as_raw_fd(), events: libc::POLLIN, revents: 0 });
        }
        // In the background, a look at the terminal now and then: `fg`
        // sends nothing a poll sees.
        let wait = if stdin_open && !taking { 500 } else { -1 };
        // SAFETY: poll on descriptors we hold.
        if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, wait) } < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            drop(raw);
            bail!("relay the sandbox's terminal: {}", std::io::Error::last_os_error());
        }
        for p in fds.iter().filter(|p| p.revents != 0) {
            if p.fd == conn.as_raw_fd() {
                match proto::recv::<FromDaemon>(&conn) {
                    Ok(Some((FromDaemon::Exited { code, signal }, _))) => {
                        if let Some(m) = &master {
                            drain(m.as_raw_fd(), out);
                        }
                        drop(raw);
                        finish(code, signal);
                    }
                    Ok(Some(_)) => {}
                    // The daemon is gone: the process with it.
                    _ => {
                        drop(raw);
                        bail!("the sandbox daemon closed the run");
                    }
                }
            } else if master.as_ref().is_some_and(|m| m.as_raw_fd() == p.fd) {
                if p.revents & libc::POLLOUT != 0 && !pending.is_empty() {
                    // SAFETY: a non-blocking write from our buffer.
                    let n = unsafe { libc::write(p.fd, pending.as_ptr() as *const _, pending.len()) };
                    if n > 0 {
                        pending.drain(..n as usize);
                    }
                }
                if p.revents & !libc::POLLOUT == 0 {
                    continue;
                }
                // SAFETY: read into our buffer.
                let n = unsafe { libc::read(p.fd, buf.as_mut_ptr() as *mut _, buf.len()) };
                if n > 0 {
                    write_all(out, &buf[..n as usize]);
                } else if n == 0 || !matches!(std::io::Error::last_os_error().kind(), std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock) {
                    master_open = false;
                }
            } else if p.fd == input {
                // SAFETY: read into our buffer.
                let n = unsafe { libc::read(input, buf.as_mut_ptr() as *mut _, buf.len()) };
                if n > 0 {
                    pending.extend_from_slice(&buf[..n as usize]);
                } else if n == 0
                    || !matches!(std::io::Error::last_os_error().kind(), std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock)
                {
                    stdin_open = false;
                }
            } else if let Some(sig) = signals.drain(p.fd) {
                match sig {
                    libc::SIGWINCH => {
                        if let Some(m) = &master {
                            copy_winsize(out, m.as_raw_fd());
                        }
                    }
                    // A send failing (the process just ended, the daemon
                    // closing) is not the run's failure: its `Exited` is
                    // read next.
                    s if PASSED.contains(&s) => {
                        let _ = proto::send(&conn, &ToDaemon::Signal { signal: s }, &[]);
                    }
                    _ => {}
                }
            }
        }
    }
}

/// What the jail's terminal still holds once the process ended.
fn drain(master: RawFd, out: RawFd) {
    let mut buf = [0u8; 16 * 1024];
    // Bounded: a process left in the jail writing on and on never holds the
    // run open.
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
    let mut left: usize = 1 << 20;
    while std::time::Instant::now() < deadline && left > 0 {
        let mut p = libc::pollfd { fd: master, events: libc::POLLIN, revents: 0 };
        // SAFETY: poll and read on a descriptor we hold.
        unsafe {
            if libc::poll(&mut p, 1, 50) <= 0 {
                return;
            }
            let n = libc::read(master, buf.as_mut_ptr() as *mut _, buf.len());
            if n <= 0 {
                return;
            }
            write_all(out, &buf[..n as usize]);
            left = left.saturating_sub(n as usize);
        }
    }
}

/// Exit as the process did.
fn finish(code: Option<i32>, signal: Option<i32>) -> ! {
    if let Some(sig) = signal {
        // SAFETY: the default action back (no core: the limit is 0 from
        // the start), then the same signal to ourselves.
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
        std::process::exit(128 + sig);
    }
    std::process::exit(code.unwrap_or(1));
}

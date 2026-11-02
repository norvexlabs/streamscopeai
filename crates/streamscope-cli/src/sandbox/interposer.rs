//! Native-sandbox `connect()` address interposer (Linux, seccomp user-notification).
//!
//! Landlock's network access is port-only (it cannot match an address), so the
//! Landlock-net rule pins TCP-connect to the loopback guard *port* but leaves it
//! reachable on any host — a sandboxed process that learns the ephemeral guard
//! port (it is in its own `HTTPS_PROXY`) could open a raw socket to
//! `attacker:<guard_port>` and exfiltrate, bypassing the userspace guard.
//!
//! This closes that hole: a seccomp filter routes every `connect()` to a
//! user-notification listener held by the supervisor (the trampoline's parent
//! after the fork), which reads the target `sockaddr` and permits only
//! `127.0.0.1:<port>` / `[::1]:<port>` for the policy's connect ports (the
//! guard, plus the engine port of an engine-backed client). Everything else
//! gets `EPERM` without the syscall running.
//!
//! **Best-effort, never a regression.** If the kernel can't provide a notify
//! listener (or the supervisor can't read the address), the connect degrades to
//! the still-active Landlock-net port pin — i.e. back to the pre-interposer
//! state, never worse, and the agent keeps working.
//!
//! **TOCTOU caveat.** An allowed `connect()` is resumed with
//! `SECCOMP_USER_NOTIF_FLAG_CONTINUE`, so the kernel re-reads the `sockaddr`
//! from the (potentially racing) target memory. Combined with the Landlock-net
//! port pin, the worst a deliberate race achieves is "any host on the guard
//! port" — exactly the residual this interposer otherwise removes, so a race
//! never drops below the baseline guarantee.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::mem::size_of;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use libc::{c_int, c_long, c_void, pid_t};

// seccomp(2) mode + flag + return-action constants (not all exposed by `libc`).
const SECCOMP_SET_MODE_FILTER: c_long = 1;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: c_long = 1 << 3;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;

// classic-BPF opcodes for the tiny filter program.
const BPF_LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
const BPF_JMP_JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
const BPF_RET_K: u16 = 0x06; // BPF_RET | BPF_K

// seccomp_data field offsets (arch-independent layout).
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;

/// Linux `SECCOMP_IOCTL_NOTIF_*` numbers, derived from the `_IOC` encoding so
/// they stay correct without hardcoding magic ints. `'!'` (0x21) is the seccomp
/// ioctl type; dir READ=2, WRITE=1; size is the payload struct's byte size.
const fn ioc(dir: u64, nr: u64, size: u64) -> u64 {
    (dir << 30) | (size << 16) | (0x21u64 << 8) | nr
}
const SECCOMP_IOCTL_NOTIF_RECV: u64 = ioc(3, 0, size_of::<SeccompNotif>() as u64);
const SECCOMP_IOCTL_NOTIF_SEND: u64 = ioc(3, 1, size_of::<SeccompNotifResp>() as u64);
const SECCOMP_IOCTL_NOTIF_ID_VALID: u64 = ioc(2, 2, size_of::<u64>() as u64);

// The ioctl payload structs MUST match the kernel ABI sizes the `_IOC` numbers
// above encode (80 / 24 / 8 bytes) — assert at compile time.
const _: () = assert!(size_of::<SeccompNotif>() == 80);
const _: () = assert!(size_of::<SeccompNotifResp>() == 24);

#[repr(C)]
#[derive(Clone, Copy)]
struct SeccompData {
    nr: i32,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SeccompNotif {
    id: u64,
    pid: u32,
    flags: u32,
    data: SeccompData,
}

#[repr(C)]
struct SeccompNotifResp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

/// The kernel `AUDIT_ARCH_*` token for this build's architecture (the value the
/// seccomp filter compares `seccomp_data.arch` against).
const fn audit_arch() -> Option<u32> {
    #[cfg(target_arch = "x86_64")]
    {
        Some(0xC000_003E)
    }
    #[cfg(target_arch = "aarch64")]
    {
        Some(0xC00000B7)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        None
    }
}

/// Build the filter: `connect` on the native arch → `USER_NOTIF`; everything
/// else (and any other arch) → `ALLOW`. The denylist filter installed earlier
/// handles the real syscall denials; this one only diverts `connect`.
fn program() -> Option<Vec<SockFilter>> {
    let arch = audit_arch()?;
    let nr_connect = libc::SYS_connect as u32;
    let stmt = |code: u16, k: u32| SockFilter { code, jt: 0, jf: 0, k };
    let jump = |k: u32, jt: u8, jf: u8| SockFilter { code: BPF_JMP_JEQ_K, jt, jf, k };
    Some(vec![
        stmt(BPF_LD_W_ABS, OFF_ARCH),       // 0: A = arch
        jump(arch, 0, 3),                   // 1: arch == native? else → ALLOW (5)
        stmt(BPF_LD_W_ABS, OFF_NR),         // 2: A = nr
        jump(nr_connect, 0, 1),             // 3: nr == connect? else → ALLOW (5)
        stmt(BPF_RET_K, SECCOMP_RET_USER_NOTIF), // 4: connect → notify supervisor
        stmt(BPF_RET_K, SECCOMP_RET_ALLOW), // 5: otherwise allow
    ])
}

/// Install the `connect`-diverting filter on THIS process (and, by inheritance,
/// every descendant) and return the notification listener fd. `None` if the
/// kernel won't provide a listener — the caller then runs without the address
/// pin (Landlock-net still pins the port). Requires `no_new_privs`, already set.
pub fn try_install() -> Option<c_int> {
    let prog = program()?;
    let fprog = SockFprog { len: prog.len() as u16, filter: prog.as_ptr() };
    // SAFETY: `fprog` (and the `prog` Vec it points into) outlive the call; the
    // kernel copies the program in. NEW_LISTENER returns the listener fd.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &fprog as *const SockFprog,
        )
    };
    if fd < 0 {
        None
    } else {
        Some(fd as c_int)
    }
}

/// The process the supervisor stands in front of, for [`forward_to_child`].
static SUPERVISED: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
/// The run parent the supervisor was started by.
static RUN_PARENT: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

extern "C" fn forward_to_child(sig: c_int, info: *mut libc::siginfo_t, _: *mut c_void) {
    let child = SUPERVISED.load(std::sync::atomic::Ordering::Relaxed);
    // SAFETY: the kernel hands a valid siginfo to an SA_SIGINFO handler;
    // si_pid, getppid and kill are async-signal-safe.
    unsafe {
        // What the run parent sends is passed on; a signal sent to the whole
        // process group (a terminal hangup) has reached the client already.
        // Once the run parent is gone, anyone's signal is passed on, so the
        // leftover supervisor still stops its client.
        let parent = RUN_PARENT.load(std::sync::atomic::Ordering::Relaxed);
        if child > 0 && ((*info).si_pid() == parent || libc::getppid() != parent) {
            libc::kill(child, sig);
        }
    }
}

/// Make the supervisor transparent to the run parent's signals: SIGTERM and
/// SIGHUP from it are passed on to `child`, so stopping the process the parent
/// launched stops the client, and the supervisor still finishes after it (a
/// learn pass writes its record). The same signals from anyone else neither
/// stop the supervisor nor are passed on while the run parent lives; SIGINT is
/// ignored (the terminal delivers Ctrl-C to the client itself).
fn forward_signals(child: pid_t) {
    SUPERVISED.store(child, std::sync::atomic::Ordering::Relaxed);
    // SAFETY: getppid(2) has no failure mode.
    RUN_PARENT.store(unsafe { libc::getppid() }, std::sync::atomic::Ordering::Relaxed);
    // SAFETY: installs async-signal-safe dispositions on this single-threaded
    // process; the handler only reads an atomic and calls getppid/kill.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        let handler: extern "C" fn(c_int, *mut libc::siginfo_t, *mut c_void) = forward_to_child;
        action.sa_sigaction = handler as libc::sighandler_t;
        action.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut());
        libc::sigaction(libc::SIGHUP, &action, std::ptr::null_mut());
        libc::signal(libc::SIGINT, libc::SIG_IGN);
    }
}

/// Supervise the listener until the agent (`child`) exits, then exit with its
/// code. Permits only loopback connects to one of `ports`; denies the rest
/// with `EPERM`. Never returns.
pub fn supervise(notify_fd: c_int, ports: &[u16], child: pid_t) -> ! {
    forward_signals(child);
    loop {
        let mut pfd = libc::pollfd { fd: notify_fd, events: libc::POLLIN, revents: 0 };
        // 200ms cadence: service connect notifications promptly while still
        // noticing the agent's exit (POLLHUP fires only once every filter
        // holder is gone, which can lag a lingering grandchild).
        let n = unsafe { libc::poll(&mut pfd, 1, 200) };
        if n > 0 && (pfd.revents & libc::POLLIN) != 0 {
            handle_one(notify_fd, ports);
        }

        let mut status = 0;
        let r = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
        if r == child {
            unsafe { libc::close(notify_fd) };
            std::process::exit(exit_code(status));
        }
    }
}

fn exit_code(status: c_int) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        1
    }
}

/// Receive one notification, decide, and answer it.
fn handle_one(fd: c_int, ports: &[u16]) {
    // SAFETY: zeroed `SeccompNotif` is a valid all-integer struct; the kernel
    // fills it on a successful RECV.
    let mut notif: SeccompNotif = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV as _, &mut notif) };
    if r != 0 {
        // EINTR / ENOENT (target vanished before RECV) — the poll loop retries.
        return;
    }

    // Only `connect` reaches USER_NOTIF; for anything else, or when the address
    // can't be inspected, fall back to allow (degrade to the Landlock-net port
    // pin rather than break the agent).
    let allow = if notif.data.nr == libc::SYS_connect as i32 {
        match read_sockaddr(notif.pid, notif.data.args[1], notif.data.args[2] as usize) {
            Some(buf) => is_loopback_allowed(&buf, ports),
            None => true,
        }
    } else {
        true
    };

    // Confirm the notification is still live before answering. If the target
    // died (and its pid was possibly reused) between RECV and the
    // /proc/<pid>/mem read, this fails → we skip SEND and the original connect
    // gets ENOENT from the kernel. It guards the *answer*, not the read itself,
    // so a stale read can't resume a connect on a wrong decision.
    let mut id = notif.id;
    if unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_ID_VALID as _, &mut id) } != 0 {
        return;
    }

    let resp = if allow {
        SeccompNotifResp { id: notif.id, val: 0, error: 0, flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE }
    } else {
        SeccompNotifResp { id: notif.id, val: 0, error: -libc::EPERM, flags: 0 }
    };
    // Ignore the result: ENOENT just means the target already went away.
    unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND as _, &resp) };
}

/// Read the `connect` target `sockaddr` from the calling process's memory.
fn read_sockaddr(pid: u32, uaddr: u64, len: usize) -> Option<Vec<u8>> {
    if uaddr == 0 || len < 4 {
        return None;
    }
    // A sockaddr_in6 is 28 bytes — never read more (and never an absurd len).
    let want = len.min(28);
    let f = std::fs::File::open(format!("/proc/{pid}/mem")).ok()?;
    let mut buf = vec![0u8; want];
    f.read_at(&mut buf, uaddr).ok()?;
    Some(buf)
}

/// True only for `127.0.0.1:<port>` (IPv4) or `[::1]:<port>` (IPv6) with
/// `<port>` one of `ports`.
fn is_loopback_allowed(buf: &[u8], ports: &[u16]) -> bool {
    if buf.len() < 4 {
        return false;
    }
    let family = u16::from_ne_bytes([buf[0], buf[1]]) as i32;
    let port = u16::from_be_bytes([buf[2], buf[3]]); // sockaddr port is network order
    if !ports.contains(&port) {
        return false;
    }
    match family {
        libc::AF_INET => buf.len() >= 8 && buf[4..8] == [127, 0, 0, 1],
        libc::AF_INET6 => {
            const LOOPBACK6: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
            buf.len() >= 24 && buf[8..24] == LOOPBACK6
        }
        _ => false,
    }
}

// ── Learn mode: divert connect() AND openat()/openat2() ─────────────────────
//
// The learn pass observes what the client opens. The filter routes `openat` /
// `openat2` (plus `connect`, unchanged) to the supervisor, which records the
// resolved path and resumes the open (CONTINUE — learn never blocks a file).
// The supervisor reads the child's memory with `process_vm_readv` and writes
// through a pre-opened fd, so it never issues an `openat` of its own (which
// would trap into its own listener and deadlock).

/// Build the learn filter: `connect`, `openat`, `openat2` on the native arch →
/// `USER_NOTIF`; everything else → `ALLOW`.
fn program_learn() -> Option<Vec<SockFilter>> {
    let arch = audit_arch()?;
    let stmt = |code: u16, k: u32| SockFilter { code, jt: 0, jf: 0, k };
    let jump = |k: u32, jt: u8, jf: u8| SockFilter { code: BPF_JMP_JEQ_K, jt, jf, k };
    let (connect, openat, openat2) =
        (libc::SYS_connect as u32, libc::SYS_openat as u32, libc::SYS_openat2 as u32);
    Some(vec![
        stmt(BPF_LD_W_ABS, OFF_ARCH),            // 0: A = arch
        jump(arch, 0, 4),                        // 1: arch == native? else → ALLOW (6)
        stmt(BPF_LD_W_ABS, OFF_NR),              // 2: A = nr
        jump(connect, 3, 0),                     // 3: connect → NOTIF (7)
        jump(openat, 2, 0),                      // 4: openat  → NOTIF (7)
        jump(openat2, 1, 0),                     // 5: openat2 → NOTIF (7)
        stmt(BPF_RET_K, SECCOMP_RET_ALLOW),      // 6: otherwise allow
        stmt(BPF_RET_K, SECCOMP_RET_USER_NOTIF), // 7: divert to supervisor
    ])
}

/// Install the learn filter and return the notification listener fd, or `None`
/// if the kernel won't provide one (the pass then records nothing but still
/// runs the client under the Landlock-net egress pin).
pub fn try_install_learn() -> Option<c_int> {
    let prog = program_learn()?;
    let fprog = SockFprog { len: prog.len() as u16, filter: prog.as_ptr() };
    // SAFETY: `fprog` (and `prog`) outlive the call; the kernel copies the program.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &fprog as *const SockFprog,
        )
    };
    if fd < 0 { None } else { Some(fd as c_int) }
}

/// Supervise the learn listener until the child exits: record every non-secret
/// `$HOME` path it opens, deny non-gateway connects, then write the observed
/// paths to `record_fd` and exit with the child's code. Never returns.
pub fn supervise_learn(
    notify_fd: c_int,
    ports: &[u16],
    child: pid_t,
    record_fd: c_int,
    home: &Path,
    deny: &[PathBuf],
) -> ! {
    forward_signals(child);
    let mut seen: HashSet<PathBuf> = HashSet::new();
    loop {
        let mut pfd = libc::pollfd { fd: notify_fd, events: libc::POLLIN, revents: 0 };
        let n = unsafe { libc::poll(&mut pfd, 1, 200) };
        if n > 0 && (pfd.revents & libc::POLLIN) != 0 {
            handle_one_learn(notify_fd, ports, home, deny, &mut seen);
        }

        let mut status = 0;
        let r = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
        if r == child {
            flush_seen(record_fd, &seen);
            unsafe { libc::close(notify_fd) };
            std::process::exit(exit_code(status));
        }
    }
}

/// Write the recorded path set to the pre-opened record fd (one per line).
fn flush_seen(fd: c_int, seen: &HashSet<PathBuf>) {
    if fd < 0 {
        return;
    }
    let mut out = String::new();
    for p in seen {
        out.push_str(&p.to_string_lossy());
        out.push('\n');
    }
    let bytes = out.as_bytes();
    // SAFETY: writing `bytes.len()` bytes from a valid slice to an owned fd.
    unsafe {
        libc::write(fd, bytes.as_ptr() as *const c_void, bytes.len());
        libc::close(fd);
    }
}

/// Receive one learn notification: record the path for `openat`, gate `connect`
/// to the loopback guard, and resume everything else.
fn handle_one_learn(
    fd: c_int,
    ports: &[u16],
    home: &Path,
    deny: &[PathBuf],
    seen: &mut HashSet<PathBuf>,
) {
    // SAFETY: zeroed `SeccompNotif` is a valid all-integer struct the kernel fills.
    let mut notif: SeccompNotif = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV as _, &mut notif) } != 0 {
        return;
    }

    let nr = notif.data.nr as i64;
    let mut deny_connect = false;
    if nr == libc::SYS_connect {
        // Address pin (same as the enforcing path) — but read via process_vm_readv,
        // since the supervisor must not open /proc/<pid>/mem in learn mode.
        let permitted = match read_bytes_vm(notif.pid, notif.data.args[1], notif.data.args[2] as usize) {
            Some(buf) => is_loopback_allowed(&buf, ports),
            None => true, // can't inspect → fall back to allow (Landlock-net still pins the port)
        };
        deny_connect = !permitted;
    } else if nr == libc::SYS_openat || nr == libc::SYS_openat2 {
        // openat(dirfd=args[0], pathname=args[1], …); openat2 has the same first
        // two args. Record the resolved path when it is a non-secret $HOME file.
        if let Some(path) = read_cstr_vm(notif.pid, notif.data.args[1])
            && let Some(abs) = resolve_at(notif.pid, notif.data.args[0] as i64, &path)
            && abs.starts_with(home)
            && !path_under_secret(&abs, deny)
        {
            seen.insert(abs);
        }
    }

    // Confirm the notification is still live before answering (target may have died).
    let mut id = notif.id;
    if unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_ID_VALID as _, &mut id) } != 0 {
        return;
    }
    let resp = if deny_connect {
        SeccompNotifResp { id: notif.id, val: 0, error: -libc::EPERM, flags: 0 }
    } else {
        // openat + allowed connect + anything else: resume the real syscall.
        SeccompNotifResp { id: notif.id, val: 0, error: 0, flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE }
    };
    unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND as _, &resp) };
}

/// True when `p` is at or under a `SECRET_DENY` prefix, by **string** prefix —
/// the entries are filename prefixes (`~/.ssh/id_` guards `id_rsa`), which the
/// component-wise `Path::starts_with` would miss. `state_dirs::dir_touches_secret`
/// additionally rejects a candidate that is an *ancestor* of a secret; this
/// front-line check just keeps direct secret-file opens out of the record file.
fn path_under_secret(p: &Path, deny: &[PathBuf]) -> bool {
    let p = p.to_string_lossy();
    deny.iter().any(|d| p.starts_with(&*d.to_string_lossy()))
}

/// Read `len` bytes from process `pid`'s address space at `addr` via
/// `process_vm_readv` (no `openat`, unlike `/proc/<pid>/mem`).
fn read_bytes_vm(pid: u32, addr: u64, len: usize) -> Option<Vec<u8>> {
    if addr == 0 || len == 0 {
        return None;
    }
    let want = len.min(28); // sockaddr_in6 is 28 bytes — never read more.
    let mut buf = vec![0u8; want];
    let local = libc::iovec { iov_base: buf.as_mut_ptr() as *mut c_void, iov_len: want };
    let remote = libc::iovec { iov_base: addr as *mut c_void, iov_len: want };
    // SAFETY: both iovecs describe valid, correctly-sized buffers; the kernel
    // copies at most `want` bytes and validates the remote range itself.
    let n = unsafe { libc::process_vm_readv(pid as i32, &local, 1, &remote, 1, 0) };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    Some(buf)
}

/// Read a NUL-terminated path string (up to `PATH_MAX`) from `pid`'s memory.
fn read_cstr_vm(pid: u32, addr: u64) -> Option<PathBuf> {
    if addr == 0 {
        return None;
    }
    let mut buf = vec![0u8; 4096];
    let local = libc::iovec { iov_base: buf.as_mut_ptr() as *mut c_void, iov_len: buf.len() };
    let remote = libc::iovec { iov_base: addr as *mut c_void, iov_len: buf.len() };
    // SAFETY: as read_bytes_vm; a short read near an unmapped page still yields the
    // NUL-terminated prefix, which is all we need.
    let n = unsafe { libc::process_vm_readv(pid as i32, &local, 1, &remote, 1, 0) };
    if n <= 0 {
        return None;
    }
    let read = &buf[..n as usize];
    let end = read.iter().position(|&b| b == 0).unwrap_or(read.len());
    if end == 0 {
        return None;
    }
    Some(PathBuf::from(OsStr::from_bytes(&read[..end])))
}

/// Resolve an `openat` `(dirfd, pathname)` pair to an absolute path (best effort).
/// Absolute pathnames pass through; a relative one is joined onto the directory
/// `dirfd` points at (`AT_FDCWD` → the child's cwd), read via `readlink` on
/// `/proc/<pid>/…` (a `readlinkat`, not an `openat`). Returns `None` when the base
/// can't be resolved — the path is simply not recorded.
fn resolve_at(pid: u32, dirfd: i64, path: &Path) -> Option<PathBuf> {
    if path.is_absolute() {
        return Some(path.to_path_buf());
    }
    let base = if dirfd == libc::AT_FDCWD as i64 {
        std::fs::read_link(format!("/proc/{pid}/cwd")).ok()?
    } else {
        std::fs::read_link(format!("/proc/{pid}/fd/{dirfd}")).ok()?
    };
    Some(base.join(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa_in(ip: [u8; 4], port: u16) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        v.extend_from_slice(&port.to_be_bytes());
        v.extend_from_slice(&ip);
        v
    }

    #[test]
    fn loopback_matches_only_localhost_and_an_allowed_port() {
        assert!(is_loopback_allowed(&sa_in([127, 0, 0, 1], 5000), &[5000]));
        // wrong host, right port — the residual this interposer closes.
        assert!(!is_loopback_allowed(&sa_in([10, 0, 0, 9], 5000), &[5000]));
        // right host, wrong port.
        assert!(!is_loopback_allowed(&sa_in([127, 0, 0, 1], 5001), &[5000]));
        // An engine-backed client: the guard and the engine port, nothing between.
        assert!(is_loopback_allowed(&sa_in([127, 0, 0, 1], 5000), &[5000, 6000]));
        assert!(is_loopback_allowed(&sa_in([127, 0, 0, 1], 6000), &[5000, 6000]));
        assert!(!is_loopback_allowed(&sa_in([127, 0, 0, 1], 5999), &[5000, 6000]));
        assert!(!is_loopback_allowed(&sa_in([10, 0, 0, 9], 6000), &[5000, 6000]));
        // No allowed port: nothing connects.
        assert!(!is_loopback_allowed(&sa_in([127, 0, 0, 1], 5000), &[]));
    }

    #[test]
    fn ipv6_loopback_matches() {
        let mut v = Vec::new();
        v.extend_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
        v.extend_from_slice(&7000u16.to_be_bytes());
        v.extend_from_slice(&0u32.to_ne_bytes()); // flowinfo
        v.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // ::1
        assert!(is_loopback_allowed(&v, &[7000]));
        v[23] = 2; // ::2
        assert!(!is_loopback_allowed(&v, &[7000]));
    }

    #[test]
    fn program_builds_for_supported_arch() {
        // On x86_64/aarch64 the filter is six instructions; elsewhere None.
        if audit_arch().is_some() {
            assert_eq!(program().unwrap().len(), 6);
        } else {
            assert!(program().is_none());
        }
    }
}

//! The FreeBSD system calls the jail daemon makes: `nmount`, `statfs`,
//! `getfsstat`, unmount by filesystem id, `jail_set` / `jail_get` /
//! `jail_remove`, and the `sysctl`s it reads.

use std::ffi::{CStr, CString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use super::record::MountEntry;

pub fn cstr(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

fn last() -> io::Error {
    io::Error::last_os_error()
}

/// A `name=value` option list for `nmount` / `jail_set`. A `None` value is
/// a flag option (`persist`); every value is passed as given (strings carry
/// their NUL).
struct Iov {
    keys: Vec<Vec<u8>>,
    values: Vec<Option<Vec<u8>>>,
}

impl Iov {
    fn new() -> Self {
        Self { keys: Vec::new(), values: Vec::new() }
    }
    fn str(mut self, k: &str, v: &[u8]) -> Self {
        let mut v = v.to_vec();
        v.push(0);
        self.keys.push(k.as_bytes().to_vec());
        self.values.push(Some(v));
        self
    }
    fn int(mut self, k: &str, v: i32) -> Self {
        self.keys.push(k.as_bytes().to_vec());
        self.values.push(Some(v.to_ne_bytes().to_vec()));
        self
    }
    fn flag(mut self, k: &str) -> Self {
        self.keys.push(k.as_bytes().to_vec());
        self.values.push(None);
        self
    }
    /// The iovec array over this list (and an `errmsg` buffer), valid while
    /// `self` and `errmsg` live.
    fn build(&mut self, errmsg: &mut [u8]) -> Vec<libc::iovec> {
        for k in &mut self.keys {
            if k.last() != Some(&0) {
                k.push(0);
            }
        }
        let mut iov = Vec::new();
        for (k, v) in self.keys.iter().zip(&mut self.values) {
            iov.push(libc::iovec { iov_base: k.as_ptr() as *mut _, iov_len: k.len() });
            match v {
                Some(v) => iov.push(libc::iovec { iov_base: v.as_mut_ptr() as *mut _, iov_len: v.len() }),
                None => iov.push(libc::iovec { iov_base: std::ptr::null_mut(), iov_len: 0 }),
            }
        }
        const ERRMSG: &[u8] = b"errmsg\0";
        iov.push(libc::iovec { iov_base: ERRMSG.as_ptr() as *mut _, iov_len: ERRMSG.len() });
        iov.push(libc::iovec { iov_base: errmsg.as_mut_ptr() as *mut _, iov_len: errmsg.len() });
        iov
    }
}

fn with_errmsg(e: io::Error, errmsg: &[u8]) -> io::Error {
    let msg = CStr::from_bytes_until_nul(errmsg).ok().map(|m| m.to_string_lossy().into_owned()).unwrap_or_default();
    if msg.is_empty() { e } else { io::Error::new(e.kind(), format!("{e}: {msg}")) }
}

/// Mount `fstype` on `fspath` with `opts` (`(key, value)`, a `None` value a
/// flag) and `flags` (`MNT_RDONLY`, `MNT_NOSUID`).
pub fn nmount(fstype: &str, fspath: &Path, opts: &[(&str, Option<&[u8]>)], flags: i32) -> io::Result<()> {
    let mut iov = Iov::new().str("fstype", fstype.as_bytes()).str("fspath", fspath.as_os_str().as_bytes());
    for (k, v) in opts {
        iov = match v {
            Some(v) => iov.str(k, v),
            None => iov.flag(k),
        };
    }
    let mut errmsg = [0u8; 256];
    let mut v = iov.build(&mut errmsg);
    // SAFETY: the iovecs point into `iov` and `errmsg`, alive for the call.
    if unsafe { libc::nmount(v.as_mut_ptr(), v.len() as u32, flags) } != 0 {
        return Err(with_errmsg(last(), &errmsg));
    }
    Ok(())
}

fn c_chars(chars: &[libc::c_char]) -> String {
    // SAFETY: reinterpreting c_char as u8, same size.
    let bytes = unsafe { std::slice::from_raw_parts(chars.as_ptr() as *const u8, chars.len()) };
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// A filesystem as `statfs` describes it.
pub struct Fs {
    pub entry: MountEntry,
    pub flags: u64,
}

fn fs_of(st: &libc::statfs) -> Fs {
    // SAFETY: fsid_t is two ints (`val[2]`), its field private in the binding.
    let fsid = unsafe { *(&st.f_fsid as *const libc::fsid_t as *const [i32; 2]) };
    Fs {
        entry: MountEntry { fsid, fstype: c_chars(&st.f_fstypename), on: c_chars(&st.f_mntonname) },
        flags: st.f_flags,
    }
}

/// `statfs(path)`.
pub fn statfs(path: &Path) -> io::Result<Fs> {
    let c = cstr(path)?;
    // SAFETY: statfs fills the zeroed struct we own.
    unsafe {
        let mut st: libc::statfs = std::mem::zeroed();
        if libc::statfs(c.as_ptr(), &mut st) != 0 {
            return Err(last());
        }
        Ok(fs_of(&st))
    }
}

/// The filesystem what descriptor `fd` is on.
pub fn fstatfs(fd: std::os::fd::RawFd) -> Option<Fs> {
    // SAFETY: fstatfs into a struct we own.
    unsafe {
        let mut st: libc::statfs = std::mem::zeroed();
        (libc::fstatfs(fd, &mut st) == 0).then(|| fs_of(&st))
    }
}

/// The filesystem id of what descriptor `fd` is on.
pub fn fstatfs_fsid(fd: std::os::fd::RawFd) -> Option<[i32; 2]> {
    // SAFETY: fstatfs into a struct we own.
    unsafe {
        let mut st: libc::statfs = std::mem::zeroed();
        (libc::fstatfs(fd, &mut st) == 0).then(|| fs_of(&st).entry.fsid)
    }
}

/// Every mounted filesystem, in mount order.
pub fn mounts() -> Vec<MountEntry> {
    statfs_all().iter().map(|st| fs_of(st).entry).collect()
}

/// [`mounts`], those root made only.
pub fn root_mounts() -> Vec<MountEntry> {
    statfs_all().iter().filter(|st| st.f_owner == 0).map(|st| fs_of(st).entry).collect()
}

fn statfs_all() -> Vec<libc::statfs> {
    // SAFETY: getfsstat with a NULL buffer counts; the second call fills a
    // buffer of that many entries (more may appear: it then truncates).
    unsafe {
        let n = libc::getfsstat(std::ptr::null_mut(), 0, libc::MNT_NOWAIT);
        if n <= 0 {
            return Vec::new();
        }
        let mut buf: Vec<libc::statfs> = vec![std::mem::zeroed(); n as usize + 16];
        let size = (buf.len() * std::mem::size_of::<libc::statfs>()) as libc::c_long;
        let n = libc::getfsstat(buf.as_mut_ptr(), size, libc::MNT_NOWAIT);
        if n <= 0 {
            return Vec::new();
        }
        buf.truncate(n as usize);
        buf
    }
}

/// Unmount the filesystem `fsid` — by its id, never a path, and never forced.
pub fn unmount_fsid(fsid: [i32; 2]) -> io::Result<()> {
    let name = CString::new(format!("FSID:{}:{}", fsid[0], fsid[1])).expect("no NUL in digits");
    // SAFETY: a NUL-terminated string we own.
    if unsafe { libc::unmount(name.as_ptr(), libc::MNT_BYFSID) } != 0 {
        return Err(last());
    }
    Ok(())
}

/// Create the persistent vnet jail `name` rooted at `path`; its id.
pub fn jail_create(name: &str, path: &Path) -> io::Result<i32> {
    let mut iov = Iov::new()
        .str("name", name.as_bytes())
        .str("path", path.as_os_str().as_bytes())
        .str("host.hostname", b"ssai")
        .int("vnet", libc::JAIL_SYS_NEW)
        .int("enforce_statfs", 2)
        .int("children.max", 0)
        .flag("persist");
    let mut errmsg = [0u8; 256];
    let mut v = iov.build(&mut errmsg);
    // SAFETY: as in `nmount`.
    let jid = unsafe { libc::jail_set(v.as_mut_ptr(), v.len() as u32, libc::JAIL_CREATE) };
    if jid < 0 {
        return Err(with_errmsg(last(), &errmsg));
    }
    Ok(jid)
}

/// Raise the jail's securelevel.
pub fn jail_securelevel(jid: i32, level: i32) -> io::Result<()> {
    let mut iov = Iov::new().int("jid", jid).int("securelevel", level);
    let mut errmsg = [0u8; 256];
    let mut v = iov.build(&mut errmsg);
    // SAFETY: as in `nmount`.
    if unsafe { libc::jail_set(v.as_mut_ptr(), v.len() as u32, libc::JAIL_UPDATE) } < 0 {
        return Err(with_errmsg(last(), &errmsg));
    }
    Ok(())
}

/// The id of the live jail `name`, if there is one.
pub fn jail_id(name: &str) -> Option<i32> {
    jail_id_flags(name, 0)
}

/// [`jail_id`] with `jail_get` flags (`JAIL_DYING`: a removed jail still
/// dying counts).
fn jail_id_flags(name: &str, flags: i32) -> Option<i32> {
    let mut iov = Iov::new().str("name", name.as_bytes());
    let mut errmsg = [0u8; 256];
    let mut v = iov.build(&mut errmsg);
    // SAFETY: as in `nmount`.
    let jid = unsafe { libc::jail_get(v.as_mut_ptr(), v.len() as u32, flags) };
    (jid >= 0).then_some(jid)
}

/// Remove the jail `name` (killing its processes), and wait — briefly — until
/// it is gone, dying included: a dying jail still holds its mounts. An error
/// when it is still there after the wait.
pub fn jail_remove(name: &str) -> io::Result<()> {
    let Some(jid) = jail_id(name) else {
        // Already removed, perhaps still dying: wait for that too.
        return wait_gone(name);
    };
    // SAFETY: jail_remove takes an id.
    if unsafe { libc::jail_remove(jid) } != 0 && last().raw_os_error() != Some(libc::EINVAL) {
        return Err(last());
    }
    wait_gone(name)
}

fn wait_gone(name: &str) -> io::Result<()> {
    for _ in 0..200 {
        if jail_id_flags(name, libc::JAIL_DYING).is_none() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    Err(io::Error::new(io::ErrorKind::ResourceBusy, format!("the jail {name} is still dying")))
}

/// `kern.boot_id` in hex — a random id per boot, which a clock step never
/// changes; empty where the kernel has none.
pub fn boot_id() -> String {
    let mut id = [0u8; 64];
    let mut len = id.len();
    // SAFETY: sysctlbyname into a buffer we own, its size given.
    let ok = unsafe { libc::sysctlbyname(c"kern.boot_id".as_ptr(), id.as_mut_ptr() as *mut _, &mut len, std::ptr::null(), 0) == 0 };
    if ok { hex::encode(&id[..len.min(id.len())]) } else { String::new() }
}

/// Whether the sysctl `name` exists (a kernel feature or a loaded module).
pub fn sysctl_exists(name: &CStr) -> bool {
    let mut len = 0usize;
    // SAFETY: a size query; nothing is written.
    unsafe { libc::sysctlbyname(name.as_ptr(), std::ptr::null_mut(), &mut len, std::ptr::null(), 0) == 0 }
}

/// The integer sysctl `name`.
pub fn sysctl_int(name: &CStr) -> Option<i32> {
    let mut v: i32 = 0;
    let mut len = std::mem::size_of::<i32>();
    // SAFETY: an int-sized read into `v`.
    let ok = unsafe { libc::sysctlbyname(name.as_ptr(), &mut v as *mut _ as *mut _, &mut len, std::ptr::null(), 0) == 0 };
    ok.then_some(v)
}

/// A user's account: name, primary group, home and groups.
pub struct Account {
    pub name: CString,
    pub gid: libc::gid_t,
    pub home: std::path::PathBuf,
    pub groups: Vec<libc::gid_t>,
}

/// The passwd entry of `uid` and its groups.
pub fn account(uid: libc::uid_t) -> io::Result<Account> {
    // SAFETY: getpwuid_r into buffers we own; the result points into `buf`.
    unsafe {
        let mut pw: libc::passwd = std::mem::zeroed();
        let mut buf = vec![0 as libc::c_char; 16 * 1024];
        let mut out: *mut libc::passwd = std::ptr::null_mut();
        // A larger buffer while the entry does not fit (a directory's).
        let rc = loop {
            let rc = libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr(), buf.len(), &mut out);
            if rc != libc::ERANGE || buf.len() >= 1 << 20 {
                break rc;
            }
            buf.resize(buf.len() * 4, 0);
        };
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc));
        }
        if out.is_null() {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("no account for uid {uid}")));
        }
        let name = CStr::from_ptr(pw.pw_name).to_owned();
        let home = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(CStr::from_ptr(pw.pw_dir).to_bytes()));
        let mut groups = vec![0 as libc::gid_t; 1024];
        let mut n = groups.len() as libc::c_int;
        if libc::getgrouplist(name.as_ptr(), pw.pw_gid, groups.as_mut_ptr(), &mut n) < 0 {
            n = groups.len() as libc::c_int;
        }
        // No more than the kernel takes (`kern.ngroups`), or setgroups refuses.
        let max = usize::try_from(libc::sysconf(libc::_SC_NGROUPS_MAX)).unwrap_or(16);
        groups.truncate((n.max(0) as usize).min(max));
        Ok(Account { name, gid: pw.pw_gid, home, groups })
    }
}

/// Drop this process to `uid` with `acct`'s groups — for good.
pub fn become_user(uid: libc::uid_t, acct: &Account) -> io::Result<()> {
    // SAFETY: plain id-changing syscalls on this process.
    unsafe {
        if libc::setgroups(acct.groups.len() as libc::c_int, acct.groups.as_ptr()) != 0
            || libc::setgid(acct.gid) != 0
            || libc::setuid(uid) != 0
        {
            return Err(last());
        }
    }
    Ok(())
}

/// The pid of the process at the other end of a unix socket
/// (`LOCAL_PEERCRED`): the kernel's, never the peer's word.
pub fn peer_pid(fd: std::os::fd::RawFd) -> Option<libc::pid_t> {
    // SAFETY: getsockopt into a struct we own, its size given.
    unsafe {
        let mut cred: libc::xucred = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::xucred>() as libc::socklen_t;
        if libc::getsockopt(fd, 0, libc::LOCAL_PEERCRED, &mut cred as *mut _ as *mut _, &mut len) != 0 {
            return None;
        }
        let pid = cred.cr_pid__c_anonymous_union.cr_pid;
        (pid > 0).then_some(pid)
    }
}

/// The resources whose limits a jailed process takes from its caller.
const LIMITS: [libc::c_int; 16] = [
    libc::RLIMIT_CPU,
    libc::RLIMIT_FSIZE,
    libc::RLIMIT_DATA,
    libc::RLIMIT_STACK,
    libc::RLIMIT_CORE,
    libc::RLIMIT_RSS,
    libc::RLIMIT_MEMLOCK,
    libc::RLIMIT_NPROC,
    libc::RLIMIT_NOFILE,
    libc::RLIMIT_SBSIZE,
    libc::RLIMIT_AS,
    libc::RLIMIT_NPTS,
    libc::RLIMIT_SWAP,
    libc::RLIMIT_KQUEUES,
    libc::RLIMIT_UMTXP,
    RLIMIT_PIPEBUF,
];

/// `RLIMIT_PIPEBUF` (`sys/resource.h`, FreeBSD 14+), which the binding lacks.
const RLIMIT_PIPEBUF: libc::c_int = 15;

/// `kern.proc` sysctl numbers (`sys/sysctl.h`), which the binding lacks.
const KERN_PROC_RLIMIT: libc::c_int = 37;
const KERN_PROC_UMASK: libc::c_int = 39;

/// Process `pid`'s resource limits, as the kernel holds them — every one of
/// [`LIMITS`], or `None`.
pub fn proc_limits(pid: libc::pid_t) -> Option<Vec<(libc::c_int, libc::rlimit)>> {
    LIMITS
        .iter()
        .map(|&resource| {
            let mib = [libc::CTL_KERN, libc::KERN_PROC, KERN_PROC_RLIMIT, pid, resource];
            // SAFETY: sysctl into a struct we own, its size given.
            unsafe {
                let mut rl: libc::rlimit = std::mem::zeroed();
                let mut len = std::mem::size_of::<libc::rlimit>();
                (libc::sysctl(mib.as_ptr(), mib.len() as u32, &mut rl as *mut _ as *mut _, &mut len, std::ptr::null(), 0) == 0)
                    .then_some((resource, rl))
            }
        })
        .collect()
}

/// Process `pid`'s effective uid and ignored signals, from one snapshot.
pub fn proc_info(pid: libc::pid_t) -> Option<(libc::uid_t, libc::sigset_t)> {
    let mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];
    // SAFETY: sysctl into a struct we own, its size given.
    unsafe {
        let mut kp: libc::kinfo_proc = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::kinfo_proc>();
        let ok = libc::sysctl(mib.as_ptr(), mib.len() as u32, &mut kp as *mut _ as *mut _, &mut len, std::ptr::null(), 0) == 0;
        (ok && len == std::mem::size_of::<libc::kinfo_proc>() && kp.ki_pid == pid).then_some((kp.ki_uid, kp.ki_sigignore))
    }
}

/// Process `pid`'s umask.
pub fn proc_umask(pid: libc::pid_t) -> Option<libc::mode_t> {
    let mib = [libc::CTL_KERN, libc::KERN_PROC, KERN_PROC_UMASK, pid];
    let mut mask: u16 = 0;
    let mut len = std::mem::size_of::<u16>();
    // SAFETY: sysctl into a u_short we own.
    let ok = unsafe { libc::sysctl(mib.as_ptr(), mib.len() as u32, &mut mask as *mut _ as *mut _, &mut len, std::ptr::null(), 0) == 0 };
    ok.then_some(libc::mode_t::from(mask))
}

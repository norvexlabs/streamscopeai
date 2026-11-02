//! The confined client's temp dir: one private directory per run, under the
//! user's cache (`${XDG_CACHE_HOME:-~/.cache}/streamscopeai/tmp/<run>/`, mode
//! 0700), granted read + write + execute and named by every temp variable the
//! supported runtimes read ([`TEMP_VARS`]).
//!
//! It is the sandbox's own directory, never the user's `$TMPDIR` or `/tmp`:
//! a runtime that extracts a native library and `dlopen`s it (Bun, for
//! OpenCode's TUI) needs a directory that is both inside the grant and on a
//! mount that allows exec, and a shared `/tmp` is often `noexec`. It is per
//! run, never shared between runs, so it carries nothing a confined client
//! wrote in one project into a run in another.
//!
//! Lifetime: [`ScratchDir`] removes the directory when dropped — every exit
//! path of the run, early errors included. A run killed before that leaves its
//! directory behind; the next run prunes it. A run's liveness is an exclusive
//! `flock` on `<run>.lock` beside the directory, held by every process of the
//! run that keeps the descriptor each confined command inherits — one that
//! closes its inherited descriptors drops out — and released by the kernel
//! however they end, so a lock that can be taken names a run none of whose
//! holders is left. The lock sits in the
//! parent, outside the run's own grant (unless the project root is an ancestor
//! of the cache, e.g. a project at `$HOME`, whose grant already covers it).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
#[cfg(unix)]
use rand::Rng;

/// The temp variables a confined process reads, each pinned to the run's
/// scratch dir: the POSIX/Windows trio every runtime falls back to (Node,
/// Python, Go, Deno, Rust), and Bun's own override, which Bun reads FIRST —
/// an inherited `BUN_TMPDIR` would otherwise send its extraction outside the
/// grant.
pub const TEMP_VARS: &[&str] = &["TMPDIR", "TMP", "TEMP", "BUN_TMPDIR"];

/// One run's scratch dir. Dropping it removes the directory, the run's trust
/// bundle beside it and its lock.
pub struct ScratchDir {
    dir: PathBuf,
    root: PathBuf,
    lock_path: PathBuf,
    #[cfg(unix)]
    _lock: std::fs::File,
}

impl ScratchDir {
    /// Create this run's scratch dir under [`scratch_root`], pruning the dirs
    /// of runs that are gone first, and refuse it when its mount is `noexec`.
    pub fn create() -> Result<Self> {
        Self::create_in(&scratch_root()?)
    }

    #[cfg(unix)]
    fn create_in(root: &Path) -> Result<Self> {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(root).with_context(|| {
            format!(
                "create the sandbox's temp dir under {} — make it writable, set {TMPDIR_VAR} to a \
                 directory you can write, or pass --sandbox off to launch unconfined",
                root.display()
            )
        })?;
        // Canonical, so the grant and the variables name the path the kernel
        // (Landlock) and Seatbelt (`/private/var/…`, not `/var/…`) match.
        // Never through a symlink: another user can plant one where a shared
        // `STREAMSCOPE_TMPDIR` holds our root, pointing at a tree of ours the
        // pruner would then empty.
        if std::fs::symlink_metadata(root).is_ok_and(|m| m.file_type().is_symlink()) {
            anyhow::bail!(
                "{} is a symbolic link: the sandbox keeps each run's temp dir there and removes what it \
                 finds. Remove the link, or set {TMPDIR_VAR} elsewhere",
                root.display()
            );
        }
        let root = dunce::canonicalize(root).with_context(|| format!("resolve {}", root.display()))?;
        ensure_private(&root)?;
        prune_dead_runs(&root);
        // A pruner in another run can take, unlink and release a lock between
        // its creation and our `flock`; a lock that is not (or no longer) the
        // file at its path is given up and a fresh name tried.
        let (name, lock_path, lock) = 'named: {
            for _ in 0..4 {
                // Short: a client may put a Unix socket in its temp dir, and
                // `sun_path` holds 104 bytes on macOS.
                let mut suffix = [0u8; 4];
                rand::rng().fill_bytes(&mut suffix);
                let name = hex::encode(suffix);
                // The lock exists, held, before the directory does: a pruner
                // never sees this run's directory without a live lock beside it.
                let lock_path = root.join(format!("{name}.lock"));
                // Open for writing: NFS emulates `flock` with POSIX locks,
                // whose exclusive form needs a writable descriptor.
                let lock = match std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&lock_path) {
                    Ok(lock) => lock,
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(e) => return Err(e).with_context(|| format!("create {}", lock_path.display())),
                };
                match try_lock(&lock) {
                    Ok(true) if is_the_file_at(&lock, &lock_path) => break 'named (name, lock_path, lock),
                    Ok(_) => continue,
                    Err(e) => {
                        let _ = std::fs::remove_file(&lock_path);
                        return Err(e).with_context(|| {
                            format!(
                                "lock {} — the sandbox needs flock(2) on that filesystem; set {TMPDIR_VAR} \
                                 to a directory on one that has it, or pass --sandbox off to launch \
                                 unconfined",
                                lock_path.display()
                            )
                        });
                    }
                }
            }
            anyhow::bail!("could not claim a temp dir for this run under {}", root.display());
        };
        inherit_across_exec(&lock).with_context(|| format!("share {}", lock_path.display()))?;
        let dir = root.join(&name);
        let scratch = Self { dir: dir.clone(), root, lock_path, _lock: lock };
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .with_context(|| format!("create {}", dir.display()))?;
        ensure_exec(&scratch.dir)?;
        Ok(scratch)
    }

    #[cfg(not(unix))]
    fn create_in(_root: &Path) -> Result<Self> {
        anyhow::bail!("the native sandbox is only implemented on Linux and macOS")
    }

    /// The directory, canonical.
    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// The directory every run's scratch dir lives in, canonical. Nothing a
    /// confined client writes there is ever its own state. Read by the Linux
    /// learn pass, which never records a path under it.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Write a `--ca-file` trust bundle as `<root>/<run>.pem` (0600, created
    /// exclusively): beside the run's dir, so outside every run's write grant —
    /// a confined client can read it but cannot add a CA to it, nor can any
    /// other run — unless a run's project root contains the scratch root (a
    /// run from `$HOME`), whose grant covers everything below it. Removed with
    /// the run, and pruned with it.
    pub fn write_ca_bundle(&self, pem: &[u8]) -> Result<PathBuf> {
        let path = self.ca_bundle_path();
        let mut file = crate::state::create_new_private_file(&path)?;
        std::io::Write::write_all(&mut file, pem).with_context(|| format!("write {}", path.display()))?;
        Ok(path)
    }

    fn ca_bundle_path(&self) -> PathBuf {
        self.dir.with_extension("pem")
    }

    /// Point every [`TEMP_VARS`] entry at this dir. Appended last, so it
    /// overrides an inherited value and a user's `-e TMPDIR=…` alike.
    pub fn pin_env(&self, env: &mut Vec<(String, String)>) {
        let dir = self.dir.to_string_lossy().into_owned();
        env.extend(TEMP_VARS.iter().map(|k| (k.to_string(), dir.clone())));
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        remove_tree(&self.dir);
        let _ = std::fs::remove_file(self.ca_bundle_path());
        // Unlinked while still held; the lock goes with the descriptor.
        let _ = std::fs::remove_file(&self.lock_path);
    }
}

/// Where every run's scratch dir lives: `$STREAMSCOPE_TMPDIR/streamscope-<uid>`
/// when that is set — a place of the user's choosing, for a cache on a
/// `noexec` mount; under `/tmp`, which every run is granted, a run could write
/// into another's — else
/// `${XDG_CACHE_HOME:-~/.cache}/streamscopeai/tmp` ([`crate::state::cache_dir`]).
/// `STREAMSCOPE_TMPDIR` is read by this CLI alone, so unlike `XDG_CACHE_HOME`
/// it moves no client's own cache out of its grant.
pub fn scratch_root() -> Result<PathBuf> {
    #[cfg(unix)]
    // SAFETY: geteuid(2) cannot fail and touches no memory.
    let uid = unsafe { libc::geteuid() };
    #[cfg(not(unix))]
    let uid = 0;
    match scratch_override(std::env::var_os(TMPDIR_VAR), uid)? {
        Some(root) => Ok(root),
        None => Ok(crate::state::cache_dir()?.join("tmp")),
    }
}

/// The variable that moves the scratch root.
pub const TMPDIR_VAR: &str = "STREAMSCOPE_TMPDIR";

/// The scratch root `STREAMSCOPE_TMPDIR` names, if set: a per-user directory
/// in it, so a shared one serves every user without any of them reaching
/// another's (each root must be its owner's — [`ensure_private`]).
fn scratch_override(value: Option<std::ffi::OsString>, uid: u32) -> Result<Option<PathBuf>> {
    let Some(dir) = value.filter(|v| !v.is_empty()).map(PathBuf::from) else {
        return Ok(None);
    };
    if !dir.is_absolute() {
        anyhow::bail!("{TMPDIR_VAR} must be an absolute path, got {}", dir.display());
    }
    Ok(Some(dir.join(format!("streamscope-{uid}"))))
}

/// Refuse a scratch root another user could reach into: one not owned by this
/// user, or writable by its group or others (an `XDG_CACHE_HOME` on a shared
/// path, say). Its owner could swap a run's dir for a symlink to one of theirs
/// before the grant is built, and read what the client extracts there.
#[cfg(unix)]
fn ensure_private(root: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(root).with_context(|| format!("read {}", root.display()))?;
    // SAFETY: geteuid(2) cannot fail and touches no memory.
    let me = unsafe { libc::geteuid() };
    if meta.uid() != me || meta.mode() & 0o022 != 0 {
        anyhow::bail!(
            "{} is not private to you (owner uid {}, mode {:o}): the sandbox keeps each run's temp dir \
             there. Make it yours with mode 0700, set {TMPDIR_VAR} to a directory of your own, or \
             pass --sandbox off to launch unconfined",
            root.display(),
            meta.uid(),
            meta.mode() & 0o7777
        );
    }
    Ok(())
}

/// An exclusive, non-blocking `flock`: `Ok(true)` when taken, `Ok(false)` when
/// another open file holds it, an error when the filesystem cannot lock.
#[cfg(unix)]
fn try_lock(file: &std::fs::File) -> std::io::Result<bool> {
    use std::os::fd::AsRawFd;
    // SAFETY: flock(2) on a descriptor this function borrows; no memory.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(true);
    }
    let e = std::io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::EWOULDBLOCK) { Ok(false) } else { Err(e) }
}

/// Whether `file` is still the file at `path` (not unlinked or replaced).
#[cfg(unix)]
fn is_the_file_at(file: &std::fs::File, path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (file.metadata(), std::fs::symlink_metadata(path)) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

/// Let `file` survive `exec`, so every command the run starts holds the lock
/// too: a run whose `ssai run` process was killed while its client
/// still runs stays live to the pruner. A confined process can release it
/// (`flock(LOCK_UN)` on the shared open file); that only exposes its own run's
/// dir to the next start's prune.
#[cfg(unix)]
fn inherit_across_exec(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: fcntl(2) on a descriptor this function borrows; clears FD_CLOEXEC only.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Remove every run's scratch dir (and lock) under `root` whose run is gone:
/// its lock can be taken, or it has none. Only an entry named as a run names
/// one ([`is_run_name`]); anything else in the root is never touched. A lock this run's pruner holds while
/// removing keeps a concurrent pruner off the same entry.
#[cfg(unix)]
fn prune_dead_runs(root: &Path) {
    let Ok(entries) = std::fs::read_dir(root) else { return };
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            name.strip_suffix(".lock").or_else(|| name.strip_suffix(".pem")).map(str::to_string).unwrap_or(name)
        })
        .filter(|name| is_run_name(name))
        .collect();
    names.sort();
    names.dedup();
    for name in names {
        let lock_path = root.join(format!("{name}.lock"));
        let held = match std::fs::OpenOptions::new().write(true).open(&lock_path) {
            Ok(lock) => {
                if !matches!(try_lock(&lock), Ok(true)) {
                    continue;
                }
                Some(lock)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => continue,
        };
        remove_tree(&root.join(&name));
        let _ = std::fs::remove_file(root.join(format!("{name}.pem")));
        if held.is_some() {
            let _ = std::fs::remove_file(&lock_path);
        }
    }
}

/// Whether `name` is a run's (8 lowercase hex digits).
#[cfg(unix)]
fn is_run_name(name: &str) -> bool {
    name.len() == 8 && name.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Remove `dir` and everything in it, never following a symlink. A confined
/// client may leave a directory it made unwritable (mode 0500); those are made
/// writable and the removal retried once.
fn remove_tree(dir: &Path) {
    #[cfg(unix)]
    if std::fs::remove_dir_all(dir).is_err() && dir.exists() {
        make_dirs_writable(dir);
        let _ = std::fs::remove_dir_all(dir);
    }
    #[cfg(not(unix))]
    let _ = std::fs::remove_dir_all(dir);
}

/// Make `dir` and every directory below it writable. Each directory is opened
/// by name relative to its parent with `O_NOFOLLOW` and changed through that
/// descriptor, so no step follows a symlink or touches a file another process
/// swapped in: what a confined leftover does in the dir meanwhile can never
/// redirect a change outside it. A directory with no read permission cannot be
/// opened, so a dir holding one stays behind.
#[cfg(unix)]
fn make_dirs_writable(dir: &Path) {
    let Ok(c) = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(dir.as_os_str())) else {
        return;
    };
    // SAFETY: open(2) on a NUL-terminated path `c` owns.
    let fd = unsafe { libc::open(c.as_ptr(), DIR_FLAGS) };
    if fd >= 0 {
        writable_below(fd);
    }
}

#[cfg(unix)]
const DIR_FLAGS: libc::c_int = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

/// Make the open directory `fd` and every directory below it writable; closes `fd`.
#[cfg(unix)]
fn writable_below(fd: libc::c_int) {
    // SAFETY: `fd` is an open directory this function owns; fdopendir takes
    // it over and closedir closes it. Each entry name is copied out before the
    // next readdir, and every child descriptor is handed to the recursion,
    // which closes it.
    unsafe {
        libc::fchmod(fd, 0o700);
        let d = libc::fdopendir(fd);
        if d.is_null() {
            libc::close(fd);
            return;
        }
        let mut names = Vec::new();
        loop {
            let ent = libc::readdir(d);
            if ent.is_null() {
                break;
            }
            let name = std::ffi::CStr::from_ptr((*ent).d_name.as_ptr()).to_owned();
            if name.as_bytes() != b"." && name.as_bytes() != b".." {
                names.push(name);
            }
        }
        for name in &names {
            let child = libc::openat(libc::dirfd(d), name.as_ptr(), DIR_FLAGS);
            if child >= 0 {
                writable_below(child);
            }
        }
        libc::closedir(d);
    }
}

/// Refuse a scratch dir whose mount forbids exec: a runtime that extracts a
/// native library there cannot map it executable whatever the sandbox grants,
/// and fails with an error that names neither the directory nor the mount
/// (Bun: "Failed to open library \"/$bunfs/root/…\"").
#[cfg(unix)]
fn ensure_exec(dir: &Path) -> Result<()> {
    let noexec = mount_is_noexec(dir).with_context(|| format!("read the mount flags of {}", dir.display()))?;
    if noexec {
        anyhow::bail!(
            "{} is on a noexec mount ({}): the sandboxed client cannot load the native libraries it \
             extracts to its temp dir there. Set {TMPDIR_VAR} to a directory of your own on a mount \
             that allows exec (not under /tmp, which every sandboxed run can write), or pass \
             --sandbox off to launch unconfined",
            dir.display(),
            mount_point(dir).display()
        );
    }
    Ok(())
}

/// Whether the filesystem holding `path` is mounted `noexec`.
#[cfg(target_os = "linux")]
fn mount_is_noexec(path: &Path) -> std::io::Result<bool> {
    let c = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str()))?;
    // SAFETY: statvfs(3) fills the zeroed struct it is handed; `c` outlives the call.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(st.f_flag & libc::ST_NOEXEC != 0)
}

/// Whether the filesystem holding `path` is mounted `noexec`.
#[cfg(target_os = "macos")]
fn mount_is_noexec(path: &Path) -> std::io::Result<bool> {
    let c = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str()))?;
    // SAFETY: statfs(2) fills the zeroed struct it is handed; `c` outlives the call.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(st.f_flags & (libc::MNT_NOEXEC as u32) != 0)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn mount_is_noexec(_path: &Path) -> std::io::Result<bool> {
    Ok(false)
}

/// The mount point holding `path` (canonical): the longest mount point in the
/// mount table that contains it — a bind mount or a subvolume shares its
/// device with what it is mounted over, so `st_dev` cannot tell.
#[cfg(target_os = "linux")]
fn mount_point(path: &Path) -> PathBuf {
    let table = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    longest_mount_point(&table, path).unwrap_or_else(|| path.to_path_buf())
}

/// The mount point holding `path`, as `statfs` reports it.
#[cfg(target_os = "macos")]
fn mount_point(path: &Path) -> PathBuf {
    let Ok(c) = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str())) else {
        return path.to_path_buf();
    };
    // SAFETY: statfs(2) fills the zeroed struct it is handed; `c` outlives the call,
    // and `f_mntonname` is NUL-terminated by the kernel.
    unsafe {
        let mut st: libc::statfs = std::mem::zeroed();
        if libc::statfs(c.as_ptr(), &mut st) != 0 {
            return path.to_path_buf();
        }
        let name = std::ffi::CStr::from_ptr(st.f_mntonname.as_ptr());
        PathBuf::from(<std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(name.to_bytes()))
    }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn mount_point(path: &Path) -> PathBuf {
    path.to_path_buf()
}

/// The longest mount point (field 5 of `/proc/self/mountinfo`, octal escapes
/// decoded) that is `path` or an ancestor of it.
#[cfg(target_os = "linux")]
fn longest_mount_point(mountinfo: &str, path: &Path) -> Option<PathBuf> {
    mountinfo
        .lines()
        .filter_map(|line| line.split(' ').nth(4))
        .map(|field| PathBuf::from(unescape_octal(field)))
        .filter(|mount| path.starts_with(mount))
        .max_by_key(|mount| mount.components().count())
}

/// Decode the kernel's `\ooo` escapes (space, tab, newline, backslash).
#[cfg(target_os = "linux")]
fn unescape_octal(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && let Some(code) = field.get(i + 1..i + 4).and_then(|o| u8::from_str_radix(o, 8).ok())
        {
            out.push(code);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn test_root(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("ss-scratch-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    /// A directory the test binary itself runs from allows exec by construction.
    fn exec_capable_dir() -> PathBuf {
        std::env::current_exe().unwrap().parent().unwrap().to_path_buf()
    }

    #[test]
    fn each_run_gets_its_own_private_dir_removed_with_it() {
        use std::os::unix::fs::PermissionsExt;
        let root = exec_capable_dir().join(format!("ss-scratch-own-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let a = ScratchDir::create_in(&root).unwrap();
        let b = ScratchDir::create_in(&root).unwrap();
        assert_ne!(a.path(), b.path());
        for s in [&a, &b] {
            assert!(s.path().starts_with(dunce::canonicalize(&root).unwrap()));
            let mode = std::fs::metadata(s.path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{}", s.path().display());
        }
        // What a client leaves behind, an unwritable directory included, goes too.
        let stuck = a.path().join("stuck");
        std::fs::create_dir_all(stuck.join("inner")).unwrap();
        std::fs::write(stuck.join("inner/lib.so"), b"x").unwrap();
        std::fs::set_permissions(&stuck, std::fs::Permissions::from_mode(0o500)).unwrap();
        let (a_dir, b_dir) = (a.path().to_path_buf(), b.path().to_path_buf());
        drop(a);
        assert!(!a_dir.exists(), "the dropped run's dir survived");
        assert!(b_dir.exists(), "another run's dir was removed");
        drop(b);
        assert!(!b_dir.exists());
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0, "a lock file survived");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn making_a_dir_removable_never_follows_a_symlink_out_of_it() {
        use std::os::unix::fs::PermissionsExt;
        let root = test_root("walk");
        let (dir, outside) = (root.join("run"), root.join("outside"));
        std::fs::create_dir_all(dir.join("stuck/inner")).unwrap();
        std::fs::create_dir_all(outside.join("sub")).unwrap();
        for d in [&outside, &outside.join("sub")] {
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o555)).unwrap();
        }
        std::os::unix::fs::symlink(&outside, dir.join("stuck/link")).unwrap();
        std::fs::set_permissions(dir.join("stuck"), std::fs::Permissions::from_mode(0o500)).unwrap();
        make_dirs_writable(&dir);
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        // Positive control: the dir's own unwritable directory was changed.
        assert_eq!(mode(&dir.join("stuck")), 0o700);
        assert_eq!(mode(&outside), 0o555, "a symlinked directory outside was changed");
        assert_eq!(mode(&outside.join("sub")), 0o555, "the walk went through a symlink");
        for d in [&outside, &outside.join("sub")] {
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_scratch_root_others_can_write_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let root = test_root("shared");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = ensure_private(&root).unwrap_err().to_string();
        assert!(err.contains("not private to you"), "{err}");
        // Positive control: the same root, made private, is accepted.
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        ensure_private(&root).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_symlinked_root_is_refused_and_its_target_untouched() {
        let base = exec_capable_dir().join(format!("ss-scratch-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let victim = base.join("victim");
        std::fs::create_dir_all(victim.join("projects")).unwrap();
        std::os::unix::fs::symlink(&victim, base.join("root")).unwrap();
        let err = ScratchDir::create_in(&base.join("root")).err().expect("a symlinked root was used").to_string();
        assert!(err.contains("symbolic link"), "{err}");
        assert!(victim.join("projects").exists(), "the link's target was pruned");
        // Positive control: a real directory there is used.
        std::fs::remove_file(base.join("root")).unwrap();
        drop(ScratchDir::create_in(&base.join("root")).unwrap());
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn a_runs_trust_bundle_sits_beside_its_dir_private_and_goes_with_it() {
        use std::os::unix::fs::PermissionsExt;
        let root = exec_capable_dir().join(format!("ss-scratch-ca-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let s = ScratchDir::create_in(&root).unwrap();
        let path = s.write_ca_bundle(b"PEM").unwrap();
        // Beside the run's dir, never in it: the run's grant does not reach it.
        assert_eq!(path.parent(), Some(s.root()));
        assert!(!path.starts_with(s.path()), "{}", path.display());
        assert_eq!(std::fs::read(&path).unwrap(), b"PEM");
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        drop(s);
        assert!(!path.exists(), "the run's trust bundle outlived it");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_start_prunes_a_dead_runs_dir_and_keeps_a_live_ones() {
        let root = test_root("prune");
        std::fs::create_dir_all(&root).unwrap();
        // Dead: its lock is free. Dead too: a dir whose lock is gone.
        std::fs::create_dir_all(root.join("0000dead/x")).unwrap();
        std::fs::write(root.join("0000dead.lock"), b"").unwrap();
        std::fs::write(root.join("0000dead.pem"), b"").unwrap();
        std::fs::create_dir_all(root.join("1111aaaa")).unwrap();
        // Not a run's name: never touched, lock or not.
        std::fs::create_dir_all(root.join("not-a-run")).unwrap();
        // Live: its lock is held (by this process, through its own open file).
        std::fs::create_dir_all(root.join("2222beef")).unwrap();
        let live = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join("2222beef.lock"))
            .unwrap();
        assert!(try_lock(&live).unwrap());
        prune_dead_runs(&root);
        assert!(!root.join("0000dead").exists());
        assert!(!root.join("0000dead.lock").exists());
        assert!(!root.join("0000dead.pem").exists(), "a dead run's trust bundle survived");
        assert!(!root.join("1111aaaa").exists());
        assert!(root.join("2222beef").exists(), "a live run's dir was pruned");
        assert!(root.join("2222beef.lock").exists());
        assert!(root.join("not-a-run").exists(), "an entry not named as a run was pruned");
        // Positive control: the same entry goes once its run is gone. Unlock
        // rather than only close: a child another test forks shares the open
        // file until its exec, and would hold the lock past a plain drop.
        use std::os::fd::AsRawFd;
        // SAFETY: flock(2) on a descriptor this test owns; no memory.
        assert_eq!(unsafe { libc::flock(live.as_raw_fd(), libc::LOCK_UN) }, 0);
        drop(live);
        prune_dead_runs(&root);
        assert!(!root.join("2222beef").exists());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_pin_names_the_run_dir_in_every_temp_variable_and_overrides_an_inherited_one() {
        let root = exec_capable_dir().join(format!("ss-scratch-pin-{}", std::process::id()));
        let s = ScratchDir::create_in(&root).unwrap();
        let mut env = vec![
            ("BUN_TMPDIR".to_string(), "/home/u/tmp".to_string()),
            ("TMPDIR".to_string(), "/tmp".to_string()),
        ];
        s.pin_env(&mut env);
        let want = s.path().to_string_lossy().into_owned();
        for k in ["TMPDIR", "TMP", "TEMP", "BUN_TMPDIR"] {
            // `Command::env` keeps the last value of a key.
            let last = env.iter().rev().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
            assert_eq!(last, Some(want.as_str()), "{k}");
        }
        drop(s);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_root_follows_xdg_cache_home_and_nothing_else() {
        let home = Path::new("/home/u");
        let root = |x: Option<&str>| crate::state::cache_dir_in(x.map(Into::into), &home.join(".cache/streamscopeai")).join("tmp");
        assert_eq!(root(None), PathBuf::from("/home/u/.cache/streamscopeai/tmp"));
        assert_eq!(root(Some("/xdg/cache")), PathBuf::from("/xdg/cache/streamscopeai/tmp"));
        // The XDG spec makes a relative value invalid.
        assert_eq!(root(Some("relative/cache")), PathBuf::from("/home/u/.cache/streamscopeai/tmp"));
        assert_eq!(root(Some("")), PathBuf::from("/home/u/.cache/streamscopeai/tmp"));
    }

    #[test]
    fn streamscope_tmpdir_moves_the_root_to_a_per_user_dir_in_it() {
        let at = |v: Option<&str>| scratch_override(v.map(Into::into), 1000);
        assert_eq!(at(Some("/tmp")).unwrap(), Some(PathBuf::from("/tmp/streamscope-1000")));
        assert_eq!(at(Some("/data/x")).unwrap(), Some(PathBuf::from("/data/x/streamscope-1000")));
        // Unset or empty: the cache's root.
        assert_eq!(at(None).unwrap(), None);
        assert_eq!(at(Some("")).unwrap(), None);
        // A relative value would follow the cwd, inside the project grant.
        assert!(at(Some("rel/tmp")).is_err());
    }

    #[test]
    fn an_exec_capable_dir_is_accepted() {
        ensure_exec(&exec_capable_dir()).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_mount_named_is_the_longest_mount_point_holding_the_dir() {
        // A bind mount of `/home` shares `/`'s device; the table still names it.
        let table = "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
                     30 22 8:1 /home /home rw,noexec - ext4 /dev/sda1 rw\n\
                     31 22 0:5 / /home/u/my\\040cache rw - tmpfs t rw\n\
                     32 22 0:6 / /homework rw - tmpfs t rw\n";
        let at = |p: &str| longest_mount_point(table, Path::new(p));
        assert_eq!(at("/home/u/.cache/streamscopeai/tmp/1-ab"), Some(PathBuf::from("/home")));
        assert_eq!(at("/home/u/my cache/x"), Some(PathBuf::from("/home/u/my cache")));
        // Component-wise: `/homework` does not hold `/home/u`, nor `/home` `/homework`.
        assert_eq!(at("/homework/x"), Some(PathBuf::from("/homework")));
        assert_eq!(at("/var/x"), Some(PathBuf::from("/")));
    }

    #[test]
    fn every_process_the_run_starts_holds_its_lock() {
        use std::os::fd::AsRawFd;
        let root = exec_capable_dir().join(format!("ss-scratch-inherit-{}", std::process::id()));
        let s = ScratchDir::create_in(&root).unwrap();
        // SAFETY: F_GETFD reads the descriptor flags of a file `s` owns.
        let flags = unsafe { libc::fcntl(s._lock.as_raw_fd(), libc::F_GETFD) };
        assert_eq!(flags & libc::FD_CLOEXEC, 0, "the lock is closed on exec");
        drop(s);
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// procfs is mounted `noexec` on every Linux system.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_dir_on_a_noexec_mount_is_refused_naming_the_mount() {
        let err = ensure_exec(Path::new("/proc")).unwrap_err().to_string();
        assert!(err.contains("noexec mount (/proc)"), "{err}");
        assert!(err.contains("STREAMSCOPE_TMPDIR"), "{err}");
    }
}

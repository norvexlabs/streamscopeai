//! The exit sweep (`ssai __sandbox-sweep <root>`, run under `podman
//! unshare`): give back to the developer what the container's root wrote in
//! the project, and take setuid and setgid off what its other users wrote.
//!
//! Under `podman unshare` the developer is uid 0 and the subordinate range is
//! 1..=N. Under keep-id the container's root — the agent's `sudo`, an inner
//! engine and its containers' root — is uid 1 and gid 1 there; for a root agent
//! it is the developer. The launcher names it ([`Root`]) for each id apart:
//! an agent whose group is 0 has the developer's group as its root group. The
//! container's root's id is handed to 0 with `lchown`, which on a regular file
//! also clears setuid (and setgid with group-exec): a planted setuid binary
//! becomes an ordinary file of the developer's. A file of the container's
//! other users (an inner postgres's data directory, uid 999) keeps its owner,
//! so the service still owns it on the next run; only its setuid and setgid
//! bits are cleared. Any other id is left: the developer's own, and an unmapped
//! one — another host user's file, or a developer's file in a non-primary
//! group — which reads as the overflow id.
//!
//! The walk holds directory descriptors (`openat` with `O_NOFOLLOW`) and
//! makes every change relative to the entry's parent descriptor, so a symlink
//! is never followed — not at an entry, not at a directory a live container
//! swaps for one during the walk. It never leaves the project's filesystem (a
//! mount point or subvolume under it is not crossed) and stops after
//! [`MAX_ENTRIES`], saying so. It is idempotent: the launcher runs it after a
//! run, and the next run runs it for a run killed before it could.

use std::ffi::{CStr, CString, OsStr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use anyhow::{bail, Context, Result};

/// The most entries one sweep visits.
pub const MAX_ENTRIES: usize = 2_000_000;

/// What a sweep did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Swept {
    pub visited: usize,
    /// Entries changed: given back, or their setuid/setgid cleared.
    pub given_back: usize,
    /// Entries whose change was refused.
    pub left: usize,
    /// The walk stopped at [`MAX_ENTRIES`].
    pub cut: bool,
}

/// The container's root, as ids of the `podman unshare` namespace; `None`
/// where it is the developer's own id.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Root {
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}

impl Root {
    /// For the agent at `uid:gid`. A root agent (uid 0) runs without keep-id
    /// (`plan::agent_is_root`): rootless podman's own map makes the container's
    /// root the developer on both sides. Under keep-id the container's root
    /// id is the first subordinate one (1), unless the agent's gid is 0 — then
    /// the developer's group is the container's root group.
    pub fn for_agent(uid: u32, gid: u32) -> Self {
        if uid == 0 {
            return Self::default();
        }
        Self { uid: Some(1), gid: (gid != 0).then_some(1) }
    }

    /// As a run dir records it: `<uid>:<gid>`, a side empty for `None`.
    pub fn record(&self) -> String {
        let id = |i: Option<u32>| i.map(|i| i.to_string()).unwrap_or_default();
        format!("{}:{}", id(self.uid), id(self.gid))
    }

    /// Read back what [`Root::record`] wrote; `None` when it does not parse.
    pub fn parse(text: &str) -> Option<Self> {
        let (u, g) = text.trim().split_once(':')?;
        let id = |s: &str| if s.is_empty() { Some(None) } else { s.parse().ok().map(Some) };
        Some(Self { uid: id(u)?, gid: id(g)? })
    }

    /// The sweep's options naming it.
    pub fn args(&self) -> Vec<String> {
        let mut a = Vec::new();
        if let Some(u) = self.uid {
            a.push(format!("--container-root-uid={u}"));
        }
        if let Some(g) = self.gid {
            a.push(format!("--container-root-gid={g}"));
        }
        a
    }
}

/// The ids of the sweep's namespace: the subordinate ones are `1..=uid_max`
/// (`1..=gid_max`), less the overflow id an unmapped one reads as; the
/// container's root among them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ids {
    pub uid_max: u32,
    pub gid_max: u32,
    pub overflow_uid: u32,
    pub overflow_gid: u32,
    pub root: Root,
}

impl Ids {
    /// The highest id a `/proc/self/{uid,gid}_map` maps (`inside outside
    /// count` lines); 0 when it maps only the developer.
    pub fn highest(map: &str) -> u32 {
        map_lines(map).filter(|&(_, _, n)| n > 0).map(|(i, _, n)| (i + n - 1).min(u64::from(u32::MAX)) as u32).max().unwrap_or(0)
    }

    fn subordinate(id: u32, max: u32, overflow: u32) -> bool {
        id != 0 && id <= max && id != overflow
    }
}

fn map_lines(map: &str) -> impl Iterator<Item = (u64, u64, u64)> + '_ {
    map.lines().filter_map(|l| {
        let mut f = l.split_whitespace().map(|n| n.parse::<u64>().ok());
        match (f.next(), f.next(), f.next()) {
            (Some(Some(i)), Some(Some(o)), Some(Some(n))) => Some((i, o, n)),
            _ => None,
        }
    })
}

/// Whether a `uid_map` is the initial namespace's (inside id 0 is outside id
/// 0): not under `podman unshare`, where every host uid would read as a
/// subordinate one.
pub fn is_initial_namespace(map: &str) -> bool {
    map_lines(map).any(|(i, o, n)| i == 0 && o == 0 && n > 0)
}

/// One change the sweep makes to an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// `lchown` the ids given (`None` keeps one) to the developer.
    GiveBack { uid: Option<u32>, gid: Option<u32> },
    /// A regular file of a container user: `mode` without setuid/setgid.
    ClearSetid { mode: u32 },
}

/// What the sweep decides for an entry with `uid`, `gid` and `mode`.
pub fn decide(ids: Ids, uid: u32, gid: u32, mode: u32, regular: bool) -> Option<Change> {
    let root_uid = ids.root.uid == Some(uid) && Ids::subordinate(uid, ids.uid_max, ids.overflow_uid);
    let root_gid = ids.root.gid == Some(gid) && Ids::subordinate(gid, ids.gid_max, ids.overflow_gid);
    if root_uid || root_gid {
        return Some(Change::GiveBack { uid: root_uid.then_some(0), gid: root_gid.then_some(0) });
    }
    let container_user = Ids::subordinate(uid, ids.uid_max, ids.overflow_uid)
        || Ids::subordinate(gid, ids.gid_max, ids.overflow_gid);
    (container_user && regular && mode & 0o6000 != 0).then_some(Change::ClearSetid { mode: mode & 0o7777 & !0o6000 })
}

/// An entry to change: its parent directory's descriptor and its name in it
/// (empty for the root itself, changed through its own descriptor), and its
/// path, for what is reported.
pub struct Entry<'a> {
    pub dir: &'a OwnedFd,
    pub name: &'a CStr,
    pub path: &'a Path,
}

/// The change a sweep makes to an entry.
pub type Apply<'a> = dyn FnMut(&Entry, Change) -> std::io::Result<()> + 'a;

const OPEN_DIR: libc::c_int = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

fn cstr(name: &OsStr) -> std::io::Result<CString> {
    CString::new(name.as_bytes()).map_err(std::io::Error::other)
}

fn stat_at(dir: &OwnedFd, name: &CStr, flags: libc::c_int) -> std::io::Result<libc::stat> {
    // SAFETY: a zeroed `stat` is a valid out-buffer; the fd and name are valid.
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstatat(dir.as_raw_fd(), name.as_ptr(), &mut st, flags) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(st)
    }
}

fn open_at(dir: libc::c_int, name: &CStr) -> std::io::Result<OwnedFd> {
    // SAFETY: a valid fd and C name; the returned fd is owned here.
    let fd = unsafe { libc::openat(dir, name.as_ptr(), OPEN_DIR) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` was just opened and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// A directory being read: its entries' names, one at a time (`.` and `..`
/// left out), so one huge directory is never held whole.
struct Listing(*mut libc::DIR);

impl Listing {
    fn open(dir: &OwnedFd) -> std::io::Result<Self> {
        // SAFETY: the dup is owned by the DIR stream, which closedir releases.
        unsafe {
            let dup = libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0);
            if dup < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let stream = libc::fdopendir(dup);
            if stream.is_null() {
                let e = std::io::Error::last_os_error();
                libc::close(dup);
                return Err(e);
            }
            Ok(Self(stream))
        }
    }
}

impl Iterator for Listing {
    type Item = CString;

    fn next(&mut self) -> Option<CString> {
        loop {
            // SAFETY: an open DIR stream; the name is copied before the next read.
            let name = unsafe {
                let ent = libc::readdir(self.0);
                if ent.is_null() {
                    return None;
                }
                CStr::from_ptr((*ent).d_name.as_ptr()).to_owned()
            };
            if name.to_bytes() != b"." && name.to_bytes() != b".." {
                return Some(name);
            }
        }
    }
}

impl Drop for Listing {
    fn drop(&mut self) {
        // SAFETY: the stream was opened by `Listing::open` and is closed once.
        unsafe { libc::closedir(self.0) };
    }
}

/// Sweep `root`, applying each change [`decide`] makes (the real one is
/// [`apply`]).
pub fn sweep(root: &Path, ids: Ids, apply: &mut Apply) -> Result<Swept> {
    let c_root = cstr(root.as_os_str())?;
    let root_fd = Rc::new(open_at(libc::AT_FDCWD, &c_root).with_context(|| format!("{} is not a directory to sweep", root.display()))?);
    let st = stat_at(&root_fd, c"", libc::AT_EMPTY_PATH).with_context(|| format!("read {}", root.display()))?;
    let dev = st.st_dev;
    let mut swept = Swept { visited: 1, ..Swept::default() };
    let mut change = |entry: &Entry, st: &libc::stat, swept: &mut Swept| {
        let regular = st.st_mode & libc::S_IFMT == libc::S_IFREG;
        if let Some(c) = decide(ids, st.st_uid, st.st_gid, st.st_mode, regular) {
            match apply(entry, c) {
                Ok(()) => swept.given_back += 1,
                Err(_) => swept.left += 1,
            }
        }
    };
    change(&Entry { dir: &root_fd, name: c"", path: root }, &st, &mut swept);
    // A directory waiting to be walked holds its parent's descriptor (shared
    // by its siblings) and its name; it is opened only when walked, so the
    // open descriptors stay about the tree's depth, not its width.
    let mut walk = |dir: Rc<OwnedFd>, path: &Path, pending: &mut Vec<(Rc<OwnedFd>, CString, PathBuf)>, swept: &mut Swept| {
        let Ok(listing) = Listing::open(&dir) else {
            swept.left += 1;
            return false;
        };
        for name in listing {
            if swept.visited + pending.len() >= MAX_ENTRIES {
                swept.cut = true;
                return true;
            }
            swept.visited += 1;
            let Ok(st) = stat_at(&dir, &name, libc::AT_SYMLINK_NOFOLLOW) else {
                swept.left += 1;
                continue;
            };
            let child = path.join(OsStr::from_bytes(name.to_bytes()));
            change(&Entry { dir: &dir, name: &name, path: &child }, &st, swept);
            if st.st_mode & libc::S_IFMT == libc::S_IFDIR && st.st_dev == dev {
                pending.push((dir.clone(), name, child));
            }
        }
        false
    };
    let mut pending = Vec::new();
    if walk(root_fd, root, &mut pending, &mut swept) {
        return Ok(swept);
    }
    while let Some((parent, name, path)) = pending.pop() {
        // Opened without following a symlink, and only on the project's
        // filesystem: a directory swapped since its stat is not entered.
        let opened = open_at(parent.as_raw_fd(), &name)
            .ok()
            .filter(|fd| stat_at(fd, c"", libc::AT_EMPTY_PATH).is_ok_and(|s| s.st_dev == dev));
        let Some(fd) = opened else {
            swept.left += 1;
            continue;
        };
        drop(parent);
        if walk(Rc::new(fd), &path, &mut pending, &mut swept) {
            break;
        }
    }
    Ok(swept)
}

/// Make `change` to `entry`, relative to its parent's descriptor, never
/// through a symlink.
pub fn apply(entry: &Entry, change: Change) -> std::io::Result<()> {
    let (dir, name) = (entry.dir.as_raw_fd(), entry.name.as_ptr());
    let empty = entry.name.is_empty();
    // SAFETY: a valid fd and C name; AT_SYMLINK_NOFOLLOW never follows one,
    // AT_EMPTY_PATH changes the descriptor's own directory (the root).
    let rc = unsafe {
        match change {
            Change::GiveBack { uid, gid } => libc::fchownat(
                dir,
                name,
                uid.unwrap_or(u32::MAX),
                gid.unwrap_or(u32::MAX),
                if empty { libc::AT_EMPTY_PATH } else { libc::AT_SYMLINK_NOFOLLOW },
            ),
            // Only a regular file is cleared, never the root directory.
            Change::ClearSetid { mode } => libc::fchmodat(dir, name, mode as libc::mode_t, libc::AT_SYMLINK_NOFOLLOW),
        }
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// The hidden subcommand's body: sweep `root`, print one summary line when
/// something was changed or left.
pub fn main(root: &Path, container_root: Root) -> Result<()> {
    let read = |f: &str| std::fs::read_to_string(f).with_context(|| format!("read {f}"));
    let uid_map = read("/proc/self/uid_map")?;
    if is_initial_namespace(&uid_map) {
        bail!("__sandbox-sweep runs only under `podman unshare`");
    }
    let overflow = |f: &str| read(f).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(65_534);
    let ids = Ids {
        uid_max: Ids::highest(&uid_map),
        gid_max: Ids::highest(&read("/proc/self/gid_map")?),
        overflow_uid: overflow("/proc/sys/kernel/overflowuid"),
        overflow_gid: overflow("/proc/sys/kernel/overflowgid"),
        root: container_root,
    };
    // The first few entries left, to name them.
    let mut left = Vec::new();
    let swept = sweep(root, ids, &mut |e, c| {
        apply(e, c).inspect_err(|_| {
            if left.len() < 3 {
                left.push(e.path.display().to_string());
            }
        })
    })?;
    if swept.given_back > 0 || swept.left > 0 || swept.cut {
        eprintln!(
            "ssai: sandbox sweep of {}: {} file(s) given back to you, {} left{}{}",
            root.display(),
            swept.given_back,
            swept.left,
            if left.is_empty() { String::new() } else { format!(" ({}{})", left.join(", "), if swept.left > 3 { ", …" } else { "" }) },
            if swept.cut { " (stopped early: too many files — some may still be the container's)" } else { "" }
        );
    }
    // Not done: the launcher keeps the run's record, so a later run tries again.
    if swept.left > 0 || swept.cut {
        bail!("the sweep of {} is not complete", root.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    const KEEP_ID: Root = Root { uid: Some(1), gid: Some(1) };
    /// The usual shape: a 65536-id subordinate range, which holds the
    /// overflow id 65534.
    const IDS: Ids = Ids { uid_max: 65_536, gid_max: 65_536, overflow_uid: 65_534, overflow_gid: 65_534, root: KEEP_ID };
    const FILE: u32 = 0o100_644;

    #[test]
    fn the_containers_root_is_given_back_each_id_on_its_own() {
        assert_eq!(decide(IDS, 1, 1, FILE, true), Some(Change::GiveBack { uid: Some(0), gid: Some(0) }));
        assert_eq!(decide(IDS, 1, 0, FILE, true), Some(Change::GiveBack { uid: Some(0), gid: None }));
        assert_eq!(decide(IDS, 0, 1, 0o040_755, false), Some(Change::GiveBack { uid: None, gid: Some(0) }));
        // A setuid plant by the container's root: the chown clears the bit.
        assert_eq!(decide(IDS, 1, 1, 0o104_755, true), Some(Change::GiveBack { uid: Some(0), gid: Some(0) }));
        // No subordinate range at all: id 1 is not the container's.
        let none = Ids { uid_max: 0, gid_max: 0, ..IDS };
        assert_eq!(decide(none, 1, 1, FILE, true), None);
    }

    #[test]
    fn a_root_agents_container_users_keep_their_files() {
        // A root agent: the container's root is the developer (id 0), and id 1
        // is the container's `daemon` — a user like any other.
        let root_agent = Ids { root: Root::for_agent(0, 0), ..IDS };
        assert_eq!(decide(root_agent, 1, 1, 0o040_755, false), None);
        assert_eq!(decide(root_agent, 1, 1, 0o104_755, true), Some(Change::ClearSetid { mode: 0o755 }));
        assert_eq!(decide(root_agent, 0, 0, 0o104_755, true), None, "its root's own files are the developer's");
        // Its gid does not matter: no keep-id map, the container's root is
        // the developer on both sides.
        assert_eq!(Root::for_agent(0, 1000), Root::default());
        assert_eq!(Root::for_agent(1000, 1000), KEEP_ID);
    }

    #[test]
    fn an_agent_in_group_0_has_the_developers_group_as_its_root_group() {
        // `1001:0` (an image whose user is in the root group): the container's
        // root uid is 1, its root gid the developer's; gid 1 is `daemon`'s.
        let ids = Ids { root: Root::for_agent(1001, 0), ..IDS };
        assert_eq!(ids.root, Root { uid: Some(1), gid: None });
        assert_eq!(decide(ids, 1, 1, FILE, true), Some(Change::GiveBack { uid: Some(0), gid: None }));
        assert_eq!(decide(ids, 999, 1, 0o102_755, true), Some(Change::ClearSetid { mode: 0o755 }));
        assert_eq!(decide(ids, 999, 1, FILE, true), None, "a daemon-group file keeps its group");
    }

    #[test]
    fn a_container_users_file_keeps_its_owner_and_loses_only_setid() {
        // An inner postgres's data: kept as it is.
        assert_eq!(decide(IDS, 999, 999, 0o040_700, false), None);
        assert_eq!(decide(IDS, 999, 999, FILE, true), None);
        // Its setuid / setgid bits go; the rest of the mode stays.
        assert_eq!(decide(IDS, 999, 999, 0o106_755, true), Some(Change::ClearSetid { mode: 0o755 }));
        assert_eq!(decide(IDS, 0, 999, 0o102_750, true), Some(Change::ClearSetid { mode: 0o750 }));
        // A directory's setgid (group inheritance) is not a privilege: kept.
        assert_eq!(decide(IDS, 999, 999, 0o042_775, false), None);
        // The range's edges: its last id is a container user's, one past it is not.
        assert_eq!(decide(IDS, 65_536, 0, 0o104_755, true), Some(Change::ClearSetid { mode: 0o755 }));
        assert_eq!(decide(IDS, 65_537, 0, 0o104_755, true), None);
    }

    #[test]
    fn the_developers_own_and_an_unmapped_id_are_left() {
        assert_eq!(decide(IDS, 0, 0, 0o104_755, true), None, "the developer's own setuid file");
        // A developer's file in a shared group (unmapped: the overflow gid),
        // setgid included — the developer's, not the container's.
        assert_eq!(decide(IDS, 0, 65_534, 0o102_755, true), None);
        assert_eq!(decide(IDS, 65_534, 65_534, 0o104_755, true), None, "another host user's file");
    }

    #[test]
    fn the_maps_are_read_and_the_initial_namespace_refused() {
        let unshare = "         0       1000          1\n         1     100000      65536\n";
        assert_eq!(Ids::highest(unshare), 65_536);
        assert_eq!(Ids::highest("0 1000 1\n"), 0, "only the developer mapped");
        assert_eq!(Ids::highest(""), 0);
        assert_eq!(Ids::highest("0 0 4294967295\n"), u32::MAX - 1);
        assert!(!is_initial_namespace(unshare));
        assert!(is_initial_namespace("         0          0 4294967295\n"));
    }

    #[test]
    fn the_root_reads_back_as_recorded() {
        for root in [KEEP_ID, Root::default(), Root { uid: Some(1), gid: None }] {
            assert_eq!(Root::parse(&root.record()), Some(root));
        }
        assert_eq!(Root::parse("x:1"), None);
        assert_eq!(Root::parse(""), None);
        assert_eq!(KEEP_ID.args(), ["--container-root-uid=1", "--container-root-gid=1"]);
        assert!(Root::default().args().is_empty());
    }

    fn tree() -> PathBuf {
        let root = std::env::temp_dir().join(format!("ssai-sweep-test-{}-{}", std::process::id(), rand::random::<u32>()));
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        std::fs::write(root.join("a/b/f"), "x").unwrap();
        std::fs::write(root.join("top"), "x").unwrap();
        root
    }

    // SAFETY: getuid(2) cannot fail.
    fn me() -> u32 {
        unsafe { libc::getuid() }
    }

    /// The test's own uid stands for a container user: a setuid file of its
    /// is the one change asked for.
    fn ids_for_me() -> Ids {
        Ids { uid_max: me(), gid_max: 0, overflow_uid: 65_534, overflow_gid: 65_534, root: Root::default() }
    }

    #[test]
    fn the_walk_visits_every_entry_and_never_follows_a_symlink() {
        if me() == 0 {
            return;
        }
        let root = tree();
        let outside = std::env::temp_dir().join(format!("ssai-sweep-outside-{}", std::process::id()));
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret"), "x").unwrap();
        std::fs::set_permissions(outside.join("secret"), PermissionsExt::from_mode(0o4755)).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        std::fs::set_permissions(root.join("a/b/f"), PermissionsExt::from_mode(0o4755)).unwrap();
        let mut asked = BTreeMap::new();
        let swept = sweep(&root, ids_for_me(), &mut |e, c| {
            asked.insert(e.path.strip_prefix(&root).unwrap().to_path_buf(), c);
            Ok(())
        })
        .unwrap();
        assert_eq!(asked, BTreeMap::from([(PathBuf::from("a/b/f"), Change::ClearSetid { mode: 0o755 })]));
        assert_eq!(swept.visited, 6, "the root, a, a/b, a/b/f, top and the link — not the link's target");
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn a_change_lands_on_the_entry_and_a_refused_one_is_counted() {
        if me() == 0 {
            return;
        }
        let root = tree();
        for f in ["top", "a/b/f"] {
            std::fs::set_permissions(root.join(f), PermissionsExt::from_mode(0o6755)).unwrap();
        }
        // The real change, through the parent descriptor.
        let swept = sweep(&root, ids_for_me(), &mut |e, c| {
            if e.path.ends_with("top") { Err(std::io::Error::from_raw_os_error(libc::EPERM)) } else { apply(e, c) }
        })
        .unwrap();
        assert_eq!((swept.given_back, swept.left), (1, 1));
        assert_eq!(std::fs::metadata(root.join("a/b/f")).unwrap().mode() & 0o7777, 0o755);
        assert_eq!(std::fs::metadata(root.join("top")).unwrap().mode() & 0o7777, 0o6755, "the refused one is untouched");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_directory_swapped_for_a_symlink_mid_walk_is_not_followed() {
        if me() == 0 {
            return;
        }
        let root = tree();
        let outside = std::env::temp_dir().join(format!("ssai-sweep-swap-{}-{}", std::process::id(), rand::random::<u32>()));
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("f"), "x").unwrap();
        std::fs::set_permissions(outside.join("f"), PermissionsExt::from_mode(0o4755)).unwrap();
        std::fs::set_permissions(root.join("a/b/f"), PermissionsExt::from_mode(0o4755)).unwrap();
        // On the first change asked for, swap `a/b` (already open) for a link
        // to `outside`, then make the change: it lands in the directory the
        // walk opened, never through the link.
        let (r, o) = (root.clone(), outside.clone());
        let mut swapped = false;
        sweep(&root, ids_for_me(), &mut |e, c| {
            if !swapped {
                swapped = true;
                std::fs::rename(r.join("a/b"), r.join("a/moved")).unwrap();
                std::os::unix::fs::symlink(&o, r.join("a/b")).unwrap();
            }
            apply(e, c)
        })
        .unwrap();
        assert_eq!(std::fs::metadata(outside.join("f")).unwrap().mode() & 0o7777, 0o4755, "the link's target is untouched");
        assert_eq!(std::fs::metadata(root.join("a/moved/f")).unwrap().mode() & 0o7777, 0o755, "the walked file is cleared");
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn a_file_root_is_refused() {
        let root = tree();
        assert!(sweep(&root.join("top"), IDS, &mut |_, _| Ok(())).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }
}

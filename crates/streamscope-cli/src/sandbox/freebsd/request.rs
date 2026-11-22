//! What `ssai run` asks the jail daemon for, and the daemon's check of it.
//!
//! The daemon runs as root and answers every local user, so the request is
//! untrusted input: the only identity is the peer uid the kernel reports
//! (`getpeereid`), never a field of the request. Two checks stand between a
//! request and a mount:
//!
//! - [`check_shape`], pure: every path absolute and lexically clean, nothing
//!   that is or holds a directory the jail builds itself (`/`, `/usr`, `/dev`,
//!   `/var`, …), nothing under the daemon's own state, held paths only inside
//!   a writable grant, bounded counts and lengths.
//! - [`walk`], over the filesystem AS THE PEER (the daemon walks in a child
//!   that has dropped to the peer's uid and groups, so the kernel decides
//!   every search permission): each path opened one component at a time from
//!   `/` without following a link — a symbolic link anywhere refuses the path —
//!   ending on a directory or a regular file, and a writable grant's last
//!   component owned by the peer. What it returns is the open file: the mount
//!   is made from it, never by resolving the path again.
//!
//! Claim (locked by `no_accepted_grant_crosses_a_link_or_writes_what_the_peer_does_not_own`):
//! no grant [`walk`] accepts reaches its target through a symbolic link, and
//! no writable grant it accepts names something the peer does not own. Not
//! claimed: that a read-only grant names something the peer owns — reading
//! is what the peer can already do on the host, which the kernel decides.

use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The wire protocol both sides speak. A daemon of another protocol is
/// refused by the CLI (and the CLI by it), naming `ssai sandbox setup`.
#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
pub const PROTOCOL: u32 = 1;

/// How many grants, and how many held paths, one run may ask for.
pub const MAX_GRANTS: usize = 256;
pub const MAX_HELD: usize = 4096;
/// The longest path accepted, in bytes (FreeBSD's `MNAMELEN` is 1024).
pub const MAX_PATH: usize = 900;

/// The directories the daemon mounts in every jail itself, read-only from
/// the host. No grant may be one of them or hold one.
pub const SYSTEM_MOUNTS: &[&str] = &["/bin", "/sbin", "/lib", "/libexec", "/usr", "/etc", "/compat"];

/// Other directories the jail builds or keeps out: no grant may be one of
/// them or hold one; nothing under `/dev` or `/proc` may be granted.
const RESERVED: &[&str] = &["/dev", "/tmp", "/var", "/proc", "/boot", "/rescue", STAGE];
const NOTHING_UNDER: &[&str] = &["/dev", "/proc", STAGE];

/// The jail's root-only staging folder: no grant is mounted at or under it.
pub const STAGE: &str = "/.ssai-stage";

/// The daemon's own state (its socket among it): never in a jail.
pub const STATE_DIR: &str = "/var/run/ssai";

/// A host path mounted into the jail — at the same path, or `at` another:
/// where a link to it is (a `~/.claude` that is a link elsewhere is mounted
/// both where it really is and where the link is).
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(Debug))]
pub struct Grant {
    pub path: PathBuf,
    pub write: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<PathBuf>,
}

impl Grant {
    /// Where it is mounted in the jail.
    pub fn target(&self) -> &Path {
        self.at.as_deref().unwrap_or(&self.path)
    }
}

/// A path inside a writable grant the jail holds as its own mount point:
/// a `node` (a git dir) keeps its contents writable but cannot be renamed or
/// removed; any other is read-only.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(Debug))]
pub struct Held {
    pub path: PathBuf,
    pub node: bool,
}

/// One run's jail.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(Debug))]
pub struct RunRequest {
    pub grants: Vec<Grant>,
    pub held: Vec<Held>,
}

/// Why a request is refused, worded for the developer.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct Refusal(pub String);

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn refuse<T>(why: impl Into<String>) -> Result<T, Refusal> {
    Err(Refusal(why.into()))
}

/// Whether `path` is absolute, without `.`, `..` or an empty component, and
/// within [`MAX_PATH`] bytes.
pub fn is_clean(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() > MAX_PATH || bytes.contains(&0) || !bytes.starts_with(b"/") || bytes.windows(2).any(|w| w == b"//") {
        return false;
    }
    if bytes.len() > 1 && bytes.ends_with(b"/") {
        return false;
    }
    // Split by hand: `Path::components` drops an inner `.` silently.
    bytes[1..].split(|b| *b == b'/').all(|c| bytes.len() == 1 || (c != b"." && c != b".." && !c.is_empty()))
}

/// Whether `p` may be a grant at all: absolute and clean, neither one of
/// the folders the jail builds itself nor holding one, nothing under `/dev`,
/// `/proc` or the daemon's state.
pub fn grantable(p: &Path) -> Result<(), Refusal> {
    if !is_clean(p) {
        return refuse(format!("{} is not an absolute, clean path", p.display()));
    }
    let builds = SYSTEM_MOUNTS.iter().chain(RESERVED).chain(std::iter::once(&STATE_DIR));
    for own in builds {
        if Path::new(own).starts_with(p) {
            return refuse(format!("{} holds {own}, which the sandbox provides itself", p.display()));
        }
    }
    if NOTHING_UNDER.iter().chain(std::iter::once(&STATE_DIR)).any(|d| p.starts_with(d)) {
        return refuse(format!("{} cannot be given to the sandbox", p.display()));
    }
    Ok(())
}

/// The pure check of a request: see the module doc.
pub fn check_shape(req: &RunRequest) -> Result<(), Refusal> {
    if req.grants.len() > MAX_GRANTS {
        return refuse(format!("the run asks for more than {MAX_GRANTS} folders and files"));
    }
    if req.held.len() > MAX_HELD {
        return refuse(format!(
            "the project has more than {MAX_HELD} git paths to hold read-only (its submodules and worktrees)"
        ));
    }
    for g in &req.grants {
        grantable(&g.path)?;
        if let Some(at) = &g.at {
            grantable(at)?;
        }
    }
    for h in &req.held {
        if !is_clean(&h.path) {
            return refuse(format!("{} is not an absolute, clean path", h.path.display()));
        }
        // Strictly inside: holding the grant itself would cover it.
        if !req.grants.iter().any(|g| g.write && h.path.starts_with(g.target()) && h.path != g.target()) {
            return refuse(format!("{} is not inside a writable grant", h.path.display()));
        }
    }
    Ok(())
}

/// What a filesystem entry is, as `fstat` says after an `O_NOFOLLOW` open.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub enum Kind {
    Dir,
    File,
    Other,
}

/// What [`walk`] learns of the last component.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct Meta {
    pub kind: Kind,
    pub uid: u32,
}

/// One step of a walk: open `name` in `dir` without following a link (an
/// error for a link, or for anything the walker may not search or open),
/// and say what it is.
pub trait Walker {
    type Fd;
    fn root(&mut self) -> std::io::Result<Self::Fd>;
    fn step(&mut self, dir: &Self::Fd, name: &OsStr) -> std::io::Result<(Self::Fd, Meta)>;
}

/// Open `grant.path` one component at a time from `/` (see the module doc),
/// as the peer `uid`. Returns the open last component and what it is.
pub fn walk<W: Walker>(w: &mut W, grant: &Grant, uid: u32) -> Result<(W::Fd, Meta), Refusal> {
    let mut at = w.root().map_err(|e| Refusal(format!("open /: {e}")))?;
    let mut meta = Meta { kind: Kind::Dir, uid: 0 };
    let mut walked = PathBuf::from("/");
    let names: Vec<OsString> = grant
        .path
        .components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(n.to_os_string()),
            _ => None,
        })
        .collect();
    if names.is_empty() {
        return refuse("/ cannot be given to the sandbox");
    }
    for (i, name) in names.iter().enumerate() {
        if meta.kind != Kind::Dir {
            return refuse(format!("{} is not a directory", walked.display()));
        }
        walked.push(name);
        let (next, m) = w.step(&at, name).map_err(|e| {
            Refusal(format!(
                "{} cannot be reached without following a link, or not by you ({e})",
                walked.display()
            ))
        })?;
        at = next;
        meta = m;
        let last = i + 1 == names.len();
        if !last && meta.kind != Kind::Dir {
            return refuse(format!("{} is not a directory", walked.display()));
        }
    }
    match meta.kind {
        Kind::Dir | Kind::File => {}
        Kind::Other => return refuse(format!("{} is neither a folder nor a regular file", grant.path.display())),
    }
    if grant.write && meta.uid != uid {
        return refuse(format!("{} is not yours, so it cannot be writable in the sandbox", grant.path.display()));
    }
    Ok((at, meta))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::BTreeMap;

    fn g(p: &str, write: bool) -> Grant {
        Grant { path: PathBuf::from(p), write, at: None }
    }

    #[test]
    fn a_clean_path_is_absolute_and_plain() {
        for ok in ["/", "/home/u", "/home/u/.config/x y"] {
            assert!(is_clean(Path::new(ok)), "{ok}");
        }
        for bad in ["home/u", "/home/../etc", "/home/./u", "/home//u", "/home/u/", ""] {
            assert!(!is_clean(Path::new(bad)), "{bad}");
        }
        assert!(!is_clean(Path::new(&"/a".repeat(MAX_PATH))));
    }

    #[test]
    fn the_shape_refuses_what_the_jail_builds_and_allows_a_project() {
        let ok = RunRequest {
            grants: vec![g("/home/u/p", true), g("/usr/local/lib/node_modules", false)],
            held: vec![Held { path: "/home/u/p/.git".into(), node: true }],
        };
        assert_eq!(check_shape(&ok), Ok(()));
        for bad in ["/", "/usr", "/var", "/var/run", "/var/run/ssai/x", "/dev/mem", "/proc/1", "/compat", "/tmp", "/.ssai-stage", "/.ssai-stage/2"] {
            let r = RunRequest { grants: vec![g(bad, false)], held: vec![] };
            assert!(check_shape(&r).is_err(), "{bad}");
            // Where a grant is mounted is held to the same rules.
            let r = RunRequest { grants: vec![Grant { at: Some(bad.into()), ..g("/home/u/x", false) }], held: vec![] };
            assert!(check_shape(&r).is_err(), "at {bad}");
        }
        // A held path outside every writable grant, or the grant itself.
        for held in ["/home/u/q/.git", "/home/u/p", "/usr/local/lib/node_modules/x"] {
            let r = RunRequest { held: vec![Held { path: held.into(), node: false }], ..ok.clone() };
            assert!(check_shape(&r).is_err(), "{held}");
        }
        let many = RunRequest { grants: vec![g("/home/u/p", true); MAX_GRANTS + 1], held: vec![] };
        assert!(check_shape(&many).is_err());
    }

    #[test]
    fn each_cap_holds_at_its_bound_and_refuses_one_past_it() {
        let grants = |n: usize| (0..n).map(|i| g(&format!("/home/u/p{i}"), true)).collect::<Vec<_>>();
        assert_eq!(check_shape(&RunRequest { grants: grants(MAX_GRANTS), held: vec![] }), Ok(()));
        assert!(check_shape(&RunRequest { grants: grants(MAX_GRANTS + 1), held: vec![] }).is_err());
        let held = |n: usize| (0..n).map(|i| Held { path: format!("/home/u/p0/h{i}").into(), node: false }).collect::<Vec<_>>();
        assert_eq!(check_shape(&RunRequest { grants: grants(1), held: held(MAX_HELD) }), Ok(()));
        assert!(check_shape(&RunRequest { grants: grants(1), held: held(MAX_HELD + 1) }).is_err());
        let at = |len: usize| format!("/{}", "a".repeat(len - 1));
        assert!(is_clean(Path::new(&at(MAX_PATH))));
        assert!(!is_clean(Path::new(&at(MAX_PATH + 1))));
    }

    proptest! {
        /// What `grantable` accepts is clean, neither is nor holds a folder
        /// the jail builds or the daemon's state, and is under none of the
        /// trees nothing may come from. Not claimed: that it exists, or is
        /// the peer's (the walk decides those).
        #[test]
        fn a_grantable_path_is_clean_and_touches_nothing_the_jail_builds(
            parts in proptest::collection::vec(
                prop_oneof![
                    Just("home"), Just("u"), Just("usr"), Just("var"), Just("run"), Just("ssai"), Just("dev"),
                    Just("proc"), Just("tmp"), Just("etc"), Just("compat"), Just("bin"), Just(".ssai-stage"), Just("."), Just(".."), Just(""),
                ],
                0..6,
            ),
        ) {
            let path = PathBuf::from(format!("/{}", parts.join("/")));
            if grantable(&path).is_ok() {
                prop_assert!(is_clean(&path));
                for own in SYSTEM_MOUNTS.iter().chain(RESERVED).chain(std::iter::once(&STATE_DIR)) {
                    prop_assert!(!Path::new(own).starts_with(&path), "{} holds {own}", path.display());
                }
                for d in NOTHING_UNDER.iter().chain(std::iter::once(&STATE_DIR)) {
                    prop_assert!(!path.starts_with(d), "{} is under {d}", path.display());
                }
            }
        }

        /// The positive control: a plain path under a home is grantable.
        #[test]
        fn a_plain_path_under_a_home_is_grantable(parts in proptest::collection::vec("[a-z]{1,8}", 1..5)) {
            let path = PathBuf::from(format!("/home/{}", parts.join("/")));
            prop_assert_eq!(grantable(&path), Ok(()));
        }
    }

    /// A fake filesystem: path → (kind, uid, link), searchable by `peer`
    /// when the mode allows (owner or other search bit).
    #[derive(Debug, Clone)]
    struct Entry {
        kind: Kind,
        uid: u32,
        link: bool,
        other_search: bool,
    }

    struct Fake<'a> {
        tree: &'a BTreeMap<PathBuf, Entry>,
        peer: u32,
    }

    impl Walker for Fake<'_> {
        type Fd = PathBuf;
        fn root(&mut self) -> std::io::Result<PathBuf> {
            Ok(PathBuf::from("/"))
        }
        fn step(&mut self, dir: &PathBuf, name: &OsStr) -> std::io::Result<(PathBuf, Meta)> {
            let denied = || std::io::Error::from(std::io::ErrorKind::PermissionDenied);
            if dir != Path::new("/") {
                let parent = self.tree.get(dir).ok_or_else(denied)?;
                if parent.uid != self.peer && !parent.other_search {
                    return Err(denied());
                }
            }
            let path = dir.join(name);
            let e = self.tree.get(&path).ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
            if e.link {
                // O_NOFOLLOW on a link: EMLINK on FreeBSD.
                return Err(std::io::Error::from_raw_os_error(31));
            }
            Ok((path, Meta { kind: e.kind, uid: e.uid }))
        }
    }

    fn tree_strategy() -> impl Strategy<Value = BTreeMap<PathBuf, Entry>> {
        let entry = (0u8..3, 0u32..3, any::<bool>(), any::<bool>()).prop_map(|(k, uid, link, other)| Entry {
            kind: [Kind::Dir, Kind::File, Kind::Other][k as usize],
            uid,
            link: link && k == 0,
            other_search: other,
        });
        let path = proptest::collection::vec(prop_oneof![Just("a"), Just("b"), Just("c")], 1..5)
            .prop_map(|v| PathBuf::from(format!("/{}", v.join("/"))));
        proptest::collection::btree_map(path, entry, 0..40)
    }

    fn has_link_on_the_way(tree: &BTreeMap<PathBuf, Entry>, path: &Path) -> bool {
        path.ancestors().any(|a| tree.get(a).is_some_and(|e| e.link))
    }

    proptest! {
        #[test]
        fn no_accepted_grant_crosses_a_link_or_writes_what_the_peer_does_not_own(
            tree in tree_strategy(),
            path in proptest::collection::vec(prop_oneof![Just("a"), Just("b"), Just("c")], 1..5),
            write in any::<bool>(),
        ) {
            let peer = 1;
            let grant = Grant { path: PathBuf::from(format!("/{}", path.join("/"))), write, at: None };
            if let Ok((_, meta)) = walk(&mut Fake { tree: &tree, peer }, &grant, peer) {
                prop_assert!(!has_link_on_the_way(&tree, &grant.path));
                prop_assert!(tree.contains_key(&grant.path));
                prop_assert!(meta.kind != Kind::Other);
                if write {
                    prop_assert_eq!(tree[&grant.path].uid, peer);
                }
            }
        }

        /// The positive control: a path of the peer's own folders, no link
        /// on the way, is accepted writable.
        #[test]
        fn a_path_of_the_peers_own_folders_is_accepted(
            path in proptest::collection::vec(prop_oneof![Just("a"), Just("b"), Just("c")], 1..5),
            file in any::<bool>(),
        ) {
            let peer = 1;
            let mut tree = BTreeMap::new();
            let full = PathBuf::from(format!("/{}", path.join("/")));
            for a in full.ancestors().filter(|a| *a != Path::new("/")) {
                let kind = if a == full && file { Kind::File } else { Kind::Dir };
                tree.insert(a.to_path_buf(), Entry { kind, uid: peer, link: false, other_search: false });
            }
            let grant = Grant { path: full, write: true, at: None };
            let accepted = walk(&mut Fake { tree: &tree, peer }, &grant, peer).is_ok();
            prop_assert!(accepted);
            // The same tree with one folder on the way made a link refuses it.
            let first = grant.path.ancestors().filter(|a| *a != Path::new("/")).last().unwrap().to_path_buf();
            tree.get_mut(&first).unwrap().link = true;
            tree.get_mut(&first).unwrap().kind = Kind::Dir;
            let refused = walk(&mut Fake { tree: &tree, peer }, &grant, peer).is_err();
            prop_assert!(refused);
        }
    }

    #[test]
    fn a_writable_grant_of_another_users_folder_is_refused_and_a_readable_one_is_not() {
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("/o"), Entry { kind: Kind::Dir, uid: 2, link: false, other_search: true });
        let peer = 1;
        assert!(walk(&mut Fake { tree: &tree, peer }, &g("/o", true), peer).is_err());
        assert!(walk(&mut Fake { tree: &tree, peer }, &g("/o", false), peer).is_ok());
        // Behind a folder the peer cannot search: refused, read-only too.
        tree.insert(PathBuf::from("/s"), Entry { kind: Kind::Dir, uid: 0, link: false, other_search: false });
        tree.insert(PathBuf::from("/s/x"), Entry { kind: Kind::Dir, uid: 1, link: false, other_search: true });
        assert!(walk(&mut Fake { tree: &tree, peer }, &g("/s/x", false), peer).is_err());
    }
}

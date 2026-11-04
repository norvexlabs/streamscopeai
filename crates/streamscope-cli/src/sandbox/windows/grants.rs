//! The Windows access entries one run of the sandbox account needs, as a
//! plan: pure, so it is tested on every host; `acl.rs` writes it.
//!
//! The account owns nothing and is granted only what the plan lists, by
//! inheritable entries on a folder — never a walk over its files. The
//! entries are written with the access-control API with exact masks: a deny
//! written by `icacls` carries SYNCHRONIZE, which refuses even opening the
//! file to read it (git then cannot read its own config).

// Off Windows this module is compiled for its tests only.
#![cfg_attr(not(windows), allow(dead_code))]

use std::path::{Path, PathBuf};

use crate::sandbox::protect::{Guard, ProjectGrants};

/// Whom an entry is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Trustee {
    /// The sandbox account.
    Account,
    /// `OWNER RIGHTS` (S-1-3-4): what the owner of an object may do with it.
    /// Granted Modify on the project, it takes from a file's creator the
    /// right to change its access list, so the agent cannot lock the
    /// developer out of a file it wrote.
    OwnerRights,
}

/// An entry's rights and reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// Read, write, run, delete — no access-list change, no delete-child —
    /// on the folder and everything in it.
    Modify,
    /// Read and run, on the folder and everything in it.
    ReadExecute,
    /// Read one file.
    ReadFile,
    /// Open the folder and read its attributes — never list or read it —
    /// the folder alone: what Node's `realpath` and git's stat of a parent
    /// need. `SYNCHRONIZE` must stay: a native open of the folder asks for it
    /// (Bun's and libuv's `realpath`), and without it the path does not
    /// resolve, so a client that vouches for every folder above a write
    /// (Claude Code) refuses each file below as one it cannot vouch for.
    ReadAttributes,
    /// Deny: create, change or remove anything in a held tree, or the tree.
    DenyTree,
    /// Deny: change, replace or remove a held file.
    DenyFile,
    /// Deny: remove or rename a held folder (its contents stay writable).
    DenyNode,
}

// File access rights (winnt.h).
const FILE_READ_DATA: u32 = 0x1;
const FILE_WRITE_DATA: u32 = 0x2;
const FILE_APPEND_DATA: u32 = 0x4;
const FILE_READ_EA: u32 = 0x8;
const FILE_WRITE_EA: u32 = 0x10;
const FILE_EXECUTE: u32 = 0x20;
const FILE_DELETE_CHILD: u32 = 0x40;
const FILE_READ_ATTRIBUTES: u32 = 0x80;
const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
const DELETE: u32 = 0x1_0000;
const READ_CONTROL: u32 = 0x2_0000;
const SYNCHRONIZE: u32 = 0x10_0000;
// Inheritance flags (winnt.h ACE flags).
pub const OBJECT_INHERIT: u32 = 0x1;
pub const CONTAINER_INHERIT: u32 = 0x2;

impl Kind {
    /// The access mask.
    pub fn mask(self) -> u32 {
        let read = FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
        match self {
            Kind::Modify => {
                read | FILE_EXECUTE | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE
            }
            Kind::ReadExecute | Kind::ReadFile => read | FILE_EXECUTE,
            Kind::ReadAttributes => FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            Kind::DenyTree => {
                FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE | FILE_DELETE_CHILD
            }
            Kind::DenyFile => FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE,
            Kind::DenyNode => DELETE,
        }
    }

    pub fn is_deny(self) -> bool {
        matches!(self, Kind::DenyTree | Kind::DenyFile | Kind::DenyNode)
    }

    /// The inheritance flags: a folder grant and a held tree reach
    /// everything in them; the rest is the object alone.
    pub fn inheritance(self) -> u32 {
        match self {
            Kind::Modify | Kind::ReadExecute | Kind::DenyTree => OBJECT_INHERIT | CONTAINER_INHERIT,
            Kind::ReadFile | Kind::ReadAttributes | Kind::DenyFile | Kind::DenyNode => 0,
        }
    }
}

/// One entry to write.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ace {
    pub path: PathBuf,
    pub trustee: Trustee,
    pub kind: Kind,
}

/// What a run grants beyond the project's own grants.
#[derive(Debug, Clone, Default)]
pub struct RunDirs {
    /// The client's state folders (its config and caches), written.
    pub state: Vec<PathBuf>,
    /// The folders the client's program and its runtime load from, read and run.
    pub tools: Vec<PathBuf>,
    /// Single files the client reads, never writes: its trust bundles and
    /// the files it was provisioned with, which hold its gateway key.
    pub files: Vec<PathBuf>,
}

/// The folders of `walled` (each with an access list that inherits nothing,
/// so the account's grant misses it) worth reporting: all but the project's
/// held trees, which the account must not write anyway. A held node (`.git`)
/// is written inside, so it stays reported.
pub fn walled_to_report(mut walled: Vec<PathBuf>, project: &ProjectGrants) -> Vec<PathBuf> {
    walled.retain(|w| !project.protected.iter().any(|p| p.guard == Guard::Tree && &p.path == w));
    walled
}

/// The entries for a run in the project at `root` (absolute, already
/// accepted by [`refused_root`]) of the developer whose profile folder is
/// `profile`.
pub fn plan(root: &Path, project: &ProjectGrants, dirs: &RunDirs, profile: &Path) -> Vec<Ace> {
    let mut out: Vec<Ace> = Vec::new();
    let mut push = |path: &Path, trustee, kind| {
        let ace = Ace { path: path.to_path_buf(), trustee, kind };
        if !out.contains(&ace) {
            out.push(ace);
        }
    };
    let mut reached: Vec<&Path> = Vec::new();
    // `OWNER RIGHTS` replaces an owner's implied right to change access with
    // the entry's (Modify, which has none). Inside the profile the developer
    // keeps that right through their own full-control entry; outside it
    // (`--allow-outside-profile`) it may come from ownership alone, and the
    // entry would cost them revoke and the sweep there, so it is not written.
    let inside = |dir: &Path| below(dir, profile).is_some_and(|rest| !rest.as_os_str().is_empty());
    for dir in std::iter::once(root).chain(project.extra_rw.iter().map(PathBuf::as_path)) {
        push(dir, Trustee::Account, Kind::Modify);
        if inside(dir) {
            push(dir, Trustee::OwnerRights, Kind::Modify);
        }
        reached.push(dir);
    }
    // The project folder itself is not the agent's to rename or remove.
    push(root, Trustee::Account, Kind::DenyNode);
    // A client's own folders: a file it rewrites there (write aside, rename
    // over) is the account's, and `OWNER RIGHTS` keeps the account, as its
    // owner, from changing who may read it.
    for dir in &dirs.state {
        push(dir, Trustee::Account, Kind::Modify);
        if inside(dir) {
            push(dir, Trustee::OwnerRights, Kind::Modify);
        }
        reached.push(dir);
    }
    for dir in &dirs.tools {
        push(dir, Trustee::Account, Kind::ReadExecute);
        reached.push(dir);
    }
    for file in &dirs.files {
        push(file, Trustee::Account, Kind::ReadFile);
        // Its folder too, opened and its attributes read, like every folder
        // above a grant.
        if let Some(parent) = file.parent().filter(|p| below(p, profile).is_some()) {
            push(parent, Trustee::Account, Kind::ReadAttributes);
            reached.push(parent);
        }
    }
    // Never on a folder the grant refuses (a drive root, the profile or
    // above): there the entry would need an administrator or reach too far.
    let grantable = |d: &PathBuf| refused_root(&d.to_string_lossy(), &profile.to_string_lossy(), true).is_none();
    for dir in project.stat_only.iter().filter(|d| grantable(d)) {
        push(dir, Trustee::Account, Kind::ReadAttributes);
        reached.push(dir);
    }
    // Each folder between the profile and a granted one (the profile
    // included), opened and its attributes read.
    for dir in reached {
        if let Some(rest) = below(dir, profile) {
            let mut at = profile.to_path_buf();
            push(&at, Trustee::Account, Kind::ReadAttributes);
            let parts: Vec<_> = rest.components().collect();
            for part in parts.iter().take(parts.len().saturating_sub(1)) {
                at.push(part);
                push(&at, Trustee::Account, Kind::ReadAttributes);
            }
        }
    }
    for held in project.held() {
        let kind = match held.guard {
            Guard::Tree => Kind::DenyTree,
            Guard::File => Kind::DenyFile,
            Guard::Node => Kind::DenyNode,
        };
        push(&held.path, Trustee::Account, kind);
    }
    out
}

/// What follows `base` in `path` when `path` is `base` or under it, compared
/// without case, as Windows compares paths.
fn below(path: &Path, base: &Path) -> Option<PathBuf> {
    let same = |a: std::path::Component<'_>, b: std::path::Component<'_>| {
        a.as_os_str().to_string_lossy().to_lowercase() == b.as_os_str().to_string_lossy().to_lowercase()
    };
    let mut rest = path.components();
    for want in base.components() {
        if !same(rest.next()?, want) {
            return None;
        }
    }
    Some(rest.as_path().to_path_buf())
}

/// Why the folder at `root` may not be a sandbox project, if it may not:
/// a drive root; the profile folder `profile` or a folder above it (the
/// grant would reach every secret in it); and, unless `outside_ok`, a folder
/// outside the profile — a folder made directly under a drive inherits the
/// drive's "Authenticated Users: Modify", so every local account (the
/// sandbox's included) writes it whatever the grant says. Compared without
/// case, as Windows compares paths.
pub fn refused_root(root: &str, profile: &str, outside_ok: bool) -> Option<String> {
    let norm = |p: &str| p.trim_end_matches(['\\', '/']).replace('/', "\\").to_lowercase();
    let (r, p) = (norm(root), norm(profile));
    let is_drive = r.len() <= 2 && r.ends_with(':');
    if is_drive || r.is_empty() {
        return Some(format!("{root} is a drive's root: run in a project folder"));
    }
    if r == p || p.starts_with(&format!("{r}\\")) {
        return Some(format!("{root} holds your whole profile: run in a project folder inside it"));
    }
    if !r.starts_with(&format!("{p}\\")) && !outside_ok {
        return Some(format!(
            "{root} is outside your profile ({profile}), where every account on this computer may write \
             (a folder under a drive's root inherits that); move the project into your profile, or pass \
             --allow-outside-profile to run there anyway"
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::protect::Protected;

    #[test]
    fn a_walled_held_tree_goes_unreported_and_a_walled_git_folder_is_reported() {
        let root = PathBuf::from(r"C:\Users\dev\proj");
        let (state, git, other) = (root.join(".streamscopeai"), root.join(".git"), root.join("vendor"));
        let project = ProjectGrants {
            protected: vec![
                Protected { path: state.clone(), guard: Guard::Tree },
                Protected { path: git.clone(), guard: Guard::Node },
            ],
            ..Default::default()
        };
        assert_eq!(walled_to_report(vec![state, git.clone(), other.clone()], &project), vec![git, other]);
    }

    #[test]
    fn the_masks_are_exact_and_no_deny_carries_synchronize() {
        assert_eq!(Kind::Modify.mask(), 0x13_01BF, "icacls' M");
        assert_eq!(Kind::ReadExecute.mask(), 0x12_00A9, "icacls' RX");
        assert_eq!(Kind::ReadFile.mask(), Kind::ReadExecute.mask());
        assert_eq!(Kind::ReadFile.inheritance(), 0, "a file inherits nothing");
        assert_eq!(Kind::Modify.mask() & FILE_DELETE_CHILD, 0, "Modify must not delete a held child");
        for deny in [Kind::DenyTree, Kind::DenyFile, Kind::DenyNode] {
            assert!(deny.is_deny());
            assert_eq!(deny.mask() & (SYNCHRONIZE | FILE_READ_DATA | FILE_READ_ATTRIBUTES), 0, "{deny:?}");
        }
        assert!(!Kind::Modify.is_deny());
        // A folder above a grant opens (its path resolves) and is neither
        // listed nor read.
        assert_eq!(Kind::ReadAttributes.mask(), FILE_READ_ATTRIBUTES | SYNCHRONIZE, "icacls' (S,RA)");
        assert_eq!(Kind::ReadAttributes.mask() & (FILE_READ_DATA | FILE_READ_EA | READ_CONTROL), 0);
    }

    #[test]
    fn a_path_is_below_its_base_whatever_the_case() {
        assert_eq!(below(Path::new("/users/DEV/a/b"), Path::new("/Users/dev")), Some(PathBuf::from("a/b")));
        assert_eq!(below(Path::new("/Users/dev"), Path::new("/Users/dev")), Some(PathBuf::new()));
        assert_eq!(below(Path::new("/Users/devil/a"), Path::new("/Users/dev")), None);
        assert_eq!(below(Path::new("/Users"), Path::new("/Users/dev")), None);
    }

    #[test]
    fn a_run_grants_the_project_its_dirs_and_their_ancestors() {
        let profile = Path::new("/Users/dev");
        let root = Path::new("/Users/dev/src/app");
        let project = ProjectGrants {
            extra_rw: vec![],
            stat_only: vec![],
            protected: vec![
                Protected { path: root.join(".git"), guard: Guard::Node },
                Protected { path: root.join(".git/hooks"), guard: Guard::Tree },
            ],
        };
        let dirs = RunDirs {
            state: vec![PathBuf::from("/Users/dev/.claude")],
            tools: vec![PathBuf::from("/Users/dev/AppData/Roaming/npm")],
            files: vec![PathBuf::from("/Users/dev/AppData/Local/streamscopeai/ca/bundle.pem")],
        };
        let aces = plan(root, &project, &dirs, profile);
        let has = |p: &str, t, k| aces.contains(&Ace { path: PathBuf::from(p), trustee: t, kind: k });
        assert!(has("/Users/dev/src/app", Trustee::Account, Kind::Modify));
        assert!(has("/Users/dev/src/app", Trustee::OwnerRights, Kind::Modify));
        assert!(has("/Users/dev/src/app", Trustee::Account, Kind::DenyNode));
        assert!(has("/Users/dev/.claude", Trustee::Account, Kind::Modify));
        assert!(has("/Users/dev/.claude", Trustee::OwnerRights, Kind::Modify));
        // Outside the profile no `OWNER RIGHTS` entry: it would take the
        // developer's own right to change access there.
        let outside = plan(Path::new("/data/app"), &ProjectGrants::default(), &RunDirs::default(), profile);
        assert!(outside.iter().any(|a| a.trustee == Trustee::Account && a.kind == Kind::Modify));
        assert!(!outside.iter().any(|a| a.trustee == Trustee::OwnerRights), "{outside:?}");
        assert!(has("/Users/dev/AppData/Roaming/npm", Trustee::Account, Kind::ReadExecute));
        assert!(has("/Users/dev/AppData/Local/streamscopeai/ca/bundle.pem", Trustee::Account, Kind::ReadFile));
        for folder in ["/Users/dev/AppData/Local", "/Users/dev/AppData/Local/streamscopeai", "/Users/dev/AppData/Local/streamscopeai/ca"] {
            assert!(has(folder, Trustee::Account, Kind::ReadAttributes), "{folder}");
            assert!(!has(folder, Trustee::Account, Kind::ReadExecute), "{folder}");
        }
        for ancestor in ["/Users/dev", "/Users/dev/src", "/Users/dev/AppData", "/Users/dev/AppData/Roaming"] {
            assert!(has(ancestor, Trustee::Account, Kind::ReadAttributes), "{ancestor}");
        }
        assert!(!has("/Users/dev/src/app", Trustee::Account, Kind::ReadAttributes));
        assert!(has("/Users/dev/src/app/.git", Trustee::Account, Kind::DenyNode));
        assert!(has("/Users/dev/src/app/.git/hooks", Trustee::Account, Kind::DenyTree));
        // A project inside the profile, with no worktree and no file outside:
        // nothing outside the profile is touched.
        assert!(!aces.iter().any(|a| !a.path.starts_with(profile)), "{aces:?}");
    }

    #[test]
    fn a_linked_worktree_is_granted_its_git_dir_and_a_look_at_its_main_checkout() {
        let profile = Path::new("/Users/dev");
        let project = ProjectGrants {
            extra_rw: vec![PathBuf::from("/Users/dev/main/.git")],
            stat_only: vec![PathBuf::from("/Users/dev/main")],
            protected: vec![],
        };
        let aces = plan(Path::new("/Users/dev/wt"), &project, &RunDirs::default(), profile);
        let has = |p: &str, t, k| aces.contains(&Ace { path: PathBuf::from(p), trustee: t, kind: k });
        assert!(has("/Users/dev/main/.git", Trustee::Account, Kind::Modify));
        assert!(has("/Users/dev/main/.git", Trustee::OwnerRights, Kind::Modify));
        assert!(has("/Users/dev/main", Trustee::Account, Kind::ReadAttributes));
        assert!(!has("/Users/dev/main", Trustee::Account, Kind::Modify));
        // A main checkout whose git folder lies elsewhere: the folders above
        // it are opened too, or its path does not resolve.
        let project = ProjectGrants {
            extra_rw: vec![PathBuf::from("/Users/dev/git/main.git")],
            stat_only: vec![PathBuf::from("/Users/dev/code/main")],
            protected: vec![],
        };
        let aces = plan(Path::new("/Users/dev/wt"), &project, &RunDirs::default(), profile);
        let has = |p: &str, t, k| aces.contains(&Ace { path: PathBuf::from(p), trustee: t, kind: k });
        assert!(has("/Users/dev/code", Trustee::Account, Kind::ReadAttributes));
        // One outside the profile (`--allow-outside-profile`) is opened too;
        // a drive root never gets an entry.
        let project =
            ProjectGrants { stat_only: vec![PathBuf::from("/srv/main"), PathBuf::from(r"D:\")], ..Default::default() };
        let aces = plan(Path::new("/Users/dev/wt"), &project, &RunDirs::default(), profile);
        let has = |p: &str, t, k| aces.contains(&Ace { path: PathBuf::from(p), trustee: t, kind: k });
        assert!(has("/srv/main", Trustee::Account, Kind::ReadAttributes));
        assert!(!aces.iter().any(|a| a.path == Path::new(r"D:\")), "{aces:?}");
    }

    #[test]
    fn roots_that_reach_too_far_are_refused() {
        let profile = r"C:\Users\dev";
        assert_eq!(refused_root(r"C:\Users\dev\src\app", profile, false), None);
        assert_eq!(refused_root(r"c:\users\DEV\src\app\", profile, false), None);
        for bad in [r"C:\", "C:", r"C:\Users", r"C:\Users\dev", r"C:\Users\dev\"] {
            assert!(refused_root(bad, profile, true).is_some(), "{bad}");
        }
        // Outside the profile: refused unless forced.
        let outside = refused_root(r"C:\proj", profile, false).unwrap();
        assert!(outside.contains("--allow-outside-profile"), "{outside}");
        assert_eq!(refused_root(r"C:\proj", profile, true), None);
        assert_eq!(refused_root(r"D:\work\app", profile, true), None);
        // A sibling sharing the profile's prefix is outside it.
        assert!(refused_root(r"C:\Users\dev2\app", profile, false).is_some());
    }
}

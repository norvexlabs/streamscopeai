//! Write the plan of `grants.rs` onto the file system, keep a record of what
//! it touched, and take it back (`ssai sandbox revoke`, `uninstall`).
//!
//! Each path's entries for the sandbox account are merged into its access
//! list by `SetEntriesInAclW`, which orders denies before allows. A path whose
//! list already holds every wanted entry is left alone.
//!
//! Writing a folder's list by name (`TreeSetNamedSecurityInfoW`) re-applies
//! what its contents inherit: it rewrites every item below it that inherits,
//! so on the profile it walks every file the developer has, each reported to
//! a [`Progress`]. That walk is needed only when an inheritable entry comes or
//! goes; a change of entries for the folder alone (the open or list entry
//! on each folder above a grant, a deny on one file) is written on an open
//! handle to that one object, which touches nothing below it.
//!
//! An item that inherits nothing (its list protected) is out of a grant's
//! reach, and so is one whose list was written before the grant reached it (a
//! file moved in afterwards, a hard link from a package cache): [`scan`] finds
//! both, [`unprotect`] and [`rewrite`] repair them (`ssai sandbox doctor`).
//! A project outside the profile sits under a private root, made the
//! developer's alone as the profile is ([`make_private_root`]).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    DENY_ACCESS, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, NO_MULTIPLE_TRUSTEE, PROG_INVOKE_SETTING,
    ProgressInvokePrePostError, SE_FILE_OBJECT, SetEntriesInAclW, TREE_SEC_INFO_SET, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN,
    TRUSTEE_W, TreeSetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION_DS, ACL_SIZE_INFORMATION, AclSizeInformation, AddAce,
    DACL_SECURITY_INFORMATION, EqualSid, GetAce, InitializeAcl, GetAclInformation, GetSecurityDescriptorControl, INHERITED_ACE, PSECURITY_DESCRIPTOR,
    GetLengthSid, InitializeSecurityDescriptor, PROTECTED_DACL_SECURITY_INFORMATION, SECURITY_DESCRIPTOR, SE_DACL_AUTO_INHERIT_REQ,
    SE_DACL_AUTO_INHERITED, SE_DACL_PROTECTED, SetKernelObjectSecurity, SetSecurityDescriptorControl,
    SetSecurityDescriptorDacl,
};

use super::grants::{Ace, Kind, Trustee};
use super::setup::Sid;
use crate::progress::{Progress, grouped};
use crate::win_acl::wide;

const OWNER_RIGHTS_SID: &str = "S-1-3-4";
/// The groups every local account belongs to — the sandbox account
/// included: a write right one of them holds on a project reaches the
/// account whatever it is granted, and revoke cannot take it back.
const BROAD_GROUPS: [(&str, &str); 9] = [
    ("S-1-1-0", "Everyone"),
    ("S-1-5-11", "Authenticated Users"),
    ("S-1-5-32-545", "Users"),
    ("S-1-5-4", "INTERACTIVE"),
    ("S-1-2-0", "LOCAL"),
    ("S-1-2-1", "CONSOLE LOGON"),
    ("S-1-5-15", "This Organization"),
    ("S-1-5-113", "Local account"),
    ("S-1-5-64-10", "NTLM Authentication"),
];
/// What a private folder names no entry for, beside [`BROAD_GROUPS`]: a
/// creator's entry gives whoever creates a file there — the agent among them
/// — full control of it, the right to change who may open it included.
const CREATORS: [(&str, &str); 2] = [("S-1-3-0", "CREATOR OWNER"), ("S-1-3-1", "CREATOR GROUP")];
/// Every right that writes, removes or re-permissions: write data, append,
/// write EA, delete child, write attributes, DELETE, WRITE_DAC, WRITE_OWNER,
/// GENERIC_ALL, GENERIC_WRITE.
const WRITE_RIGHTS: u32 = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x1_0000 | 0x4_0000 | 0x8_0000 | 0x1000_0000 | 0x4000_0000;
/// Full control, on the folder and everything in it.
const FULL_CONTROL: u32 = 0x1F_01FF;
/// Object and container inherit, as an inheritable grant carries them.
const OBJECT_AND_CONTAINER_INHERIT: u32 = super::grants::OBJECT_INHERIT | super::grants::CONTAINER_INHERIT;
const ACCESS_ALLOWED: u8 = 0;
const ACCESS_DENIED: u8 = 1;
/// How many refused items an error names before it counts the rest.
const NAMED_REFUSALS: usize = 5;
const RECORD_FILE: &str = "sandbox-grants.json";

/// What the writer did.
#[derive(Debug, Default)]
pub struct Applied {
    /// Paths whose access list it changed.
    pub changed: Vec<PathBuf>,
    /// Items a by-name write walked (the paths themselves and what inherits
    /// below them).
    pub walked: u64,
}

/// Where the grants are recorded: the developer's config folder.
pub fn record_path() -> Result<PathBuf> {
    Ok(crate::state::config_dir()?.join(RECORD_FILE))
}

/// Write `aces` for the account `account_sid`, recorded in `record` under
/// the project `root`; each by-name write's walk reported to `progress`.
pub fn apply(record: &Path, account_sid: &str, root: &Path, aces: &[Ace], progress: &Progress) -> Result<Applied> {
    let account = Sid::parse(account_sid)?;
    let owner_rights = Sid::parse(OWNER_RIGHTS_SID)?;
    let mut by_path: BTreeMap<&Path, Vec<&Ace>> = BTreeMap::new();
    for ace in aces {
        by_path.entry(&ace.path).or_default().push(ace);
    }
    let mut applied = Applied::default();
    // A path whose write failed is named after every other path is written
    // (a held tree's deny among them), never instead of them.
    let mut failed: Option<anyhow::Error> = None;
    // Held to the end: two runs merging into one folder's list (a read, then
    // a write) would each write over the other's entries. Revoke holds it too.
    let _lock = lock_record(record)?;
    // Record first: a run stopped half-way still leaves its grants revocable.
    record_grants(record, root, aces)?;
    for (path, wanted) in by_path {
        let sid_of = |t: Trustee| if t == Trustee::Account { &account } else { &owner_rights };
        let read = Dacl::read(path).and_then(|dacl| dacl.aces().map(|present| (present, dacl)));
        let (present, dacl) = match read {
            Ok(read) => read,
            Err(e) => {
                failed.get_or_insert(e.context(format!("read the access list of {}", path.display())));
                continue;
            }
        };
        if wanted.iter().all(|a| Dacl::has(&present, sid_of(a.trustee), a.kind)) {
            continue;
        }
        // Every wanted entry is merged in one call, denies included: a grant
        // merged alone combines with the trustee's existing deny and can
        // strip it. Only a path with an inheritable entry is written by name.
        let local = wanted.iter().all(|a| a.kind.inheritance() == 0);
        let entries: Vec<EXPLICIT_ACCESS_W> = wanted
            .iter()
            .map(|a| EXPLICIT_ACCESS_W {
                grfAccessPermissions: a.kind.mask(),
                grfAccessMode: if a.kind.is_deny() { DENY_ACCESS } else { GRANT_ACCESS },
                grfInheritance: a.kind.inheritance(),
                Trustee: trustee(sid_of(a.trustee)),
            })
            .collect();
        if !local {
            progress.phase(format!("Applying the sandbox's access below {}", path.display()), None);
        }
        if let Err(e) = dacl.write_with(path, &entries, local, progress) {
            failed.get_or_insert(e.context(format!("grant the sandbox account {}", path.display())));
            continue;
        }
        if !local {
            applied.walked += progress.count();
        }
        applied.changed.push(path.to_path_buf());
    }
    match failed {
        Some(e) => Err(e),
        None => Ok(applied),
    }
}

/// Remove every entry for the account (and the `OWNER RIGHTS` entries the
/// grants added) from the paths `record` holds for the project `root`, or for
/// every project when `root` is `None`, and drop them from it. A path another
/// project still granted also holds (the profile folder, a client's config
/// folder, a tool folder) keeps its entries: that project, maybe running now,
/// needs them; revoking it too takes them back. The project's own folder is
/// revoked whatever else records it. A path whose list cannot be
/// read or written is named in a warning and stays in the record, so a later
/// revoke tries it again; the rest are revoked all the same.
pub fn revoke(record_file: &Path, account_sid: &str, root: Option<&Path>, progress: &Progress) -> Result<Vec<PathBuf>> {
    let account = Sid::parse(account_sid)?;
    let owner_rights = Sid::parse(OWNER_RIGHTS_SID)?;
    let _lock = lock_record(record_file)?;
    let mut record = GrantRecord::load(record_file)?;
    let roots: Vec<String> = match root {
        Some(r) => vec![key(r)],
        None => record.projects.keys().cloned().collect(),
    };
    let mut revoked = Vec::new();
    for r in roots {
        let Some(paths) = record.projects.get(&r).cloned() else { continue };
        let kept_by_others = |path: &str| {
            let path = path.to_lowercase();
            record
                .projects
                .iter()
                .any(|(other, entries)| *other != r && entries.iter().any(|e| e.path.to_lowercase() == path))
        };
        let mut failed = Vec::new();
        for entry in &paths {
            // The project's own folder is always taken back: a project
            // inside it records it too, to list it only.
            if root.is_some() && entry.path.to_lowercase() != r && kept_by_others(&entry.path) {
                continue;
            }
            let path = Path::new(&entry.path);
            if std::fs::symlink_metadata(path).is_err() {
                continue;
            }
            let mut whom = vec![&account];
            if entry.owner_rights {
                whom.push(&owner_rights);
            }
            if entry.inheritable {
                progress.phase(format!("Taking the sandbox's access back below {}", path.display()), None);
            }
            let done = Dacl::read(path)
                .with_context(|| format!("read the access list of {}", path.display()))
                .and_then(|dacl| {
                    dacl.write_without(path, &whom, entry.inheritable, progress)
                        .with_context(|| format!("revoke the sandbox account on {}", path.display()))
                });
            match done {
                Ok(()) => revoked.push(path.to_path_buf()),
                Err(e) => {
                    crate::ui::warn("", format_args!("{e:#}"));
                    failed.push(entry.clone());
                }
            }
        }
        if failed.is_empty() {
            record.projects.remove(&r);
        } else {
            record.projects.insert(r, failed);
        }
        record.save(record_file)?;
    }
    Ok(revoked)
}

/// Whether `record_file` still holds a grant (a revoke left one it could not
/// take back).
pub fn has_grants(record_file: &Path) -> Result<bool> {
    Ok(!GrantRecord::load(record_file)?.projects.is_empty())
}

/// What a walk of a project, or of a private root, found out of the grant's
/// reach.
#[derive(Debug, Default)]
pub struct Scan {
    /// Items walked.
    pub items: u64,
    /// Folders and files whose list inherits nothing: no grant above reaches
    /// them, nor what is below a protected folder.
    pub protected: Vec<PathBuf>,
    /// Items that inherit and yet hold no entry for the account below a
    /// granted root: their list was written before the grant reached them (a
    /// file moved in afterwards keeps its old folder's, a hard link shares its
    /// cache's). None below a protected item, which [`Self::protected`] covers.
    pub stale: Vec<PathBuf>,
    /// Items that inherit and yet give every account access (or a creator's
    /// entry) by an entry of their own, which no private folder above
    /// removes: a takeover drops that entry, as it does on a protected item.
    pub broad: Vec<PathBuf>,
    /// Left alone whatever they hold: every `.streamscopeai` folder, and each
    /// protected file a project's manifest records (a provisioned client
    /// config, holding a gateway key).
    pub kept: Vec<PathBuf>,
    /// Items whose list could not be read (nothing below an unreadable folder
    /// is walked).
    pub unreadable: Vec<PathBuf>,
    /// Folders holding a project whose manifest does not read as this
    /// version's, with why: its key files cannot be told apart, so nothing
    /// below is listed, and nothing below is changed.
    pub skipped: Vec<(PathBuf, String)>,
}

/// Walk what `root` holds — its own list is the grant's or the takeover's,
/// never listed — for items out of the grant's reach. No reparse point (a
/// junction, a link) is followed. With `account` (the sandbox account's SID,
/// `root` granted) the items missing its entry are listed too. Each item is
/// reported to `progress`.
pub fn scan(root: &Path, account: Option<&str>, progress: &Progress) -> Result<Scan> {
    use std::os::windows::fs::MetadataExt as _;
    const REPARSE_POINT: u32 = 0x400;
    let account = account.map(Sid::parse).transpose()?;
    let groups = not_private()?;
    let mut out = Scan::default();
    let mut keep: std::collections::HashSet<String> = std::collections::HashSet::new();
    progress.phase(format!("Checking {}", root.display()), None);
    // Each folder, and whether an item above it is protected.
    let mut stack: Vec<(PathBuf, bool)> = vec![(root.to_path_buf(), false)];
    while let Some((dir, under_protected)) = stack.pop() {
        // A project's manifest names the key files below it: read before
        // anything below is listed.
        match crate::state::Manifest::recorded_files(&dir.join(".streamscopeai").join("manifest.json")) {
            Ok(Some(files)) => keep.extend(files.iter().map(|f| key(f))),
            Ok(None) => {}
            Err(e) => {
                out.skipped.push((dir, format!("{e:#}")));
                continue;
            }
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            out.unreadable.push(dir);
            continue;
        };
        for entry in entries.flatten() {
            out.items += 1;
            progress.tick();
            let path = entry.path();
            let Ok(meta) = entry.metadata() else {
                out.unreadable.push(path);
                continue;
            };
            if meta.file_attributes() & REPARSE_POINT != 0 {
                continue;
            }
            if meta.is_dir() && entry.file_name().eq_ignore_ascii_case(".streamscopeai") {
                out.kept.push(path);
                continue;
            }
            let Ok(dacl) = Dacl::read(&path) else {
                out.unreadable.push(path);
                continue;
            };
            let kept = !meta.is_dir() && keep.contains(&key(&path));
            if dacl.protected {
                if kept {
                    out.kept.push(path.clone());
                } else {
                    out.protected.push(path.clone());
                }
            } else if !kept {
                // One whose entries cannot be enumerated is unreadable, never
                // the end of the walk.
                let (Ok(mentions), Ok(own_broad)) =
                    (account.as_ref().map_or(Ok(true), |a| dacl.mentions(a)), dacl.names_own(&groups))
                else {
                    out.unreadable.push(path);
                    continue;
                };
                if own_broad {
                    out.broad.push(path.clone());
                }
                if !under_protected && !mentions {
                    out.stale.push(path.clone());
                }
            }
            if meta.is_dir() {
                stack.push((path, under_protected || dacl.protected));
            }
        }
    }
    Ok(out)
}

/// Turn inheritance back on for each of `items` (protected folders and
/// files, or inheriting ones carrying a broad entry of their own), keeping
/// its own entries but every account's and a creator's ([`not_private`]):
/// written on the object alone, so nothing below is walked — the by-name
/// write that follows ([`rewrite`], [`make_private_root`]) gives each what it
/// inherits. An item whose remaining entries give the developer `me` no full
/// control gets theirs, on the item alone: dropping every account's entries
/// must never leave a list its developer may not change, which the walk that
/// follows needs (one owned by another account would stay out of reach).
/// Returns the items Windows refused (one whose access the developer may not
/// change), with why.
pub fn unprotect(items: &[PathBuf], me: &str, progress: &Progress) -> Result<Vec<(PathBuf, String)>> {
    let groups = not_private()?;
    let me = Sid::parse(me)?;
    // SAFETY: `me` holds a valid SID.
    let me_len = unsafe { GetLengthSid(me.0) };
    let mine_len = 8 + me_len;
    let mut mine = Vec::with_capacity(mine_len as usize);
    mine.extend_from_slice(&[ACCESS_ALLOWED, 0]);
    mine.extend_from_slice(&(mine_len as u16).to_le_bytes());
    mine.extend_from_slice(&FULL_CONTROL.to_le_bytes());
    // SAFETY: `me` holds a valid SID of `me_len` bytes.
    mine.extend_from_slice(unsafe { std::slice::from_raw_parts(me.0.cast::<u8>(), me_len as usize) });
    let mut refused = Vec::new();
    progress.phase("Turning inheritance back on", Some(items.len() as u64));
    for item in items {
        progress.tick();
        let done = (|| -> Result<()> {
            let dacl = Dacl::read(item)?;
            if dacl.acl.is_null() {
                bail!("it has no access list");
            }
            let aces = dacl.aces()?;
            let mut buf = AclBuf::with_room(&aces, mine_len)?;
            let mut holds_mine = false;
            for ace in aces {
                // SAFETY: an entry of `dacl`, `AceSize` bytes long; an allowed
                // entry is an ACCESS_ALLOWED_ACE, its SID at `SidStart`.
                unsafe {
                    let header = &*ace.cast::<ACE_HEADER>();
                    if u32::from(header.AceFlags) & INHERITED_ACE != 0 || broad_allow(ace, &groups).is_some() {
                        continue;
                    }
                    let entry = &*ace.cast::<ACCESS_ALLOWED_ACE>();
                    // On the item itself (not inherit-only, 0x8).
                    holds_mine |= header.AceType == ACCESS_ALLOWED
                        && u32::from(header.AceFlags) & 0x8 == 0
                        && entry.Mask & FULL_CONTROL == FULL_CONTROL
                        && EqualSid((&raw const entry.SidStart).cast_mut().cast(), me.0) != 0;
                    buf.push(std::slice::from_raw_parts(ace.cast::<u8>(), usize::from(header.AceSize)))?;
                }
            }
            if !holds_mine {
                buf.push(&mine)?;
            }
            dacl.write_local(item, buf.acl(), false, true)
        })();
        if let Err(e) = done {
            refused.push((item.clone(), format!("{e:#}")));
        }
    }
    Ok(refused)
}

/// Write `path`'s list back as it is, by name: Windows re-applies what every
/// item below inherits from it — the repair of an item [`unprotect`] opened
/// and of one whose list was written before the grant reached it. Returns
/// how many items the walk visited.
pub fn rewrite(path: &Path, progress: &Progress) -> Result<u64> {
    let dacl = Dacl::read(path).with_context(|| format!("read the access list of {}", path.display()))?;
    if dacl.acl.is_null() {
        bail!("{} has no access list (every account may do anything there)", path.display());
    }
    progress.phase(format!("Applying what the items below {} inherit", path.display()), None);
    dacl.store(path, dacl.acl, false, progress)?;
    Ok(progress.count())
}

/// The paths of project `root`'s grant whose entry is inheritable (the
/// project, a linked worktree's git folder, a client's own folders), as
/// recorded; empty when the project is not granted.
pub fn granted_trees(record_file: &Path, root: &Path) -> Result<Vec<PathBuf>> {
    let record = GrantRecord::load(record_file)?;
    Ok(record
        .projects
        .get(&key(root))
        .map(|paths| paths.iter().filter(|p| p.inheritable).map(|p| PathBuf::from(&p.path)).collect())
        .unwrap_or_default())
}

/// Whether `path`'s own list (not inherited) holds the account's `kind`
/// entry — the grant `apply` writes there.
pub fn holds(path: &Path, account_sid: &str, kind: Kind) -> Result<bool> {
    let dacl = Dacl::read(path).with_context(|| format!("read the access list of {}", path.display()))?;
    Ok(Dacl::has(&dacl.aces()?, &Sid::parse(account_sid)?, kind))
}

/// The projects the record holds grants for.
pub fn granted_projects(record_file: &Path) -> Result<Vec<PathBuf>> {
    Ok(granted(record_file)?.into_iter().filter_map(|g| g.root).collect())
}

/// One entry of the grant record, as `ssai sandbox status` lists it.
pub struct Granted {
    /// The project folder, by its own recorded path (the one the record's
    /// key is made from). `None` when a partial revoke took the project's
    /// own grant back and left only paths it could not.
    pub root: Option<PathBuf>,
    /// The record's key: the project folder, lowercased.
    pub key: String,
    /// Every other path whose access its grants changed (the folders above
    /// it, the tool's and its configuration's, and the holds — denies — on
    /// its git and `.streamscopeai` folders), sorted.
    pub others: Vec<PathBuf>,
}

/// Every entry the record holds, in the record's (key) order. Reads without
/// the record's lock: the record is replaced whole, never written in place.
pub fn granted(record_file: &Path) -> Result<Vec<Granted>> {
    let record = GrantRecord::load(record_file)?;
    Ok(record
        .projects
        .into_iter()
        .map(|(key, paths)| {
            let (own, others): (Vec<_>, Vec<_>) = paths.into_iter().partition(|p| p.path.to_lowercase() == key);
            let mut others: Vec<PathBuf> = others.into_iter().map(|p| PathBuf::from(p.path)).collect();
            others.sort();
            Granted { root: own.into_iter().next().map(|p| PathBuf::from(p.path)), key, others }
        })
        .collect())
}

/// How private a private root is.
#[derive(Debug, PartialEq, Eq)]
pub enum RootState {
    /// The developer's alone: its list names no group every account belongs
    /// to, reading included, and no creator ([`not_private`]) — whether it
    /// inherits (a drive that names none) or not.
    Private,
    /// Making it private was started and did not finish: its own list may
    /// read as private above items that are not.
    Pending,
    /// What its list names of [`not_private`], reading or writing.
    Open(Vec<&'static str>),
}

/// How private the private root `root` is.
pub fn root_state(record_file: &Path, root: &Path) -> Result<RootState> {
    if GrantRecord::load(record_file)?.private_pending.contains(&key(root)) {
        return Ok(RootState::Pending);
    }
    let dacl = Dacl::read(root).with_context(|| format!("read the access list of {}", root.display()))?;
    if dacl.acl.is_null() {
        bail!(
            "{} keeps no access list (every account may do anything there, as on a FAT or exFAT drive), so the \
             sandbox cannot confine it: run in a project on an NTFS volume",
            root.display()
        );
    }
    // Inheriting or not, a folder whose list names none of them is the
    // developer's alone (a drive that names none is, and its folders with it).
    let named = dacl.broad_any(&not_private()?)?;
    Ok(if named.is_empty() { RootState::Private } else { RootState::Open(named) })
}

/// Whether the folder `dir` was made private on its own, as an earlier
/// `ssai` made a project folder outside the profile: it inherits nothing, no
/// group every account belongs to may write it (they may still read it), and
/// no change of it is pending. Such a project keeps running as it did; the
/// doctor offers its private root.
pub fn private_alone(record_file: &Path, dir: &Path) -> Result<bool> {
    if GrantRecord::load(record_file)?.private_pending.contains(&key(dir)) {
        return Ok(false);
    }
    let dacl = Dacl::read(dir).with_context(|| format!("read the access list of {}", dir.display()))?;
    Ok(dacl.protected && !dacl.acl.is_null() && dacl.broad_names(&broad_groups()?)?.is_empty())
}

/// Whether `path`'s own entries (not inherited) give every account access, or
/// carry a creator's ([`not_private`]) — what no private folder above removes.
pub fn names_own_broad(path: &Path) -> Result<bool> {
    let dacl = Dacl::read(path).with_context(|| format!("read the access list of {}", path.display()))?;
    dacl.names_own(&not_private()?)
}

/// Whether the developer may change who may open `path` (its list opened for
/// that, nothing written).
pub fn can_change(path: &Path) -> Result<()> {
    Dacl::read(path).and_then(|dacl| dacl.open_to_change(path))
}

/// Make the folder `root` the developer `me`'s alone, as their profile is:
/// it stops inheriting from the drive, keeps every entry it had as its own
/// but every account's and a creator's ([`not_private`], reading included), and grants `me`
/// full control, inherited by everything in it. The owner is not changed.
/// `items` — the protected folders and files under it the caller listed and
/// the developer agreed to ([`scan`]) — inherit again first, so the one
/// by-name write of `root` that follows reaches every item below. `root` is
/// marked pending in `record` until that walk returns, so a run cut short is
/// finished by the next ([`root_state`]). `items` holds the scan's protected
/// items and those giving every account access by an entry of their own
/// ([`Scan::broad`]): each keeps its own entries but those. Returns the items
/// Windows refused.
pub fn make_private_root(
    record: &Path,
    root: &Path,
    me: &str,
    account: &str,
    items: &[PathBuf],
    progress: &Progress,
) -> Result<Vec<(PathBuf, String)>> {
    let _lock = lock_record(record)?;
    // Nothing changes when the root's own list may not: the items below would
    // lose every account's entries for nothing, and the mark would stay.
    if let Err(e) = can_change(root) {
        bail!(
            "you may not change who may open {} ({e:#}): its owner or an administrator can make it private to you",
            root.display()
        );
    }
    let mut pending = GrantRecord::load(record)?;
    if pending.private_pending.insert(key(root)) {
        pending.save(record)?;
    }
    let refused = unprotect(items, me, progress)?;
    progress.phase(format!("Making {} private to you", root.display()), None);
    write_private_list(root, me, account, progress)?;
    let mut done = GrantRecord::load(record)?;
    done.private_pending.remove(&key(root));
    done.save(record)?;
    Ok(refused)
}

/// The groups of [`BROAD_GROUPS`] holding a write right in the list of
/// `path` — on the folder or on what it holds, inherited or its own — by name.
pub fn broad_writers(path: &Path) -> Result<Vec<&'static str>> {
    let dacl = Dacl::read(path).with_context(|| format!("read the access list of {}", path.display()))?;
    if dacl.acl.is_null() {
        bail!(
            "{} keeps no access list (every account may do anything there, as on a FAT or exFAT drive), so the \
             sandbox cannot confine it: run in a project on an NTFS volume",
            path.display()
        );
    }
    dacl.broad_names(&broad_groups()?)
}

/// `account`'s and `OWNER RIGHTS`' allow entries the folder inherited (from
/// a granted project above it) are dropped, not made its own: on a list that
/// inherits nothing they would outlive that project's revoke.
fn write_private_list(path: &Path, me: &str, account: &str, progress: &Progress) -> Result<()> {
    let dacl = Dacl::read(path).with_context(|| format!("read the access list of {}", path.display()))?;
    if dacl.acl.is_null() {
        bail!("{} has no access list (every account may do anything there)", path.display());
    }
    let groups = not_private()?;
    let aces = dacl.aces()?;
    let me = Sid::parse(me)?;
    let ours = [Sid::parse(account)?, Sid::parse(OWNER_RIGHTS_SID)?];
    // SAFETY: `me` holds a valid SID.
    let me_len = unsafe { GetLengthSid(me.0) };
    // The developer's full-control entry: header, mask, SID.
    let mine_len = 8 + me_len;
    let mut buf = AclBuf::with_room(&aces, mine_len)?;
    // Every entry is kept, made its own, in the order Windows keeps a list
    // (every deny before every allow, each in its order): the grant that
    // follows merges into it with `SetEntriesInAclW`, which orders it so or
    // refuses it. A deny the folder inherited thus also outranks an allow
    // the folder held itself — never the other way round.
    let is_deny = |ace: &*mut core::ffi::c_void| {
        // SAFETY: an entry of `dacl`.
        // Plain, object, callback and callback-object denies.
        unsafe { matches!((*ace.cast::<ACE_HEADER>()).AceType, 1 | 6 | 10 | 12) }
    };
    let (denies, allows): (Vec<_>, Vec<_>) = aces.iter().copied().partition(is_deny);
    for ace in denies.into_iter().chain(allows) {
        // SAFETY: `ace` is an entry of `dacl`, `AceSize` bytes long; the copy
        // is edited in place (an allowed entry's mask follows its 4-byte
        // header) and `kept` has room for every entry of the old list.
        unsafe {
            let header = &*ace.cast::<ACE_HEADER>();
            // Allows only: an inherited deny (a held tree's, from a granted
            // project above) keeps holding the account out.
            if u32::from(header.AceFlags) & INHERITED_ACE != 0 && header.AceType == ACCESS_ALLOWED {
                let sid = (&raw const (*ace.cast::<ACCESS_ALLOWED_ACE>()).SidStart).cast_mut().cast();
                if ours.iter().any(|o| EqualSid(sid, o.0) != 0) {
                    continue;
                }
            }
            // Every account's entry goes, reading included, and a creator's:
            // the folder is the developer's alone, as the profile is.
            if broad_allow(ace, &groups).is_some() {
                continue;
            }
            let mut copy = std::slice::from_raw_parts(ace.cast::<u8>(), usize::from(header.AceSize)).to_vec();
            // Its own now: the list inherits nothing any more.
            copy[1] &= !(INHERITED_ACE as u8);
            buf.push(&copy)?;
        }
    }
    // Then the developer's full control, on the folder and everything in it
    // (once: a run finishing a change cut short finds it there).
    let holds_mine = aces.iter().any(|&ace| {
        // SAFETY: an entry of `dacl`; an allowed entry's SID at `SidStart`.
        unsafe {
            let header = &*ace.cast::<ACE_HEADER>();
            let entry = &*ace.cast::<ACCESS_ALLOWED_ACE>();
            // OI|CI and not inherit-only (0x8): on the folder itself too.
            header.AceType == ACCESS_ALLOWED
                && u32::from(header.AceFlags) & (OBJECT_AND_CONTAINER_INHERIT | 0x8) == OBJECT_AND_CONTAINER_INHERIT
                && entry.Mask & FULL_CONTROL == FULL_CONTROL
                && EqualSid((&raw const entry.SidStart).cast_mut().cast(), me.0) != 0
        }
    });
    let mut mine = Vec::with_capacity(mine_len as usize);
    mine.extend_from_slice(&[ACCESS_ALLOWED, OBJECT_AND_CONTAINER_INHERIT as u8]);
    mine.extend_from_slice(&(mine_len as u16).to_le_bytes());
    mine.extend_from_slice(&FULL_CONTROL.to_le_bytes());
    // SAFETY: `me` holds a valid SID of `me_len` bytes.
    mine.extend_from_slice(unsafe { std::slice::from_raw_parts(me.0.cast::<u8>(), me_len as usize) });
    if !holds_mine {
        buf.push(&mine)?;
    }
    write_by_name(path, buf.acl(), DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, progress)
        .with_context(|| format!("make {} private", path.display()))
}

/// Write `acl` as the list of `path` by name (`info`: the parts written):
/// Windows re-applies what every item below inherits, each reported to
/// `progress`. An item Windows refused fails the write, named (the first few,
/// then how many) — the rest of the walk is done. The pre/post/error
/// progress setting is what makes this walk `SetNamedSecurityInfoW`'s (an
/// item whose list is protected is left as it is); invoked on every object,
/// it rewrites a protected item too — never use that setting.
fn write_by_name(path: &Path, acl: *const ACL, info: u32, progress: &Progress) -> Result<()> {
    struct Walk<'a> {
        progress: &'a Progress,
        /// The items Windows named whose list no call has said was set yet:
        /// the folders being walked, and what it passed by.
        unset: std::collections::HashSet<String>,
        /// Items an error was reported for, and why.
        refused: Vec<(String, String)>,
    }
    /// Called by Windows before and after each item, and on its error.
    unsafe extern "system" fn each(
        name: windows_sys::core::PCWSTR,
        status: u32,
        invoke: *mut PROG_INVOKE_SETTING,
        args: *const core::ffi::c_void,
        set: windows_sys::core::BOOL,
    ) {
        // SAFETY: `args` is the `Walk` below, alive and borrowed by no one
        // else for the call; `name` is a NUL-terminated string Windows owns
        // for the call; `invoke` is Windows' setting to write.
        unsafe {
            let walk = &mut *args.cast_mut().cast::<Walk<'_>>();
            let len = (0..).take_while(|&i| *name.add(i) != 0).count();
            let text = String::from_utf16_lossy(std::slice::from_raw_parts(name, len));
            // An item whose list was written is counted once, on the call
            // that says so.
            if set != 0 {
                walk.progress.tick();
            }
            if status != 0 {
                walk.refused.push((text.clone(), std::io::Error::from_raw_os_error(status as i32).to_string()));
            }
            note(&mut walk.unset, text, set != 0);
            *invoke = ProgressInvokePrePostError;
        }
    }
    let name = wide(path.as_os_str());
    let mut walk = Walk { progress, unset: std::collections::HashSet::new(), refused: Vec::new() };
    // SAFETY: a NUL-terminated name, a valid list, and `walk` outliving the
    // call that hands it to `each`.
    let rc = unsafe {
        TreeSetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            info,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            acl,
            std::ptr::null(),
            TREE_SEC_INFO_SET,
            Some(each),
            ProgressInvokePrePostError,
            (&raw mut walk).cast(),
        )
    };
    // An item Windows named and never set, with no error reported: left
    // alone rightly when its list is protected, refused otherwise (a file
    // held open with no sharing is reported so).
    let mut refused: Vec<String> = walk.refused.iter().map(|(item, why)| format!("{item} ({why})")).collect();
    let reported: std::collections::HashSet<&str> = walk.refused.iter().map(|(item, _)| item.as_str()).collect();
    let mut never_set: Vec<&String> = walk.unset.iter().collect();
    never_set.sort();
    for item in never_set {
        let item = item.as_str();
        // Left alone rightly when protected; one gone since (a file a build
        // deleted mid-walk) is no refusal to name. One whose list cannot be
        // read is refused like one that cannot be written.
        if std::fs::symlink_metadata(item).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
            continue;
        }
        let protected = Dacl::read(Path::new(item)).is_ok_and(|d| d.protected);
        if !protected && !reported.contains(item) {
            refused.push(format!("{item} (its list could not be written)"));
        }
    }
    if rc != ERROR_SUCCESS {
        bail!("{}", std::io::Error::from_raw_os_error(rc as i32));
    }
    if !refused.is_empty() {
        let more = refused.len().saturating_sub(NAMED_REFUSALS);
        bail!(
            "{} item(s) below refused the change: {}{}",
            grouped(refused.len() as u64),
            refused[..refused.len().min(NAMED_REFUSALS)].join("; "),
            if more > 0 { format!("; and {} more", grouped(more as u64)) } else { String::new() }
        );
    }
    Ok(())
}

/// One call of a walk naming `item`: Windows calls before and after each item
/// (a folder's last call after its contents'), the one after saying when its
/// list was set. `unset` keeps what no call has said was set yet — what the
/// walk is inside of, and what it passed by — never the whole tree.
fn note(unset: &mut std::collections::HashSet<String>, item: String, set: bool) {
    if set {
        unset.remove(&item);
    } else {
        unset.insert(item);
    }
}

/// The group's name and the entry's mask, when `ace` allows one of `groups`.
///
/// # Safety
/// `ace` is an entry of a valid list.
unsafe fn broad_allow(ace: *mut core::ffi::c_void, groups: &[(Sid, &'static str)]) -> Option<(&'static str, u32)> {
    // SAFETY: per the contract; an allowed entry is an ACCESS_ALLOWED_ACE,
    // its SID at `SidStart`.
    unsafe {
        if (*ace.cast::<ACE_HEADER>()).AceType != ACCESS_ALLOWED {
            return None;
        }
        let entry = &*ace.cast::<ACCESS_ALLOWED_ACE>();
        let sid = (&raw const entry.SidStart).cast_mut().cast();
        groups.iter().find(|(g, _)| EqualSid(sid, g.0) != 0).map(|(_, name)| (*name, entry.Mask))
    }
}

fn broad_groups() -> Result<Vec<(Sid, &'static str)>> {
    BROAD_GROUPS.iter().map(|(sid, name)| Ok((Sid::parse(sid)?, *name))).collect()
}

/// [`BROAD_GROUPS`] and [`CREATORS`]: the entries a private folder holds none
/// of.
fn not_private() -> Result<Vec<(Sid, &'static str)>> {
    BROAD_GROUPS.iter().chain(CREATORS.iter()).map(|(sid, name)| Ok((Sid::parse(sid)?, *name))).collect()
}

/// An access list being built, sized for a given set of entries.
struct AclBuf(Vec<u32>);

impl AclBuf {
    fn for_entries(aces: &[*mut core::ffi::c_void]) -> Result<Self> {
        Self::with_room(aces, 0)
    }

    /// Sized for `aces` and `extra` more bytes of entries.
    fn with_room(aces: &[*mut core::ffi::c_void], extra: u32) -> Result<Self> {
        let mut size = std::mem::size_of::<ACL>() as u32 + extra;
        for ace in aces {
            // SAFETY: each is an entry of a valid list.
            size += u32::from(unsafe { &*ace.cast::<ACE_HEADER>() }.AceSize);
        }
        let size = size.next_multiple_of(4);
        let mut buf = Self(vec![0u32; size as usize / 4]);
        // SAFETY: the buffer is `size` bytes, DWORD-aligned.
        // The directory-service revision takes every entry type a list may
        // hold (an object or a conditional entry among them), the plain ones too.
        if unsafe { InitializeAcl(buf.acl(), size, ACL_REVISION_DS) } == 0 {
            bail!("build the access list: {}", std::io::Error::last_os_error());
        }
        Ok(buf)
    }

    fn acl(&mut self) -> *mut ACL {
        self.0.as_mut_ptr().cast()
    }

    /// Append one entry (its bytes, `AceSize` long); room was made for it.
    fn push(&mut self, ace: &[u8]) -> Result<()> {
        // SAFETY: `ace` is one whole entry; the list has room for it.
        if unsafe { AddAce(self.acl(), ACL_REVISION_DS, u32::MAX, ace.as_ptr().cast(), ace.len() as u32) } == 0 {
            bail!("build the access list: {}", std::io::Error::last_os_error());
        }
        Ok(())
    }
}

/// A path's access list, owned (freed on drop).
struct Dacl {
    sd: PSECURITY_DESCRIPTOR,
    acl: *mut ACL,
    protected: bool,
    /// The list was built for automatic inheritance (`AI` in SDDL): a write
    /// on a handle must say so again, or the flag is lost.
    auto_inherited: bool,
}

impl Dacl {
    fn read(path: &Path) -> Result<Self> {
        let name = wide(path.as_os_str());
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let mut acl: *mut ACL = std::ptr::null_mut();
        // SAFETY: `name` is NUL-terminated; `sd` is LocalAlloc'd on success
        // and owned by the returned value; `acl` points into it.
        let rc = unsafe {
            GetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut acl,
                std::ptr::null_mut(),
                &mut sd,
            )
        };
        if rc != ERROR_SUCCESS {
            bail!("{}", std::io::Error::from_raw_os_error(rc as i32));
        }
        let (mut control, mut revision) = (0u16, 0u32);
        // SAFETY: `sd` is the descriptor just read.
        unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) };
        Ok(Self {
            sd,
            acl,
            protected: control & SE_DACL_PROTECTED != 0,
            auto_inherited: control & SE_DACL_AUTO_INHERITED != 0,
        })
    }

    /// The groups of `groups` an entry of this list lets write, by name.
    fn broad_names(&self, groups: &[(Sid, &'static str)]) -> Result<Vec<&'static str>> {
        let mut out = Vec::new();
        for ace in self.aces()? {
            // SAFETY: an entry of this list.
            unsafe {
                if let Some((name, mask)) = broad_allow(ace, groups)
                    && mask & WRITE_RIGHTS != 0
                    && !out.contains(&name)
                {
                    out.push(name);
                }
            }
        }
        Ok(out)
    }

    /// The groups of `groups` an entry of this list lets do anything —
    /// reading included — by name.
    fn broad_any(&self, groups: &[(Sid, &'static str)]) -> Result<Vec<&'static str>> {
        let mut out = Vec::new();
        for ace in self.aces()? {
            // SAFETY: an entry of this list.
            if let Some((name, _)) = unsafe { broad_allow(ace, groups) }
                && !out.contains(&name)
            {
                out.push(name);
            }
        }
        Ok(out)
    }

    /// Whether an allow entry of this list's own (not inherited) names one of
    /// `groups`.
    fn names_own(&self, groups: &[(Sid, &'static str)]) -> Result<bool> {
        Ok(self.aces()?.into_iter().any(|ace| {
            // SAFETY: an entry of this list.
            unsafe {
                u32::from((*ace.cast::<ACE_HEADER>()).AceFlags) & INHERITED_ACE == 0 && broad_allow(ace, groups).is_some()
            }
        }))
    }

    /// Whether an entry of this list, of any kind and wherever it came from,
    /// names `sid`.
    fn mentions(&self, sid: &Sid) -> Result<bool> {
        Ok(self.aces()?.into_iter().any(|ace| {
            // SAFETY: an entry of this list; an allowed and a denied entry
            // share ACCESS_ALLOWED_ACE's layout, the SID at `SidStart`.
            unsafe {
                let header = &*ace.cast::<ACE_HEADER>();
                (header.AceType == ACCESS_ALLOWED || header.AceType == ACCESS_DENIED)
                    && EqualSid((&raw const (*ace.cast::<ACCESS_ALLOWED_ACE>()).SidStart).cast_mut().cast(), sid.0) != 0
            }
        }))
    }

    /// The list's entries, pointers into it (empty for no list).
    fn aces(&self) -> Result<Vec<*mut core::ffi::c_void>> {
        if self.acl.is_null() {
            return Ok(Vec::new());
        }
        let mut info = ACL_SIZE_INFORMATION::default();
        // SAFETY: `acl` is a valid list owned by `sd`; `info` is sized.
        if unsafe {
            GetAclInformation(self.acl, (&raw mut info).cast(), std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32, AclSizeInformation)
        } == 0
        {
            bail!("read the access list: {}", std::io::Error::last_os_error());
        }
        (0..info.AceCount)
            .map(|i| {
                let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
                // SAFETY: `i` is below the list's count.
                if unsafe { GetAce(self.acl, i, &mut ace) } == 0 {
                    bail!("read the access list: {}", std::io::Error::last_os_error());
                }
                Ok(ace)
            })
            .collect()
    }

    /// Whether `aces` (a list's entries) hold an explicit entry for `sid` granting (or
    /// denying, for a deny kind) at least `kind`'s rights with its inheritance.
    fn has(aces: &[*mut core::ffi::c_void], sid: &Sid, kind: Kind) -> bool {
        let want_type = if kind.is_deny() { ACCESS_DENIED } else { ACCESS_ALLOWED };
        aces.iter().any(|&ace| {
            // SAFETY: an entry of this list; an allowed and a denied entry
            // share ACCESS_ALLOWED_ACE's layout, the SID at `SidStart`.
            unsafe {
                let header = &*ace.cast::<ACE_HEADER>();
                if header.AceType != want_type || u32::from(header.AceFlags) & INHERITED_ACE != 0 {
                    return false;
                }
                let entry = &*ace.cast::<ACCESS_ALLOWED_ACE>();
                let flags = u32::from(header.AceFlags) & 0x3;
                entry.Mask & kind.mask() == kind.mask()
                    && flags == kind.inheritance()
                    && EqualSid((&raw const entry.SidStart).cast_mut().cast(), sid.0) != 0
            }
        })
    }

    /// Write this list back to `path` without its explicit entries — allow
    /// and deny alike — for any of `whom`. (`SetEntriesInAclW`'s revoke
    /// removes allow entries only.) Written on the object alone when every
    /// removed entry reached it alone, which is read from the entries
    /// themselves; otherwise by name. When none is left to remove, nothing is
    /// written — unless `was_inheritable` (the record says an inheritable
    /// entry was granted here): then by name, taking back the inherited
    /// copies an earlier write cut short left below a folder that no longer
    /// holds the entry.
    fn write_without(&self, path: &Path, whom: &[&Sid], was_inheritable: bool, progress: &Progress) -> Result<()> {
        // No list at all grants everyone everything and names nobody: an
        // empty one written in its place would refuse everyone.
        if self.acl.is_null() {
            return Ok(());
        }
        let aces = self.aces()?;
        let mut buf = AclBuf::for_entries(&aces)?;
        let (mut dropped, mut inheritable) = (false, false);
        for ace in aces {
            // SAFETY: an entry of this list; an allowed and a denied entry
            // share ACCESS_ALLOWED_ACE's layout.
            unsafe {
                let header = &*ace.cast::<ACE_HEADER>();
                let explicit = u32::from(header.AceFlags) & INHERITED_ACE == 0;
                let typed = header.AceType == ACCESS_ALLOWED || header.AceType == ACCESS_DENIED;
                if explicit && typed {
                    let sid = (&raw const (*ace.cast::<ACCESS_ALLOWED_ACE>()).SidStart).cast_mut().cast();
                    if whom.iter().any(|w| EqualSid(sid, w.0) != 0) {
                        dropped = true;
                        inheritable |= u32::from(header.AceFlags) & OBJECT_AND_CONTAINER_INHERIT != 0;
                        continue;
                    }
                }
                buf.push(std::slice::from_raw_parts(ace.cast::<u8>(), usize::from(header.AceSize)))?;
            }
        }
        if !dropped && !was_inheritable {
            return Ok(());
        }
        // A path granted an inheritable entry is rewritten by name whatever
        // is removed now: copies of that entry may still sit below it.
        self.store(path, buf.acl(), dropped && !inheritable && !was_inheritable, progress)
    }

    /// Merge `entries` into this list and write it back to `path` — on the
    /// object alone when `local` (no entry is inheritable).
    fn write_with(&self, path: &Path, entries: &[EXPLICIT_ACCESS_W], local: bool, progress: &Progress) -> Result<()> {
        // No list grants everyone everything: one built from our entries
        // alone would lock everyone else out.
        if self.acl.is_null() {
            bail!("it has no access list (every account may do anything there), so the sandbox cannot confine it");
        }
        let mut new_acl: *mut ACL = std::ptr::null_mut();
        // SAFETY: `entries` are valid (their trustee SIDs outlive the call);
        // `new_acl` is LocalAlloc'd on success and freed below, once.
        let rc = unsafe { SetEntriesInAclW(entries.len() as u32, entries.as_ptr(), self.acl, &mut new_acl) };
        if rc != ERROR_SUCCESS {
            bail!("build the access list: {}", std::io::Error::from_raw_os_error(rc as i32));
        }
        let done = self.store(path, new_acl, local, progress);
        // SAFETY: allocated by SetEntriesInAclW above.
        unsafe { LocalFree(new_acl.cast()) };
        done
    }

    /// Write `acl` as the list of `path`. By name, which re-applies what
    /// everything below inherits (walking the tree, each item reported to
    /// `progress`); or, when `local`, on an open handle to the object alone,
    /// its protection and auto-inheritance flags kept as read — no file below
    /// is touched.
    fn store(&self, path: &Path, acl: *mut ACL, local: bool, progress: &Progress) -> Result<()> {
        if !local {
            return write_by_name(path, acl, DACL_SECURITY_INFORMATION, progress);
        }
        self.write_local(path, acl, self.protected, self.auto_inherited)
    }

    /// Whether this list may be written on `path`: opened for that, nothing
    /// written.
    fn open_to_change(&self, path: &Path) -> Result<()> {
        use std::os::windows::fs::OpenOptionsExt;
        const READ_CONTROL: u32 = 0x2_0000;
        const WRITE_DAC: u32 = 0x4_0000;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        std::fs::OpenOptions::new()
            .access_mode(READ_CONTROL | WRITE_DAC)
            .share_mode(0x7)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)?;
        Ok(())
    }

    /// Write `acl` as the list of `path` on an open handle to the object
    /// alone, protected or not as `protected` says — nothing below is
    /// touched. `auto_inherited` keeps the list marked for automatic
    /// inheritance (`AI`), which a handle write loses unless it asks for it.
    fn write_local(&self, path: &Path, acl: *mut ACL, protected: bool, auto_inherited: bool) -> Result<()> {
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        const READ_CONTROL: u32 = 0x2_0000;
        const WRITE_DAC: u32 = 0x4_0000;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        // Followed like the read by name (a junction is its target); backup
        // semantics opens a folder.
        let file = std::fs::OpenOptions::new()
            .access_mode(READ_CONTROL | WRITE_DAC)
            .share_mode(0x7)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)?;
        let mut sd = SECURITY_DESCRIPTOR::default();
        let sd_ptr: PSECURITY_DESCRIPTOR = (&raw mut sd).cast();
        let mut bits = 0;
        if protected {
            bits |= SE_DACL_PROTECTED;
        }
        // A handle write keeps `AI` only when it asks for it; the request
        // reaches this object alone (the walk below is the by-name writer's).
        if auto_inherited {
            bits |= SE_DACL_AUTO_INHERITED | SE_DACL_AUTO_INHERIT_REQ;
        }
        // SAFETY: `sd` is a local descriptor living past the call; `acl` is
        // valid; the handle is open for the duration of the call.
        unsafe {
            if InitializeSecurityDescriptor(sd_ptr, 1) == 0
                || SetSecurityDescriptorDacl(sd_ptr, 1, acl, 0) == 0
                || SetSecurityDescriptorControl(
                    sd_ptr,
                    SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED | SE_DACL_AUTO_INHERIT_REQ,
                    bits,
                ) == 0
                || SetKernelObjectSecurity(file.as_raw_handle(), DACL_SECURITY_INFORMATION, sd_ptr) == 0
            {
                bail!("{}", std::io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

impl Drop for Dacl {
    fn drop(&mut self) {
        // SAFETY: allocated by GetNamedSecurityInfoW, freed once.
        unsafe { LocalFree(self.sd) };
    }
}

pub(super) fn trustee(sid: &Sid) -> TRUSTEE_W {
    TRUSTEE_W {
        pMultipleTrustee: std::ptr::null_mut(),
        MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_UNKNOWN,
        ptstrName: sid.0.cast(),
    }
}

/// What the grants touched, per project: the record `revoke` reads.
#[derive(Debug, Default, Serialize, Deserialize)]
struct GrantRecord {
    projects: BTreeMap<String, Vec<GrantedPath>>,
    /// Folders (lowercased) whose making private was started and has not
    /// returned: a run makes each private again before granting it.
    #[serde(default, skip_serializing_if = "std::collections::BTreeSet::is_empty")]
    private_pending: std::collections::BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct GrantedPath {
    path: String,
    /// The grant added an `OWNER RIGHTS` entry here too.
    #[serde(default)]
    owner_rights: bool,
    /// The grant wrote an inheritable entry here, whose copies a by-name
    /// write gives every file below: a revoke finding the entry gone still
    /// rewrites below, in case that write was cut short. Never set on a
    /// folder above a grant, which is never walked.
    #[serde(default)]
    inheritable: bool,
}

impl GrantRecord {
    fn load(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).context("parse the sandbox grant record"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).context("read the sandbox grant record"),
        }
    }

    fn save(&self, path: &Path) -> Result<()> {
        crate::state::write_private(path, &serde_json::to_vec_pretty(self)?)
    }
}

fn key(root: &Path) -> String {
    root.to_string_lossy().to_lowercase()
}

/// Hold the record's lock (a file beside it) until the guard drops: two runs
/// starting together each read, change and write it, and without the lock
/// one would lose the other's project.
fn lock_record(record: &Path) -> Result<std::fs::File> {
    if let Some(dir) = record.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    let path = record.with_extension("lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;
    match file.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => {
            crate::ui::note("", "waiting for another ssai run to finish changing the sandbox's access…");
            file.lock().with_context(|| format!("lock {}", path.display()))?;
        }
        Err(std::fs::TryLockError::Error(e)) => return Err(e).with_context(|| format!("lock {}", path.display())),
    }
    Ok(file)
}

/// Add `aces` to the record of project `root`. The caller holds the lock.
fn record_grants(file: &Path, root: &Path, aces: &[Ace]) -> Result<()> {
    let mut record = GrantRecord::load(file)?;
    let paths = record.projects.entry(key(root)).or_default();
    for ace in aces {
        let path = ace.path.to_string_lossy().into_owned();
        let owner_rights = ace.trustee == Trustee::OwnerRights;
        let inheritable = ace.kind.inheritance() != 0;
        match paths.iter_mut().find(|p| p.path == path) {
            Some(p) => {
                p.owner_rights |= owner_rights;
                p.inheritable |= inheritable;
            }
            None => paths.push(GrantedPath { path, owner_rights, inheritable }),
        }
    }
    record.save(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The access list of `path` in SDDL, its entries for `sid` only.
    fn entries_for(path: &Path, sid: &str) -> Vec<String> {
        let dacl = dacl_of(path);
        let aces = &dacl[dacl.find('(').unwrap_or(dacl.len())..];
        aces.split_inclusive(')').filter(|a| a.contains(sid)).map(str::to_string).collect()
    }

    /// The access list of `path` in SDDL, from `D:` up to a SACL.
    fn dacl_of(path: &Path) -> String {
        let out = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", &format!("(Get-Acl -LiteralPath '{}').Sddl", path.display())])
            .output()
            .unwrap();
        let sddl = String::from_utf8_lossy(&out.stdout).trim().to_string();
        format!("D:{}", sddl.split("D:").nth(1).unwrap_or("").split("S:").next().unwrap_or(""))
    }

    /// Give `file` exactly the list `sddl`, on the file alone.
    fn set_file_sddl(file: &Path, sddl: &str) {
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows_sys::Win32::Security::SetFileSecurityW;
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let text = wide(std::ffi::OsStr::new(sddl));
        let name = wide(file.as_os_str());
        // SAFETY: NUL-terminated strings; `sd` is LocalAlloc'd and freed once.
        unsafe {
            assert_ne!(ConvertStringSecurityDescriptorToSecurityDescriptorW(text.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut()), 0);
            // `SetFileSecurityW` reads no protection from the SDDL: it is
            // stated, protected for `D:P…`, inheriting otherwise.
            const UNPROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x2000_0000;
            let info = DACL_SECURITY_INFORMATION
                | if sddl.starts_with("D:P") { PROTECTED_DACL_SECURITY_INFORMATION } else { UNPROTECTED_DACL_SECURITY_INFORMATION };
            assert_ne!(SetFileSecurityW(name.as_ptr(), info, sd), 0);
            LocalFree(sd);
        }
    }

    /// The list entry each folder above the project gets reaches that
    /// folder alone: adding and removing it rewrites nothing below (a child
    /// keeps an entry only a rewrite of its list would drop) and gives the
    /// folder back its exact list, flags included — on a folder built for
    /// auto-inheritance (`AI`) and on a protected one (`P`), as the profile
    /// is. An inheritable entry does rewrite what is below.
    #[test]
    fn an_entry_for_a_folder_alone_rewrites_nothing_below_it() {
        const GUESTS: &str = "S-1-5-32-546";
        let me = crate::win_acl::current_user_sid().unwrap();
        let base = std::env::temp_dir().join(format!("ssai-acl-local-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let (auto, private) = (base.join("auto"), base.join("private"));
        for d in [&auto, &private] {
            std::fs::create_dir_all(d).unwrap();
            std::fs::write(d.join("f"), "x").unwrap();
        }
        // A list written by name is marked for auto-inheritance.
        let d = Dacl::read(&auto).unwrap();
        d.store(&auto, d.acl, false, &Progress::silent()).unwrap();
        drop(d);
        let record_dir = std::env::temp_dir().join(format!("ssai-acl-local-record-{}", std::process::id()));
        let record = record_dir.join("grants.json");
        // Protected as a private folder is (`make_private_root` leaves alone one
        // no broad group writes).
        write_private_list(&private, &me, GUESTS, &Progress::silent()).unwrap();
        // An entry flagged inherited that the parent does not hold: any
        // rewrite of the child's list recomputes its inherited entries and
        // drops it.
        let marker = "(A;ID;FR;;;BG)";
        for (dir, flags) in [(&auto, "D:AI("), (&private, "D:PAI(")] {
            let child = dir.join("f");
            set_file_sddl(&child, &format!("D:AI(A;ID;FA;;;SY)(A;ID;FA;;;{me}){marker}"));
            assert!(dacl_of(&child).contains(marker));
            let before = dacl_of(dir);
            assert!(before.starts_with(flags), "{before}");
            let aces = vec![Ace { path: dir.to_path_buf(), trustee: Trustee::Account, kind: Kind::ListFolder }];
            assert_eq!(apply(&record, GUESTS, dir, &aces, &Progress::silent()).unwrap().changed.len(), 1);
            let granted = dacl_of(dir);
            assert!(granted.starts_with(flags), "{granted}");
            assert!(entries_for(dir, "BG").contains(&"(A;;0x100081;;;BG)".to_string()), "{granted}");
            assert!(dacl_of(&child).contains(marker), "the child's list was rewritten by the grant");
            revoke(&record, GUESTS, Some(dir), &Progress::silent()).unwrap();
            assert_eq!(dacl_of(dir), before, "revoke gives the folder back its exact list");
            assert!(dacl_of(&child).contains(marker), "the child's list was rewritten by the revoke");
            // Positive control: an inheritable entry reaches the child.
            let aces = vec![Ace { path: dir.to_path_buf(), trustee: Trustee::Account, kind: Kind::Modify }];
            apply(&record, GUESTS, dir, &aces, &Progress::silent()).unwrap();
            assert!(!dacl_of(&child).contains(marker), "an inheritable entry did not reach the child");
            revoke(&record, GUESTS, Some(dir), &Progress::silent()).unwrap();
            assert!(entries_for(&child, "BG").is_empty(), "revoke took the inherited copy back");
        }
        let _ = std::fs::remove_dir_all(&record_dir);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A grant whose by-name write was cut short leaves the inherited copies
    /// below a folder whose own entry is gone: revoke, finding nothing to
    /// remove there, still rewrites below (the record says the entry was
    /// inheritable) and takes them back.
    #[test]
    fn a_revoke_takes_back_what_a_cut_short_grant_left_below() {
        const GUESTS: &str = "S-1-5-32-546";
        let base = std::env::temp_dir().join(format!("ssai-acl-cut-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("f"), "x").unwrap();
        let record_dir = std::env::temp_dir().join(format!("ssai-acl-cut-record-{}", std::process::id()));
        let record = record_dir.join("grants.json");
        let aces = vec![Ace { path: base.clone(), trustee: Trustee::Account, kind: Kind::Modify }];
        apply(&record, GUESTS, &base, &aces, &Progress::silent()).unwrap();
        assert_eq!(entries_for(&base.join("f"), "BG").len(), 1, "the child inherits the entry");
        // The folder's own entry gone, on the folder alone: the copy below stays.
        let own = dacl_of(&base).replace("(A;OICI;0x1301bf;;;BG)", "");
        set_file_sddl(&base, &own);
        assert!(entries_for(&base, "BG").is_empty());
        assert_eq!(entries_for(&base.join("f"), "BG").len(), 1);
        revoke(&record, GUESTS, Some(&base), &Progress::silent()).unwrap();
        assert!(entries_for(&base.join("f"), "BG").is_empty(), "{}", dacl_of(&base.join("f")));
        let _ = std::fs::remove_dir_all(&record_dir);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A folder Authenticated Users may write (as one made under a drive's
    /// root is) is named so; made a private root, it inherits nothing, names
    /// no group every account belongs to (reading included), the developer
    /// holds full control, and a protected file in it the caller listed
    /// inherits again. A takeover cut short reads pending until one finishes.
    #[test]
    fn a_folder_every_account_may_write_is_made_a_private_root() {
        const AUTHENTICATED_USERS: &str = "S-1-5-11";
        let me = crate::win_acl::current_user_sid().unwrap();
        // In the profile, which no broad group writes (a temporary folder may
        // be one they do: `C:\Windows\Temp`, a runner's work folder).
        let base = crate::state::home_dir().unwrap().join(format!("ssai-acl-private-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let open = base.join("open");
        std::fs::create_dir_all(open.join("sub")).unwrap();
        std::fs::write(open.join("sub/f"), "x").unwrap();
        std::fs::write(open.join("sub/locked"), "x").unwrap();
        assert!(broad_writers(&open).unwrap().is_empty(), "a folder in the profile");
        let record_dir = std::env::temp_dir().join(format!("ssai-acl-private-record-{}", std::process::id()));
        let record = record_dir.join("grants.json");
        // A granted project above it: the sandbox account (here Guests) holds
        // an inherited entry in the folder.
        const GUESTS: &str = "S-1-5-32-546";
        // Its held tree's deny reaches the folder too.
        let above = vec![
            Ace { path: base.clone(), trustee: Trustee::Account, kind: Kind::Modify },
            Ace { path: base.clone(), trustee: Trustee::Account, kind: Kind::DenyTree },
        ];
        apply(&record, GUESTS, &base, &above, &Progress::silent()).unwrap();
        assert_eq!(entries_for(&open, "BG").len(), 2);
        let aces = vec![Ace { path: open.clone(), trustee: Trustee::Account, kind: Kind::Modify }];
        apply(&record, AUTHENTICATED_USERS, &open, &aces, &Progress::silent()).unwrap();
        assert_eq!(broad_writers(&open).unwrap(), vec!["Authenticated Users"]);
        assert_eq!(broad_writers(&open.join("sub/f")).unwrap(), vec!["Authenticated Users"]);
        assert_eq!(root_state(&record, &open).unwrap(), RootState::Open(vec!["Authenticated Users"]));
        // A file the developer locked to themselves: protected, every
        // account named in it, out of any grant's reach.
        set_file_sddl(&open.join("sub/locked"), &format!("D:P(A;;FA;;;{me})(A;;FR;;;AU)"));
        // A file that inherits and gives every account read by its own entry.
        std::fs::write(open.join("sub/shared"), "x").unwrap();
        let granted_read = std::process::Command::new("icacls")
            .arg(open.join("sub/shared"))
            .args(["/grant", "*S-1-5-32-545:(R)"])
            .output()
            .unwrap();
        assert!(granted_read.status.success(), "{granted_read:?}");
        let found = scan(&open, None, &Progress::silent()).unwrap();
        assert_eq!(found.protected, vec![open.join("sub/locked")]);
        assert_eq!(found.broad, vec![open.join("sub/shared")]);
        let items: Vec<PathBuf> = found.protected.iter().chain(&found.broad).cloned().collect();

        // A takeover cut short (the folder left marked) reads pending, and
        // one that finishes clears the mark.
        let mut marked = GrantRecord::load(&record).unwrap();
        marked.private_pending.insert(key(&open));
        marked.save(&record).unwrap();
        assert_eq!(root_state(&record, &open).unwrap(), RootState::Pending);
        let refused = make_private_root(&record, &open, &me, GUESTS, &items, &Progress::silent()).unwrap();
        assert!(refused.is_empty(), "{refused:?}");
        assert_eq!(root_state(&record, &open).unwrap(), RootState::Private);
        // The account's inherited allow is dropped, never made the folder's
        // own, so the project above's revoke still reaches everything; its
        // inherited deny is kept and keeps holding the account out.
        let left = entries_for(&open, "BG");
        assert!(left.iter().all(|e| e.starts_with("(D;")) && left.len() == 1, "{}", dacl_of(&open));
        revoke(&record, GUESTS, Some(&base), &Progress::silent()).unwrap();
        let list = dacl_of(&open);
        assert!(list.starts_with("D:P"), "{list}");
        assert!(!list.contains(";ID;") && !list.contains("ID;"), "nothing inherited: {list}");
        assert!(list.contains(&format!("(A;OICI;FA;;;{me})")), "{list}");
        // No group every account belongs to, reading or writing, anywhere.
        for p in [open.clone(), open.join("sub"), open.join("sub/f"), open.join("sub/locked"), open.join("sub/shared")] {
            assert!(entries_for(&p, "AU").is_empty(), "{p:?}: {}", dacl_of(&p));
            assert!(entries_for(&p, "BU").is_empty(), "{p:?}: {}", dacl_of(&p));
        }
        // The locked file inherits again: the developer's full control
        // reaches it from the root.
        let locked = dacl_of(&open.join("sub/locked"));
        assert!(!locked.starts_with("D:P"), "{locked}");
        assert!(locked.contains(&format!("(A;ID;FA;;;{me})")), "{locked}");
        let _ = std::fs::remove_dir_all(&record_dir);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A folder naming `CREATOR OWNER` (as many drives do) is not private:
    /// whoever creates a file there — the agent — would hold full control of
    /// it. A takeover drops the entry; the same folder then reads private.
    #[test]
    fn a_creators_entry_keeps_a_folder_from_being_private() {
        const GUESTS: &str = "S-1-5-32-546";
        let me = crate::win_acl::current_user_sid().unwrap();
        let base = crate::state::home_dir().unwrap().join(format!("ssai-acl-creator-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let record_dir = std::env::temp_dir().join(format!("ssai-acl-creator-record-{}", std::process::id()));
        let record = record_dir.join("grants.json");
        set_file_sddl(&base, &format!("D:P(A;OICI;FA;;;{me})(A;OICIIO;FA;;;CO)"));
        assert_eq!(root_state(&record, &base).unwrap(), RootState::Open(vec!["CREATOR OWNER"]));
        make_private_root(&record, &base, &me, GUESTS, &[], &Progress::silent()).unwrap();
        assert_eq!(root_state(&record, &base).unwrap(), RootState::Private);
        assert!(entries_for(&base, "CO").is_empty(), "{}", dacl_of(&base));
        let _ = std::fs::remove_dir_all(&record_dir);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A project folder made private on its own (protected, every account
    /// reading but none writing) reads so; one every account writes, one
    /// still inheriting, and one whose change is pending do not.
    #[test]
    fn a_folder_made_private_on_its_own_is_told_apart() {
        let me = crate::win_acl::current_user_sid().unwrap();
        let base = crate::state::home_dir().unwrap().join(format!("ssai-acl-alone-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let record_dir = std::env::temp_dir().join(format!("ssai-acl-alone-record-{}", std::process::id()));
        let record = record_dir.join("grants.json");
        set_file_sddl(&base, &format!("D:P(A;OICI;FA;;;{me})(A;OICI;0x1200a9;;;AU)"));
        assert!(private_alone(&record, &base).unwrap());
        set_file_sddl(&base, &format!("D:P(A;OICI;FA;;;{me})(A;OICI;0x1301bf;;;AU)"));
        assert!(!private_alone(&record, &base).unwrap(), "every account writes it");
        // A folder that inherits (as made: never protected).
        let fresh = base.join("fresh");
        std::fs::create_dir_all(&fresh).unwrap();
        assert!(!private_alone(&record, &fresh).unwrap(), "it inherits");
        set_file_sddl(&base, &format!("D:P(A;OICI;FA;;;{me})"));
        assert!(private_alone(&record, &base).unwrap());
        let mut marked = GrantRecord::load(&record).unwrap();
        marked.private_pending.insert(key(&base));
        marked.save(&record).unwrap();
        assert!(!private_alone(&record, &base).unwrap(), "pending");
        let _ = std::fs::remove_dir_all(&record_dir);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// `status` names each project by its own recorded path with the rest
    /// apart, and keeps an entry a partial revoke left without its project's
    /// own path (still granted), which `granted_projects` leaves out.
    #[test]
    fn the_listing_names_each_project_and_keeps_what_a_revoke_left() {
        let record_dir = std::env::temp_dir().join(format!("ssai-acl-listing-record-{}", std::process::id()));
        let record = record_dir.join("grants.json");
        let entry = |path: &str| GrantedPath { path: path.into(), owner_rights: false, inheritable: false };
        let mut held = GrantRecord::default();
        held.projects.insert(r"c:\users\me\app".into(), vec![entry(r"C:\Users\me"), entry(r"C:\Users\Me\App"), entry(r"C:\Tools\ssai")]);
        held.projects.insert(r"c:\users\me\gone".into(), vec![entry(r"C:\Tools\aider")]);
        held.save(&record).unwrap();
        let listed = granted(&record).unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].root.as_deref(), Some(Path::new(r"C:\Users\Me\App")));
        assert_eq!(listed[0].others, [PathBuf::from(r"C:\Tools\ssai"), PathBuf::from(r"C:\Users\me")], "sorted");
        assert_eq!(listed[1].root, None);
        assert_eq!(listed[1].key, r"c:\users\me\gone");
        assert_eq!(listed[1].others, [PathBuf::from(r"C:\Tools\aider")]);
        assert_eq!(granted_projects(&record).unwrap(), [PathBuf::from(r"C:\Users\Me\App")]);
        // No record: nothing granted, not an error.
        let _ = std::fs::remove_dir_all(&record_dir);
        assert!(granted(&record).unwrap().is_empty());
    }

    /// What a scan of a granted project finds out of the grant's reach, and
    /// the repair: a protected folder (and the file in it), a protected file,
    /// a file moved in after the grant (its old folder's list) — each listed,
    /// and each reached by the account after `unprotect` + `rewrite`; the
    /// manifest's key file and `.streamscopeai` left alone; a project whose
    /// manifest does not read listed as skipped, nothing below it listed. The
    /// positive control: a file made after the grant is not listed.
    #[test]
    fn a_scan_finds_what_the_grant_misses_and_the_repair_reaches_it() {
        const GUESTS: &str = "S-1-5-32-546";
        let me = crate::win_acl::current_user_sid().unwrap();
        let base = crate::state::home_dir().unwrap().join(format!("ssai-acl-scan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("proj");
        let elsewhere = base.join("elsewhere");
        for d in [root.join("walled"), root.join(".streamscopeai"), root.join(".claude"), root.join("bad/.streamscopeai"), elsewhere.clone()] {
            std::fs::create_dir_all(d).unwrap();
        }
        let key_file = dunce::canonicalize(&root).unwrap().join(".claude").join("settings.json");
        std::fs::write(&key_file, "{}").unwrap();
        let mut manifest = crate::state::Manifest::default();
        let mut ws = crate::state::WorkspaceManifest::default();
        ws.clients.push(crate::state::ManagedClient {
            client_id: "claude-code".into(),
            template_index: 0,
            mode: "gateway".into(),
            provider_id: None,
            key_id: None,
            mcp_server_ids: Vec::new(),
            mcp_local_servers: Vec::new(),
            mcp_local_commands: Default::default(),
            files: vec![crate::state::ManagedFile {
                path: key_file.to_string_lossy().into_owned(),
                format: "json".into(),
                owned: Vec::new(),
                file_hash: "x".into(),
            }],
            last_provisioned: chrono::Utc::now(),
            launch_command: None,
            usable_as_tool: false,
        });
        manifest.hosts.insert("https://gw#t".into(), ws);
        std::fs::write(root.join(".streamscopeai/manifest.json"), serde_json::to_vec(&manifest).unwrap()).unwrap();
        std::fs::write(root.join("bad/.streamscopeai/manifest.json"), "{ not json").unwrap();
        std::fs::write(root.join("bad/hidden"), "x").unwrap();
        std::fs::write(root.join("walled/in"), "x").unwrap();
        std::fs::write(root.join("locked"), "x").unwrap();
        std::fs::write(root.join("everyone"), "x").unwrap();
        let record_dir = std::env::temp_dir().join(format!("ssai-acl-scan-record-{}", std::process::id()));
        let record = record_dir.join("grants.json");
        let aces = vec![Ace { path: root.clone(), trustee: Trustee::Account, kind: Kind::Modify }];
        apply(&record, GUESTS, &root, &aces, &Progress::silent()).unwrap();
        // After the grant: a protected folder and file, the key file locked
        // as provisioning writes it, a file moved in, a file made.
        set_file_sddl(&root.join("walled"), &format!("D:P(A;OICI;FA;;;{me})"));
        set_file_sddl(&root.join("locked"), &format!("D:P(A;;FA;;;{me})"));
        // Every account's full control alone: dropping it must not leave a
        // list the developer may not change.
        set_file_sddl(&root.join("everyone"), "D:P(A;;FA;;;WD)");
        set_file_sddl(&key_file, &format!("D:P(A;;FA;;;{me})"));
        std::fs::write(elsewhere.join("moved"), "x").unwrap();
        std::fs::rename(elsewhere.join("moved"), root.join("moved")).unwrap();
        std::fs::write(root.join("made"), "x").unwrap();
        let found = scan(&root, Some(GUESTS), &Progress::silent()).unwrap();
        let mut protected = found.protected.clone();
        protected.sort();
        assert_eq!(protected, vec![root.join("everyone"), root.join("locked"), root.join("walled")]);
        assert_eq!(found.stale, vec![root.join("moved")], "the file in the walled folder is the protected one's");
        assert!(found.kept.contains(&root.join(".streamscopeai")), "{:?}", found.kept);
        assert!(found.kept.iter().any(|k| k.ends_with(".claude/settings.json") || k.ends_with(".claude\\settings.json")), "{:?}", found.kept);
        assert_eq!(found.skipped.len(), 1, "{:?}", found.skipped);
        assert!(found.skipped[0].0.ends_with("bad"));
        assert!(!found.stale.iter().chain(&found.protected).any(|p| p.starts_with(root.join("bad"))));

        let refused = unprotect(&found.protected, &me, &Progress::silent()).unwrap();
        assert!(refused.is_empty(), "{refused:?}");
        for tree in granted_trees(&record, &root).unwrap() {
            rewrite(&tree, &Progress::silent()).unwrap();
        }
        for p in [root.join("walled"), root.join("walled/in"), root.join("locked"), root.join("everyone"), root.join("moved"), root.join("made")] {
            assert_eq!(entries_for(&p, "BG").len(), 1, "{p:?}: {}", dacl_of(&p));
        }
        let everyone = dacl_of(&root.join("everyone"));
        assert!(entries_for(&root.join("everyone"), "WD").is_empty(), "{everyone}");
        assert!(everyone.contains(&format!("(A;;FA;;;{me})")), "{everyone}");
        let again = scan(&root, Some(GUESTS), &Progress::silent()).unwrap();
        assert!(again.protected.is_empty() && again.stale.is_empty(), "{again:?}");
        // The key file kept its own list, untouched.
        assert!(dacl_of(&key_file).starts_with("D:P"), "{}", dacl_of(&key_file));
        assert!(entries_for(&key_file, "BG").is_empty());
        revoke(&record, GUESTS, Some(&root), &Progress::silent()).unwrap();
        let _ = std::fs::remove_dir_all(&record_dir);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A by-name write counts every item it walks and leaves a protected
    /// item's list as it is (a refusal cannot be staged for a test runner
    /// holding restore privileges: `note` is tested on its own).
    #[test]
    fn a_by_name_write_counts_what_it_walks_and_keeps_what_is_protected() {
        let me = crate::win_acl::current_user_sid().unwrap();
        let base = crate::state::home_dir().unwrap().join(format!("ssai-acl-walk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("sub")).unwrap();
        for f in ["a", "b", "sub/c", "kept"] {
            std::fs::write(base.join(f), "x").unwrap();
        }
        set_file_sddl(&base.join("kept"), &format!("D:P(A;;FA;;;{me})"));
        let kept = dacl_of(&base.join("kept"));
        // A junction (as pnpm makes in node_modules) to a folder elsewhere:
        // never walked into, and no refusal.
        let target = crate::state::home_dir().unwrap().join(format!("ssai-acl-walk-target-{}", std::process::id()));
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("t"), "x").unwrap();
        let target_list = dacl_of(&target.join("t"));
        let made = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(base.join("link"))
            .arg(&target)
            .output()
            .unwrap();
        assert!(made.status.success(), "{made:?}");
        let progress = Progress::silent();
        // Positive control: every item walked (the folder, a, b, sub, sub/c),
        // none refused; the protected one is left as it was.
        assert!(rewrite(&base, &progress).unwrap() >= 5);
        assert_eq!(dacl_of(&base.join("kept")), kept);
        assert_eq!(dacl_of(&target.join("t")), target_list, "the walk went through the junction");
        let _ = std::fs::remove_dir(base.join("link"));
        let _ = std::fs::remove_dir_all(&target);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// An item a walk named and no call set — Windows passes a refused item
    /// by with no error — is kept; one set on its last call is not, a folder
    /// set after its contents included; what is kept is what is unset, never
    /// the whole walk.
    #[test]
    fn an_item_named_and_never_set_is_kept() {
        let mut unset = std::collections::HashSet::new();
        // The calls a walk of `d` (holding `a`, and `b` refused) makes.
        for (item, set) in [("d", false), ("a", false), ("a", true), ("b", false), ("b", false), ("d", true)] {
            note(&mut unset, item.to_string(), set);
        }
        assert_eq!(unset, std::collections::HashSet::from(["b".to_string()]));
        // Mid-walk only the folder being walked is held.
        let mut mid = std::collections::HashSet::new();
        for (item, set) in [("d", false), ("a", false), ("a", true)] {
            note(&mut mid, item.to_string(), set);
        }
        assert_eq!(mid, std::collections::HashSet::from(["d".to_string()]));
    }

    /// Grants for the built-in Guests group (present on every Windows, never
    /// the test runner): the exact entries land, a deny carries no
    /// SYNCHRONIZE, a second apply changes nothing, and revoke removes them.
    #[test]
    fn grants_land_exactly_once_and_revoke_removes_them() {
        const GUESTS: &str = "S-1-5-32-546";
        let base = std::env::temp_dir().join(format!("ssai-acl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("hooks")).unwrap();
        std::fs::write(base.join("config"), "x").unwrap();
        let aces = vec![
            Ace { path: base.clone(), trustee: Trustee::Account, kind: Kind::Modify },
            Ace { path: base.clone(), trustee: Trustee::Account, kind: Kind::DenyNode },
            Ace { path: base.join("hooks"), trustee: Trustee::Account, kind: Kind::DenyTree },
            Ace { path: base.join("config"), trustee: Trustee::Account, kind: Kind::DenyFile },
        ];
        // In a folder of its own: writing the record makes its folder owner-only.
        let record_dir = std::env::temp_dir().join(format!("ssai-acl-record-{}", std::process::id()));
        let record = record_dir.join("grants.json");
        let applied = apply(&record, GUESTS, &base, &aces, &Progress::silent()).unwrap();
        assert_eq!(applied.changed.len(), 3);
        // Guests is spelled `BG` in SDDL; SD = DELETE.
        let root = entries_for(&base, "BG");
        assert!(root.contains(&"(D;;SD;;;BG)".to_string()), "{root:?}");
        assert!(root.contains(&"(A;OICI;0x1301bf;;;BG)".to_string()), "{root:?}");
        // Deny 0x10156 (SDDL spells file rights with the directory-service
        // letters: DC write data, LC append, RP write EA, DT delete child,
        // CR write attributes, SD delete) — never SYNCHRONIZE.
        let hooks = entries_for(&base.join("hooks"), "BG");
        assert!(hooks.contains(&"(D;OICI;DCLCRPDTCRSD;;;BG)".to_string()), "{hooks:?}");
        let config = entries_for(&base.join("config"), "BG");
        assert!(config.contains(&"(D;;DCLCRPCRSD;;;BG)".to_string()), "{config:?}");
        // The deny leaves reading the file open.
        assert_eq!(std::fs::read_to_string(base.join("config")).unwrap(), "x");

        assert!(apply(&record, GUESTS, &base, &aces, &Progress::silent()).unwrap().changed.is_empty(), "a second apply rewrites nothing");

        let revoked = revoke(&record, GUESTS, Some(&base), &Progress::silent()).unwrap();
        assert_eq!(revoked.len(), 3);
        for p in [base.clone(), base.join("hooks"), base.join("config")] {
            assert_eq!(entries_for(&p, "BG"), Vec::<String>::new(), "{p:?}");
        }
        assert!(GrantRecord::load(&record).unwrap().projects.is_empty());
        let _ = std::fs::remove_dir_all(&record_dir);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Two projects share a folder (a client's config folder): revoking one
    /// takes back its own project but keeps the shared folder's entry, which
    /// the other still needs; revoking every project takes that back too.
    #[test]
    fn a_folder_another_project_shares_keeps_its_entry_until_that_one_is_revoked() {
        const GUESTS: &str = "S-1-5-32-546";
        let base = std::env::temp_dir().join(format!("ssai-acl-shared-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let (a, b, shared) = (base.join("a"), base.join("b"), base.join("shared"));
        for d in [&a, &b, &shared] {
            std::fs::create_dir_all(d).unwrap();
        }
        let record_dir = std::env::temp_dir().join(format!("ssai-acl-shared-record-{}", std::process::id()));
        let record = record_dir.join("grants.json");
        let grant = |root: &Path| {
            let aces = vec![
                Ace { path: root.to_path_buf(), trustee: Trustee::Account, kind: Kind::Modify },
                Ace { path: shared.clone(), trustee: Trustee::Account, kind: Kind::Modify },
            ];
            apply(&record, GUESTS, root, &aces, &Progress::silent()).unwrap();
        };
        grant(&a);
        grant(&b);

        assert_eq!(revoke(&record, GUESTS, Some(&a), &Progress::silent()).unwrap(), vec![a.clone()]);
        assert!(entries_for(&a, "BG").is_empty());
        assert_eq!(entries_for(&shared, "BG").len(), 1, "b still needs it");
        assert_eq!(entries_for(&b, "BG").len(), 1);

        revoke(&record, GUESTS, None, &Progress::silent()).unwrap();
        for p in [&b, &shared] {
            assert!(entries_for(p, "BG").is_empty(), "{p:?}");
        }
        assert!(GrantRecord::load(&record).unwrap().projects.is_empty());
        let _ = std::fs::remove_dir_all(&record_dir);
        let _ = std::fs::remove_dir_all(&base);
    }
}

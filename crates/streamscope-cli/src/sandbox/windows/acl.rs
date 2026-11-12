//! Write the plan of `grants.rs` onto the file system, keep a record of what
//! it touched, and take it back (`ssai sandbox revoke`, `uninstall`).
//!
//! Each path's entries for the sandbox account are merged into its access
//! list by `SetEntriesInAclW`, which orders denies before allows. A path whose
//! list already holds every wanted entry is left alone.
//!
//! Writing a folder's list by name (`SetNamedSecurityInfoW`) re-applies what
//! its contents inherit: it rewrites every file below it, so on the profile
//! it walks every file the developer has. That walk is needed only when an
//! inheritable entry comes or goes; a change of entries for the folder alone
//! (the read-attributes entry on each folder above a grant, a deny on one
//! file) is written on an open handle to that one object, which touches
//! nothing below it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    DENY_ACCESS, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
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
/// Every right that writes, removes or re-permissions: write data, append,
/// write EA, delete child, write attributes, DELETE, WRITE_DAC, WRITE_OWNER,
/// GENERIC_ALL, GENERIC_WRITE.
const WRITE_RIGHTS: u32 = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x1_0000 | 0x4_0000 | 0x8_0000 | 0x1000_0000 | 0x4000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
/// Full control, on the folder and everything in it.
const FULL_CONTROL: u32 = 0x1F_01FF;
/// Object and container inherit, as an inheritable grant carries them.
const OBJECT_AND_CONTAINER_INHERIT: u32 = super::grants::OBJECT_INHERIT | super::grants::CONTAINER_INHERIT;
const ACCESS_ALLOWED: u8 = 0;
const ACCESS_DENIED: u8 = 1;
/// How many folders the protected-list check looks at before it stops.
const PROTECTED_SCAN_LIMIT: usize = 20_000;
const RECORD_FILE: &str = "sandbox-grants.json";

/// What the writer did.
#[derive(Debug, Default)]
pub struct Applied {
    /// Paths whose access list it changed.
    pub changed: Vec<PathBuf>,
}

/// Where the grants are recorded: the developer's config folder.
pub fn record_path() -> Result<PathBuf> {
    Ok(crate::state::config_dir()?.join(RECORD_FILE))
}

/// Write `aces` for the account `account_sid`, recorded in `record` under
/// the project `root`.
pub fn apply(record: &Path, account_sid: &str, root: &Path, aces: &[Ace]) -> Result<Applied> {
    let account = Sid::parse(account_sid)?;
    let owner_rights = Sid::parse(OWNER_RIGHTS_SID)?;
    let mut by_path: BTreeMap<&Path, Vec<&Ace>> = BTreeMap::new();
    for ace in aces {
        by_path.entry(&ace.path).or_default().push(ace);
    }
    let mut applied = Applied::default();
    // Held to the end: two runs merging into one folder's list (a read, then
    // a write) would each write over the other's entries. Revoke holds it too.
    let _lock = lock_record(record)?;
    // Record first: a run stopped half-way still leaves its grants revocable.
    record_grants(record, root, aces)?;
    for (path, wanted) in by_path {
        let sid_of = |t: Trustee| if t == Trustee::Account { &account } else { &owner_rights };
        let dacl = Dacl::read(path).with_context(|| format!("read the access list of {}", path.display()))?;
        let present = dacl.aces().with_context(|| format!("read the access list of {}", path.display()))?;
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
        dacl.write_with(path, &entries, local).with_context(|| format!("grant the sandbox account {}", path.display()))?;
        applied.changed.push(path.to_path_buf());
    }
    Ok(applied)
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
pub fn revoke(record_file: &Path, account_sid: &str, root: Option<&Path>) -> Result<Vec<PathBuf>> {
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
            // inside it records it too, for its attributes only.
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
            let done = Dacl::read(path)
                .with_context(|| format!("read the access list of {}", path.display()))
                .and_then(|dacl| {
                    dacl.write_without(path, &whom, entry.inheritable)
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

/// The folders under `root` whose access list is protected (inherits
/// nothing): the project grant does not reach into them. Reparse points
/// (junctions, links) are not followed. Stops after a bounded number of folders.
pub fn protected_folders(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    let mut seen = 0;
    while let Some(dir) = stack.pop() {
        seen += 1;
        if seen > PROTECTED_SCAN_LIMIT {
            break;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else { continue };
            if !kind.is_dir() || kind.is_symlink() {
                continue;
            }
            let path = entry.path();
            if Dacl::read(&path).is_ok_and(|d| d.protected) {
                out.push(path);
            } else {
                stack.push(path);
            }
        }
    }
    out
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

/// Make the folder `path` private to the developer `me`: it stops
/// inheriting from its parent, keeps every entry it had as its own except
/// the write rights of [`BROAD_GROUPS`] (they keep reading), and grants `me`
/// full control. Written by name, so everything in it loses the inherited
/// broad write too, a walk of the whole folder. The root's list is written
/// first, so a walk cut short leaves a root that looks private above files
/// that are not: the folder is marked pending in `record` until the walk
/// returns, and [`private_pending`] has the next run treat it as not private.
pub fn make_private(record: &Path, path: &Path, me: &str, account: &str) -> Result<()> {
    let _lock = lock_record(record)?;
    let mut pending = GrantRecord::load(record)?;
    // Another run may have made it private while this one waited.
    if !pending.private_pending.contains(&key(path)) && broad_writers(path)?.is_empty() {
        return Ok(());
    }
    if pending.private_pending.insert(key(path)) {
        pending.save(record)?;
    }
    if let Err(e) = write_private_list(path, me, account) {
        // Refused before its list was written (no right to change it): the
        // folder still reads as open, nothing to finish. A folder that cannot
        // be read again keeps its mark: the next run asks again.
        if broad_writers(path).is_ok_and(|w| !w.is_empty()) {
            let mut undone = GrantRecord::load(record)?;
            undone.private_pending.remove(&key(path));
            undone.save(record)?;
            return Err(e);
        }
        return Err(e.context(format!(
            "{} was made private, but not everything in it: a file or folder in it refused the change (one \
             whose access you may not change: fix it, or move the project into your profile), then run again",
            path.display()
        )));
    }
    let mut done = GrantRecord::load(record)?;
    done.private_pending.remove(&key(path));
    done.save(record)
}

/// Whether making `path` private was started and never finished.
pub fn private_pending(record: &Path, path: &Path) -> Result<bool> {
    let _lock = lock_record(record)?;
    Ok(GrantRecord::load(record)?.private_pending.contains(&key(path)))
}

/// `account`'s and `OWNER RIGHTS`' allow entries the folder inherited (from
/// a granted project above it) are dropped, not made its own: on a list that
/// inherits nothing they would outlive that project's revoke.
fn write_private_list(path: &Path, me: &str, account: &str) -> Result<()> {
    let dacl = Dacl::read(path).with_context(|| format!("read the access list of {}", path.display()))?;
    if dacl.acl.is_null() {
        bail!("{} has no access list (every account may do anything there)", path.display());
    }
    let groups = broad_groups()?;
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
            let mut copy = std::slice::from_raw_parts(ace.cast::<u8>(), usize::from(header.AceSize)).to_vec();
            // Its own now: the list inherits nothing any more.
            copy[1] &= !(INHERITED_ACE as u8);
            if let Some((_, had)) = broad_allow(ace, &groups) {
                let mut mask = had & !WRITE_RIGHTS;
                // What a broad group keeps of GENERIC_ALL: read and run.
                if had & GENERIC_ALL != 0 {
                    mask |= Kind::ReadExecute.mask();
                }
                if mask == 0 {
                    continue;
                }
                copy[4..8].copy_from_slice(&mask.to_le_bytes());
            }
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
    let private = buf.acl();
    let name = wide(path.as_os_str());
    // SAFETY: a NUL-terminated name and the list just built.
    let rc = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            private,
            std::ptr::null(),
        )
    };
    if rc != ERROR_SUCCESS {
        bail!("make {} private: {}", path.display(), std::io::Error::from_raw_os_error(rc as i32));
    }
    Ok(())
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
    fn write_without(&self, path: &Path, whom: &[&Sid], was_inheritable: bool) -> Result<()> {
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
        self.store(path, buf.acl(), dropped && !inheritable && !was_inheritable)
    }

    /// Merge `entries` into this list and write it back to `path` — on the
    /// object alone when `local` (no entry is inheritable).
    fn write_with(&self, path: &Path, entries: &[EXPLICIT_ACCESS_W], local: bool) -> Result<()> {
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
        let done = self.store(path, new_acl, local);
        // SAFETY: allocated by SetEntriesInAclW above.
        unsafe { LocalFree(new_acl.cast()) };
        done
    }

    /// Write `acl` as the list of `path`. By name, which re-applies what
    /// everything below inherits (walking the tree); or, when `local`, on an
    /// open handle to the object alone, its protection and auto-inheritance
    /// flags kept as read — no file below is touched.
    fn store(&self, path: &Path, acl: *mut ACL, local: bool) -> Result<()> {
        if !local {
            let name = wide(path.as_os_str());
            // SAFETY: a NUL-terminated name and a valid list.
            let rc = unsafe {
                SetNamedSecurityInfoW(
                    name.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    acl,
                    std::ptr::null(),
                )
            };
            if rc != ERROR_SUCCESS {
                bail!("{}", std::io::Error::from_raw_os_error(rc as i32));
            }
            return Ok(());
        }
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
        if self.protected {
            bits |= SE_DACL_PROTECTED;
        }
        // A handle write keeps `AI` only when it asks for it; the request
        // reaches this object alone (the walk below is the by-name writer's).
        if self.auto_inherited {
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
            assert_ne!(SetFileSecurityW(name.as_ptr(), DACL_SECURITY_INFORMATION, sd), 0);
            LocalFree(sd);
        }
    }

    /// The read-attributes entry each folder above a grant gets reaches that
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
        d.store(&auto, d.acl, false).unwrap();
        drop(d);
        let record_dir = std::env::temp_dir().join(format!("ssai-acl-local-record-{}", std::process::id()));
        let record = record_dir.join("grants.json");
        // Protected as a private folder is (`make_private` leaves alone one
        // no broad group writes).
        write_private_list(&private, &me, GUESTS).unwrap();
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
            let aces = vec![Ace { path: dir.to_path_buf(), trustee: Trustee::Account, kind: Kind::ReadAttributes }];
            assert_eq!(apply(&record, GUESTS, dir, &aces).unwrap().changed.len(), 1);
            let granted = dacl_of(dir);
            assert!(granted.starts_with(flags), "{granted}");
            assert!(entries_for(dir, "BG").contains(&"(A;;0x100080;;;BG)".to_string()), "{granted}");
            assert!(dacl_of(&child).contains(marker), "the child's list was rewritten by the grant");
            revoke(&record, GUESTS, Some(dir)).unwrap();
            assert_eq!(dacl_of(dir), before, "revoke gives the folder back its exact list");
            assert!(dacl_of(&child).contains(marker), "the child's list was rewritten by the revoke");
            // Positive control: an inheritable entry reaches the child.
            let aces = vec![Ace { path: dir.to_path_buf(), trustee: Trustee::Account, kind: Kind::Modify }];
            apply(&record, GUESTS, dir, &aces).unwrap();
            assert!(!dacl_of(&child).contains(marker), "an inheritable entry did not reach the child");
            revoke(&record, GUESTS, Some(dir)).unwrap();
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
        apply(&record, GUESTS, &base, &aces).unwrap();
        assert_eq!(entries_for(&base.join("f"), "BG").len(), 1, "the child inherits the entry");
        // The folder's own entry gone, on the folder alone: the copy below stays.
        let own = dacl_of(&base).replace("(A;OICI;0x1301bf;;;BG)", "");
        set_file_sddl(&base, &own);
        assert!(entries_for(&base, "BG").is_empty());
        assert_eq!(entries_for(&base.join("f"), "BG").len(), 1);
        revoke(&record, GUESTS, Some(&base)).unwrap();
        assert!(entries_for(&base.join("f"), "BG").is_empty(), "{}", dacl_of(&base.join("f")));
        let _ = std::fs::remove_dir_all(&record_dir);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A folder Authenticated Users may write (as one made under a drive's
    /// root is) is named so; made private, it inherits nothing, that group
    /// keeps reading it and what it holds but writes nothing, the developer
    /// holds full control, and it is no longer named. A folder no broad
    /// group writes is not named.
    #[test]
    fn a_folder_every_account_may_write_is_named_and_made_private() {
        const AUTHENTICATED_USERS: &str = "S-1-5-11";
        let me = crate::win_acl::current_user_sid().unwrap();
        // In the profile, which no broad group writes (a temporary folder may
        // be one they do: `C:\Windows\Temp`, a runner's work folder).
        let base = crate::state::home_dir().unwrap().join(format!("ssai-acl-private-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let open = base.join("open");
        std::fs::create_dir_all(open.join("sub")).unwrap();
        std::fs::write(open.join("sub/f"), "x").unwrap();
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
        apply(&record, GUESTS, &base, &above).unwrap();
        assert_eq!(entries_for(&open, "BG").len(), 2);
        let aces = vec![Ace { path: open.clone(), trustee: Trustee::Account, kind: Kind::Modify }];
        apply(&record, AUTHENTICATED_USERS, &open, &aces).unwrap();
        assert_eq!(broad_writers(&open).unwrap(), vec!["Authenticated Users"]);
        assert_eq!(broad_writers(&open.join("sub/f")).unwrap(), vec!["Authenticated Users"]);

        // A walk cut short (the folder left marked) is reported pending, and
        // making it private again clears the mark.
        let mut marked = GrantRecord::load(&record).unwrap();
        marked.private_pending.insert(key(&open));
        marked.save(&record).unwrap();
        assert!(private_pending(&record, &open).unwrap());
        make_private(&record, &open, &me, GUESTS).unwrap();
        assert!(!private_pending(&record, &open).unwrap());
        // The account's inherited allow is dropped, never made the folder's
        // own, so the project above's revoke still reaches everything; its
        // inherited deny is kept and keeps holding the account out.
        let left = entries_for(&open, "BG");
        assert!(left.iter().all(|e| e.starts_with("(D;")) && left.len() == 1, "{}", dacl_of(&open));
        revoke(&record, GUESTS, Some(&base)).unwrap();
        let list = dacl_of(&open);
        assert!(list.starts_with("D:P"), "{list}");
        assert!(!list.contains(";ID;") && !list.contains("ID;"), "nothing inherited: {list}");
        assert!(list.contains(&format!("(A;OICI;FA;;;{me})")), "{list}");
        for p in [open.clone(), open.join("sub"), open.join("sub/f")] {
            assert!(broad_writers(&p).unwrap().is_empty(), "{p:?}: {}", dacl_of(&p));
        }
        // The group keeps reading.
        assert!(entries_for(&open.join("sub/f"), "AU").iter().any(|a| a.contains("0x1200a9") || a.contains("FR")),
            "{}", dacl_of(&open.join("sub/f")));
        let _ = std::fs::remove_dir_all(&record_dir);
        let _ = std::fs::remove_dir_all(&base);
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
        let applied = apply(&record, GUESTS, &base, &aces).unwrap();
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

        assert!(apply(&record, GUESTS, &base, &aces).unwrap().changed.is_empty(), "a second apply rewrites nothing");

        let revoked = revoke(&record, GUESTS, Some(&base)).unwrap();
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
            apply(&record, GUESTS, root, &aces).unwrap();
        };
        grant(&a);
        grant(&b);

        assert_eq!(revoke(&record, GUESTS, Some(&a)).unwrap(), vec![a.clone()]);
        assert!(entries_for(&a, "BG").is_empty());
        assert_eq!(entries_for(&shared, "BG").len(), 1, "b still needs it");
        assert_eq!(entries_for(&b, "BG").len(), 1);

        revoke(&record, GUESTS, None).unwrap();
        for p in [&b, &shared] {
            assert!(entries_for(p, "BG").is_empty(), "{p:?}");
        }
        assert!(GrantRecord::load(&record).unwrap().projects.is_empty());
        let _ = std::fs::remove_dir_all(&record_dir);
        let _ = std::fs::remove_dir_all(&base);
    }
}

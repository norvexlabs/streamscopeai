//! Write the plan of `grants.rs` onto the file system, keep a record of what
//! it touched, and take it back (`ssai sandbox revoke`, `uninstall`).
//!
//! Each path's entries for the sandbox account are merged into its access
//! list by `SetEntriesInAclW`, which orders denies before allows. A path whose
//! list already holds every wanted entry is left alone: writing a folder's
//! list re-applies what its contents inherit, so re-writing a project's root
//! on every run would walk the whole tree each time.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    DENY_ACCESS, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION, ACL_SIZE_INFORMATION, AclSizeInformation, AddAce,
    DACL_SECURITY_INFORMATION, EqualSid, GetAce, InitializeAcl, GetAclInformation, GetSecurityDescriptorControl, INHERITED_ACE, PSECURITY_DESCRIPTOR,
    SE_DACL_PROTECTED,
};

use super::grants::{Ace, Kind, Trustee};
use super::setup::Sid;
use crate::win_acl::wide;

const OWNER_RIGHTS_SID: &str = "S-1-3-4";
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
    // Record first: a run stopped half-way still leaves its grants revocable.
    record_grants(record, root, aces)?;
    for (path, wanted) in by_path {
        let sid_of = |t: Trustee| if t == Trustee::Account { &account } else { &owner_rights };
        let dacl = Dacl::read(path).with_context(|| format!("read the access list of {}", path.display()))?;
        if wanted.iter().all(|a| dacl.has(sid_of(a.trustee), a.kind)) {
            continue;
        }
        let entries: Vec<EXPLICIT_ACCESS_W> = wanted
            .iter()
            .map(|a| EXPLICIT_ACCESS_W {
                grfAccessPermissions: a.kind.mask(),
                grfAccessMode: if a.kind.is_deny() { DENY_ACCESS } else { GRANT_ACCESS },
                grfInheritance: a.kind.inheritance(),
                Trustee: trustee(sid_of(a.trustee)),
            })
            .collect();
        dacl.write_with(path, &entries).with_context(|| format!("grant the sandbox account {}", path.display()))?;
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
                    dacl.write_without(path, &whom)
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

/// A path's access list, owned (freed on drop).
struct Dacl {
    sd: PSECURITY_DESCRIPTOR,
    acl: *mut ACL,
    protected: bool,
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
        Ok(Self { sd, acl, protected: control & SE_DACL_PROTECTED != 0 })
    }

    /// Whether the list holds an explicit entry for `sid` granting (or
    /// denying, for a deny kind) at least `kind`'s rights with its inheritance.
    fn has(&self, sid: &Sid, kind: Kind) -> bool {
        if self.acl.is_null() {
            return false;
        }
        let mut info = ACL_SIZE_INFORMATION::default();
        // SAFETY: `acl` is a valid list owned by `sd`; `info` is sized.
        if unsafe {
            GetAclInformation(self.acl, (&raw mut info).cast(), std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32, AclSizeInformation)
        } == 0
        {
            return false;
        }
        let want_type = if kind.is_deny() { ACCESS_DENIED } else { ACCESS_ALLOWED };
        (0..info.AceCount).any(|i| {
            let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
            // SAFETY: `i` is below the list's count; an allowed and a denied
            // entry share ACCESS_ALLOWED_ACE's layout, the SID at `SidStart`.
            unsafe {
                if GetAce(self.acl, i, &mut ace) == 0 {
                    return false;
                }
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
    /// removes allow entries only.) The inherited entries are recomputed by
    /// the write.
    fn write_without(&self, path: &Path, whom: &[&Sid]) -> Result<()> {
        // No list at all grants everyone everything and names nobody: an
        // empty one written in its place would refuse everyone.
        if self.acl.is_null() {
            return Ok(());
        }
        let mut info = ACL_SIZE_INFORMATION::default();
        // SAFETY: `acl` is a valid list owned by `sd`; `info` is sized.
        if unsafe {
            GetAclInformation(self.acl, (&raw mut info).cast(), std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32, AclSizeInformation)
        } == 0
        {
            bail!("read the access list: {}", std::io::Error::last_os_error());
        }
        let size = (std::mem::size_of::<ACL>() as u32 + info.AclBytesInUse).next_multiple_of(4);
        let mut buf = vec![0u32; size as usize / 4];
        let new_acl: *mut ACL = buf.as_mut_ptr().cast();
        // SAFETY: `buf` is `size` bytes, DWORD-aligned.
        if unsafe { InitializeAcl(new_acl, size, ACL_REVISION) } == 0 {
            bail!("build the access list: {}", std::io::Error::last_os_error());
        }
        for i in 0..info.AceCount {
            let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
            // SAFETY: `i` is below the count; an allowed and a denied entry
            // share ACCESS_ALLOWED_ACE's layout; `new_acl` has room for every
            // entry of the old list.
            unsafe {
                if GetAce(self.acl, i, &mut ace) == 0 {
                    bail!("read the access list: {}", std::io::Error::last_os_error());
                }
                let header = &*ace.cast::<ACE_HEADER>();
                let explicit = u32::from(header.AceFlags) & INHERITED_ACE == 0;
                let typed = header.AceType == ACCESS_ALLOWED || header.AceType == ACCESS_DENIED;
                if explicit && typed {
                    let sid = (&raw const (*ace.cast::<ACCESS_ALLOWED_ACE>()).SidStart).cast_mut().cast();
                    if whom.iter().any(|w| EqualSid(sid, w.0) != 0) {
                        continue;
                    }
                }
                if AddAce(new_acl, ACL_REVISION, u32::MAX, ace, u32::from(header.AceSize)) == 0 {
                    bail!("build the access list: {}", std::io::Error::last_os_error());
                }
            }
        }
        let name = wide(path.as_os_str());
        // SAFETY: a NUL-terminated name and the list just built in `buf`.
        let rc = unsafe {
            SetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                new_acl,
                std::ptr::null(),
            )
        };
        if rc != ERROR_SUCCESS {
            bail!("{}", std::io::Error::from_raw_os_error(rc as i32));
        }
        Ok(())
    }

    /// Merge `entries` into this list and write it back to `path`.
    fn write_with(&self, path: &Path, entries: &[EXPLICIT_ACCESS_W]) -> Result<()> {
        let mut new_acl: *mut ACL = std::ptr::null_mut();
        // SAFETY: `entries` are valid (their trustee SIDs outlive the call);
        // `new_acl` is LocalAlloc'd on success and freed below, once.
        let rc = unsafe { SetEntriesInAclW(entries.len() as u32, entries.as_ptr(), self.acl, &mut new_acl) };
        if rc != ERROR_SUCCESS {
            bail!("build the access list: {}", std::io::Error::from_raw_os_error(rc as i32));
        }
        let name = wide(path.as_os_str());
        // SAFETY: a NUL-terminated name and the list just built.
        let rc = unsafe {
            SetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                new_acl,
                std::ptr::null(),
            )
        };
        // SAFETY: allocated by SetEntriesInAclW above.
        unsafe { LocalFree(new_acl.cast()) };
        if rc != ERROR_SUCCESS {
            bail!("{}", std::io::Error::from_raw_os_error(rc as i32));
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct GrantedPath {
    path: String,
    /// The grant added an `OWNER RIGHTS` entry here too.
    #[serde(default)]
    owner_rights: bool,
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
    file.lock().with_context(|| format!("lock {}", path.display()))?;
    Ok(file)
}

fn record_grants(file: &Path, root: &Path, aces: &[Ace]) -> Result<()> {
    let _lock = lock_record(file)?;
    let mut record = GrantRecord::load(file)?;
    let paths = record.projects.entry(key(root)).or_default();
    for ace in aces {
        let path = ace.path.to_string_lossy().into_owned();
        let owner_rights = ace.trustee == Trustee::OwnerRights;
        match paths.iter_mut().find(|p| p.path == path) {
            Some(p) => p.owner_rights |= owner_rights,
            None => paths.push(GrantedPath { path, owner_rights }),
        }
    }
    record.save(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The access list of `path` in SDDL, its entries for `sid` only.
    fn entries_for(path: &Path, sid: &str) -> Vec<String> {
        let out = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", &format!("(Get-Acl -LiteralPath '{}').Sddl", path.display())])
            .output()
            .unwrap();
        let sddl = String::from_utf8_lossy(&out.stdout).trim().to_string();
        // `D:<flags>(ace)(ace)…`, up to a SACL (`S:`) if any.
        let dacl = sddl.split("D:").nth(1).unwrap_or("").split("S:").next().unwrap_or("");
        let aces = &dacl[dacl.find('(').unwrap_or(dacl.len())..];
        aces.split_inclusive(')').filter(|a| a.contains(sid)).map(str::to_string).collect()
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

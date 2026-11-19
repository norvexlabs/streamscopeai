//! After a run: every file in the project is the developer's again. A file
//! the agent created, or replaced (write a copy, rename it over), is owned
//! by the sandbox account; the developer, whose inherited full control
//! includes the right to take ownership, sets themselves back as its owner.
//! Only the account's files are touched: one another account owns (an
//! elevated session's files are the Administrators group's) stays as it is.
//! Run at the end of a run that ends alone (no other run of the
//! developer's live), once the account's processes are ended: a run killed
//! before its sweep, or one that ended beside another, leaves its files to
//! the next run in the same project that ends alone, which re-owns whatever
//! the account owns there.

use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex};

use anyhow::Result;
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT, SetNamedSecurityInfoW};
use windows_sys::Win32::Security::{EqualSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};

use super::setup::Sid;
use crate::win_acl::wide;

/// What one sweep did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Swept {
    /// Files and folders whose owner was set back to the developer.
    pub reowned: usize,
    /// Entries whose owner could not be read or set (named in a warning).
    pub failed: usize,
}

/// Set the developer (`owner_sid`) as the owner of every file and folder
/// under `root`, the root included, that the sandbox account
/// (`account_sid`) owns. A link (a junction, a symbolic link, any reparse
/// point) is neither followed nor re-owned: reading or setting an owner by
/// name would act on what it points at, which may be outside the project.
/// An entry's kind is read from its folder's listing, so the owner query is
/// its one open; the account's processes are ended before a sweep, so none
/// swaps an entry for a link between the listing and the query.
pub fn reown(root: &Path, account_sid: &str, owner_sid: &str) -> Result<Swept> {
    // Checked here; each worker parses its own (a SID is a local
    // allocation, used on one thread).
    Sid::parse(account_sid)?;
    Sid::parse(owner_sid)?;
    let meta = match std::fs::symlink_metadata(root) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Swept::default()),
        Err(_) => return Ok(Swept { reowned: 0, failed: 1 }),
    };
    if meta.file_type().is_symlink() || is_reparse_point(&meta) {
        return Ok(Swept::default());
    }
    let work = Work { state: Mutex::new((vec![(root.to_path_buf(), meta.is_dir())], 0)), changed: Condvar::new() };
    let swept = Mutex::new(Swept::default());
    let workers = std::thread::available_parallelism().map_or(4, |n| n.get()).clamp(1, WORKERS);
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| sweep_from(&work, account_sid, owner_sid, &swept));
        }
    });
    Ok(swept.into_inner().unwrap_or_else(|p| p.into_inner()))
}

/// The most threads a sweep uses: each waits on the file system (and the
/// virus scanner's look at every open) far more than it computes.
const WORKERS: usize = 8;

/// The entries still to look at, shared by a sweep's workers: each takes
/// one, gives back its folder's entries, and the sweep is over when none is
/// left and no worker holds one.
struct Work {
    /// The entries to look at (path, is a folder), and how many workers hold one.
    state: Mutex<(Vec<(PathBuf, bool)>, usize)>,
    changed: Condvar,
}

impl Work {
    fn take(&self) -> Option<(PathBuf, bool)> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            if let Some(entry) = state.0.pop() {
                state.1 += 1;
                return Some(entry);
            }
            if state.1 == 0 {
                return None;
            }
            state = self.changed.wait(state).unwrap_or_else(|p| p.into_inner());
        }
    }

    fn give_back(&self, found: Vec<(PathBuf, bool)>) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.0.extend(found);
        state.1 -= 1;
        self.changed.notify_all();
    }
}

/// An entry a worker took, and the entries of its folder found so far:
/// given back to the [`Work`] when it drops.
struct Held<'a> {
    work: &'a Work,
    found: Vec<(PathBuf, bool)>,
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        self.work.give_back(std::mem::take(&mut self.found));
    }
}

/// One worker: re-own each entry it takes that the account owns, and give
/// back a folder's entries but its links — read from the folder listing,
/// with no open of their own.
fn sweep_from(work: &Work, account_sid: &str, owner_sid: &str, swept: &Mutex<Swept>) {
    let (Ok(account), Ok(owner)) = (Sid::parse(account_sid), Sid::parse(owner_sid)) else {
        return;
    };
    let mut mine = Swept::default();
    while let Some((path, is_dir)) = work.take() {
        // Given back as it drops, so a worker that unwinds never leaves the
        // others waiting for it.
        let mut held = Held { work, found: Vec::new() };
        match owned_by(&path, &account) {
            Some(false) => {}
            Some(true) if set_owner(&path, &owner) => mine.reowned += 1,
            // Removed since its folder was listed: nothing to give back.
            None if matches!(std::fs::symlink_metadata(&path), Err(e) if e.kind() == std::io::ErrorKind::NotFound) => {}
            Some(true) | None => mine.failed += 1,
        }
        if is_dir && let Ok(entries) = std::fs::read_dir(&path) {
            for entry in entries.flatten() {
                match (entry.file_type(), entry.metadata()) {
                    (Ok(kind), Ok(meta)) if kind.is_symlink() || is_reparse_point(&meta) => {}
                    (Ok(kind), Ok(_)) => held.found.push((entry.path(), kind.is_dir())),
                    _ => mine.failed += 1,
                }
            }
        }
        drop(held);
    }
    let mut total = swept.lock().unwrap_or_else(|p| p.into_inner());
    total.reowned += mine.reowned;
    total.failed += mine.failed;
}

/// A junction, a mount point or any other reparse point: never descended.
fn is_reparse_point(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// Whether `owner` owns `path`; `None` when its owner cannot be read.
fn owned_by(path: &Path, owner: &Sid) -> Option<bool> {
    let name = wide(path.as_os_str());
    let mut sid: PSID = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: a NUL-terminated path; `sid` points into `sd`, freed below.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut sid,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if rc != ERROR_SUCCESS {
        return None;
    }
    // SAFETY: both SIDs are valid here; `sd` is freed once, after the compare.
    let same = unsafe {
        let same = EqualSid(sid, owner.0) != 0;
        LocalFree(sd.cast());
        same
    };
    Some(same)
}

fn set_owner(path: &Path, owner: &Sid) -> bool {
    let name = wide(path.as_os_str());
    // SAFETY: a NUL-terminated path and a valid SID; nothing else is set.
    let rc = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            owner.0,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    rc == ERROR_SUCCESS
}

/// [`reown`], reporting what could not be given back.
pub fn reown_reporting(root: &Path, account_sid: &str, owner_sid: &str) -> Result<()> {
    let swept = reown(root, account_sid, owner_sid)?;
    if swept.failed > 0 {
        crate::ui::warn(
            "",
            format_args!(
                "{} file(s) in {} could not be checked or given back to you as their owner",
                swept.failed,
                root.display()
            ),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A folder of this test's own: a root, two folders, two files.
    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ssai-sweep-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("a/b")).unwrap();
        std::fs::write(dir.join("a/b/f.txt"), "x").unwrap();
        std::fs::write(dir.join("top.txt"), "y").unwrap();
        dir
    }

    /// Who owns `path`, as a SID string.
    fn owner_of(path: &Path) -> String {
        use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
        let name = wide(path.as_os_str());
        let (mut sid, mut sd): (PSID, PSECURITY_DESCRIPTOR) = (std::ptr::null_mut(), std::ptr::null_mut());
        // SAFETY: as in `owned_by`; the text and `sd` are freed below.
        unsafe {
            let rc = GetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut sid,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sd,
            );
            assert_eq!(rc, ERROR_SUCCESS);
            let mut text: *mut u16 = std::ptr::null_mut();
            assert_ne!(ConvertSidToStringSidW(sid, &mut text), 0);
            let out = crate::win_acl::wide_to_string(text);
            LocalFree(text.cast());
            LocalFree(sd.cast());
            out
        }
    }

    #[test]
    fn files_the_account_does_not_own_are_left_as_they_are() {
        let dir = scratch("other");
        let me = crate::win_acl::current_user_sid().unwrap();
        // Guests owns none of them.
        assert_eq!(reown(&dir, "S-1-5-32-546", &me).unwrap(), Swept::default());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn every_file_and_folder_the_account_owns_is_given_back() {
        // Positive control: taken as the "account", whoever owns the new
        // tree (this user, or the Administrators group in an elevated
        // session) owns all five entries, each set back — here to itself,
        // which any owner may do.
        let dir = scratch("own");
        let holder = owner_of(&dir.join("a/b/f.txt"));
        assert_eq!(reown(&dir, &holder, &holder).unwrap(), Swept { reowned: 5, failed: 0 });
        assert_eq!(owner_of(&dir.join("top.txt")), holder);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

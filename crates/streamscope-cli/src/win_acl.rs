//! Owner-only access on Windows — the counterpart of a Unix 0600/0700 for the
//! files and folders that hold gateway keys and tokens.

use std::collections::BTreeSet;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use anyhow::{bail, Context, Result};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INVALID_FUNCTION, ERROR_NOT_SUPPORTED, ERROR_SUCCESS, HANDLE, LocalFree, WIN32_ERROR,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    SetNamedSecurityInfoW, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetTokenInformation, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Where the access list is applied: a path (a folder), or an open handle (a
/// file being written — no other process can open it in between).
enum Target<'a> {
    Path(&'a Path),
    Handle(HANDLE),
}

/// Make the folder `dir` the owner's alone — a protected list (nothing
/// inherited from its parent) granting full control to the current user and
/// SYSTEM, both inherited by everything created in it — unless it already is.
pub fn restrict_dir_to_owner(dir: &Path) -> Result<()> {
    // Each folder once per run: one a share refused is not asked (nor warned
    // about) again on every write into it.
    static TRIED: std::sync::Mutex<BTreeSet<std::path::PathBuf>> = std::sync::Mutex::new(BTreeSet::new());
    if TRIED.lock().is_ok_and(|tried| tried.contains(dir)) {
        return Ok(());
    }
    let (sid, spelled) = current_user()?;
    if !is_owner_only(dir, spelled) {
        apply(Target::Path(dir), dir, sid, &[], "OICI").with_context(|| format!("restrict {} to its owner", dir.display()))?;
    }
    if let Ok(mut tried) = TRIED.lock() {
        tried.insert(dir.to_path_buf());
    }
    Ok(())
}

/// Make the open file `file` (at `path`, named in errors) its owner's alone:
/// a protected list granting full control to the current user and SYSTEM.
pub fn restrict_file_to_owner(file: &std::fs::File, path: &Path) -> Result<()> {
    let sid = current_user_sid()?;
    apply(Target::Handle(file.as_raw_handle() as HANDLE), path, &sid, &[], "")
        .with_context(|| format!("restrict {} to its owner", path.display()))
}

/// Give the folder `dir` a protected list granting full control to the
/// current user, SYSTEM and the Administrators group, inherited by everything
/// created in it: a hand-off folder between the developer and an elevated
/// helper, which may run as another (administrator) account.
pub fn restrict_dir_to_owner_and_admins(dir: &Path) -> Result<()> {
    let sid = current_user_sid()?;
    apply(Target::Path(dir), dir, &sid, &["BA"], "OICI")
        .with_context(|| format!("restrict {} to you and the administrators", dir.display()))
}

/// Set the owner-only list (`inherit` = `OICI` on a folder) on `target` (at
/// `path`, named in a warning), granting the `also` trustees (SDDL SIDs or
/// aliases) full control as well. Where the file system keeps no access lists
/// (FAT, exFAT) it is left as it is, as a Unix mode is on such a file system;
/// where it refuses this one (a network share that maps no access lists, or
/// grants no right to change them) it is left as it is with a warning. An
/// error is this code's own failure, never the file system's.
fn apply(target: Target<'_>, path: &Path, sid: &str, also: &[&str], inherit: &str) -> Result<()> {
    let also: String = also.iter().map(|who| format!("(A;{inherit};FA;;;{who})")).collect();
    let sddl = wide(format!("D:P(A;{inherit};FA;;;{sid})(A;{inherit};FA;;;SY){also}").as_ref());
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `sddl` is NUL-terminated; `sd` receives a LocalAlloc'd
    // descriptor, freed below.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut())
    } == 0
    {
        bail!("build an owner-only access list: {}", std::io::Error::last_os_error());
    }
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let info = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    // SAFETY: `sd` is the valid descriptor built above; the DACL pointer
    // points into it and is used before it is freed; a path is NUL-terminated
    // and a handle is open for the duration of the call.
    let rc: std::io::Result<WIN32_ERROR> = unsafe {
        if GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) == 0 {
            Err(std::io::Error::last_os_error())
        } else if present == 0 || dacl.is_null() {
            // A null DACL would grant everyone everything: fail closed.
            Err(std::io::Error::other("the owner-only access list came out empty"))
        } else {
            Ok(match target {
                Target::Path(path) => {
                    let name = wide(path.as_os_str());
                    SetNamedSecurityInfoW(
                        name.as_ptr(),
                        SE_FILE_OBJECT,
                        info,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        dacl,
                        std::ptr::null(),
                    )
                }
                Target::Handle(handle) => SetSecurityInfo(
                    handle,
                    SE_FILE_OBJECT,
                    info,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    dacl,
                    std::ptr::null(),
                ),
            })
        }
    };
    // SAFETY: frees the descriptor allocated above, once.
    unsafe { LocalFree(sd) };
    match rc? {
        ERROR_SUCCESS | ERROR_NOT_SUPPORTED | ERROR_INVALID_FUNCTION => {}
        code => {
            // Once per folder: a share refusing one file refuses them all.
            static WARNED: std::sync::Mutex<BTreeSet<std::path::PathBuf>> = std::sync::Mutex::new(BTreeSet::new());
            let folder = path.parent().unwrap_or(path).to_path_buf();
            if WARNED.lock().is_ok_and(|mut warned| warned.insert(folder)) {
                crate::ui::warn(
                    "",
                    format_args!(
                        "{} could not be made readable by you alone ({}) — the folder it is in decides who can \
                         read it (and the other files written there)",
                        path.display(),
                        std::io::Error::from_raw_os_error(code as i32)
                    ),
                );
            }
        }
    }
    Ok(())
}

/// How an access list in SDDL names the user `sid`: some accounts by an
/// alias (`LA` for the built-in Administrator), the rest by the SID itself.
fn sddl_spelling(sid: &str) -> String {
    let text = wide(format!("O:{sid}").as_ref());
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `text` is NUL-terminated; `sd` and `out` are LocalAlloc'd on
    // success and freed below, once.
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(text.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut()) == 0 {
            return sid.to_string();
        }
        let mut out: *mut u16 = std::ptr::null_mut();
        let ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd,
            SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION,
            &mut out,
            std::ptr::null_mut(),
        ) != 0;
        let spelled = if ok { wide_to_string(out).strip_prefix("O:").map(str::to_string) } else { None };
        if ok {
            LocalFree(out.cast());
        }
        LocalFree(sd);
        spelled.unwrap_or_else(|| sid.to_string())
    }
}

/// Whether `path`'s access list is already owner-only for the user an access
/// list spells `me` ([`sddl_spelling`]):
/// the protected list a folder gets, or the same two entries inherited from
/// such a folder (a subfolder of the state folder) — in any order.
fn is_owner_only(path: &Path, me: &str) -> bool {
    let Some(sddl) = dacl_sddl(path) else { return false };
    let Some(rest) = sddl.strip_prefix("D:") else { return false };
    let (flags, aces) = rest.split_at(rest.find('(').unwrap_or(rest.len()));
    let got: BTreeSet<&str> = aces.split_inclusive(')').collect();
    let entries = |inherit: &str| -> BTreeSet<String> {
        [me, "SY"].iter().map(|who| format!("(A;{inherit};FA;;;{who})")).collect()
    };
    let is = |want: BTreeSet<String>| got.len() == want.len() && want.iter().all(|w| got.contains(w.as_str()));
    (flags.contains('P') && is(entries("OICI"))) || is(entries("OICIID"))
}

/// `path`'s access list in SDDL (`D:…`), when it can be read.
fn dacl_sddl(path: &Path) -> Option<String> {
    let name = wide(path.as_os_str());
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `name` is NUL-terminated; `sd` is LocalAlloc'd on success and
    // freed below.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if rc != ERROR_SUCCESS {
        return None;
    }
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: `sd` is the valid descriptor read above; `text` is LocalAlloc'd
    // on success; both are freed below, once.
    unsafe {
        let ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut text,
            std::ptr::null_mut(),
        ) != 0;
        let out = ok.then(|| wide_to_string(text));
        if ok {
            LocalFree(text.cast());
        }
        LocalFree(sd);
        out
    }
}

/// The current user's SID as a string (`S-1-5-21-…`), read once per process.
pub(crate) fn current_user_sid() -> Result<String> {
    Ok(current_user()?.0.clone())
}

/// The current user's SID and how an access list spells it
/// ([`sddl_spelling`]), read once per process.
fn current_user() -> Result<&'static (String, String)> {
    static USER: std::sync::OnceLock<(String, String)> = std::sync::OnceLock::new();
    if let Some(user) = USER.get() {
        return Ok(user);
    }
    let sid = read_current_user_sid()?;
    let spelled = sddl_spelling(&sid);
    Ok(USER.get_or_init(|| (sid, spelled)))
}

fn read_current_user_sid() -> Result<String> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: the pseudo-handle of this process; `token` is closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        bail!("open this process's token: {}", std::io::Error::last_os_error());
    }
    let sid = token_user_sid(token);
    // SAFETY: closes the token opened above, once.
    unsafe { CloseHandle(token) };
    sid
}

pub(crate) fn token_user_sid(token: HANDLE) -> Result<String> {
    let mut len = 0u32;
    // SAFETY: a size query (null buffer, zero length) on an open token.
    unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len) };
    // u64 storage keeps TOKEN_USER's pointer field aligned.
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buf` holds at least `len` bytes.
    if unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) } == 0 {
        bail!("read this process's user: {}", std::io::Error::last_os_error());
    }
    // SAFETY: the call above filled `buf` with a TOKEN_USER.
    let user = unsafe { &*buf.as_ptr().cast::<TOKEN_USER>() };
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: the SID points into `buf`, alive here; `text` is LocalAlloc'd.
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
        bail!("spell this process's user: {}", std::io::Error::last_os_error());
    }
    // SAFETY: `text` is the NUL-terminated string from the call above, freed
    // right after, once.
    let sid = unsafe {
        let s = wide_to_string(text);
        LocalFree(text.cast());
        s
    };
    Ok(sid)
}

/// # Safety
/// `text` points at a NUL-terminated UTF-16 string.
pub(crate) unsafe fn wide_to_string(text: *const u16) -> String {
    // SAFETY: per the contract, every unit up to the NUL is readable.
    unsafe {
        let n = (0..).take_while(|&i| *text.add(i) != 0).count();
        String::from_utf16_lossy(std::slice::from_raw_parts(text, n))
    }
}

pub(crate) fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The list's flags (`P` protected, `AI` auto-inherited) and its entries,
    /// in any order.
    fn split(sddl: &str) -> (String, BTreeSet<String>) {
        let rest = sddl.strip_prefix("D:").unwrap();
        let (flags, aces) = rest.split_at(rest.find('(').unwrap_or(rest.len()));
        (flags.to_string(), aces.split_inclusive(')').map(str::to_string).collect())
    }

    fn entries(inherit: &str, me: &str) -> BTreeSet<String> {
        let me = sddl_spelling(me);
        [me.as_str(), "SY"].iter().map(|who| format!("(A;{inherit};FA;;;{who})")).collect()
    }

    /// The built-in Administrator is spelled `LA` in an access list; an
    /// ordinary account by its SID.
    #[test]
    fn an_account_is_spelled_as_an_access_list_spells_it() {
        let me = current_user_sid().unwrap();
        let admin = format!("{}-500", me.rsplit_once('-').unwrap().0);
        assert_eq!(sddl_spelling(&admin), "LA");
        if !me.ends_with("-500") {
            assert_eq!(sddl_spelling(&me), me);
        }
    }

    #[test]
    fn a_restricted_file_and_folder_grant_only_their_owner_and_system() {
        let dir = std::env::temp_dir().join(format!("ss-acl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let me = current_user_sid().unwrap();
        // Control: a fresh folder inherits its parent's entries, unprotected.
        assert!(!is_owner_only(&dir, &sddl_spelling(&me)));

        restrict_dir_to_owner(&dir).unwrap();
        assert!(is_owner_only(&dir, &sddl_spelling(&me)), "{:?}", dacl_sddl(&dir));
        let (flags, aces) = split(&dacl_sddl(&dir).unwrap());
        assert!(flags.contains('P'), "{flags}");
        assert_eq!(aces, entries("OICI", &me));
        // A subfolder inheriting them is owner-only already (left as it is).
        let sub = dir.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        assert!(is_owner_only(&sub, &sddl_spelling(&me)), "{:?}", dacl_sddl(&sub));
        // A file created in it inherits only those two.
        let later = dir.join("later.json");
        std::fs::write(&later, "{}").unwrap();
        assert_eq!(split(&dacl_sddl(&later).unwrap()).1, entries("ID", &me));

        // A file the CLI creates for a key is restricted through its open
        // handle, in a folder whose entries it would otherwise inherit —
        // control: a plain file beside it keeps them.
        let open = std::env::temp_dir().join(format!("ss-acl-{}.json", std::process::id()));
        let plain = std::env::temp_dir().join(format!("ss-acl-{}-plain.json", std::process::id()));
        drop(crate::state::create_private_file(&open).unwrap());
        std::fs::write(&plain, "{}").unwrap();
        assert!(!split(&dacl_sddl(&plain).unwrap()).0.contains('P'));
        let (flags, aces) = split(&dacl_sddl(&open).unwrap());
        assert!(flags.contains('P'), "{flags}");
        assert_eq!(aces, entries("", &me));
        let _ = std::fs::remove_file(&plain);
        let _ = std::fs::remove_file(&open);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

//! `ssai sandbox setup` / `--check` / `uninstall` on Windows, and the probe
//! `--sandbox native|auto` runs before every launch.
//!
//! Setup is split in two halves. The developer's own process resolves who
//! they are, generates the account's password and protects it with their own
//! data protection (DPAPI is per account, so it must be theirs), and keeps the
//! record. The elevated helper (`ssai __sandbox-setup`, one UAC prompt) does
//! only what needs an administrator: the account, its profile, the egress
//! rule — and it may run as ANOTHER account (a standard developer elevates
//! with an administrator's credentials), so it is handed the developer's
//! identity and never derives it from its own.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_CANCELLED, ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_NONE_MAPPED, ERROR_SUCCESS,
    HANDLE, LocalFree,
};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    LG_INCLUDE_INDIRECT, LOCALGROUP_USERS_INFO_0, MAX_PREFERRED_LENGTH, NetApiBufferFree, NetUserAdd, NetUserDel,
    NetUserGetInfo, NetUserGetLocalGroups, NetUserSetInfo, UF_ACCOUNTDISABLE, UF_DONT_EXPIRE_PASSWD,
    UF_PASSWD_CANT_CHANGE, UF_SCRIPT, USER_INFO_1, USER_INFO_1003, USER_INFO_1007, USER_INFO_1008, USER_INFO_1011,
    USER_PRIV_USER,
};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use windows_sys::Win32::Security::{
    EqualSid, GetTokenInformation, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, LogonUserW,
    LookupAccountNameW, PSID, SID_AND_ATTRIBUTES, SID_NAME_USE, TOKEN_ELEVATION, TOKEN_GROUPS,
    TOKEN_QUERY, TokenElevation, TokenGroups,
};
use windows_sys::Win32::System::Registry::{
    HKEY_LOCAL_MACHINE, REG_DWORD, RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RegDeleteKeyValueW, RegGetValueW, RegSetKeyValueW,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, INFINITE, OpenProcessToken, WaitForSingleObject,
};
use windows_sys::Win32::System::WindowsProgramming::{GetComputerNameW, GetUserNameW};
use windows_sys::Win32::UI::Shell::{
    CreateProfile, DeleteProfileW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
};

use super::account::{
    self, HelperRequest, HelperResponse, SetupRecord, account_name, add_rule_script, check_profile,
    check_stored_rule, is_account_name, is_account_sid, remove_rule_script, rule_name,
};
use crate::win_acl::{wide_to_string, wide};

/// Where the developer's record lives: their own (owner-only) config folder.
const RECORD_FILE: &str = "sandbox-user.json";
/// Bound into the protected password, so no other program's DPAPI blob of
/// this developer's decrypts as it.
const ENTROPY: &[u8] = b"streamscopeai sandbox account password";
const RULES_KEY: &str = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
const HIDDEN_USERS_KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList";
/// The firewall profiles: their name, their key in the local store, and in the policy store.
const PROFILES: [(&str, &str, &str); 3] = [
    ("Domain", "DomainProfile", "DomainProfile"),
    ("Private", "StandardProfile", "PrivateProfile"),
    ("Public", "PublicProfile", "PublicProfile"),
];
const ADMINISTRATORS_SID: &str = "S-1-5-32-544";
const SETUP_HINT: &str = "run `ssai sandbox setup` (once, as an administrator)";
/// Windows data protection needs a sign-in that carried a password: an SSH
/// session signed in with a key has none, so the record can be neither
/// written nor read there.
const DPAPI_HINT: &str = "Windows data protection needs a sign-in with your password — at the desktop, \
                          or over SSH with a password rather than a key.";

/// The sandbox account, checked ready to run a client.
pub struct Ready {
    pub record: SetupRecord,
    /// The account's password, for the launch.
    pub password: String,
}

/// Whether the sandbox account is set up and sound: the record, the account
/// it names (same SID), a sign-in that works and is not an administrator's,
/// the egress rule exactly as setup wrote it, and a firewall that applies it.
/// The error says what is wrong and which command fixes it.
pub fn probe() -> std::result::Result<Ready, String> {
    let owner = crate::win_acl::current_user_sid().map_err(|e| format!("{e:#}"))?;
    let record = load_record()
        .map_err(|e| format!("the sandbox setup record is unreadable ({e:#}) — {SETUP_HINT}"))?
        .ok_or_else(|| format!("the Windows sandbox account is not set up — {SETUP_HINT}"))?;
    if record.owner_sid != owner || record.account != account_name(&owner) {
        return Err(format!("the sandbox setup record is another user's — {SETUP_HINT}"));
    }
    let password = unprotect(&record.password)
        .map_err(|e| format!("the sandbox account's password cannot be read in this sign-in ({e:#}). {DPAPI_HINT}"))?;
    match lookup_account(&record.account) {
        Ok(Some(sid)) if sid == record.account_sid => {}
        Ok(Some(_)) => return Err(format!("the account {} was replaced by another — {SETUP_HINT}", record.account)),
        Ok(None) => return Err(format!("the account {} no longer exists — {SETUP_HINT}", record.account)),
        Err(e) => return Err(format!("{e:#}")),
    }
    let token = logon(&record.account, &password)
        .map_err(|e| format!("the account {} does not sign in ({e}) — {SETUP_HINT}", record.account))?;
    let admin = token_has_group(token.0, ADMINISTRATORS_SID);
    drop(token);
    match admin {
        Ok(false) => {}
        Ok(true) => {
            return Err(format!(
                "the account {} is an administrator, which the sandbox refuses — remove it from the \
                 Administrators group",
                record.account
            ));
        }
        Err(e) => return Err(format!("{e:#}")),
    }
    check_firewall(&record.account, &record.account_sid)?;
    Ok(Ready { record, password })
}

/// `ssai sandbox setup --check`: report, change nothing.
pub fn check() -> Result<()> {
    match probe() {
        Ok(ready) => {
            println!(
                "The Windows sandbox is ready: account {} ({}), its egress blocked but for loopback.",
                ready.record.account, ready.record.account_sid
            );
            Ok(())
        }
        Err(reason) => bail!("{reason}"),
    }
}

/// `ssai sandbox setup`: create the account and its egress rule, or repair
/// them. Idempotent; the account's password is kept while it still signs in.
pub fn setup() -> Result<()> {
    let owner_sid = crate::win_acl::current_user_sid()?;
    let owner_name = user_name()?;
    let account = account_name(&owner_sid);
    let recorded = load_record().ok().flatten().filter(|r| r.owner_sid == owner_sid && r.account == account);
    // Set once: an administrator's reset loses what the account keeps
    // protected under its password, so a recorded one that still signs in
    // stays. One this sign-in cannot decrypt is no reason to reset it.
    let kept = match &recorded {
        Some(record) => match unprotect(&record.password) {
            Ok(pw) => logon(&account, &pw).is_ok().then_some(record),
            Err(e) => bail!(
                "the recorded sandbox password cannot be read in this sign-in ({e:#}). {DPAPI_HINT} \
                 To start over instead, run `ssai sandbox uninstall`, then `ssai sandbox setup`."
            ),
        },
        None => None,
    };
    let password = match kept {
        Some(_) => None,
        None => Some(account::generate_password(&mut rand::rng())),
    };
    if password.is_some() && lookup_account(&account)?.is_some() {
        crate::ui::warn(
            "",
            format_args!(
                "the account {account} exists but no password recorded here signs it in: setup sets a new one \
                 (what the account kept protected under the old one is lost)"
            ),
        );
    }
    let protected = match (&password, kept) {
        (Some(pw), _) => protect(pw)?,
        (None, Some(record)) => record.password.clone(),
        (None, None) => unreachable!("no password is generated only when one is kept"),
    };
    let response = run_elevated(&HelperRequest::Setup { owner_sid: owner_sid.clone(), owner_name, account: account.clone(), password })?;
    for line in &response.done {
        println!("  {line}");
    }
    if let Some(error) = response.error {
        bail!("{error}");
    }
    let account_sid = response.account_sid.context("the setup helper did not name the account's SID")?;
    save_record(&SetupRecord { account, account_sid, owner_sid, password: protected })?;
    match probe() {
        Ok(ready) => {
            println!("The Windows sandbox is ready: `ssai run --sandbox native <client>` runs as {}.", ready.record.account);
            Ok(())
        }
        Err(reason) => bail!("setup finished but the sandbox is not usable: {reason}"),
    }
}

/// `ssai sandbox revoke`: take the sandbox account's access back from the
/// project at `root` (every project when `None`).
pub fn revoke(root: Option<&Path>) -> Result<()> {
    let record = load_record()?.context("the Windows sandbox account is not set up: there is nothing to revoke")?;
    let revoked = super::acl::revoke(&super::acl::record_path()?, &record.account_sid, root)?;
    println!("Revoked the sandbox account's access on {} path(s).", revoked.len());
    Ok(())
}

/// `ssai sandbox uninstall`: take back every grant, remove the account, its
/// profile and its rule, then the record.
pub fn uninstall() -> Result<()> {
    let owner_sid = crate::win_acl::current_user_sid()?;
    let account = account_name(&owner_sid);
    // While the account still exists: an entry for a deleted account stays
    // behind as an unresolvable SID.
    if let Some(record) = load_record().ok().flatten() {
        let revoked = super::acl::revoke(&super::acl::record_path()?, &record.account_sid, None)?;
        if !revoked.is_empty() {
            println!("  revoked the sandbox account's access on {} path(s)", revoked.len());
        }
        // Removed now, the account would leave the entries above behind as
        // a SID no tool can name or take back.
        if super::acl::has_grants(&super::acl::record_path()?)? {
            bail!("some of the sandbox account's access could not be taken back (named above): fix those, then run `ssai sandbox uninstall` again");
        }
    } else if super::acl::has_grants(&super::acl::record_path()?)? {
        // Grants recorded with no account record to name the account by:
        // nothing here can take them back, and removing the account would
        // strand them.
        bail!("the sandbox setup record is missing or unreadable while projects are still granted: run `ssai sandbox setup` to repair it, then `ssai sandbox uninstall`");
    }
    let response = run_elevated(&HelperRequest::Uninstall { account })?;
    for line in &response.done {
        println!("  {line}");
    }
    if let Some(error) = response.error {
        bail!("{error}");
    }
    match std::fs::remove_file(record_path()?) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).context("remove the sandbox setup record"),
    }
    println!("The Windows sandbox is removed.");
    Ok(())
}

/// `ssai __sandbox-setup <request>`: the elevated half. Reads the request,
/// does it, and always answers in `response.json` beside it — its own window
/// is hidden, so the answer file is how its errors reach the developer.
pub fn helper(request: &Path) -> Result<()> {
    let dir = request.parent().context("the request has no folder")?;
    let response = match std::fs::read(request).map_err(anyhow::Error::from).and_then(|b| Ok(serde_json::from_slice(&b)?)) {
        Ok(req) => perform(&req),
        Err(e) => HelperResponse { error: Some(format!("read the setup request: {e:#}")), ..Default::default() },
    };
    std::fs::write(dir.join("response.json"), serde_json::to_vec(&response)?).context("write the setup answer")?;
    if response.error.is_some() { std::process::exit(1) } else { Ok(()) }
}

fn perform(request: &HelperRequest) -> HelperResponse {
    let mut out = HelperResponse::default();
    let result = match request {
        HelperRequest::Setup { owner_sid, owner_name, account, password } => {
            perform_setup(owner_sid, owner_name, account, password.as_deref(), &mut out)
        }
        HelperRequest::Uninstall { account } => perform_uninstall(account, &mut out),
    };
    if let Err(e) = result {
        out.error = Some(format!("{e:#}"));
    }
    out
}

fn perform_setup(owner_sid: &str, owner_name: &str, account: &str, password: Option<&str>, out: &mut HelperResponse) -> Result<()> {
    if !is_account_sid(owner_sid) || account != account_name(owner_sid) {
        bail!("the setup request names an account that is not the developer's");
    }
    let name = wide_str(account);
    let comment = wide_str(&account::description(owner_name));
    match user_flags(account)? {
        None => {
            let password = password.context("the account must be created, and the request carries no password")?;
            let mut pw = wide_str(password);
            let info = USER_INFO_1 {
                usri1_name: name.as_ptr().cast_mut(),
                usri1_password: pw.as_mut_ptr(),
                usri1_password_age: 0,
                usri1_priv: USER_PRIV_USER,
                usri1_home_dir: std::ptr::null_mut(),
                usri1_comment: comment.as_ptr().cast_mut(),
                usri1_flags: UF_SCRIPT | UF_DONT_EXPIRE_PASSWD | UF_PASSWD_CANT_CHANGE,
                usri1_script_path: std::ptr::null_mut(),
            };
            // SAFETY: `info` points at NUL-terminated strings alive for the call.
            net(unsafe { NetUserAdd(std::ptr::null(), 1, (&raw const info).cast(), std::ptr::null_mut()) }, "create the account")?;
            out.done.push(format!("created the account {account}"));
        }
        Some(flags) => {
            if let Some(password) = password {
                let mut pw = wide_str(password);
                let info = USER_INFO_1003 { usri1003_password: pw.as_mut_ptr() };
                // SAFETY: as above.
                net(unsafe { NetUserSetInfo(std::ptr::null(), name.as_ptr(), 1003, (&raw const info).cast(), std::ptr::null_mut()) }, "set the account's password")?;
                out.done.push(format!("set a new password on {account}"));
            }
            if flags & UF_ACCOUNTDISABLE != 0 {
                let info = USER_INFO_1008 { usri1008_flags: flags & !UF_ACCOUNTDISABLE };
                // SAFETY: as above.
                net(unsafe { NetUserSetInfo(std::ptr::null(), name.as_ptr(), 1008, (&raw const info).cast(), std::ptr::null_mut()) }, "enable the account")?;
                out.done.push(format!("enabled {account}"));
            }
            let info = USER_INFO_1007 { usri1007_comment: comment.as_ptr().cast_mut() };
            // SAFETY: as above.
            net(unsafe { NetUserSetInfo(std::ptr::null(), name.as_ptr(), 1007, (&raw const info).cast(), std::ptr::null_mut()) }, "describe the account")?;
        }
    }
    let full = wide_str(account::FULL_NAME);
    let info = USER_INFO_1011 { usri1011_full_name: full.as_ptr().cast_mut() };
    // SAFETY: as above.
    net(unsafe { NetUserSetInfo(std::ptr::null(), name.as_ptr(), 1011, (&raw const info).cast(), std::ptr::null_mut()) }, "name the account")?;
    if local_groups(account)?.iter().any(|g| g == ADMINISTRATORS_SID) {
        bail!("the account {account} is in the Administrators group — remove it, then re-run setup");
    }
    let sid = lookup_account(account)?.context("the account was created but does not resolve")?;
    out.account_sid = Some(sid.clone());

    // Hidden from the sign-in screen.
    let zero = 0u32;
    // SAFETY: NUL-terminated names; `zero` is 4 readable bytes.
    let rc = unsafe {
        RegSetKeyValueW(HKEY_LOCAL_MACHINE, wide_str(HIDDEN_USERS_KEY).as_ptr(), name.as_ptr(), REG_DWORD, (&raw const zero).cast(), 4)
    };
    win(rc, "hide the account from the sign-in screen")?;

    // Its profile, made now so no first sign-in of the launch has to.
    let mut path = vec![0u16; 260];
    // SAFETY: NUL-terminated SID and name; `path` holds `path.len()` units.
    let hr = unsafe { CreateProfile(wide_str(&sid).as_ptr(), name.as_ptr(), path.as_mut_ptr(), path.len() as u32) };
    const ALREADY_EXISTS: i32 = 0x8007_00B7_u32 as i32;
    match hr {
        0 => out.done.push(format!("created the profile of {account}")),
        ALREADY_EXISTS => {}
        other => bail!("create the account's profile: HRESULT {:#010x}", other as u32),
    }

    powershell(&add_rule_script(account, &sid)).context("write the egress rule")?;
    check_firewall(account, &sid).map_err(anyhow::Error::msg).context("the egress rule written")?;
    out.done.push(format!("blocked every connection of {account} but loopback (firewall rule {})", rule_name(account)));
    Ok(())
}

fn perform_uninstall(account: &str, out: &mut HelperResponse) -> Result<()> {
    if !is_account_name(account) {
        bail!("the uninstall request names an account setup does not make");
    }
    powershell(&remove_rule_script(account)).context("remove the egress rule")?;
    out.done.push(format!("removed the firewall rule {}", rule_name(account)));
    let name = wide_str(account);
    if let Some(sid) = lookup_account(account)? {
        // SAFETY: a NUL-terminated SID string; null path and computer = this machine's profile.
        if unsafe { DeleteProfileW(wide_str(&sid).as_ptr(), std::ptr::null(), std::ptr::null()) } == 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() != Some(ERROR_FILE_NOT_FOUND as i32) {
                bail!("remove the profile of {account} (is a program still running as it?): {e}");
            }
        } else {
            out.done.push(format!("removed the profile of {account}"));
        }
        // SAFETY: a NUL-terminated name.
        net(unsafe { NetUserDel(std::ptr::null(), name.as_ptr()) }, "delete the account")?;
        out.done.push(format!("deleted the account {account}"));
    }
    // SAFETY: NUL-terminated key and value names.
    let rc = unsafe { RegDeleteKeyValueW(HKEY_LOCAL_MACHINE, wide_str(HIDDEN_USERS_KEY).as_ptr(), name.as_ptr()) };
    if rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND {
        win(rc, "unhide the account")?;
    }
    Ok(())
}

/// Run the elevated half: in this process when it is already elevated,
/// else through one UAC prompt. The request (which may carry the password)
/// and the answer pass through a fresh folder only the developer, SYSTEM and
/// the administrators can open, removed afterwards.
fn run_elevated(request: &HelperRequest) -> Result<HelperResponse> {
    if is_elevated()? {
        return Ok(perform(request));
    }
    let dir = HandOff::create()?;
    let request_path = dir.0.join("request.json");
    std::fs::write(&request_path, serde_json::to_vec(request)?).context("write the setup request")?;
    let exe = std::env::current_exe().context("locate ssai")?;
    let file = wide(exe.as_os_str());
    let params = wide_str(&format!("__sandbox-setup \"{}\"", request_path.display()));
    let verb = wide_str("runas");
    // SAFETY: zeroed is a valid empty SHELLEXECUTEINFOW (null handles and strings).
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = params.as_ptr();
    info.nShow = 0; // SW_HIDE: the answer comes back in the file.
    println!("ssai: setup needs administrator rights — approve the Windows prompt.");
    // SAFETY: `info` and the strings it points at are alive for the call.
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(ERROR_CANCELLED as i32) {
            bail!("the administrator prompt was declined — nothing was changed");
        }
        bail!("start the elevated setup: {e}");
    }
    let mut code = 1u32;
    // SAFETY: `hProcess` is the process handle SEE_MASK_NOCLOSEPROCESS
    // returned; waited on, read, then closed once.
    unsafe {
        WaitForSingleObject(info.hProcess, INFINITE);
        GetExitCodeProcess(info.hProcess, &mut code);
        CloseHandle(info.hProcess);
    }
    match std::fs::read(dir.0.join("response.json")) {
        Ok(bytes) => serde_json::from_slice(&bytes).context("read the setup answer"),
        Err(_) => bail!("the elevated setup stopped (exit code {code}) without an answer"),
    }
}

/// The hand-off folder, removed when dropped.
struct HandOff(PathBuf);

impl HandOff {
    fn create() -> Result<Self> {
        let mut suffix = [0u8; 8];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut suffix);
        let dir = std::env::temp_dir().join(format!("ssai-setup-{}", hex::encode(suffix)));
        std::fs::create_dir(&dir).with_context(|| format!("create {}", dir.display()))?;
        let dir = Self(dir);
        crate::win_acl::restrict_dir_to_owner_and_admins(&dir.0)?;
        Ok(dir)
    }
}

impl Drop for HandOff {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The egress rule as the firewall stores it, and every profile applying it.
fn check_firewall(account: &str, sid: &str) -> std::result::Result<(), String> {
    let stored = reg_string(RULES_KEY, &rule_name(account))
        .map_err(|e| format!("{e:#}"))?
        .ok_or_else(|| format!("the sandbox's firewall rule is missing — {SETUP_HINT}"))?;
    check_stored_rule(&stored, sid).map_err(|e| format!("{e} — {SETUP_HINT}"))?;
    let local = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";
    let policy = r"SOFTWARE\Policies\Microsoft\WindowsFirewall";
    for (name, local_key, policy_key) in PROFILES {
        let read = |key: String, value: &str| reg_dword(&key, value).map_err(|e| format!("{e:#}"));
        check_profile(
            name,
            read(format!(r"{local}\{local_key}"), "EnableFirewall")?,
            read(format!(r"{policy}\{policy_key}"), "EnableFirewall")?,
            read(format!(r"{policy}\{policy_key}"), "AllowLocalPolicyMerge")?,
        )?;
    }
    Ok(())
}

fn record_path() -> Result<PathBuf> {
    Ok(crate::state::config_dir()?.join(RECORD_FILE))
}

fn load_record() -> Result<Option<SetupRecord>> {
    match std::fs::read(record_path()?) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes).context("parse the sandbox setup record")?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).context("read the sandbox setup record"),
    }
}

fn save_record(record: &SetupRecord) -> Result<()> {
    crate::state::write_private(&record_path()?, &serde_json::to_vec_pretty(record)?)
}

/// Protect `secret` for the current Windows account (DPAPI), base64.
fn protect(secret: &str) -> Result<String> {
    let input = CRYPT_INTEGER_BLOB { cbData: secret.len() as u32, pbData: secret.as_ptr().cast_mut() };
    let entropy = CRYPT_INTEGER_BLOB { cbData: ENTROPY.len() as u32, pbData: ENTROPY.as_ptr().cast_mut() };
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: the blobs point at live buffers (read only); `output` is LocalAlloc'd on success.
    if unsafe {
        CryptProtectData(&input, std::ptr::null(), &entropy, std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output)
    } == 0
    {
        bail!("protect the sandbox password: {}. {DPAPI_HINT}", std::io::Error::last_os_error());
    }
    Ok(base64::engine::general_purpose::STANDARD.encode(take_blob(output)))
}

/// [`protect`]'s inverse.
fn unprotect(text: &str) -> Result<String> {
    let mut sealed = base64::engine::general_purpose::STANDARD.decode(text).context("the protected password is not base64")?;
    let input = CRYPT_INTEGER_BLOB { cbData: sealed.len() as u32, pbData: sealed.as_mut_ptr() };
    let entropy = CRYPT_INTEGER_BLOB { cbData: ENTROPY.len() as u32, pbData: ENTROPY.as_ptr().cast_mut() };
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: as in `protect`.
    if unsafe {
        CryptUnprotectData(&input, std::ptr::null_mut(), &entropy, std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output)
    } == 0
    {
        bail!("unprotect the sandbox password: {}", std::io::Error::last_os_error());
    }
    String::from_utf8(take_blob(output)).context("the protected password is not text")
}

/// Copy a DPAPI output blob and free it, once.
fn take_blob(blob: CRYPT_INTEGER_BLOB) -> Vec<u8> {
    // SAFETY: DPAPI filled `pbData` with `cbData` bytes, LocalAlloc'd.
    unsafe {
        let bytes = std::slice::from_raw_parts(blob.pbData, blob.cbData as usize).to_vec();
        LocalFree(blob.pbData.cast());
        bytes
    }
}

/// A sign-in token, closed when dropped.
struct Token(HANDLE);

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: a token LogonUserW returned, closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// Sign the local account `account` in, as the launch will.
fn logon(account: &str, password: &str) -> std::result::Result<Token, std::io::Error> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: NUL-terminated strings; `token` receives a handle on success.
    let ok = unsafe {
        LogonUserW(
            wide_str(account).as_ptr(),
            wide_str(".").as_ptr(),
            wide_str(password).as_ptr(),
            LOGON32_LOGON_INTERACTIVE,
            LOGON32_PROVIDER_DEFAULT,
            &mut token,
        )
    };
    if ok == 0 { Err(std::io::Error::last_os_error()) } else { Ok(Token(token)) }
}

/// Whether `token` carries the group `group_sid` in any state — enabled, or
/// deny-only as in an administrator's filtered (UAC) token.
fn token_has_group(token: HANDLE, group_sid: &str) -> Result<bool> {
    let mut len = 0u32;
    // SAFETY: a size query on an open token.
    unsafe { GetTokenInformation(token, TokenGroups, std::ptr::null_mut(), 0, &mut len) };
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buf` holds `len` bytes, 8-aligned.
    if unsafe { GetTokenInformation(token, TokenGroups, buf.as_mut_ptr().cast(), len, &mut len) } == 0 {
        bail!("read the sandbox account's groups: {}", std::io::Error::last_os_error());
    }
    let wanted = Sid::parse(group_sid)?;
    // SAFETY: the call above filled `buf` with a TOKEN_GROUPS whose
    // `GroupCount` entries follow it in the same buffer.
    let found = unsafe {
        let groups = &*buf.as_ptr().cast::<TOKEN_GROUPS>();
        let entries: &[SID_AND_ATTRIBUTES] = std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize);
        entries.iter().any(|g| EqualSid(g.Sid, wanted.0) != 0)
    };
    Ok(found)
}

/// A SID built from its string, freed when dropped.
pub(super) struct Sid(pub(super) PSID);

impl Sid {
    pub(super) fn parse(text: &str) -> Result<Self> {
        let mut sid: PSID = std::ptr::null_mut();
        // SAFETY: a NUL-terminated string; `sid` is LocalAlloc'd on success.
        if unsafe { ConvertStringSidToSidW(wide_str(text).as_ptr(), &mut sid) } == 0 {
            bail!("parse the SID {text}: {}", std::io::Error::last_os_error());
        }
        Ok(Self(sid))
    }
}

impl Drop for Sid {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSidToSidW, freed once.
        unsafe { LocalFree(self.0) };
    }
}

/// The SID of THIS machine's local account `account`, if it exists — the
/// name is qualified with the computer's, so a domain account of the same
/// name is never taken for it.
fn lookup_account(account: &str) -> Result<Option<String>> {
    let qualified = wide_str(&format!("{}\\{account}", computer_name()?));
    let (mut sid_len, mut dom_len, mut kind) = (0u32, 0u32, SID_NAME_USE::default());
    // SAFETY: a size query (null buffers, zero lengths).
    let ok = unsafe {
        LookupAccountNameW(std::ptr::null(), qualified.as_ptr(), std::ptr::null_mut(), &mut sid_len, std::ptr::null_mut(), &mut dom_len, &mut kind)
    };
    if ok == 0 {
        let e = std::io::Error::last_os_error();
        match e.raw_os_error().map(|c| c as u32) {
            Some(ERROR_NONE_MAPPED) => return Ok(None),
            Some(ERROR_INSUFFICIENT_BUFFER) => {}
            _ => bail!("look up the account {account}: {e}"),
        }
    }
    let mut sid = vec![0u64; (sid_len as usize).div_ceil(8)];
    let mut dom = vec![0u16; dom_len as usize];
    // SAFETY: the buffers hold the sizes the query asked for.
    if unsafe {
        LookupAccountNameW(std::ptr::null(), qualified.as_ptr(), sid.as_mut_ptr().cast(), &mut sid_len, dom.as_mut_ptr(), &mut dom_len, &mut kind)
    } == 0
    {
        bail!("look up the account {account}: {}", std::io::Error::last_os_error());
    }
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: `sid` holds the SID just read; `text` is LocalAlloc'd on success, freed once.
    unsafe {
        if ConvertSidToStringSidW(sid.as_mut_ptr().cast(), &mut text) == 0 {
            bail!("spell the account's SID: {}", std::io::Error::last_os_error());
        }
        let out = wide_to_string(text);
        LocalFree(text.cast());
        Ok(Some(out))
    }
}

/// The name an access list's owner spells for `sid`, used to name local
/// groups by SID rather than by their (translated) names.
fn sid_of_group_name(name: &str) -> Option<String> {
    let wide_name = wide_str(name);
    let (mut sid_len, mut dom_len, mut kind) = (0u32, 0u32, SID_NAME_USE::default());
    // SAFETY: a size query.
    unsafe { LookupAccountNameW(std::ptr::null(), wide_name.as_ptr(), std::ptr::null_mut(), &mut sid_len, std::ptr::null_mut(), &mut dom_len, &mut kind) };
    let mut sid = vec![0u64; (sid_len as usize).div_ceil(8)];
    let mut dom = vec![0u16; dom_len as usize];
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: buffers sized by the query; `text` freed once.
    unsafe {
        if LookupAccountNameW(std::ptr::null(), wide_name.as_ptr(), sid.as_mut_ptr().cast(), &mut sid_len, dom.as_mut_ptr(), &mut dom_len, &mut kind) == 0
            || ConvertSidToStringSidW(sid.as_mut_ptr().cast(), &mut text) == 0
        {
            return None;
        }
        let out = wide_to_string(text);
        LocalFree(text.cast());
        Some(out)
    }
}

/// The SIDs of the local groups `account` belongs to, directly or not.
fn local_groups(account: &str) -> Result<Vec<String>> {
    let mut buf: *mut u8 = std::ptr::null_mut();
    let (mut read, mut total) = (0u32, 0u32);
    // SAFETY: a NUL-terminated name; `buf` is allocated by the call and freed below.
    let rc = unsafe {
        NetUserGetLocalGroups(std::ptr::null(), wide_str(account).as_ptr(), 0, LG_INCLUDE_INDIRECT, &mut buf, MAX_PREFERRED_LENGTH, &mut read, &mut total)
    };
    net(rc, "read the account's groups")?;
    if buf.is_null() {
        return Ok(Vec::new());
    }
    // SAFETY: on success a non-null `buf` holds `read` LOCALGROUP_USERS_INFO_0
    // entries; freed once.
    let names: Vec<String> = unsafe {
        let entries = std::slice::from_raw_parts(buf.cast::<LOCALGROUP_USERS_INFO_0>(), read as usize);
        let names = entries.iter().map(|e| wide_to_string(e.lgrui0_name)).collect();
        NetApiBufferFree(buf.cast());
        names
    };
    Ok(names.iter().filter_map(|n| sid_of_group_name(n)).collect())
}

/// The account's flags, or `None` when no such local account exists.
fn user_flags(account: &str) -> Result<Option<u32>> {
    const NERR_USER_NOT_FOUND: u32 = 2221;
    let mut buf: *mut u8 = std::ptr::null_mut();
    // SAFETY: a NUL-terminated name; `buf` is allocated by the call and freed below.
    let rc = unsafe { NetUserGetInfo(std::ptr::null(), wide_str(account).as_ptr(), 1, &mut buf) };
    if rc == NERR_USER_NOT_FOUND {
        return Ok(None);
    }
    net(rc, "read the account")?;
    // SAFETY: on success `buf` holds one USER_INFO_1; freed once.
    let flags = unsafe {
        let flags = (*buf.cast::<USER_INFO_1>()).usri1_flags;
        NetApiBufferFree(buf.cast());
        flags
    };
    Ok(Some(flags))
}

fn is_elevated() -> Result<bool> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: this process's pseudo-handle; `token` is wrapped and closed on drop.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        bail!("open this process's token: {}", std::io::Error::last_os_error());
    }
    let token = Token(token);
    let mut elevation = TOKEN_ELEVATION::default();
    let mut len = 0u32;
    // SAFETY: `elevation` is a TOKEN_ELEVATION of the size passed.
    if unsafe {
        GetTokenInformation(token.0, TokenElevation, (&raw mut elevation).cast(), std::mem::size_of::<TOKEN_ELEVATION>() as u32, &mut len)
    } == 0
    {
        bail!("read this process's elevation: {}", std::io::Error::last_os_error());
    }
    Ok(elevation.TokenIsElevated != 0)
}

fn user_name() -> Result<String> {
    let mut buf = vec![0u16; 257];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` holds `len` units.
    if unsafe { GetUserNameW(buf.as_mut_ptr(), &mut len) } == 0 {
        bail!("read your user name: {}", std::io::Error::last_os_error());
    }
    // SAFETY: NUL-terminated on success.
    Ok(unsafe { wide_to_string(buf.as_ptr()) })
}

fn computer_name() -> Result<String> {
    let mut buf = vec![0u16; 64];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` holds `len` units.
    if unsafe { GetComputerNameW(buf.as_mut_ptr(), &mut len) } == 0 {
        bail!("read the computer's name: {}", std::io::Error::last_os_error());
    }
    Ok(String::from_utf16_lossy(&buf[..len as usize]))
}

fn reg_string(key: &str, value: &str) -> Result<Option<String>> {
    let (key_w, value_w) = (wide_str(key), wide_str(value));
    let mut len = 0u32;
    // SAFETY: a size query.
    let rc = unsafe {
        RegGetValueW(HKEY_LOCAL_MACHINE, key_w.as_ptr(), value_w.as_ptr(), RRF_RT_REG_SZ, std::ptr::null_mut(), std::ptr::null_mut(), &mut len)
    };
    if rc == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    win(rc, "read the firewall rule store")?;
    let mut buf = vec![0u16; (len as usize).div_ceil(2) + 1];
    let mut len = (buf.len() * 2) as u32;
    // SAFETY: `buf` holds `len` bytes.
    let rc = unsafe {
        RegGetValueW(HKEY_LOCAL_MACHINE, key_w.as_ptr(), value_w.as_ptr(), RRF_RT_REG_SZ, std::ptr::null_mut(), buf.as_mut_ptr().cast(), &mut len)
    };
    win(rc, "read the firewall rule store")?;
    // SAFETY: RRF_RT_REG_SZ data comes back NUL-terminated.
    Ok(Some(unsafe { wide_to_string(buf.as_ptr()) }))
}

fn reg_dword(key: &str, value: &str) -> Result<Option<u32>> {
    let mut data = 0u32;
    let mut len = 4u32;
    // SAFETY: `data` is 4 writable bytes.
    let rc = unsafe {
        RegGetValueW(HKEY_LOCAL_MACHINE, wide_str(key).as_ptr(), wide_str(value).as_ptr(), RRF_RT_REG_DWORD, std::ptr::null_mut(), (&raw mut data).cast(), &mut len)
    };
    if rc == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    win(rc, "read the firewall settings")?;
    Ok(Some(data))
}

/// Run a PowerShell script (the firewall cmdlets have no flat API), from
/// the system's own copy.
fn powershell(script: &str) -> Result<()> {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    let exe = Path::new(&root).join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let output = std::process::Command::new(&exe)
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script])
        .output()
        .with_context(|| format!("run {}", exe.display()))?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        bail!("PowerShell: {}", err.trim().chars().take(600).collect::<String>());
    }
    Ok(())
}

fn net(rc: u32, what: &str) -> Result<()> {
    if rc == 0 { Ok(()) } else { bail!("{what}: error {rc} ({})", std::io::Error::from_raw_os_error(rc as i32)) }
}

fn win(rc: u32, what: &str) -> Result<()> {
    if rc == ERROR_SUCCESS { Ok(()) } else { bail!("{what}: {}", std::io::Error::from_raw_os_error(rc as i32)) }
}

fn wide_str(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

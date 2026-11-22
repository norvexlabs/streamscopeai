//! `ssai update` — self-update from the gateway's distribution
//! surface: compare versions, download the binary for this platform, verify
//! its sha256 against the gateway's manifest, and atomically replace the
//! running executable.
//!
//! What the test suite reaches, and what it does not. [`resolve_origin`] is pinned
//! below. [`run`] is not, and cannot usefully be: past the origin it needs a live
//! gateway ADVERTISING A NEWER BUILD than the running binary, then downloads that
//! binary and replaces the running executable in place. The e2e harness drives the real
//! CLI hard, but it drives the build under test — which is never newer than itself — so
//! the download-and-swap path takes its first branch and stops. Nothing here is
//! dead code; it is the one command whose whole point is an interaction the suite has
//! no way to stage, and it is named in the coverage union for that reason rather than
//! as an omission to fix.

use anyhow::{bail, Context, Result};

use crate::api;
use crate::state::{sha256_hex, HostsFile};

use super::session::confirm;

/// Distribution target this build self-updates from. The CLI ships for Linux
/// x86_64, macOS Apple Silicon, Windows x86_64 and FreeBSD amd64; other platforms get a clear
/// error.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SELF_TARGET: Option<&str> = Some("linux-x86_64");
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const SELF_TARGET: Option<&str> = Some("darwin-arm64");
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
const SELF_TARGET: Option<&str> = Some("windows-x86_64");
#[cfg(all(target_os = "freebsd", target_arch = "x86_64"))]
const SELF_TARGET: Option<&str> = Some("freebsd-x86_64");
#[cfg(not(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64"),
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "freebsd", target_arch = "x86_64")
)))]
const SELF_TARGET: Option<&str> = None;

/// The names a Windows update moves the executable it replaces to: a running
/// `.exe` can be renamed but not overwritten, so it steps aside as
/// `<name>.old.exe` — or, while earlier ones still run there,
/// `<name>.old-2.exe` … `<name>.old-9.exe` — and a later start removes them
/// ([`remove_replaced_exe`]). A fixed set, so that start needs no folder scan.
#[cfg(windows)]
fn replaced_names(exe: &std::path::Path) -> Vec<std::path::PathBuf> {
    std::iter::once(exe.with_extension("old.exe"))
        .chain((2..=9).map(|n| exe.with_extension(format!("old-{n}.exe"))))
        .collect()
}

/// The first of [`replaced_names`] free to take the executable `exe`: one
/// that is absent, or held by no running copy (removed here).
#[cfg(windows)]
fn replaced_exe(exe: &std::path::Path) -> Result<std::path::PathBuf> {
    replaced_names(exe)
        .into_iter()
        .find(|old| {
            let _ = std::fs::remove_file(old);
            !old.exists()
        })
        .context("nine earlier copies of ssai replaced by updates are still running — close them, then update")
}

/// Remove the executables earlier updates replaced, now that they no longer
/// run. Best effort: one still running (another `ssai` started before the
/// update) is removed by a later start.
#[cfg(windows)]
pub fn remove_replaced_exe() {
    if let Ok(exe) = std::env::current_exe() {
        for old in replaced_names(&exe) {
            let _ = std::fs::remove_file(old);
        }
    }
}

/// How to reinstall when the executable cannot be replaced in place.
fn reinstall_hint(origin: &str) -> String {
    let url = api::installer_url(origin);
    if cfg!(windows) { format!("irm {url} | iex") } else { format!("curl -fsSL {url} | sh") }
}

pub async fn run(host: Option<&str>, yes: bool) -> Result<()> {
    let Some(self_target) = SELF_TARGET else {
        bail!(
            "self-update is not available for this platform (supported: Linux x86_64, macOS Apple Silicon, \
             Windows x86_64, FreeBSD amd64)"
        );
    };
    let origin = resolve_origin(host)?;
    // This command downloads an executable and puts it where the next
    // `ssai` invocation will run it, so the manifest's sha256 proves
    // only that the bytes match what the *same* origin claimed. TLS is what
    // makes the origin mean anything, and unlike the credential paths there is
    // no loopback exemption: a plaintext fetch here is arbitrary code
    // execution, and the opt-out env var must not reach it either.
    if !origin.starts_with("https://") {
        bail!(
            "refusing to self-update from {origin} — a binary this command will execute must \
             come over https"
        );
    }

    let info = api::cli_version(&origin).await?;
    if info.version == crate::VERSION {
        println!("Already up to date (v{}).", crate::VERSION);
        return Ok(());
    }
    let target = info
        .targets
        .iter()
        .find(|t| t.target == self_target)
        .with_context(|| format!("the gateway ships no {self_target} build"))?;

    println!(
        "Updating ssai v{} → v{} from {origin}",
        crate::VERSION,
        info.version
    );
    if !yes && !confirm("Proceed?")? {
        bail!("aborted");
    }

    let bytes = api::cli_download(&origin, self_target).await?;
    let got_sha = sha256_hex(&bytes);
    if got_sha != target.sha256 {
        bail!(
            "downloaded binary fails verification (sha256 {got_sha}, gateway manifest says {}) — aborting",
            target.sha256
        );
    }

    #[cfg(target_os = "freebsd")]
    refuse_a_build_this_freebsd_cannot_run(&bytes)?;

    let exe = std::env::current_exe().context("cannot resolve the running executable's path")?;
    replace_exe(&exe, &bytes).with_context(|| {
        format!(
            "failed to replace {} — if it's owned by another user, re-run the \
             installer instead: {}",
            exe.display(),
            reinstall_hint(&origin)
        )
    })?;

    println!("Updated to v{} ({}).", info.version, exe.display());
    Ok(())
}

/// Put `bytes` at `exe`, the running executable, atomically: write them next
/// to it (same filesystem) and rename over it — the running process keeps its
/// old inode, the path serves the new build. On Windows the running file is
/// first renamed aside ([`replaced_exe`]), and put back if the new one cannot
/// take its place.
fn replace_exe(exe: &std::path::Path, bytes: &[u8]) -> Result<()> {
    let dir = exe.parent().context("the running executable has no parent directory")?;
    let tmp = dir.join(format!(".ssai.update-{}", std::process::id()));
    let install = || -> Result<()> {
        {
            use std::io::Write;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o755);
            }
            let mut f = opts.open(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
        }
        #[cfg(windows)]
        {
            let old = replaced_exe(exe)?;
            std::fs::rename(exe, &old)?;
            if let Err(e) = std::fs::rename(&tmp, exe) {
                if let Err(back) = std::fs::rename(&old, exe) {
                    return Err(anyhow::Error::new(e).context(format!(
                        "the new build could not take {}'s place, nor the previous one be put back ({back}): \
                         rename {} to {} to restore it",
                        exe.display(),
                        old.display(),
                        exe.display()
                    )));
                }
                return Err(e.into());
            }
        }
        #[cfg(not(windows))]
        std::fs::rename(&tmp, exe)?;
        Ok(())
    };
    let result = install();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// The `__FreeBSD_version` a FreeBSD executable was linked against: the
/// descriptor of its ABI note (owner `FreeBSD`, type 1, 4 bytes), found by
/// walking the notes of its `PT_NOTE` segments — never by scanning the file,
/// whose data may hold the same bytes. `None` for anything but a 64-bit
/// little-endian ELF carrying that note.
#[cfg_attr(not(target_os = "freebsd"), allow(dead_code, reason = "read only by the FreeBSD update"))]
fn freebsd_abi_version(elf: &[u8]) -> Option<u32> {
    const PT_NOTE: u32 = 4;
    const NT_FREEBSD_ABI_TAG: u32 = 1;
    let u16_at = |o: usize| Some(u16::from_le_bytes(elf.get(o..o.checked_add(2)?)?.try_into().ok()?));
    let u32_at = |o: usize| Some(u32::from_le_bytes(elf.get(o..o.checked_add(4)?)?.try_into().ok()?));
    let usize_at = |o: usize| usize::try_from(u64::from_le_bytes(elf.get(o..o.checked_add(8)?)?.try_into().ok()?)).ok();
    if elf.get(..6)? != [0x7f, b'E', b'L', b'F', 2, 1] {
        return None;
    }
    let (phoff, phentsize, phnum) = (usize_at(0x20)?, usize::from(u16_at(0x36)?), usize::from(u16_at(0x38)?));
    for i in 0..phnum {
        let ph = phoff.checked_add(i.checked_mul(phentsize)?)?;
        if u32_at(ph)? != PT_NOTE {
            continue;
        }
        let mut at = usize_at(ph.checked_add(8)?)?;
        let end = at.checked_add(usize_at(ph.checked_add(0x20)?)?)?;
        while at.checked_add(12)? <= end {
            let namesz = usize::try_from(u32_at(at)?).ok()?;
            let descsz = usize::try_from(u32_at(at + 4)?).ok()?;
            let name = at + 12;
            let desc = name.checked_add(namesz.checked_next_multiple_of(4)?)?;
            if u32_at(at + 8)? == NT_FREEBSD_ABI_TAG && descsz == 4 && elf.get(name..desc)?.starts_with(b"FreeBSD\0") {
                return u32_at(desc);
            }
            at = desc.checked_add(descsz.checked_next_multiple_of(4)?)?;
        }
    }
    None
}

/// `(major, minor)` of a FreeBSD release name as `freebsd-version` prints it
/// (`14.4-RELEASE-p3`, `15.0-CURRENT`); `None` for anything else.
#[cfg_attr(not(target_os = "freebsd"), allow(dead_code, reason = "read only by the FreeBSD update"))]
fn freebsd_release(name: &str) -> Option<(u32, u32)> {
    let (major, rest) = name.trim().split_once('.')?;
    let minor = rest.split(|c: char| !c.is_ascii_digit()).next()?;
    Some((major.parse().ok()?, minor.parse().ok()?))
}

/// Whether a build linked against FreeBSD `abi` (a `__FreeBSD_version`)
/// runs on a userland at release `host`: one of its own release or later —
/// an earlier one may lack a symbol it needs.
#[cfg_attr(not(target_os = "freebsd"), allow(dead_code, reason = "read only by the FreeBSD update"))]
fn freebsd_build_runs_on(abi: u32, host: (u32, u32)) -> bool {
    (abi / 100_000, abi / 1_000 % 100) <= host
}

/// Refuse to install a FreeBSD build this system could not start — the
/// gateway builds for the oldest FreeBSD release it supports, so a userland
/// left on a release that support has moved past would otherwise be updated
/// into a command that no longer runs. The userland's release is what
/// `freebsd-version -u` reports (in a jail, the jail's own, unlike the kernel's);
/// without it, the kernel's (`uname -r`) — the installer reads it the same way.
#[cfg(target_os = "freebsd")]
fn refuse_a_build_this_freebsd_cannot_run(bytes: &[u8]) -> Result<()> {
    let read = |program: &str, arg: &str| {
        std::process::Command::new(program)
            .arg(arg)
            .output()
            .ok()
            .filter(|out| out.status.success())
            .and_then(|out| freebsd_release(&String::from_utf8_lossy(&out.stdout)))
    };
    let host = read("/bin/freebsd-version", "-u")
        .or_else(|| read("/usr/bin/uname", "-r"))
        .context("cannot read this system's FreeBSD release (neither freebsd-version -u nor uname -r answered)")?;
    let abi = freebsd_abi_version(bytes).context("the gateway's FreeBSD build carries no FreeBSD ABI note")?;
    if !freebsd_build_runs_on(abi, host) {
        bail!(
            "the gateway's build needs FreeBSD {}.{} or newer and this system runs FreeBSD {}.{} — upgrade \
             FreeBSD before updating ssai",
            abi / 100_000,
            abi / 1_000 % 100,
            host.0,
            host.1
        );
    }
    Ok(())
}

/// `YYYY.M.MICRO` as a comparable triple; `None` for anything else.
fn parse_version(v: &str) -> Option<(u32, u32, u32)> {
    let field = |p: &str| (!p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())).then(|| p.parse::<u32>().ok()).flatten();
    let mut parts = v.trim().split('.').map(field);
    let triple = (parts.next()??, parts.next()??, parts.next()??);
    parts.next().is_none().then_some(triple)
}

/// Whether the gateway's `shipped` build is newer than `running`: compared as
/// numbers, and never when either version does not parse.
fn is_newer(shipped: &str, running: &str) -> bool {
    matches!((parse_version(shipped), parse_version(running)), (Some(s), Some(r)) if s > r)
}

/// Say so when the gateway at `origin` ships a newer `ssai` than this one,
/// and how to get it; returns whether the gateway answered. Best effort: a
/// gateway that cannot be asked says nothing.
pub async fn newer_version_notice(origin: &str) -> bool {
    let Ok(info) = api::cli_version(origin).await else { return false };
    if !is_newer(&info.version, crate::VERSION) {
        return true;
    }
    let served = SELF_TARGET.is_some_and(|t| info.targets.iter().any(|x| x.target == t));
    // `ssai update` takes a build over https only, and for a system it ships for.
    let how = if !origin.starts_with("https://") || SELF_TARGET.is_none() {
        format!("reinstall it: {}", reinstall_hint(origin))
    } else if served {
        format!("run: ssai update --host {origin}")
    } else {
        "it serves no build for this system".to_string()
    };
    crate::ui::note(
        "",
        format_args!("the gateway ships ssai v{} (you run v{}) — {how}", info.version, crate::VERSION),
    );
    true
}

/// The gateway origin to update from: `--host` / `STREAMSCOPE_URL` (any
/// portal URL), or the stored login when there's exactly one.
fn resolve_origin(host: Option<&str>) -> Result<String> {
    let selector = match host {
        Some(s) => Some(s.to_string()),
        None => std::env::var("STREAMSCOPE_URL").ok().filter(|s| !s.is_empty()),
    };
    if let Some(sel) = &selector
        && let Ok((origin, _)) = crate::oauth::parse_portal_url(sel)
    {
        return Ok(origin);
    }
    let hosts = HostsFile::load()?;
    let (_, entry) = hosts.select(selector.as_deref()).context(
        "no gateway to update from — pass --host <portal-url> or log in first",
    )?;
    Ok(entry.api_origin)
}


#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal ELF64: a `PT_LOAD` header, then a `PT_NOTE` one whose segment
    /// holds an unrelated note and then the ABI note — and, outside every
    /// note segment, the ABI note's bytes with another version, as a binary's
    /// data could carry them.
    fn elf_with_abi_note(version: u32) -> Vec<u8> {
        let note = |name: &[u8], ty: u32, desc: &[u8]| {
            let mut n = Vec::new();
            n.extend_from_slice(&u32::try_from(name.len()).unwrap().to_le_bytes());
            n.extend_from_slice(&u32::try_from(desc.len()).unwrap().to_le_bytes());
            n.extend_from_slice(&ty.to_le_bytes());
            n.extend_from_slice(name);
            n.resize(n.len().next_multiple_of(4), 0);
            n.extend_from_slice(desc);
            n.resize(n.len().next_multiple_of(4), 0);
            n
        };
        let decoy = note(b"FreeBSD\0", 1, &999_999u32.to_le_bytes());
        let notes = [note(b"GNU\0", 3, &[1; 20]), note(b"FreeBSD\0", 1, &version.to_le_bytes())].concat();
        let (phoff, phnum, phentsize) = (64usize, 2u16, 56u16);
        let decoy_at = phoff + 2 * 56;
        let notes_at = decoy_at + decoy.len();
        let mut elf = vec![0u8; notes_at];
        elf[..6].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1]);
        elf[0x20..0x28].copy_from_slice(&(phoff as u64).to_le_bytes());
        elf[0x36..0x38].copy_from_slice(&phentsize.to_le_bytes());
        elf[0x38..0x3a].copy_from_slice(&phnum.to_le_bytes());
        elf[phoff..phoff + 4].copy_from_slice(&1u32.to_le_bytes());
        let ph = phoff + 56;
        elf[ph..ph + 4].copy_from_slice(&4u32.to_le_bytes());
        elf[ph + 8..ph + 16].copy_from_slice(&(notes_at as u64).to_le_bytes());
        elf[ph + 0x20..ph + 0x28].copy_from_slice(&(notes.len() as u64).to_le_bytes());
        elf[decoy_at..notes_at].copy_from_slice(&decoy);
        elf.extend_from_slice(&notes);
        elf
    }

    /// The ABI note is read from the note segment — past another note, and
    /// never from the same bytes elsewhere in the file; a file cut inside the
    /// segment, or not an ELF64 at all, has no version.
    #[test]
    fn the_freebsd_abi_version_is_read_from_the_note_segment() {
        let elf = elf_with_abi_note(1_404_000);
        assert_eq!(freebsd_abi_version(&elf), Some(1_404_000));
        assert_eq!(freebsd_abi_version(&elf[..elf.len() - 2]), None);
        assert_eq!(freebsd_abi_version(b"\x7fELF no header"), None);
    }

    /// The test executable itself is a FreeBSD build: the walk finds its note,
    /// at least the oldest release the CLI is built for.
    #[cfg(target_os = "freebsd")]
    #[test]
    fn this_build_carries_its_freebsd_abi_note() {
        let me = std::fs::read(std::env::current_exe().expect("own path")).expect("own bytes");
        assert!(freebsd_abi_version(&me).is_some_and(|v| v >= 1_400_000));
    }

    /// A release name gives its major and minor, whatever follows them.
    #[test]
    fn a_freebsd_release_name_gives_its_major_and_minor() {
        assert_eq!(freebsd_release("14.4-RELEASE-p3\n"), Some((14, 4)));
        assert_eq!(freebsd_release("15.0-CURRENT"), Some((15, 0)));
        assert_eq!(freebsd_release("15"), None);
        assert_eq!(freebsd_release("x.1-RELEASE"), None);
    }

    /// A build runs on its own release and every later one, never on an
    /// earlier minor or major — the boundary on both sides.
    #[test]
    fn a_freebsd_build_runs_on_its_release_and_later_only() {
        assert!(freebsd_build_runs_on(1_404_000, (14, 4)));
        assert!(freebsd_build_runs_on(1_404_000, (14, 5)));
        assert!(freebsd_build_runs_on(1_404_000, (15, 0)));
        assert!(!freebsd_build_runs_on(1_404_000, (14, 3)));
        assert!(!freebsd_build_runs_on(1_500_000, (14, 9)));
    }

    /// Only a strictly newer `YYYY.M.MICRO` is announced, compared as
    /// numbers: never an older or equal one, never one that does not parse.
    #[test]
    fn only_a_strictly_newer_release_is_announced() {
        assert!(is_newer("2026.11.36", "2026.11.35"));
        assert!(is_newer("2026.11.10", "2026.11.9"));
        assert!(is_newer("2026.12.1", "2026.11.99"));
        assert!(is_newer("2027.1.1", "2026.12.400"));
        assert!(!is_newer("2026.11.35", "2026.11.35"));
        assert!(!is_newer("2026.11.34", "2026.11.35"));
        assert!(!is_newer("2026.11", "2026.10.1"));
        assert!(!is_newer("2026.11.36.1", "2026.11.35"));
        assert!(!is_newer("2026.11.36-dev", "2026.11.35"));
        assert!(!is_newer("2026.11.+37", "2026.11.35"));
        assert!(!is_newer("2026..37", "2026.11.35"));
        assert!(!is_newer("2026.11.36", "dev"));
        assert!(!is_newer("", "2026.11.35"));
    }

    /// `--host` takes any portal URL and the origin is what survives — the CLI talks to
    /// the API origin, not to whatever deep link the operator happened to paste. This
    /// branch never consults the environment or the hosts file, which is what makes it
    /// the part of the command a unit test can hold.
    #[test]
    fn an_explicit_host_resolves_to_its_origin_whatever_path_it_carries() {
        for (given, expected) in [
            ("https://gw.example.test/portal/t/acme", "https://gw.example.test"),
            ("https://gw.example.test", "https://gw.example.test"),
            ("https://gw.example.test:8443/portal/t/acme/keys", "https://gw.example.test:8443"),
            ("http://localhost:3000/portal", "http://localhost:3000"),
        ] {
            assert_eq!(
                resolve_origin(Some(given)).unwrap(),
                expected,
                "--host {given}"
            );
        }
    }

    /// The executable is replaced in place, leaving only the new build beside
    /// it. (On Unix a plain file stands in: executing a just-copied binary in a
    /// multithreaded test races another thread's fork for `ETXTBSY`.)
    #[cfg(unix)]
    #[test]
    fn the_executable_is_replaced_in_place() {
        let dir = std::env::temp_dir().join(format!("ss-update-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("tool");
        std::fs::write(&exe, b"old build").unwrap();
        replace_exe(&exe, b"new build").unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"new build");
        let left: Vec<String> =
            std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        assert_eq!(left, ["tool"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A running executable steps aside and the new build takes its place —
    /// twice, the second while the first one replaced is still running — and
    /// a later start removes both replaced ones.
    #[cfg(windows)]
    #[test]
    fn a_running_executable_is_replaced_in_place() {
        let dir = std::env::temp_dir().join(format!("ss-update-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("tool.exe");
        let run = || {
            std::fs::copy(r"C:\Windows\System32\ping.exe", &exe).unwrap();
            std::process::Command::new(&exe)
                .args(["-n", "30", "127.0.0.1"])
                .stdout(std::process::Stdio::null())
                .spawn()
                .unwrap()
        };
        let names = || {
            let mut left: Vec<String> =
                std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
            left.sort();
            left
        };
        let mut first = run();
        // Control: a running image cannot be overwritten where it is.
        assert!(std::fs::write(&exe, b"x").is_err());
        let replaced = replace_exe(&exe, b"new build");
        let mut second = run();
        let replaced_again = replace_exe(&exe, b"newer build");
        let left = names();
        for child in [&mut first, &mut second] {
            let _ = child.kill();
            let _ = child.wait();
        }
        replaced.unwrap();
        replaced_again.unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"newer build");
        assert_eq!(left, ["tool.exe", "tool.old-2.exe", "tool.old.exe"]);

        // A later start removes exactly the names an update gives.
        std::fs::write(dir.join("tool.older.exe"), b"").unwrap();
        for old in replaced_names(&exe) {
            let _ = std::fs::remove_file(old);
        }
        assert_eq!(names(), ["tool.exe", "tool.older.exe"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

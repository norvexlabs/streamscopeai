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
/// x86_64, macOS Apple Silicon and Windows x86_64; other platforms get a clear
/// error.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SELF_TARGET: Option<&str> = Some("linux-x86_64");
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const SELF_TARGET: Option<&str> = Some("darwin-arm64");
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
const SELF_TARGET: Option<&str> = Some("windows-x86_64");
#[cfg(not(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64"),
    all(target_os = "windows", target_arch = "x86_64")
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
             Windows x86_64)"
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

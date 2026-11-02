//! Finding a client's program on PATH, as the platform's shell does.

use std::path::{Path, PathBuf};

/// The file `bin` runs as: the first PATH folder holding an executable under
/// one of its [`file_names`].
pub fn find(bin: &str) -> Option<PathBuf> {
    find_on(bin, None, None)
}

/// [`find`] with the `path` and `pathext` a launch sets for its child, each
/// when given, else this process's own.
pub fn find_on(bin: &str, path: Option<&std::ffi::OsStr>, pathext: Option<&str>) -> Option<PathBuf> {
    let path = path.map(std::ffi::OsString::from).or_else(|| std::env::var_os("PATH"))?;
    let own = std::env::var("PATHEXT").ok();
    find_in(bin, &path, pathext.or(own.as_deref()))
}

/// The extensions a launch can start: an `.exe`/`.com` directly, a `.bat`/
/// `.cmd` through `cmd.exe` (which Rust's process API does on its own). A
/// `PATHEXT` entry outside them (`.JS`, `.PY`, …) runs only through a shell's
/// file association.
const LAUNCHABLE: [&str; 4] = [".com", ".exe", ".bat", ".cmd"];

/// [`find`] for a PATH value and a `PATHEXT` value.
fn find_in(bin: &str, path: &std::ffi::OsStr, pathext: Option<&str>) -> Option<PathBuf> {
    // A command naming a folder is a path, used as it is — never searched for.
    if bin.contains('/') || (cfg!(windows) && bin.contains('\\')) {
        return None;
    }
    let names = file_names(bin, pathext);
    // On Windows only absolute folders: an empty or relative entry (a trailing
    // `;` is one) would name the current directory, and run what a checkout
    // holds. Elsewhere the lookup is the OS's own (`execvp` searches them all).
    std::env::split_paths(path)
        .filter(|dir| !cfg!(windows) || dir.is_absolute())
        .find_map(|dir| names.iter().map(|name| dir.join(name)).find(|p| is_executable(p)))
}

/// The file names a command `bin` may have in a PATH folder: `bin` itself on
/// Unix; on Windows `bin` with each launchable `PATHEXT` extension
/// (`claude.exe`, the `codex.cmd` an npm install puts there), in `PATHEXT`
/// order — after `bin` itself when it already names one (`codex.cmd`).
fn file_names(bin: &str, pathext: Option<&str>) -> Vec<String> {
    if !cfg!(windows) {
        return vec![bin.to_string()];
    }
    let mut exts: Vec<String> = pathext
        .unwrap_or_default()
        .split(';')
        .map(str::to_ascii_lowercase)
        .filter(|ext| LAUNCHABLE.contains(&ext.as_str()))
        .collect();
    // No launchable extension listed (unset, or only `.JS;.PY`): the defaults.
    if exts.is_empty() {
        exts = LAUNCHABLE.iter().map(|ext| ext.to_string()).collect();
    }
    let lower = bin.to_ascii_lowercase();
    let named = LAUNCHABLE.iter().any(|ext| lower.ends_with(ext));
    named.then(|| bin.to_string()).into_iter().chain(exts.iter().map(|ext| format!("{bin}{ext}"))).collect()
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(p: &Path) -> bool {
    p.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_command_is_looked_up_by_the_file_names_the_platform_gives_it() {
        if cfg!(windows) {
            assert_eq!(file_names("codex", Some(".EXE;.CMD;")), ["codex.exe", "codex.cmd"]);
            assert_eq!(file_names("codex", None), ["codex.com", "codex.exe", "codex.bat", "codex.cmd"]);
            // An extension no process starts from is never tried.
            assert_eq!(file_names("aider", Some(".EXE;.JS;.PY;.CMD")), ["aider.exe", "aider.cmd"]);
            assert_eq!(file_names("aider", Some(".JS;.PY")), ["aider.com", "aider.exe", "aider.bat", "aider.cmd"]);
            // A name already carrying an extension is tried as given first.
            assert_eq!(file_names("codex.CMD", Some(".EXE;.CMD")), ["codex.CMD", "codex.CMD.exe", "codex.CMD.cmd"]);
            // …even when PATHEXT does not list its extension.
            assert_eq!(file_names("codex.exe", Some(".CMD")), ["codex.exe", "codex.exe.cmd"]);
        } else {
            assert_eq!(file_names("codex", Some(".EXE")), ["codex"]);
        }
    }

    /// An npm-installed client is a `.cmd` beside no `.exe`: found by its bare
    /// name on Windows, and only under its exact name elsewhere.
    #[test]
    fn a_command_resolves_to_the_file_on_path() {
        let dir = std::env::temp_dir().join(format!("ss-program-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join(if cfg!(windows) { "sstool.cmd" } else { "sstool" });
        std::fs::write(&file, "").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let path = std::env::join_paths([dir.join("empty"), dir.clone()]).unwrap();
        assert_eq!(find_in("sstool", &path, None), Some(file.clone()));
        assert_eq!(find_in("sstool-not-there", &path, None), None);
        // On Windows a relative PATH entry is never searched, though it names
        // the folder holding the tool from here (control: the file is there).
        let normal = |p: &Path| -> PathBuf {
            p.components().filter(|c| matches!(c, std::path::Component::Normal(_))).collect()
        };
        // Only where the temp folder is on the working directory's drive can a
        // relative path reach it.
        fn drive(p: &Path) -> Option<std::path::Component<'_>> {
            p.components().next().filter(|c| matches!(c, std::path::Component::Prefix(_)))
        }
        if drive(&std::env::current_dir().unwrap()) != drive(&dir) {
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        let up: PathBuf = normal(&std::env::current_dir().unwrap()).components().map(|_| "..").collect();
        let relative_dir = up.join(normal(&dir));
        assert!(is_executable(&relative_dir.join(file.file_name().unwrap())), "{}", relative_dir.display());
        let relative = std::env::join_paths([relative_dir, PathBuf::new()]).unwrap();
        let found = find_in("sstool", &relative, None);
        if cfg!(windows) {
            assert_eq!(found, None);
        } else {
            assert!(found.is_some(), "as execvp finds it");
        }
        // A command naming a folder is a path: never searched for on PATH.
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        assert_eq!(find_in("sub/sstool", &std::env::join_paths([dir.parent().unwrap()]).unwrap(), None), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

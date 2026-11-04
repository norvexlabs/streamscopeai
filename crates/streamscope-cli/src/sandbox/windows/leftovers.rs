//! What the sandbox account left behind a run: its scheduled tasks (which
//! the Task Scheduler starts later, outside the run's job) and its processes
//! that outlived the job (one a service started on its behalf). Both still
//! run as the account, so the firewall rule and the grants confine them —
//! this is tidiness, not containment: nothing keeps running, or starts
//! later, once the run is over.
//!
//! The account does it itself — the developer may not be allowed to end its
//! processes or delete its tasks — through a short second start of the host
//! in its cleanup mode (`ssai __sandbox-host cleanup -- <account SID>`,
//! [`super::launch::cleanup`]), at the end of each run and before the next
//! launch (which covers a run that was killed). The host reports one line
//! per item; the run reports what was left as a warning, never as a failure.
//! The decisions are pure, so they are tested on every host.

// Off Windows this module is compiled for its tests only.
#![cfg_attr(not(windows), allow(dead_code))]

/// One process on the computer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proc {
    pub pid: u32,
    pub parent: u32,
    pub name: String,
    pub sid: Option<String>,
}

/// The processes of the account `me` to end, from the cleanup process
/// `own`: every one but `own` and what descends from it (its console host).
pub fn to_end<'a>(procs: &'a [Proc], me: &str, own: u32) -> Vec<&'a Proc> {
    // `own` and its descendants, grown until no process joins: a parent id
    // can name a process that has exited, but never one that is not yet ours.
    let mut spared = vec![own];
    loop {
        let before = spared.len();
        for p in procs {
            if spared.contains(&p.parent) && !spared.contains(&p.pid) && p.sid.as_deref() == Some(me) {
                spared.push(p.pid);
            }
        }
        if spared.len() == before {
            break;
        }
    }
    procs.iter().filter(|p| p.sid.as_deref() == Some(me) && !spared.contains(&p.pid)).collect()
}

/// The script that deletes the account's scheduled tasks: the tasks whose
/// principal is this account, by SID or name, wherever they are. One line
/// per task: `ended\ttask <path>` or `left\ttask <path>: <why>`.
pub const TASKS_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$me = [Security.Principal.WindowsIdentity]::GetCurrent()
$names = @($me.User.Value, $me.Name, $me.Name.Split('\')[-1])
foreach ($t in @(Get-ScheduledTask)) {
  if ($names -contains $t.Principal.UserId) {
    $path = "$($t.TaskPath)$($t.TaskName)"
    try {
      Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false
      "ended`ttask $path"
    } catch {
      "left`ttask ${path}: $($_.Exception.Message -replace '\s+', ' ')"
    }
  }
}"#;

/// What a cleanup reported: the items it ended, and those it left (with why).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub ended: Vec<String>,
    pub left: Vec<String>,
}

impl Report {
    /// Read the host's report: `ended\t<what>` and `left\t<what>` lines; any
    /// other line (an error the host printed) counts as something left.
    pub fn parse(text: &str) -> Report {
        let mut out = Report::default();
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
            match line.split_once('\t') {
                Some(("ended", what)) => out.ended.push(what.to_string()),
                Some(("left", what)) => out.left.push(what.to_string()),
                _ => out.left.push(line.to_string()),
            }
        }
        out
    }
}

/// The developer's runs share the one sandbox account, so the cleanup —
/// which ends EVERY process of the account — runs only while no other run
/// is live: each run holds a shared lock on one file for its life; a run
/// that gets the lock exclusively is alone. At the start, the exclusive hold
/// covers the cleanup, then becomes shared (waiting out another run's
/// cleanup) before anything is launched; at the end, the run lets go and
/// cleans up only if it then gets the lock exclusively.
pub struct RunHold(std::fs::File);

impl RunHold {
    /// Open the lock at `path`; `true` when this run is alone, holding it
    /// exclusively until [`RunHold::share`].
    pub fn open(path: &std::path::Path) -> std::io::Result<(RunHold, bool)> {
        let file = std::fs::OpenOptions::new().create(true).truncate(false).read(true).write(true).open(path)?;
        let alone = match file.try_lock() {
            Ok(()) => true,
            Err(std::fs::TryLockError::WouldBlock) => false,
            Err(std::fs::TryLockError::Error(e)) => return Err(e),
        };
        Ok((RunHold(file), alone))
    }

    /// Hold the lock shared for the run's life. `alone`: what
    /// [`RunHold::open`] returned. Blocks while another run cleans up.
    pub fn share(&self, alone: bool) -> std::io::Result<()> {
        if alone {
            self.0.unlock()?;
        }
        self.0.lock_shared()
    }

    /// Let go; whether this run is then alone (and holds the lock
    /// exclusively until dropped).
    pub fn last(&self) -> bool {
        let _ = self.0.unlock();
        self.0.try_lock().is_ok()
    }
}

/// The run's side: have the account end what it left, and warn about what
/// it could not. `when` names the moment for the warning ("before the run",
/// "after the run").
#[cfg(windows)]
pub async fn end(account: std::sync::Arc<super::launch::Account>, account_sid: String, when: &'static str) {
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
    let done = tokio::task::spawn_blocking(move || super::launch::cleanup(&account, &account_sid, TIMEOUT)).await;
    let warn = |what: String| {
        crate::ui::warn("", format_args!("the sandbox account's leftovers {when}: {what}"));
    };
    match done {
        Ok(Ok((text, clean))) => {
            let report = Report::parse(&text);
            if !report.left.is_empty() {
                warn(format!("could not end {}", report.left.join("; ")));
            } else if !clean {
                warn("the cleanup did not finish".to_string());
            }
        }
        Ok(Err(e)) => warn(format!("the cleanup could not start ({e})")),
        Err(e) => warn(format!("the cleanup failed ({e})")),
    }
}

/// The host's cleanup mode, running as the account: refuse unless this
/// process is the sandbox account `account_sid` (so a mistaken run never
/// ends the developer's own processes), then delete the account's tasks
/// (first, so none starts again) and end its processes. Prints the report;
/// exits 0 unless something could not be read.
#[cfg(windows)]
pub fn host_main(account_sid: &str) -> anyhow::Result<i32> {
    use anyhow::bail;
    let me = crate::win_acl::current_user_sid()?;
    let name = std::env::var("USERNAME").unwrap_or_default();
    if me != account_sid || !super::account::is_account_name(&name) {
        bail!("__sandbox-host cleanup runs only as the sandbox account it names");
    }
    let mut ok = true;
    match tasks() {
        Ok(text) => print!("{text}"),
        Err(e) => {
            println!("left\ttasks: {e:#}");
            ok = false;
        }
    }
    match sys::processes() {
        Ok(procs) => {
            for p in to_end(&procs, &me, std::process::id()) {
                match sys::terminate(p.pid) {
                    Ok(()) => println!("ended\tprocess {} ({})", p.name, p.pid),
                    Err(e) => println!("left\tprocess {} ({}): {e}", p.name, p.pid),
                }
            }
        }
        Err(e) => {
            println!("left\tprocesses: {e:#}");
            ok = false;
        }
    }
    Ok(if ok { 0 } else { 1 })
}

/// A script as `powershell -EncodedCommand` takes it: base64 of its UTF-16LE
/// — no quoting of the script on the command line to get wrong.
pub fn encoded(script: &str) -> String {
    use base64::Engine;
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Run [`TASKS_SCRIPT`] in Windows PowerShell; its output, UTF-8.
#[cfg(windows)]
fn tasks() -> anyhow::Result<String> {
    use anyhow::{Context, bail};
    let root = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into()));
    let ps = root.join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let out = std::process::Command::new(&ps)
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded(TASKS_SCRIPT)])
        .stdin(std::process::Stdio::null())
        .output()
        .with_context(|| format!("start {}", ps.display()))?;
    if !out.status.success() {
        bail!("list them: {}", String::from_utf8_lossy(&out.stderr).split_whitespace().collect::<Vec<_>>().join(" "));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(windows)]
mod sys {
    use anyhow::{Result, bail};
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};

    use super::Proc;

    /// Every process with its parent and name (a snapshot) and its account
    /// (the system's process list).
    pub fn processes() -> Result<Vec<Proc>> {
        let sids = super::super::peer::process_sids()?;
        // SAFETY: plain call; the snapshot is closed below.
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snap == INVALID_HANDLE_VALUE {
            bail!("snapshot the processes: {}", std::io::Error::last_os_error());
        }
        let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut out = Vec::new();
        // SAFETY: an open snapshot and an entry whose size is set.
        let mut more = unsafe { Process32FirstW(snap, &mut entry) } != 0;
        while more {
            let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
            let pid = entry.th32ProcessID;
            out.push(Proc {
                pid,
                parent: entry.th32ParentProcessID,
                name: String::from_utf16_lossy(&entry.szExeFile[..len]),
                sid: sids.iter().find(|(p, _)| *p == pid).and_then(|(_, s)| s.clone()),
            });
            // SAFETY: as above.
            more = unsafe { Process32NextW(snap, &mut entry) } != 0;
        }
        // SAFETY: the snapshot opened above, once.
        unsafe { CloseHandle(snap) };
        Ok(out)
    }

    /// End the process `pid`.
    pub fn terminate(pid: u32) -> std::io::Result<()> {
        // SAFETY: plain call; the handle is closed below.
        let handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: the handle opened above, with the right to terminate.
        let ended = unsafe { TerminateProcess(handle, 1) } != 0;
        let err = std::io::Error::last_os_error();
        // SAFETY: the handle opened above, once.
        unsafe { CloseHandle(handle) };
        if ended { Ok(()) } else { Err(err) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(pid: u32, parent: u32, sid: Option<&str>) -> Proc {
        Proc { pid, parent, name: format!("p{pid}.exe"), sid: sid.map(str::to_string) }
    }

    #[test]
    fn every_process_of_the_account_ends_but_the_cleanup_and_its_children() {
        let me = "S-1-5-21-1-2-3-1001";
        let procs = [
            p(4, 0, Some("S-1-5-18")),
            // The developer's.
            p(10, 4, Some("S-1-5-21-1-2-3-1000")),
            // The cleanup, its console host and that one's child.
            p(20, 10, Some(me)),
            p(21, 20, Some(me)),
            p(22, 21, Some(me)),
            // Left by the run: a task's process, its child, an orphan.
            p(30, 4, Some(me)),
            p(31, 30, Some(me)),
            p(40, 999, Some(me)),
            // Another's child of the cleanup is not the account's to end.
            p(50, 20, Some("S-1-5-18")),
            // No account read: not ended.
            p(60, 4, None),
        ];
        let ended: Vec<u32> = to_end(&procs, me, 20).iter().map(|p| p.pid).collect();
        assert_eq!(ended, [30, 31, 40]);
        // Nothing of the account's: nothing.
        assert!(to_end(&procs[..2], me, 20).is_empty());
    }

    #[test]
    fn only_a_run_alone_cleans_up_at_its_start_or_its_end() {
        let dir = std::env::temp_dir().join(format!("ssai-leftovers-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("run.lock");
        let (a, alone) = RunHold::open(&path).unwrap();
        assert!(alone);
        a.share(alone).unwrap();
        // A second run while the first lives: not alone, at its start or end.
        let (b, alone) = RunHold::open(&path).unwrap();
        assert!(!alone);
        b.share(alone).unwrap();
        assert!(!b.last());
        drop(b);
        // The first, now the only one: alone at its end.
        assert!(a.last());
        // Holding it exclusively, another run is not alone.
        let (c, alone) = RunHold::open(&path).unwrap();
        assert!(!alone);
        drop((a, c));
        assert!(RunHold::open(&path).unwrap().1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_encoded_script_is_base64_of_its_utf16() {
        assert_eq!(encoded("ab"), "YQBiAA==");
        assert_eq!(encoded("é"), "6QA=");
    }

    /// Windows PowerShell parses the script, passed encoded as the cleanup
    /// passes it (parsed only: running it would delete this user's tasks).
    #[cfg(windows)]
    #[test]
    fn windows_powershell_parses_the_tasks_script() {
        let check = format!(
            "$errors = $null; $null = [System.Management.Automation.Language.Parser]::ParseInput([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{}')), [ref]$null, [ref]$errors); \"errors=$($errors.Count)\"",
            {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(TASKS_SCRIPT)
            }
        );
        let out = std::process::Command::new("powershell.exe")
            .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded(&check)])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success() && text.trim() == "errors=0", "{text} {}", String::from_utf8_lossy(&out.stderr));
    }

    #[test]
    fn a_report_reads_ended_and_left_lines_and_anything_else_as_left() {
        let r = Report::parse("ended\ttask \\t1\r\nleft\ttask \\t2: Access is denied.\n\nended\tprocess a.exe (5)\nboom\n");
        assert_eq!(r.ended, ["task \\t1", "process a.exe (5)"]);
        assert_eq!(r.left, ["task \\t2: Access is denied.", "boom"]);
        assert_eq!(Report::parse(""), Report::default());
    }

    #[test]
    fn the_tasks_script_matches_the_principal_and_reports_each_task() {
        for needle in ["$me.User.Value", "$t.Principal.UserId", "Unregister-ScheduledTask", "\"ended`ttask", "\"left`ttask"] {
            assert!(TASKS_SCRIPT.contains(needle), "{needle}");
        }
        // Passed as one argument to `-Command`: no double quote may need
        // escaping beyond what the process API quotes.
        assert!(!TASKS_SCRIPT.contains('\0'));
    }
}

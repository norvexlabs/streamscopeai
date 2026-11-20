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

/// Whether a task's principal (`UserId`, as the Task Scheduler records it:
/// a SID, `COMPUTER\name` or a bare name) is the account whose SID is `sid`
/// and whose qualified name is `qualified`. Compared without case, as
/// Windows compares account names.
pub fn is_own_principal(user_id: &str, sid: &str, qualified: &str) -> bool {
    let bare = qualified.rsplit('\\').next().unwrap_or(qualified);
    [sid, qualified, bare].iter().any(|n| !n.is_empty() && n.eq_ignore_ascii_case(user_id))
}

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

/// A run lets go when it ends, explicitly: closing its handle releases the
/// lock only once no other handle to the same open file remains, and a
/// process another thread is starting holds a copy of every handle until it
/// execs — the lock would outlive the run that held it.
impl Drop for RunHold {
    fn drop(&mut self) {
        let _ = self.0.unlock();
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
    use windows_sys::Win32::System::Diagnostics::Debug::{SEM_FAILCRITICALERRORS, SEM_NOOPENFILEERRORBOX, SetErrorMode};
    // A library the loader refuses (the Task Scheduler's, which an endpoint
    // agent may deny this account) comes back as an error the report
    // carries, never as a dialog: this process has no window anyone watches,
    // and a dialog would hold it, and the run, until someone clicks.
    // SAFETY: plain call; it sets this process's error mode only.
    unsafe { SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX) };
    let me = crate::win_acl::current_user_sid()?;
    let name = std::env::var("USERNAME").unwrap_or_default();
    if me != account_sid || !super::account::is_account_name(&name) {
        bail!("__sandbox-host cleanup runs only as the sandbox account it names");
    }
    let mut ok = true;
    match tasks(&me) {
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

/// Delete the account's scheduled tasks — every task, in every folder it
/// can read, whose principal [`is_own_principal`] — through the Task
/// Scheduler's own interface, in this process. One report line per task:
/// `ended\ttask <path>` or `left\ttask <path>: <why>`. A folder or task the
/// account cannot read (a system folder, a task removed since it was
/// listed) is not its own and is passed over; only failing to reach the
/// scheduler or its root folder is an error.
#[cfg(windows)]
fn tasks(account_sid: &str) -> anyhow::Result<String> {
    use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize};
    use windows::Win32::System::TaskScheduler::{ITaskFolder, ITaskService, TASK_ENUM_HIDDEN, TaskScheduler};
    use windows::Win32::System::Variant::{VARIANT, VT_I4};
    use windows::core::BSTR;

    /// The 32-bit integer variant a collection's `Item` is indexed by.
    fn index(i: i32) -> VARIANT {
        let mut v = VARIANT::default();
        // SAFETY: a zeroed variant given its type tag and the matching member.
        unsafe {
            (*v.Anonymous.Anonymous).vt = VT_I4;
            (*v.Anonymous.Anonymous).Anonymous.lVal = i;
        }
        v
    }

    /// An error as one line of text, read while COM is still initialised
    /// (it holds the call's error object).
    fn text(e: &windows::core::Error) -> String {
        e.message().split_whitespace().collect::<Vec<_>>().join(" ")
    }

    fn walk(folder: &ITaskFolder, sid: &str, qualified: &str, out: &mut String) {
        // SAFETY: COM calls on interfaces this thread holds; collections are 1-based.
        unsafe {
            // Collected first, deleted after: a deletion renumbers the collection.
            let mut own = Vec::new();
            if let Ok(tasks) = folder.GetTasks(TASK_ENUM_HIDDEN.0) {
                for i in 1..=tasks.Count().unwrap_or(0) {
                    let Ok(task) = tasks.get_Item(&index(i)) else { continue };
                    let mut user = BSTR::new();
                    let read = task.Definition().and_then(|d| d.Principal()).and_then(|p| p.UserId(&mut user));
                    if read.is_ok()
                        && is_own_principal(&user.to_string(), sid, qualified)
                        && let (Ok(name), Ok(path)) = (task.Name(), task.Path())
                    {
                        own.push((name, path));
                    }
                }
            }
            for (name, path) in own {
                match folder.DeleteTask(&name, 0) {
                    Ok(()) => out.push_str(&format!("ended\ttask {path}\n")),
                    Err(e) => out.push_str(&format!("left\ttask {path}: {}\n", text(&e))),
                }
            }
            if let Ok(folders) = folder.GetFolders(0) {
                for i in 1..=folders.Count().unwrap_or(0) {
                    if let Ok(sub) = folders.get_Item(&index(i)) {
                        walk(&sub, sid, qualified, out);
                    }
                }
            }
        }
    }

    let qualified = format!("{}\\{}", std::env::var("USERDOMAIN").unwrap_or_default(), std::env::var("USERNAME").unwrap_or_default());
    // SAFETY: COM initialised for this thread and uninitialised once every
    // interface and error object is released: the closure returns only text.
    unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.ok().map_err(|e| anyhow::anyhow!("start COM: {}", text(&e)))?;
    let result = (|| -> Result<String, String> {
        // SAFETY: COM calls on this thread's apartment.
        unsafe {
            let service: ITaskService =
                CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER).map_err(|e| format!("reach the Task Scheduler: {}", text(&e)))?;
            let none = VARIANT::default();
            service.Connect(&none, &none, &none, &none).map_err(|e| format!("connect to the Task Scheduler: {}", text(&e)))?;
            let root = service.GetFolder(&BSTR::from("\\")).map_err(|e| format!("open its root folder: {}", text(&e)))?;
            let mut out = String::new();
            walk(&root, account_sid, &qualified, &mut out);
            Ok(out)
        }
    })();
    // SAFETY: paired with the initialisation above.
    unsafe { CoUninitialize() };
    result.map_err(|e| anyhow::anyhow!("list them: {e}"))
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
        // A second handle to the first run's file (what a process another
        // thread starts holds until it execs) outlives the run: the run's end
        // still lets go.
        let copy = a.0.try_clone().unwrap();
        drop((a, c));
        assert!(RunHold::open(&path).unwrap().1);
        drop(copy);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_task_is_the_accounts_by_its_sid_or_either_name_whatever_the_case() {
        let (sid, qualified) = ("S-1-5-21-1-2-3-1005", "WIN-DEV\\ssai-sbx-e9a8bb");
        for own in ["S-1-5-21-1-2-3-1005", "WIN-DEV\\ssai-sbx-e9a8bb", "win-dev\\SSAI-SBX-E9A8BB", "ssai-sbx-e9a8bb"] {
            assert!(is_own_principal(own, sid, qualified), "{own}");
        }
        // Another account's, the developer's, a system principal, none.
        for other in ["S-1-5-21-1-2-3-1000", "WIN-DEV\\lab", "lab", "SYSTEM", "S-1-5-18", "", "ssai-sbx-e9a8b"] {
            assert!(!is_own_principal(other, sid, qualified), "{other}");
        }
        // An unknown name never matches an empty principal.
        assert!(!is_own_principal("", sid, ""));
    }

    #[test]
    fn a_report_reads_ended_and_left_lines_and_anything_else_as_left() {
        let r = Report::parse("ended\ttask \\t1\r\nleft\ttask \\t2: Access is denied.\n\nended\tprocess a.exe (5)\nboom\n");
        assert_eq!(r.ended, ["task \\t1", "process a.exe (5)"]);
        assert_eq!(r.left, ["task \\t2: Access is denied.", "boom"]);
        assert_eq!(Report::parse(""), Report::default());
    }

}

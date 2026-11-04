//! Start a client as the sandbox account: the Windows stand-in for the part
//! of `tokio::process::Command` / `Child` the sandbox's launch uses.
//!
//! What starts is the host (`ssai __sandbox-host`, [`super::host`]), signed
//! in as the account with its profile loaded, on a hidden console of its
//! own, started suspended and resumed only once it is in a job that ends it
//! and everything it started when the job's handle closes — when the
//! [`Child`] is dropped, killed, or this process dies. Its standard input is
//! the control stream ([`super::frame`]); its exit code is the client's.
//!
//! - **Console mode** (standard input and output both the developer's
//!   console): the console is put in raw VT mode and UTF-8 for the run and
//!   restored after it, keystrokes travel as `Data`, size changes as
//!   `Resize`, and the host's output — the client's screen — is copied to
//!   the console as bytes.
//! - **Pipes mode** (anything else): each stream is relayed, captured, a
//!   file or `NUL`; a console on standard input is read line by line, as
//!   the console edits them, Ctrl-Z ending the input; Ctrl-C on this
//!   console becomes `Interrupt` for every live child whose input is
//!   relayed. The handler that does it is the console's first one only
//!   while no later handler (`tokio::signal`) takes the event before it.
//!
//! A process started as another account inherits this one's window station
//! and desktop and must be allowed to open them, or it ends before its
//! first line: the account is admitted to both before the first start.

use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::mem::ManuallyDrop;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::os::windows::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Output};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Once, mpsc};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GRANT_ACCESS, GetSecurityInfo, SE_WINDOW_OBJECT, SetEntriesInAclW, SetSecurityInfo,
};
use windows_sys::Win32::Security::{ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
use windows_sys::Win32::System::Console::{
    CONSOLE_MODE, CONSOLE_READCONSOLE_CONTROL, CONSOLE_SCREEN_BUFFER_INFO, CTRL_C_EVENT, DISABLE_NEWLINE_AUTO_RETURN, ENABLE_ECHO_INPUT,
    ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, ENABLE_PROCESSED_OUTPUT, ENABLE_VIRTUAL_TERMINAL_INPUT,
    ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleCP, GetConsoleMode, GetConsoleOutputCP, GetConsoleScreenBufferInfo,
    GetStdHandle, ReadConsoleW, STD_ERROR_HANDLE, STD_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetConsoleCP,
    SetConsoleCtrlHandler, SetConsoleMode, SetConsoleOutputCP,
};
use windows_sys::Win32::System::IO::CancelSynchronousIo;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::StationsAndDesktops::{GetProcessWindowStation, GetThreadDesktop};
use windows_sys::Win32::System::Threading::{
    CREATE_NEW_CONSOLE, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessWithLogonW, GetCurrentProcess,
    GetCurrentThreadId, GetExitCodeProcess, INFINITE, LOGON_WITH_PROFILE, PROCESS_INFORMATION, ResumeThread, STARTF_USESHOWWINDOW,
    STARTF_USESTDHANDLES, STARTUPINFOW, TerminateProcess, WaitForSingleObject,
};

use super::cmdline;
use super::frame::{self, Frame};
use super::launch_env;
use super::setup::Sid;

/// The sandbox account a launch signs in as (from `setup::Ready`).
pub struct Account {
    pub name: String,
    /// Its SID string, for the window station and desktop entries.
    pub sid: String,
    pub password: String,
}

/// Where one of the host's standard streams goes.
pub enum Io {
    /// The developer's own stream, relayed.
    Relay,
    /// `NUL`.
    Null,
    /// This file.
    File(std::fs::File),
    /// Collected, for [`Command::output`].
    Capture,
}

impl From<std::fs::File> for Io {
    fn from(file: std::fs::File) -> Self {
        Io::File(file)
    }
}

/// A command to run as the sandbox account.
pub struct Command {
    account: Arc<Account>,
    program: String,
    args: Vec<String>,
    cwd: Option<PathBuf>,
    env: Vec<(String, String)>,
    stdin: Option<Io>,
    stdout: Option<Io>,
    stderr: Option<Io>,
}

impl Command {
    pub fn new(account: Arc<Account>, program: impl Into<String>) -> Self {
        Command {
            account,
            program: program.into(),
            args: Vec::new(),
            cwd: None,
            env: Vec::new(),
            stdin: None,
            stdout: None,
            stderr: None,
        }
    }

    pub fn args<I: IntoIterator<Item = S>, S: Into<String>>(&mut self, args: I) -> &mut Self {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    #[allow(dead_code, reason = "parity with tokio::process::Command")]
    pub fn arg(&mut self, arg: impl Into<String>) -> &mut Self {
        self.args.push(arg.into());
        self
    }

    pub fn current_dir(&mut self, dir: impl Into<PathBuf>) -> &mut Self {
        self.cwd = Some(dir.into());
        self
    }

    pub fn env(&mut self, key: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.env.push((key.into(), value.into()));
        self
    }

    pub fn stdin(&mut self, io: impl Into<Io>) -> &mut Self {
        self.stdin = Some(io.into());
        self
    }

    pub fn stdout(&mut self, io: impl Into<Io>) -> &mut Self {
        self.stdout = Some(io.into());
        self
    }

    pub fn stderr(&mut self, io: impl Into<Io>) -> &mut Self {
        self.stderr = Some(io.into());
        self
    }

    /// The job ends every process of the run when the [`Child`] drops,
    /// always; kept for parity with `tokio::process::Command`.
    pub fn kill_on_drop(&mut self, _: bool) -> &mut Self {
        self
    }

    pub fn spawn(&mut self) -> io::Result<Child> {
        let (stdin, stdout, stderr) = (own(&self.stdin)?, own(&self.stdout)?, own(&self.stderr)?);
        self.spawn_with(stdin, stdout, stderr)
    }

    pub async fn status(&mut self) -> io::Result<ExitStatus> {
        self.spawn()?.wait().await
    }

    /// Run to the end with no input, collecting both outputs.
    pub async fn output(&mut self) -> io::Result<Output> {
        let stdin = match &self.stdin {
            None => Io::Null,
            some => own(some)?,
        };
        let mut child = self.spawn_with(stdin, Io::Capture, Io::Capture)?;
        let status = child.wait().await?;
        let (stdout, stderr) = std::mem::take(&mut child.captured);
        Ok(Output { status, stdout, stderr })
    }

    fn spawn_with(&self, stdin: Io, stdout: Io, stderr: Io) -> io::Result<Child> {
        if matches!(stdin, Io::Capture) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "a sandboxed command's input cannot be captured"));
        }
        let cwd = match &self.cwd {
            Some(dir) => dir.clone(),
            None => std::env::current_dir()?,
        };
        let program = self.resolve(&cwd)?;
        let console = matches!(stdin, Io::Relay)
            && matches!(stdout, Io::Relay)
            && is_console(STD_INPUT_HANDLE)
            && is_console(STD_OUTPUT_HANDLE);
        let mode = if console {
            let (cols, rows) = window_size().unwrap_or((80, 25));
            format!("console:{cols}x{rows}")
        } else {
            "pipes".to_string()
        };
        let exe = std::env::current_exe()?;
        let line = [utf8(&exe)?, "__sandbox-host", &mode, "--", utf8(&program)?]
            .into_iter()
            .chain(self.args.iter().map(String::as_str))
            .map(cmdline::quote)
            .collect::<Vec<_>>()
            .join(" ");
        let defaults = account_defaults(&self.account)?;
        let env = launch_env::environment(defaults, &|name| std::env::var(name).ok(), &self.env);
        let block = launch_env::block(&env)?;

        // The host's three standard handles, and this process's ends of them.
        let (host_in, frames_out) = pipe()?;
        let (host_out, out_relay) = output_end(stdout)?;
        let (host_err, err_relay) = output_end(stderr)?;
        // Raw mode before the start, so the first keystroke is already raw;
        // restored when `modes` drops, on every path.
        let modes = if console { Some(ConsoleModes::enter()?) } else { None };
        let started = start(&self.account, &line, Some(&block), &cwd, [&host_in, &host_out, &host_err])?;
        // The host holds its own copies now.
        drop((host_in, host_out, host_err));

        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel::<Frame>();
        // SAFETY: the write end this thread now owns, closed with the file.
        let mut control = unsafe { std::fs::File::from_raw_handle(ManuallyDrop::new(frames_out).0) };
        std::thread::spawn(move || {
            for f in rx {
                if f.write_to(&mut control).is_err() {
                    break;
                }
            }
        });

        let mut input = Input { stop: stop.clone(), readers: Vec::new(), interrupt: None };
        if console {
            input.readers.push(spawn_named("ssai-console-input", {
                let (tx, stop) = (tx.clone(), stop.clone());
                move || console_input(&tx, &stop, false)
            })?);
            spawn_named("ssai-console-resize", {
                let (tx, stop) = (tx.clone(), stop.clone());
                move || watch_size(&tx, &stop)
            })?;
        } else {
            match stdin {
                Io::Relay => {
                    input.interrupt = Some(register_interrupt(tx.clone()));
                    let tx = tx.clone();
                    input.readers.push(if is_console(STD_INPUT_HANDLE) {
                        let stop = stop.clone();
                        spawn_named("ssai-stdin", move || console_input(&tx, &stop, true))?
                    } else {
                        spawn_named("ssai-stdin", move || relay_stdin(&tx))?
                    });
                }
                Io::File(file) => {
                    input.readers.push(spawn_named("ssai-stdin-file", {
                        let tx = tx.clone();
                        move || send_all(&tx, file)
                    })?);
                }
                Io::Null | Io::Capture => {
                    let _ = tx.send(Frame::Eof);
                }
            }
        }
        drop(tx);

        let (done_tx, done) = mpsc::channel();
        let mut relays = Relays { done, count: 0, out: None, err: None };
        for (end, which) in [(out_relay, Stream::Out), (err_relay, Stream::Err)] {
            let Some((pipe, kind)) = end else { continue };
            let sink = match kind {
                RelayKind::Capture => {
                    let buf = Arc::new(Mutex::new(Vec::new()));
                    match which {
                        Stream::Out => relays.out = Some(buf.clone()),
                        Stream::Err => relays.err = Some(buf.clone()),
                    }
                    Sink::Capture(buf)
                }
                RelayKind::Relay => Sink::developer(which, console),
            };
            let done_tx = done_tx.clone();
            spawn_named("ssai-relay", move || {
                copy(pipe, sink);
                let _ = done_tx.send(());
            })?;
            relays.count += 1;
        }

        Ok(Child {
            pid: started.pid,
            process: started.process,
            job: Some(started.job),
            finish: Some(Finish { input, relays, modes }),
            status: None,
            captured: Default::default(),
        })
    }

    /// The program as an absolute path: looked up on the `PATH` and
    /// `PATHEXT` the host is given (an npm client is a `.cmd`), a path
    /// taken relative to the working directory.
    fn resolve(&self, cwd: &Path) -> io::Result<PathBuf> {
        let given = |name: &str| self.env.iter().rev().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone());
        let (path, pathext) = (given("PATH"), given("PATHEXT"));
        if let Some(found) = crate::program::find_on(&self.program, path.as_deref().map(OsStr::new), pathext.as_deref()) {
            return Ok(found);
        }
        let named = Path::new(&self.program);
        if named.components().count() > 1 || named.is_absolute() {
            let full = if named.is_absolute() { named.to_path_buf() } else { cwd.join(named) };
            if full.is_file() {
                return Ok(full);
            }
        }
        Err(io::Error::new(io::ErrorKind::NotFound, format!("{} was not found on the PATH the sandbox is given", self.program)))
    }
}

/// A started host.
pub struct Child {
    pid: u32,
    process: Arc<Handle>,
    job: Option<Handle>,
    finish: Option<Finish>,
    status: Option<ExitStatus>,
    captured: (Vec<u8>, Vec<u8>),
}

impl Child {
    /// The host's process id, until it has been waited for.
    #[allow(dead_code, reason = "parity with tokio::process::Child")]
    pub fn id(&self) -> Option<u32> {
        self.status.is_none().then_some(self.pid)
    }

    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        if let Some(status) = self.status {
            return Ok(Some(status));
        }
        // SAFETY: the host's process handle, open while `self` lives.
        match unsafe { WaitForSingleObject(self.process.0, 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let status = exit_status(&self.process)?;
                self.end_job();
                if let Some(finish) = self.finish.take() {
                    self.captured = finish.run();
                }
                self.status = Some(status);
                Ok(Some(status))
            }
            _ => Err(io::Error::last_os_error()),
        }
    }

    pub async fn wait(&mut self) -> io::Result<ExitStatus> {
        if let Some(status) = self.status {
            return Ok(status);
        }
        let process = self.process.clone();
        let status = tokio::task::spawn_blocking(move || {
            // SAFETY: the process handle, kept open by the `Arc` this
            // closure holds.
            unsafe { WaitForSingleObject(process.0, INFINITE) };
            exit_status(&process)
        })
        .await
        .map_err(io::Error::other)??;
        // What the client left running must not hold its outputs open.
        self.end_job();
        if let Some(finish) = self.finish.take() {
            self.captured = tokio::task::spawn_blocking(move || finish.run()).await.map_err(io::Error::other)?;
        }
        self.status = Some(status);
        Ok(status)
    }

    /// End the host, the client and everything they started, and wait.
    pub async fn kill(&mut self) -> io::Result<()> {
        if self.status.is_none() {
            self.end_job();
            self.wait().await?;
        }
        Ok(())
    }

    fn end_job(&self) {
        if let Some(job) = &self.job {
            // SAFETY: the run's job, open while `self` lives.
            unsafe { TerminateJobObject(job.0, 1) };
        }
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        self.end_job();
        // Closing the handle ends the job too (kill on close).
        self.job = None;
        if let Some(mut finish) = self.finish.take() {
            finish.input.stop();
            // `finish.modes` restores the console as it drops.
        }
    }
}

/// What ends with the host: the input readers, the output relays, the
/// console's modes.
struct Finish {
    input: Input,
    relays: Relays,
    modes: Option<ConsoleModes>,
}

impl Finish {
    /// After the host exited and its job ended: stop reading input, let the
    /// relays copy what is left, then give the console back. Returns the
    /// captured output and error.
    fn run(mut self) -> (Vec<u8>, Vec<u8>) {
        self.input.stop();
        let captured = self.relays.drain(Duration::from_secs(5));
        drop(self.modes);
        captured
    }
}

/// The readers feeding the control stream.
struct Input {
    stop: Arc<AtomicBool>,
    readers: Vec<std::thread::JoinHandle<()>>,
    interrupt: Option<u64>,
}

impl Input {
    /// Stop every reader, so none takes the developer's next keystroke: the
    /// flag for a reader between two reads, a cancel for one blocked in a
    /// read (repeated briefly, for one that was just entering it). No reader
    /// re-issues a read the cancel aborted — the cancel waits in the kernel
    /// for the thread's cancelled read to be over, and one that re-issued it
    /// at once (std's console reader does: it takes the abort for a Ctrl-C)
    /// would hold the cancel, and this run's end, for good.
    fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(id) = self.interrupt.take() {
            unregister_interrupt(id);
        }
        for _ in 0..10 {
            self.readers.retain(|r| !r.is_finished());
            if self.readers.is_empty() {
                break;
            }
            for r in &self.readers {
                // SAFETY: the thread's handle, open while its JoinHandle lives.
                unsafe { CancelSynchronousIo(r.as_raw_handle() as HANDLE) };
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// The output relays: each signals `done` when its pipe ends.
struct Relays {
    done: mpsc::Receiver<()>,
    count: usize,
    out: Option<Arc<Mutex<Vec<u8>>>>,
    err: Option<Arc<Mutex<Vec<u8>>>>,
}

impl Relays {
    /// Wait up to `grace` for every relay to finish (the job has ended, so
    /// every writer is gone; only a process outside it could hold a pipe),
    /// then return what was captured.
    fn drain(self, grace: Duration) -> (Vec<u8>, Vec<u8>) {
        let deadline = Instant::now() + grace;
        for _ in 0..self.count {
            if self.done.recv_timeout(deadline.saturating_duration_since(Instant::now())).is_err() {
                break;
            }
        }
        let take = |b: Option<Arc<Mutex<Vec<u8>>>>| b.map(|b| std::mem::take(&mut *b.lock().unwrap_or_else(|p| p.into_inner()))).unwrap_or_default();
        (take(self.out), take(self.err))
    }
}

#[derive(Clone, Copy)]
enum Stream {
    Out,
    Err,
}

enum RelayKind {
    Relay,
    Capture,
}

/// Where a relay writes.
enum Sink {
    /// Bytes, unchanged: a file or pipe, or the console in raw VT mode.
    Raw(STD_HANDLE),
    /// Text, to a console in its own mode: decoded from UTF-8 and written
    /// through std, which converts it for the console.
    Text(Stream, launch_env::Utf8Stream),
    Capture(Arc<Mutex<Vec<u8>>>),
}

impl Sink {
    fn developer(which: Stream, console_mode: bool) -> Sink {
        let std = match which {
            Stream::Out => STD_OUTPUT_HANDLE,
            Stream::Err => STD_ERROR_HANDLE,
        };
        if console_mode || !is_console(std) { Sink::Raw(std) } else { Sink::Text(which, Default::default()) }
    }

    fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self {
            Sink::Raw(std) => {
                // SAFETY: plain call; the standard handle stays open for the
                // process's life and is never closed through this file.
                let mut to = ManuallyDrop::new(unsafe { std::fs::File::from_raw_handle(GetStdHandle(*std)) });
                to.write_all(bytes).and_then(|()| to.flush())
            }
            Sink::Text(which, decoder) => {
                let text = decoder.push(bytes);
                match which {
                    Stream::Out => {
                        let mut out = io::stdout().lock();
                        out.write_all(text.as_bytes()).and_then(|()| out.flush())
                    }
                    Stream::Err => io::stderr().lock().write_all(text.as_bytes()),
                }
            }
            Sink::Capture(buf) => {
                buf.lock().unwrap_or_else(|p| p.into_inner()).extend_from_slice(bytes);
                Ok(())
            }
        }
    }
}

/// Copy `from` into `to` until it ends. A sink that fails stops being
/// written, but the pipe is still read to its end, so the writer never
/// blocks on a full pipe.
fn copy(from: Handle, mut to: Sink) {
    // SAFETY: the read end this relay owns, closed with the file.
    let mut from = unsafe { std::fs::File::from_raw_handle(ManuallyDrop::new(from).0) };
    let mut buf = vec![0u8; 16 * 1024];
    let mut writing = true;
    while let Ok(n) = from.read(&mut buf) {
        if n == 0 {
            break;
        }
        if writing && to.write(&buf[..n]).is_err() {
            writing = false;
        }
    }
}

/// The developer's input — a pipe or a file, never a console — as frames,
/// then the end of input.
fn relay_stdin(tx: &mpsc::Sender<Frame>) {
    let mut buf = vec![0u8; frame::MAX_PAYLOAD];
    // SAFETY: plain call; the standard handle stays open for the process's
    // life and is never closed through this file.
    let mut raw = ManuallyDrop::new(unsafe { std::fs::File::from_raw_handle(GetStdHandle(STD_INPUT_HANDLE)) });
    loop {
        match raw.read(&mut buf) {
            Ok(0) => {
                let _ = tx.send(Frame::Eof);
                return;
            }
            Ok(n) => {
                if tx.send(Frame::Data(buf[..n].to_vec())).is_err() {
                    return;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            // Cancelled (the run is over) or broken: the input ends.
            Err(_) => {
                let _ = tx.send(Frame::Eof);
                return;
            }
        }
    }
}

/// A file given as input, as frames, then the end of input.
fn send_all(tx: &mpsc::Sender<Frame>, mut file: std::fs::File) {
    let mut buf = vec![0u8; frame::MAX_PAYLOAD];
    while let Ok(n) = file.read(&mut buf) {
        if n == 0 || tx.send(Frame::Data(buf[..n].to_vec())).is_err() {
            break;
        }
    }
    let _ = tx.send(Frame::Eof);
}

/// The console's input as frames: keystrokes in raw mode (`cooked` false,
/// the console-mode run), lines as the console edits them in cooked mode
/// (`cooked` true, pipes mode with a console on standard input), where
/// Ctrl-Z ends the input, as std's reader has it. Read with `ReadConsoleW`
/// itself, never through std's reader, which re-issues a read a cancel
/// aborted (it takes the abort for a Ctrl-C) — see [`Input::stop`] — and
/// turns Ctrl-Z into the end of input in raw mode too; a wait first, so the
/// stop flag is seen between reads. A read a cancel or a Ctrl-C aborted
/// returns no characters; the flag then ends the loop, or the next read
/// begins.
fn console_input(tx: &mpsc::Sender<Frame>, stop: &AtomicBool, cooked: bool) {
    const CTRL_Z: u16 = 0x1A;
    // SAFETY: plain call.
    let input = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let mut buf = [0u16; 4096];
    let mut decoder = launch_env::Utf16Stream::default();
    // Cooked: a Ctrl-Z ends the read at once (the wake-up mask), not with
    // the line it is typed on.
    let control = CONSOLE_READCONSOLE_CONTROL {
        nLength: std::mem::size_of::<CONSOLE_READCONSOLE_CONTROL>() as u32,
        nInitialChars: 0,
        dwCtrlWakeupMask: 1 << CTRL_Z,
        dwControlKeyState: 0,
    };
    while !stop.load(Ordering::SeqCst) {
        // SAFETY: the console input handle, open for the process's life.
        match unsafe { WaitForSingleObject(input, 100) } {
            WAIT_OBJECT_0 => {}
            WAIT_TIMEOUT => continue,
            _ => return,
        }
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let mut n = 0u32;
        // SAFETY: `buf` holds `buf.len()` units; `n` receives the count;
        // `control` outlives the call.
        let ok = unsafe {
            ReadConsoleW(input, buf.as_mut_ptr().cast(), buf.len() as u32, &mut n, if cooked { &control } else { std::ptr::null() })
        };
        // The console is gone: in cooked mode the client's input ends with it.
        if ok == 0 {
            if cooked {
                let _ = tx.send(Frame::Eof);
            }
            return;
        }
        let units = &buf[..n as usize];
        let (units, eof) = match units.iter().position(|&u| u == CTRL_Z) {
            Some(at) if cooked => (&units[..at], true),
            _ => (units, false),
        };
        let text = decoder.push(units);
        if !text.is_empty() && tx.send(Frame::Data(text.into_bytes())).is_err() {
            return;
        }
        if eof {
            let _ = tx.send(Frame::Eof);
            return;
        }
    }
}

/// A `Resize` frame whenever the console's visible window changes size.
fn watch_size(tx: &mpsc::Sender<Frame>, stop: &AtomicBool) {
    let mut last = window_size();
    while !stop.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(200));
        let now = window_size();
        if let Some((cols, rows)) = now
            && now != last
        {
            last = now;
            if tx.send(Frame::Resize { cols, rows }).is_err() {
                return;
            }
        }
    }
}

/// The console's visible window, in columns and rows.
fn window_size() -> Option<(u16, u16)> {
    // SAFETY: zeroed plain data the call fills.
    let mut info: CONSOLE_SCREEN_BUFFER_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: plain calls; `info` receives the buffer's description.
    if unsafe { GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &mut info) } == 0 {
        return None;
    }
    let w = info.srWindow;
    let cols = u16::try_from(i32::from(w.Right) - i32::from(w.Left) + 1).ok()?;
    let rows = u16::try_from(i32::from(w.Bottom) - i32::from(w.Top) + 1).ok()?;
    Some((cols.max(1), rows.max(1)))
}

fn is_console(std: STD_HANDLE) -> bool {
    let mut mode: CONSOLE_MODE = 0;
    // SAFETY: plain calls; `mode` receives the console's mode.
    unsafe { GetConsoleMode(GetStdHandle(std), &mut mode) != 0 }
}

/// The developer's console as it was before a console-mode run, put back
/// when this drops.
struct ConsoleModes {
    input: CONSOLE_MODE,
    output: CONSOLE_MODE,
    input_cp: u32,
    output_cp: u32,
}

impl ConsoleModes {
    /// Raw VT input (no line editing, echo or Ctrl-C processing), VT output
    /// without the automatic carriage return, UTF-8 both ways.
    fn enter() -> io::Result<ConsoleModes> {
        let (mut input, mut output): (CONSOLE_MODE, CONSOLE_MODE) = (0, 0);
        // SAFETY: plain calls; the modes are read into the two locals.
        let saved = unsafe {
            GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mut input) != 0
                && GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &mut output) != 0
        };
        if !saved {
            return Err(io::Error::other(format!("read the console's mode: {}", io::Error::last_os_error())));
        }
        // SAFETY: plain calls.
        let modes = ConsoleModes { input, output, input_cp: unsafe { GetConsoleCP() }, output_cp: unsafe { GetConsoleOutputCP() } };
        let raw_in = (input & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT)) | ENABLE_VIRTUAL_TERMINAL_INPUT;
        let raw_out = output | ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN;
        // SAFETY: plain calls. A failure leaves `modes` to put back what
        // changed as it drops.
        let ok = unsafe {
            SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), raw_in) != 0
                && SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), raw_out) != 0
                && SetConsoleCP(65001) != 0
                && SetConsoleOutputCP(65001) != 0
        };
        if !ok {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "this console cannot be put in virtual terminal mode ({}) — run the client from Windows Terminal \
                     or a current Windows console",
                    io::Error::last_os_error()
                ),
            ));
        }
        Ok(modes)
    }
}

impl Drop for ConsoleModes {
    fn drop(&mut self) {
        // SAFETY: plain calls putting back what `enter` read.
        unsafe {
            SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), self.input);
            SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), self.output);
            SetConsoleCP(self.input_cp);
            SetConsoleOutputCP(self.output_cp);
        }
    }
}

/// Live children whose input is relayed: Ctrl-C on this console is sent to
/// each of them as `Interrupt`.
static INTERRUPTS: Mutex<Vec<(u64, mpsc::Sender<Frame>)>> = Mutex::new(Vec::new());
static NEXT_INTERRUPT: AtomicU64 = AtomicU64::new(0);
static HANDLER: Once = Once::new();

fn register_interrupt(tx: mpsc::Sender<Frame>) -> u64 {
    HANDLER.call_once(|| {
        // SAFETY: a handler with the signature the call expects, never removed.
        unsafe { SetConsoleCtrlHandler(Some(on_ctrl), 1) };
    });
    let id = NEXT_INTERRUPT.fetch_add(1, Ordering::SeqCst);
    INTERRUPTS.lock().unwrap_or_else(|p| p.into_inner()).push((id, tx));
    id
}

fn unregister_interrupt(id: u64) {
    INTERRUPTS.lock().unwrap_or_else(|p| p.into_inner()).retain(|(i, _)| *i != id);
}

/// Ctrl-C while a child's input is relayed is that child's, and this
/// process takes no action on it; otherwise the next handler (the default
/// one ends the process) decides.
unsafe extern "system" fn on_ctrl(event: u32) -> windows_sys::core::BOOL {
    if event != CTRL_C_EVENT {
        return 0;
    }
    let list = INTERRUPTS.lock().unwrap_or_else(|p| p.into_inner());
    if list.is_empty() {
        return 0;
    }
    for (_, tx) in list.iter() {
        let _ = tx.send(Frame::Interrupt);
    }
    1
}

/// An owned kernel handle, closed when dropped.
struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: a handle this module opened, closed once.
            unsafe { CloseHandle(self.0) };
        }
    }
}

// SAFETY: a kernel handle may be used from any thread.
unsafe impl Send for Handle {}
// SAFETY: as above; every use is a kernel call that is thread-safe.
unsafe impl Sync for Handle {}

/// A pipe: (read end, write end), neither inheritable.
fn pipe() -> io::Result<(Handle, Handle)> {
    let (mut read, mut write): (HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut());
    // SAFETY: out-pointers to two handles; default (non-inheritable) security.
    if unsafe { CreatePipe(&mut read, &mut write, std::ptr::null(), 0) } == 0 {
        return Err(io::Error::other(format!("create a pipe: {}", io::Error::last_os_error())));
    }
    Ok((Handle(read), Handle(write)))
}

/// A copy of `h`, of this process's own, for the host to receive.
fn duplicate(h: HANDLE, inheritable: bool) -> io::Result<Handle> {
    let mut out: HANDLE = std::ptr::null_mut();
    // SAFETY: `h` is open; `out` receives the copy.
    let ok = unsafe { DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &mut out, 0, i32::from(inheritable), DUPLICATE_SAME_ACCESS) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Handle(out))
}

/// The host's end of an output stream, and this process's relay of it (none
/// for `NUL` or a file).
fn output_end(io: Io) -> io::Result<(Handle, Option<(Handle, RelayKind)>)> {
    Ok(match io {
        Io::Relay => {
            let (read, write) = pipe()?;
            (write, Some((read, RelayKind::Relay)))
        }
        Io::Capture => {
            let (read, write) = pipe()?;
            (write, Some((read, RelayKind::Capture)))
        }
        Io::Null => (null_device()?, None),
        Io::File(file) => (duplicate(file.as_raw_handle() as HANDLE, false)?, None),
    })
}

fn null_device() -> io::Result<Handle> {
    let file = std::fs::OpenOptions::new().read(true).write(true).open("NUL")?;
    duplicate(file.as_raw_handle() as HANDLE, false)
}

/// The command's stream, as one this spawn owns (a file is duplicated, so
/// the command can be spawned again).
fn own(io: &Option<Io>) -> io::Result<Io> {
    Ok(match io {
        None | Some(Io::Relay) => Io::Relay,
        Some(Io::Null) => Io::Null,
        Some(Io::Capture) => Io::Capture,
        Some(Io::File(f)) => Io::File(f.try_clone()?),
    })
}

fn utf8(path: &Path) -> io::Result<&str> {
    path.to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("{} is not valid Unicode", path.display())))
}

fn spawn_named<T: Send + 'static>(name: &str, f: impl FnOnce() -> T + Send + 'static) -> io::Result<std::thread::JoinHandle<T>> {
    std::thread::Builder::new().name(name.to_string()).spawn(f)
}

fn exit_status(process: &Handle) -> io::Result<ExitStatus> {
    let mut code = 0u32;
    // SAFETY: an open process handle; `code` receives its exit code.
    if unsafe { GetExitCodeProcess(process.0, &mut code) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ExitStatus::from_raw(code))
}

/// A process started as the account, in its job and running.
struct Started {
    pid: u32,
    process: Arc<Handle>,
    job: Handle,
}

/// One start at a time: the standard handles a start hands on are
/// inheritable from their copy to their close, and no other start of this
/// module may take them along.
static START: Mutex<()> = Mutex::new(());

/// Start `line` as `account` (domain `.`, its profile loaded) on a hidden
/// console of its own, with `env` (the account's own when `None`), in `cwd`,
/// with `stdio` as its standard handles; suspended until it is in a new
/// kill-on-close job.
fn start(account: &Account, line: &str, env: Option<&[u16]>, cwd: &Path, stdio: [&Handle; 3]) -> io::Result<Started> {
    admit_to_station(account)?;
    let job = new_job()?;
    let wide = |s: &OsStr| s.encode_wide().chain(std::iter::once(0)).collect::<Vec<u16>>();
    let (name, domain) = (wide(OsStr::new(&account.name)), wide(OsStr::new(".")));
    let mut password = wide(OsStr::new(&account.password));
    let mut line = wide(OsStr::new(line));
    let dir = wide(cwd.as_os_str());

    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let result = {
        let _one = START.lock().unwrap_or_else(|p| p.into_inner());
        // Inheritable copies, only for this call; closed right after it.
        let handed = [duplicate(stdio[0].0, true)?, duplicate(stdio[1].0, true)?, duplicate(stdio[2].0, true)?];
        // SAFETY: zeroed plain data, filled below.
        let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.wShowWindow = 0; // SW_HIDE
        si.hStdInput = handed[0].0;
        si.hStdOutput = handed[1].0;
        si.hStdError = handed[2].0;
        // SAFETY: NUL-terminated strings that outlive the call (the command
        // line writable); a double-NUL-terminated environment block or
        // null; `info` receives the handles.
        let ok = unsafe {
            CreateProcessWithLogonW(
                name.as_ptr(),
                domain.as_ptr(),
                password.as_ptr(),
                LOGON_WITH_PROFILE,
                std::ptr::null(),
                line.as_mut_ptr(),
                CREATE_SUSPENDED | CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
                env.map_or(std::ptr::null(), |b| b.as_ptr().cast()),
                dir.as_ptr(),
                &si,
                &mut info,
            )
        };
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    };
    password.iter_mut().for_each(|u| *u = 0);
    std::hint::black_box(&password);
    result.map_err(|e| start_error(account, cwd, e))?;

    let (process, thread) = (Handle(info.hProcess), Handle(info.hThread));
    // SAFETY: the job and the new process's handle, both open.
    if unsafe { AssignProcessToJobObject(job.0, process.0) } == 0 {
        let e = io::Error::last_os_error();
        // SAFETY: the suspended process this call started.
        unsafe { TerminateProcess(process.0, 1) };
        return Err(io::Error::new(e.kind(), format!("put the sandbox host in its job: {e}")));
    }
    // SAFETY: the new process's main thread, suspended.
    if unsafe { ResumeThread(thread.0) } == u32::MAX {
        let e = io::Error::last_os_error();
        // SAFETY: the job holding the process just started.
        unsafe { TerminateJobObject(job.0, 1) };
        return Err(io::Error::new(e.kind(), format!("resume the sandbox host: {e}")));
    }
    Ok(Started { pid: info.dwProcessId, process: Arc::new(process), job })
}

/// A start failure, with what the developer can do about it.
fn start_error(account: &Account, cwd: &Path, e: io::Error) -> io::Error {
    // The sign-in itself was refused: wrong password, account disabled,
    // locked or expired, sign-in type not granted.
    const SIGN_IN: [i32; 9] = [1326, 1327, 1328, 1329, 1330, 1331, 1385, 1907, 1909];
    // The Secondary Logon service, which starts another account's
    // processes, is disabled, missing or will not start.
    const SECLOGON: [i32; 3] = [1058, 1060, 1068];
    let name = &account.name;
    match e.raw_os_error() {
        Some(c) if SIGN_IN.contains(&c) => io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("sign in as the sandbox account {name}: {e} — run `ssai sandbox setup --check`"),
        ),
        Some(c) if SECLOGON.contains(&c) => io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "start a process as the sandbox account {name}: {e} — the Secondary Logon service (seclogon) must be \
                 enabled"
            ),
        ),
        Some(267) => io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("the sandbox account {name} cannot open the working directory {}: {e}", cwd.display()),
        ),
        _ => io::Error::new(e.kind(), format!("start the sandbox host as {name}: {e} — run `ssai sandbox setup --check`")),
    }
}

/// Admit `account` to this process's window station and the current
/// thread's desktop, once per process. A process started as another account
/// inherits both and must be allowed to open them, or `user32` fails to
/// initialise in it and it ends with `STATUS_DLL_INIT_FAILED` right after a
/// start call that succeeded (the `CreateProcessWithLogonW` reference: "the
/// application must add permission for the specified user account to the
/// inherited window station and desktop"). At the interactive desktop the
/// account can open `WinSta0\Default` after its sign-in; a session a
/// service made — an SSH sign-in's `Service-0x0-<logon id>$` — admits only
/// its own sign-in. The entries are merged (one per account, however often
/// this runs) and die with the session's objects.
fn admit_to_station(account: &Account) -> io::Result<()> {
    // winnt.h / winuser.h: the standard rights every object has, every
    // window station right, every desktop right.
    const STANDARD_RIGHTS_REQUIRED: u32 = 0x000F_0000;
    const WINSTA_ALL_ACCESS: u32 = 0x37F;
    const DESKTOP_ALL_ACCESS: u32 = 0x1FF;
    static DONE: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let mut done = DONE.lock().unwrap_or_else(|p| p.into_inner());
    if done.contains(&account.sid) {
        return Ok(());
    }
    let sid = Sid::parse(&account.sid).map_err(io::Error::other)?;
    // SAFETY: plain calls; the station and desktop handles are the
    // process's and the thread's own, never closed here.
    let station = unsafe { GetProcessWindowStation() };
    let desktop = unsafe { GetThreadDesktop(GetCurrentThreadId()) };
    for (handle, mask, what) in [
        (station, STANDARD_RIGHTS_REQUIRED | WINSTA_ALL_ACCESS, "window station"),
        (desktop, STANDARD_RIGHTS_REQUIRED | DESKTOP_ALL_ACCESS, "desktop"),
    ] {
        admit(handle, &sid, mask).map_err(|e| {
            io::Error::new(e.kind(), format!("admit the sandbox account {} to this session's {what}: {e}", account.name))
        })?;
    }
    done.push(account.sid.clone());
    Ok(())
}

/// Merge an allow entry for `sid` with `mask` into the access list of the
/// window station or desktop `handle`.
fn admit(handle: HANDLE, sid: &Sid, mask: u32) -> io::Result<()> {
    let (mut dacl, mut sd): (*mut ACL, PSECURITY_DESCRIPTOR) = (std::ptr::null_mut(), std::ptr::null_mut());
    // SAFETY: an open handle; `dacl` points into `sd`, LocalAlloc'd on
    // success and freed below, once.
    let rc = unsafe {
        GetSecurityInfo(
            handle,
            SE_WINDOW_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: mask,
        grfAccessMode: GRANT_ACCESS,
        // No inheritance: a window station or desktop holds no objects of its own.
        grfInheritance: 0,
        Trustee: super::acl::trustee(sid),
    };
    let mut merged: *mut ACL = std::ptr::null_mut();
    // SAFETY: one valid entry (its SID outlives the call) and the list read
    // above; `merged` is LocalAlloc'd on success and freed below, once.
    let rc = unsafe { SetEntriesInAclW(1, &entry, dacl, &mut merged) };
    // SAFETY: allocated by GetSecurityInfo, freed once; `dacl` is not used
    // past this point.
    unsafe { LocalFree(sd) };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    // SAFETY: the same handle and the list just built.
    let rc = unsafe {
        SetSecurityInfo(handle, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION, std::ptr::null_mut(), std::ptr::null_mut(), merged, std::ptr::null())
    };
    // SAFETY: allocated by SetEntriesInAclW, freed once.
    unsafe { LocalFree(merged.cast()) };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    Ok(())
}

fn new_job() -> io::Result<Handle> {
    // SAFETY: an unnamed job, default (non-inheritable) security.
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job.is_null() {
        return Err(io::Error::other(format!("create a job: {}", io::Error::last_os_error())));
    }
    let job = Handle(job);
    // SAFETY: zeroed plain data with one flag set.
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: the job just created; `limits` is the class's structure.
    let ok = unsafe {
        SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast(),
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::other(format!("set up a job: {}", io::Error::last_os_error())));
    }
    Ok(job)
}

/// Run `ssai __sandbox-host cleanup -- <account_sid>` as the account: it
/// ends what the account left running or scheduled
/// ([`super::leftovers`]), with its own sign-in, since the developer may not
/// be allowed to. Blocking; returns its standard output (one line per item,
/// UTF-8) and whether it finished within `timeout` with exit code 0.
pub fn cleanup(account: &Account, account_sid: &str, timeout: Duration) -> io::Result<(String, bool)> {
    let system = PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into())).join("System32");
    let exe = std::env::current_exe()?;
    let line = [utf8(&exe)?, "__sandbox-host", "cleanup", "--", account_sid]
        .into_iter()
        .map(cmdline::quote)
        .collect::<Vec<_>>()
        .join(" ");
    let (read, write) = pipe()?;
    let null = null_device()?;
    let started = start(account, &line, None, &system, [&null, &write, &null])?;
    drop((write, null));
    let reader = spawn_named("ssai-account-cleanup", move || {
        // SAFETY: the read end this thread owns, closed with the file.
        let mut from = unsafe { std::fs::File::from_raw_handle(ManuallyDrop::new(read).0) };
        let mut bytes = Vec::new();
        let _ = from.read_to_end(&mut bytes);
        bytes
    })?;
    let wait = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
    // SAFETY: the cleanup's process handle, open while `started` lives.
    let finished = unsafe { WaitForSingleObject(started.process.0, wait) } == WAIT_OBJECT_0;
    let mut code = 1u32;
    // SAFETY: the same handle; `code` is a local out-pointer.
    let clean = finished && unsafe { GetExitCodeProcess(started.process.0, &mut code) } != 0 && code == 0;
    // SAFETY: the cleanup's job; anything it left ends with it.
    unsafe { TerminateJobObject(started.job.0, 1) };
    let bytes = reader.join().map_err(|_| io::Error::other("read the sandbox cleanup's report"))?;
    Ok((String::from_utf8_lossy(&bytes).into_owned(), clean))
}

/// The account's own environment (its `USERPROFILE`, `APPDATA`, `TEMP`, …),
/// as a sign-in with its profile builds it: read once per process from
/// `cmd /u /c set` run as the account, which prints it as UTF-16.
fn account_defaults(account: &Account) -> io::Result<Vec<(String, String)>> {
    type Vars = Vec<(String, String)>;
    static CACHE: Mutex<Vec<(String, Vars)>> = Mutex::new(Vec::new());
    if let Some((_, vars)) = CACHE.lock().unwrap_or_else(|p| p.into_inner()).iter().find(|(n, _)| *n == account.name) {
        return Ok(vars.clone());
    }
    let system = PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into())).join("System32");
    let cmd = system.join("cmd.exe");
    let line = format!("{} /u /d /c set", cmdline::quote(utf8(&cmd)?));
    let (read, write) = pipe()?;
    let null = null_device()?;
    let started = start(account, &line, None, &system, [&null, &write, &null])?;
    drop((write, null));
    let reader = spawn_named("ssai-account-env", move || {
        // SAFETY: the read end this thread owns, closed with the file.
        let mut from = unsafe { std::fs::File::from_raw_handle(ManuallyDrop::new(read).0) };
        let mut bytes = Vec::new();
        let _ = from.read_to_end(&mut bytes);
        bytes
    })?;
    // SAFETY: the probe's process handle, open while `started` lives.
    let finished = unsafe { WaitForSingleObject(started.process.0, 15_000) } == WAIT_OBJECT_0;
    // SAFETY: the probe's job; anything it left ends with it.
    unsafe { TerminateJobObject(started.job.0, 1) };
    let bytes = reader.join().map_err(|_| io::Error::other("read the sandbox account's environment"))?;
    let units: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
    let vars = launch_env::parse_set(&String::from_utf16_lossy(&units));
    if !finished || !vars.iter().any(|(k, _)| k.eq_ignore_ascii_case("USERPROFILE")) {
        return Err(io::Error::other(format!(
            "read the sandbox account {}'s environment: {} — run `ssai sandbox setup --check`",
            account.name,
            if finished {
                let code = exit_status(&started.process).map(|s| format!("{:#x}", s.code().unwrap_or(0) as u32));
                format!("it names no profile folder (the reader exited {})", code.unwrap_or_else(|e| e.to_string()))
            } else {
                "the reader did not finish".to_string()
            }
        )));
    }
    CACHE.lock().unwrap_or_else(|p| p.into_inner()).push((account.name.clone(), vars.clone()));
    Ok(vars)
}

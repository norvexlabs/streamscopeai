//! `ssai __sandbox-host <mode> -- <program> <args…>`: the process `ssai run`
//! starts as the sandbox account, which starts the client and passes it the
//! developer's input. Its standard input is the control stream
//! ([`super::frame`]); its exit code is the client's.
//!
//! - `console:<cols>x<rows>`: the client runs in a pseudo-console of that
//!   size; its screen is written to standard output, keystrokes and resizes
//!   arrive as frames. Used when `ssai run` is in a terminal.
//! - `pipes`: the client inherits standard output and error; input frames
//!   feed its standard input, an interrupt frame is Ctrl-C on the console
//!   it shares with this process.
//! - `cleanup` (`-- <account SID>`): no client; ends what the account left
//!   running or scheduled ([`super::leftovers`]), dispatched before this
//!   module's [`main`].

use std::io::{Read, Write};
use std::mem::ManuallyDrop;
use std::os::windows::io::FromRawHandle;

use anyhow::{Context, Result, bail};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Console::{
    COORD, CTRL_C_EVENT, ClosePseudoConsole, CreatePseudoConsole, GenerateConsoleCtrlEvent, GetStdHandle, HPCON,
    ResizePseudoConsole, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetConsoleCtrlHandler,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, INFINITE,
    InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
    PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW, UpdateProcThreadAttribute, WaitForSingleObject,
};

use super::cmdline;
use super::frame::Frame;

/// Run the host; returns the client's exit code.
pub fn main(mode: &str, program: &str, args: &[String]) -> Result<i32> {
    // Ctrl-C on this console is the client's: this process outlives it to
    // report its exit code. A handler, not the inherited ignore flag, so
    // the client still receives it.
    // SAFETY: a handler with the signature the call expects, never removed.
    unsafe { SetConsoleCtrlHandler(Some(ignore_ctrl), 1) };
    if mode == "pipes" {
        return pipes(program, args);
    }
    let Some((cols, rows)) = mode.strip_prefix("console:").and_then(|s| s.split_once('x')) else {
        bail!("__sandbox-host: unknown mode {mode:?}");
    };
    let size = (cols.parse().context("console columns")?, rows.parse().context("console rows")?);
    console(program, args, size)
}

unsafe extern "system" fn ignore_ctrl(_event: u32) -> windows_sys::core::BOOL {
    1
}

/// The client with this process's standard output and error; its input fed
/// from the frames.
fn pipes(program: &str, args: &[String]) -> Result<i32> {
    let mut child = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("start {program}"))?;
    let mut input = child.stdin.take();
    std::thread::spawn(move || {
        let mut control = std::io::stdin().lock();
        // The control stream closed (`ssai run` is gone) or broken: the
        // client's input ends with it.
        while let Ok(Some(frame)) = Frame::read_from(&mut control) {
            match frame {
                Frame::Data(bytes) => {
                    if let Some(i) = input.as_mut()
                        && i.write_all(&bytes).and_then(|()| i.flush()).is_err()
                    {
                        input = None;
                    }
                }
                Frame::Eof => input = None,
                // SAFETY: plain call; group 0 is every process on this console.
                Frame::Interrupt => unsafe {
                    GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0);
                },
                Frame::Resize { .. } => {}
            }
        }
    });
    let status = child.wait().with_context(|| format!("wait for {program}"))?;
    Ok(exit_code(status.code().unwrap_or(1) as u32))
}

/// An owned handle, closed when dropped.
struct Owned(HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: a handle this module opened, closed once.
            unsafe { CloseHandle(self.0) };
        }
    }
}

// SAFETY: a kernel handle may be used from any thread.
unsafe impl Send for Owned {}

fn pipe() -> Result<(Owned, Owned)> {
    let (mut read, mut write): (HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut());
    // SAFETY: out-pointers to two handles; default (non-inheritable) security.
    if unsafe { CreatePipe(&mut read, &mut write, std::ptr::null(), 0) } == 0 {
        bail!("create a pipe: {}", std::io::Error::last_os_error());
    }
    Ok((Owned(read), Owned(write)))
}

/// A file over a handle this function does not own.
fn borrowed_file(handle: HANDLE) -> ManuallyDrop<std::fs::File> {
    // SAFETY: the handle stays open for the process's life (a standard
    // handle) and is never closed through this file.
    ManuallyDrop::new(unsafe { std::fs::File::from_raw_handle(handle) })
}

/// The client in a pseudo-console of `size` (columns, rows).
fn console(program: &str, args: &[String], size: (i16, i16)) -> Result<i32> {
    let cmd_exe = std::env::var("ComSpec").unwrap_or_else(|_| r"C:\Windows\System32\cmd.exe".to_string());
    let mut line: Vec<u16> = cmdline::command_line(&cmd_exe, program, args)?
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let (input_read, input_write) = pipe()?;
    let (output_read, output_write) = pipe()?;
    let mut pty: HPCON = 0;
    // SAFETY: two pipe ends this function owns; `pty` receives the console.
    let hr = unsafe { CreatePseudoConsole(COORD { X: size.0.max(1), Y: size.1.max(1) }, input_read.0, output_write.0, 0, &mut pty) };
    if hr < 0 {
        bail!("create a pseudo-console: HRESULT {hr:#x}");
    }
    // The pseudo-console holds its own copies of these two.
    drop((input_read, output_write));

    let mut list_size = 0usize;
    // SAFETY: a size query with a null list, as documented.
    unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut list_size) };
    // u64 storage keeps the list aligned.
    let mut list_buf = vec![0u64; list_size.div_ceil(8)];
    let list: LPPROC_THREAD_ATTRIBUTE_LIST = list_buf.as_mut_ptr().cast();
    // SAFETY: `list` has `list_size` bytes; it is deleted below.
    if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut list_size) } == 0 {
        // SAFETY: the console created above, closed once.
        unsafe { ClosePseudoConsole(pty) };
        bail!("prepare the client's start: {}", std::io::Error::last_os_error());
    }
    // SAFETY: the attribute's value is the console handle itself, passed by
    // value as the documentation shows; the list outlives the call that reads it.
    let ok = unsafe {
        UpdateProcThreadAttribute(
            list,
            0,
            PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
            pty as *const std::ffi::c_void,
            std::mem::size_of::<HPCON>(),
            std::ptr::null_mut(),
            std::ptr::null(),
        )
    };
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let started = ok != 0 && {
        let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        // No standard handles of this process's own: the client's are the
        // pseudo-console's.
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        si.StartupInfo.hStdInput = INVALID_HANDLE_VALUE;
        si.StartupInfo.hStdOutput = INVALID_HANDLE_VALUE;
        si.StartupInfo.hStdError = INVALID_HANDLE_VALUE;
        si.lpAttributeList = list;
        // SAFETY: a NUL-terminated, writable command line; the environment
        // and directory are this process's; `info` receives the handles.
        unsafe {
            CreateProcessW(
                std::ptr::null(),
                line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                EXTENDED_STARTUPINFO_PRESENT,
                std::ptr::null(),
                std::ptr::null(),
                &si.StartupInfo,
                &mut info,
            ) != 0
        }
    };
    let start_error = std::io::Error::last_os_error();
    // SAFETY: the list initialized above, deleted once, after its last use.
    unsafe { DeleteProcThreadAttributeList(list) };
    if !started {
        // SAFETY: the console created above, closed once.
        unsafe { ClosePseudoConsole(pty) };
        bail!("start {program}: {start_error}");
    }
    let (process, _thread) = (Owned(info.hProcess), Owned(info.hThread));
    // The console, until it is closed: a resize after the close would use a
    // freed one, so both go through this lock.
    let console = std::sync::Arc::new(std::sync::Mutex::new(Some(pty)));
    let resizer = console.clone();

    // The screen, to standard output, until the pseudo-console closes.
    let screen = std::thread::spawn(move || {
        // SAFETY: the read end this thread now owns, closed with the file.
        let mut from = unsafe { std::fs::File::from_raw_handle(ManuallyDrop::new(output_read).0) };
        // SAFETY: plain call.
        let mut to = borrowed_file(unsafe { GetStdHandle(STD_OUTPUT_HANDLE) });
        let mut buf = [0u8; 16 * 1024];
        while let Ok(n) = from.read(&mut buf) {
            if n == 0 || to.write_all(&buf[..n]).and_then(|()| to.flush()).is_err() {
                break;
            }
        }
    });
    // Keystrokes and resizes, from the control stream.
    std::thread::spawn(move || {
        // SAFETY: the write end this thread now owns, closed with the file.
        let mut keys = unsafe { std::fs::File::from_raw_handle(ManuallyDrop::new(input_write).0) };
        // SAFETY: plain call.
        let mut control = borrowed_file(unsafe { GetStdHandle(STD_INPUT_HANDLE) });
        while let Ok(Some(frame)) = Frame::read_from(&mut *control) {
            let written = match frame {
                Frame::Data(bytes) => keys.write_all(&bytes),
                Frame::Interrupt => keys.write_all(b"\x03"),
                Frame::Resize { cols, rows } => {
                    let size = COORD { X: (cols.max(1)).min(i16::MAX as u16) as i16, Y: (rows.max(1)).min(i16::MAX as u16) as i16 };
                    if let Ok(open) = resizer.lock()
                        && let Some(pty) = *open
                    {
                        // SAFETY: the console is open while the lock holds it.
                        unsafe { ResizePseudoConsole(pty, size) };
                    }
                    Ok(())
                }
                Frame::Eof => Ok(()),
            };
            if written.is_err() {
                break;
            }
        }
    });

    // SAFETY: the client's process handle, open until `process` drops.
    unsafe { WaitForSingleObject(process.0, INFINITE) };
    let mut code = 1u32;
    // SAFETY: as above; `code` receives the exit code.
    unsafe { GetExitCodeProcess(process.0, &mut code) };
    // Closing the console ends the screen stream once what the client wrote
    // is read, which the screen thread is doing.
    let open = match console.lock() {
        Ok(mut open) => open.take(),
        Err(poisoned) => poisoned.into_inner().take(),
    };
    if let Some(pty) = open {
        // SAFETY: the console created above, closed once (taken out of the lock).
        unsafe { ClosePseudoConsole(pty) };
    }
    let _ = screen.join();
    Ok(exit_code(code))
}

/// The client's exit code as `ssai run` reports it: an end by Ctrl-C
/// (`STATUS_CONTROL_C_EXIT`) is 130, as a shell reports one on Unix, so the
/// run reads it as the user stopping it.
fn exit_code(code: u32) -> i32 {
    const STATUS_CONTROL_C_EXIT: u32 = 0xC000_013A;
    if code == STATUS_CONTROL_C_EXIT { 130 } else { code as i32 }
}

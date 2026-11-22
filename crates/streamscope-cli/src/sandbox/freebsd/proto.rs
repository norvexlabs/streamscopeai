//! The jail daemon's wire: length-prefixed JSON frames on its unix socket,
//! with file descriptors passed beside a frame (`SCM_RIGHTS`). Plain blocking
//! std: both ends are single-threaded processes.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

use anyhow::{bail, Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use super::request::RunRequest;

/// The largest frame either side reads: the largest run request the caps
/// allow (`MAX_GRANTS` and `MAX_HELD` paths of `MAX_PATH` bytes each, about
/// 4 MiB) fits, and so does an exec's whole environment.
const MAX_FRAME: usize = 8 << 20;
/// The most descriptors a frame carries (an exec's stdin, stdout, stderr).
const MAX_FDS: usize = 3;

/// From `ssai` to the daemon.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(Debug))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ToDaemon {
    /// Build a jail for this connection's run; it lives until the connection
    /// closes.
    Open { protocol: u32, request: RunRequest },
    /// Start `argv` in the caller's run `run`, with the caller's stdin,
    /// stdout and stderr passed beside this frame (the daemon gives each that
    /// is a terminal the jail's own terminal instead).
    Exec {
        protocol: u32,
        run: String,
        argv: Vec<String>,
        /// Bytes as they are (not every name or value is UTF-8).
        env: Vec<(OsString, OsString)>,
        cwd: OsString,
        /// The caller's core-file limit (soft, hard) before it set its own to
        /// 0 (it holds the client's environment): what the process gets.
        core: (u64, u64),
    },
    /// Send this signal to the started process.
    Signal { signal: i32 },
}

/// From the daemon to `ssai`.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(Debug))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FromDaemon {
    /// The first frame on every connection.
    Hello { protocol: u32 },
    /// The run's jail is built.
    Ready { run: String },
    /// The process started; with `pty`, the jail terminal's master side is
    /// passed beside this frame.
    Started { pty: bool },
    /// The process ended: its exit code, or the signal that ended it.
    Exited { code: Option<i32>, signal: Option<i32> },
    /// The request was refused, or the jail could not be built.
    Refused { message: String },
}

/// Write `msg` as one frame, passing `fds` beside its first byte.
pub fn send<T: Serialize>(sock: &UnixStream, msg: &T, fds: &[RawFd]) -> Result<()> {
    let body = serde_json::to_vec(msg)?;
    if body.len() > MAX_FRAME {
        bail!("a frame of {} bytes is larger than the sandbox daemon reads ({MAX_FRAME})", body.len());
    }
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    if fds.is_empty() {
        return (&*sock).write_all(&frame).context("write to the sandbox daemon's socket");
    }
    if fds.len() > MAX_FDS {
        bail!("at most {MAX_FDS} descriptors go with a frame");
    }
    // SAFETY: a msghdr over our own buffers; CMSG_* compute offsets inside
    // `control`, whose size is CMSG_SPACE of the descriptors' bytes.
    unsafe {
        let bytes = std::mem::size_of_val(fds) as u32;
        // u64-backed: the buffer is read as a `cmsghdr`, which needs its
        // alignment.
        let mut control = vec![0u64; (libc::CMSG_SPACE(bytes) as usize).div_ceil(8)];
        let mut iov = libc::iovec { iov_base: frame.as_ptr() as *mut _, iov_len: frame.len() };
        let mut hdr: libc::msghdr = std::mem::zeroed();
        hdr.msg_iov = &mut iov;
        hdr.msg_iovlen = 1;
        hdr.msg_control = control.as_mut_ptr() as *mut _;
        hdr.msg_controllen = libc::CMSG_SPACE(bytes) as _;
        let cmsg = libc::CMSG_FIRSTHDR(&hdr);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(bytes) as _;
        std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(cmsg) as *mut RawFd, fds.len());
        let n = libc::sendmsg(sock.as_raw_fd(), &hdr, 0);
        if n < 0 {
            return Err(std::io::Error::last_os_error()).context("write to the sandbox daemon's socket");
        }
        // The descriptors went with the first byte; the rest is plain.
        (&*sock).write_all(&frame[n as usize..]).context("write to the sandbox daemon's socket")
    }
}

/// Read one frame and the descriptors passed beside it. `None` at a clean
/// end of stream before a frame starts.
pub fn recv<T: DeserializeOwned>(sock: &UnixStream) -> Result<Option<(T, Vec<OwnedFd>)>> {
    let mut head = [0u8; 4];
    let mut fds = Vec::new();
    // SAFETY: a msghdr over our own buffers; every descriptor received is
    // taken into an OwnedFd at once, so none leaks.
    let n = unsafe {
        let bytes = (MAX_FDS * std::mem::size_of::<RawFd>()) as u32;
        // u64-backed: the buffer is read as a `cmsghdr`, which needs its
        // alignment.
        let mut control = vec![0u64; (libc::CMSG_SPACE(bytes) as usize).div_ceil(8)];
        let mut iov = libc::iovec { iov_base: head.as_mut_ptr() as *mut _, iov_len: head.len() };
        let mut hdr: libc::msghdr = std::mem::zeroed();
        hdr.msg_iov = &mut iov;
        hdr.msg_iovlen = 1;
        hdr.msg_control = control.as_mut_ptr() as *mut _;
        hdr.msg_controllen = libc::CMSG_SPACE(bytes) as _;
        let n = loop {
            let n = libc::recvmsg(sock.as_raw_fd(), &mut hdr, libc::MSG_CMSG_CLOEXEC);
            if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break n;
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error()).context("read from the sandbox daemon's socket");
        }
        // A truncated control message (more descriptors than a frame
        // carries) is refused: its header still claims the descriptors the
        // kernel dropped, so only those inside the buffer are read.
        let truncated = hdr.msg_flags & libc::MSG_CTRUNC != 0;
        let end = (control.as_ptr() as usize) + hdr.msg_controllen as usize;
        let mut cmsg = libc::CMSG_FIRSTHDR(&hdr);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(cmsg) as *const RawFd;
                let claimed = ((*cmsg).cmsg_len as usize).saturating_sub(libc::CMSG_LEN(0) as usize) / std::mem::size_of::<RawFd>();
                // Never past the control buffer, whatever the header says.
                let fits = end.saturating_sub(data as usize) / std::mem::size_of::<RawFd>();
                // Every one that arrived is owned (and so closed when refused).
                for i in 0..claimed.min(fits) {
                    fds.push(OwnedFd::from_raw_fd(std::ptr::read_unaligned(data.add(i))));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&hdr, cmsg);
        }
        // Those that did arrive are owned above, so they close as this
        // refusal drops them.
        if truncated || fds.len() > MAX_FDS {
            bail!("the sandbox daemon's peer passed more descriptors than a frame carries");
        }
        n as usize
    };
    if n == 0 {
        return Ok(None);
    }
    (&*sock).read_exact(&mut head[n..]).context("read from the sandbox daemon's socket")?;
    let len = u32::from_be_bytes(head) as usize;
    if len > MAX_FRAME {
        bail!("a frame of {len} bytes on the sandbox daemon's socket is too large");
    }
    let mut body = vec![0u8; len];
    (&*sock).read_exact(&mut body).context("read from the sandbox daemon's socket")?;
    let msg = serde_json::from_slice(&body).context("read a frame on the sandbox daemon's socket")?;
    Ok(Some((msg, fds)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_and_its_descriptors_cross_the_socket() {
        let (a, b) = UnixStream::pair().unwrap();
        let (r, w) = UnixStream::pair().unwrap();
        let msg = ToDaemon::Exec {
            protocol: 1,
            run: "r".into(),
            argv: vec!["claude".into()],
            env: vec![("K".into(), "V".into())],
            cwd: "/p".into(),
            core: (0, u64::MAX),
        };
        send(&a, &msg, &[w.as_raw_fd()]).unwrap();
        drop(w);
        let (got, fds): (ToDaemon, _) = recv(&b).unwrap().unwrap();
        assert_eq!(got, msg);
        assert_eq!(fds.len(), 1);
        // The descriptor received is the same socket: a write through it
        // reaches `r`.
        let passed = UnixStream::from(fds.into_iter().next().unwrap());
        (&passed).write_all(b"x").unwrap();
        let mut one = [0u8; 1];
        (&r).read_exact(&mut one).unwrap();
        assert_eq!(&one, b"x");
        // A plain frame, then the end of the stream.
        send(&a, &FromDaemon::Hello { protocol: 1 }, &[]).unwrap();
        drop(a);
        let (hello, none): (FromDaemon, _) = recv(&b).unwrap().unwrap();
        assert_eq!(hello, FromDaemon::Hello { protocol: 1 });
        assert!(none.is_empty());
        assert!(recv::<FromDaemon>(&b).unwrap().is_none());
    }

    #[test]
    fn the_largest_request_the_caps_allow_fits_a_frame() {
        use super::super::request::{Grant, Held, MAX_GRANTS, MAX_HELD, MAX_PATH};
        let long = |i: usize| std::path::PathBuf::from(format!("/{:0>width$}", i, width = MAX_PATH - 1));
        let request = RunRequest {
            grants: (0..MAX_GRANTS).map(|i| Grant { path: long(i), write: true, at: Some(long(i)) }).collect(),
            held: (0..MAX_HELD).map(|i| Held { path: long(i), node: true }).collect(),
        };
        let body = serde_json::to_vec(&ToDaemon::Open { protocol: 1, request }).unwrap();
        assert!(body.len() <= MAX_FRAME, "{} > {MAX_FRAME}", body.len());
    }

    #[test]
    fn a_frame_with_more_descriptors_than_it_carries_is_refused() {
        // Four descriptors, one more than a frame carries: the control
        // message is truncated, and the frame refused without reading it.
        let (a, b) = UnixStream::pair().unwrap();
        let extra: Vec<UnixStream> = (0..4).map(|_| UnixStream::pair().unwrap().0).collect();
        let raw: Vec<RawFd> = extra.iter().map(|s| s.as_raw_fd()).collect();
        // SAFETY: as `send`, over four descriptors.
        unsafe {
            // A frame that would parse: only the descriptors refuse it.
            let body = br#"{"kind":"hello","protocol":1}"#;
            let mut frame = (body.len() as u32).to_be_bytes().to_vec();
            frame.extend_from_slice(body);
            let bytes = std::mem::size_of_val(&raw[..]) as u32;
            // u64-backed: the buffer is read as a `cmsghdr`, which needs its
            // alignment.
            let mut control = vec![0u64; (libc::CMSG_SPACE(bytes) as usize).div_ceil(8)];
            let mut iov = libc::iovec { iov_base: frame.as_ptr() as *mut _, iov_len: frame.len() };
            let mut hdr: libc::msghdr = std::mem::zeroed();
            hdr.msg_iov = &mut iov;
            hdr.msg_iovlen = 1;
            hdr.msg_control = control.as_mut_ptr() as *mut _;
            hdr.msg_controllen = libc::CMSG_SPACE(bytes) as _;
            let cmsg = libc::CMSG_FIRSTHDR(&hdr);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(bytes) as _;
            std::ptr::copy_nonoverlapping(raw.as_ptr(), libc::CMSG_DATA(cmsg) as *mut RawFd, raw.len());
            assert!(libc::sendmsg(a.as_raw_fd(), &hdr, 0) > 0);
        }
        assert!(recv::<FromDaemon>(&b).is_err());
        // The positive control: three are read.
        let (c, d) = UnixStream::pair().unwrap();
        send(&c, &FromDaemon::Hello { protocol: 1 }, &raw[..3]).unwrap();
        let (_, fds) = recv::<FromDaemon>(&d).unwrap().unwrap();
        assert_eq!(fds.len(), 3);
    }

    #[test]
    fn a_frame_of_exactly_the_largest_size_is_read() {
        let (a, b) = UnixStream::pair().unwrap();
        let empty = serde_json::to_vec(&FromDaemon::Refused { message: String::new() }).unwrap().len();
        let msg = FromDaemon::Refused { message: "a".repeat(MAX_FRAME - empty) };
        assert_eq!(serde_json::to_vec(&msg).unwrap().len(), MAX_FRAME);
        let writer = std::thread::spawn(move || send(&a, &msg, &[]).unwrap());
        assert!(recv::<FromDaemon>(&b).unwrap().is_some());
        writer.join().unwrap();
    }

    #[test]
    fn an_oversized_frame_is_refused() {
        let (a, b) = UnixStream::pair().unwrap();
        (&a).write_all(&((MAX_FRAME as u32) + 1).to_be_bytes()).unwrap();
        assert!(recv::<FromDaemon>(&b).is_err());
    }
}

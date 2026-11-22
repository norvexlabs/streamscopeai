//! A TCP listener on a sandbox's loopback that passes every connection to
//! the egress guard's unix socket: inside a docker-tier container (its init
//! runs it) and inside a FreeBSD jail (`ssai __jail-relay`), the client's
//! only way out. Also the reverse, for the jail: a unix socket on the host's
//! side passed to a port on the jail's loopback (an engine's readiness probe).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;

use anyhow::{Context, Result};

/// Listen on `<addr>:<port>` and pass every connection to the guard's
/// socket, one thread pair per connection. It lives in init, so it lives as
/// long as the container.
pub fn relay(addr: std::net::Ipv4Addr, port: u16, socket: String) -> Result<()> {
    let listener = TcpListener::bind((addr, port)).with_context(|| format!("listen on {addr}:{port}"))?;
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            // A failed accept (out of fds, say) backs off instead of
            // spinning PID 1; a connection ending frees what it held.
            let Ok(conn) = conn else {
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            };
            let socket = socket.clone();
            // Out of threads (the pids limit): this connection is dropped,
            // the relay lives on.
            let _ = std::thread::Builder::new().spawn(move || {
                if let Ok(up) = UnixStream::connect(&socket) {
                    pipe(conn, up);
                }
            });
        }
    });
    Ok(())
}

/// Copy both ways. The client closing its side passes on to the guard; the
/// guard closing ends the connection both ways, so an idle client that never
/// closes does not hold the upload thread.
pub fn pipe(tcp: TcpStream, unix: UnixStream) {
    let (Ok(mut tcp_r), Ok(mut unix_r)) = (tcp.try_clone(), unix.try_clone()) else { return };
    let (mut tcp_w, mut unix_w) = (tcp, unix);
    let Ok(up) = std::thread::Builder::new().spawn(move || {
        let _ = copy(&mut tcp_r, &mut unix_w);
        let _ = unix_w.shutdown(std::net::Shutdown::Write);
    }) else {
        return;
    };
    let _ = copy(&mut unix_r, &mut tcp_w);
    let _ = tcp_w.shutdown(std::net::Shutdown::Both);
    let _ = up.join();
}

fn copy(from: &mut impl Read, to: &mut impl Write) -> std::io::Result<()> {
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = from.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        to.write_all(&buf[..n])?;
    }
}


/// Listen on the unix socket `path` and pass every connection to
/// `127.0.0.1:<port>`.
#[cfg(target_os = "freebsd")]
pub fn reverse(path: &std::path::Path, port: u16) -> Result<()> {
    let _ = std::fs::remove_file(path);
    let listener = std::os::unix::net::UnixListener::bind(path).with_context(|| format!("listen on {}", path.display()))?;
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(conn) = conn else {
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            };
            let _ = std::thread::Builder::new().spawn(move || {
                if let Ok(tcp) = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)) {
                    pipe(tcp, conn);
                }
            });
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_relay_carries_both_ways_to_the_socket() {
        let dir = std::env::temp_dir().join(format!("ssai-relay-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("g.sock");
        let echo = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        std::thread::spawn(move || {
            for mut c in echo.incoming().flatten() {
                let mut buf = [0u8; 5];
                c.read_exact(&mut buf).unwrap();
                c.write_all(&buf).unwrap();
            }
        });
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        relay(std::net::Ipv4Addr::LOCALHOST, port, sock.to_string_lossy().into_owned()).unwrap();
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.write_all(b"hello").unwrap();
        let mut back = [0u8; 5];
        c.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"hello");
        let _ = std::fs::remove_dir_all(&dir);
    }


    #[test]
    fn the_guard_closing_ends_the_pipe_while_the_client_stays_open() {
        let (guard_end, relay_end) = UnixStream::pair().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            pipe(accepted, relay_end);
            let _ = done_tx.send(());
        });
        drop(guard_end);
        // The client never closes; the pipe returns anyway.
        assert!(done_rx.recv_timeout(std::time::Duration::from_secs(5)).is_ok(), "the pipe held on an open client");
        drop(client);
    }
}

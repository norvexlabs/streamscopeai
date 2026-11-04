//! Who is on the other end of a loopback connection to the guard, on
//! Windows, which has no peer-credential call for TCP: the connection's row
//! in the system's TCP table names the process that opened it, and the
//! system's process list names that process's account — read from the list
//! rather than the process's token, which the developer may not open for a
//! process of the sandbox account. The matching is pure, so it is tested on
//! every host.

// Off Windows this module is compiled for its tests only.
#![cfg_attr(not(windows), allow(dead_code))]

use std::net::SocketAddrV4;

/// One row of the TCP table: a connection's two ends and its process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Row {
    pub local: SocketAddrV4,
    pub remote: SocketAddrV4,
    pub pid: u32,
}

/// The process that opened the connection the guard, at `guard`, accepted
/// from `peer`: the row whose local end is the peer and remote end the
/// guard. (The guard's own end of it is the reverse row, this process's.)
pub fn opener(rows: &[Row], guard: SocketAddrV4, peer: SocketAddrV4) -> Option<u32> {
    rows.iter().find(|r| r.local == peer && r.remote == guard).map(|r| r.pid)
}

/// The account SID (`S-1-5-21-…`) of the process that opened the connection
/// the guard at `guard` accepted from `peer`. An error when either lookup
/// finds nothing: the caller refuses the connection.
#[cfg(windows)]
pub fn opener_sid(guard: SocketAddrV4, peer: SocketAddrV4) -> anyhow::Result<String> {
    let rows = sys::tcp_rows()?;
    let pid = opener(&rows, guard, peer).ok_or_else(|| anyhow::anyhow!("no process holds the connection from {peer}"))?;
    sys::process_sid(pid)
}

#[cfg(windows)]
mod sys {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use anyhow::{Result, anyhow, bail};
    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, LocalFree, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_CONNECTIONS,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::System::RemoteDesktop::{
        WTS_CURRENT_SERVER_HANDLE, WTS_PROCESS_INFO_EXW, WTSEnumerateProcessesExW, WTSFreeMemoryExW,
        WTSTypeProcessInfoLevel1,
    };

    use super::Row;

    /// Every session's processes (`WTS_ANY_SESSION`, wtsapi32.h).
    const WTS_ANY_SESSION: u32 = 0xFFFF_FFFE;

    /// The system's IPv4 TCP connections with their processes.
    pub fn tcp_rows() -> Result<Vec<Row>> {
        let mut size = 0u32;
        // The table can grow between the size query and the read: asked again
        // with the size the last refusal named.
        for _ in 0..8 {
            // u32 storage keeps the table's rows aligned.
            let mut buf = vec![0u32; (size as usize).div_ceil(4).max(1)];
            let mut len = (buf.len() * 4) as u32;
            // SAFETY: `buf` holds `len` bytes; the call writes at most that.
            let status = unsafe {
                GetExtendedTcpTable(buf.as_mut_ptr().cast(), &mut len, 0, u32::from(AF_INET), TCP_TABLE_OWNER_PID_CONNECTIONS, 0)
            };
            if status == ERROR_INSUFFICIENT_BUFFER {
                size = len;
                continue;
            }
            if status != NO_ERROR {
                bail!("read the TCP table: {}", std::io::Error::from_raw_os_error(status as i32));
            }
            // SAFETY: the call filled `buf` with a MIB_TCPTABLE_OWNER_PID,
            // whose `dwNumEntries` rows follow its count within `len` bytes.
            let rows = unsafe {
                let table = &*buf.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>();
                std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize)
            };
            return Ok(rows.iter().map(row).collect());
        }
        bail!("read the TCP table: it kept growing")
    }

    /// Addresses are in network order in memory, ports in network order in
    /// the low two bytes.
    fn row(r: &MIB_TCPROW_OWNER_PID) -> Row {
        let end = |addr: u32, port: u32| {
            SocketAddrV4::new(Ipv4Addr::from(addr.to_ne_bytes()), u16::from_be((port & 0xFFFF) as u16))
        };
        Row { local: end(r.dwLocalAddr, r.dwLocalPort), remote: end(r.dwRemoteAddr, r.dwRemotePort), pid: r.dwOwningPid }
    }

    /// The account SID of the process `pid`, from the system's process list.
    pub fn process_sid(pid: u32) -> Result<String> {
        process_sids()?
            .into_iter()
            .find(|(p, _)| *p == pid)
            .ok_or_else(|| anyhow!("no process {pid}"))?
            .1
            .ok_or_else(|| anyhow!("the account of process {pid} cannot be read"))
    }

    /// Every process on the computer, every session, with its account's SID
    /// (`None` when it has none or it cannot be spelled), from the system's
    /// process list — which names the account of a process the caller may not
    /// open.
    pub fn process_sids() -> Result<Vec<(u32, Option<String>)>> {
        let mut level = 1u32;
        let mut list: windows_sys::core::PWSTR = std::ptr::null_mut();
        let mut count = 0u32;
        // SAFETY: out-pointers to locals; the list is freed below, once.
        if unsafe { WTSEnumerateProcessesExW(WTS_CURRENT_SERVER_HANDLE, &mut level, WTS_ANY_SESSION, &mut list, &mut count) }
            == 0
        {
            bail!("list the processes: {}", std::io::Error::last_os_error());
        }
        // SAFETY: at level 1 the call returned `count` WTS_PROCESS_INFO_EXW;
        // each SID points into the same allocation, alive until it is freed.
        let out = unsafe {
            let procs = std::slice::from_raw_parts(list.cast::<WTS_PROCESS_INFO_EXW>(), count as usize);
            procs
                .iter()
                .map(|p| {
                    let mut text: *mut u16 = std::ptr::null_mut();
                    let sid = (!p.pUserSid.is_null() && ConvertSidToStringSidW(p.pUserSid, &mut text) != 0).then(|| {
                        let sid = crate::win_acl::wide_to_string(text);
                        LocalFree(text.cast());
                        sid
                    });
                    (p.ProcessId, sid)
                })
                .collect()
        };
        // SAFETY: the list the call above returned, with its count.
        unsafe { WTSFreeMemoryExW(WTSTypeProcessInfoLevel1, list.cast(), count) };
        Ok(out)
    }
}

#[cfg(windows)]
pub use sys::process_sids;

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> SocketAddrV4 {
        s.parse().unwrap()
    }

    #[test]
    fn the_opener_is_the_row_whose_local_end_is_the_peer() {
        let guard = at("127.0.0.1:5000");
        let rows = [
            // The guard's own end of the connection: this process.
            Row { local: guard, remote: at("127.0.0.1:6000"), pid: 1 },
            // Another connection to the guard.
            Row { local: at("127.0.0.1:6001"), remote: guard, pid: 3 },
            // The same peer port to another listener.
            Row { local: at("127.0.0.1:6000"), remote: at("127.0.0.1:5001"), pid: 4 },
            Row { local: at("127.0.0.1:6000"), remote: guard, pid: 2 },
        ];
        assert_eq!(opener(&rows, guard, at("127.0.0.1:6000")), Some(2));
        assert_eq!(opener(&rows, guard, at("127.0.0.1:6001")), Some(3));
        // Not in the table: nobody.
        assert_eq!(opener(&rows, guard, at("127.0.0.1:6002")), None);
        assert_eq!(opener(&[], guard, at("127.0.0.1:6000")), None);
    }

    #[cfg(windows)]
    #[test]
    fn a_connection_from_this_process_is_found_as_this_user() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let guard = match listener.local_addr().unwrap() {
            std::net::SocketAddr::V4(a) => a,
            other => panic!("{other}"),
        };
        let client = std::net::TcpStream::connect(guard).unwrap();
        let (_server, peer) = listener.accept().unwrap();
        let std::net::SocketAddr::V4(peer) = peer else { panic!("{peer}") };
        assert_eq!(client.local_addr().unwrap(), std::net::SocketAddr::V4(peer));
        let rows = sys::tcp_rows().unwrap();
        assert_eq!(opener(&rows, guard, peer), Some(std::process::id()));
        assert_eq!(opener_sid(guard, peer).unwrap(), crate::win_acl::current_user_sid().unwrap());
    }
}

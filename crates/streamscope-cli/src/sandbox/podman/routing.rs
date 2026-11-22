//! Transparent routing for a docker-tier container with an engine inside:
//! every outbound TCP connection — the agent's, and those of the inner
//! engine's containers and builds — reaches the guard as `CONNECT name:port`,
//! whether or not it honours the proxy variables (which name the relay on
//! [`STUB`], an address the engine's containers reach too).
//!
//! Pieces, all set up by init (root in the container) before the engine
//! starts:
//! - a dummy device `ssai0` holding the stub's address, and a default route
//!   on it, so a connect to a public address reaches the nat hook instead of
//!   failing with "network unreachable" (nothing leaves through it: what is
//!   not redirected is dropped there);
//! - a DNS stub on that address answering every A question with a fake
//!   address from `198.18.0.0/15`, remembered against the name; AAAA and
//!   every other type answered empty;
//! - nat rules (the image's `iptables`, which the engine needs anyway): a
//!   private, CGNAT or link-local destination left as it is; DNS to any other
//!   address → the stub; TCP leaving by `ssai0` (the agent) or arriving from
//!   the engine's bridges → the listener;
//! - the listener: the connection's original destination (`SO_ORIGINAL_DST`),
//!   a fake address read back as its name, sent to the guard's socket as
//!   `CONNECT`.
//!
//! Invariant: **the routing is a convenience, never a control.** The
//! container keeps `--network=none`: its only way out is the guard's socket,
//! which decides every connection as before. An agent root that removes the
//! rules or the stub leaves its traffic with no route at all.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream, UdpSocket};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};

/// The stub's address, on the dummy device (inside CGNAT space, which the
/// bridge rule leaves direct).
pub const STUB: Ipv4Addr = Ipv4Addr::new(100, 100, 100, 53);
const DEVICE: &str = "ssai0";
/// The listener every redirected connection arrives at.
const LISTEN_PORT: u16 = 15001;
/// The fake addresses: `198.18.0.0/15` (RFC 2544 benchmarking space, never
/// a real destination).
const POOL_BASE: u32 = u32::from_be_bytes([198, 18, 0, 0]);
const POOL_SIZE: u32 = 1 << 17;
/// What a client may cache an answer for: a name evicted from the map (after
/// `POOL_SIZE` other names) must not be connected to by its old address.
const TTL_SECS: u32 = 30;
/// Destinations a container's connection keeps going to directly: loopback,
/// the private ranges the engine's bridges are drawn from (container to
/// container, a published port), CGNAT (the stub) and link-local. A private
/// address that is not on a bridge is therefore never reached from an inner
/// container.
const DIRECT: [&str; 6] = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16"];

/// Set the routing up and start the stub and the listener; `guard` is the
/// guard's socket. A failure stops the run: without it nothing in the
/// container (the agent included, which has no proxy variable) reaches out.
pub fn start(guard: &str) -> Result<()> {
    link().context("create the sandbox's routing device")?;
    rules().context("install the sandbox's routing rules")?;
    let names = Arc::new(Mutex::new(FakeNames::default()));
    let udp = UdpSocket::bind((STUB, 53)).context("listen on the DNS stub (udp)")?;
    let tcp = TcpListener::bind((STUB, 53)).context("listen on the DNS stub (tcp)")?;
    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, LISTEN_PORT)).with_context(|| format!("listen on :{LISTEN_PORT}"))?;
    // Every resolver in the container (the engine copies it into its
    // containers) is the stub.
    // Replaced, never written through: an image's may be a symlink to a
    // resolver directory the container does not have.
    let _ = std::fs::remove_file("/etc/resolv.conf");
    std::fs::write("/etc/resolv.conf", format!("nameserver {STUB}\n")).context("write /etc/resolv.conf")?;
    let n = names.clone();
    std::thread::spawn(move || dns_udp(udp, n));
    let n = names.clone();
    std::thread::spawn(move || dns_tcp(tcp, n));
    let guard = guard.to_string();
    std::thread::spawn(move || listen(listener, names, guard));
    Ok(())
}

/// Every name asked, by its fake address and back; bounded by the pool: the
/// address handed out next evicts whatever name held it.
#[derive(Default)]
pub(crate) struct FakeNames {
    by_name: HashMap<String, u32>,
    by_addr: HashMap<u32, String>,
    next: u32,
}

impl FakeNames {
    pub(crate) fn address_for(&mut self, name: &str) -> Ipv4Addr {
        if let Some(a) = self.by_name.get(name) {
            return Ipv4Addr::from(*a);
        }
        // Skips the pool's first address (its network address).
        let addr = POOL_BASE + 1 + self.next;
        self.next = (self.next + 1) % (POOL_SIZE - 2);
        if let Some(old) = self.by_addr.insert(addr, name.to_string()) {
            self.by_name.remove(&old);
        }
        self.by_name.insert(name.to_string(), addr);
        Ipv4Addr::from(addr)
    }

    pub(crate) fn name_of(&self, addr: Ipv4Addr) -> Option<&str> {
        self.by_addr.get(&u32::from(addr)).map(String::as_str)
    }
}

fn in_pool(addr: Ipv4Addr) -> bool {
    u32::from(addr).wrapping_sub(POOL_BASE) < POOL_SIZE
}

/// The answer to one DNS query (`None`: not a query, nothing is sent). A
/// name is kept only when every label is letters, digits, `-` or `_` — it is
/// written into the `CONNECT` line, so nothing else may reach it — and is
/// kept lowercase. Such a name's A question gets its fake address; any other
/// question about it an empty answer; a malformed or refused name `REFUSED`.
pub(crate) fn answer(query: &[u8], names: &mut FakeNames) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([query[2], query[3]]);
    // A response (QR set) is never answered.
    if flags & 0x8000 != 0 {
        return None;
    }
    let reply = |rcode: u16, question: &[u8], a: Option<Ipv4Addr>| {
        let mut out = Vec::with_capacity(12 + question.len() + 16);
        out.extend_from_slice(&query[..2]);
        // QR, the query's opcode and RD, RA, the code.
        out.extend_from_slice(&(0x8080 | (flags & 0x7900) | rcode).to_be_bytes());
        out.extend_from_slice(&[0, u8::from(!question.is_empty()), 0, u8::from(a.is_some()), 0, 0, 0, 0]);
        out.extend_from_slice(question);
        if let Some(a) = a {
            out.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
            out.extend_from_slice(&TTL_SECS.to_be_bytes());
            out.extend_from_slice(&[0, 4]);
            out.extend_from_slice(&a.octets());
        }
        out
    };
    let opcode = (flags >> 11) & 0xf;
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    if opcode != 0 {
        return Some(reply(4, &[], None));
    }
    if qdcount != 1 {
        return Some(reply(1, &[], None));
    }
    let Some((name, end)) = question_name(query) else { return Some(reply(1, &[], None)) };
    let Some(tail) = query.get(end..end + 4) else { return Some(reply(1, &[], None)) };
    let question = &query[12..end + 4];
    let Some(name) = name else { return Some(reply(5, question, None)) };
    let (qtype, qclass) = (u16::from_be_bytes([tail[0], tail[1]]), u16::from_be_bytes([tail[2], tail[3]]));
    if qtype == 1 && qclass == 1 && !name.is_empty() {
        let a = names.address_for(&name);
        return Some(reply(0, question, Some(a)));
    }
    Some(reply(0, question, None))
}

/// The question's name (`None` inside: a name refused for its characters)
/// and where its type begins; `None`: malformed (a compression pointer, a
/// label running past the end, a name over 255 bytes).
fn question_name(query: &[u8]) -> Option<(Option<String>, usize)> {
    let mut i = 12;
    let mut labels: Vec<&[u8]> = Vec::new();
    let mut total = 0usize;
    loop {
        let len = *query.get(i)? as usize;
        i += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return None;
        }
        total += len + 1;
        if total > 255 {
            return None;
        }
        labels.push(query.get(i..i + len)?);
        i += len;
    }
    let fine = labels.iter().all(|l| l.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_'));
    let name = fine.then(|| labels.iter().map(|l| String::from_utf8_lossy(l).to_ascii_lowercase()).collect::<Vec<_>>().join("."));
    Some((name, i))
}

fn dns_udp(sock: UdpSocket, names: Arc<Mutex<FakeNames>>) {
    let mut buf = [0u8; 1500];
    loop {
        let Ok((n, from)) = sock.recv_from(&mut buf) else {
            std::thread::sleep(std::time::Duration::from_millis(100));
            continue;
        };
        let out = match names.lock() {
            Ok(mut names) => answer(&buf[..n], &mut names),
            Err(_) => return,
        };
        if let Some(out) = out {
            let _ = sock.send_to(&out, from);
        }
    }
}

/// The most DNS-over-TCP connections served at once: another waits in the
/// backlog (resolvers use UDP; TCP is the rare fallback).
const DNS_TCP_MAX: usize = 32;

fn dns_tcp(listener: TcpListener, names: Arc<Mutex<FakeNames>>) {
    let open = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    for conn in listener.incoming() {
        let Ok(mut conn) = conn else {
            std::thread::sleep(std::time::Duration::from_millis(100));
            continue;
        };
        while open.load(std::sync::atomic::Ordering::Acquire) >= DNS_TCP_MAX {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        open.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        let (names, open) = (names.clone(), open.clone());
        let held = open.clone();
        let spawned = std::thread::Builder::new().spawn(move || {
            struct Release(Arc<std::sync::atomic::AtomicUsize>);
            impl Drop for Release {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                }
            }
            let _release = Release(open);
            let _ = conn.set_read_timeout(Some(std::time::Duration::from_secs(10)));
            // A connection holds its slot at most this long, however slowly
            // it sends.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            let mut len = [0u8; 2];
            while std::time::Instant::now() < deadline && conn.read_exact(&mut len).is_ok() {
                let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
                if conn.read_exact(&mut q).is_err() {
                    return;
                }
                let Some(out) = names.lock().ok().and_then(|mut n| answer(&q, &mut n)) else { return };
                let Ok(n) = u16::try_from(out.len()) else { return };
                if conn.write_all(&n.to_be_bytes()).and_then(|()| conn.write_all(&out)).is_err() {
                    return;
                }
            }
        });
        // Out of threads: the connection is dropped, its slot given back.
        if spawned.is_err() {
            held.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        }
    }
}

/// Accept redirected connections, one thread per connection (a failed
/// accept backs off; out of threads, that connection is dropped).
fn listen(listener: TcpListener, names: Arc<Mutex<FakeNames>>, guard: String) {
    for conn in listener.incoming() {
        let Ok(conn) = conn else {
            std::thread::sleep(std::time::Duration::from_millis(100));
            continue;
        };
        let (names, guard) = (names.clone(), guard.clone());
        let _ = std::thread::Builder::new().spawn(move || {
            let _ = forward(conn, &names, &guard);
        });
    }
}

/// The connection's original destination, through the guard: `CONNECT
/// name:port` for a fake address (its name forgotten: dropped), the address
/// itself otherwise. Anything but a 200 closes it — the guard has recorded
/// the refusal, which `ssai run` names.
fn forward(conn: TcpStream, names: &Mutex<FakeNames>, guard: &str) -> Result<()> {
    let (addr, port) = original_destination(&conn)?;
    let host = if in_pool(addr) {
        names.lock().ok().and_then(|n| n.name_of(addr).map(str::to_string)).context("a fake address no name holds")?
    } else if conn.local_addr().is_ok_and(|l| l == std::net::SocketAddr::from((addr, port))) {
        // The listener reached directly: no redirection, nothing to forward.
        bail!("a direct connection to the listener");
    } else {
        addr.to_string()
    };
    let mut up = UnixStream::connect(guard).context("reach the guard")?;
    // The guard answers once it has decided and dialled (each attempt is
    // bounded there): a guard that never answers frees the thread.
    up.set_read_timeout(Some(std::time::Duration::from_secs(60)))?;
    up.write_all(format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n").as_bytes())?;
    // Read the answer's head a byte at a time: whatever follows it (a server
    // that speaks first) is the client's.
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 8192 || up.read(&mut byte)? == 0 {
            bail!("the guard's answer has no end");
        }
        head.push(byte[0]);
    }
    if !head.starts_with(b"HTTP/1.1 200") && !head.starts_with(b"HTTP/1.0 200") {
        bail!("refused");
    }
    up.set_read_timeout(None)?;
    crate::sandbox::relay::pipe(conn, up);
    Ok(())
}

fn original_destination(conn: &TcpStream) -> Result<(Ipv4Addr, u16)> {
    const SO_ORIGINAL_DST: libc::c_int = 80;
    // SAFETY: getsockopt into a zeroed sockaddr_in of the size passed.
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let fd = std::os::fd::AsRawFd::as_raw_fd(conn);
    // SAFETY: as above, on a socket we own.
    if unsafe { libc::getsockopt(fd, libc::SOL_IP, SO_ORIGINAL_DST, (&raw mut sa).cast(), &mut len) } != 0 {
        return Err(std::io::Error::last_os_error()).context("read the original destination");
    }
    Ok((Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)), u16::from_be(sa.sin_port)))
}

/// The nat rules, through the image's `iptables` (the one the engine uses).
/// From the engine's containers (PREROUTING), a destination in the
/// [`DIRECT`] ranges (the stub included) is left as it is — container to
/// container, a published port, a DNS server they run themselves; from the
/// agent (OUTPUT), only its DNS to them is. Then DNS to any other address →
/// the stub; then TCP → the listener (the agent's: what leaves by `ssai0`,
/// a private address off the bridges included).
fn rules() -> Result<()> {
    let to_stub = format!("{STUB}:53");
    let port = LISTEN_PORT.to_string();
    let mut all: Vec<Vec<String>> = Vec::new();
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    for (chain, ours) in [("PREROUTING", "SSAI_PREROUTING"), ("OUTPUT", "SSAI_OUTPUT")] {
        all.push(s(&["-t", "nat", "-N", ours]));
        all.push(s(&["-t", "nat", "-I", chain, "1", "-j", ours]));
        for net in DIRECT {
            if chain == "PREROUTING" {
                all.push(s(&["-t", "nat", "-A", ours, "-d", net, "-j", "RETURN"]));
            } else {
                // The agent's TCP is redirected only when it leaves by `ssai0`
                // (bridges and loopback never do): here only its DNS is kept.
                for proto in ["udp", "tcp"] {
                    all.push(s(&["-t", "nat", "-A", ours, "-p", proto, "--dport", "53", "-d", net, "-j", "RETURN"]));
                }
            }
        }
        for proto in ["udp", "tcp"] {
            all.push(s(&["-t", "nat", "-A", ours, "-p", proto, "--dport", "53", "-j", "DNAT", "--to-destination", &to_stub]));
        }
    }
    all.push(s(&["-t", "nat", "-A", "SSAI_OUTPUT", "-p", "tcp", "-o", DEVICE, "-j", "REDIRECT", "--to-ports", &port]));
    all.push(s(&["-t", "nat", "-A", "SSAI_PREROUTING", "-p", "tcp", "-j", "REDIRECT", "--to-ports", &port]));
    for args in all {
        let out = std::process::Command::new("iptables")
            .args(&args)
            .stdin(std::process::Stdio::null())
            .output()
            .context("run iptables — an engine inside needs it in the image")?;
        if !out.status.success() {
            bail!("iptables {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
        }
    }
    Ok(())
}

/// `ip link add ssai0 type dummy; ip addr add STUB/32 dev ssai0; ip link set
/// ssai0 up; ip route add default dev ssai0`, over rtnetlink.
fn link() -> Result<()> {
    let nl = Netlink::open()?;
    let mut attrs = attr(libc::IFLA_IFNAME, b"ssai0\0");
    attrs.extend(attr(libc::IFLA_LINKINFO, &attr(libc::IFLA_INFO_KIND, b"dummy")));
    nl.request(libc::RTM_NEWLINK, libc::NLM_F_CREATE | libc::NLM_F_EXCL, &[ifinfo(0, 0), attrs].concat())?;
    let name = std::ffi::CString::new(DEVICE)?;
    // SAFETY: a valid C string.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        bail!("{DEVICE} was not created");
    }
    let flags = libc::IFF_UP as u32;
    nl.request(libc::RTM_NEWLINK, 0, &ifinfo(index as i32, flags))?;
    // ifaddrmsg: AF_INET, /32, no flags, universe scope, the index.
    let mut addr = vec![libc::AF_INET as u8, 32, 0, 0];
    addr.extend_from_slice(&index.to_ne_bytes());
    addr.extend(attr(libc::IFA_LOCAL, &STUB.octets()));
    addr.extend(attr(libc::IFA_ADDRESS, &STUB.octets()));
    nl.request(libc::RTM_NEWADDR, libc::NLM_F_CREATE | libc::NLM_F_EXCL, &addr)?;
    // rtmsg: AF_INET, default (0/0), main table, boot protocol, link scope,
    // unicast; then the output device.
    let mut route = vec![libc::AF_INET as u8, 0, 0, 0, libc::RT_TABLE_MAIN, libc::RTPROT_BOOT, libc::RT_SCOPE_LINK, libc::RTN_UNICAST];
    route.extend_from_slice(&0u32.to_ne_bytes());
    route.extend(attr(libc::RTA_OIF, &index.to_ne_bytes()));
    nl.request(libc::RTM_NEWROUTE, libc::NLM_F_CREATE | libc::NLM_F_EXCL, &route)?;
    Ok(())
}

/// An `ifinfomsg`: AF_UNSPEC, the index, `flags` set (and only those changed).
fn ifinfo(index: i32, flags: u32) -> Vec<u8> {
    let mut b = vec![libc::AF_UNSPEC as u8, 0, 0, 0];
    b.extend_from_slice(&index.to_ne_bytes());
    b.extend_from_slice(&flags.to_ne_bytes());
    b.extend_from_slice(&flags.to_ne_bytes());
    b
}

/// One netlink attribute, padded to 4 bytes.
pub(crate) fn attr(kind: u16, data: &[u8]) -> Vec<u8> {
    let len = 4 + data.len();
    let mut b = Vec::with_capacity(len.next_multiple_of(4));
    b.extend_from_slice(&(len as u16).to_ne_bytes());
    b.extend_from_slice(&kind.to_ne_bytes());
    b.extend_from_slice(data);
    b.resize(len.next_multiple_of(4), 0);
    b
}

struct Netlink(std::os::fd::OwnedFd);

impl Netlink {
    fn open() -> Result<Self> {
        use std::os::fd::FromRawFd;
        // SAFETY: socket(2); the descriptor is owned from here.
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_ROUTE) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("open a netlink socket");
        }
        // SAFETY: a descriptor socket(2) just returned.
        Ok(Self(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) }))
    }

    /// Send one request and read its acknowledgement.
    fn request(&self, kind: u16, flags: libc::c_int, body: &[u8]) -> Result<()> {
        use std::os::fd::AsRawFd;
        let len = 16 + body.len();
        let mut msg = Vec::with_capacity(len);
        msg.extend_from_slice(&(len as u32).to_ne_bytes());
        msg.extend_from_slice(&kind.to_ne_bytes());
        msg.extend_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_ACK | flags) as u16).to_ne_bytes());
        msg.extend_from_slice(&1u32.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes());
        msg.extend_from_slice(body);
        // SAFETY: send(2) of a buffer we own, on our socket.
        if unsafe { libc::send(self.0.as_raw_fd(), msg.as_ptr().cast(), msg.len(), 0) } < 0 {
            return Err(std::io::Error::last_os_error()).context("send a netlink request");
        }
        let mut buf = [0u8; 4096];
        // SAFETY: recv(2) into a buffer we own.
        let n = unsafe { libc::recv(self.0.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            return Err(std::io::Error::last_os_error()).context("read a netlink answer");
        }
        let n = n as usize;
        // NLMSG_ERROR: the header, then the error code (0: acknowledged).
        if n >= 20 && u16::from_ne_bytes([buf[4], buf[5]]) == libc::NLMSG_ERROR as u16 {
            let code = i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
            if code != 0 {
                return Err(std::io::Error::from_raw_os_error(-code)).with_context(|| format!("netlink request {kind}"));
            }
            return Ok(());
        }
        bail!("netlink request {kind}: no acknowledgement")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in name.split('.').filter(|l| !l.is_empty()) {
            q.push(l.len() as u8);
            q.extend_from_slice(l.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&[0, 1]);
        q
    }

    fn answered_address(r: &[u8]) -> Option<Ipv4Addr> {
        (u16::from_be_bytes([r[6], r[7]]) == 1).then(|| {
            let a = &r[r.len() - 4..];
            Ipv4Addr::new(a[0], a[1], a[2], a[3])
        })
    }

    #[test]
    fn an_a_question_gets_a_fake_address_that_reads_back_as_its_name() {
        let mut names = FakeNames::default();
        let r = answer(&query("Registry.NPMjs.org", 1), &mut names).unwrap();
        assert_eq!(&r[..2], &[0x12, 0x34], "the id");
        assert_eq!(r[3] & 0x0f, 0, "NOERROR");
        let a = answered_address(&r).unwrap();
        assert!(in_pool(a));
        assert_eq!(names.name_of(a), Some("registry.npmjs.org"));
        // Asked again: the same address.
        assert_eq!(answered_address(&answer(&query("registry.npmjs.org", 1), &mut names).unwrap()), Some(a));
        // Another name: another address.
        let b = answered_address(&answer(&query("pypi.org", 1), &mut names).unwrap()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn any_other_question_gets_an_empty_answer() {
        let mut names = FakeNames::default();
        for qtype in [28u16, 15, 16, 255] {
            let r = answer(&query("pypi.org", qtype), &mut names).unwrap();
            assert_eq!(r[3] & 0x0f, 0);
            assert_eq!(answered_address(&r), None, "type {qtype}");
        }
        assert!(names.by_name.is_empty());
    }

    #[test]
    fn a_name_that_could_change_the_connect_line_is_refused() {
        let mut names = FakeNames::default();
        for bad in ["a b.example", "evil\r\nHost: x", "x:1.example", "ünï.example", "a/b.example"] {
            let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
            q.push(bad.len() as u8);
            q.extend_from_slice(bad.as_bytes());
            q.extend_from_slice(&[0, 0, 1, 0, 1]);
            let r = answer(&q, &mut names).unwrap();
            assert_eq!(r[3] & 0x0f, 5, "{bad:?} refused");
            assert_eq!(answered_address(&r), None);
        }
        assert!(names.by_name.is_empty());
    }

    #[test]
    fn a_malformed_query_is_a_format_error_and_a_response_is_never_answered() {
        let mut names = FakeNames::default();
        // A compression pointer in the question.
        let mut q = query("a.example", 1);
        q[12] = 0xc0;
        assert_eq!(answer(&q, &mut names).unwrap()[3] & 0x0f, 1);
        // A label past the end.
        let q = [0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 9, b'a'];
        assert_eq!(answer(&q, &mut names).unwrap()[3] & 0x0f, 1);
        // Two questions.
        let mut q = query("a.example", 1);
        q[5] = 2;
        assert_eq!(answer(&q, &mut names).unwrap()[3] & 0x0f, 1);
        // A response.
        let mut q = query("a.example", 1);
        q[2] |= 0x80;
        assert!(answer(&q, &mut names).is_none());
        assert!(answer(&[0; 11], &mut names).is_none());
    }

    #[test]
    fn the_map_is_bounded_by_the_pool_and_an_evicted_name_is_forgotten() {
        let mut names = FakeNames::default();
        let first = names.address_for("first.example");
        for i in 0..POOL_SIZE - 2 {
            names.address_for(&format!("n{i}.example"));
        }
        assert!(names.by_name.len() <= (POOL_SIZE - 2) as usize);
        assert_ne!(names.name_of(first), Some("first.example"), "its address went to another name");
        assert!(!names.by_name.contains_key("first.example"));
    }

    #[test]
    fn an_attribute_is_padded_to_four_bytes() {
        let a = attr(3, b"ssai0\0");
        assert_eq!(a.len(), 12);
        assert_eq!(u16::from_ne_bytes([a[0], a[1]]), 10);
        assert_eq!(attr(1, b"dummy").len(), 12);
        assert_eq!(attr(4, &[0; 4]).len(), 8);
    }

    proptest! {
        /// Whatever bytes an inner container sends, the stub answers without
        /// panicking, and a name it remembers is one the `CONNECT` line can
        /// carry as it is.
        #[test]
        fn any_bytes_are_answered_and_only_a_plain_name_is_remembered(q in proptest::collection::vec(any::<u8>(), 0..300)) {
            let mut names = FakeNames::default();
            let _ = answer(&q, &mut names);
            for name in names.by_name.keys() {
                prop_assert!(name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_' || b == b'.'));
            }
        }

        /// A plain name's A question always gets an address in the pool that
        /// reads back as the lowercased name.
        #[test]
        fn a_plain_name_reads_back(labels in proptest::collection::vec("[A-Za-z0-9_-]{1,20}", 1..5)) {
            let name = labels.join(".");
            let mut names = FakeNames::default();
            let r = answer(&query(&name, 1), &mut names).unwrap();
            let a = answered_address(&r).unwrap();
            prop_assert!(in_pool(a));
            let lower = name.to_ascii_lowercase();
            prop_assert_eq!(names.name_of(a), Some(lower.as_str()));
        }
    }
}

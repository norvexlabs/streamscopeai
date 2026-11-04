//! Egress guard — a loopback HTTP proxy, the sandboxed client's only way out.
//! The client is pointed here via `HTTPS_PROXY` / `HTTP_PROXY`. Runs in the
//! parent (full network); the confined child can only see it via loopback.
//!
//! Every target is decided the same way:
//! 1. a gateway origin is always allowed (a block entry naming the gateway is
//!    never read for it — the developer would lose the gateway);
//! 2. a **block** entry matching it refuses it;
//! 3. an **allow** entry matching it permits it;
//! 4. anything else is refused.
//!
//! A name target is matched by name first; an address or prefix entry is
//! matched against the address the name resolves to, here, and the guard
//! dials exactly the address it checked — never resolving again between the
//! check and the dial (each permitted address in turn, until one answers).
//! The metadata address is refused whatever a list says. A name that does not
//! resolve is answered `502`, not refused: no list decided it.
//!
//! Two request forms: `CONNECT host:port` (blind tunnel after `200`, so the
//! client's TLS stays end-to-end and CA trust is unaffected), and a plain
//! `http://` request in absolute form (forwarded to the origin, one request per
//! connection) for tools that speak plain HTTP through a proxy — apt does.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use streamscope_client_templates::destination::{host_ip, NameDecision, Policy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The longest request head read.
const MAX_HEAD: usize = 8192;
/// How long a name may take to resolve.
const RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// How long one address may take to accept a connection, before the next is
/// tried.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// The most distinct refused destinations remembered for the end-of-run line.
const MAX_REFUSED: usize = 64;

/// What the guard lets through.
#[derive(Debug, Clone, Default)]
pub struct EgressPolicy {
    /// The gateway proxy origins, `(host, port)`: always allowed.
    pub gateway: Vec<(String, u16)>,
    /// The tenant's destination lists for this workspace's sandbox.
    pub destinations: Policy,
}

/// A running guard: its loopback port and the background accept task.
pub struct Guard {
    pub port: u16,
    refused: Arc<Mutex<BTreeSet<String>>>,
    _task: tokio::task::JoinHandle<()>,
}

impl Guard {
    /// The destinations refused so far (`host:port`), at most [`MAX_REFUSED`].
    pub fn refused(&self) -> Vec<String> {
        self.refused.lock().map(|r| r.iter().cloned().collect()).unwrap_or_default()
    }
}

/// Decides whether the guard serves a loopback connection, from the guard's
/// own address and the peer's: blocking (it may read system tables), run off
/// the accept loop. `false` is answered 403.
type PeerCheck = Arc<dyn Fn(SocketAddr, SocketAddr) -> bool + Send + Sync>;

/// Bind the guard on `127.0.0.1:<ephemeral>` and start accepting.
#[cfg_attr(windows, allow(dead_code, reason = "Windows starts the account's guard, `start_for_account`"))]
pub async fn start(policy: EgressPolicy, verbose: bool) -> Result<Guard> {
    listen(policy, verbose, None).await
}

/// [`start`], serving only connections opened by a process of the account
/// `account_sid` — the Windows sandbox account: the client, its engine and
/// every tool they start run as it, and nothing else needs the guard. A
/// connection whose process or account cannot be found is refused.
#[cfg(windows)]
pub async fn start_for_account(policy: EgressPolicy, verbose: bool, account_sid: String) -> Result<Guard> {
    let check: PeerCheck = Arc::new(move |guard, peer| {
        let found = match (guard, peer) {
            (SocketAddr::V4(guard), SocketAddr::V4(peer)) => super::windows::peer::opener_sid(guard, peer),
            _ => Err(anyhow::anyhow!("not an IPv4 connection")),
        };
        match found {
            Ok(sid) if sid == account_sid => true,
            other => {
                if verbose {
                    let who = other.unwrap_or_else(|e| format!("unknown: {e:#}"));
                    eprintln!("ssai: guard refused a connection from {peer} (account {who})");
                }
                false
            }
        }
    });
    listen(policy, verbose, Some(check)).await
}

async fn listen(policy: EgressPolicy, verbose: bool, check: Option<PeerCheck>) -> Result<Guard> {
    let listener = TcpListener::bind("127.0.0.1:0").await.context("bind egress guard on loopback")?;
    let port = listener.local_addr()?.port();
    let policy = Arc::new(policy);
    let refused: Arc<Mutex<BTreeSet<String>>> = Arc::default();
    let task = {
        let refused = refused.clone();
        tokio::spawn(async move {
            while let Ok((sock, peer)) = listener.accept().await {
                // The guard binds 127.0.0.1, so only local processes can reach
                // it. Without a peer check, any local process may use it —
                // another local user's included (SO_PEERCRED is
                // Unix-socket-only), a residual noted in the design. Anything
                // not from loopback is refused as a belt-and-suspenders check.
                if !peer.ip().is_loopback() {
                    tokio::spawn(refuse(sock));
                    continue;
                }
                let Some(check) = check.clone() else {
                    serve_detached(sock, policy.clone(), refused.clone(), verbose);
                    continue;
                };
                let (policy, refused) = (policy.clone(), refused.clone());
                tokio::spawn(async move {
                    let admitted = match sock.local_addr() {
                        Ok(own) => tokio::task::spawn_blocking(move || check(own, peer)).await.unwrap_or(false),
                        Err(_) => false,
                    };
                    if admitted {
                        serve_detached(sock, policy, refused, verbose);
                    } else {
                        refuse(sock).await;
                    }
                });
            }
        })
    };
    Ok(Guard { port, refused, _task: task })
}

/// Answer 403 to a connection whose request was not read, and close it
/// without a reset: closed with its request unread, Windows resets the
/// connection, and the peer may lose the answer before reading it. So the
/// write side is shut, then what the peer sent is drained (for a while) until
/// it closes.
async fn refuse(mut sock: TcpStream) {
    let _ = sock.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await;
    let _ = sock.shutdown().await;
    let mut sink = [0u8; 1024];
    let drain = async {
        while matches!(sock.read(&mut sink).await, Ok(n) if n > 0) {}
    };
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), drain).await;
}

/// The peers a socket guard admits, by the uid the kernel reports for the
/// connecting process (`SO_PEERCRED`, in this process's user namespace): the
/// developer's own, and their subordinate range — a rootless container's root
/// and every other id it maps. An id the namespace does not map reads as the
/// overflow uid, which no range here holds.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub struct Admit {
    pub uid: u32,
    /// `(first, count)` ranges, as `/etc/subuid` lists them.
    pub ranges: Vec<(u32, u32)>,
}

#[cfg(target_os = "linux")]
impl Admit {
    pub fn admits(&self, uid: u32) -> bool {
        uid == self.uid || self.ranges.iter().any(|&(first, count)| uid >= first && uid - first < count)
    }
}

/// A running guard on a unix socket and its background accept task.
#[cfg(target_os = "linux")]
pub struct SocketGuard {
    refused: Arc<Mutex<BTreeSet<String>>>,
    _task: tokio::task::JoinHandle<()>,
}

#[cfg(target_os = "linux")]
impl SocketGuard {
    /// The destinations refused so far (`host:port`), at most [`MAX_REFUSED`].
    pub fn refused(&self) -> Vec<String> {
        self.refused.lock().map(|r| r.iter().cloned().collect()).unwrap_or_default()
    }
}

/// Bind the guard on a unix socket at `path` and start accepting. The socket
/// is made connectable by every user — a container's root is another host uid
/// than the developer's — so the peer check is its access control: a
/// connection from a uid `admit` refuses is answered 403 and closed.
#[cfg(target_os = "linux")]
pub async fn start_unix(policy: EgressPolicy, verbose: bool, path: &std::path::Path, admit: Admit) -> Result<SocketGuard> {
    use std::os::unix::fs::PermissionsExt;
    let listener = tokio::net::UnixListener::bind(path)
        .with_context(|| format!("bind egress guard on {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))
        .with_context(|| format!("open {} to the container", path.display()))?;
    let policy = Arc::new(policy);
    let refused: Arc<Mutex<BTreeSet<String>>> = Arc::default();
    let task = {
        let refused = refused.clone();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                match sock.peer_cred() {
                    Ok(cred) if admit.admits(cred.uid()) => {}
                    peer => {
                        if verbose {
                            let uid = peer.map(|c| c.uid().to_string()).unwrap_or_else(|_| "unknown".into());
                            eprintln!("ssai: guard refused a connection from uid {uid}");
                        }
                        let _ = sock.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await;
                        continue;
                    }
                }
                serve_detached(sock, policy.clone(), refused.clone(), verbose);
            }
        })
    };
    Ok(SocketGuard { refused, _task: task })
}

/// Handle one admitted connection on its own task.
fn serve_detached<S>(sock: S, policy: Arc<EgressPolicy>, refused: Arc<Mutex<BTreeSet<String>>>, verbose: bool)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        if let Err(e) = handle(sock, &policy, &refused, verbose).await {
            // Per-connection failures are the client's problem, not the
            // guard's — surface a terse line only when asked, so the client's
            // TUI isn't corrupted by default.
            if verbose {
                eprintln!("ssai: guard connection error: {e}");
            }
        }
    });
}

/// Where a permitted target is dialled.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Dial {
    /// A gateway origin, by its name.
    Gateway(String, u16),
    /// The addresses the decision checked and permitted, in resolution
    /// order; never empty.
    Addrs(Vec<SocketAddr>),
}

/// Why a target is not dialled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    /// The policy refuses it.
    Policy,
    /// The name did not resolve, so no address could be checked.
    Unresolved,
}

impl EgressPolicy {
    /// A gateway origin's host is compared without IPv6 brackets or a
    /// trailing dot on either side (a URL's host keeps the brackets, a
    /// CONNECT authority's parse drops them).
    fn is_gateway(&self, host: &str, port: u16) -> bool {
        let bare = |h: &str| h.trim_start_matches('[').trim_end_matches(']').trim_end_matches('.').to_ascii_lowercase();
        let host = bare(host);
        self.gateway.iter().any(|(h, p)| *p == port && bare(h) == host)
    }

    /// The decision for `host:port`, resolving a name with `resolve` only
    /// when an address entry could decide it.
    async fn decide<F, Fut>(&self, host: &str, port: u16, resolve: F) -> Result<Dial, Refusal>
    where
        F: FnOnce(String, u16) -> Fut,
        Fut: std::future::Future<Output = Vec<SocketAddr>>,
    {
        if self.is_gateway(host, port) {
            return Ok(Dial::Gateway(host.to_string(), port));
        }
        let policy = &self.destinations;
        if let Some(ip) = host_ip(host) {
            return match policy.permits_addr(false, ip, port) {
                true => Ok(Dial::Addrs(vec![SocketAddr::new(ip, port)])),
                false => Err(Refusal::Policy),
            };
        }
        let name_allowed = match policy.by_name(host, port) {
            NameDecision::Blocked => return Err(Refusal::Policy),
            NameDecision::Allowed => true,
            NameDecision::Undecided if policy.allows_by_address() => false,
            NameDecision::Undecided => return Err(Refusal::Policy),
        };
        let resolved = resolve(host.to_string(), port).await;
        if resolved.is_empty() {
            return Err(Refusal::Unresolved);
        }
        let permitted: Vec<SocketAddr> =
            resolved.into_iter().filter(|a| policy.permits_addr(name_allowed, a.ip(), port)).collect();
        if permitted.is_empty() { Err(Refusal::Policy) } else { Ok(Dial::Addrs(permitted)) }
    }
}

async fn resolve(host: String, port: u16) -> Vec<SocketAddr> {
    match tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host((host.as_str(), port))).await {
        Ok(Ok(addrs)) => addrs.collect(),
        _ => Vec::new(),
    }
}

async fn handle<S>(mut client: S, policy: &EgressPolicy, refused: &Mutex<BTreeSet<String>>, verbose: bool) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // Read the request head up to CRLFCRLF (bounded — a client that never sends
    // a complete head is dropped rather than buffered without limit). Byte by
    // byte, so nothing past the head is consumed.
    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        match client.read(&mut byte).await {
            Ok(0) => return Ok(()),
            Ok(_) => buf.push(byte[0]),
            Err(e) => return Err(e).context("read the request head"),
        }
        if buf.len() > MAX_HEAD {
            let _ = client.write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n").await;
            return Ok(());
        }
    }
    let head = String::from_utf8_lossy(&buf).into_owned();
    let Some(request) = Request::parse(&head) else {
        let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
        return Ok(());
    };
    let (host, port) = (request.host(), request.port());

    // The host is the confined process's text: never written raw to the
    // developer's terminal.
    let dial = match policy.decide(host, port, resolve).await {
        Ok(dial) => dial,
        Err(Refusal::Unresolved) => {
            if verbose {
                eprintln!("ssai: guard could not resolve {}", printable(host));
            }
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            return Ok(());
        }
        Err(Refusal::Policy) => {
            let shown = printable(host);
            if verbose {
                eprintln!("ssai: guard refused egress to {shown}:{port}");
            }
            if let Ok(mut r) = refused.lock()
                && r.len() < MAX_REFUSED
            {
                r.insert(format!("{shown}:{port}"));
            }
            let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await;
            return Ok(());
        }
    };
    if verbose {
        eprintln!("ssai: guard allowed egress to {}:{port}", printable(host));
    }

    // A gateway is resolved here, in the parent (full network) — the confined
    // child never resolves DNS itself; any other target was resolved by the
    // decision and is dialled at the addresses it checked.
    let connected = match &dial {
        Dial::Gateway(h, p) => connect_first(&resolve(h.clone(), *p).await).await,
        Dial::Addrs(addrs) => connect_first(addrs).await,
    };
    let Some(mut upstream) = connected else {
        let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
        return Ok(());
    };
    match &request {
        Request::Connect { .. } => {
            client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.context("write 200")?;
        }
        Request::Forward { .. } => {
            upstream.write_all(request.origin_head(&head).as_bytes()).await.context("forward the request head")?;
        }
    }
    // Blind bidirectional copy — for CONNECT, TLS stays end-to-end.
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
}

/// The first of `addrs` that accepts a connection, each tried for at most
/// [`CONNECT_TIMEOUT`].
async fn connect_first(addrs: &[SocketAddr]) -> Option<TcpStream> {
    for addr in addrs {
        if let Ok(Ok(stream)) = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            return Some(stream);
        }
    }
    None
}

/// `s` with every control character replaced by `?`, and at most 255 chars.
fn printable(s: &str) -> String {
    s.chars().take(255).map(|c| if c.is_control() { '?' } else { c }).collect()
}

/// A request the guard serves.
#[derive(Debug, PartialEq, Eq)]
enum Request {
    /// `CONNECT host:port`.
    Connect { host: String, port: u16 },
    /// A plain `http://` request in absolute form.
    Forward { method: String, host: String, port: u16, path: String, version: String },
}

impl Request {
    fn parse(head: &str) -> Option<Request> {
        let first = head.lines().next()?;
        let mut parts = first.split_whitespace();
        let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() {
            return None;
        }
        if method.eq_ignore_ascii_case("CONNECT") {
            let (host, port) = parse_authority(target)?;
            return Some(Request::Connect { host, port });
        }
        // Only plain HTTP is forwarded: an `https://` target in absolute form
        // would have this proxy speak TLS for the client, which it never does.
        if !target.get(..7).is_some_and(|s| s.eq_ignore_ascii_case("http://")) {
            return None;
        }
        let url = url::Url::parse(target).ok()?;
        if !url.username().is_empty() || url.password().is_some() {
            return None;
        }
        let host = url.host_str()?.trim_start_matches('[').trim_end_matches(']').to_string();
        let port = url.port_or_known_default()?;
        let mut path = url.path().to_string();
        if let Some(q) = url.query() {
            path.push('?');
            path.push_str(q);
        }
        Some(Request::Forward { method: method.to_string(), host, port, path, version: version.to_string() })
    }

    fn host(&self) -> &str {
        match self {
            Request::Connect { host, .. } | Request::Forward { host, .. } => host,
        }
    }

    fn port(&self) -> u16 {
        match self {
            Request::Connect { port, .. } | Request::Forward { port, .. } => *port,
        }
    }

    /// The head a forwarded request is sent upstream with: origin-form
    /// request line, `Host` set to the authority the guard checked (the
    /// client's own is dropped — an origin serving several hosts routes by
    /// it), the client's other headers less the proxy and hop-by-hop ones,
    /// and `Connection: close` — so the connection carries this one request,
    /// and a second one to another host cannot ride a tunnel the guard
    /// decided for this one.
    fn origin_head(&self, head: &str) -> String {
        let Request::Forward { method, host, port, path, version } = self else {
            return String::new();
        };
        let mut out = format!("{method} {path} {version}\r\n");
        let bracketed = if host.contains(':') { format!("[{host}]") } else { host.clone() };
        match *port {
            80 => out.push_str(&format!("Host: {bracketed}\r\n")),
            p => out.push_str(&format!("Host: {bracketed}:{p}\r\n")),
        }
        for line in head.split("\r\n").skip(1) {
            if line.is_empty() {
                continue;
            }
            let name = line.split(':').next().unwrap_or("").trim().to_ascii_lowercase();
            if matches!(name.as_str(), "host" | "proxy-connection" | "proxy-authorization" | "connection" | "keep-alive") {
                continue;
            }
            out.push_str(line);
            out.push_str("\r\n");
        }
        out.push_str("Connection: close\r\n\r\n");
        out
    }
}

/// Parse a CONNECT authority `host:port` (host may be bracketed IPv6).
fn parse_authority(target: &str) -> Option<(String, u16)> {
    if let Some(rest) = target.strip_prefix('[') {
        // [::1]:443
        let (host, port) = rest.split_once("]:")?;
        return Some((host.to_string(), port.parse().ok()?));
    }
    let (host, port) = target.rsplit_once(':')?;
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port.parse().ok()?))
}

/// `ssai __connect <host> <port>`: open a tunnel to `host:port` through the
/// guard `HTTPS_PROXY` names and relay stdin/stdout over it — an
/// `ssh -o ProxyCommand` for a tool that does not read the proxy variables.
pub async fn connect_through(host: &str, port: u16) -> Result<()> {
    let proxy = ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
        .context("no HTTPS_PROXY set — `ssai __connect` runs inside `ssai run`")?;
    let proxy = url::Url::parse(&proxy).with_context(|| format!("HTTPS_PROXY {proxy:?} is not a URL"))?;
    let addr = (
        proxy.host_str().context("HTTPS_PROXY has no host")?.to_string(),
        proxy.port_or_known_default().context("HTTPS_PROXY has no port")?,
    );
    let mut tunnel = TcpStream::connect((addr.0.as_str(), addr.1)).await.context("reach the sandbox guard")?;
    let authority = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
    tunnel
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .context("send CONNECT")?;
    let mut head = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if tunnel.read(&mut byte).await.context("read the guard's answer")? == 0 || head.len() > MAX_HEAD {
            anyhow::bail!("the sandbox guard closed the connection to {authority}");
        }
        head.push(byte[0]);
    }
    let status = String::from_utf8_lossy(&head).split_whitespace().nth(1).unwrap_or("").to_string();
    match status.as_str() {
        "200" => {}
        "403" => anyhow::bail!("the sandbox refused {authority} — it is on no allowed destination list"),
        _ => anyhow::bail!("{authority} is unreachable through the sandbox (HTTP {status})"),
    }
    let (mut read, mut write) = tunnel.into_split();
    let up = async {
        let _ = tokio::io::copy(&mut tokio::io::stdin(), &mut write).await;
        let _ = write.shutdown().await;
    };
    let down = async {
        let _ = tokio::io::copy(&mut read, &mut tokio::io::stdout()).await;
    };
    tokio::join!(up, down);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use streamscope_client_templates::destination::DestinationSet;

    #[test]
    fn a_host_is_printed_without_control_characters() {
        assert_eq!(printable("evil\x1b[2J.lan"), "evil?[2J.lan");
        assert_eq!(printable("ok.lan"), "ok.lan");
        assert_eq!(printable(&"a".repeat(300)).len(), 255);
    }

    #[test]
    fn authority_parsing() {
        assert_eq!(parse_authority("example.com:443"), Some(("example.com".into(), 443)));
        assert_eq!(parse_authority("[::1]:8443"), Some(("::1".into(), 8443)));
        assert_eq!(parse_authority("nohost"), None);
        assert_eq!(parse_authority(":443"), None);
        assert_eq!(parse_authority("host:notaport"), None);
    }

    fn policy(allow: &[&str], block: &[&str]) -> EgressPolicy {
        EgressPolicy {
            gateway: vec![("gw.example".into(), 443)],
            destinations: Policy {
                allow: DestinationSet::parse(allow).unwrap(),
                block: DestinationSet::parse(block).unwrap(),
            },
        }
    }

    /// A resolver answering `addrs` for every name, counting its calls.
    fn answering<'a>(
        addrs: &'static [&'static str],
        calls: &'a std::sync::atomic::AtomicUsize,
    ) -> impl FnOnce(String, u16) -> std::future::Ready<Vec<SocketAddr>> + 'a {
        move |_, port| {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::future::ready(addrs.iter().map(|a| SocketAddr::new(a.parse().unwrap(), port)).collect())
        }
    }

    async fn decide(p: &EgressPolicy, host: &str, port: u16, addrs: &'static [&'static str]) -> Result<Dial, Refusal> {
        let calls = std::sync::atomic::AtomicUsize::new(0);
        p.decide(host, port, answering(addrs, &calls)).await
    }

    fn at(a: &str, port: u16) -> Result<Dial, Refusal> {
        Ok(Dial::Addrs(vec![SocketAddr::new(a.parse().unwrap(), port)]))
    }

    const REFUSED: Result<Dial, Refusal> = Err(Refusal::Policy);

    #[tokio::test]
    async fn the_gateway_is_always_allowed_even_when_a_block_names_it() {
        let p = policy(&[], &["gw.example", "10.0.0.0/8"]);
        assert_eq!(decide(&p, "gw.example", 443, &[]).await, Ok(Dial::Gateway("gw.example".into(), 443)));
        assert_eq!(decide(&p, "GW.example.", 443, &[]).await, Ok(Dial::Gateway("GW.example.".into(), 443)));
        assert_eq!(decide(&p, "gw.example", 8443, &["203.0.113.5"]).await, REFUSED, "another port is not the gateway");
        let v6 = EgressPolicy { gateway: vec![("[::1]".into(), 8443)], destinations: Policy::default() };
        assert_eq!(decide(&v6, "::1", 8443, &[]).await, Ok(Dial::Gateway("::1".into(), 8443)), "a bracketed gateway host");
    }

    #[tokio::test]
    async fn nothing_attached_refuses_everything_but_the_gateway_without_resolving() {
        let p = policy(&[], &[]);
        let calls = std::sync::atomic::AtomicUsize::new(0);
        assert_eq!(p.decide("github.com", 443, answering(&["140.82.112.3"], &calls)).await, REFUSED);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0, "no address entry: no resolution");
    }

    #[tokio::test]
    async fn an_allowed_name_that_does_not_resolve_is_not_a_refusal() {
        let p = policy(&["github.com"], &[]);
        assert_eq!(decide(&p, "github.com", 443, &[]).await, Err(Refusal::Unresolved));
        assert_eq!(decide(&p, "github.com", 443, &["140.82.112.3"]).await, at("140.82.112.3", 443), "the positive control");
    }

    #[tokio::test]
    async fn every_permitted_address_is_kept_for_the_dial_in_order() {
        let p = policy(&["registry.lan"], &["10.9.0.0/16"]);
        assert_eq!(
            decide(&p, "registry.lan", 443, &["2001:db8::1", "10.9.0.1", "10.1.0.1"]).await,
            Ok(Dial::Addrs(vec![
                SocketAddr::new("2001:db8::1".parse().unwrap(), 443),
                SocketAddr::new("10.1.0.1".parse().unwrap(), 443),
            ])),
            "the blocked one left out"
        );
    }

    #[tokio::test]
    async fn a_dial_moves_past_an_address_that_refuses_the_connection() {
        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live = up.local_addr().unwrap();
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        assert!(connect_first(&[closed, live]).await.is_some());
        assert!(connect_first(&[closed]).await.is_none());
    }

    #[tokio::test]
    async fn an_allowed_name_is_dialled_at_the_address_it_resolved_to() {
        let p = policy(&["github.com:443,22"], &[]);
        assert_eq!(decide(&p, "github.com", 22, &["140.82.112.3"]).await, at("140.82.112.3", 22));
        assert_eq!(decide(&p, "github.com", 80, &["140.82.112.3"]).await, REFUSED, "a port the entry does not name");
        assert_eq!(decide(&p, "gist.github.com", 443, &["140.82.112.4"]).await, REFUSED);
    }

    #[tokio::test]
    async fn a_block_wins_over_an_allow_by_name_and_by_address() {
        let p = policy(&["*.corp.example", "10.0.0.0/8"], &["hr.corp.example", "10.9.0.0/16"]);
        assert_eq!(decide(&p, "git.corp.example", 443, &["10.1.0.5"]).await, at("10.1.0.5", 443));
        assert_eq!(decide(&p, "hr.corp.example", 443, &["10.1.0.6"]).await, REFUSED, "blocked by name");
        assert_eq!(decide(&p, "wiki.corp.example", 443, &["10.9.0.1"]).await, REFUSED, "resolves into a blocked prefix");
        assert_eq!(
            decide(&p, "wiki.corp.example", 443, &["10.9.0.1", "10.1.0.9"]).await,
            at("10.1.0.9", 443),
            "the first address the policy permits"
        );
    }

    #[tokio::test]
    async fn a_prefix_allows_a_name_by_the_address_it_resolves_to() {
        let p = policy(&["10.20.0.0/16:5000"], &[]);
        assert_eq!(decide(&p, "registry.lan", 5000, &["10.20.1.1"]).await, at("10.20.1.1", 5000));
        assert_eq!(decide(&p, "registry.lan", 5000, &["10.21.1.1"]).await, REFUSED);
        assert_eq!(decide(&p, "10.20.1.1", 5000, &[]).await, at("10.20.1.1", 5000), "an IP literal target");
        assert_eq!(decide(&p, "10.20.1.1", 5001, &[]).await, REFUSED);
    }

    #[tokio::test]
    async fn the_metadata_address_is_refused_through_every_path() {
        let p = policy(&["169.254.0.0/16", "metadata.lan"], &[]);
        assert_eq!(decide(&p, "169.254.169.254", 443, &[]).await, REFUSED);
        assert_eq!(decide(&p, "metadata.lan", 443, &["169.254.169.254"]).await, REFUSED);
        assert_eq!(decide(&p, "metadata.lan", 443, &["169.254.169.254", "169.254.1.1"]).await, at("169.254.1.1", 443));
    }

    #[test]
    fn a_plain_http_request_is_forwarded_in_origin_form_and_closes() {
        let head = "GET http://archive.ubuntu.com/ubuntu/dists/noble/InRelease?x=1 HTTP/1.1\r\n\
                    Host: archive.ubuntu.com\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\n\
                    Proxy-Authorization: Basic Zm9v\r\nUser-Agent: apt\r\n\r\n";
        let req = Request::parse(head).unwrap();
        assert_eq!((req.host(), req.port()), ("archive.ubuntu.com", 80));
        assert_eq!(
            req.origin_head(head),
            "GET /ubuntu/dists/noble/InRelease?x=1 HTTP/1.1\r\nHost: archive.ubuntu.com\r\nUser-Agent: apt\r\nConnection: close\r\n\r\n"
        );
        let spoofed = "GET http://archive.ubuntu.com/x HTTP/1.1\r\nHost: attacker.example\r\n\r\n";
        assert_eq!(
            Request::parse(spoofed).unwrap().origin_head(spoofed),
            "GET /x HTTP/1.1\r\nHost: archive.ubuntu.com\r\nConnection: close\r\n\r\n",
            "the Host is the authority the guard checked"
        );
        let v6 = "GET http://[2001:db8::5]:8080/ HTTP/1.1\r\n\r\n";
        assert!(Request::parse(v6).unwrap().origin_head(v6).contains("Host: [2001:db8::5]:8080\r\n"));
        let other_port = Request::parse("GET http://deb.debian.org:8080/ HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(other_port.port(), 8080);
    }

    #[test]
    fn only_connect_and_plain_http_absolute_requests_are_served() {
        assert_eq!(
            Request::parse("CONNECT github.com:443 HTTP/1.1\r\n\r\n"),
            Some(Request::Connect { host: "github.com".into(), port: 443 })
        );
        for refused in [
            "GET https://github.com/ HTTP/1.1\r\n\r\n",
            "GET /relative HTTP/1.1\r\n\r\n",
            "GET http://user:pw@host/ HTTP/1.1\r\n\r\n",
            "CONNECT nohost HTTP/1.1\r\n\r\n",
            "GET http://a/ HTTP/1.1 extra\r\n\r\n",
            "\r\n\r\n",
        ] {
            assert_eq!(Request::parse(refused), None, "{refused:?}");
        }
    }

    #[tokio::test]
    async fn the_guard_tunnels_an_allowed_target_and_refuses_another() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_port = upstream.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = upstream.accept().await {
                let _ = s.write_all(b"hello").await;
            }
        });
        let guard = start(
            EgressPolicy {
                gateway: vec![],
                destinations: Policy {
                    allow: DestinationSet::parse(&[format!("127.0.0.1:{up_port}")]).unwrap(),
                    block: DestinationSet::default(),
                },
            },
            false,
        )
        .await
        .unwrap();
        let ask = |target: String| async move {
            let mut s = TcpStream::connect(("127.0.0.1", guard.port)).await.unwrap();
            s.write_all(format!("CONNECT {target} HTTP/1.1\r\n\r\n").as_bytes()).await.unwrap();
            let mut out = Vec::new();
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), s.read_to_end(&mut out)).await;
            String::from_utf8_lossy(&out).into_owned()
        };
        let allowed = ask(format!("127.0.0.1:{up_port}")).await;
        assert!(allowed.starts_with("HTTP/1.1 200") && allowed.ends_with("hello"), "{allowed}");
        let refused = ask(format!("127.0.0.1:{}", up_port.wrapping_add(1))).await;
        assert!(refused.starts_with("HTTP/1.1 403"), "{refused}");
        assert_eq!(guard.refused(), vec![format!("127.0.0.1:{}", up_port.wrapping_add(1))]);
    }

    /// A guard with a peer check: CONNECT to a target that answers "hello",
    /// through a guard started by `start_guard`.
    async fn ask_through<F, Fut>(start_guard: F) -> String
    where
        F: FnOnce(EgressPolicy) -> Fut,
        Fut: std::future::Future<Output = Guard>,
    {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_port = upstream.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = upstream.accept().await {
                let _ = s.write_all(b"hello").await;
            }
        });
        let policy = EgressPolicy {
            gateway: vec![],
            destinations: Policy {
                allow: DestinationSet::parse(&[format!("127.0.0.1:{up_port}")]).unwrap(),
                block: DestinationSet::default(),
            },
        };
        let guard = start_guard(policy).await;
        let mut s = TcpStream::connect(("127.0.0.1", guard.port)).await.unwrap();
        s.write_all(format!("CONNECT 127.0.0.1:{up_port} HTTP/1.1\r\n\r\n").as_bytes()).await.unwrap();
        let mut out = Vec::new();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), s.read_to_end(&mut out)).await;
        String::from_utf8_lossy(&out).into_owned()
    }

    #[tokio::test]
    async fn a_peer_check_decides_with_both_ends_of_the_connection() {
        let seen: Arc<Mutex<Vec<(SocketAddr, SocketAddr)>>> = Arc::default();
        let log = seen.clone();
        let served = ask_through(|p| async move {
            let check: PeerCheck = Arc::new(move |own, peer| {
                log.lock().unwrap().push((own, peer));
                true
            });
            listen(p, false, Some(check)).await.unwrap()
        })
        .await;
        assert!(served.starts_with("HTTP/1.1 200") && served.ends_with("hello"), "{served}");
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        let (own, peer) = seen[0];
        assert!(own.ip().is_loopback() && peer.ip().is_loopback() && own != peer, "{own} {peer}");

        let refused = ask_through(|p| async move { listen(p, false, Some(Arc::new(|_, _| false))).await.unwrap() }).await;
        assert!(refused.starts_with("HTTP/1.1 403") && !refused.contains("hello"), "{refused}");
    }

    /// Positive control: a guard for this process's own account serves it;
    /// one for another account refuses it.
    #[cfg(windows)]
    #[tokio::test]
    async fn an_account_guard_serves_its_account_and_refuses_another() {
        let me = crate::win_acl::current_user_sid().unwrap();
        let served = ask_through(|p| async move { start_for_account(p, false, me).await.unwrap() }).await;
        assert!(served.starts_with("HTTP/1.1 200") && served.ends_with("hello"), "{served}");
        // LocalSystem: never this test's account.
        let other = "S-1-5-18".to_string();
        let refused = ask_through(|p| async move { start_for_account(p, false, other).await.unwrap() }).await;
        assert!(refused.starts_with("HTTP/1.1 403") && !refused.contains("hello"), "{refused}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_socket_guard_admits_its_uid_and_exactly_its_ranges() {
        let admit = Admit { uid: 1000, ranges: vec![(100_000, 65_536), (300_000, 1)] };
        for uid in [1000, 100_000, 165_535, 300_000] {
            assert!(admit.admits(uid), "{uid}");
        }
        for uid in [0, 999, 1001, 99_999, 165_536, 299_999, 300_001, 65_534, u32::MAX] {
            assert!(!admit.admits(uid), "{uid}");
        }
        // No range at all: the uid alone.
        let alone = Admit { uid: 1000, ranges: vec![] };
        assert!(alone.admits(1000) && !alone.admits(1001));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_socket_guard_serves_an_admitted_peer_and_refuses_another() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_port = upstream.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = upstream.accept().await {
                let _ = s.write_all(b"hello").await;
            }
        });
        let policy = EgressPolicy {
            gateway: vec![],
            destinations: Policy {
                allow: DestinationSet::parse(&[format!("127.0.0.1:{up_port}")]).unwrap(),
                block: DestinationSet::default(),
            },
        };
        let dir = std::env::temp_dir().join(format!("ssai-guard-test-{}-{up_port}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // SAFETY: getuid(2) cannot fail.
        let me = unsafe { libc::getuid() };
        let ask = |path: std::path::PathBuf| async move {
            let mut s = tokio::net::UnixStream::connect(&path).await.unwrap();
            s.write_all(format!("CONNECT 127.0.0.1:{up_port} HTTP/1.1\r\n\r\n").as_bytes()).await.unwrap();
            let mut out = Vec::new();
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), s.read_to_end(&mut out)).await;
            String::from_utf8_lossy(&out).into_owned()
        };

        let admitted = dir.join("admitted.sock");
        let _guard = start_unix(policy.clone(), false, &admitted, Admit { uid: me, ranges: vec![] }).await.unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&admitted).unwrap().permissions().mode() & 0o777, 0o666);
        let served = ask(admitted).await;
        assert!(served.starts_with("HTTP/1.1 200") && served.ends_with("hello"), "{served}");

        let other = dir.join("other.sock");
        let _guard =
            start_unix(policy, false, &other, Admit { uid: me.wrapping_add(1), ranges: vec![] }).await.unwrap();
        let refused = ask(other).await;
        assert!(refused.starts_with("HTTP/1.1 403") && !refused.contains("hello"), "{refused}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

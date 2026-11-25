//! A minimal client of the sandbox's own engine (`dockerd` inside, on
//! `/var/run/docker.sock`), for init: plain std, one HTTP/1.0 exchange per
//! call (the engine then closes the connection), each bounded in time and
//! size. Init reads container states and a failed service's last log lines
//! with it; the DNS stub, a service's address.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::Value;

/// The engine's socket inside the container.
pub const SOCKET: &str = "/var/run/docker.sock";
/// The longest an exchange may take.
const TIMEOUT: Duration = Duration::from_secs(5);
/// The largest answer read (a container list of a compose project is a few KB).
const ANSWER_CAP: u64 = 4 << 20;

/// `GET path` on the engine at `socket`, its JSON body.
pub fn get(socket: &str, path: &str) -> Result<Value> {
    get_within(socket, path, TIMEOUT)
}

/// [`get`], each read and write bounded by `timeout`.
pub fn get_within(socket: &str, path: &str, timeout: Duration) -> Result<Value> {
    let bytes = exchange(socket, path, timeout, ANSWER_CAP)?;
    serde_json::from_slice(&bytes).with_context(|| format!("the engine's answer to {path}: not JSON"))
}

/// The body of `GET path`, at most `cap` bytes of answer.
fn exchange(socket: &str, path: &str, timeout: Duration, cap: u64) -> Result<Vec<u8>> {
    let mut conn = UnixStream::connect(socket).with_context(|| format!("reach the sandbox's docker engine at {socket}"))?;
    conn.set_read_timeout(Some(timeout))?;
    conn.set_write_timeout(Some(timeout))?;
    conn.write_all(format!("GET {path} HTTP/1.0\r\nHost: engine\r\n\r\n").as_bytes())?;
    // `timeout` bounds the whole answer, not each read: an engine trickling
    // bytes would otherwise hold the caller (the DNS stub) far longer.
    let deadline = std::time::Instant::now() + timeout;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 16 << 10];
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            bail!("the engine did not answer {path} within {}ms", timeout.as_millis());
        }
        conn.set_read_timeout(Some(left))?;
        let n = match conn.read(&mut chunk) {
            Ok(n) => n,
            // The read's own timeout is what is left of the deadline.
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                bail!("the engine did not answer {path} within {}ms", timeout.as_millis())
            }
            Err(e) => return Err(e).context("read the engine's answer"),
        };
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..n]);
        if raw.len() as u64 > cap {
            break;
        }
    }
    if raw.len() as u64 > cap {
        bail!("the engine's answer to {path} is larger than {cap} bytes");
    }
    body_bytes(&raw).with_context(|| format!("the engine's answer to {path}"))
}

/// The last `lines` lines of container `id`'s output, as the engine keeps
/// them (both streams, in order).
pub fn log_tail(socket: &str, id: &str, lines: u32) -> Result<String> {
    if !container_id(id) {
        bail!("{id:?} is not a container id");
    }
    let raw = exchange(socket, &format!("/containers/{id}/logs?stdout=1&stderr=1&tail={lines}"), TIMEOUT, ANSWER_CAP)?;
    Ok(String::from_utf8_lossy(&demux(&raw)).into_owned())
}

/// A container's log stream as the engine sends it without a terminal:
/// frames of `[stream, 0, 0, 0, len (u32 BE)]` + `len` bytes. A stream that is
/// not framed (a container with a terminal) is the text itself.
pub fn demux(raw: &[u8]) -> Vec<u8> {
    let framed = |mut rest: &[u8]| -> Option<Vec<u8>> {
        let mut out = Vec::new();
        while !rest.is_empty() {
            let head = rest.get(..8)?;
            if !matches!(head[0], 0..=2) || head[1..4] != [0, 0, 0] {
                return None;
            }
            let len = u32::from_be_bytes([head[4], head[5], head[6], head[7]]) as usize;
            out.extend_from_slice(rest.get(8..8 + len)?);
            rest = &rest[8 + len..];
        }
        Some(out)
    };
    framed(raw).unwrap_or_else(|| raw.to_vec())
}

/// The body of a raw HTTP answer: a 200, its body as sent, or chunked.
fn body_bytes(raw: &[u8]) -> Result<Vec<u8>> {
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").context("no end to its head")?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or_default();
    let code = status.split_whitespace().nth(1).unwrap_or_default();
    if !status.starts_with("HTTP/1.") || code != "200" {
        bail!("status {status:?}");
    }
    let chunked = lines.any(|l| {
        l.split_once(':').is_some_and(|(k, v)| k.trim().eq_ignore_ascii_case("transfer-encoding") && v.trim().eq_ignore_ascii_case("chunked"))
    });
    let rest = &raw[split + 4..];
    if chunked { dechunk(rest) } else { Ok(rest.to_vec()) }
}

fn dechunk(mut rest: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let eol = rest.windows(2).position(|w| w == b"\r\n").context("a chunk size with no end")?;
        let size = std::str::from_utf8(&rest[..eol]).ok().and_then(|s| usize::from_str_radix(s.split(';').next()?.trim(), 16).ok());
        let size = size.context("a chunk size that is not hex")?;
        rest = &rest[eol + 2..];
        if size == 0 {
            return Ok(out);
        }
        let chunk = rest.get(..size).context("a chunk shorter than its size")?;
        out.extend_from_slice(chunk);
        rest = rest.get(size + 2..).context("a chunk with no end")?;
    }
}

/// `text` percent-encoded for a query string.
pub fn encode(text: &str) -> String {
    text.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

/// Where one container stands for a run waiting on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Readiness {
    /// Running (healthy, when it has a healthcheck), or done: exited 0.
    Ready,
    /// Not yet: starting, its healthcheck not passed yet, restarting.
    Pending(String),
    /// It will not be: exited with another status, unhealthy.
    Failed(String),
}

/// A container's readiness, from its inspect answer (`State`); `must_exit`:
/// a service the primary waits on to finish, ready only once exited 0.
pub fn readiness(inspect: &Value, must_exit: bool) -> Readiness {
    let state = &inspect["State"];
    let status = state["Status"].as_str().unwrap_or_default();
    let health = state["Health"]["Status"].as_str();
    match status {
        "dead" => Readiness::Failed("is dead (the engine could not stop or remove it)".into()),
        "exited" => match state["ExitCode"].as_i64() {
            Some(0) => Readiness::Ready,
            code => Readiness::Failed(format!("exited with status {}", code.map_or("?".into(), |c| c.to_string()))),
        },
        "running" if must_exit => Readiness::Pending("running, to finish".into()),
        "running" => match health {
            None | Some("healthy") | Some("none") => Readiness::Ready,
            Some("unhealthy") => Readiness::Failed("is unhealthy".into()),
            Some(other) => Readiness::Pending(format!("health {other}")),
        },
        other => Readiness::Pending(if other.is_empty() { "starting".into() } else { other.to_string() }),
    }
}

/// The address of the compose `project`'s running service `name` (asked
/// lowercase, as DNS asks), from the engine's container list: on the
/// project's default network, else the first of its networks by name. Only a
/// private address — one the engine's bridges are drawn from — is answered:
/// the labels are the agent's to write, and the answer must never name
/// anything but a container of the sandbox's own engine.
pub fn service_address(list: &Value, project: &str, name: &str) -> Option<std::net::Ipv4Addr> {
    let default = format!("{project}_default");
    list.as_array()?
        .iter()
        .filter(|c| c["Labels"]["com.docker.compose.project"].as_str() == Some(project))
        // A `compose run` container is not the service's.
        .filter(|c| c["Labels"]["com.docker.compose.oneoff"].as_str() != Some("True"))
        .filter(|c| c["Labels"]["com.docker.compose.service"].as_str().is_some_and(|s| s.eq_ignore_ascii_case(name)))
        .find_map(|c| {
            let nets = c["NetworkSettings"]["Networks"].as_object()?;
            let mut order: Vec<&String> = nets.keys().collect();
            order.sort_by_key(|k| (**k != default, (*k).clone()));
            order.into_iter().find_map(|k| {
                let ip: std::net::Ipv4Addr = nets[k]["IPAddress"].as_str()?.parse().ok()?;
                ip.is_private().then_some(ip)
            })
        })
}

/// Whether `id` is a container id the engine would hand out (hex), and so
/// safe in a request path.
pub fn container_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::assert_matches;

    #[test]
    fn an_answer_is_read_as_sent_or_chunked_and_only_a_200() {
        assert_eq!(body_bytes(b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n[1]").unwrap(), b"[1]");
        assert_eq!(body_bytes(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n[1\r\n1;x\r\n]\r\n0\r\n\r\n").unwrap(), b"[1]");
        for bad in [&b"HTTP/1.0 404 Not Found\r\n\r\n{}"[..], b"HTTP/1.0 200 OK", b"SSH-2.0\r\n\r\n{}", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"] {
            assert!(body_bytes(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn a_service_is_ready_running_or_done_and_failed_only_for_good() {
        let s = |status: &str, health: Option<&str>, code: i64| {
            let mut state = json!({"Status": status, "ExitCode": code});
            if let Some(h) = health {
                state["Health"] = json!({"Status": h});
            }
            readiness(&json!({ "State": state }), false)
        };
        assert_eq!(s("running", None, 0), Readiness::Ready);
        assert_eq!(s("running", Some("healthy"), 0), Readiness::Ready);
        assert_matches!(s("running", Some("starting"), 0), Readiness::Pending(_));
        assert_matches!(s("running", Some("unhealthy"), 0), Readiness::Failed(_));
        // A one-shot service (a migration) that is done.
        assert_eq!(s("exited", None, 0), Readiness::Ready);
        assert_eq!(s("exited", None, 3), Readiness::Failed("exited with status 3".into()));
        // A restart policy at work is waited on: a service waiting on another
        // settles; one that never does is named, restarting, at the deadline.
        assert_matches!(s("restarting", None, 1), Readiness::Pending(_));
        assert_matches!(s("created", None, 0), Readiness::Pending(_));
        assert_matches!(s("dead", None, 0), Readiness::Failed(_), "dead is never done");
        // One the primary waits on to finish: running is not yet ready; done is.
        let migrate = |status: &str, code: i64| readiness(&json!({"State": {"Status": status, "ExitCode": code}}), true);
        assert_matches!(migrate("running", 0), Readiness::Pending(_));
        assert_eq!(migrate("exited", 0), Readiness::Ready);
        assert_matches!(migrate("exited", 2), Readiness::Failed(_));
    }

    #[test]
    fn a_log_stream_is_read_framed_or_as_it_is() {
        let frame = |stream: u8, text: &str| {
            let mut f = vec![stream, 0, 0, 0];
            f.extend_from_slice(&(text.len() as u32).to_be_bytes());
            f.extend_from_slice(text.as_bytes());
            f
        };
        let raw = [frame(1, "out\n"), frame(2, "err\n")].concat();
        assert_eq!(demux(&raw), b"out\nerr\n");
        assert_eq!(demux(b"plain text\n"), b"plain text\n", "a terminal's stream is not framed");
        let cut = &raw[..raw.len() - 2];
        assert_eq!(demux(cut), cut, "a short frame: the bytes as they are, never a panic");
    }

    #[test]
    fn a_service_name_is_answered_with_its_private_address_on_its_projects_network() {
        let c = |project: &str, svc: &str, nets: Value| json!({"Labels": {"com.docker.compose.project": project, "com.docker.compose.service": svc}, "NetworkSettings": {"Networks": nets}});
        let list = json!([
            c("other", "db", json!({"other_default": {"IPAddress": "172.20.0.9"}})),
            c("p", "db", json!({"a_net": {"IPAddress": "10.0.0.5"}, "p_default": {"IPAddress": "172.18.0.2"}})),
            c("p", "cache", json!({"b": {"IPAddress": ""}, "a": {"IPAddress": "192.168.5.4"}})),
            c("p", "evil", json!({"p_default": {"IPAddress": "140.82.112.3"}})),
            c("p", "loop", json!({"p_default": {"IPAddress": "127.0.0.1"}})),
        ]);
        assert_eq!(service_address(&list, "p", "db"), Some("172.18.0.2".parse().unwrap()), "its project's default network first");
        assert_eq!(service_address(&list, "p", "CACHE"), Some("192.168.5.4".parse().unwrap()), "else the first network with an address");
        assert_eq!(service_address(&list, "other", "db"), Some("172.20.0.9".parse().unwrap()));
        // Only a private address: a label the agent wrote never names the internet, nor loopback.
        assert_eq!(service_address(&list, "p", "evil"), None);
        assert_eq!(service_address(&list, "p", "loop"), None);
        assert_eq!(service_address(&list, "p", "nope"), None);
        assert_eq!(service_address(&json!({"message": "x"}), "p", "db"), None);
    }

    /// A socket answering one request with `answer`, then closing.
    fn answering(answer: Vec<u8>) -> String {
        let dir = std::env::temp_dir().join(format!("ssai-engine-cap-{}-{}", std::process::id(), rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            if let Some(Ok(mut conn)) = listener.incoming().next() {
                let mut req = [0u8; 256];
                let _ = conn.read(&mut req);
                let _ = conn.write_all(&answer);
            }
        });
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn an_answer_of_exactly_the_cap_is_read_and_one_byte_more_refused() {
        let head = b"HTTP/1.0 200 OK\r\n\r\n".to_vec();
        let cap = 64u64;
        let at_cap = [head.clone(), vec![b'a'; cap as usize - head.len()]].concat();
        assert_eq!(exchange(&answering(at_cap), "/x", TIMEOUT, cap).unwrap().len(), cap as usize - head.len());
        let over = [head.clone(), vec![b'a'; cap as usize - head.len() + 1]].concat();
        assert!(exchange(&answering(over), "/x", TIMEOUT, cap).is_err());
    }

    #[test]
    fn a_trickling_answer_is_cut_at_the_deadline_not_per_read() {
        let dir = std::env::temp_dir().join(format!("ssai-engine-trickle-{}-{}", std::process::id(), rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            if let Some(Ok(mut conn)) = listener.incoming().next() {
                let mut req = [0u8; 256];
                let _ = conn.read(&mut req);
                // A byte every 100ms: each read is quick, the whole is not.
                for b in b"HTTP/1.0 200 OK\r\n\r\n[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20]" {
                    if conn.write_all(&[*b]).is_err() {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        });
        let started = std::time::Instant::now();
        let err = exchange(&path.to_string_lossy(), "/x", Duration::from_millis(500), ANSWER_CAP).unwrap_err();
        assert!(format!("{err:#}").contains("did not answer"), "{err:#}");
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    }

    proptest::proptest! {
        /// Whatever the chunk sizes, a chunked body reads back as it was sent;
        /// any bytes read as a chunked body are an answer or an error, never a panic.
        #[test]
        fn a_chunked_body_reads_back(body in proptest::collection::vec(proptest::num::u8::ANY, 0..300), size in 1usize..50, junk in proptest::collection::vec(proptest::num::u8::ANY, 0..100)) {
            let mut wire = Vec::new();
            for c in body.chunks(size) {
                wire.extend_from_slice(format!("{:x}\r\n", c.len()).as_bytes());
                wire.extend_from_slice(c);
                wire.extend_from_slice(b"\r\n");
            }
            wire.extend_from_slice(b"0\r\n\r\n");
            proptest::prop_assert_eq!(dechunk(&wire).unwrap(), body);
            let _ = dechunk(&junk);
            let _ = demux(&junk);
        }
    }

    #[test]
    fn only_a_hex_id_reaches_a_request_path_and_a_query_is_encoded() {
        assert!(container_id("0123abcdef"));
        for bad in ["", "../info", "ab cd", "a/b", &"a".repeat(65)] {
            assert!(!container_id(bad), "{bad}");
        }
        assert_eq!(encode(r#"{"label":["a=b"]}"#), "%7B%22label%22%3A%5B%22a%3Db%22%5D%7D");
    }
}

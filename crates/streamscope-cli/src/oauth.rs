//! Loopback-PKCE client side of the login flow: portal-URL parsing, PKCE
//! material, the one-shot `127.0.0.1` callback listener, and browser launch.

use anyhow::{bail, Context, Result};
use base64::Engine;
use rand::Rng;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Parse `(origin, Some(slug))` out of any URL of the tenant's UI — the
/// quickstart page, the portal home, the admin console (`/t/<slug>/...`), or
/// a bare `https://host` (slug unknown). The slug is the segment following a
/// `t` segment, optionally preceded by `portal`.
pub fn parse_portal_url(input: &str) -> Result<(String, Option<String>)> {
    let url = url::Url::parse(input.trim())
        .with_context(|| format!("{input:?} is not a URL — copy it from your portal's address bar"))?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("{input:?}: only http(s) portal URLs are supported");
    }
    let host = url.host_str().context("URL has no host")?;
    let origin = match url.port() {
        Some(p) => format!("{}://{}:{}", url.scheme(), host, p),
        None => format!("{}://{}", url.scheme(), host),
    };
    let segments: Vec<&str> = url
        .path_segments()
        .map(|s| s.filter(|p| !p.is_empty()).collect())
        .unwrap_or_default();
    let slug = segments
        .windows(2)
        .find(|w| w[0] == "t")
        .map(|w| w[1].to_string());
    Ok((origin, slug))
}

/// Whether an origin is a loopback address.
///
/// The one place plaintext is defensible: nothing leaves the machine, so there
/// is no path for anyone to sit on. It is also how the gateway is developed
/// against, so refusing it would make the CLI untestable locally.
fn is_loopback_origin(origin: &str) -> bool {
    url::Url::parse(origin)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .is_some_and(|h| h == "localhost" || h == "127.0.0.1" || h == "[::1]" || h == "::1")
}

/// Check an origin the CLI discovered rather than one the user typed.
///
/// Discovery hands us an origin out of the authorization-server metadata
/// document, and everything afterwards — the token exchange, every refresh, the
/// whole portal API — is sent there. The RFC 9207 `iss` check does not cover
/// this: it compares against the `issuer` in the *same* document, so a
/// substituted document is self-consistent and passes.
///
/// Requiring TLS is what makes the document itself trustworthy. Over plaintext
/// anyone on the path can rewrite it, and the credential the CLI then posts is
/// a 30-day refresh token.
pub fn check_discovered_origin(origin: &str, what: &str) -> Result<()> {
    if origin.starts_with("https://") || is_loopback_origin(origin) || insecure_origins_allowed() {
        return Ok(());
    }
    bail!(
        "the gateway advertised {what} at {origin}, which is not https — refusing to send \
         credentials over plaintext. Ask your administrator to set the gateway's public API URL \
         to an https address. (Set STREAMSCOPE_ALLOW_INSECURE_ORIGIN=1 to override, for a \
         development gateway only.)"
    )
}

/// The deliberate opt-out, for a development or CI gateway served over plain
/// HTTP on a hostname that is not loopback.
///
/// Off unless explicitly set, so a deployment that configures nothing gets the
/// safe behaviour — the failure this guards against is silent, and inferring it
/// from anything ambient is how it stays silent.
fn insecure_origins_allowed() -> bool {
    std::env::var("STREAMSCOPE_ALLOW_INSECURE_ORIGIN").is_ok_and(|v| v == "1" || v == "true")
}

pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

/// RFC 7636 S256 material: 32 random bytes → base64url verifier (43 chars),
/// challenge = base64url(sha256(verifier)).
pub fn generate_pkce() -> Pkce {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let challenge =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    Pkce { verifier, challenge }
}

pub fn generate_state() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub struct LoopbackListener {
    listener: TcpListener,
    pub redirect_uri: String,
}

impl LoopbackListener {
    /// Bind an ephemeral port on 127.0.0.1 for the authorization-code
    /// redirect.
    pub async fn bind() -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .context("failed to bind a loopback port for the login callback")?;
        let port = listener.local_addr()?.port();
        Ok(Self {
            listener,
            redirect_uri: format!("http://127.0.0.1:{port}/callback"),
        })
    }

    /// Accept connections until one carries `code` + `state` query params
    /// (browsers often probe with favicon or preflight requests first).
    /// Returns the authorization code after verifying the `state` echo and the
    /// RFC 9207 `iss` identifying which authorization server answered.
    pub async fn receive_code(self, expected_state: &str, expected_issuer: &str) -> Result<String> {
        loop {
            let (mut stream, _) = self
                .listener
                .accept()
                .await
                .context("login callback listener failed")?;
            let mut buf = vec![0u8; 8192];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]).into_owned();

            // First line: `GET /callback?code=...&state=... HTTP/1.1`.
            let target = request
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("");
            let query = target.split_once('?').map(|(_, q)| q).unwrap_or("");
            let mut code = None;
            let mut state = None;
            let mut error = None;
            let mut issuer = None;
            for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
                match k.as_ref() {
                    "code" => code = Some(v.into_owned()),
                    "state" => state = Some(v.into_owned()),
                    "error" => error = Some(v.into_owned()),
                    "iss" => issuer = Some(v.into_owned()),
                    _ => {}
                }
            }

            if let Some(err) = error {
                respond(&mut stream, 200, "Login was denied. You can close this tab.").await;
                bail!("authorization denied: {err}");
            }
            let (Some(code), Some(state)) = (code, state) else {
                // Not the redirect (favicon etc.) — answer and keep waiting.
                respond(&mut stream, 404, "Waiting for the login redirect…").await;
                continue;
            };
            if state != expected_state {
                respond(&mut stream, 400, "Login failed (state mismatch). Close this tab and retry.").await;
                bail!("state mismatch on the login callback — possible interception, aborting");
            }
            // RFC 9207: the server names itself in the response. Checking it is
            // what tells a code minted by the server we started with from one
            // returned by a different server that intercepted the flow — the
            // mix-up attack `state` alone cannot detect, because `state` only
            // proves the response belongs to a login we started.
            //
            // A MISSING `iss` is refused, not waved through. The attacker
            // controls the redirect that reaches this listener, so treating
            // absence as "nothing to check" would let them evade the whole
            // protection by simply omitting the parameter. Our server always
            // sends it and ships in lockstep with this binary, so absence means
            // the response did not come from our server.
            let Some(issuer) = issuer else {
                respond(&mut stream, 400, "Login failed (unidentified server). Close this tab and retry.").await;
                bail!(
                    "the login callback carried no `iss` — cannot confirm it came \
                     from {expected_issuer}, aborting"
                );
            };
            if issuer != expected_issuer {
                respond(&mut stream, 400, "Login failed (wrong issuer). Close this tab and retry.").await;
                bail!(
                    "the login callback names a different authorization server \
                     ({issuer}, expected {expected_issuer}) — aborting"
                );
            }
            respond(
                &mut stream,
                200,
                "You're logged in — return to the terminal. You can close this tab.",
            )
            .await;
            return Ok(code);
        }
    }
}

async fn respond(stream: &mut tokio::net::TcpStream, status: u16, message: &str) {
    let reason = if status == 200 { "OK" } else { "Not Found" };
    let body = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Streamscope CLI</title>\
         <body style=\"font-family:system-ui;display:grid;place-items:center;height:100vh;margin:0\">\
         <p>{message}</p></body>"
    );
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// Best-effort browser launch; the caller always prints the URL too.
/// Returns `false` when no browser can possibly open — the login command
/// then falls back to the device grant.
pub fn open_browser(url: &str) -> bool {
    let candidates: &[(&str, &[&str])] = if cfg!(target_os = "macos") {
        &[("open", &[])]
    } else if cfg!(target_os = "windows") {
        // The URL handler takes the URL as one argument; `cmd /c start` would
        // parse it, and end the command at its first `&`.
        &[("rundll32", &["url.dll,FileProtocolHandler"])]
    } else {
        // Headless Linux (SSH session, server): xdg-open is often INSTALLED
        // (pulled in as a dependency) so a spawn check alone passes while
        // the launch goes nowhere — no display means no browser.
        if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
            return false;
        }
        &[("xdg-open", &[])]
    };
    for (cmd, args) in candidates {
        let mut c = std::process::Command::new(cmd);
        c.args(*args).arg(url);
        c.stdout(std::process::Stdio::null());
        c.stderr(std::process::Stdio::null());
        if c.spawn().is_ok() {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_portal_urls() {
        let (origin, slug) = parse_portal_url("https://gw.example.com/portal/t/acme/quickstart").unwrap();
        assert_eq!(origin, "https://gw.example.com");
        assert_eq!(slug.as_deref(), Some("acme"));

        let (origin, slug) = parse_portal_url("https://gw.example.com:8443/t/acme").unwrap();
        assert_eq!(origin, "https://gw.example.com:8443");
        assert_eq!(slug.as_deref(), Some("acme"));

        let (_, slug) = parse_portal_url("https://gw.example.com/").unwrap();
        assert_eq!(slug, None);

        assert!(parse_portal_url("not a url").is_err());
        assert!(parse_portal_url("ftp://gw/t/acme").is_err());
    }

    #[test]
    fn pkce_challenge_matches_server_verifier() {
        let pkce = generate_pkce();
        assert!(streamscope_mcp_auth::verify_s256_challenge(
            &pkce.verifier,
            &pkce.challenge
        ));
        assert_eq!(pkce.verifier.len(), 43);
    }

}

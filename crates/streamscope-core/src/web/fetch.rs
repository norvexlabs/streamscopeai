//! Generic HTTP fetcher for the `web_fetch` tool.
//!
//! Pipeline per fetch:
//!   1. URL filter chain (policy first; runs in the service layer).
//!   2. Initial-URL scheme + IP-literal guard via
//!      [`streamscope_mcp_auth::ssrf::check_url`].
//!   3. One [`reqwest::Client`] for the whole fetch — including every
//!      redirect hop — backed by a [`streamscope_mcp_auth::ssrf::GuardedResolver`]
//!      that re-vets each resolved name against the internal-address list.
//!      `Policy::custom` enforces the [`MAX_REDIRECTS`] cap and records the
//!      chain for audit.
//!   4. GET with bounded body read (`web_search.fetch_max_bytes`); abort
//!      with [`super::WebError::Oversized`] beyond the cap.
//!   5. Tag-strip + entity-decode + whitespace-normalise to "extracted_text"
//!      when content-type is `text/html`. Other text content types pass
//!      through. Binary content types return the byte length only (no
//!      extraction).

use std::sync::{Arc, Mutex};

use reqwest::redirect::Policy;
use streamscope_mcp_auth::egress::Surface;
use streamscope_mcp_auth::ssrf::{
    check_url_for, redirect_target_is_internal_ip_literal, Egress, GuardedResolver, SsrfError,
};

/// What a fetch may reach: an internal address only when the platform's `web`
/// egress list lists it.
const EGRESS: Egress = Egress::Surface(Surface::Web);

use super::types::{FetchRequest, FetchResult, WebError};

/// Max redirect hops the fetcher follows. Tight on purpose — most
/// legitimate fetches don't need more than 2–3 hops.
pub const MAX_REDIRECTS: usize = 5;

/// Built-in fetcher. SSRF + bounded body + extraction. Returns the result
/// and the raw body bytes (caller persists raw bytes into
/// `audit_media_blobs` when `media_blob_storage_enabled`).
///
/// An internal target (RFC 1918 / loopback / link-local) is reached only when
/// the platform's `web` egress list lists it; the scheme allowlist (http /
/// https only) is always enforced, and IMDS is refused whatever the list says.
pub async fn fetch_builtin(
    req: &FetchRequest,
    cap_bytes: u64,
) -> Result<(FetchResult, bytes::Bytes), WebError> {
    let cap = req.max_bytes.unwrap_or(cap_bytes).min(cap_bytes);

    // Initial-URL guard: scheme is always enforced; an IP-literal internal is
    // refused unless listed, and IMDS always (the connector never hands a
    // literal to the resolver, so this is its only check). Hostnames pass this
    // layer and are re-checked by `GuardedResolver` at DNS resolution time
    // (which also runs on every redirect hop).
    let parsed_initial = check_url_for(&req.url, EGRESS).map_err(map_ssrf)?;

    let (resolver, refusal_handle) = GuardedResolver::pair(EGRESS);

    // Custom redirect policy: cap at MAX_REDIRECTS, refuse IP-literal targets
    // that would bypass the DNS resolver (hyper-util's connector parses
    // IP-literal hosts directly and skips `dns::Resolve`, so `GuardedResolver`
    // never sees them), and record the URL that returned each 3xx into
    // `redirect_chain` for audit (preserves the pre-existing audit shape —
    // chain entries are the URLs that 3xx'd, the final URL lives separately
    // in `final_url`). `policy_refusal` is a second side-channel for the
    // IP-literal refusal so the error path can promote it to typed
    // `SsrfRefused`.
    let redirect_chain = Arc::new(Mutex::new(Vec::<String>::new()));
    let chain_for_policy = redirect_chain.clone();
    let policy_refusal: Arc<Mutex<Option<SsrfError>>> = Arc::new(Mutex::new(None));
    let policy_refusal_for_closure = policy_refusal.clone();
    let policy = Policy::custom(move |attempt| {
        // `previous()` is the slice of URLs already visited (initial + each
        // hop that 3xx'd). To allow at most MAX_REDIRECTS redirects, refuse
        // once `previous().len() > MAX_REDIRECTS`.
        if attempt.previous().len() > MAX_REDIRECTS {
            return attempt.error(format!("redirect limit ({MAX_REDIRECTS}) exceeded"));
        }
        // IP-literal targets bypass `GuardedResolver`. Re-apply the
        // internal-IP check here.
        if redirect_target_is_internal_ip_literal(attempt.url(), EGRESS) {
            *policy_refusal_for_closure.lock().unwrap() = Some(SsrfError::InternalAddress);
            return attempt.error("internal redirect target refused");
        }
        if let Some(prev) = attempt.previous().last() {
            chain_for_policy.lock().unwrap().push(prev.to_string());
        }
        attempt.follow()
    });

    let client = crate::tls::add_custom_roots(
        reqwest::Client::builder()
            .dns_resolver(resolver)
            .redirect(policy)
            .timeout(crate::settings::core_settings().web_fetch_timeout),
        crate::settings::core_settings().custom_ca_bundle.as_deref(),
    )
    .build()
    .map_err(|e| WebError::Internal(format!("client build: {e}")))?;

    let resp = match client
        .get(parsed_initial.clone())
        .header(reqwest::header::USER_AGENT, "streamscope-web/1")
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            // Promote a guard refusal to typed SsrfRefused before falling
            // back to generic transport. The resolver (hostname targets)
            // and the redirect policy (IP-literal targets) each stash the
            // typed error into their slot when refusing.
            if let Some(ssrf_err) = refusal_handle.take_refusal() {
                return Err(map_ssrf(ssrf_err));
            }
            if let Some(ssrf_err) = policy_refusal.lock().unwrap().take() {
                return Err(map_ssrf(ssrf_err));
            }
            if e.is_redirect() {
                return Err(WebError::UpstreamError {
                    status: None,
                    detail: format!("redirect limit ({MAX_REDIRECTS}) exceeded"),
                });
            }
            return Err(WebError::Transport(e.to_string()));
        }
    };

    let status = resp.status();
    let final_url = resp.url().clone();

    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();

    let bytes = read_capped_body(resp, cap).await?;
    let raw_size = bytes.len();
    let extracted = if is_html(&content_type) {
        extract_text_from_html(&bytes)
    } else if is_text(&content_type) {
        String::from_utf8_lossy(&bytes).into_owned()
    } else {
        format!("[binary content: type={content_type}, size={raw_size} bytes]")
    };
    let extracted_size = extracted.len();

    let redirect_chain = redirect_chain.lock().unwrap().clone();

    Ok((
        FetchResult {
            url: req.url.clone(),
            final_url: final_url.to_string(),
            content_type,
            status: status.as_u16(),
            extracted_text: extracted,
            redirect_chain,
            extracted_size,
            raw_size,
        },
        bytes,
    ))
}

/// Stream the response body with a hard byte cap, mapping the shared
/// [`crate::http_body`] errors onto [`WebError`]. A hostile target advertising
/// a huge body never makes the gateway buffer it — the read aborts the moment
/// the cumulative length crosses `cap`.
async fn read_capped_body(
    resp: reqwest::Response,
    cap: u64,
) -> Result<bytes::Bytes, WebError> {
    crate::http_body::read_body_capped(resp, cap).await.map_err(|e| match e {
        crate::http_body::CappedReadError::Oversized { limit_bytes } => {
            WebError::Oversized { limit_bytes }
        }
        crate::http_body::CappedReadError::Transport(e) => {
            WebError::Transport(format!("read body: {e}"))
        }
    })
}

/// The [`WebError`] a refusal by the shared SSRF guard surfaces as.
pub(crate) fn map_ssrf(e: SsrfError) -> WebError {
    match e {
        SsrfError::BadScheme => WebError::SchemeRefused("non-http(s)".into()),
        SsrfError::UrlParse(s) => WebError::InvalidUrl(s),
        SsrfError::MissingHost => WebError::InvalidUrl("missing host".into()),
        SsrfError::InternalAddress => WebError::SsrfRefused("internal address".into()),
        SsrfError::DnsLookup(s) => WebError::SsrfRefused(format!("dns: {s}")),
        SsrfError::NoAddresses => WebError::SsrfRefused("no addresses".into()),
        SsrfError::PlainHttp => WebError::SsrfRefused("plain http to a public address".into()),
    }
}

fn is_html(ct: &str) -> bool {
    ct.starts_with("text/html") || ct.starts_with("application/xhtml")
}

fn is_text(ct: &str) -> bool {
    ct.starts_with("text/")
        || ct.starts_with("application/json")
        || ct.starts_with("application/xml")
        || ct.contains("+json")
        || ct.contains("+xml")
}

/// Cheap HTML→text extraction. Strips `<script>` and `<style>` blocks,
/// removes all remaining tags, decodes a small set of HTML entities, and
/// normalises whitespace. Good enough for a phase-1 default; Tavily's
/// `extract` API or a real readability port lands in phase 2.
pub fn extract_text_from_html(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes).into_owned();

    // Strip `<script>...</script>` and `<style>...</style>` (case-insensitive)
    // including their bodies. Without this, JS source pollutes the extract.
    let s = strip_block(&s, "script");
    let s = strip_block(&s, "style");

    // Strip remaining tags.
    let mut out = String::with_capacity(s.len() / 2);
    let mut in_tag = false;
    for ch in s.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }

    // Decode common entities.
    let decoded = decode_entities(&out);

    // Collapse runs of whitespace; preserve paragraph breaks.
    collapse_whitespace(&decoded)
}

fn strip_block(s: &str, tag: &str) -> String {
    let lower = s.to_ascii_lowercase();
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut out = String::with_capacity(s.len());
    let mut idx = 0;
    while idx < s.len() {
        if let Some(rel) = lower[idx..].find(&open) {
            let abs = idx + rel;
            out.push_str(&s[idx..abs]);
            // Find the closing `>` of the opening tag.
            let after_open_lt = abs + 1;
            let scan_lower = &lower[after_open_lt..];
            let Some(open_close_rel) = scan_lower.find('>') else {
                // Malformed; emit rest verbatim and stop.
                out.push_str(&s[abs..]);
                return out;
            };
            let after_open_tag = after_open_lt + open_close_rel + 1;
            // Find `</tag>` after the opening tag.
            if let Some(close_rel) = lower[after_open_tag..].find(&close) {
                idx = after_open_tag + close_rel + close.len();
            } else {
                // No closing — drop the rest of the document.
                return out;
            }
        } else {
            out.push_str(&s[idx..]);
            return out;
        }
    }
    out
}

fn decode_entities(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#039;", "'")
        .replace("&apos;", "'")
        .replace("&nbsp;", " ")
}

fn collapse_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_was_space = false;
    let mut blank_lines = 0;
    for line in s.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if blank_lines == 0 && !out.is_empty() {
                out.push('\n');
            }
            blank_lines += 1;
            last_was_space = false;
            continue;
        }
        blank_lines = 0;
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        for ch in trimmed.chars() {
            if ch.is_whitespace() {
                if !last_was_space {
                    out.push(' ');
                    last_was_space = true;
                }
            } else {
                out.push(ch);
                last_was_space = false;
            }
        }
    }
    out.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    #[test]
    fn extract_strips_script_and_style() {
        let html = b"<html><head><style>body{color:red}</style></head>\
            <body><p>Hello</p><script>alert('x')</script></body></html>";
        let out = extract_text_from_html(html);
        assert!(!out.contains("color:red"));
        assert!(!out.contains("alert"));
        assert!(out.contains("Hello"));
    }

    #[test]
    fn extract_decodes_entities() {
        let html = b"<p>Tom &amp; Jerry &lt;rocks&gt; &nbsp;here</p>";
        let out = extract_text_from_html(html);
        assert!(out.contains("Tom & Jerry"));
        assert!(out.contains("<rocks>"));
    }

    #[test]
    fn extract_collapses_whitespace() {
        let html = b"<p>line1</p>\n\n\n<p>line2   spaces</p>";
        let out = extract_text_from_html(html);
        // Single blank between paragraphs, single space inside a line.
        assert!(out.contains("line1"));
        assert!(out.contains("line2 spaces"));
        assert!(!out.contains("line2   spaces"));
    }

    #[test]
    fn extract_handles_malformed_input_without_panic() {
        let html = b"<p>unclosed <script>alert(1)";
        let _ = extract_text_from_html(html);
    }

    #[test]
    fn is_html_classifier() {
        assert!(is_html("text/html"));
        assert!(is_html("text/html; charset=utf-8"));
        assert!(is_html("application/xhtml+xml"));
        assert!(!is_html("application/json"));
    }

    #[test]
    fn redirect_ip_literal_refused_when_internal() {
        let u = reqwest::Url::parse("http://127.0.0.1/x").unwrap();
        assert!(redirect_target_is_internal_ip_literal(&u, Egress::PublicOnly));
        let u = reqwest::Url::parse("http://10.0.0.1/x").unwrap();
        assert!(redirect_target_is_internal_ip_literal(&u, Egress::PublicOnly));
        let u = reqwest::Url::parse("http://169.254.169.254/imds").unwrap();
        assert!(redirect_target_is_internal_ip_literal(&u, Egress::PublicOnly));
        let u = reqwest::Url::parse("http://[::1]/x").unwrap();
        assert!(redirect_target_is_internal_ip_literal(&u, Egress::PublicOnly));
    }

    #[test]
    fn redirect_ip_literal_allowed_when_public() {
        let u = reqwest::Url::parse("http://1.1.1.1/x").unwrap();
        assert!(!redirect_target_is_internal_ip_literal(&u, Egress::PublicOnly));
        let u = reqwest::Url::parse("http://example.com/x").unwrap();
        // Hostname → false here (resolver path handles it).
        assert!(!redirect_target_is_internal_ip_literal(&u, Egress::PublicOnly));
    }

    /// `web` lists every private address (`crate::test_egress`).
    fn list_every_private_address_for_web() {
        crate::test_egress::install();
    }

    #[test]
    fn a_listed_internal_literal_is_followed() {
        list_every_private_address_for_web();
        let u = reqwest::Url::parse("http://127.0.0.1/x").unwrap();
        assert!(!redirect_target_is_internal_ip_literal(&u, EGRESS));
    }

    #[tokio::test]
    async fn the_metadata_literal_is_refused_with_every_private_address_listed() {
        list_every_private_address_for_web();
        for url in ["http://169.254.169.254/latest/meta-data", "http://[fd00:ec2::254]/"] {
            let req = FetchRequest { url: url.to_string(), max_bytes: None };
            assert_matches!(fetch_builtin(&req, 1024).await, Err(WebError::SsrfRefused(_)), "{url}");
        }
    }

    #[test]
    fn is_text_classifier() {
        assert!(is_text("text/plain"));
        assert!(is_text("application/json"));
        assert!(is_text("application/ld+json"));
        assert!(is_text("text/markdown"));
        assert!(!is_text("application/octet-stream"));
        assert!(!is_text("image/png"));
    }
}

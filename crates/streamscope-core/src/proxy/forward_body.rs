//! The body a raw-bytes forward sends upstream — the media endpoints and the
//! catch-all `/v1/*`, which skip the request phase and forward the client's
//! bytes rather than a re-serialised wire struct.
//!
//! Two jobs, both done here so neither path can forget one:
//! - remove every [`GATEWAY_OWNED_WIRE_FIELDS`] member the client set, in each
//!   body shape an upstream would read a field from (JSON object, multipart
//!   form, URL-encoded form);
//! - on a routed media target, name the TARGET's upstream model in `model`, not
//!   the client's alias.
//!
//! A body is re-encoded only when one of those changed something; otherwise
//! the client's bytes go out untouched. A body in a shape that could carry a
//! field but cannot be read is REFUSED rather than forwarded unchecked: an
//! upstream's parser is more lenient than serde (Python's `json` accepts
//! `NaN`), so "we could not parse it" does not mean "nor can they". A body
//! with NO content type is read as JSON, as the engines read it.
//!
//! A form is read the way its upstream's parser may read it, not only the way
//! the RFC does: a field is removed if ANY reading names it. A multipart part's
//! name is read under RFC 7230/2231 and under Python's `email` package (what
//! python-multipart uses, behind Starlette and FastAPI); a URL-encoded body
//! whose `;` would separate a gateway-owned field is refused.
//!
//! Not claimed: nested occurrences are left alone (these fields are top-level
//! only on every engine that reads them), a form parser reading neither way is
//! not modelled, and a content type outside the three shapes is forwarded
//! opaque — no engine reads a body field from it.

use bytes::Bytes;
use serde_json::Value;

use crate::api::{strip_gateway_owned_json, GATEWAY_OWNED_WIRE_FIELDS};
use crate::error::AppError;

/// The prepared body plus what was removed from it (for the audit marker).
#[derive(Debug)]
pub struct ForwardBody {
    pub bytes: Bytes,
    /// `(field, value)` for each removed gateway-owned field, value rendered
    /// as text.
    pub removed: Vec<(&'static str, String)>,
}

impl ForwardBody {
    fn unchanged(body: &Bytes) -> Self {
        Self { bytes: body.clone(), removed: Vec::new() }
    }

    /// The audit `transform_diff` recording what was removed, or `None` when
    /// nothing was.
    pub fn audit_diff(&self) -> Option<Value> {
        if self.removed.is_empty() {
            return None;
        }
        let blocks: Vec<_> = self.removed.iter().map(|(f, v)| removed_field_block(f, v)).collect();
        Some(serde_json::json!({ "injection_blocks": blocks }))
    }
}

/// The audit marker for one removed gateway-owned field — the single shape
/// every forward path records, so the audit view renders them alike.
pub fn removed_field_block(field: &str, value: &str) -> crate::proxy::content::InjectionBlock {
    crate::proxy::content::InjectionBlock {
        transform: "gateway_owned_field".to_string(),
        scope: "params".to_string(),
        field: field.to_string(),
        action: "remove".to_string(),
        content: crate::error::truncate_error_detail(value, 200),
    }
}

/// How much of a removed value is kept for the audit marker. The marker shows
/// 200 bytes of it; a hostile multi-megabyte value is never copied in full
/// just to be cut there.
const REMOVED_VALUE_CAPTURE: usize = 256;

/// The text of a removed value, at most [`REMOVED_VALUE_CAPTURE`] bytes of it.
fn capture_bytes(raw: &[u8]) -> String {
    String::from_utf8_lossy(&raw[..raw.len().min(REMOVED_VALUE_CAPTURE)]).into_owned()
}

/// A writer that keeps the first [`REMOVED_VALUE_CAPTURE`] bytes and then
/// refuses, so a serialiser writing into it stops there.
struct CappedWriter(Vec<u8>);

impl std::io::Write for CappedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let room = REMOVED_VALUE_CAPTURE - self.0.len();
        if room == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        let n = buf.len().min(room);
        self.0.extend_from_slice(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A removed JSON value as text for the audit marker — serialisation stops
/// once [`REMOVED_VALUE_CAPTURE`] bytes are written.
pub fn capture_json(value: &Value) -> String {
    let mut w = CappedWriter(Vec::with_capacity(REMOVED_VALUE_CAPTURE));
    // The error a full buffer raises is how serialisation stops early; what
    // was written up to it is the capture.
    let _ = serde_json::to_writer(&mut w, value);
    capture_bytes(&w.0)
}

/// Prepare `body` (sent with `content_type`) for an upstream. `target_model`
/// is the routed target's upstream model name, or `None` where the path has
/// no model routing (catch-all).
pub fn prepare(
    body: &Bytes,
    content_type: &str,
    target_model: Option<&str>,
) -> Result<ForwardBody, AppError> {
    let mime = content_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    if mime == "multipart/form-data" {
        let boundary = multipart_boundary(content_type)?;
        return prepare_multipart(body, &boundary, target_model);
    }
    if mime == "application/x-www-form-urlencoded" {
        return prepare_urlencoded(body, target_model);
    }
    if mime.is_empty() || mime == "application/json" || (mime.starts_with("application/") && mime.ends_with("+json")) {
        return prepare_json(body, target_model);
    }
    Ok(ForwardBody::unchanged(body))
}

fn prepare_json(body: &Bytes, target_model: Option<&str>) -> Result<ForwardBody, AppError> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(ForwardBody::unchanged(body));
    }
    let mut value: Value = serde_json::from_slice(body)
        .map_err(|_| AppError::BadRequest("request body is not valid JSON".to_string()))?;
    let removed: Vec<(&'static str, String)> = strip_gateway_owned_json(&mut value)
        .into_iter()
        .map(|(f, v)| (f, capture_json(&v)))
        .collect();
    let mut changed = !removed.is_empty();
    if let (Some(model), Some(obj)) = (target_model, value.as_object_mut())
        && obj.get("model").and_then(Value::as_str) != Some(model)
    {
        obj.insert("model".to_string(), Value::String(model.to_string()));
        changed = true;
    }
    if !changed {
        return Ok(ForwardBody::unchanged(body));
    }
    let bytes = serde_json::to_vec(&value)
        .map_err(|e| AppError::Internal(format!("re-encode forward body: {e}")))?;
    Ok(ForwardBody { bytes: Bytes::from(bytes), removed })
}

fn prepare_urlencoded(body: &Bytes, target_model: Option<&str>) -> Result<ForwardBody, AppError> {
    let out = rewrite_urlencoded(body, target_model);
    if semicolon_carries_an_owned_field(&out.bytes) {
        return Err(AppError::BadRequest(
            "form body separates a gateway-owned field with ';' — encode ';' as %3B".to_string(),
        ));
    }
    Ok(out)
}

/// Whether a gateway-owned field is a key of `body` when `;` ALSO separates
/// pairs. python-multipart (behind Starlette and FastAPI forms) splits on `;`
/// where no `&` follows, so a field hidden that way is read by the upstream
/// while the `&`-only parse above never sees it. Splitting on every `;` is a
/// superset of what any such parser reads, so this can refuse a body a
/// stricter upstream would have read as one value — never pass one it reads
/// as the field. A conforming encoder writes `;` as `%3B`.
fn semicolon_carries_an_owned_field(body: &[u8]) -> bool {
    body.contains(&b';')
        && body.split(|&b| b == b'&' || b == b';').any(|pair| {
            url::form_urlencoded::parse(pair).any(|(k, _)| GATEWAY_OWNED_WIRE_FIELDS.contains(&k.as_ref()))
        })
}

fn rewrite_urlencoded(body: &Bytes, target_model: Option<&str>) -> ForwardBody {
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(body)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let mut removed = Vec::new();
    let mut kept = Vec::with_capacity(pairs.len());
    let mut changed = false;
    let mut saw_model = false;
    for (k, v) in pairs {
        if let Some(&field) = GATEWAY_OWNED_WIRE_FIELDS.iter().find(|f| **f == k) {
            removed.push((field, capture_bytes(v.as_bytes())));
            changed = true;
            continue;
        }
        if k == "model" && let Some(m) = target_model {
            saw_model = true;
            if v != m {
                changed = true;
                kept.push((k, m.to_string()));
                continue;
            }
        }
        kept.push((k, v));
    }
    if let Some(m) = target_model && !saw_model {
        kept.push(("model".to_string(), m.to_string()));
        changed = true;
    }
    if !changed {
        return ForwardBody::unchanged(body);
    }
    let encoded = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(kept).finish();
    ForwardBody { bytes: Bytes::from(encoded), removed }
}

/// The `boundary` parameter of a multipart content type (quoted or not).
///
/// Read the way an upstream may read it — RFC 7230/2231 and Python's `email`
/// package (python-multipart: last value wins, `"`-balancing split, `<…>`,
/// RFC 2231 continuations) — and EVERY occurrence under either reading must
/// name the same boundary. Otherwise the body is refused: split on another
/// boundary, the upstream would read parts this forward never inspected (they
/// would sit in what it takes for the preamble).
pub(crate) fn multipart_boundary(content_type: &str) -> Result<String, AppError> {
    let mut seen = rfc_param_values(content_type, "boundary");
    seen.extend(email_param_values(content_type, "boundary"));
    seen.sort();
    seen.dedup();
    match seen.as_slice() {
        [one] if is_rfc2046_boundary(one) => Ok(one.clone()),
        [one] if !one.is_empty() => {
            Err(AppError::BadRequest("multipart boundary uses characters RFC 2046 does not allow".to_string()))
        }
        [] | [_] => Err(AppError::BadRequest("multipart body has no boundary".to_string())),
        _ => Err(AppError::BadRequest("multipart content type names more than one boundary".to_string())),
    }
}

/// One part of a multipart body, as raw bytes (headers + CRLFCRLF + content).
struct Part<'a> {
    raw: &'a [u8],
    /// Where the content starts in `raw` (after the header block's CRLFCRLF).
    content_start: usize,
    /// Every name any reading gives the part (for the gateway-owned removal).
    names: Vec<String>,
    /// The name each reading SETTLES on, per Content-Disposition line — the one
    /// an upstream using that reading would act on.
    settled: Vec<Option<String>>,
}

impl Part<'_> {
    fn content(&self) -> &[u8] {
        &self.raw[self.content_start..]
    }

    /// Whether every reading settles on `field` — `Some(true)` when all do,
    /// `Some(false)` when none does, `None` when they disagree (a part one
    /// parser reads as `field` and another does not).
    fn settles_on(&self, field: &str) -> Option<bool> {
        let hits = self.settled.iter().filter(|s| s.as_deref() == Some(field)).count();
        match hits {
            0 => Some(false),
            n if n == self.settled.len() => Some(true),
            _ => None,
        }
    }
}

/// Split a multipart body into its preamble, parts and epilogue.
///
/// A delimiter is `--boundary` at the start of the body or right after a CRLF,
/// optionally followed by transport padding (spaces/tabs) before its CRLF; the
/// close delimiter is `--boundary--`. Anything that does not fit is refused.
fn split_multipart<'a>(body: &'a [u8], boundary: &str) -> Option<(&'a [u8], Vec<Part<'a>>, &'a [u8])> {
    let delim = format!("--{boundary}");
    let d = delim.as_bytes();
    // A delimiter starts the body or follows a CRLF, so only the byte after
    // each `\n` is a candidate: one pass over the body, not a comparison at
    // every offset (an audio upload runs to tens of megabytes).
    // The scan walks the `\n` positions themselves, so it ends by construction
    // (a boundary holds no newline — it comes from a header line).
    let mut positions = Vec::new();
    if body.starts_with(d) {
        positions.push(0);
    }
    for (nl, _) in body.iter().enumerate().filter(|(_, b)| **b == b'\n') {
        let p = nl + 1;
        if body[..nl].ends_with(b"\r") && body[p..].starts_with(d) {
            positions.push(p);
        }
    }
    let (&first, rest) = positions.split_first()?;
    let preamble = &body[..first];
    // A lenient parser (python-multipart skips leading CR/LF; Go's reader scans
    // the preamble for a delimiter line) can find parts in a preamble this scan
    // does not: one holding the delimiter is refused, never forwarded unread.
    if find(preamble, d).is_some() {
        return None;
    }
    let mut parts = Vec::new();
    let mut cursor = first;
    for &next in rest.iter() {
        // After the delimiter: optional padding, then CRLF, then the part.
        let mut j = cursor + d.len();
        if body[j..].starts_with(b"--") {
            // A close delimiter before the last one: malformed.
            return None;
        }
        while matches!(body.get(j), Some(b' ' | b'\t')) {
            j += 1;
        }
        if !body[j..].starts_with(b"\r\n") {
            return None;
        }
        j += 2;
        // The part ends at the CRLF that precedes the next delimiter.
        let end = next.checked_sub(2)?;
        // None when the part is shorter than its own CRLF (j past end).
        let raw = body.get(j..end)?;
        // Every form part carries a header block; one without is not read.
        let header_end = find(raw, b"\r\n\r\n")?;
        let headers = std::str::from_utf8(&raw[..header_end]).ok()?;
        let (names, settled) = disposition_names(headers);
        parts.push(Part { raw, content_start: header_end + 4, names, settled });
        cursor = next;
    }
    // The last delimiter must be the close delimiter.
    if !body[cursor + d.len()..].starts_with(b"--") {
        return None;
    }
    let epilogue = &body[cursor..];
    Some((preamble, parts, epilogue))
}

/// The value of the multipart field named `field` (as an RFC parser settles
/// the name), read by the same parser the forward rewrites with — so what
/// routing reads and what goes upstream cannot disagree. `None` when the body
/// is not a readable multipart form or carries no such field.
pub(crate) fn multipart_field(body: &[u8], content_type: &str, field: &str) -> Option<String> {
    let boundary = multipart_boundary(content_type).ok()?;
    let (_, parts, _) = split_multipart(body, &boundary)?;
    parts
        .iter()
        .find(|p| p.settles_on(field) == Some(true))
        .map(|p| String::from_utf8_lossy(p.content()).trim().to_string())
        .filter(|v| !v.is_empty())
}

/// RFC 2046 `boundary`: 1 to 70 of its characters, not ending in a space. A
/// boundary outside it (a lossy-decoded `boundary*`, a stray quote) could be
/// split differently by an upstream, so it is refused rather than read.
fn is_rfc2046_boundary(b: &str) -> bool {
    (1..=70).contains(&b.len())
        && !b.ends_with(' ')
        && b.bytes().all(|c| c.is_ascii_alphanumeric() || b"'()+_,-./:=? ".contains(&c))
}

/// Every name the part's Content-Disposition can be read as carrying, under
/// each reading an upstream applies: Python's `email` package first
/// ([`email_disposition_names`]), then RFC 7230/2231 — so `names.last()` is
/// the name an RFC parser settles on. A gateway-owned field is removed when
/// ANY reading names it.
fn disposition_names(headers: &str) -> (Vec<String>, Vec<Option<String>>) {
    let mut names = Vec::new();
    let mut settled = Vec::new();
    for line in headers.split("\r\n") {
        let Some((key, value)) = line.split_once(':') else { continue };
        if !key.trim().eq_ignore_ascii_case("content-disposition") {
            continue;
        }
        let email = email_disposition_names(value);
        let rfc = rfc_disposition_names(value);
        settled.push(email.last().cloned());
        settled.push(rfc.last().cloned());
        names.extend(email);
        names.extend(rfc);
    }
    (names, settled)
}

/// The `name` / `name*` values of one Content-Disposition under RFC
/// 7230/2231: `;` splits only outside quotes, `name*` is
/// charset'language'percent-encoded.
fn rfc_disposition_names(value: &str) -> Vec<String> {
    rfc_param_values(value, "name")
}

/// Every value of parameter `param` (lowercase) in a header value under RFC
/// 7230/2231 — `param` itself, and `param*` percent-decoded.
fn rfc_param_values(value: &str, param: &str) -> Vec<String> {
    let extended = format!("{param}*");
    let mut values = Vec::new();
    for p in split_params(value).into_iter().skip(1) {
        let Some((k, v)) = p.split_once('=') else { continue };
        let k = k.trim().to_ascii_lowercase();
        let v = v.trim();
        if k == param {
            values.push(unquote(v));
        } else if k == extended {
            let encoded = v.splitn(3, '\'').nth(2).unwrap_or(v);
            values.push(percent_encoding::percent_decode_str(&unquote(encoded)).decode_utf8_lossy().into_owned());
        }
    }
    values
}

/// The `name` values of one Content-Disposition as Python's `email` package
/// reads it (`Message.get_params`) — the parser python-multipart hands a
/// part's header to, behind Starlette and FastAPI forms. It departs from RFC
/// 7230 where a client can aim at it: the `;` split balances `"` against `\"`
/// counted ANYWHERE, outside quotes too; `<value>` unquotes; and RFC 2231
/// continuations (`name*0`, `name*1*`) join into one value. Every value it
/// could settle on is returned, not only the one that wins.
fn email_disposition_names(value: &str) -> Vec<String> {
    email_param_values(value, "name")
}

/// Every value of parameter `param` (lowercase) in a header value as Python's
/// `email` package reads it — see [`email_disposition_names`].
fn email_param_values(value: &str, param: &str) -> Vec<String> {
    let continuation = format!("{param}*");
    let mut names = Vec::new();
    // (number, value, percent-encoded) for each `param*` / `param*N` / `param*N*`.
    let mut pieces: Vec<(Option<u64>, String, bool)> = Vec::new();
    for p in email_split_params(value).into_iter().skip(1) {
        let (k, v) = p.split_once('=').unwrap_or((p, ""));
        let k = k.trim().to_ascii_lowercase();
        let v = email_unquote(v.trim());
        if k == param {
            names.push(v);
        } else if let Some(num) = k.strip_prefix(continuation.as_str()).and_then(continuation_number) {
            pieces.push((num, v, k.ends_with('*')));
        }
    }
    if !pieces.is_empty() {
        // Ordered as Python orders the tuples: by number, then by the value
        // as written (before decoding).
        pieces.sort();
        let extended = pieces.iter().any(|p| p.2);
        let mut joined: Vec<u8> = Vec::new();
        for (_, v, encoded) in pieces {
            if encoded {
                joined.extend(percent_encoding::percent_decode_str(&v));
            } else {
                joined.extend_from_slice(v.as_bytes());
            }
        }
        // An extended value is charset'language'value; without both ticks it
        // is kept whole.
        let value = match extended.then(|| joined.splitn(3, |&b| b == b'\'').nth(2)).flatten() {
            Some(v) => v.to_vec(),
            None => joined,
        };
        names.push(String::from_utf8_lossy(&value).into_owned());
    }
    names
}

/// What follows `name*` in an RFC 2231 continuation key: nothing (`name*`),
/// a number (`name*0`) or a number and `*` (`name*0*`). `Some(None)` for the
/// first, `Some(Some(n))` for the others, `None` for a key that is not one.
fn continuation_number(rest: &str) -> Option<Option<u64>> {
    let digits = rest.strip_suffix('*').unwrap_or(rest);
    if rest.is_empty() {
        return Some(None);
    }
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(Some(digits.parse().unwrap_or(u64::MAX)))
}

/// `email.message._parseparam`: split on `;`, extending a segment past each
/// `;` while its count of `"` minus its count of `\"` is odd (an empty segment
/// is never odd, as Python's `end > 0` has it).
fn email_split_params(value: &str) -> Vec<&str> {
    // One pass: the parity of the segment's `"` not preceded by `\` (Python's
    // count of `"` minus its count of `\"`) is carried across a skipped `;`,
    // never recounted — a header of `x="` and a million `;` stays linear.
    let mut out = Vec::new();
    let mut start = 0;
    let mut odd = false;
    let mut prev: Option<char> = None;
    for (i, c) in value.char_indices() {
        match c {
            '"' if prev != Some('\\') => odd = !odd,
            ';' if !odd => {
                out.push(value[start..i].trim());
                start = i + 1;
                prev = None;
                continue;
            }
            _ => {}
        }
        prev = Some(c);
    }
    out.push(value[start..].trim());
    out
}

/// `email.utils.unquote`: strip `"…"` (unescaping `\\` then `\"`) or `<…>`.
fn email_unquote(v: &str) -> String {
    if v.len() > 1 {
        if let Some(inner) = v.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
            return inner.replace("\\\\", "\\").replace("\\\"", "\"");
        }
        if let Some(inner) = v.strip_prefix('<').and_then(|s| s.strip_suffix('>')) {
            return inner.to_string();
        }
    }
    v.to_string()
}

/// Split a header value on `;` outside double quotes.
fn split_params(value: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut start, mut quoted, mut escaped) = (0, false, false);
    for (i, c) in value.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ';' if !quoted => {
                out.push(&value[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&value[start..]);
    out
}

fn unquote(v: &str) -> String {
    let v = v.trim();
    match v.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        Some(inner) => inner.replace("\\\"", "\"").replace("\\\\", "\\"),
        None => v.to_string(),
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn prepare_multipart(body: &Bytes, boundary: &str, target_model: Option<&str>) -> Result<ForwardBody, AppError> {
    let (preamble, parts, epilogue) = split_multipart(body, boundary)
        .ok_or_else(|| AppError::BadRequest("multipart body could not be parsed".to_string()))?;

    let mut removed = Vec::new();
    let mut changed = false;
    let mut saw_model = false;
    // Each kept part as borrowed pieces (its bytes, or its header + a new
    // value): an upload of tens of megabytes is copied once, into the output,
    // and only when something changed.
    let mut out: Vec<[&[u8]; 2]> = Vec::with_capacity(parts.len() + 1);
    for part in &parts {
        if let Some(&field) = GATEWAY_OWNED_WIRE_FIELDS.iter().find(|f| part.names.iter().any(|n| n == *f)) {
            removed.push((field, capture_bytes(part.content())));
            changed = true;
            continue;
        }
        let is_model = part.settles_on("model").ok_or_else(|| {
            AppError::BadRequest("a multipart part's name reads differently to different parsers".to_string())
        })?;
        if is_model && let Some(m) = target_model {
            saw_model = true;
            if part.content() != m.as_bytes() {
                out.push([&part.raw[..part.content_start], m.as_bytes()]);
                changed = true;
                continue;
            }
        }
        out.push([part.raw, &[]]);
    }
    let appended = target_model
        .filter(|_| !saw_model)
        .map(|m| format!("Content-Disposition: form-data; name=\"model\"\r\n\r\n{m}"));
    if let Some(a) = &appended {
        out.push([a.as_bytes(), &[]]);
        changed = true;
    }
    if !changed {
        return Ok(ForwardBody::unchanged(body));
    }
    let delim = format!("--{boundary}");
    let mut bytes = Vec::with_capacity(body.len() + appended.as_ref().map_or(0, |a| a.len() + delim.len() + 4));
    bytes.extend_from_slice(preamble);
    for [a, b] in out {
        bytes.extend_from_slice(delim.as_bytes());
        bytes.extend_from_slice(b"\r\n");
        bytes.extend_from_slice(a);
        bytes.extend_from_slice(b);
        bytes.extend_from_slice(b"\r\n");
    }
    bytes.extend_from_slice(epilogue);
    Ok(ForwardBody { bytes: Bytes::from(bytes), removed })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;
    use proptest::prelude::*;

    const B: &str = "XyZzy";

    fn form(fields: &[(&str, &str)]) -> Bytes {
        let mut s = String::new();
        for (name, value) in fields {
            s.push_str(&format!("--{B}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"));
        }
        s.push_str(&format!("--{B}--\r\n"));
        Bytes::from(s)
    }

    fn ct() -> String {
        format!("multipart/form-data; boundary={B}")
    }

    fn fields_of(body: &[u8]) -> Vec<(String, String)> {
        let (_, parts, _) = split_multipart(body, B).expect("output must parse");
        parts
            .iter()
            .map(|p| {
                let h = find(p.raw, b"\r\n\r\n").unwrap();
                (p.names.last().cloned().unwrap_or_default(), String::from_utf8_lossy(&p.raw[h + 4..]).into_owned())
            })
            .collect()
    }

    #[test]
    fn json_strips_the_denylist_and_keeps_every_other_field() {
        let body = Bytes::from(r#"{"model":"a","priority":-100,"kv_transfer_params":{"remote_host":"x"},"chat_template_kwargs":{"k":1}}"#);
        let out = prepare(&body, "application/json", None).unwrap();
        let v: Value = serde_json::from_slice(&out.bytes).unwrap();
        assert!(v.get("priority").is_none());
        assert!(v.get("kv_transfer_params").is_none());
        // Positive control: an engine extra the client may legitimately set.
        assert_eq!(v["chat_template_kwargs"]["k"], 1);
        assert_eq!(v["model"], "a");
        assert_eq!(out.removed.iter().map(|(f, _)| *f).collect::<Vec<_>>(), vec!["priority", "kv_transfer_params"]);
    }

    #[test]
    fn json_names_the_targets_model_not_the_clients_alias() {
        let body = Bytes::from(r#"{"model":"my-embed-alias","input":"hi"}"#);
        let out = prepare(&body, "application/json", Some("BAAI/bge-m3")).unwrap();
        let v: Value = serde_json::from_slice(&out.bytes).unwrap();
        assert_eq!(v["model"], "BAAI/bge-m3");
        assert_eq!(v["input"], "hi");
        assert!(out.removed.is_empty());
    }

    #[test]
    fn an_untouched_body_is_forwarded_byte_for_byte() {
        // Key order and spacing a re-serialisation would change.
        let body = Bytes::from("{ \"model\": \"m\",  \"z\": 1, \"a\": 2 }");
        let out = prepare(&body, "application/json", Some("m")).unwrap();
        assert_eq!(out.bytes, body);
        let out = prepare(&body, "application/json; charset=utf-8", None).unwrap();
        assert_eq!(out.bytes, body);
    }

    #[test]
    fn unparseable_json_is_refused_not_forwarded_unchecked() {
        // Python's json accepts NaN, so an upstream would read `priority` here.
        let body = Bytes::from(r#"{"model":"m","priority":-5,"x":NaN}"#);
        assert_matches!(prepare(&body, "application/json", None), Err(AppError::BadRequest(_)));
        // A body with no content type is read as JSON by the upstream too.
        assert_matches!(prepare(&body, "", None), Err(AppError::BadRequest(_)));
        assert_matches!(prepare(&body, "application/vnd.x+json", None), Err(AppError::BadRequest(_)));
    }

    #[test]
    fn an_opaque_body_is_forwarded_as_is() {
        let body = Bytes::from_static(b"\x00\x01priority");
        let out = prepare(&body, "application/octet-stream", Some("m")).unwrap();
        assert_eq!(out.bytes, body);
    }

    #[test]
    fn urlencoded_strips_and_rewrites_the_model() {
        let body = Bytes::from("model=alias&priority=-9&language=en");
        let out = prepare(&body, "application/x-www-form-urlencoded", Some("whisper-large")).unwrap();
        let pairs: Vec<(String, String)> = url::form_urlencoded::parse(&out.bytes).into_owned().collect();
        assert_eq!(pairs, vec![("model".into(), "whisper-large".into()), ("language".into(), "en".into())]);
        assert_eq!(out.removed, vec![("priority", "-9".to_string())]);
    }

    /// python-multipart splits a form on `;` where no `&` follows, so a field
    /// behind one is read upstream while an `&`-only parse never sees it.
    #[test]
    fn a_semicolon_separated_owned_field_is_refused() {
        let ct = "application/x-www-form-urlencoded";
        for bad in ["model=a;priority=-9", "language=en;kv_transfer_params=x&b=c", "a=1;%70riority=2"] {
            assert_matches!(prepare(&Bytes::from(bad), ct, None), Err(AppError::BadRequest(_)), "{bad}");
        }
        // Positive controls: a `;` hiding no owned field, and an encoded `;`
        // (a value, under every reading), both go through.
        for ok in ["model=a;b=c", "prompt=a%3Bpriority%3D1"] {
            let out = prepare(&Bytes::from(ok), ct, None).unwrap();
            assert_eq!(out.bytes, Bytes::from(ok), "{ok}");
        }
    }

    #[test]
    fn multipart_drops_a_denylisted_part_and_rewrites_the_model() {
        let body = form(&[("model", "alias"), ("priority", "-7"), ("language", "fr")]);
        let out = prepare(&body, &ct(), Some("openai/whisper-large-v3")).unwrap();
        // Byte for byte: every kept part re-emitted whole, nothing left over.
        assert_eq!(out.bytes, form(&[("model", "openai/whisper-large-v3"), ("language", "fr")]));
        assert_eq!(out.removed, vec![("priority", "-7".to_string())]);
    }

    #[test]
    fn multipart_sees_every_spelling_of_the_name() {
        for disposition in [
            "form-data; name=priority",
            "form-data; NAME=\"priority\"",
            "form-data;name=\"priority\"",
            "form-data; name*=utf-8''priority",
            "form-data; name*=utf-8''%70riority",
            "form-data; name=\"x\"; name=\"priority\"",
        ] {
            let body = Bytes::from(format!(
                "--{B}\r\ncontent-disposition: {disposition}\r\n\r\n-3\r\n--{B}\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nb\r\n--{B}--\r\n"
            ));
            let out = prepare(&body, &ct(), None).unwrap();
            assert_eq!(fields_of(&out.bytes), vec![("a".into(), "b".into())], "{disposition}");
        }
    }

    /// Each disposition here is read as `priority` by Python's `email`
    /// package — checked against it, the parser python-multipart (Starlette,
    /// FastAPI) hands a part's header to — while an RFC 7230 parser reads
    /// something else or nothing.
    #[test]
    fn multipart_sees_the_name_pythons_email_package_reads() {
        for disposition in [
            "form-data; name=a\\\"; name=priority",
            "form-data; name=<priority>",
            "form-data; name*0=pri; name*1=ority",
            "form-data; name*0*=utf-8''%70ri; name*1=ority",
            "form-data; name*0=utf-8''pri; name*1*=%6Frity",
            "form-data; filename=a\\; name=\"priority\"",
        ] {
            let body = Bytes::from(format!(
                "--{B}\r\nContent-Disposition: {disposition}\r\n\r\n-3\r\n--{B}\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nb\r\n--{B}--\r\n"
            ));
            let out = prepare(&body, &ct(), None).unwrap();
            assert_eq!(out.removed.len(), 1, "{disposition}");
            assert_eq!(fields_of(&out.bytes), vec![("a".into(), "b".into())], "{disposition}");
        }
    }

    #[test]
    fn the_email_reading_matches_python_on_each_departure() {
        // Values pinned from Python's `email.message.Message.get_params`.
        assert_eq!(email_disposition_names("form-data; name=a\\\"; name=priority"), vec!["a\\\"", "priority"]);
        assert_eq!(email_disposition_names("form-data; name=\"pri\\ority\""), vec!["pri\\ority"]);
        assert_eq!(email_disposition_names("form-data; name*1=ority; name*0=pri"), vec!["priority"]);
        // Tied numbers order by the value as written, as Python's tuple sort does.
        assert_eq!(email_disposition_names("form-data; name*0=pri; name*0=ority"), vec!["oritypri"]);
        assert_eq!(email_disposition_names("form-data; name*=utf-8''%70riority"), vec!["priority"]);
        // An extended value without both ticks is kept whole.
        assert_eq!(email_disposition_names("form-data; name*=%70riority"), vec!["priority"]);
        assert_eq!(email_disposition_names("form-data; name0*=priority; name*x=priority"), Vec::<String>::new());
        assert_eq!(email_disposition_names("form-data"), Vec::<String>::new());
        assert_eq!(continuation_number(""), Some(None));
        assert_eq!(continuation_number("12"), Some(Some(12)));
        assert_eq!(continuation_number("12*"), Some(Some(12)));
        assert_eq!(continuation_number("*"), None);
        assert_eq!(continuation_number("1x"), None);
    }

    /// Each reading on its own — the union would hide a regression in one.
    #[test]
    fn each_reading_names_only_the_name_parameter() {
        let value = " form-data; name=\"a\"; filename=\"priority\"";
        assert_eq!(rfc_disposition_names(value), vec!["a"]);
        assert_eq!(email_disposition_names(value), vec!["a"]);
        let value = " form-data; filename=\"x\"; name*=utf-8''%70riority";
        assert_eq!(rfc_disposition_names(value), vec!["priority"]);
        assert_eq!(email_disposition_names(value), vec!["priority"]);
    }

    #[test]
    fn the_email_split_extends_only_an_unbalanced_segment() {
        assert_eq!(email_split_params(r#"a; b="x"; c"#), vec!["a", r#"b="x""#, "c"]);
        assert_eq!(email_split_params(r#"a; b="x;y"; c"#), vec!["a", r#"b="x;y""#, "c"]);
        assert_eq!(email_split_params(r#"a; b="x;y;z"; c"#), vec!["a", r#"b="x;y;z""#, "c"]);
        // `\"` counts against `"` outside quotes too.
        assert_eq!(email_split_params(r#"a; b=x\"; c"#), vec!["a", r#"b=x\""#, "c"]);
        assert_eq!(email_split_params(";a;;b"), vec!["", "a", "", "b"]);
    }

    /// Linear in the header: an unbalanced quote followed by a million `;`
    /// is one segment, read in one pass.
    #[test]
    fn an_unbalanced_quote_before_many_semicolons_is_read_in_one_pass() {
        let hostile = format!("form-data; x=\"{}", ";".repeat(1_000_000));
        let t = std::time::Instant::now();
        assert_eq!(email_split_params(&hostile).len(), 2);
        assert!(t.elapsed() < std::time::Duration::from_secs(2), "{:?}", t.elapsed());
    }

    #[test]
    fn the_capture_writer_keeps_the_cap_and_then_refuses() {
        use std::io::Write;
        let mut w = CappedWriter(Vec::new());
        assert_eq!(w.write(&[b'x'; 300]).unwrap(), REMOVED_VALUE_CAPTURE);
        assert!(w.write(b"y").is_err());
        assert_eq!(w.0.len(), REMOVED_VALUE_CAPTURE);
        // Positive control: below the cap, everything is kept.
        let mut w = CappedWriter(Vec::new());
        assert_eq!(w.write(b"abc").unwrap(), 3);
        assert_eq!(w.0, b"abc");
    }

    /// The boundary is read under every reading an upstream may apply; one
    /// that is ambiguous — two values, or one read differently — is refused,
    /// never guessed.
    #[test]
    fn an_ambiguous_boundary_is_refused_and_an_agreed_one_is_used() {
        let b = |ct: &str| multipart_boundary(ct).ok();
        assert_eq!(b("multipart/form-data; boundary=XyZzy").as_deref(), Some("XyZzy"));
        assert_eq!(b("multipart/form-data; BOUNDARY=\"XyZzy\"").as_deref(), Some("XyZzy"));
        assert_eq!(b("multipart/form-data; boundary*=utf-8''XyZzy").as_deref(), Some("XyZzy"));
        // An unclosed quote reads the same under both (`"AAA`, as Python has it),
        // but a quote is no boundary character: refused rather than split on.
        assert_matches!(multipart_boundary("multipart/form-data; boundary=\"AAA"), Err(AppError::BadRequest(_)));
        // A percent-escape that is not UTF-8 would be split on a replacement
        // character here and on the raw byte upstream.
        assert_matches!(multipart_boundary("multipart/form-data; boundary*=utf-8''A%E9B"), Err(AppError::BadRequest(_)));
        // A quoted `; boundary=AAA` inside another parameter is a value, under
        // both readings: the boundary is BBB, not the first `boundary=` text.
        assert_eq!(b(r#"multipart/form-data; x="; boundary=AAA; y="; boundary=BBB"#).as_deref(), Some("BBB"));
        for ambiguous in ["multipart/form-data; boundary=AAA; boundary=BBB", "multipart/form-data; boundary=AAA; boundary*=utf-8''BBB"] {
            assert_matches!(multipart_boundary(ambiguous), Err(AppError::BadRequest(_)), "{ambiguous}");
        }
        assert_matches!(multipart_boundary("multipart/form-data"), Err(AppError::BadRequest(_)));
        assert_matches!(multipart_boundary("multipart/form-data; boundary="), Err(AppError::BadRequest(_)));
        // End to end: a body framed under a second boundary is refused, not
        // forwarded with its parts unread.
        let body = form(&[("a", "b")]);
        assert_matches!(prepare(&body, &format!("multipart/form-data; boundary=OTHER; boundary={B}"), None), Err(AppError::BadRequest(_)));
    }

    /// A part a lenient parser finds where this scan sees only preamble is
    /// refused (python-multipart skips a leading LF); a plain preamble passes.
    #[test]
    fn a_delimiter_in_the_preamble_is_refused() {
        let smuggled = Bytes::from(format!(
            "\n--{B}\r\nContent-Disposition: form-data; name=\"priority\"\r\n\r\n-100\r\n--{B}\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nb\r\n--{B}--\r\n"
        ));
        assert_matches!(prepare(&smuggled, &ct(), None), Err(AppError::BadRequest(_)));
        // Positive control: preamble text with no delimiter is kept.
        let plain = Bytes::from(format!(
            "ignored preamble\r\n--{B}\r\nContent-Disposition: form-data; name=\"priority\"\r\n\r\n1\r\n--{B}--\r\n"
        ));
        assert_eq!(prepare(&plain, &ct(), None).unwrap().removed.len(), 1);
    }

    /// A part one reading names `model` and another does not is refused:
    /// rewriting it would follow one parser while the upstream follows the other.
    #[test]
    fn a_part_the_readings_disagree_on_is_refused() {
        for disposition in ["form-data; name*=x; name=model", "form-data; name=<model>"] {
            let body = Bytes::from(format!(
                "--{B}\r\nContent-Disposition: {disposition}\r\n\r\nchosen\r\n--{B}--\r\n"
            ));
            assert_matches!(prepare(&body, &ct(), Some("target")), Err(AppError::BadRequest(_)), "{disposition}");
        }
        // Positive control: a model part every reading agrees on is rewritten.
        let body = form(&[("model", "alias")]);
        assert_eq!(fields_of(&prepare(&body, &ct(), Some("target")).unwrap().bytes), vec![("model".into(), "target".into())]);
    }

    /// RFC 2046 lets a delimiter carry transport padding before its CRLF.
    #[test]
    fn a_padded_delimiter_is_still_a_delimiter() {
        let body = Bytes::from(format!(
            "--{B} \t\r\nContent-Disposition: form-data; name=\"priority\"\r\n\r\n-1\r\n--{B}\t\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nb\r\n--{B}--\r\n"
        ));
        let out = prepare(&body, &ct(), None).unwrap();
        assert_eq!(out.removed, vec![("priority", "-1".to_string())]);
        assert_eq!(out.bytes, form(&[("a", "b")]));
    }

    /// The audit marker keeps the start of a removed value, never a copy of a
    /// hostile multi-megabyte one.
    #[test]
    fn a_removed_value_is_captured_bounded() {
        let big = "9".repeat(1 << 20);
        let json = Bytes::from(format!(r#"{{"model":"m","priority":"{big}"}}"#));
        let multipart = form(&[("priority", &big)]);
        let urlencoded = Bytes::from(format!("priority={big}"));
        for (body, ct) in [
            (json, "application/json".to_string()),
            (multipart, ct()),
            (urlencoded, "application/x-www-form-urlencoded".to_string()),
        ] {
            let out = prepare(&body, &ct, None).unwrap();
            let (_, captured) = &out.removed[0];
            assert_eq!(captured.len(), REMOVED_VALUE_CAPTURE, "{ct}");
            // JSON renders the string with its opening quote.
            assert!(big.starts_with(captured.trim_start_matches('"')), "{ct}");
        }
        // Positive control: a short value is kept whole.
        assert_eq!(capture_json(&serde_json::json!({"k": [1, 2]})), r#"{"k":[1,2]}"#);
    }

    #[test]
    fn the_audit_diff_records_each_removed_field_and_nothing_else() {
        let body = Bytes::from(r#"{"model":"m","priority":-3}"#);
        let diff = prepare(&body, "application/json", None).unwrap().audit_diff().unwrap();
        let blocks = diff["injection_blocks"].as_array().unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0]["transform"], "gateway_owned_field");
        assert_eq!(blocks[0]["field"], "priority");
        assert_eq!(blocks[0]["action"], "remove");
        assert_eq!(blocks[0]["content"], "-3");
        // Nothing removed → no diff at all (the row carries no Modified mark).
        let clean = Bytes::from(r#"{"model":"m"}"#);
        assert!(prepare(&clean, "application/json", None).unwrap().audit_diff().is_none());
    }

    /// A `;` or `name=` inside a QUOTED parameter value is part of that value:
    /// a file named `a; name="priority"` is a file, not the priority field —
    /// and an escaped quote does not end the value early.
    #[test]
    fn a_quoted_parameter_value_is_never_read_as_a_parameter() {
        for disposition in [
            "form-data; name=\"file\"; filename=\"a; name=priority.wav\"",
            "form-data; name=\"file\"; filename=\"a; name=priority; b\"",
            "form-data; name=\"file\"; filename=\"a\\\"; name=priority\"",
            "form-data; name=\"file\"; filename=\"a\\\"; name=priority; b=\\\"\"",
        ] {
            let body = Bytes::from(format!(
                "--{B}\r\nContent-Disposition: {disposition}\r\n\r\nRIFF\r\n--{B}--\r\n"
            ));
            let out = prepare(&body, &ct(), None).unwrap();
            assert_eq!(out.bytes, body, "{disposition}");
            assert!(out.removed.is_empty(), "{disposition}");
        }
        // Positive control: the same name OUTSIDE quotes is the field.
        let body = Bytes::from(format!(
            "--{B}\r\nContent-Disposition: form-data; filename=\"a.wav\"; name=priority\r\n\r\n-1\r\n--{B}--\r\n"
        ));
        assert_eq!(prepare(&body, &ct(), None).unwrap().removed.len(), 1);
    }

    /// The RFC reading on its own (the email reading would hide a regression
    /// here in the end-to-end cases): `;` splits only outside quotes, `\`
    /// escapes only inside them.
    #[test]
    fn the_rfc_reading_splits_only_outside_quotes() {
        assert_eq!(
            split_params(r#"form-data; filename=a\; name="priority""#),
            vec!["form-data", r" filename=a\", r#" name="priority""#]
        );
        assert_eq!(
            split_params(r#"form-data; filename="a; name=priority; b""#),
            vec!["form-data", r#" filename="a; name=priority; b""#]
        );
        assert_eq!(split_params(r#"a; f="x\"; y"; z"#), vec!["a", r#" f="x\"; y""#, " z"]);
    }

    #[test]
    fn a_file_named_like_a_denylisted_field_is_kept() {
        // Positive control: only the field NAME decides, never a filename.
        let body = Bytes::from(format!(
            "--{B}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"priority.wav\"\r\nContent-Type: audio/wav\r\n\r\nRIFF\r\n--{B}--\r\n"
        ));
        let out = prepare(&body, &ct(), None).unwrap();
        assert_eq!(out.bytes, body);
    }

    #[test]
    fn a_multipart_body_that_cannot_be_split_is_refused() {
        for bad in [
            "no delimiter at all".to_string(),
            format!("--{B}\r\nContent-Disposition: form-data; name=\"priority\"\r\n\r\n1\r\n"), // no close
            format!("--{B}\nContent-Disposition: form-data; name=\"priority\"\n\n1\n--{B}--\n"),    // LF only
            format!("--{B}\r\n--{B}--\r\n"),                                                       // empty part
        ] {
            assert_matches!(prepare(&Bytes::from(bad.clone()), &ct(), None), Err(AppError::BadRequest(_)), "{bad:?}");
        }
        assert_matches!(prepare(&form(&[("a", "b")]), "multipart/form-data", None), Err(AppError::BadRequest(_)));
    }

    fn field_name() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("priority".to_string()),
            Just("kv_transfer_params".to_string()),
            Just("model".to_string()),
            "[a-z_]{1,12}",
        ]
    }

    proptest! {
        /// No denylisted field survives, every other field survives with its
        /// exact value and order, and the output is itself a valid form.
        #[test]
        fn multipart_output_carries_no_gateway_owned_field(
            fields in proptest::collection::vec((field_name(), "[ -~]{0,20}"), 0..8),
            target in proptest::option::of("[a-z0-9/-]{1,16}"),
        ) {
            let fields: Vec<(String, String)> = fields;
            let refs: Vec<(&str, &str)> = fields.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
            let out = prepare(&form(&refs), &ct(), target.as_deref()).unwrap();
            let got = fields_of(&out.bytes);
            prop_assert!(got.iter().all(|(n, _)| !GATEWAY_OWNED_WIRE_FIELDS.contains(&n.as_str())));
            let expect_others: Vec<&(String, String)> = fields.iter()
                .filter(|(n, _)| !GATEWAY_OWNED_WIRE_FIELDS.contains(&n.as_str()) && (target.is_none() || n != "model"))
                .collect();
            let got_others: Vec<&(String, String)> = got.iter()
                .filter(|(n, _)| target.is_none() || n != "model")
                .collect();
            prop_assert_eq!(expect_others, got_others);
            if let Some(m) = &target {
                prop_assert!(got.iter().filter(|(n, _)| n == "model").all(|(_, v)| v == m));
                prop_assert!(got.iter().any(|(n, _)| n == "model"));
            }
            // Stripping what is already stripped changes nothing.
            let again = prepare(&out.bytes, &ct(), target.as_deref()).unwrap();
            prop_assert_eq!(again.bytes, out.bytes);
        }

        /// A JSON object never keeps a gateway-owned top-level key, and keeps
        /// every other one unchanged.
        #[test]
        fn json_output_carries_no_gateway_owned_field(
            fields in proptest::collection::btree_map(field_name(), any::<i32>(), 0..8),
        ) {
            let body = Bytes::from(serde_json::to_vec(&fields).unwrap());
            let out = prepare(&body, "application/json", None).unwrap();
            let v: serde_json::Map<String, Value> = serde_json::from_slice(&out.bytes).unwrap();
            for (k, n) in &fields {
                if GATEWAY_OWNED_WIRE_FIELDS.contains(&k.as_str()) {
                    prop_assert!(!v.contains_key(k));
                } else {
                    prop_assert_eq!(v.get(k), Some(&Value::from(*n)));
                }
            }
        }
    }
}

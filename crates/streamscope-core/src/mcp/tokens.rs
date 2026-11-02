//! Stateless virtualization tokens for the MCP gateway.
//!
//! The gateway hands the agent three classes of opaque tokens it can later
//! round-trip back: session ids (`sssid.…`), server-initiated request ids
//! (`ssrid.…`), and resource URIs (`stsmcp://…`). Each carries the routing
//! state needed to deliver the next call. Any proxy replica decodes the token
//! to recover that state — no cross-instance sync required.
//!
//! Session and request tokens are HMAC-SHA256 signed so a tenant member can't
//! forge a token that pins to an arbitrary upstream. The HMAC secret is
//! derived from `ENCRYPTION_KEY` via HKDF with a per-token-type domain tag,
//! so leaking one secret doesn't compromise the others.
//!
//! Resource URIs are wrapped in the gateway's own `stsmcp://` scheme rather
//! than signed: a stale or forged URI fails the prefix→route resolution and
//! returns `-32004 not found`, which is a stronger guarantee than HMAC for
//! this surface (the upstream can't be coaxed into reading something it
//! doesn't own because the prefix is the only routing input).

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

use crate::crypto::get_encryption_key;

type HmacSha256 = Hmac<Sha256>;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

const SESSION_PREFIX: &str = "sssid.";
const REQUEST_PREFIX: &str = "ssrid.";
const EVENT_PREFIX: &str = "ssevt.";
/// Multi Round-Trip Request state (MCP 2026-07-28 § MRTR). Handed to the
/// client as the opaque `requestState` of an `InputRequiredResult` and quoted
/// back verbatim on the retry.
const REQUEST_STATE_PREFIX: &str = "ssmrtr.";
const URI_SCHEME_PREFIX: &str = "stsmcp://";
/// Template-envelope scheme for `resources/templates/list`. Encodes
/// `(route_prefix, original_scheme)` into the scheme portion of the URI so
/// RFC 6570 placeholders inside `original_after_scheme` survive expansion
/// without our wrapper interfering. Decoded back to `(prefix, "<scheme>://<rest>")`
/// at `resources/read` time.
const URI_SCHEME_TEMPLATE_PREFIX: &str = "stsmcp+";

const SESSION_DOMAIN: &[u8] = b"streamscope-mcp-sid-v1";
const REQUEST_DOMAIN: &[u8] = b"streamscope-mcp-rid-v1";
const EVENT_DOMAIN: &[u8] = b"streamscope-mcp-evt-v1";
const REQUEST_STATE_DOMAIN: &[u8] = b"streamscope-mcp-mrtr-v1";

/// Default session-token lifetime — 24 hours. Long enough for any realistic
/// agent connection, short enough to bound replay risk if a token leaks.
pub const DEFAULT_TOKEN_TTL_SECS: u64 = 24 * 3600;

/// Lifetime of an MRTR `requestState` blob — 5 minutes. MCP 2026-07-28
/// § MRTR requires a *short* expiry: the state is handed to the client and
/// quoted back on the retry, so its window is one user interaction (answering
/// an elicitation form), not one session. Bounding it bounds the replay
/// window; the principal and request-identity bindings inside the payload
/// close cross-user and cross-request reuse independently.
pub const DEFAULT_REQUEST_STATE_TTL_SECS: u64 = 300;

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("token missing prefix")]
    MissingPrefix,
    #[error("token malformed (expected payload.signature)")]
    Malformed,
    #[error("base64 decode failed")]
    Base64,
    #[error("payload deserialization failed")]
    Payload,
    #[error("HMAC signature mismatch")]
    Signature,
    #[error("HMAC secret unavailable (ENCRYPTION_KEY not set)")]
    SecretUnavailable,
    #[error("token expired")]
    Expired,
    #[error("unknown schema version {0}")]
    UnknownVersion(u8),
    #[error("URI scheme is not stsmcp://")]
    UriScheme,
    #[error("URI is malformed")]
    UriMalformed,
    /// Template encode rejected: orig template carries no `://` separator, so
    /// we can't extract the orig-scheme. RFC 6570 templates SHOULD include a
    /// scheme; rejecting forces the upstream to emit well-formed templates.
    #[error("URI template missing scheme")]
    TemplateNoScheme,
    /// Template encode rejected: orig-scheme contains `+`, which our envelope
    /// uses as the prefix/scheme separator. Per RFC 3986 schemes MAY include
    /// `+`, but it's vanishingly rare in MCP servers (file://, git://, https://
    /// are the common ones), so `templates/list` drops such a template.
    #[error("URI template orig-scheme contains '+'")]
    TemplateSchemeHasPlus,
}

/// What we recover from a session-id token — the per-session state needed
/// for header substitution, audit emission, and reverse-path routing on
/// any proxy replica.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedSession {
    pub upstream_session_id: String,
    pub upstream_id: Uuid,
    pub virtual_server_id: Uuid,
    pub protocol_version: String,
    pub minted_at_secs: u64,
}

/// What we recover from a server-initiated-request id token. Used to route
/// the agent's response back to the upstream that originated the call.
///
/// `tenant_id` / `user_id` bind the token to the identity that minted it so
/// a captured token can't be replayed by a sibling user with their own access
/// to the same virtual server. The handler asserts both match `AuthCtx`
/// before forwarding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedRequest {
    pub upstream_id: Uuid,
    pub upstream_session_id: String,
    pub original_id: serde_json::Value,
    pub minted_at_secs: u64,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
}

/// What we recover from an MRTR `requestState` blob (MCP 2026-07-28 § Multi
/// Round-Trip Requests).
///
/// The gateway hands this to a modern client alongside an
/// `InputRequiredResult` and the client quotes it back verbatim on the retry.
/// The spec treats `requestState` as attacker-controlled, so every field the
/// retry path trusts is inside the HMAC-protected payload and re-checked on
/// decode:
///
/// - `tenant_id` / `user_id` — the authenticated principal that minted it.
///   The handler rejects state presented by a different principal.
/// - `method` + `params_digest` — the identity of the originating request.
///   The handler rejects state replayed onto a different call.
/// - `minted_at_secs` + the caller's TTL — bounds the replay window.
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedRequestState {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub virtual_server_id: Uuid,
    pub method: String,
    pub params_digest: String,
    pub minted_at_secs: u64,
    /// The upstream that asked the question, when the question came from a
    /// *modern* upstream rather than from the gateway's own bridge.
    ///
    /// A modern upstream answers with its own opaque `requestState`, which
    /// cannot be handed to the client: the client would quote it back and
    /// nothing in it says which upstream it belongs to. Wrapping it here —
    /// under the same HMAC that already binds the principal and the call —
    /// is what makes the retry routable.
    pub upstream_id: Option<Uuid>,
    /// The upstream's own `requestState`, verbatim. Opaque to the gateway:
    /// only the upstream that minted it can read it.
    pub upstream_state: Option<String>,
}

#[derive(Serialize)]
struct RequestStatePayload<'a> {
    v: u8,
    /// `n` for tenancy — the tenant the minting identity belongs to.
    n: Uuid,
    /// `o` for owner — the user_id that minted the state.
    o: Uuid,
    g: Uuid,
    m: &'a str,
    d: &'a str,
    t: u64,
    /// `s` for server — the upstream that asked, when one did.
    #[serde(skip_serializing_if = "Option::is_none")]
    s: Option<Uuid>,
    /// `x` for the upstream's own opaque state.
    #[serde(skip_serializing_if = "Option::is_none")]
    x: Option<&'a str>,
}

#[derive(Serialize, Deserialize)]
struct RequestStatePayloadOwned {
    v: u8,
    n: Uuid,
    o: Uuid,
    g: Uuid,
    m: String,
    d: String,
    t: u64,
    #[serde(default)]
    s: Option<Uuid>,
    #[serde(default)]
    x: Option<String>,
}

/// What we recover from an SSE-event id token. Used by `Last-Event-ID`
/// replay on `GET /mcp/<slug>`: any proxy replica decodes the token, asserts
/// `(tenant_id, user_id)` match the authenticated identity, and replays
/// `mcp_sse_events` rows with `sequence > q` for `mcp_session_id == s`.
///
/// `tenant_id` / `user_id` bind the token to the identity that minted it so
/// a captured `ssevt.…` id can't be replayed by a sibling user under the
/// same tenant — same posture as the `ssrid.…` request-id binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedEvent {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub mcp_session_id: String,
    pub sequence: u64,
    pub minted_at_secs: u64,
}

#[derive(Serialize, Deserialize)]
struct EventPayload<'a> {
    v: u8,
    t: Uuid,
    u: Uuid,
    s: &'a str,
    q: u64,
    ts: u64,
}

#[derive(Serialize, Deserialize)]
struct EventPayloadOwned {
    v: u8,
    t: Uuid,
    u: Uuid,
    s: String,
    q: u64,
    ts: u64,
}

#[derive(Serialize, Deserialize)]
struct SessionPayload<'a> {
    v: u8,
    u: &'a str,
    s: Uuid,
    g: Uuid,
    p: &'a str,
    t: u64,
}

#[derive(Serialize, Deserialize)]
struct SessionPayloadOwned {
    v: u8,
    u: String,
    s: Uuid,
    g: Uuid,
    p: String,
    t: u64,
}

#[derive(Serialize, Deserialize)]
struct RequestPayload<'a> {
    v: u8,
    s: Uuid,
    u: &'a str,
    #[serde(borrow)]
    i: &'a serde_json::value::RawValue,
    t: u64,
    /// `n` for tenancy — the tenant the minting identity belongs to.
    n: Uuid,
    /// `o` for owner — the user_id that minted the token.
    o: Uuid,
}

#[derive(Serialize, Deserialize)]
struct RequestPayloadOwned {
    v: u8,
    s: Uuid,
    u: String,
    i: serde_json::Value,
    t: u64,
    n: Uuid,
    o: Uuid,
}

const SCHEMA_VERSION: u8 = 1;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn token_secret(domain: &[u8]) -> Result<[u8; 32], TokenError> {
    let root = get_encryption_key().ok_or(TokenError::SecretUnavailable)?;
    let hk = hkdf::Hkdf::<Sha256>::new(None, &root);
    let mut okm = [0u8; 32];
    hk.expand(domain, &mut okm)
        .map_err(|_| TokenError::SecretUnavailable)?;
    Ok(okm)
}

fn sign(secret: &[u8; 32], payload: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(payload);
    mac.finalize().into_bytes().to_vec()
}

fn verify(secret: &[u8; 32], payload: &[u8], tag: &[u8]) -> bool {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(payload);
    mac.verify_slice(tag).is_ok()
}

/// Mint a gateway session id for `(upstream_session_id, upstream_id, vs_id,
/// protocol_version)`. Returns a string of the form `sssid.<b64>.<b64>`.
pub fn encode_session_id(
    upstream_session_id: &str,
    upstream_id: Uuid,
    virtual_server_id: Uuid,
    protocol_version: &str,
) -> Result<String, TokenError> {
    let payload = SessionPayload {
        v: SCHEMA_VERSION,
        u: upstream_session_id,
        s: upstream_id,
        g: virtual_server_id,
        p: protocol_version,
        t: now_secs(),
    };
    let json = serde_json::to_vec(&payload).map_err(|_| TokenError::Payload)?;
    let secret = token_secret(SESSION_DOMAIN)?;
    let tag = sign(&secret, &json);
    Ok(format!(
        "{SESSION_PREFIX}{}.{}",
        B64.encode(&json),
        B64.encode(&tag)
    ))
}

/// Decode a gateway session id minted by [`encode_session_id`]. Validates the
/// HMAC tag, schema version, and TTL. `ttl_secs == 0` disables the TTL check.
pub fn decode_session_id(token: &str, ttl_secs: u64) -> Result<DecodedSession, TokenError> {
    let body = token.strip_prefix(SESSION_PREFIX).ok_or(TokenError::MissingPrefix)?;
    let (payload_b64, sig_b64) = body.split_once('.').ok_or(TokenError::Malformed)?;
    let payload = B64.decode(payload_b64).map_err(|_| TokenError::Base64)?;
    let tag = B64.decode(sig_b64).map_err(|_| TokenError::Base64)?;
    let secret = token_secret(SESSION_DOMAIN)?;
    if !verify(&secret, &payload, &tag) {
        return Err(TokenError::Signature);
    }
    let parsed: SessionPayloadOwned =
        serde_json::from_slice(&payload).map_err(|_| TokenError::Payload)?;
    if parsed.v != SCHEMA_VERSION {
        return Err(TokenError::UnknownVersion(parsed.v));
    }
    if ttl_secs > 0 {
        let now = now_secs();
        if now > parsed.t.saturating_add(ttl_secs) {
            return Err(TokenError::Expired);
        }
    }
    Ok(DecodedSession {
        upstream_session_id: parsed.u,
        upstream_id: parsed.s,
        virtual_server_id: parsed.g,
        protocol_version: parsed.p,
        minted_at_secs: parsed.t,
    })
}

/// Mint a virtualized JSON-RPC request id for a server-initiated request.
/// The agent will quote this back verbatim on its response; the proxy decodes
/// to find the originating upstream + the original (upstream-side) id.
///
/// `tenant_id` / `user_id` bind the token to the identity that mints it.
/// On decode, the handler asserts both match the inbound `AuthCtx` so a
/// captured token can't be replayed by a sibling user in the same VS.
pub fn encode_request_id(
    upstream_id: Uuid,
    upstream_session_id: &str,
    original_id: &serde_json::Value,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Result<String, TokenError> {
    let id_raw = serde_json::value::to_raw_value(original_id).map_err(|_| TokenError::Payload)?;
    let payload = RequestPayload {
        v: SCHEMA_VERSION,
        s: upstream_id,
        u: upstream_session_id,
        i: &id_raw,
        t: now_secs(),
        n: tenant_id,
        o: user_id,
    };
    let json = serde_json::to_vec(&payload).map_err(|_| TokenError::Payload)?;
    let secret = token_secret(REQUEST_DOMAIN)?;
    let tag = sign(&secret, &json);
    Ok(format!(
        "{REQUEST_PREFIX}{}.{}",
        B64.encode(&json),
        B64.encode(&tag)
    ))
}

/// Decode a virtualized request id. Returns `Err(MissingPrefix)` when the id
/// is not a string starting with `ssrid.` — callers fall back to the legacy
/// path for non-virtualized ids (e.g. plain numeric ids agents may use for
/// their own local correlation).
pub fn decode_request_id(token: &str, ttl_secs: u64) -> Result<DecodedRequest, TokenError> {
    let body = token.strip_prefix(REQUEST_PREFIX).ok_or(TokenError::MissingPrefix)?;
    let (payload_b64, sig_b64) = body.split_once('.').ok_or(TokenError::Malformed)?;
    let payload = B64.decode(payload_b64).map_err(|_| TokenError::Base64)?;
    let tag = B64.decode(sig_b64).map_err(|_| TokenError::Base64)?;
    let secret = token_secret(REQUEST_DOMAIN)?;
    if !verify(&secret, &payload, &tag) {
        return Err(TokenError::Signature);
    }
    let parsed: RequestPayloadOwned =
        serde_json::from_slice(&payload).map_err(|_| TokenError::Payload)?;
    if parsed.v != SCHEMA_VERSION {
        return Err(TokenError::UnknownVersion(parsed.v));
    }
    if ttl_secs > 0 {
        let now = now_secs();
        if now > parsed.t.saturating_add(ttl_secs) {
            return Err(TokenError::Expired);
        }
    }
    Ok(DecodedRequest {
        upstream_id: parsed.s,
        upstream_session_id: parsed.u,
        original_id: parsed.i,
        minted_at_secs: parsed.t,
        tenant_id: parsed.n,
        user_id: parsed.o,
    })
}

/// Digest the salient parameters of a request so an MRTR `requestState` can
/// be pinned to the call that produced it (MCP 2026-07-28 § MRTR, server
/// requirement 5).
///
/// The digest deliberately covers the request params with `inputResponses`
/// and `requestState` themselves REMOVED: those two fields are what the
/// retry *adds*, so including them would make every retry look like a
/// different request and the state would never verify. Everything else the
/// server acts on — the tool name, its arguments, the resource URI — is
/// inside.
///
/// `_meta` is also excluded: it carries per-request client metadata
/// (`clientInfo`, `progressToken`, trace context) that legitimately differs
/// between the original call and its retry.
pub fn digest_request_params(params: Option<&serde_json::Value>) -> String {
    use sha2::Digest;
    let mut salient = params.cloned().unwrap_or(serde_json::Value::Null);
    if let Some(obj) = salient.as_object_mut() {
        obj.remove("inputResponses");
        obj.remove("requestState");
        obj.remove("_meta");
    }
    // `serde_json::to_vec` on a `Value` emits object keys in the map's own
    // order, and `serde_json`'s default `Map` is a `BTreeMap` — so the bytes
    // are already canonical for a given logical value. Keep the `preserve_order`
    // feature OFF for this crate or this digest stops being stable.
    let bytes = serde_json::to_vec(&salient).unwrap_or_default();
    let mut hasher = sha2::Sha256::new();
    hasher.update(&bytes);
    B64.encode(hasher.finalize())
}

/// Mint an MRTR `requestState` blob for a request the gateway could not
/// complete without more client input.
///
/// Returns a string of the form `ssmrtr.<b64>.<b64>`. The client treats it as
/// opaque; [`decode_request_state`] is the only thing that reads it.
///
/// `upstream` names the modern upstream that asked the question, and carries
/// that upstream's own opaque `requestState` when it minted one. `None` is the
/// gateway's own bridge, where the question came from a legacy upstream's live
/// stream and the retry is answered by re-issuing rather than by quoting
/// anything back.
///
/// The two halves are separately optional because § MRTR makes the upstream's
/// `requestState` optional: a server may ask a question and keep no state at
/// all. "Upstream known, state absent" must therefore be expressible, and
/// neither collapse works. Folding it into `None` drops the id the retry is
/// routed by. Encoding it as `Some("")` conflates it with a server that
/// really did mint an empty state, and the two owe opposite things on the
/// retry: one must send no `requestState` at all (client requirement 2 forbids
/// quoting back a state that was never issued), the other must echo `""`
/// exactly.
pub fn encode_request_state(
    tenant_id: Uuid,
    user_id: Uuid,
    virtual_server_id: Uuid,
    method: &str,
    params_digest: &str,
    upstream: Option<(Uuid, Option<&str>)>,
) -> Result<String, TokenError> {
    let payload = RequestStatePayload {
        v: SCHEMA_VERSION,
        n: tenant_id,
        o: user_id,
        g: virtual_server_id,
        m: method,
        d: params_digest,
        t: now_secs(),
        s: upstream.map(|(id, _)| id),
        x: upstream.and_then(|(_, state)| state),
    };
    let json = serde_json::to_vec(&payload).map_err(|_| TokenError::Payload)?;
    let secret = token_secret(REQUEST_STATE_DOMAIN)?;
    let tag = sign(&secret, &json);
    Ok(format!(
        "{REQUEST_STATE_PREFIX}{}.{}",
        B64.encode(&json),
        B64.encode(&tag)
    ))
}

/// Decode an MRTR `requestState` blob minted by [`encode_request_state`].
/// Validates the HMAC tag, schema version, and TTL. The caller MUST still
/// assert the principal and request identity against the inbound request —
/// this function proves only that *we* minted the blob and that it has not
/// lapsed, not that it belongs to the call presenting it.
pub fn decode_request_state(
    token: &str,
    ttl_secs: u64,
) -> Result<DecodedRequestState, TokenError> {
    let body = token
        .strip_prefix(REQUEST_STATE_PREFIX)
        .ok_or(TokenError::MissingPrefix)?;
    let (payload_b64, sig_b64) = body.split_once('.').ok_or(TokenError::Malformed)?;
    let payload = B64.decode(payload_b64).map_err(|_| TokenError::Base64)?;
    let tag = B64.decode(sig_b64).map_err(|_| TokenError::Base64)?;
    let secret = token_secret(REQUEST_STATE_DOMAIN)?;
    if !verify(&secret, &payload, &tag) {
        return Err(TokenError::Signature);
    }
    let parsed: RequestStatePayloadOwned =
        serde_json::from_slice(&payload).map_err(|_| TokenError::Payload)?;
    if parsed.v != SCHEMA_VERSION {
        return Err(TokenError::UnknownVersion(parsed.v));
    }
    if ttl_secs > 0 {
        let now = now_secs();
        if now > parsed.t.saturating_add(ttl_secs) {
            return Err(TokenError::Expired);
        }
    }
    Ok(DecodedRequestState {
        tenant_id: parsed.n,
        user_id: parsed.o,
        virtual_server_id: parsed.g,
        method: parsed.m,
        params_digest: parsed.d,
        minted_at_secs: parsed.t,
        upstream_id: parsed.s,
        upstream_state: parsed.x,
    })
}

/// Mint an SSE event id for one server-initiated MCP event in
/// `mcp_session_id` at `sequence`. The token round-trips back as the
/// `Last-Event-ID` request header on a `GET /mcp/<slug>` reconnect; the
/// proxy decodes to learn which session and from which sequence to replay.
///
/// `tenant_id` / `user_id` bind the token to the minting identity so a
/// captured id can't be used by a sibling user to replay another user's
/// event stream.
pub fn encode_event_id(
    tenant_id: Uuid,
    user_id: Uuid,
    mcp_session_id: &str,
    sequence: u64,
) -> Result<String, TokenError> {
    let payload = EventPayload {
        v: SCHEMA_VERSION,
        t: tenant_id,
        u: user_id,
        s: mcp_session_id,
        q: sequence,
        ts: now_secs(),
    };
    let json = serde_json::to_vec(&payload).map_err(|_| TokenError::Payload)?;
    let secret = token_secret(EVENT_DOMAIN)?;
    let tag = sign(&secret, &json);
    Ok(format!(
        "{EVENT_PREFIX}{}.{}",
        B64.encode(&json),
        B64.encode(&tag)
    ))
}

/// Decode an SSE event id minted by [`encode_event_id`]. Validates the HMAC
/// tag, schema version, and TTL. `ttl_secs == 0` disables the TTL check.
///
/// The caller MUST additionally assert that the decoded `tenant_id` and
/// `user_id` match the authenticated identity — silent fresh connect on
/// mismatch (no 4xx) so a tampered/wrong-user `Last-Event-ID` never errors
/// the reconnect.
pub fn decode_event_id(token: &str, ttl_secs: u64) -> Result<DecodedEvent, TokenError> {
    let body = token.strip_prefix(EVENT_PREFIX).ok_or(TokenError::MissingPrefix)?;
    let (payload_b64, sig_b64) = body.split_once('.').ok_or(TokenError::Malformed)?;
    let payload = B64.decode(payload_b64).map_err(|_| TokenError::Base64)?;
    let tag = B64.decode(sig_b64).map_err(|_| TokenError::Base64)?;
    let secret = token_secret(EVENT_DOMAIN)?;
    if !verify(&secret, &payload, &tag) {
        return Err(TokenError::Signature);
    }
    let parsed: EventPayloadOwned =
        serde_json::from_slice(&payload).map_err(|_| TokenError::Payload)?;
    if parsed.v != SCHEMA_VERSION {
        return Err(TokenError::UnknownVersion(parsed.v));
    }
    if ttl_secs > 0 {
        let now = now_secs();
        if now > parsed.ts.saturating_add(ttl_secs) {
            return Err(TokenError::Expired);
        }
    }
    Ok(DecodedEvent {
        tenant_id: parsed.t,
        user_id: parsed.u,
        mcp_session_id: parsed.s,
        sequence: parsed.q,
        minted_at_secs: parsed.ts,
    })
}

/// Wrap an upstream-supplied resource URI with the route's prefix marker.
/// The encoded URI is itself a valid URI (`stsmcp://<prefix>/<b64>`) so it
/// round-trips through any client that treats URIs as opaque per spec.
pub fn encode_resource_uri(prefix: &str, original: &str) -> String {
    format!("{URI_SCHEME_PREFIX}{prefix}/{}", B64.encode(original.as_bytes()))
}

/// Wrap a `resources/templates/list` `uriTemplate` so the route prefix
/// survives RFC 6570 placeholder expansion on the agent side.
///
/// Shape: `stsmcp+<prefix>+<orig_scheme>://<orig_after_scheme>`.
///
/// **Why a second envelope.** The concrete-URI envelope (`stsmcp://<prefix>/<b64>`)
/// works for `resources/list` because each item carries a fully-resolved URI
/// the gateway base64-encodes once. Templates carry RFC 6570 placeholders
/// (`{path}`, `{ref}`) that the agent expands client-side; if we base64'd the
/// whole template, expansion would substitute placeholders into an opaque
/// blob and the resulting URI would no longer round-trip. Wrapping at the
/// scheme level lets the agent expand `stsmcp+gh+file:///{path}` to
/// `stsmcp+gh+file:///foo/bar` — placeholders inside `orig_after_scheme` are
/// untouched by our envelope, so the recovered original is `file:///foo/bar`
/// at `resources/read` time.
pub fn encode_resource_template(prefix: &str, orig_template: &str) -> Result<String, TokenError> {
    let (orig_scheme, orig_rest) = orig_template
        .split_once("://")
        .ok_or(TokenError::TemplateNoScheme)?;
    if orig_scheme.contains('+') {
        return Err(TokenError::TemplateSchemeHasPlus);
    }
    // Empty prefix is the no-namespacing route (`route_for_prefix(_, Some(""))`
    // matches the no-namespacing route) and round-trips cleanly through `decode_resource_uri`
    // — output `stsmcp++<scheme>://<rest>` splits as ("", "<scheme>://<rest>").
    Ok(format!("{URI_SCHEME_TEMPLATE_PREFIX}{prefix}+{orig_scheme}://{orig_rest}"))
}

/// Reverse of [`encode_resource_uri`] / [`encode_resource_template`]. Returns
/// `(prefix, original_uri)`.
///
/// Recognizes both envelopes:
///   * `stsmcp://<prefix>/<b64>`              — concrete URI from `resources/list`
///   * `stsmcp+<prefix>+<scheme>://<rest>`    — expanded template URI from `resources/templates/list`
///
/// The two shapes are unambiguous because the URI grammar is `scheme://body`
/// and `:` cannot appear in a scheme — so a `stsmcp` scheme followed by `+`
/// vs `://` partitions cleanly.
pub fn decode_resource_uri(virt: &str) -> Result<(String, String), TokenError> {
    if let Some(body) = virt.strip_prefix(URI_SCHEME_PREFIX) {
        let (prefix, b64) = body.split_once('/').ok_or(TokenError::UriMalformed)?;
        let bytes = B64.decode(b64).map_err(|_| TokenError::Base64)?;
        let original = String::from_utf8(bytes).map_err(|_| TokenError::UriMalformed)?;
        return Ok((prefix.to_string(), original));
    }
    if let Some(body) = virt.strip_prefix(URI_SCHEME_TEMPLATE_PREFIX) {
        // body = "<prefix>+<scheme>://<rest>" — empty prefix is the
        // no-namespacing route (matches `route_for_prefix(_, Some(""))`).
        let (prefix, after_prefix) = body.split_once('+').ok_or(TokenError::UriMalformed)?;
        let (orig_scheme, orig_rest) = after_prefix
            .split_once("://")
            .ok_or(TokenError::UriMalformed)?;
        if orig_scheme.is_empty() {
            return Err(TokenError::UriMalformed);
        }
        return Ok((prefix.to_string(), format!("{orig_scheme}://{orig_rest}")));
    }
    Err(TokenError::UriScheme)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;
    use serde_json::json;

    fn with_test_secret<R>(f: impl FnOnce() -> R) -> R {
        // Tests must observe a stable ENCRYPTION_KEY. The module under test
        // uses the OnceLock cache in `crate::crypto`, so the first test that
        // sets the env var wins — subsequent tests inherit it. Set unconditionally
        // to keep tests order-independent in isolation.
        // SAFETY: tests run single-threaded by default; this is a `cargo test`
        // process whose env is private to this crate.
        unsafe {
            std::env::set_var("ENCRYPTION_KEY", "test-mcp-token-secret-very-long");
        }
        f()
    }

    #[test]
    fn session_round_trip() {
        with_test_secret(|| {
            let up_id = Uuid::new_v4();
            let vs_id = Uuid::new_v4();
            let token = encode_session_id("upstream-sid-abc", up_id, vs_id, "2025-11-25").unwrap();
            assert!(token.starts_with("sssid."));
            let decoded = decode_session_id(&token, DEFAULT_TOKEN_TTL_SECS).unwrap();
            assert_eq!(decoded.upstream_session_id, "upstream-sid-abc");
            assert_eq!(decoded.upstream_id, up_id);
            assert_eq!(decoded.virtual_server_id, vs_id);
            assert_eq!(decoded.protocol_version, "2025-11-25");
        });
    }

    #[test]
    fn a_wrapped_upstream_state_round_trips_and_is_covered_by_the_signature() {
        with_test_secret(|| {
            let tenant = Uuid::new_v4();
            let user = Uuid::new_v4();
            let vs = Uuid::new_v4();
            let upstream = Uuid::new_v4();
            let token = encode_request_state(
                tenant,
                user,
                vs,
                "tools/call",
                "digest",
                Some((upstream, Some("upstream-opaque-blob"))),
            )
            .unwrap();
            let decoded = decode_request_state(&token, DEFAULT_REQUEST_STATE_TTL_SECS).unwrap();
            assert_eq!(decoded.upstream_id, Some(upstream));
            assert_eq!(decoded.upstream_state.as_deref(), Some("upstream-opaque-blob"));

            // The upstream identity is inside the HMAC-protected payload, not
            // beside it: a caller who edits which upstream a retry re-issues
            // to invalidates the tag. Without this the wrapper would be a
            // routing hint anyone could rewrite, and a member could aim a
            // colleague's answered question at an upstream of their choosing.
            let (lhs, sig) = token.rsplit_once('.').unwrap();
            let mut payload = lhs.to_string();
            let last = payload.pop().unwrap();
            payload.push(if last == 'A' { 'B' } else { 'A' });
            assert_matches!(
                decode_request_state(&format!("{payload}.{sig}"), 0),
                Err(TokenError::Signature)
            );
        });
    }

    #[test]
    fn a_gateway_minted_state_names_no_upstream() {
        with_test_secret(|| {
            // The legacy-upstream bridge answers a retry by re-issuing, so it
            // has nothing to quote back. Both fields must read as absent —
            // `Some("")` would send an empty `requestState` upstream, which
            // is a value, not an omission.
            let token = encode_request_state(
                Uuid::new_v4(),
                Uuid::new_v4(),
                Uuid::new_v4(),
                "tools/call",
                "digest",
                None,
            )
            .unwrap();
            let decoded = decode_request_state(&token, DEFAULT_REQUEST_STATE_TTL_SECS).unwrap();
            assert!(decoded.upstream_id.is_none());
            assert!(decoded.upstream_state.is_none());
        });
    }

    #[test]
    fn an_upstream_that_asked_without_state_is_still_named_by_the_wrapper() {
        with_test_secret(|| {
            // § MRTR makes the upstream's own `requestState` optional, so a
            // modern upstream may ask a question and keep nothing. The retry
            // still has to reach THAT upstream, so the id travels alone —
            // this is the shape a single `Option` over the pair could not
            // express.
            let upstream = Uuid::new_v4();
            let token = encode_request_state(
                Uuid::new_v4(),
                Uuid::new_v4(),
                Uuid::new_v4(),
                "tools/call",
                "digest",
                Some((upstream, None)),
            )
            .unwrap();
            let decoded = decode_request_state(&token, DEFAULT_REQUEST_STATE_TTL_SECS).unwrap();
            assert_eq!(decoded.upstream_id, Some(upstream));
            assert!(decoded.upstream_state.is_none());
        });
    }

    #[test]
    fn session_signature_tamper_rejected() {
        with_test_secret(|| {
            let token = encode_session_id("u", Uuid::nil(), Uuid::nil(), "v").unwrap();
            // Flip last char of the payload segment.
            let (lhs, sig) = token.rsplit_once('.').unwrap();
            let mut tampered_payload = lhs.to_string();
            let last = tampered_payload.pop().unwrap();
            tampered_payload.push(if last == 'A' { 'B' } else { 'A' });
            let tampered = format!("{tampered_payload}.{sig}");
            let err = decode_session_id(&tampered, 0).unwrap_err();
            // Tamper either lands on the b64 boundary (decode fails) or on
            // payload bytes (signature fails). Both are rejection paths.
            assert_matches!(
                err,
                TokenError::Signature | TokenError::Base64 | TokenError::Payload
            );
        });
    }

    #[test]
    fn session_missing_prefix_rejected() {
        with_test_secret(|| {
            let err = decode_session_id("nope.payload.sig", 0).unwrap_err();
            assert_matches!(err, TokenError::MissingPrefix);
        });
    }

    #[test]
    fn session_ttl_expired_rejected() {
        with_test_secret(|| {
            let mut token = encode_session_id("u", Uuid::nil(), Uuid::nil(), "v").unwrap();
            // Reach into the payload and rewrite `t` to far past.
            let body = token.strip_prefix("sssid.").unwrap();
            let (payload_b64, _) = body.split_once('.').unwrap();
            let payload = B64.decode(payload_b64).unwrap();
            let mut parsed: SessionPayloadOwned = serde_json::from_slice(&payload).unwrap();
            parsed.t = 1; // 1970
            let new_json = serde_json::to_vec(&parsed).unwrap();
            let secret = token_secret(SESSION_DOMAIN).unwrap();
            let tag = sign(&secret, &new_json);
            token = format!("sssid.{}.{}", B64.encode(&new_json), B64.encode(&tag));
            let err = decode_session_id(&token, DEFAULT_TOKEN_TTL_SECS).unwrap_err();
            assert_matches!(err, TokenError::Expired);
            // ttl=0 disables the check.
            decode_session_id(&token, 0).expect("ttl=0 disables expiry check");
        });
    }

    #[test]
    fn request_round_trip_numeric_id() {
        with_test_secret(|| {
            let up_id = Uuid::new_v4();
            let tenant_id = Uuid::new_v4();
            let user_id = Uuid::new_v4();
            let token =
                encode_request_id(up_id, "u", &json!(42), tenant_id, user_id).unwrap();
            assert!(token.starts_with("ssrid."));
            let decoded = decode_request_id(&token, 0).unwrap();
            assert_eq!(decoded.upstream_id, up_id);
            assert_eq!(decoded.upstream_session_id, "u");
            assert_eq!(decoded.original_id, json!(42));
            assert_eq!(decoded.tenant_id, tenant_id);
            assert_eq!(decoded.user_id, user_id);
        });
    }

    #[test]
    fn request_round_trip_string_id() {
        with_test_secret(|| {
            let up_id = Uuid::new_v4();
            let tenant_id = Uuid::new_v4();
            let user_id = Uuid::new_v4();
            let token =
                encode_request_id(up_id, "u", &json!("req-abc"), tenant_id, user_id).unwrap();
            let decoded = decode_request_id(&token, 0).unwrap();
            assert_eq!(decoded.original_id, json!("req-abc"));
            assert_eq!(decoded.tenant_id, tenant_id);
            assert_eq!(decoded.user_id, user_id);
        });
    }

    #[test]
    fn uri_round_trip_diverse_schemes() {
        let cases = [
            ("file:///etc/hosts", "fs"),
            ("notion://page/abc?q=1#frag", "notion"),
            ("mailto:x@y.z", "mail"),
            ("urn:isbn:0451450523", "books"),
            ("", ""),
            ("https://example.com/path", "web_search"),
        ];
        for (original, prefix) in cases {
            let virt = encode_resource_uri(prefix, original);
            assert!(virt.starts_with("stsmcp://"));
            let (got_prefix, got_original) = decode_resource_uri(&virt).unwrap();
            assert_eq!(got_prefix, prefix);
            assert_eq!(got_original, original);
        }
    }

    #[test]
    fn uri_decode_rejects_non_stsmcp_scheme() {
        assert_matches!(
            decode_resource_uri("file:///x"),
            Err(TokenError::UriScheme)
        );
    }

    #[test]
    fn template_round_trip_simple() {
        let virt = encode_resource_template("gh", "file:///{path}").unwrap();
        assert_eq!(virt, "stsmcp+gh+file:///{path}");
        let (prefix, orig) = decode_resource_uri(&virt).unwrap();
        assert_eq!(prefix, "gh");
        assert_eq!(orig, "file:///{path}");
    }

    #[test]
    fn template_round_trip_after_placeholder_expansion() {
        // Agent expands `{path}` → `foo/bar` client-side. Decoded URI must
        // recover the post-expansion original. This is the load-bearing
        // round-trip property — without it, templates can't be virtualized
        // at all.
        let virt = encode_resource_template("gh", "file:///{path}").unwrap();
        let expanded = virt.replace("{path}", "foo/bar");
        assert_eq!(expanded, "stsmcp+gh+file:///foo/bar");
        let (prefix, orig) = decode_resource_uri(&expanded).unwrap();
        assert_eq!(prefix, "gh");
        assert_eq!(orig, "file:///foo/bar");
    }

    #[test]
    fn template_round_trip_complex_scheme_and_path() {
        // Per RFC 6570 placeholders may appear anywhere after the scheme.
        // Cover query-string + fragment placeholders in addition to path.
        let virt =
            encode_resource_template("api", "https://example.com/users/{id}?include={fields}#sect")
                .unwrap();
        let expanded = virt.replace("{id}", "42").replace("{fields}", "name,email");
        let (prefix, orig) = decode_resource_uri(&expanded).unwrap();
        assert_eq!(prefix, "api");
        assert_eq!(orig, "https://example.com/users/42?include=name,email#sect");
    }

    #[test]
    fn template_encode_rejects_missing_scheme() {
        assert_matches!(
            encode_resource_template("gh", "no-scheme-here/{x}"),
            Err(TokenError::TemplateNoScheme)
        );
    }

    #[test]
    fn template_encode_rejects_plus_in_scheme() {
        // Defensive — schemes like `git+ssh` would smuggle a `+` past our
        // envelope's prefix/scheme separator and corrupt the decode.
        assert_matches!(
            encode_resource_template("gh", "git+ssh://example.com/{repo}"),
            Err(TokenError::TemplateSchemeHasPlus)
        );
    }

    #[test]
    fn template_round_trip_empty_prefix_is_single_route_case() {
        // Empty prefix is the no-namespacing route — `route_for_prefix(_, Some(""))`
        // matches the no-namespacing route — and must round-trip.
        let virt = encode_resource_template("", "file:///{path}").unwrap();
        assert_eq!(virt, "stsmcp++file:///{path}");
        let (prefix, orig) = decode_resource_uri(&virt).unwrap();
        assert_eq!(prefix, "");
        assert_eq!(orig, "file:///{path}");
    }

    #[test]
    fn template_decode_rejects_empty_scheme() {
        // Defensive — `stsmcp+gh+://` decodes to ("gh", "://") which is
        // unusable; reject at decode rather than letting an invalid orig
        // URI smuggle through to the upstream.
        assert_matches!(
            decode_resource_uri("stsmcp+gh+://"),
            Err(TokenError::UriMalformed)
        );
    }

    #[test]
    fn decode_disambiguates_concrete_vs_template() {
        // Both envelopes round-trip without colliding on the parser.
        let concrete = encode_resource_uri("ns", "file:///a");
        let template = encode_resource_template("ns", "file:///{p}").unwrap();
        let (p1, o1) = decode_resource_uri(&concrete).unwrap();
        let (p2, o2) = decode_resource_uri(&template).unwrap();
        assert_eq!((p1.as_str(), o1.as_str()), ("ns", "file:///a"));
        assert_eq!((p2.as_str(), o2.as_str()), ("ns", "file:///{p}"));
    }

    #[test]
    fn uri_decode_rejects_malformed_b64() {
        assert_matches!(
            decode_resource_uri("stsmcp://gh/!!!not-b64"),
            Err(TokenError::Base64)
        );
    }

    #[test]
    fn distinct_domains_produce_distinct_secrets() {
        with_test_secret(|| {
            let s1 = token_secret(SESSION_DOMAIN).unwrap();
            let s2 = token_secret(REQUEST_DOMAIN).unwrap();
            let s3 = token_secret(EVENT_DOMAIN).unwrap();
            assert_ne!(s1, s2);
            assert_ne!(s1, s3);
            assert_ne!(s2, s3);
        });
    }

    #[test]
    fn event_round_trip() {
        with_test_secret(|| {
            let tenant_id = Uuid::new_v4();
            let user_id = Uuid::new_v4();
            let token = encode_event_id(tenant_id, user_id, "sess-abc", 42).unwrap();
            assert!(token.starts_with("ssevt."));
            let decoded = decode_event_id(&token, DEFAULT_TOKEN_TTL_SECS).unwrap();
            assert_eq!(decoded.tenant_id, tenant_id);
            assert_eq!(decoded.user_id, user_id);
            assert_eq!(decoded.mcp_session_id, "sess-abc");
            assert_eq!(decoded.sequence, 42);
        });
    }

    #[test]
    fn event_signature_tamper_rejected() {
        with_test_secret(|| {
            let token =
                encode_event_id(Uuid::nil(), Uuid::nil(), "s", 1).unwrap();
            let (lhs, sig) = token.rsplit_once('.').unwrap();
            let mut tampered_payload = lhs.to_string();
            let last = tampered_payload.pop().unwrap();
            tampered_payload.push(if last == 'A' { 'B' } else { 'A' });
            let tampered = format!("{tampered_payload}.{sig}");
            let err = decode_event_id(&tampered, 0).unwrap_err();
            assert_matches!(
                err,
                TokenError::Signature | TokenError::Base64 | TokenError::Payload
            );
        });
    }

    #[test]
    fn event_missing_prefix_rejected() {
        with_test_secret(|| {
            let err = decode_event_id("nope.payload.sig", 0).unwrap_err();
            assert_matches!(err, TokenError::MissingPrefix);
        });
    }

    #[test]
    fn event_ttl_expired_rejected() {
        with_test_secret(|| {
            let mut token =
                encode_event_id(Uuid::nil(), Uuid::nil(), "s", 1).unwrap();
            // Reach into the payload and rewrite `ts` to far past.
            let body = token.strip_prefix("ssevt.").unwrap();
            let (payload_b64, _) = body.split_once('.').unwrap();
            let payload = B64.decode(payload_b64).unwrap();
            let mut parsed: EventPayloadOwned = serde_json::from_slice(&payload).unwrap();
            parsed.ts = 1; // 1970
            let new_json = serde_json::to_vec(&parsed).unwrap();
            let secret = token_secret(EVENT_DOMAIN).unwrap();
            let tag = sign(&secret, &new_json);
            token = format!("ssevt.{}.{}", B64.encode(&new_json), B64.encode(&tag));
            let err = decode_event_id(&token, DEFAULT_TOKEN_TTL_SECS).unwrap_err();
            assert_matches!(err, TokenError::Expired);
            // ttl=0 disables the check.
            decode_event_id(&token, 0).expect("ttl=0 disables expiry check");
        });
    }

    #[test]
    fn event_cross_user_tenant_decodes_for_caller_check() {
        // The decode itself is identity-agnostic; the caller compares the
        // decoded `(tenant_id, user_id)` against the authenticated identity
        // and silently falls back to a fresh connect on mismatch. This test
        // documents that decoding succeeds — the rejection is at the caller.
        with_test_secret(|| {
            let user_a = Uuid::new_v4();
            let user_b = Uuid::new_v4();
            let tenant_id = Uuid::new_v4();
            let token = encode_event_id(tenant_id, user_a, "s", 7).unwrap();
            let decoded = decode_event_id(&token, 0).unwrap();
            assert_eq!(decoded.user_id, user_a);
            assert_ne!(decoded.user_id, user_b);
        });
    }

    #[test]
    fn event_malformed_token_rejected() {
        with_test_secret(|| {
            assert_matches!(
                decode_event_id("ssevt.justonepart", 0),
                Err(TokenError::Malformed)
            );
            assert_matches!(
                decode_event_id("ssevt.!notb64.!notb64", 0),
                Err(TokenError::Base64)
            );
        });
    }
}

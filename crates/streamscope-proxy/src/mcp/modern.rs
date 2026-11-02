//! MCP 2026-07-28 — the stateless, per-request-metadata ("modern") era.
//!
//! Revisions `2025-03-26` … `2025-11-25` (the *legacy* era) open with an
//! `initialize` handshake and carry the negotiated version, the client's
//! identity, and its capabilities as connection state. `2026-07-28` deletes
//! all of that: there is no handshake, no `Mcp-Session-Id`, no GET stream, and
//! every request restates its own version, identity and capabilities in
//! `params._meta`.
//!
//! This module is the era's pure logic — validation, translation, and result
//! shaping. It holds no I/O and no gateway state so every rule below is
//! unit-testable on its own; [`super::handler`] wires it into the transport.
//!
//! Three invariants to preserve when editing:
//!
//! 1. **The era is decided once, from the version, and never re-derived.**
//!    A request is modern iff its resolved protocol version is in
//!    [`MODERN_PROTOCOL_VERSIONS`]. Sniffing for the *shape* of a request
//!    (does it carry `_meta`? does it look stateless?) reintroduces exactly
//!    the ambiguity the version field exists to remove.
//! 2. **Header and body must agree before either is trusted.** The transport
//!    mirrors body fields into headers so intermediaries can route without
//!    parsing; an intermediary routing on the header while we execute on the
//!    body is the vulnerability [`validate_transport_headers`] closes.
//! 3. **Nothing crosses the era boundary unconverted.** A legacy upstream's
//!    result is not a modern result until [`stamp_result`] has run, and a
//!    modern client's request is not a legacy request until
//!    [`downgrade_request_params`] has run.

use std::collections::BTreeMap;

use axum::http::HeaderMap;
use base64::Engine;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use super::jsonrpc::{INVALID_PARAMS, JsonRpcRequest, METHOD_NOT_FOUND};

// ── Protocol versions ────────────────────────────────────────────────────

/// The modern revision this gateway implements.
pub const MODERN_PROTOCOL_VERSION: &str = "2026-07-28";

/// Every modern revision we serve. A future modern revision is added here
/// *and* to `MCP_SUPPORTED_PROTOCOL_VERSIONS`; membership of this set is the
/// only thing that decides a request's era.
pub const MODERN_PROTOCOL_VERSIONS: &[&str] = &[MODERN_PROTOCOL_VERSION];

/// True when `version` names a modern (stateless, per-request-`_meta`)
/// revision.
pub fn is_modern(version: &str) -> bool {
    MODERN_PROTOCOL_VERSIONS.contains(&version)
}

// ── Reserved `_meta` keys (MCP 2026-07-28 § General fields / `_meta`) ────

pub const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
pub const META_CLIENT_INFO: &str = "io.modelcontextprotocol/clientInfo";
pub const META_CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
pub const META_LOG_LEVEL: &str = "io.modelcontextprotocol/logLevel";
pub const META_SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";
pub const META_SUBSCRIPTION_ID: &str = "io.modelcontextprotocol/subscriptionId";

/// The `_meta` keys the modern era defines for *requests*. These are the
/// gateway's own protocol envelope and are stripped before a request is
/// forwarded to a legacy upstream, which would not understand them.
///
/// `progressToken` and the OpenTelemetry trio (`traceparent`, `tracestate`,
/// `baggage`) are deliberately NOT in this list: both predate the era split
/// and mean the same thing to a legacy upstream, so stripping them would lose
/// progress reporting and break distributed traces across the gateway.
const MODERN_REQUEST_META_KEYS: &[&str] = &[
    META_PROTOCOL_VERSION,
    META_CLIENT_INFO,
    META_CLIENT_CAPABILITIES,
    META_LOG_LEVEL,
];

// ── Error codes (MCP 2026-07-28 § Error Codes) ───────────────────────────
//
// `-32020`..=`-32099` is reserved for the specification. We MUST NOT emit a
// code from that sub-range the spec has not defined, so these three are the
// only members of it this gateway may ever send.

/// HTTP headers disagree with the request body, or a required header is
/// missing or malformed. Always paired with HTTP 400.
pub const HEADER_MISMATCH: i32 = -32020;

/// Processing the request needs a client capability the request did not
/// declare. `data.requiredCapabilities` names it. Always paired with HTTP 400.
pub const MISSING_REQUIRED_CLIENT_CAPABILITY: i32 = -32021;

/// The requested protocol version is one we do not serve.
/// `data.supported` lists what we do. Always paired with HTTP 400.
pub const UNSUPPORTED_PROTOCOL_VERSION: i32 = -32022;

/// Resource-not-found as spelled by revisions up to `2025-11-25`. A modern
/// response MUST NOT carry it (the spec reassigned the condition to
/// `-32602`), but a legacy *upstream* still emits it, so
/// [`modernize_error_code`] translates it on the way out.
pub const LEGACY_RESOURCE_NOT_FOUND: i32 = -32002;

// ── Era ──────────────────────────────────────────────────────────────────

/// Which protocol era a single request belongs to.
///
/// The gateway is dual-era: it serves legacy clients on the `initialize`
/// handshake and modern clients statelessly, on the same mount, and decides
/// per request rather than per connection — which is the only thing that can
/// work once connections stop being sessions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolEra {
    /// `2025-03-26` … `2025-11-25`. Sessions, `initialize`, GET stream.
    Legacy(String),
    /// `2026-07-28` and later. Stateless, per-request `_meta`.
    Modern(String),
}

impl ProtocolEra {
    pub fn version(&self) -> &str {
        match self {
            ProtocolEra::Legacy(v) | ProtocolEra::Modern(v) => v,
        }
    }

    pub fn is_modern(&self) -> bool {
        matches!(self, ProtocolEra::Modern(_))
    }
}

// ── Errors ───────────────────────────────────────────────────────────────

/// A modern-era protocol rejection, carrying everything the transport needs
/// to render it: the HTTP status the spec mandates, the JSON-RPC code, a
/// human-readable message, and the typed `data` payload the client reads.
#[derive(Debug, Clone)]
pub struct ModernError {
    pub status: axum::http::StatusCode,
    pub code: i32,
    pub message: String,
    pub data: Option<Value>,
}

impl ModernError {
    /// `-32020`. Every header-validation failure is a 400 per
    /// § Server Validation.
    pub fn header_mismatch(message: impl Into<String>) -> Self {
        Self {
            status: axum::http::StatusCode::BAD_REQUEST,
            code: HEADER_MISMATCH,
            message: message.into(),
            data: None,
        }
    }

    /// `-32022` with the `supported` / `requested` pair the client needs in
    /// order to retry at a version we both speak.
    pub fn unsupported_version(requested: &str, supported: &[&str]) -> Self {
        Self {
            status: axum::http::StatusCode::BAD_REQUEST,
            code: UNSUPPORTED_PROTOCOL_VERSION,
            message: "Unsupported protocol version".to_string(),
            data: Some(json!({ "supported": supported, "requested": requested })),
        }
    }

    /// `-32021`. `required` is a `ClientCapabilities` object naming what the
    /// request would have needed, e.g. `{"elicitation": {}}`.
    pub fn missing_client_capability(required: Value, message: impl Into<String>) -> Self {
        Self {
            status: axum::http::StatusCode::BAD_REQUEST,
            code: MISSING_REQUIRED_CLIENT_CAPABILITY,
            message: message.into(),
            data: Some(json!({ "requiredCapabilities": required })),
        }
    }

    /// `-32602`. A required `_meta` field is absent or the wrong shape.
    /// § `_meta` mandates 400 for this, not the JSON-RPC-conventional 200.
    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self {
            status: axum::http::StatusCode::BAD_REQUEST,
            code: INVALID_PARAMS,
            message: message.into(),
            data: None,
        }
    }

    /// `-32600` + HTTP 400. The message is a well-formed JSON-RPC envelope
    /// carrying something this era does not admit on the wire at all.
    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self {
            status: axum::http::StatusCode::BAD_REQUEST,
            code: super::jsonrpc::INVALID_REQUEST,
            message: message.into(),
            data: None,
        }
    }

    /// `-32601` + HTTP 404. § Protocol Version Header is explicit that an
    /// unimplemented RPC is a 404 whose *body* distinguishes it from a legacy
    /// HTTP+SSE server's 404 — which is what a dual-era client probes for.
    pub fn method_not_found(message: impl Into<String>) -> Self {
        Self {
            status: axum::http::StatusCode::NOT_FOUND,
            code: METHOD_NOT_FOUND,
            message: message.into(),
            data: None,
        }
    }
}

// ── Header value codec (§ Value Encoding) ────────────────────────────────

const B64_SENTINEL_PREFIX: &str = "=?base64?";
const B64_SENTINEL_SUFFIX: &str = "?=";
const B64_STD: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// True when `raw` may travel as a plain HTTP header value.
///
/// RFC 9110 admits visible ASCII (0x21-0x7E), space, and horizontal tab; the
/// MCP transport additionally excludes leading/trailing whitespace (a proxy
/// may strip it, silently changing the value) and any string shaped like the
/// Base64 sentinel (which would decode to something else on the far side).
fn is_plain_header_safe(raw: &str) -> bool {
    if raw.is_empty() {
        return true;
    }
    if raw
        .chars()
        .any(|c| !(c == '\t' || c == ' ' || ('\u{21}'..='\u{7e}').contains(&c)))
    {
        return false;
    }
    let first = raw.as_bytes()[0];
    let last = raw.as_bytes()[raw.len() - 1];
    if matches!(first, b' ' | b'\t') || matches!(last, b' ' | b'\t') {
        return false;
    }
    !looks_like_sentinel(raw)
}

/// True when `raw` has the exact `=?base64?…?=` shape. The markers are
/// case-sensitive and MUST appear literally, so this is a byte comparison and
/// never a case-insensitive one.
fn looks_like_sentinel(raw: &str) -> bool {
    raw.len() >= B64_SENTINEL_PREFIX.len() + B64_SENTINEL_SUFFIX.len()
        && raw.starts_with(B64_SENTINEL_PREFIX)
        && raw.ends_with(B64_SENTINEL_SUFFIX)
}

/// Render `raw` as an `Mcp-Name` / `Mcp-Param-*` header value.
///
/// Plain-safe values pass through untouched; everything else — non-ASCII,
/// control characters, padded whitespace, or a value that merely *looks* like
/// the sentinel — is wrapped as `=?base64?<base64(utf8)>?=`.
pub fn encode_header_value(raw: &str) -> String {
    if is_plain_header_safe(raw) {
        return raw.to_string();
    }
    format!(
        "{B64_SENTINEL_PREFIX}{}{B64_SENTINEL_SUFFIX}",
        B64_STD.encode(raw.as_bytes())
    )
}

/// Recover the logical value behind an `Mcp-Name` / `Mcp-Param-*` header.
///
/// The claim this makes, and the only one: a value produced by
/// [`encode_header_value`] decodes back to the identical string. It makes
/// **no** injectivity claim in the other direction — `abc` and
/// `=?base64?YWJj?=` are distinct wire forms of the same logical value, by
/// the transport's design — and it is deliberately **single-pass**: a decoded
/// value that happens to look like a sentinel again is the caller's data, not
/// another layer, so idempotence must never be asserted here.
pub fn decode_header_value(raw: &str) -> Result<String, ModernError> {
    if !looks_like_sentinel(raw) {
        return Ok(raw.to_string());
    }
    let inner = &raw[B64_SENTINEL_PREFIX.len()..raw.len() - B64_SENTINEL_SUFFIX.len()];
    let bytes = B64_STD.decode(inner).map_err(|_| {
        ModernError::header_mismatch("header value is not valid Base64 inside the =?base64?…?= sentinel")
    })?;
    String::from_utf8(bytes).map_err(|_| {
        ModernError::header_mismatch("header value did not Base64-decode to valid UTF-8")
    })
}

// ── Per-request metadata (§ `_meta`) ─────────────────────────────────────

/// The modern protocol envelope carried in `params._meta` on every request.
#[derive(Debug, Clone)]
pub struct RequestMeta {
    pub protocol_version: String,
    /// Self-reported and unverified. Display, logging and audit only — never
    /// a behavioural or security input, per § `_meta`.
    pub client_info: Option<Value>,
    /// Required, and possibly empty (`{}` = no optional capabilities). The
    /// gateway MUST NOT infer a capability from a previous request.
    pub client_capabilities: Value,
    /// When absent, the server MUST NOT emit `notifications/message` for this
    /// request. This replaced the `logging/setLevel` RPC.
    pub log_level: Option<String>,
}

impl RequestMeta {
    /// True when the client declared support for elicitation. Gates whether
    /// an `elicitation/create` may appear in an `InputRequiredResult`.
    pub fn supports_elicitation(&self) -> bool {
        self.client_capabilities.get("elicitation").is_some()
    }

    /// True when the client declared support for sampling.
    pub fn supports_sampling(&self) -> bool {
        self.client_capabilities.get("sampling").is_some()
    }

    /// True when the client declared support for listing roots.
    pub fn supports_roots(&self) -> bool {
        self.client_capabilities.get("roots").is_some()
    }

    /// A display label for the client, from the identity it self-reported.
    ///
    /// A modern client declares itself in `clientInfo`; `User-Agent` is a
    /// transport nicety an SDK need not send at all. Without this fallback an
    /// audit row for a modern caller would identify nobody.
    ///
    /// Self-reported and unverified, exactly like a `User-Agent` — for
    /// display and diagnosis, never for a security or routing decision.
    pub fn client_info_label(&self) -> Option<String> {
        let info = self.client_info.as_ref()?;
        let name = info.get("name").and_then(Value::as_str)?;
        Some(match info.get("version").and_then(Value::as_str) {
            Some(version) => format!("{name}/{version}"),
            None => name.to_string(),
        })
    }

    /// Whether the server may emit `notifications/message` for this request.
    ///
    /// § Logging: "If absent, the server MUST NOT send any
    /// `notifications/message` notifications for this request." The client
    /// opts in by naming a level; there is no `logging/setLevel` any more and
    /// therefore no connection-scoped default to inherit.
    pub fn wants_log_notifications(&self) -> bool {
        self.log_level.is_some()
    }

    /// Whether the capability an `InputRequest` of `method` would consume was
    /// declared. § MRTR server requirement 7 forbids asking for input the
    /// client cannot produce.
    pub fn supports_input_request(&self, method: &str) -> bool {
        match method {
            "elicitation/create" => self.supports_elicitation(),
            "sampling/createMessage" => self.supports_sampling(),
            "roots/list" => self.supports_roots(),
            // An input request we do not recognise is one we cannot promise
            // the client understands either. Fail closed.
            _ => false,
        }
    }
}

/// The `ClientCapabilities` object naming the capability an input request of
/// `method` consumes — the `data.requiredCapabilities` payload of a
/// `-32021`.
pub fn required_capability_for(method: &str) -> Value {
    match method {
        "elicitation/create" => json!({ "elicitation": {} }),
        "sampling/createMessage" => json!({ "sampling": {} }),
        "roots/list" => json!({ "roots": {} }),
        _ => json!({}),
    }
}

/// Extract and validate the modern `_meta` envelope from a request's params.
///
/// Every field the spec marks required is checked here, because a server that
/// accepts a request missing one has no other moment to notice: there is no
/// handshake in which the omission would have surfaced.
pub fn extract_request_meta(params: Option<&Value>) -> Result<RequestMeta, ModernError> {
    let meta = params.and_then(|p| p.get("_meta")).ok_or_else(|| {
        ModernError::invalid_params(
            "params._meta is required on every request in protocol version 2026-07-28",
        )
    })?;
    let meta = meta.as_object().ok_or_else(|| {
        ModernError::invalid_params("params._meta must be an object")
    })?;

    let protocol_version = meta
        .get(META_PROTOCOL_VERSION)
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            ModernError::invalid_params(format!(
                "params._meta['{META_PROTOCOL_VERSION}'] is required and must be a string"
            ))
        })?
        .to_string();

    // Required, and an object. An absent value is a malformed request rather
    // than "no capabilities": the distinction matters because the server MUST
    // NOT infer capabilities, so silently reading a missing field as `{}`
    // would turn a client bug into a capability the client never claimed.
    let client_capabilities = meta.get(META_CLIENT_CAPABILITIES).ok_or_else(|| {
        ModernError::invalid_params(format!(
            "params._meta['{META_CLIENT_CAPABILITIES}'] is required"
        ))
    })?;
    if !client_capabilities.is_object() {
        return Err(ModernError::invalid_params(format!(
            "params._meta['{META_CLIENT_CAPABILITIES}'] must be an object"
        )));
    }

    Ok(RequestMeta {
        protocol_version,
        client_info: meta.get(META_CLIENT_INFO).cloned(),
        client_capabilities: client_capabilities.clone(),
        log_level: meta
            .get(META_LOG_LEVEL)
            .and_then(|v| v.as_str())
            .map(str::to_string),
    })
}

// ── Transport header validation (§ Server Validation) ────────────────────

/// The value `Mcp-Name` mirrors for `method`, read out of the request body.
///
/// `None` means the method does not carry the header at all — the three
/// methods listed in § Standard Request Headers are the closed set that does.
pub fn mcp_name_source(method: &str, params: Option<&Value>) -> Option<String> {
    let field = match method {
        "tools/call" | "prompts/get" => "name",
        "resources/read" => "uri",
        _ => return None,
    };
    params
        .and_then(|p| p.get(field))
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// Validate that the mirrored HTTP headers agree with the request body.
///
/// This exists because the transport lets an intermediary route on the header
/// without parsing the body. If a load balancer can be made to read one tool
/// name while we execute another, the mirroring is a vulnerability rather
/// than an optimisation — so disagreement is a hard `400`, never a warning.
///
/// `Mcp-Param-*` headers are **not** validated here, deliberately. Binding one
/// to a body value requires the owning tool's `inputSchema` (`x-mcp-header`
/// annotations), which belongs to the upstream that defines the tool, not to
/// this gateway. § Server Behavior for Custom Headers gives intermediaries
/// exactly this carve-out: forward what you do not recognise. We still refuse
/// a structurally invalid one via [`validate_param_header_syntax`], because
/// forwarding a header with a smuggled control character is never correct.
pub fn validate_transport_headers(
    headers: &HeaderMap,
    request: &JsonRpcRequest,
) -> Result<(), ModernError> {
    let method_header = headers
        .get("mcp-method")
        .ok_or_else(|| ModernError::header_mismatch("Mcp-Method header is required"))?
        .to_str()
        .map_err(|_| ModernError::header_mismatch("Mcp-Method header is not valid ASCII"))?;
    if method_header != request.method {
        return Err(ModernError::header_mismatch(format!(
            "Mcp-Method header value '{method_header}' does not match body method '{}'",
            request.method
        )));
    }

    match mcp_name_source(&request.method, request.params.as_ref()) {
        Some(body_name) => {
            let raw = headers
                .get("mcp-name")
                .ok_or_else(|| {
                    ModernError::header_mismatch(format!(
                        "Mcp-Name header is required for {}",
                        request.method
                    ))
                })?
                .to_str()
                .map_err(|_| {
                    ModernError::header_mismatch("Mcp-Name header is not valid ASCII")
                })?;
            let decoded = decode_header_value(raw)?;
            if decoded != body_name {
                return Err(ModernError::header_mismatch(
                    "Mcp-Name header value does not match the corresponding body value",
                ));
            }
        }
        None => {
            // The method mirrors no name, so a header present anyway has
            // nothing in the body to be checked against. It is *ignored*
            // rather than refused: the spec defines a failure as a header
            // that disagrees with its body value, and a method with no such
            // value cannot produce one — refusing would reject a client the
            // spec permits. It is never relayed either, because the outbound
            // headers are rebuilt from the request we actually send (see
            // [`outbound_transport_headers`]), so an unvalidatable value
            // cannot reach the next hop through us.
            if headers.contains_key("mcp-name") {
                tracing::debug!(
                    method = %request.method,
                    "MCP: ignoring an Mcp-Name header on a method that mirrors no name"
                );
            }
        }
    }

    validate_param_header_syntax(headers)
}

/// Refuse an `Mcp-Param-*` header we cannot forward safely.
///
/// A header value that is neither plain-safe nor a well-formed sentinel
/// cannot have come from a conforming client, and forwarding it verbatim
/// would hand the next hop bytes we never validated.
fn validate_param_header_syntax(headers: &HeaderMap) -> Result<(), ModernError> {
    for (name, value) in headers.iter() {
        let lower = name.as_str().to_ascii_lowercase();
        if !lower.starts_with("mcp-param-") {
            continue;
        }
        if lower.len() == "mcp-param-".len() {
            return Err(ModernError::header_mismatch(
                "Mcp-Param- header has an empty parameter name",
            ));
        }
        let raw = value.to_str().map_err(|_| {
            ModernError::header_mismatch(format!("{name} header is not valid ASCII"))
        })?;
        // A sentinel value must actually decode; a plain value must be
        // representable as one. Anything else is malformed.
        if looks_like_sentinel(raw) {
            decode_header_value(raw)?;
        } else if !is_plain_header_safe(raw) {
            return Err(ModernError::header_mismatch(format!(
                "{name} header value contains characters that are not valid in an HTTP field value"
            )));
        }
    }
    Ok(())
}

/// Restamp the mirrored headers for a request the gateway is forwarding to a
/// *modern* upstream, after virtualization has rewritten the body.
///
/// This is required rather than cosmetic: the gateway strips the namespace
/// prefix off `params.name` and decodes `stsmcp://` URIs before forwarding,
/// so relaying the client's original `Mcp-Name` would present the upstream
/// with a header that disagrees with the body we just sent it — which that
/// upstream MUST reject with `-32020`.
pub fn outbound_transport_headers(request: &JsonRpcRequest) -> Vec<(&'static str, String)> {
    let mut out = vec![("Mcp-Method", request.method.clone())];
    if let Some(name) = mcp_name_source(&request.method, request.params.as_ref()) {
        out.push(("Mcp-Name", encode_header_value(&name)));
    }
    out
}

// ── Method surface (§ changelog, major changes 2, 4, 5) ──────────────────

/// Methods the modern era deleted. Reaching one is a `404` + `-32601`, not a
/// silent pass-through to an upstream that might still answer it — answering
/// would let a client believe the gateway is legacy and resume building
/// connection state we do not keep.
pub fn is_removed_in_modern(method: &str) -> bool {
    matches!(
        method,
        "initialize"
            | "ping"
            | "logging/setLevel"
            | "resources/subscribe"
            | "resources/unsubscribe"
    )
}

/// Client-to-server notifications the modern era deleted. A notification POST
/// is answered with a status code and no body, so a removed one is a `400`
/// rather than a JSON-RPC error the client would never read.
pub fn is_removed_notification_in_modern(method: &str) -> bool {
    matches!(
        method,
        "notifications/initialized" | "notifications/roots/list_changed"
    )
}

/// Server-to-client notifications the modern era deleted, which a *legacy
/// upstream* may still emit onto a stream a modern client is reading.
///
/// `notifications/elicitation/complete` signalled that an out-of-band URL-mode
/// elicitation had finished. `2026-07-28` removed it along with the
/// `elicitationId` it carried, because under MRTR the client learns the
/// outcome by retrying the original request — there is nothing for a
/// server-initiated completion signal to correlate against. Forwarding one to
/// a modern client hands it a method its revision does not define, on a stream
/// where the spec is explicit about what may appear.
pub fn is_removed_server_notification_in_modern(method: &str) -> bool {
    matches!(method, "notifications/elicitation/complete")
}

/// `server/discover` — the one RPC every modern server MUST implement.
pub const METHOD_DISCOVER: &str = "server/discover";

/// `subscriptions/listen` — the long-lived notification stream that replaced
/// the GET endpoint and `resources/subscribe`.
pub const METHOD_SUBSCRIPTIONS_LISTEN: &str = "subscriptions/listen";

// ── Result shaping (§ Responses, § CacheableResult) ──────────────────────

/// How long a client may treat a result as fresh, and who may share it.
#[derive(Debug, Clone, Copy)]
pub struct CacheHint {
    pub ttl_ms: u64,
    /// Always `"private"` for this gateway. A tool list is rendered per
    /// caller — workspace grants, route filters and per-user upstream OAuth
    /// all shape it — so a shared intermediary that reused one caller's copy
    /// for another would be serving them someone else's catalog. Never widen
    /// this to `"public"` without a mechanism that proves the response is
    /// caller-independent.
    pub scope: &'static str,
}

impl CacheHint {
    /// A result the client should re-fetch every time.
    pub fn stale() -> Self {
        Self { ttl_ms: 0, scope: "private" }
    }

    /// A result we would ourselves serve from cache for `ttl_ms`.
    pub fn fresh_for(ttl_ms: u64) -> Self {
        Self { ttl_ms, scope: "private" }
    }
}

/// Methods whose result is a `CacheableResult` and therefore MUST carry
/// `ttlMs` and `cacheScope`.
pub fn is_cacheable_result(method: &str) -> bool {
    matches!(
        method,
        "tools/list"
            | "prompts/list"
            | "resources/list"
            | "resources/templates/list"
            | "resources/read"
            | METHOD_DISCOVER
    )
}

/// Bring a result produced for (or by) an upstream up to modern shape.
///
/// Adds the three things a modern result MUST or SHOULD carry and a legacy
/// one never does: `resultType`, the server identity in `_meta`, and — for a
/// cacheable method — the freshness hint.
///
/// **`resultType` is the one field an upstream's own answer keeps.** A modern
/// upstream saying `input_required` is making a statement about its own call
/// that the gateway must not overwrite with `complete`. Everything else is
/// the gateway's to state, and is overwritten even when the upstream supplied
/// it, because the client is not talking to that upstream:
///
/// - `_meta.serverInfo` must name the gateway. Relaying an upstream's
///   identity tells the client it reached a server it never addressed — and
///   on a multi-route virtual server, one arbitrary member of several.
/// - `ttlMs` / `cacheScope` govern the caching of *our* answer, which is
///   assembled from every route and narrowed by this caller's grants and tool
///   policy. An upstream's freshness claim is about its own unfiltered
///   catalog and cannot be inherited by ours.
pub fn stamp_result(
    result: &mut Value,
    method: &str,
    server_info: &Value,
    cache_hint: Option<CacheHint>,
) {
    let Some(obj) = result.as_object_mut() else {
        // MCP results are objects by construction. A non-object here is an
        // upstream that is not speaking MCP; leave it alone rather than
        // fabricate a shape around it, and let the caller's audit row carry
        // the anomaly.
        tracing::warn!(
            method = %method,
            "MCP modern: upstream result is not a JSON object; cannot stamp resultType"
        );
        return;
    };

    obj.entry("resultType")
        .or_insert_with(|| Value::String("complete".to_string()));

    if let Some(hint) = cache_hint {
        obj.insert("ttlMs".to_string(), json!(hint.ttl_ms));
        obj.insert(
            "cacheScope".to_string(),
            Value::String(hint.scope.to_string()),
        );
    }

    let meta = obj
        .entry("_meta")
        .or_insert_with(|| Value::Object(Map::new()));
    if let Some(meta_obj) = meta.as_object_mut() {
        meta_obj.insert(META_SERVER_INFO.to_string(), server_info.clone());
    }
}

/// Translate an error code produced under legacy rules into one a modern
/// client is allowed to receive.
///
/// Two distinct obligations meet here:
///
/// - `-32002` MUST NOT be emitted at all in this revision; the spec moved
///   resource-not-found onto `-32602`.
/// - `-32000`..=`-32019` is frozen, and a receiver "MUST NOT assume any
///   specific meaning" for a code in it. Our three gateway codes live there,
///   so to a modern client they are indistinguishable noise. Mapping them
///   onto the standard JSON-RPC code that carries the same meaning is
///   strictly more informative than passing them through.
///
/// The original code is preserved in `data` so the meaning is not lost for
/// operators reading an audit row or a client that wants the detail.
pub fn modernize_error_code(code: i32) -> Option<i32> {
    match code {
        LEGACY_RESOURCE_NOT_FOUND => Some(INVALID_PARAMS),
        super::jsonrpc::ROUTE_NOT_FOUND => Some(METHOD_NOT_FOUND),
        super::jsonrpc::TOOL_NOT_FOUND => Some(INVALID_PARAMS),
        super::jsonrpc::UPSTREAM_ERROR => Some(super::jsonrpc::INTERNAL_ERROR),
        _ => None,
    }
}

/// [`modernize_error_code`], refined by what the error carries.
///
/// `ROUTE_NOT_FOUND` is **overloaded**: it answers both "this mount names no
/// route" (no such tenant / virtual server / upstream) and "the URI you asked
/// for does not resolve". Those renumber to opposite things — the first really
/// is a missing endpoint (`-32601`, HTTP 404), the second is a bad parameter
/// (`-32602`, HTTP 200, per SEP-2164). A map keyed on the value alone cannot
/// separate them, which is why fixing one of the two by changing the emitted
/// code necessarily breaks the other era's wire.
///
/// `data.uri` is the discriminator. It works because it keys on the GATEWAY'S
/// OWN emissions: `resource_not_found` is the only site that attaches a `uri`,
/// and it attaches one every time, so within our own errors the field is
/// present exactly when the error is about a resource rather than a route.
/// (SEP-2164 only says the `data` SHOULD carry the uri — it is not a guarantee
/// about anyone else's errors, so do not extend this discriminator to
/// upstream-relayed codes on the assumption that it is.) Emitting it at the
/// site lets the era gate — the one place that knows which wire is in front of
/// it — answer both meanings without `dispatch` having to know the era.
fn modernize_error_code_with_data(code: i32, data: Option<&Value>) -> Option<i32> {
    if code == super::jsonrpc::ROUTE_NOT_FOUND
        && data.and_then(|d| d.get("uri")).is_some()
    {
        return Some(INVALID_PARAMS);
    }
    modernize_error_code(code)
}

/// Rewrite an outbound JSON-RPC error in place so it is legal for a modern
/// client, recording what it used to be under `data.streamscopeCode`.
pub fn modernize_error(err: &mut super::jsonrpc::JsonRpcError) {
    let Some(modern) = modernize_error_code_with_data(err.code, err.data.as_ref()) else {
        return;
    };
    let original = err.code;
    err.code = modern;
    let data = err.data.get_or_insert_with(|| Value::Object(Map::new()));
    if let Some(obj) = data.as_object_mut() {
        obj.entry("streamscopeCode").or_insert_with(|| json!(original));
    }
}

/// The HTTP status a modern client must receive alongside `code`.
///
/// This revision makes the status part of an error's meaning rather than a
/// transport detail, because a dual-era client reads it to decide whether to
/// fall back: § Backward Compatibility instructs a client that a `400`
/// carrying a *recognized* modern error means "this server is modern, correct
/// the request and retry", while an unrecognized body means "fall back to
/// `initialize`". Answering `200` for these makes the gateway look like a
/// server that implemented the method and then broke, so the client neither
/// falls back nor reports the failure.
///
/// Only the statuses the specification actually mandates appear here;
/// everything else keeps the JSON-RPC convention of a `200` carrying an error
/// body. `-32602` is deliberately NOT mapped: it is mandated as `400` only
/// for a malformed `_meta` envelope — which is rendered from
/// [`ModernError::invalid_params`] and carries its own status — while the
/// same code answers a `resources/read` for a URI that does not exist, a
/// request that was understood and refused rather than malformed.
pub fn http_status_for_error(code: i32) -> axum::http::StatusCode {
    match code {
        // § Protocol Version Header: an unimplemented RPC is a 404 whose
        // JSON-RPC body is what distinguishes it from the 404 of a legacy
        // HTTP+SSE server that does not host the modern endpoint at all.
        METHOD_NOT_FOUND => axum::http::StatusCode::NOT_FOUND,
        // Each of the three codes the specification reserves for itself is
        // mandated as a 400: § Server Validation (`-32020`), § `_meta`
        // (`-32021`), § Protocol Version Header (`-32022`).
        HEADER_MISMATCH | MISSING_REQUIRED_CLIENT_CAPABILITY | UNSUPPORTED_PROTOCOL_VERSION => {
            axum::http::StatusCode::BAD_REQUEST
        }
        _ => axum::http::StatusCode::OK,
    }
}

// ── Era translation ──────────────────────────────────────────────────────

/// Strip the modern `_meta` envelope from a request bound for a legacy
/// upstream.
///
/// A legacy server has no notion of these keys. Most would ignore them, but
/// `_meta` is explicitly a place where reserved keys carry protocol meaning,
/// and shipping a *newer* revision's envelope to a server negotiated at an
/// older one is exactly the ambiguity the era split exists to prevent. What
/// survives is what means the same thing in both eras: `progressToken` and
/// W3C trace context.
///
/// An emptied `_meta` is removed entirely rather than left as `{}` — an empty
/// object is a value some upstreams validate against a schema.
pub fn downgrade_request_params(params: Option<&Value>) -> Option<Value> {
    let params = params?;
    let Some(obj) = params.as_object() else {
        return Some(params.clone());
    };
    let mut out = obj.clone();
    // `inputResponses` / `requestState` are the modern MRTR retry channel and
    // are consumed by the gateway, never forwarded: a legacy upstream would
    // reject the unknown fields, and the whole point of the retry is that we
    // answer the upstream's own server-initiated request from them.
    out.remove("inputResponses");
    out.remove("requestState");
    if let Some(Value::Object(meta)) = out.get_mut("_meta") {
        for key in MODERN_REQUEST_META_KEYS {
            meta.remove(*key);
        }
        if meta.is_empty() {
            out.remove("_meta");
        }
    }
    Some(Value::Object(out))
}

// ── Speaking the era to an UPSTREAM ──────────────────────────────────────
//
// Everything above serves a modern client. What follows is the other face:
// the gateway as a *client* of an upstream that may itself speak either era.
// The two are deliberately independent — a legacy client's request may reach
// a modern upstream and vice versa — so nothing here reads the downstream
// era, and nothing above reads the upstream's.

/// Which era an upstream MCP server speaks, as the gateway resolved it.
///
/// A property of the **server**, not of a request: the spec has a client
/// resolve it once and cache it for the lifetime of the origin, re-probing
/// only when the cached assumption fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamEra {
    /// `initialize` + `notifications/initialized`, a session id, and a live
    /// stream the server may ask questions on.
    Legacy,
    /// `server/discover`, no handshake, no session, and questions returned as
    /// `InputRequiredResult` data.
    Modern,
}

impl UpstreamEra {
    pub fn is_modern(&self) -> bool {
        matches!(self, Self::Modern)
    }
}

/// Which eras an upstream server actually implements — both independent
/// facts, learned by one probe and cached together.
///
/// This is deliberately not a single "the era of this upstream". A server may
/// implement both, and the gateway is a *server* to clients of both
/// generations at once; collapsing the pair into one choice at probe time
/// forces that choice to serve the weakest client, which costs the others
/// something for nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpstreamEraSupport {
    pub modern: bool,
    pub legacy: bool,
}

impl UpstreamEraSupport {
    pub const LEGACY_ONLY: Self = Self {
        modern: false,
        legacy: true,
    };
    pub const MODERN_ONLY: Self = Self {
        modern: true,
        legacy: false,
    };
    pub const BOTH: Self = Self {
        modern: true,
        legacy: true,
    };
}

/// The era to address an upstream in **for one request**.
///
/// Where the server implements both, this **matches the client**, and that is
/// the whole reason the pair above is kept rather than collapsed:
///
/// - A modern client reaching a dual-era server natively means its mid-call
///   questions relay as data instead of going through the re-issue bridge —
///   so the upstream stops re-running whatever it did before it asked.
/// - A legacy client reaching the same server natively keeps the live stream
///   its revision needs to be asked a question on at all.
///
/// Neither costs the other anything: the modern era holds no session, so the
/// two legs are not a shared resource to be rationed. Where the server
/// implements only one era, there is nothing to choose and the client's own
/// era is irrelevant — the translation on the request path is what makes that
/// work.
///
/// A server that implements neither is answered as legacy: the call then
/// fails against the era the overwhelming majority of servers speak, which is
/// the more useful error to read.
pub fn era_for_request(downstream_is_modern: bool, support: UpstreamEraSupport) -> UpstreamEra {
    match (support.modern, support.legacy) {
        (true, true) => {
            if downstream_is_modern {
                UpstreamEra::Modern
            } else {
                UpstreamEra::Legacy
            }
        }
        (true, false) => UpstreamEra::Modern,
        _ => UpstreamEra::Legacy,
    }
}

/// True for the three error codes only a modern server can emit.
///
/// The era probe reads this off a *refusal*: a server that objects to our
/// modern envelope in the modern vocabulary has understood it, which is the
/// one thing a legacy server cannot do. Its complaint is then a real error to
/// surface, but it has already answered the question the probe asked.
pub fn identifies_modern_server(code: i32) -> bool {
    matches!(
        code,
        HEADER_MISMATCH | MISSING_REQUIRED_CLIENT_CAPABILITY | UNSUPPORTED_PROTOCOL_VERSION
    )
}

/// Whether a `server/discover` result is positive evidence of a modern server
/// this gateway can actually speak to: it names at least one modern revision
/// we also serve.
///
/// This is the rule the reference clients apply — a server that answers
/// `server/discover` but advertises no modern version is making a legacy
/// advertisement, not stating an incompatibility, and they all fall back to
/// the handshake. A result with no readable `supportedVersions` is not
/// evidence of anything, so it falls back too.
///
/// It is deliberately **not** the whole era decision: it says what the
/// upstream *offers*, and the gateway additionally prefers the era that keeps
/// it a reverse channel. See `resolve_upstream_era` in the handler.
pub fn offers_modern_era(discover_result: &Value) -> bool {
    discover_result
        .get("supportedVersions")
        .and_then(Value::as_array)
        .is_some_and(|versions| versions.iter().filter_map(Value::as_str).any(is_modern))
}

/// Add the modern `_meta` envelope to a request bound for a modern upstream —
/// the exact inverse of [`downgrade_request_params`].
///
/// Every field is **overwritten**, never merged, because this envelope
/// describes the gateway's own connection to the upstream and not the
/// client's connection to the gateway. A modern client's request arrives with
/// its own `clientInfo` already in `_meta`; forwarding that verbatim would
/// introduce the gateway's caller to the upstream as though it were the
/// gateway, and an upstream that adapts its behaviour to a client name would
/// then adapt it to the wrong one.
///
/// `client_capabilities` is the caller's decision and the one honest degree
/// of freedom here: the modern era declares capabilities per request, so
/// unlike the legacy handshake this *can* state what the client on this
/// particular request can actually do.
pub fn upgrade_request_params(
    params: Option<&Value>,
    client_capabilities: &Value,
    client_info: &Value,
    log_level: Option<&str>,
) -> Value {
    let mut out = match params {
        Some(Value::Object(o)) => o.clone(),
        // JSON-RPC permits positional params; MCP never uses them, and a
        // non-object cannot carry `_meta`. Forward it untouched rather than
        // reshape a body we do not understand.
        Some(other) => return other.clone(),
        None => Map::new(),
    };
    let meta = out
        .entry("_meta")
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(meta_obj) = meta.as_object_mut() else {
        // `_meta` arrived as a non-object. Replace it: a modern upstream MUST
        // reject the request otherwise, and the client's malformed value has
        // no meaning we could preserve.
        out.insert(
            "_meta".to_string(),
            json!({
                META_PROTOCOL_VERSION: MODERN_PROTOCOL_VERSION,
                META_CLIENT_CAPABILITIES: client_capabilities.clone(),
                META_CLIENT_INFO: client_info.clone(),
            }),
        );
        return Value::Object(out);
    };
    meta_obj.insert(
        META_PROTOCOL_VERSION.to_string(),
        json!(MODERN_PROTOCOL_VERSION),
    );
    meta_obj.insert(
        META_CLIENT_CAPABILITIES.to_string(),
        client_capabilities.clone(),
    );
    meta_obj.insert(META_CLIENT_INFO.to_string(), client_info.clone());
    match log_level {
        Some(level) => {
            meta_obj.insert(META_LOG_LEVEL.to_string(), json!(level));
        }
        // § Logging: with no `logLevel` on the request the server MUST NOT
        // emit log notifications for it. Removing rather than leaving the
        // client's own key is what makes the opt-in *ours* to grant — the
        // gateway forwards the upstream's log lines onto a downstream stream,
        // so it must not ask for lines it has nowhere to put.
        None => {
            meta_obj.remove(META_LOG_LEVEL);
        }
    }
    Value::Object(out)
}

/// What the gateway does with a downstream method when the upstream that
/// would serve it speaks the modern era.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModernUpstreamAction {
    /// Forward it, wrapped in the modern envelope.
    Forward,
    /// Answer it from what `server/discover` already told us. No second call:
    /// discovery is the whole of what this upstream knows about itself.
    FromDiscovery,
    /// Answer it here with an empty result. The method exists in the legacy
    /// era only, and its modern equivalent is either nothing at all (`ping`
    /// has no session to keep alive) or a per-request field (`logging/setLevel`
    /// became `_meta.logLevel`), so there is nothing upstream to ask and
    /// nothing for the caller to learn from asking.
    EmptyResult,
    /// The era deleted it and the gateway cannot emulate it against a
    /// stateless upstream. The string is the operator-facing reason.
    Unsupported(&'static str),
    /// A notification the era deleted. Dropped, never forwarded: a
    /// notification draws no reply, so forwarding an unknown one would leave
    /// the upstream to decide whether to fail the connection over it.
    ///
    /// **Unreachable today** — the handler answers every inbound notification
    /// with `202` and forwards none upstream. It exists so this function is
    /// total over the notification namespace: the arm that would otherwise
    /// cover these is `Forward`, so the day a forwarding path is added, the
    /// default would be to send a deleted notification rather than to drop it.
    DropNotification,
}

/// The gateway's disposition for `method` against a modern upstream.
///
/// The removed-method list is [`is_removed_in_modern`] and this function is
/// the other half of it: that one refuses a *modern client* the methods its
/// own revision deleted, this one decides what to do when a *legacy client*
/// asks for one and the upstream that would serve it has deleted it too.
pub fn modern_upstream_action(method: &str) -> ModernUpstreamAction {
    match method {
        "initialize" | METHOD_DISCOVER => ModernUpstreamAction::FromDiscovery,
        "ping" | "logging/setLevel" => ModernUpstreamAction::EmptyResult,
        "resources/subscribe" | "resources/unsubscribe" => ModernUpstreamAction::Unsupported(
            "this upstream serves resource subscriptions only through a subscriptions/listen stream",
        ),
        m if is_removed_notification_in_modern(m) => ModernUpstreamAction::DropNotification,
        _ => ModernUpstreamAction::Forward,
    }
}

/// Negotiate the `protocolVersion` to answer a legacy `initialize` with, when
/// the gateway is answering it itself because the upstream is modern.
///
/// **The version comes from the request BODY, not from the era.** The era is
/// resolved from `MCP-Protocol-Version`, which the legacy revisions do not
/// require on the `initialize` request itself — it is the *response* that
/// tells the client which version to send from then on. Reading the era here
/// would answer every handshake with the header's default (`2025-03-26`)
/// however new a revision the client actually asked for, and the client would
/// then downgrade itself.
///
/// The rule is the legacy handshake's own: echo the requested version when we
/// serve it, otherwise answer with one we do serve and let the client decide
/// whether it can continue.
pub fn negotiated_initialize_version<'a>(
    params: Option<&Value>,
    we_serve: &[&'a str],
    fallback: &'a str,
) -> String {
    let requested = params
        .and_then(|p| p.get("protocolVersion"))
        .and_then(Value::as_str);
    match requested {
        Some(v) if we_serve.contains(&v) => v.to_string(),
        _ => fallback.to_string(),
    }
}

/// Shape a modern upstream's `server/discover` answer like the `initialize`
/// result the legacy fan-out expects from every route.
///
/// `protocol_version` is what [`negotiated_initialize_version`] settled on,
/// not anything the upstream said. The fan-out relays the first route's
/// `protocolVersion` to the client verbatim, and telling a legacy client
/// `2026-07-28` because the first upstream happened to be modern would
/// announce a revision the gateway is not speaking to it.
pub fn discovery_as_initialize_result(
    capabilities: &Value,
    instructions: Option<&str>,
    protocol_version: &str,
) -> Value {
    let mut obj = Map::new();
    obj.insert(
        "protocolVersion".to_string(),
        Value::String(protocol_version.to_string()),
    );
    // `resources.subscribe` is dropped, because against a modern upstream the
    // gateway refuses `resources/subscribe`: that revision replaced it with a
    // `subscriptions/listen` stream the gateway does not yet hold open. The
    // upstream can genuinely do it and says so; the *gateway* cannot deliver
    // it, and `initialize` is where a legacy client decides what to attempt.
    // Advertising it and then refusing every call is the same lie the listen
    // acknowledgement is narrowed to avoid, one method earlier.
    let mut capabilities = capabilities.clone();
    if let Some(resources) = capabilities
        .get_mut("resources")
        .and_then(Value::as_object_mut)
    {
        resources.remove("subscribe");
    }
    obj.insert("capabilities".to_string(), capabilities);
    if let Some(text) = instructions.filter(|s| !s.is_empty()) {
        obj.insert(
            "instructions".to_string(),
            Value::String(text.to_string()),
        );
    }
    Value::Object(obj)
}

/// Strip a modern upstream's result down to what a legacy client's revision
/// defines — the result-side mirror of [`downgrade_request_params`].
///
/// Returns whether anything changed, so a caller holding raw wire bytes can
/// leave them alone when there was nothing to do.
///
/// Three of the four fields are simply not in that revision's vocabulary:
/// `resultType` names a shape it has one of, and `ttlMs`/`cacheScope` are a
/// freshness claim about the **upstream's own unfiltered catalog** — not
/// about the answer the client is holding, which this gateway assembled
/// across routes and narrowed by that caller's grants and tool policy.
/// Passing an upstream's `cacheScope: "public"` through to a client that acts
/// on it would have it share a per-caller answer.
///
/// The fourth is the one that matters. `_meta.serverInfo` names the upstream,
/// and every other surface a legacy client sees says `streamscope-mcp`: its
/// own `initialize` reply is rewritten to the gateway's identity, and
/// [`stamp_result`] overwrites the field for a *modern* client for exactly
/// this reason. Leaving it here would tell one client generation the name of
/// the server behind the virtual server while telling the other the gateway's
/// — two different answers to "what am I talking to", of which only one is
/// true of the connection.
pub fn downgrade_result(result: &mut Value) -> bool {
    let Some(obj) = result.as_object_mut() else {
        return false;
    };
    let mut changed = false;
    for key in ["resultType", "ttlMs", "cacheScope"] {
        changed |= obj.remove(key).is_some();
    }
    if let Some(Value::Object(meta)) = obj.get_mut("_meta") {
        changed |= meta.remove(META_SERVER_INFO).is_some();
        if meta.is_empty() {
            obj.remove("_meta");
        }
    }
    changed
}

/// Translate a modern upstream's error code into one a legacy client's
/// revision defines — the mirror of [`modernize_error_code`].
///
/// The three modern codes all say the same thing to a revision that predates
/// them: the request, as framed, cannot be served. `-32600` is the JSON-RPC
/// code for exactly that, and a legacy client can act on it. Passing the
/// original through would hand it a number from a band its own spec revision
/// reserves, which it is entitled to treat as meaningless.
pub fn legacyize_error_code(code: i32) -> Option<i32> {
    identifies_modern_server(code).then_some(super::jsonrpc::INVALID_REQUEST)
}

/// Rewrite an upstream error in place so a legacy client can read it, keeping
/// what it was under `data.upstreamCode`.
///
/// The key is `upstreamCode`, not the `streamscopeCode` [`modernize_error`]
/// writes, because the two record different facts: that one preserves a code
/// the *gateway* minted, this one a code the *upstream* did. An operator
/// reading an audit row needs to know which.
pub fn legacyize_error(err: &mut super::jsonrpc::JsonRpcError) {
    let Some(legacy) = legacyize_error_code(err.code) else {
        return;
    };
    let original = err.code;
    err.code = legacy;
    let data = err.data.get_or_insert_with(|| Value::Object(Map::new()));
    if let Some(obj) = data.as_object_mut() {
        obj.entry("upstreamCode").or_insert_with(|| json!(original));
    }
}

// ── An upstream's own `InputRequiredResult` (§ MRTR, client side) ─────────

/// A well-formed `InputRequiredResult` from an upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamInputRequired {
    /// The questions, keyed exactly as the upstream keyed them. The keys are
    /// relayed to the client untouched so its answers come back under the
    /// same names the upstream will look them up by — remapping them would
    /// require a second, perfectly-inverse mapping on the retry.
    ///
    /// Empty when the upstream asked nothing and only handed back state —
    /// § MRTR's load-shedding case, where the client may retry immediately.
    pub input_requests: Map<String, Value>,
    /// The upstream's own opaque state, when it kept any. Never handed to a
    /// client: the client would quote it back and the gateway would have no
    /// idea which upstream it belonged to.
    ///
    /// `None` is a conforming answer, not a broken one: § MRTR requires only
    /// that *at least one* of the two fields be present, and a server that
    /// encodes its continuation in the question itself keeps no state.
    pub request_state: Option<String>,
}

/// What an upstream result says about needing more input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputRequiredShape {
    /// An ordinary result.
    No,
    /// A question the client can be asked.
    Yes(Box<UpstreamInputRequired>),
    /// `resultType` claims `input_required` but the result cannot be relayed:
    /// a present field is the wrong type, or neither field carries anything
    /// (which § MRTR server requirement 6 forbids outright).
    ///
    /// A distinct variant rather than folded into [`Self::No`]: relaying such
    /// a result verbatim would hand the client a question with no key to
    /// answer under and no state to quote back, which it can only hang or
    /// error on — and the gateway would have forwarded a shape it knew was
    /// broken.
    Malformed,
}

/// Read an upstream result as an `InputRequiredResult`, if that is what it is.
///
/// § MRTR server requirement 6 is the whole rule: *at least one* of
/// `inputRequests` and `requestState` must be present. Both are individually
/// optional, so demanding both refuses two shapes the protocol defines — a
/// server that asks a question and keeps no state, and a server that keeps
/// state and asks nothing (load shedding).
///
/// Only two things are refused: a field of the WRONG TYPE, which is a claim
/// the upstream made and got wrong, and a result carrying nothing usable —
/// the one shape requirement 6 rules out. An empty `inputRequests` map
/// *beside a state* is well-typed and simply asks nothing, and an empty
/// `requestState` *beside a question* is a value client requirement 2 says to
/// echo back exactly; refusing either would repeat, one notch narrower, the
/// mistake of demanding both. A result whose only content is an empty map is
/// still refused — it leaves the client nothing to do and nothing to quote.
pub fn parse_input_required(result: &Value) -> InputRequiredShape {
    let Some(obj) = result.as_object() else {
        return InputRequiredShape::No;
    };
    if obj.get("resultType").and_then(Value::as_str) != Some("input_required") {
        return InputRequiredShape::No;
    }
    let input_requests = match obj.get("inputRequests") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(m)) => m.clone(),
        Some(_) => return InputRequiredShape::Malformed,
    };
    let request_state = match obj.get("requestState") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return InputRequiredShape::Malformed,
    };
    if input_requests.is_empty() && request_state.is_none() {
        return InputRequiredShape::Malformed;
    }
    InputRequiredShape::Yes(Box::new(UpstreamInputRequired {
        input_requests,
        request_state,
    }))
}

/// Structural check on a retry's `inputResponses`, before any upstream work.
///
/// § MRTR Error Handling names three dispositions and the gateway must not
/// conflate them: information the client did not send is answered by ASKING
/// AGAIN (not an error), extra keys it was never asked for are IGNORED, and
/// data that cannot be parsed is a protocol error. This is the third.
/// `InputResponses` is a map of results — an `ElicitResult`,
/// `CreateMessageResult` or `ListRootsResult` — so a member that is not an
/// object is not an answer in any revision, and relaying it asks an upstream
/// to interpret a shape the protocol does not define. The gateway is the
/// server this client is talking to, so the validation is ours to do.
///
/// Only the SHAPE is checked, deliberately. What a given answer must
/// *contain* is the requested schema of the question that asked for it, which
/// only the upstream that asked knows — validating that here would be the
/// gateway second-guessing an upstream about its own tool.
pub fn validate_input_responses(params: Option<&Value>) -> Result<(), ModernError> {
    let Some(responses) = params.and_then(|p| p.get("inputResponses")) else {
        return Ok(());
    };
    if responses.is_null() {
        return Ok(());
    }
    let Some(map) = responses.as_object() else {
        return Err(ModernError::invalid_params(
            "inputResponses must be an object keyed by the identifiers the server asked under",
        ));
    };
    match map.iter().find(|(_, value)| !value.is_object()) {
        Some((key, _)) => Err(ModernError::invalid_params(format!(
            "inputResponses[{key}] is not a result object"
        ))),
        None => Ok(()),
    }
}

/// The distinct input-request methods an upstream asked for.
///
/// Used to check them against what the downstream client declared before the
/// question is relayed: § MRTR forbids asking for input a client has not said
/// it can produce, and the gateway is the party asking as far as that client
/// is concerned.
pub fn input_required_methods(requests: &Map<String, Value>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for value in requests.values() {
        let Some(method) = value.get("method").and_then(Value::as_str) else {
            continue;
        };
        if !out.iter().any(|m| m == method) {
            out.push(method.to_string());
        }
    }
    out
}

/// What an MRTR retry may carry to the upstream it is being sent to.
///
/// Three cases, not two, because two of them look alike and behave in
/// opposite ways: a retry aimed at *this* upstream forwards the client's
/// answers whether or not there is any state to quote back, while a retry
/// aimed anywhere else must carry neither. Collapsing them costs the answers
/// on every question a stateless upstream asks, and the upstream then asks
/// again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MrtrRetry<'a> {
    /// Aimed here, and the upstream minted state to be quoted back.
    Quoting(&'a str),
    /// The answers travel and nothing is quoted. Two ways to arrive here, and
    /// they are the same wire outcome: this upstream asked without minting
    /// state, or the client presented no wrapper at all — which is precisely
    /// the retry a conforming client sends after a stateless question, since
    /// client requirement 2 forbids quoting back a `requestState` the server
    /// never issued. A first attempt lands here too and is unaffected: it
    /// carries neither field, and stray `inputResponses` on one are the
    /// upstream's to ignore (§ MRTR Error Handling says it SHOULD).
    AnswersOnly,
    /// A wrapper this gateway minted, naming a DIFFERENT upstream of a
    /// fanned-out virtual server. Neither field travels: we know these
    /// answers were not asked for here.
    NotAimedHere,
}

impl<'a> MrtrRetry<'a> {
    /// Resolve what a retry may carry to `upstream_id`, from the wrapper the
    /// client quoted back — `None` when it quoted none.
    ///
    /// The id is checked rather than the field's mere presence: a virtual
    /// server fans out across several upstreams, and handing upstream B a
    /// blob minted by upstream A, or the answers meant for A, would at best
    /// be rejected and at worst be acted on.
    pub fn resolve(wrapper: Option<&'a (Uuid, Option<String>)>, upstream_id: Uuid) -> Self {
        match wrapper {
            Some((id, state)) if *id == upstream_id => match state.as_deref() {
                Some(state) => Self::Quoting(state),
                None => Self::AnswersOnly,
            },
            // A wrapper that names somewhere else. This is the only case that
            // withholds the answers, and it is the only one where withholding
            // is justified: we minted the wrapper, so we know which upstream
            // asked, and it is not this one.
            Some(_) => Self::NotAimedHere,
            // No wrapper at all. Withholding here would break the conforming
            // retry against a stateless upstream, which by construction has
            // no state to quote — the answers are all it sends.
            None => Self::AnswersOnly,
        }
    }
}

/// Point an MRTR retry at the upstream that asked the question.
///
/// The client's `inputResponses` are keyed as the upstream keyed them (see
/// [`UpstreamInputRequired::input_requests`]) and are forwarded untouched;
/// only `requestState` is rewritten, from the gateway's wrapper to whatever
/// the upstream is owed — its own blob, or nothing.
///
/// Every arm removes the gateway's own wrapper — forwarding it would offer an
/// upstream a blob only we can verify. Only [`MrtrRetry::NotAimedHere`]
/// removes `inputResponses` too, and only because the wrapper named a
/// different upstream: answers asked for by one server are not answers for
/// another.
pub fn retarget_request_state(params: Option<&Value>, retry: MrtrRetry<'_>) -> Option<Value> {
    let params = params?;
    let Some(obj) = params.as_object() else {
        return Some(params.clone());
    };
    let mut out = obj.clone();
    match retry {
        MrtrRetry::Quoting(state) => {
            out.insert("requestState".to_string(), Value::String(state.to_string()));
        }
        MrtrRetry::AnswersOnly => {
            out.remove("requestState");
        }
        MrtrRetry::NotAimedHere => {
            out.remove("requestState");
            out.remove("inputResponses");
        }
    }
    Some(Value::Object(out))
}

// ── Subscriptions (§ Subscribe and Notify) ───────────────────────────────

/// The notification types a `subscriptions/listen` stream opted in to.
///
/// Every field defaults to "not subscribed". The server MUST NOT deliver a
/// type the client did not name, so an unparseable or absent filter yields an
/// empty subscription rather than a permissive one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubscriptionFilter {
    pub tools_list_changed: bool,
    pub prompts_list_changed: bool,
    pub resources_list_changed: bool,
    /// Resource URIs, as the client addressed them — i.e. still in the
    /// gateway's `stsmcp://` envelope. Routing decodes them per URI.
    pub resource_subscriptions: Vec<String>,
}

impl SubscriptionFilter {
    /// Parse `params.notifications`. Absent or malformed fields subscribe to
    /// nothing; there is no shape of input that widens the subscription.
    pub fn parse(params: Option<&Value>) -> Self {
        let Some(n) = params.and_then(|p| p.get("notifications")) else {
            return Self::default();
        };
        let flag = |k: &str| n.get(k).and_then(Value::as_bool).unwrap_or(false);
        Self {
            tools_list_changed: flag("toolsListChanged"),
            prompts_list_changed: flag("promptsListChanged"),
            resources_list_changed: flag("resourcesListChanged"),
            resource_subscriptions: n
                .get("resourceSubscriptions")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    /// Nothing was subscribed to. The stream is still legal — the client gets
    /// its acknowledgement and a channel that stays quiet — but it is worth
    /// a debug log, because it usually means a filter the client got wrong.
    pub fn is_empty(&self) -> bool {
        !self.tools_list_changed
            && !self.prompts_list_changed
            && !self.resources_list_changed
            && self.resource_subscriptions.is_empty()
    }

    /// Narrow this filter to what the merged upstream capabilities can
    /// actually deliver — the subset the acknowledgement reports.
    ///
    /// Reporting a type we cannot source would leave the client waiting on a
    /// notification that is never coming, with no way to tell that from a
    /// quiet server.
    pub fn honored(&self, caps: &Value) -> Self {
        let list_changed = |section: &str| {
            caps.get(section)
                .and_then(|s| s.get("listChanged"))
                .and_then(Value::as_bool)
                .unwrap_or(false)
        };
        let subscribe_supported = caps
            .get("resources")
            .and_then(|r| r.get("subscribe"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        Self {
            tools_list_changed: self.tools_list_changed && list_changed("tools"),
            prompts_list_changed: self.prompts_list_changed && list_changed("prompts"),
            resources_list_changed: self.resources_list_changed && list_changed("resources"),
            resource_subscriptions: if subscribe_supported {
                self.resource_subscriptions.clone()
            } else {
                Vec::new()
            },
        }
    }

    /// Render as the `notifications` object of an acknowledgement. Only the
    /// honored types appear; § Acknowledgment specifies omission, not
    /// `false`, for a type the server declined.
    pub fn to_json(&self) -> Value {
        let mut obj = Map::new();
        if self.tools_list_changed {
            obj.insert("toolsListChanged".into(), json!(true));
        }
        if self.prompts_list_changed {
            obj.insert("promptsListChanged".into(), json!(true));
        }
        if self.resources_list_changed {
            obj.insert("resourcesListChanged".into(), json!(true));
        }
        if !self.resource_subscriptions.is_empty() {
            obj.insert(
                "resourceSubscriptions".into(),
                json!(self.resource_subscriptions),
            );
        }
        Value::Object(obj)
    }

    /// Whether a notification method is one this subscription asked for.
    /// `notifications/resources/updated` is matched by URI, not by method
    /// alone, so it is checked against the subscribed set.
    pub fn accepts(&self, method: &str, uri: Option<&str>) -> bool {
        match method {
            "notifications/tools/list_changed" => self.tools_list_changed,
            "notifications/prompts/list_changed" => self.prompts_list_changed,
            "notifications/resources/list_changed" => self.resources_list_changed,
            "notifications/resources/updated" => match uri {
                Some(u) => self.resource_subscriptions.iter().any(|s| s == u),
                // A resource update with no URI names no resource, so it
                // cannot be shown to match anything the client subscribed to.
                None => false,
            },
            _ => false,
        }
    }
}

/// Stamp `io.modelcontextprotocol/subscriptionId` into a notification's
/// `params._meta`. The server MUST do this on every message delivered on a
/// listen stream so the client can demultiplex concurrent subscriptions.
pub fn stamp_subscription_id(message: &mut Value, subscription_id: &Value) {
    let Some(obj) = message.as_object_mut() else {
        return;
    };
    let params = obj
        .entry("params")
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(params_obj) = params.as_object_mut() else {
        return;
    };
    let meta = params_obj
        .entry("_meta")
        .or_insert_with(|| Value::Object(Map::new()));
    if let Some(meta_obj) = meta.as_object_mut() {
        meta_obj.insert(META_SUBSCRIPTION_ID.to_string(), subscription_id.clone());
    }
}

/// The acknowledgement that MUST precede any notification on a listen stream.
pub fn subscription_ack(subscription_id: &Value, honored: &SubscriptionFilter) -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": "notifications/subscriptions/acknowledged",
        "params": {
            "_meta": { META_SUBSCRIPTION_ID: subscription_id },
            "notifications": honored.to_json(),
        }
    })
}

/// The graceful-closure response: the JSON-RPC result for the long-lived
/// `subscriptions/listen` request itself, sent when *we* end the subscription
/// (drain, shutdown) rather than when the client walks away. Its presence is
/// how a client tells a clean close from a dropped connection.
pub fn subscription_close(subscription_id: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": subscription_id,
        "result": {
            "resultType": "complete",
            "_meta": { META_SUBSCRIPTION_ID: subscription_id },
        }
    })
}

// ── Multi Round-Trip Requests (§ MRTR) ───────────────────────────────────

/// The client requests the modern era admits inside an `InputRequiredResult`.
pub const INPUT_REQUEST_METHODS: &[&str] =
    &["elicitation/create", "sampling/createMessage", "roots/list"];

/// Only three RPCs may answer with an `InputRequiredResult`. Returning one
/// anywhere else is a protocol violation on our side, so this is checked
/// rather than assumed.
pub fn supports_input_required(method: &str) -> bool {
    matches!(method, "tools/call" | "prompts/get" | "resources/read")
}

/// The `inputResponses` a client supplied on a retry, keyed exactly as the
/// `inputRequests` we sent.
#[derive(Debug, Clone, Default)]
pub struct InputResponses(pub BTreeMap<String, Value>);

impl InputResponses {
    /// Read `params.inputResponses`.
    ///
    /// A non-object is treated as absent, so the retry looks like a first
    /// attempt and the question is asked again. That is defence in depth
    /// rather than the disposition: [`validate_input_responses`] refuses the
    /// shape at the retry gate, before any of this runs. Re-asking is what
    /// § MRTR Error Handling prescribes for information the client did not
    /// SEND, which is what an absent map is; unparseable data is an error, and
    /// the gate is where that distinction is made.
    pub fn parse(params: Option<&Value>) -> Self {
        let Some(obj) = params
            .and_then(|p| p.get("inputResponses"))
            .and_then(Value::as_object)
        else {
            return Self::default();
        };
        Self(
            obj.iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        )
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.get(key)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// How many answers the client supplied.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// Build the `InputRequiredResult` that carries a server-initiated request
/// back to a modern client as data.
///
/// `input_requests` maps a gateway-assigned key to the upstream's own request
/// object, stripped of its JSON-RPC envelope: the client answers by key, not
/// by id, because the id belonged to a stream that no longer exists.
pub fn input_required_result(
    input_requests: &Map<String, Value>,
    request_state: &str,
    server_info: &Value,
) -> Value {
    let mut out = Map::new();
    out.insert("resultType".to_string(), json!("input_required"));
    // § MRTR client requirement 1: an ABSENT `inputRequests` is what tells a
    // client it may retry immediately. An empty map would instead ask it to
    // fulfil a set of questions before retrying — a different instruction,
    // and one it can never finish.
    if !input_requests.is_empty() {
        out.insert(
            "inputRequests".to_string(),
            Value::Object(input_requests.clone()),
        );
    }
    out.insert("requestState".to_string(), json!(request_state));
    out.insert("_meta".to_string(), json!({ META_SERVER_INFO: server_info }));
    Value::Object(out)
}

/// Reduce an upstream server-initiated request to the `{method, params}` pair
/// an `InputRequests` entry holds.
pub fn input_request_entry(upstream_message: &Value) -> Option<(String, Value)> {
    let method = upstream_message.get("method")?.as_str()?.to_string();
    if !INPUT_REQUEST_METHODS.contains(&method.as_str()) {
        return None;
    }
    let params = upstream_message
        .get("params")
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    Some((method, params))
}

/// The stable key an input request is filed under.
///
/// Derived from the method rather than minted at random so a retry that the
/// gateway had to re-issue upstream — which is how this gateway bridges MRTR
/// onto a legacy upstream that asks its question again — matches the answer
/// the client already gave to the *same* question. A random key would make
/// every re-ask unanswerable and the retry would loop.
pub fn input_request_key(method: &str, ordinal: usize) -> String {
    let base = method.replace('/', "_");
    if ordinal == 0 {
        base
    } else {
        format!("{base}_{ordinal}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                axum::http::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    fn req(method: &str, params: Value) -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(super::super::jsonrpc::RpcId::Number(1.into())),
            method: method.into(),
            params: Some(params),
        }
    }

    // ── era ──────────────────────────────────────────────────────────────

    #[test]
    fn modern_version_is_recognised_and_legacy_ones_are_not() {
        assert!(is_modern("2026-07-28"));
        assert!(!is_modern("2025-11-25"));
        assert!(!is_modern("2025-03-26"));
        assert!(!is_modern(""));
    }

    // ── header value codec ───────────────────────────────────────────────

    #[test]
    fn plain_ascii_travels_unencoded() {
        assert_eq!(encode_header_value("get_weather"), "get_weather");
        assert_eq!(encode_header_value("us-west1"), "us-west1");
        assert_eq!(
            encode_header_value("file:///projects/myapp/config.json"),
            "file:///projects/myapp/config.json"
        );
    }

    #[test]
    fn the_specs_own_encoding_examples_round_trip() {
        // § Value Encoding, verbatim.
        assert_eq!(
            encode_header_value("Hello, 世界"),
            "=?base64?SGVsbG8sIOS4lueVjA==?="
        );
        assert_eq!(encode_header_value(" padded "), "=?base64?IHBhZGRlZCA=?=");
        assert_eq!(
            encode_header_value("line1\nline2"),
            "=?base64?bGluZTEKbGluZTI=?="
        );
        assert_eq!(
            encode_header_value("=?base64?literal?="),
            "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?="
        );
    }

    #[test]
    fn a_plain_value_shaped_like_the_sentinel_is_escaped() {
        // Without this the far side would decode the client's literal text as
        // if it were an encoding layer, silently yielding a different value.
        let raw = "=?base64?literal?=";
        let wire = encode_header_value(raw);
        assert_ne!(wire, raw);
        assert_eq!(decode_header_value(&wire).unwrap(), raw);
    }

    #[test]
    fn a_bare_prefix_is_not_a_sentinel() {
        // "=?base64?" alone does not end with "?=", so it is plain text.
        assert!(!looks_like_sentinel("=?base64?"));
        assert_eq!(decode_header_value("=?base64?").unwrap(), "=?base64?");
    }

    #[test]
    fn an_empty_sentinel_payload_decodes_to_the_empty_string() {
        assert!(looks_like_sentinel("=?base64??="));
        assert_eq!(decode_header_value("=?base64??=").unwrap(), "");
    }

    #[test]
    fn a_sentinel_that_is_not_base64_is_rejected_not_passed_through() {
        let err = decode_header_value("=?base64?!!!not-base64!!!?=").unwrap_err();
        assert_eq!(err.code, HEADER_MISMATCH);
        assert_eq!(err.status, axum::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn a_sentinel_decoding_to_invalid_utf8_is_rejected() {
        // 0xff is never valid UTF-8.
        let wire = format!("{B64_SENTINEL_PREFIX}{}{B64_SENTINEL_SUFFIX}", B64_STD.encode([0xffu8]));
        let err = decode_header_value(&wire).unwrap_err();
        assert_eq!(err.code, HEADER_MISMATCH);
    }

    #[test]
    fn decoding_is_single_pass() {
        // A value that decodes to something itself shaped like a sentinel is
        // the caller's data, not another layer. Asserting idempotence here
        // would be asserting a second decode, which is a bug, not a property.
        let inner = "=?base64?YWJj?=";
        let wire = encode_header_value(inner);
        let once = decode_header_value(&wire).unwrap();
        assert_eq!(once, inner);
        assert_ne!(decode_header_value(&once).unwrap(), once);
    }

    // ── transport header validation ──────────────────────────────────────

    #[test]
    fn matching_headers_pass() {
        let r = req("tools/call", json!({"name": "get_weather", "arguments": {}}));
        let h = headers(&[("mcp-method", "tools/call"), ("mcp-name", "get_weather")]);
        assert!(validate_transport_headers(&h, &r).is_ok());
    }

    #[test]
    fn a_missing_method_header_is_a_header_mismatch() {
        let r = req("tools/list", json!({}));
        let h = headers(&[]);
        let err = validate_transport_headers(&h, &r).unwrap_err();
        assert_eq!(err.code, HEADER_MISMATCH);
    }

    #[test]
    fn a_method_header_disagreeing_with_the_body_is_refused() {
        // The whole point of mirroring: a router reading the header must not
        // be able to see a different call from the one we execute.
        let r = req("tools/call", json!({"name": "rm_rf"}));
        let h = headers(&[("mcp-method", "tools/list"), ("mcp-name", "rm_rf")]);
        let err = validate_transport_headers(&h, &r).unwrap_err();
        assert_eq!(err.code, HEADER_MISMATCH);
    }

    #[test]
    fn a_name_header_disagreeing_with_the_body_is_refused() {
        let r = req("tools/call", json!({"name": "read_file"}));
        let h = headers(&[("mcp-method", "tools/call"), ("mcp-name", "delete_file")]);
        let err = validate_transport_headers(&h, &r).unwrap_err();
        assert_eq!(err.code, HEADER_MISMATCH);
    }

    #[test]
    fn a_missing_name_header_on_a_method_that_needs_one_is_refused() {
        for (method, params) in [
            ("tools/call", json!({"name": "x"})),
            ("prompts/get", json!({"name": "x"})),
            ("resources/read", json!({"uri": "file:///x"})),
        ] {
            let r = req(method, params);
            let h = headers(&[("mcp-method", method)]);
            let err = validate_transport_headers(&h, &r)
                .unwrap_err_or_panic(&format!("{method} must require Mcp-Name"));
            assert_eq!(err.code, HEADER_MISMATCH, "{method}");
        }
    }

    #[test]
    fn an_encoded_name_header_is_decoded_before_comparison() {
        let r = req("tools/call", json!({"name": "Hello, 世界"}));
        let h = headers(&[
            ("mcp-method", "tools/call"),
            ("mcp-name", "=?base64?SGVsbG8sIOS4lueVjA==?="),
        ]);
        assert!(validate_transport_headers(&h, &r).is_ok());
    }

    #[test]
    fn a_name_header_on_a_method_that_mirrors_none_is_ignored_not_refused() {
        // The spec defines a validation failure as a header that DISAGREES
        // with its body value. A method with no such value cannot produce
        // one, so refusing would reject a client the spec permits — and the
        // value cannot leak onward either, because outbound headers are
        // rebuilt rather than relayed.
        let r = req("tools/list", json!({}));
        let h = headers(&[("mcp-method", "tools/list"), ("mcp-name", "anything")]);
        assert!(validate_transport_headers(&h, &r).is_ok());
        assert_eq!(outbound_transport_headers(&r).len(), 1);
    }

    #[test]
    fn a_well_formed_param_header_is_forwarded_not_rejected() {
        // We are an intermediary for `Mcp-Param-*`: the tool's inputSchema
        // that binds it to a body field belongs to the upstream.
        let r = req("tools/call", json!({"name": "execute_sql", "arguments": {"region": "us-west1"}}));
        let h = headers(&[
            ("mcp-method", "tools/call"),
            ("mcp-name", "execute_sql"),
            ("mcp-param-region", "us-west1"),
        ]);
        assert!(validate_transport_headers(&h, &r).is_ok());
    }

    #[test]
    fn a_param_header_with_a_broken_sentinel_is_refused() {
        let r = req("tools/call", json!({"name": "t"}));
        let h = headers(&[
            ("mcp-method", "tools/call"),
            ("mcp-name", "t"),
            ("mcp-param-x", "=?base64?%%%?="),
        ]);
        let err = validate_transport_headers(&h, &r).unwrap_err();
        assert_eq!(err.code, HEADER_MISMATCH);
    }

    // ── request meta ─────────────────────────────────────────────────────

    fn meta_params(extra: Value) -> Value {
        let mut m = json!({
            META_PROTOCOL_VERSION: MODERN_PROTOCOL_VERSION,
            META_CLIENT_CAPABILITIES: {},
        });
        if let (Some(m), Some(e)) = (m.as_object_mut(), extra.as_object()) {
            for (k, v) in e {
                m.insert(k.clone(), v.clone());
            }
        }
        json!({ "_meta": m })
    }

    #[test]
    fn a_complete_meta_envelope_parses() {
        let p = meta_params(json!({
            META_CLIENT_INFO: {"name": "ExampleClient", "version": "1.0.0"},
            META_LOG_LEVEL: "debug",
        }));
        let m = extract_request_meta(Some(&p)).unwrap();
        assert_eq!(m.protocol_version, MODERN_PROTOCOL_VERSION);
        assert_eq!(m.log_level.as_deref(), Some("debug"));
        assert!(m.client_info.is_some());
    }

    #[test]
    fn a_request_without_meta_is_invalid_params_with_http_400() {
        let err = extract_request_meta(None).unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert_eq!(err.status, axum::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn absent_client_capabilities_is_an_error_not_an_empty_set() {
        // Reading it as `{}` would let a client bug present as a capability
        // declaration, and the server MUST NOT infer capabilities.
        let p = json!({"_meta": { META_PROTOCOL_VERSION: MODERN_PROTOCOL_VERSION }});
        let err = extract_request_meta(Some(&p)).unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
    }

    #[test]
    fn absent_protocol_version_in_meta_is_an_error() {
        let p = json!({"_meta": { META_CLIENT_CAPABILITIES: {} }});
        let err = extract_request_meta(Some(&p)).unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
    }

    #[test]
    fn capabilities_gate_which_input_requests_may_be_asked_for() {
        let p = meta_params(json!({}));
        let none = extract_request_meta(Some(&p)).unwrap();
        assert!(!none.supports_elicitation());
        assert!(!none.supports_input_request("elicitation/create"));
        assert!(!none.supports_input_request("sampling/createMessage"));

        let p = json!({"_meta": {
            META_PROTOCOL_VERSION: MODERN_PROTOCOL_VERSION,
            META_CLIENT_CAPABILITIES: {"elicitation": {"form": {}}},
        }});
        let elicit = extract_request_meta(Some(&p)).unwrap();
        assert!(elicit.supports_elicitation());
        assert!(elicit.supports_input_request("elicitation/create"));
        // Positive control for the negative above: declaring elicitation must
        // not silently declare sampling too.
        assert!(!elicit.supports_input_request("sampling/createMessage"));
        // An unrecognised input request fails closed even for a client that
        // declared everything it knows about.
        assert!(!elicit.supports_input_request("something/new"));
    }

    // ── removed methods ──────────────────────────────────────────────────

    #[test]
    fn a_removed_server_notification_is_recognised() {
        assert!(is_removed_server_notification_in_modern(
            "notifications/elicitation/complete"
        ));
        // Positive control: the notifications that survived must still be
        // deliverable, or this predicate would pass having silenced the
        // stream entirely.
        for m in [
            "notifications/message",
            "notifications/progress",
            "notifications/tools/list_changed",
            "notifications/resources/updated",
        ] {
            assert!(!is_removed_server_notification_in_modern(m), "{m}");
        }
    }

    #[test]
    fn the_legacy_handshake_and_its_friends_are_gone() {
        for m in [
            "initialize",
            "ping",
            "logging/setLevel",
            "resources/subscribe",
            "resources/unsubscribe",
        ] {
            assert!(is_removed_in_modern(m), "{m}");
        }
        // Positive control: the methods that survived must still be servable,
        // or this predicate would pass while having disabled the gateway.
        for m in [
            "tools/list",
            "tools/call",
            "resources/read",
            "prompts/get",
            "completion/complete",
            METHOD_DISCOVER,
            METHOD_SUBSCRIPTIONS_LISTEN,
        ] {
            assert!(!is_removed_in_modern(m), "{m}");
        }
    }

    // ── result shaping ───────────────────────────────────────────────────

    #[test]
    fn a_legacy_result_gains_result_type_and_server_info() {
        let info = json!({"name": "streamscope-mcp", "version": "9.9.9"});
        let mut r = json!({"tools": []});
        stamp_result(&mut r, "tools/list", &info, Some(CacheHint::fresh_for(60_000)));
        assert_eq!(r["resultType"], "complete");
        assert_eq!(r["ttlMs"], 60_000);
        assert_eq!(r["cacheScope"], "private");
        assert_eq!(r["_meta"][META_SERVER_INFO]["name"], "streamscope-mcp");
    }

    #[test]
    fn stamping_keeps_the_upstreams_result_type_and_takes_over_everything_else() {
        let info = json!({"name": "gw"});
        let mut r = json!({
            "resultType": "input_required",
            "ttlMs": 5,
            "cacheScope": "public",
            "_meta": { META_SERVER_INFO: {"name": "upstream"} },
        });
        stamp_result(&mut r, "tools/list", &info, Some(CacheHint::fresh_for(60_000)));

        // `resultType` is the upstream's statement about its own call.
        // Overwriting `input_required` with `complete` would tell the client
        // an unanswered question had been answered.
        assert_eq!(r["resultType"], "input_required");

        // The other three describe the answer the CLIENT is holding, which is
        // the gateway's — assembled across every route and narrowed by this
        // caller's grants. Relaying the upstream's `serverInfo` would name a
        // server the client never addressed, and its freshness claim covers a
        // catalog the client is not the one caching.
        assert_eq!(r["ttlMs"], 60_000);
        assert_eq!(r["cacheScope"], "private");
        assert_eq!(r["_meta"][META_SERVER_INFO]["name"], "gw");
    }

    #[test]
    fn a_non_cacheable_method_gains_no_freshness_hint() {
        let info = json!({"name": "gw"});
        let mut r = json!({"content": []});
        stamp_result(&mut r, "tools/call", &info, None);
        assert_eq!(r["resultType"], "complete");
        assert!(r.get("ttlMs").is_none());
        assert!(r.get("cacheScope").is_none());
    }

    #[test]
    fn every_cacheable_method_the_spec_names_is_classified_as_one() {
        for m in [
            "tools/list",
            "prompts/list",
            "resources/list",
            "resources/templates/list",
            "resources/read",
            METHOD_DISCOVER,
        ] {
            assert!(is_cacheable_result(m), "{m}");
        }
        for m in ["tools/call", "prompts/get", "completion/complete"] {
            assert!(!is_cacheable_result(m), "{m}");
        }
    }

    // ── error translation ────────────────────────────────────────────────

    #[test]
    fn the_retired_resource_not_found_code_is_never_emitted() {
        assert_eq!(modernize_error_code(LEGACY_RESOURCE_NOT_FOUND), Some(INVALID_PARAMS));
    }

    /// `ROUTE_NOT_FOUND` carries two meanings that renumber to OPPOSITE codes,
    /// and the era gate is the only place that can tell them apart without
    /// changing what a legacy client reads.
    #[test]
    fn a_missing_route_and_a_missing_resource_renumber_differently() {
        // A missing MOUNT really is a missing endpoint.
        let mut route_gone = super::super::jsonrpc::JsonRpcError {
            code: super::super::jsonrpc::ROUTE_NOT_FOUND,
            message: "no virtual server matches /mcp/x".into(),
            data: None,
        };
        modernize_error(&mut route_gone);
        assert_eq!(route_gone.code, METHOD_NOT_FOUND);
        assert_eq!(
            http_status_for_error(route_gone.code),
            axum::http::StatusCode::NOT_FOUND
        );

        // A missing RESOURCE is a bad parameter (SEP-2164), told apart by the
        // `data.uri` that SEP mandates. Renumbering both alike tells a client
        // asking for a missing resource that the METHOD does not exist, and
        // answers 404 to a request that was understood and refused.
        let mut resource_gone = super::super::jsonrpc::JsonRpcError {
            code: super::super::jsonrpc::ROUTE_NOT_FOUND,
            message: "resource not found".into(),
            data: Some(json!({ "uri": "stsmcp+alpha+file:///doc" })),
        };
        modernize_error(&mut resource_gone);
        assert_eq!(resource_gone.code, INVALID_PARAMS);
        let data = resource_gone.data.as_ref().expect("data survives renumbering");
        assert_eq!(data["uri"], json!("stsmcp+alpha+file:///doc"));
        // The original is still readable, so nothing is lost by renumbering.
        assert_eq!(
            data["streamscopeCode"],
            json!(super::super::jsonrpc::ROUTE_NOT_FOUND)
        );
        assert_eq!(
            http_status_for_error(resource_gone.code),
            axum::http::StatusCode::OK
        );
    }

    #[test]
    fn frozen_range_gateway_codes_become_standard_ones_but_keep_the_original() {
        let mut e = super::super::jsonrpc::JsonRpcError {
            code: super::super::jsonrpc::TOOL_NOT_FOUND,
            message: "no such tool".into(),
            data: None,
        };
        modernize_error(&mut e);
        assert_eq!(e.code, INVALID_PARAMS);
        assert_eq!(e.data.as_ref().unwrap()["streamscopeCode"], -32004);
    }

    #[test]
    fn codes_outside_the_contested_ranges_are_left_alone() {
        // These carry documented meaning for our clients and sit outside both
        // the frozen `-32000..=-32019` band and the spec-reserved
        // `-32020..=-32099` band, so rewriting them would lose information
        // for no conformance gain.
        for code in [
            super::super::jsonrpc::AUTH_REQUIRED,
            super::super::jsonrpc::INSUFFICIENT_SCOPE,
            super::super::jsonrpc::RATE_LIMITED,
        ] {
            assert_eq!(modernize_error_code(code), None, "{code}");
        }
    }

    #[test]
    fn no_code_we_emit_lands_in_the_range_reserved_for_the_specification() {
        // `-32020..=-32099` is the spec's own. We may emit only the three
        // codes it defines there; anything else of ours straying into that
        // band would be a conformance violation a reader could not see.
        // EVERY code this gateway can emit, not a sample. A guard that covers
        // part of the vocabulary reports "clean" while saying nothing about
        // the rest, and the next code added is exactly the one at risk — so
        // this list is the whole of `jsonrpc.rs`, and adding a constant there
        // without adding it here leaves the new code unchecked.
        use super::super::jsonrpc as codes;
        let ours = [
            codes::PARSE_ERROR,
            codes::INVALID_REQUEST,
            codes::METHOD_NOT_FOUND,
            codes::INVALID_PARAMS,
            codes::INTERNAL_ERROR,
            codes::ROUTE_NOT_FOUND,
            codes::UPSTREAM_ERROR,
            codes::TOOL_NOT_FOUND,
            codes::AUTH_REQUIRED,
            codes::INSUFFICIENT_SCOPE,
            codes::RATE_LIMITED,
            codes::UPSTREAM_CREDENTIAL_UNAVAILABLE,
            codes::MCP_USER_CREDENTIAL_MISSING,
            codes::MCP_USER_CREDENTIAL_EXPIRED,
            codes::MCP_USER_OAUTH_REFRESH_FAILED,
            codes::MCP_OAUTH_CLIENT_NOT_CONFIGURED,
            codes::MCP_UPSTREAM_SSRF_REFUSED,
            codes::MCP_BLOCKED_BY_POLICY,
            codes::MCP_UPSTREAM_SESSION_LOST,
            codes::MCP_UPSTREAM_CONFIG_UNSUPPORTED,
            codes::MCP_UPSTREAM_INPUT_UNSUPPORTED,
        ];
        for code in ours {
            assert!(
                !(-32099..=-32020).contains(&code),
                "{code} is inside the range reserved for the MCP specification"
            );
        }
        for code in [HEADER_MISMATCH, MISSING_REQUIRED_CLIENT_CAPABILITY, UNSUPPORTED_PROTOCOL_VERSION] {
            assert!((-32099..=-32020).contains(&code), "{code}");
        }
    }

    // ── downgrade ────────────────────────────────────────────────────────

    #[test]
    fn the_modern_envelope_is_stripped_before_a_legacy_upstream_sees_it() {
        let p = json!({
            "name": "get_weather",
            "inputResponses": {"k": {}},
            "requestState": "ssmrtr.x.y",
            "_meta": {
                META_PROTOCOL_VERSION: MODERN_PROTOCOL_VERSION,
                META_CLIENT_INFO: {"name": "c"},
                META_CLIENT_CAPABILITIES: {},
                META_LOG_LEVEL: "info",
                "progressToken": "p1",
                "traceparent": "00-aaaa-bbbb-01",
            }
        });
        let out = downgrade_request_params(Some(&p)).unwrap();
        assert_eq!(out["name"], "get_weather");
        assert!(out.get("inputResponses").is_none());
        assert!(out.get("requestState").is_none());
        for k in MODERN_REQUEST_META_KEYS {
            assert!(out["_meta"].get(*k).is_none(), "{k} survived the downgrade");
        }
        // Cross-era-stable keys must survive, or we lose progress reporting
        // and break distributed traces at the gateway hop.
        assert_eq!(out["_meta"]["progressToken"], "p1");
        assert_eq!(out["_meta"]["traceparent"], "00-aaaa-bbbb-01");
    }

    #[test]
    fn an_emptied_meta_is_removed_rather_than_left_as_an_empty_object() {
        let p = json!({
            "name": "t",
            "_meta": {
                META_PROTOCOL_VERSION: MODERN_PROTOCOL_VERSION,
                META_CLIENT_CAPABILITIES: {},
            }
        });
        let out = downgrade_request_params(Some(&p)).unwrap();
        assert!(out.get("_meta").is_none());
        assert_eq!(out["name"], "t");
    }

    // ── subscriptions ────────────────────────────────────────────────────

    #[test]
    fn an_absent_filter_subscribes_to_nothing() {
        let f = SubscriptionFilter::parse(None);
        assert!(f.is_empty());
        assert!(!f.accepts("notifications/tools/list_changed", None));
    }

    #[test]
    fn a_filter_admits_only_what_it_named() {
        let p = json!({"notifications": {
            "toolsListChanged": true,
            "resourceSubscriptions": ["stsmcp://p/abc"],
        }});
        let f = SubscriptionFilter::parse(Some(&p));
        assert!(f.accepts("notifications/tools/list_changed", None));
        assert!(!f.accepts("notifications/prompts/list_changed", None));
        assert!(!f.accepts("notifications/resources/list_changed", None));
        assert!(f.accepts("notifications/resources/updated", Some("stsmcp://p/abc")));
        assert!(!f.accepts("notifications/resources/updated", Some("stsmcp://p/other")));
        // A resource update naming no resource matches no subscription.
        assert!(!f.accepts("notifications/resources/updated", None));
    }

    #[test]
    fn the_honored_subset_drops_what_no_upstream_can_source() {
        let p = json!({"notifications": {
            "toolsListChanged": true,
            "promptsListChanged": true,
            "resourcesListChanged": true,
            "resourceSubscriptions": ["stsmcp://p/abc"],
        }});
        let requested = SubscriptionFilter::parse(Some(&p));
        let caps = json!({
            "tools": {"listChanged": true},
            "resources": {"listChanged": false, "subscribe": false},
        });
        let honored = requested.honored(&caps);
        assert!(honored.tools_list_changed);
        // No upstream advertises prompts at all, let alone list-change
        // notifications — reporting it would leave the client waiting forever.
        assert!(!honored.prompts_list_changed);
        assert!(!honored.resources_list_changed);
        assert!(honored.resource_subscriptions.is_empty());

        let ack = honored.to_json();
        assert_eq!(ack["toolsListChanged"], true);
        // Declined types are omitted, not reported as `false`.
        assert!(ack.get("promptsListChanged").is_none());
        assert!(ack.get("resourcesListChanged").is_none());
    }

    #[test]
    fn every_message_on_a_listen_stream_carries_its_subscription_id() {
        let id = json!(7);
        let mut n = json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"});
        stamp_subscription_id(&mut n, &id);
        assert_eq!(n["params"]["_meta"][META_SUBSCRIPTION_ID], 7);

        let ack = subscription_ack(&id, &SubscriptionFilter { tools_list_changed: true, ..Default::default() });
        assert_eq!(ack["params"]["_meta"][META_SUBSCRIPTION_ID], 7);
        assert_eq!(ack["method"], "notifications/subscriptions/acknowledged");

        let close = subscription_close(&id);
        assert_eq!(close["id"], 7);
        assert_eq!(close["result"]["resultType"], "complete");
        assert_eq!(close["result"]["_meta"][META_SUBSCRIPTION_ID], 7);
    }

    #[test]
    fn stamping_a_subscription_id_preserves_existing_params() {
        let id = json!("s-1");
        let mut n = json!({
            "jsonrpc": "2.0",
            "method": "notifications/resources/updated",
            "params": {"uri": "stsmcp://p/abc"}
        });
        stamp_subscription_id(&mut n, &id);
        assert_eq!(n["params"]["uri"], "stsmcp://p/abc");
        assert_eq!(n["params"]["_meta"][META_SUBSCRIPTION_ID], "s-1");
    }

    // ── MRTR ─────────────────────────────────────────────────────────────

    #[test]
    fn only_the_three_named_rpcs_may_answer_with_input_required() {
        for m in ["tools/call", "prompts/get", "resources/read"] {
            assert!(supports_input_required(m), "{m}");
        }
        for m in ["tools/list", "resources/list", METHOD_DISCOVER, METHOD_SUBSCRIPTIONS_LISTEN] {
            assert!(!supports_input_required(m), "{m}");
        }
    }

    #[test]
    fn an_upstream_server_request_reduces_to_an_input_request_entry() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 42,
            "method": "elicitation/create",
            "params": {"mode": "form", "message": "GitHub username?"}
        });
        let (method, params) = input_request_entry(&msg).unwrap();
        assert_eq!(method, "elicitation/create");
        assert_eq!(params["message"], "GitHub username?");
        // The upstream's JSON-RPC id is deliberately absent: the client
        // answers by key, and that id belonged to a stream we abandoned.
        assert!(params.get("id").is_none());
    }

    #[test]
    fn a_non_input_server_message_is_not_an_input_request() {
        for method in [
            "notifications/message",
            "notifications/tools/list_changed",
            "some/other",
        ] {
            let msg = json!({"jsonrpc": "2.0", "id": 1, "method": method});
            assert!(input_request_entry(&msg).is_none(), "{method}");
        }
    }

    #[test]
    fn input_request_keys_are_derived_not_random() {
        // The retry re-issues the call upstream, so the upstream asks its
        // question again. A random key would not match the answer the client
        // already supplied and the retry would loop forever.
        assert_eq!(input_request_key("elicitation/create", 0), "elicitation_create");
        assert_eq!(input_request_key("elicitation/create", 0), input_request_key("elicitation/create", 0));
        assert_eq!(input_request_key("elicitation/create", 1), "elicitation_create_1");
        assert_ne!(
            input_request_key("elicitation/create", 0),
            input_request_key("sampling/createMessage", 0)
        );
    }

    #[test]
    fn an_input_required_result_carries_both_halves_the_client_needs() {
        let mut reqs = Map::new();
        reqs.insert(
            "elicitation_create".to_string(),
            json!({"method": "elicitation/create", "params": {"mode": "form"}}),
        );
        let r = input_required_result(&reqs, "ssmrtr.a.b", &json!({"name": "gw"}));
        assert_eq!(r["resultType"], "input_required");
        assert_eq!(r["requestState"], "ssmrtr.a.b");
        assert_eq!(r["inputRequests"]["elicitation_create"]["method"], "elicitation/create");
    }

    // ── Speaking the era to an upstream ──────────────────────────────────

    #[test]
    fn each_upstream_era_reports_itself() {
        // One line, and the only thing standing between "the gateway picks an
        // era per upstream" and "the gateway addresses every upstream the
        // same way". The e2e tier would catch a constant here, but a
        // 13-minute system suite is the wrong owner for a two-variant
        // predicate — and a cargo-driven mutation run cannot see that suite
        // at all, so a survivor here reads as untested.
        assert!(UpstreamEra::Modern.is_modern());
        assert!(!UpstreamEra::Legacy.is_modern());
    }

    #[test]
    fn a_dual_era_upstream_is_addressed_in_the_clients_own_era() {
        // The whole reason the two facts are kept rather than collapsed. A
        // modern client reaches it natively — its mid-call questions relay as
        // data instead of costing the upstream a re-run — and a legacy client
        // reaches it natively too, keeping the live stream its revision needs
        // to be asked anything at all. Neither costs the other: the modern
        // leg holds no session, so there is no shared resource to ration.
        assert_eq!(
            era_for_request(true, UpstreamEraSupport::BOTH),
            UpstreamEra::Modern
        );
        assert_eq!(
            era_for_request(false, UpstreamEraSupport::BOTH),
            UpstreamEra::Legacy
        );
    }

    #[test]
    fn a_single_era_upstream_ignores_the_clients_era_entirely() {
        // There is nothing to choose, and the translation on the request path
        // is what makes the mismatch work. A gateway that let the client's era
        // win here would address a modern-only server with a handshake it
        // deleted.
        for client_is_modern in [true, false] {
            assert_eq!(
                era_for_request(client_is_modern, UpstreamEraSupport::MODERN_ONLY),
                UpstreamEra::Modern,
                "client_is_modern={client_is_modern}"
            );
            assert_eq!(
                era_for_request(client_is_modern, UpstreamEraSupport::LEGACY_ONLY),
                UpstreamEra::Legacy,
                "client_is_modern={client_is_modern}"
            );
        }
    }

    #[test]
    fn a_server_that_implements_neither_era_is_answered_as_legacy() {
        // Not reachable from the probe, which only ever records what a server
        // answered — but the call has to fail against *some* era, and failing
        // against the one nearly every server speaks is the more useful error
        // for an operator to read.
        let neither = UpstreamEraSupport {
            modern: false,
            legacy: false,
        };
        assert_eq!(era_for_request(true, neither), UpstreamEra::Legacy);
        assert_eq!(era_for_request(false, neither), UpstreamEra::Legacy);
    }

    #[test]
    fn a_discovery_naming_a_modern_revision_we_serve_is_positive_evidence() {
        assert!(offers_modern_era(&json!({"supportedVersions": ["2026-07-28"]})));
        assert!(offers_modern_era(&json!({
            "supportedVersions": ["2026-07-28", "2025-11-25"]
        })));
    }

    #[test]
    fn a_discover_answering_server_advertising_no_modern_revision_is_not() {
        // The reference clients read this as a legacy advertisement rather
        // than an incompatibility and fall back to the handshake. A gateway
        // that read it as modern would speak an era the server named nowhere.
        assert!(!offers_modern_era(&json!({"supportedVersions": ["2025-11-25"]})));
        assert!(!offers_modern_era(&json!({"supportedVersions": []})));
    }

    #[test]
    fn a_result_that_names_no_versions_at_all_is_not_evidence_either() {
        // Matching the reference clients' "unparseable result is not modern
        // evidence" branch. Reading silence as agreement would adopt an era
        // off a server that never claimed it.
        assert!(!offers_modern_era(&json!({"capabilities": {}})));
        assert!(!offers_modern_era(&json!({"supportedVersions": "2026-07-28"})));
        assert!(!offers_modern_era(&json!("nonsense")));
    }

    #[test]
    fn only_the_three_spec_codes_identify_a_modern_server() {
        for code in [
            HEADER_MISMATCH,
            MISSING_REQUIRED_CLIENT_CAPABILITY,
            UNSUPPORTED_PROTOCOL_VERSION,
        ] {
            assert!(identifies_modern_server(code), "{code} should identify one");
        }
        // The two a LEGACY server answers a `server/discover` with. Reading
        // either as modern would send the gateway down a path that upstream
        // cannot serve at all.
        for code in [METHOD_NOT_FOUND, super::super::jsonrpc::INVALID_REQUEST] {
            assert!(!identifies_modern_server(code), "{code} must not");
        }
    }

    #[test]
    fn the_envelope_states_the_gateways_identity_not_the_clients() {
        // The upstream is talking to the gateway. Forwarding the downstream
        // client's own `clientInfo` would introduce our caller to the
        // upstream as though it were us, and an upstream that adapts to a
        // client name would adapt to the wrong one.
        let params = json!({
            "name": "get_weather",
            "_meta": {
                META_CLIENT_INFO: {"name": "some-agent"},
                META_PROTOCOL_VERSION: "2026-07-28",
                "progressToken": 7,
            }
        });
        let out = upgrade_request_params(
            Some(&params),
            &json!({"elicitation": {}}),
            &json!({"name": "streamscope-mcp"}),
            None,
        );
        assert_eq!(out["_meta"][META_CLIENT_INFO]["name"], "streamscope-mcp");
        assert_eq!(out["_meta"][META_CLIENT_CAPABILITIES]["elicitation"], json!({}));
        assert_eq!(out["_meta"][META_PROTOCOL_VERSION], MODERN_PROTOCOL_VERSION);
        // Not ours to touch: it predates the era split and means the same on
        // both sides.
        assert_eq!(out["_meta"]["progressToken"], 7);
        assert_eq!(out["name"], "get_weather");
    }

    #[test]
    fn the_log_opt_in_is_the_gateways_to_grant_and_to_withdraw() {
        // § Logging: with no `logLevel` the server MUST NOT emit log
        // notifications for the request. The gateway forwards an upstream's
        // log lines onto a downstream stream, so it must not inherit a
        // client's opt-in it has nowhere to put — hence removal, not absence.
        let params = json!({"_meta": {META_LOG_LEVEL: "debug"}});
        let withdrawn = upgrade_request_params(Some(&params), &json!({}), &json!({}), None);
        assert!(withdrawn["_meta"].get(META_LOG_LEVEL).is_none());

        let granted = upgrade_request_params(Some(&params), &json!({}), &json!({}), Some("info"));
        assert_eq!(granted["_meta"][META_LOG_LEVEL], "info");
    }

    #[test]
    fn a_request_with_no_params_still_gains_the_envelope() {
        // The envelope is mandatory in this era, so even `params: null` has
        // to become an object carrying it.
        let out = upgrade_request_params(None, &json!({}), &json!({"name": "gw"}), None);
        assert_eq!(out["_meta"][META_PROTOCOL_VERSION], MODERN_PROTOCOL_VERSION);
    }

    #[test]
    fn a_malformed_meta_is_replaced_rather_than_left_to_be_rejected() {
        let params = json!({"_meta": "not-an-object", "name": "x"});
        let out = upgrade_request_params(Some(&params), &json!({}), &json!({"name": "gw"}), None);
        assert_eq!(out["_meta"][META_PROTOCOL_VERSION], MODERN_PROTOCOL_VERSION);
        assert_eq!(out["name"], "x");
    }

    #[test]
    fn positional_params_are_forwarded_untouched() {
        // JSON-RPC permits an array; MCP never uses one, and it cannot carry
        // `_meta`. Reshaping a body we do not understand is worse than
        // forwarding it.
        let params = json!([1, 2, 3]);
        let out = upgrade_request_params(Some(&params), &json!({}), &json!({}), None);
        assert_eq!(out, params);
    }

    #[test]
    fn every_method_the_modern_era_deleted_has_a_disposition() {
        use ModernUpstreamAction as A;
        assert_eq!(modern_upstream_action("initialize"), A::FromDiscovery);
        assert_eq!(modern_upstream_action(METHOD_DISCOVER), A::FromDiscovery);
        assert_eq!(modern_upstream_action("ping"), A::EmptyResult);
        assert_eq!(modern_upstream_action("logging/setLevel"), A::EmptyResult);
        assert_matches!(modern_upstream_action("resources/subscribe"), A::Unsupported(_));
        assert_matches!(modern_upstream_action("resources/unsubscribe"), A::Unsupported(_));
        assert_eq!(
            modern_upstream_action("notifications/initialized"),
            A::DropNotification
        );
        // Every method `is_removed_in_modern` refuses a modern CLIENT must
        // have an answer here for a legacy one, or a legacy client's call
        // would be forwarded to an upstream that deleted it.
        for m in [
            "initialize",
            "ping",
            "logging/setLevel",
            "resources/subscribe",
            "resources/unsubscribe",
        ] {
            assert!(is_removed_in_modern(m));
            assert_ne!(
                modern_upstream_action(m),
                A::Forward,
                "{m} would be forwarded to an upstream that deleted it"
            );
        }
        // And the surface that survived is forwarded, not intercepted.
        for m in ["tools/call", "tools/list", "resources/read", "prompts/get"] {
            assert_eq!(modern_upstream_action(m), A::Forward, "{m}");
        }
    }

    #[test]
    fn either_half_of_an_input_required_carries_it_on_its_own() {
        // § MRTR server requirement 6: at least ONE of `inputRequests` and
        // `requestState`. Each of these three is a shape a conforming
        // upstream emits, and the reference server emits the second on every
        // question it asks.
        let both = json!({
            "resultType": "input_required",
            "inputRequests": {"q1": {"method": "elicitation/create", "params": {}}},
            "requestState": "upstream-blob",
        });
        let InputRequiredShape::Yes(parsed) = parse_input_required(&both) else {
            panic!("both halves should parse");
        };
        assert_eq!(parsed.request_state.as_deref(), Some("upstream-blob"));
        assert_eq!(parsed.input_requests.len(), 1);

        let questions_only = json!({
            "resultType": "input_required",
            "inputRequests": {"q1": {"method": "elicitation/create", "params": {}}},
        });
        let InputRequiredShape::Yes(parsed) = parse_input_required(&questions_only) else {
            panic!("a question with no state should parse");
        };
        assert_eq!(parsed.request_state, None);
        assert_eq!(parsed.input_requests.len(), 1);

        // Load shedding: state and no question at all.
        let state_only = json!({"resultType": "input_required", "requestState": "s"});
        let InputRequiredShape::Yes(parsed) = parse_input_required(&state_only) else {
            panic!("state with no question should parse");
        };
        assert_eq!(parsed.request_state.as_deref(), Some("s"));
        assert!(parsed.input_requests.is_empty());
    }

    #[test]
    fn a_well_typed_empty_half_is_read_as_the_absence_it_states() {
        // An empty map asks nothing and an empty string is a value client
        // requirement 2 says to echo back exactly. Neither is broken, so
        // neither may be refused — the other half still carries the result.
        let empty_map = json!({"resultType": "input_required", "inputRequests": {}, "requestState": "s"});
        let InputRequiredShape::Yes(parsed) = parse_input_required(&empty_map) else {
            panic!("an empty question map beside a state should parse");
        };
        assert!(parsed.input_requests.is_empty());
        assert_eq!(parsed.request_state.as_deref(), Some("s"));

        let empty_state = json!({
            "resultType": "input_required",
            "inputRequests": {"q": {"method": "roots/list"}},
            "requestState": "",
        });
        let InputRequiredShape::Yes(parsed) = parse_input_required(&empty_state) else {
            panic!("an empty state beside a question should parse");
        };
        assert_eq!(parsed.request_state.as_deref(), Some(""));
    }

    #[test]
    fn an_unrelayable_input_required_is_malformed_not_an_ordinary_result() {
        for broken in [
            // Neither half — the one shape requirement 6 forbids. Relaying it
            // hands the client a question with no key to answer under and no
            // state to quote back; it can only hang on it.
            json!({"resultType": "input_required"}),
            json!({"resultType": "input_required", "inputRequests": {}}),
            json!({"resultType": "input_required", "inputRequests": {}, "requestState": null}),
            // Present and the wrong type: a claim the upstream made and got
            // wrong, whatever the other half says.
            json!({"resultType": "input_required", "inputRequests": [], "requestState": "s"}),
            json!({"resultType": "input_required", "inputRequests": {"q": {}}, "requestState": 7}),
        ] {
            assert_eq!(
                parse_input_required(&broken),
                InputRequiredShape::Malformed,
                "{broken}"
            );
        }
        assert_eq!(
            parse_input_required(&json!({"resultType": "complete", "tools": []})),
            InputRequiredShape::No
        );
        assert_eq!(parse_input_required(&json!({"tools": []})), InputRequiredShape::No);
        assert_eq!(parse_input_required(&json!("not-an-object")), InputRequiredShape::No);
    }

    #[test]
    fn a_relayed_input_required_omits_the_questions_it_does_not_have() {
        let server_info = json!({"name": "streamscope-mcp"});
        let mut asked = Map::new();
        asked.insert("q1".into(), json!({"method": "roots/list"}));

        let with_questions = input_required_result(&asked, "ssmrtr.wrapper", &server_info);
        assert_eq!(with_questions["inputRequests"]["q1"]["method"], "roots/list");
        assert_eq!(with_questions["requestState"], "ssmrtr.wrapper");

        // Load shedding relayed onward: an ABSENT `inputRequests` is what
        // tells the client it may retry immediately. An empty map instead
        // asks it to fulfil a set of questions it can never finish.
        let shed = input_required_result(&Map::new(), "ssmrtr.wrapper", &server_info);
        assert!(shed.get("inputRequests").is_none(), "{shed}");
        assert_eq!(shed["requestState"], "ssmrtr.wrapper");
        assert_eq!(shed["resultType"], "input_required");
    }

    #[test]
    fn the_asked_methods_are_deduplicated_and_entries_without_one_are_skipped() {
        let mut reqs = Map::new();
        reqs.insert("a".into(), json!({"method": "elicitation/create"}));
        reqs.insert("b".into(), json!({"method": "elicitation/create"}));
        reqs.insert("c".into(), json!({"method": "sampling/createMessage"}));
        reqs.insert("d".into(), json!({"params": {}}));
        let methods = input_required_methods(&reqs);
        assert_eq!(methods.len(), 2);
        assert!(methods.contains(&"elicitation/create".to_string()));
        assert!(methods.contains(&"sampling/createMessage".to_string()));
    }

    #[test]
    fn a_modern_error_is_brought_into_a_legacy_clients_vocabulary() {
        let mut err = super::super::jsonrpc::JsonRpcError {
            code: UNSUPPORTED_PROTOCOL_VERSION,
            message: "nope".into(),
            data: None,
        };
        legacyize_error(&mut err);
        assert_eq!(err.code, super::super::jsonrpc::INVALID_REQUEST);
        // Recorded under `upstreamCode`, not `streamscopeCode`: an operator
        // reading the row has to be able to tell a code the UPSTREAM minted
        // from one the gateway did.
        assert_eq!(err.data.as_ref().unwrap()["upstreamCode"], UNSUPPORTED_PROTOCOL_VERSION);

        // A code a legacy client already understands is left alone — the
        // rewrite exists to translate, not to flatten.
        let mut ordinary = super::super::jsonrpc::JsonRpcError {
            code: METHOD_NOT_FOUND,
            message: "nope".into(),
            data: None,
        };
        legacyize_error(&mut ordinary);
        assert_eq!(ordinary.code, METHOD_NOT_FOUND);
        assert!(ordinary.data.is_none());
    }

    #[test]
    fn a_retry_is_pointed_at_the_upstream_that_asked() {
        let params = json!({
            "name": "t",
            "requestState": "ssmrtr.gateway.wrapper",
            "inputResponses": {"q1": {"action": "accept"}},
        });
        let out = retarget_request_state(Some(&params), MrtrRetry::Quoting("upstream-blob")).unwrap();
        assert_eq!(out["requestState"], "upstream-blob");
        assert_eq!(out["inputResponses"]["q1"]["action"], "accept");
    }

    #[test]
    fn an_upstream_that_kept_no_state_still_receives_the_answers() {
        // The case the three-way split exists for. Client requirement 2
        // forbids quoting a `requestState` back to a server that issued none,
        // so it goes — but the answers are the whole point of the retry, and
        // dropping them leaves the upstream asking the same question forever.
        let params = json!({
            "name": "t",
            "requestState": "ssmrtr.gateway.wrapper",
            "inputResponses": {"q1": {"action": "accept"}},
        });
        let out = retarget_request_state(Some(&params), MrtrRetry::AnswersOnly).unwrap();
        assert!(out.get("requestState").is_none(), "{out}");
        assert_eq!(out["inputResponses"]["q1"]["action"], "accept");
        assert_eq!(out["name"], "t");
    }

    #[test]
    fn answers_a_sibling_upstream_was_never_asked_for_are_dropped() {
        // The one case that withholds: our own wrapper named a different
        // upstream of a fanned-out virtual server, so we KNOW this one did
        // not ask. Forwarding the wrapper itself would additionally offer it
        // a blob only we can verify.
        let params = json!({
            "name": "t",
            "requestState": "ssmrtr.gateway.wrapper",
            "inputResponses": {"q1": {"action": "accept"}},
        });
        let out = retarget_request_state(Some(&params), MrtrRetry::NotAimedHere).unwrap();
        assert!(out.get("requestState").is_none());
        assert!(out.get("inputResponses").is_none());
        assert_eq!(out["name"], "t");
    }

    #[test]
    fn a_retry_is_resolved_against_the_upstream_that_actually_asked() {
        let asked = Uuid::new_v4();
        let sibling = Uuid::new_v4();

        let with_state = (asked, Some("upstream-blob".to_string()));
        assert_eq!(
            MrtrRetry::resolve(Some(&with_state), asked),
            MrtrRetry::Quoting("upstream-blob")
        );
        // A fanned-out virtual server reaches several upstreams. A sibling
        // gets neither the blob (which only its minter can verify) nor the
        // answers (which belong to a question it never asked).
        assert_eq!(
            MrtrRetry::resolve(Some(&with_state), sibling),
            MrtrRetry::NotAimedHere
        );

        let stateless = (asked, None);
        assert_eq!(
            MrtrRetry::resolve(Some(&stateless), asked),
            MrtrRetry::AnswersOnly
        );
        assert_eq!(
            MrtrRetry::resolve(Some(&stateless), sibling),
            MrtrRetry::NotAimedHere
        );

        // No wrapper at all. This is what a conforming client sends after a
        // question that carried no state — client requirement 2 forbids
        // quoting back a `requestState` the server never issued — so the
        // answers are the whole retry and withholding them makes the upstream
        // ask again forever. Also the shape of a first attempt, which carries
        // no answers to forward anyway.
        assert_eq!(MrtrRetry::resolve(None, asked), MrtrRetry::AnswersOnly);
    }

    #[test]
    fn only_an_unparseable_input_response_is_a_protocol_error() {
        // § MRTR Error Handling draws three lines and each one is a different
        // disposition. Getting any of them wrong is quiet: refusing a missing
        // answer denies a retry the spec wants re-asked, refusing an extra key
        // denies one it wants ignored, and accepting a non-object relays a
        // shape no revision defines.

        // Absent, null, or empty: information the client did not send. The
        // upstream asks again; this is not an error.
        for ok in [
            json!({"name": "t"}),
            json!({"name": "t", "inputResponses": null}),
            json!({"name": "t", "inputResponses": {}}),
        ] {
            assert!(validate_input_responses(Some(&ok)).is_ok(), "{ok}");
        }
        assert!(validate_input_responses(None).is_ok());

        // Extra keys the server never asked under: ignored, not refused.
        let extra = json!({
            "inputResponses": {
                "user_name": {"action": "accept"},
                "never_asked": {"action": "accept"},
            }
        });
        assert!(validate_input_responses(Some(&extra)).is_ok());

        // Not a result object — in the map or as the map. Unparseable data,
        // which the spec answers with an error.
        for bad in [
            json!({"inputResponses": {"user_name": 42}}),
            json!({"inputResponses": {"ok": {"action": "accept"}, "user_name": "yes"}}),
            json!({"inputResponses": {"user_name": []}}),
            json!({"inputResponses": {"user_name": null}}),
            json!({"inputResponses": []}),
            json!({"inputResponses": "user_name=Alice"}),
        ] {
            let err = validate_input_responses(Some(&bad))
                .expect_err(&format!("should be refused: {bad}"));
            assert_eq!(err.code, INVALID_PARAMS, "{bad}");
        }
    }

    #[test]
    fn a_cold_retry_carrying_only_answers_reaches_the_upstream_intact() {
        // Exactly the wire the conformance suite sends for
        // `sep-2322-ignore-unexpected-params`: a `tools/call` with
        // `inputResponses` and no `requestState`, plus keys the server never
        // asked for. The answers must arrive — the extra ones are the
        // upstream's to ignore, which § MRTR Error Handling says it SHOULD.
        let params = json!({
            "name": "test_input_required_result_elicitation",
            "arguments": {},
            "inputResponses": {
                "user_name": {"action": "accept", "content": {"name": "Alice"}},
                "unknown_extra_key": {"action": "accept"},
            },
        });
        let out =
            retarget_request_state(Some(&params), MrtrRetry::resolve(None, Uuid::new_v4())).unwrap();
        assert_eq!(out["inputResponses"]["user_name"]["content"]["name"], "Alice");
        assert!(out["inputResponses"].get("unknown_extra_key").is_some());
        assert!(out.get("requestState").is_none());
    }

    #[test]
    fn the_handshake_version_is_read_from_the_body_not_the_header() {
        const SERVE: &[&str] = &["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"];

        // A legacy client is not required to send `MCP-Protocol-Version` on
        // the handshake itself — the response is what tells it what to send
        // from then on. Answering from the header's default would downgrade
        // every client that asked for something newer, and the client would
        // comply.
        let asked = json!({"protocolVersion": "2025-11-25", "capabilities": {}});
        assert_eq!(
            negotiated_initialize_version(Some(&asked), SERVE, "2025-06-18"),
            "2025-11-25"
        );

        // The legacy handshake's own rule for a version we do not serve:
        // answer with one we do and let the client decide.
        let stale = json!({"protocolVersion": "2024-01-01"});
        assert_eq!(
            negotiated_initialize_version(Some(&stale), SERVE, "2025-06-18"),
            "2025-06-18"
        );
        assert_eq!(negotiated_initialize_version(None, SERVE, "2025-06-18"), "2025-06-18");
        // A non-string is no more a request than an absent one.
        let odd = json!({"protocolVersion": 20251125});
        assert_eq!(
            negotiated_initialize_version(Some(&odd), SERVE, "2025-06-18"),
            "2025-06-18"
        );
    }

    #[test]
    fn discovery_shaped_as_initialize_announces_the_clients_own_revision() {
        // The fan-out relays the first route's `protocolVersion` verbatim.
        // Announcing `2026-07-28` to a legacy client because the first
        // upstream happened to be modern would name a revision the gateway is
        // not speaking to it.
        let r = discovery_as_initialize_result(
            &json!({"tools": {"listChanged": true}}),
            Some("use the tools"),
            "2025-11-25",
        );
        assert_eq!(r["protocolVersion"], "2025-11-25");
        assert_eq!(r["capabilities"]["tools"]["listChanged"], true);
        assert_eq!(r["instructions"], "use the tools");

        let bare = discovery_as_initialize_result(&json!({}), Some(""), "2025-06-18");
        assert!(bare.get("instructions").is_none());
    }

    #[test]
    fn a_capability_the_gateway_cannot_deliver_is_not_advertised() {
        // The upstream really can subscribe and says so; the gateway cannot
        // carry it, because that revision serves subscriptions only through a
        // `subscriptions/listen` stream it does not hold open. `initialize`
        // is where a legacy client decides what to attempt, so advertising it
        // there buys a refusal on every call instead of a client that never
        // tries.
        let r = discovery_as_initialize_result(
            &json!({"resources": {"subscribe": true, "listChanged": true}}),
            None,
            "2025-11-25",
        );
        assert!(r["capabilities"]["resources"].get("subscribe").is_none(), "{r}");
        // Everything else the upstream offers survives — the mask is one
        // capability, not a blanket.
        assert_eq!(r["capabilities"]["resources"]["listChanged"], true);
    }

    #[test]
    fn a_modern_result_is_stripped_to_what_a_legacy_client_defines() {
        let mut r = json!({
            "content": [],
            "resultType": "complete",
            "ttlMs": 60_000,
            "cacheScope": "public",
            "_meta": { META_SERVER_INFO: {"name": "some-upstream"}, "progressToken": 4 },
        });
        assert!(downgrade_result(&mut r));
        assert!(r.get("resultType").is_none());
        assert!(r.get("ttlMs").is_none());
        assert!(r.get("cacheScope").is_none());
        // The identity leak this closes: every other surface tells a legacy
        // client it is talking to `streamscope-mcp`.
        assert!(r["_meta"].get(META_SERVER_INFO).is_none(), "{r}");
        // What predates the era split and means the same thing survives.
        assert_eq!(r["_meta"]["progressToken"], 4);
        assert_eq!(r["content"], json!([]));

        // An emptied `_meta` goes with it — the same rule
        // `downgrade_request_params` follows, because an empty object is a
        // value some upstreams and clients validate against a schema.
        let mut only_server_info = json!({
            "content": [],
            "_meta": { META_SERVER_INFO: {"name": "u"} },
        });
        assert!(downgrade_result(&mut only_server_info));
        assert!(only_server_info.get("_meta").is_none(), "{only_server_info}");
    }

    #[test]
    fn the_top_level_stamps_alone_are_reported_as_a_change() {
        // The `_meta` half of the strip is what the case above happens to
        // exercise, so on its own it would let the top-level half report "no
        // change" while still removing the fields. That return value is not
        // bookkeeping: a stream event whose relay is told nothing changed
        // keeps its ORIGINAL bytes, so the fields would go out to a legacy
        // client after all — and only on the streaming path, which is the
        // half no one checks by hand.
        let mut r = json!({"content": [], "resultType": "complete", "ttlMs": 5});
        assert!(downgrade_result(&mut r));
        assert_eq!(r, json!({"content": []}));
    }

    #[test]
    fn a_result_with_nothing_modern_in_it_is_left_byte_identical() {
        // The return value is what lets a stream event keep its original
        // bytes. Reporting a change that did not happen would re-serialize
        // every event a legacy client receives, and those exact bytes are
        // what the audit copy is built from.
        let mut r = json!({"content": [{"type": "text", "text": "hi"}]});
        assert!(!downgrade_result(&mut r));
        assert_eq!(r, json!({"content": [{"type": "text", "text": "hi"}]}));
        assert!(!downgrade_result(&mut json!("not-an-object")));
    }

    #[test]
    fn input_responses_parse_by_key_and_a_bad_shape_reads_as_absent() {
        let p = json!({"inputResponses": {"elicitation_create": {"action": "accept"}}});
        let r = InputResponses::parse(Some(&p));
        assert_eq!(r.get("elicitation_create").unwrap()["action"], "accept");
        assert!(r.get("missing").is_none());

        // A malformed field must read as "no answers yet" so the server
        // re-asks, which § MRTR Error Handling prefers over an error.
        for bad in [json!({"inputResponses": []}), json!({"inputResponses": "x"}), json!({})] {
            assert!(InputResponses::parse(Some(&bad)).is_empty());
        }
    }

    #[test]
    fn required_capability_data_names_exactly_the_missing_one() {
        assert_eq!(required_capability_for("elicitation/create"), json!({"elicitation": {}}));
        assert_eq!(required_capability_for("sampling/createMessage"), json!({"sampling": {}}));
        assert_eq!(required_capability_for("roots/list"), json!({"roots": {}}));
    }

    #[test]
    fn a_missing_capability_error_carries_the_http_status_the_spec_mandates() {
        let e = ModernError::missing_client_capability(
            required_capability_for("elicitation/create"),
            "needs elicitation",
        );
        assert_eq!(e.code, MISSING_REQUIRED_CLIENT_CAPABILITY);
        assert_eq!(e.status, axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(e.data.unwrap()["requiredCapabilities"]["elicitation"], json!({}));
    }

    #[test]
    fn an_unsupported_version_error_tells_the_client_what_to_retry_with() {
        let e = ModernError::unsupported_version("1900-01-01", &["2026-07-28", "2025-11-25"]);
        assert_eq!(e.code, UNSUPPORTED_PROTOCOL_VERSION);
        assert_eq!(e.status, axum::http::StatusCode::BAD_REQUEST);
        let d = e.data.unwrap();
        assert_eq!(d["requested"], "1900-01-01");
        assert_eq!(d["supported"][0], "2026-07-28");
    }

    #[test]
    fn an_unimplemented_method_is_a_404_so_a_dual_era_client_can_tell_us_apart() {
        // § Backward Compatibility: the client distinguishes a modern server
        // that lacks the method from a legacy HTTP+SSE server by the *body*
        // of the 404, so both halves matter.
        let e = ModernError::method_not_found("no such method");
        assert_eq!(e.status, axum::http::StatusCode::NOT_FOUND);
        assert_eq!(e.code, METHOD_NOT_FOUND);
    }

    // ── outbound header restamping ───────────────────────────────────────

    #[test]
    fn outbound_headers_are_rebuilt_from_the_rewritten_body() {
        // Virtualization strips the namespace prefix, so relaying the
        // client's own Mcp-Name would disagree with the body we forward.
        let r = req("tools/call", json!({"name": "get_weather"}));
        let h = outbound_transport_headers(&r);
        assert_eq!(h[0], ("Mcp-Method", "tools/call".to_string()));
        assert_eq!(h[1], ("Mcp-Name", "get_weather".to_string()));

        let r = req("tools/list", json!({}));
        let h = outbound_transport_headers(&r);
        assert_eq!(h.len(), 1);
    }

    #[test]
    fn an_outbound_name_needing_encoding_gets_it() {
        let r = req("resources/read", json!({"uri": "file:///Hello, 世界"}));
        let h = outbound_transport_headers(&r);
        let name = &h[1].1;
        assert!(name.starts_with("=?base64?"));
        assert_eq!(decode_header_value(name).unwrap(), "file:///Hello, 世界");
    }

    // ── Mutation-closing assertions ──────────────────────────────────────
    //
    // Each test below closes a mutant that survived mutation testing over
    // this file: a way to break the code that the tests above did not notice.
    // They are grouped by what they pin rather than by function, because the
    // gap was always the same shape — a predicate whose TRUE branch was
    // exercised and whose FALSE branch was not, or a match arm nothing named.

    #[test]
    fn the_retired_resource_not_found_constant_is_the_value_the_spec_retired() {
        // The constant exists only to be recognised on the wire, so its VALUE
        // is the whole of it — a sign flip here would silently stop
        // translating the code this module exists to translate.
        assert_eq!(LEGACY_RESOURCE_NOT_FOUND, -32002);
    }

    #[test]
    fn a_field_value_may_carry_an_internal_tab_or_space_but_not_pad_with_one() {
        // RFC 9110 admits SP and HTAB *between* visible characters. Both are
        // named separately in the guard, so each needs its own case or one can
        // be dropped without a test noticing.
        assert!(is_plain_header_safe("a b"));
        assert!(is_plain_header_safe("a\tb"));
        // ...but not as padding, which an intermediary may strip — silently
        // turning a matching name into a mismatching one downstream of us.
        assert!(!is_plain_header_safe(" a"));
        assert!(!is_plain_header_safe("a "));
        assert!(!is_plain_header_safe("\ta"));
        assert!(!is_plain_header_safe("a\t"));
        // A control character is never transmissible.
        assert!(!is_plain_header_safe("a\nb"));
        assert!(!is_plain_header_safe("a\rb"));
        assert!(!is_plain_header_safe("a\u{0}b"));
    }

    #[test]
    fn a_sentinel_needs_the_prefix_and_the_suffix_and_room_for_both() {
        // All three conditions are load-bearing and each can be dropped
        // independently, so each gets a case that fails without it.
        assert!(looks_like_sentinel("=?base64??="));

        // Starts but does not end.
        assert!(!looks_like_sentinel("=?base64?abc"));
        // Ends but does not start.
        assert!(!looks_like_sentinel("notbase64?="));

        // Long enough to satisfy a *shortened* length bound while the prefix
        // and suffix OVERLAP. With the real bound this is not a sentinel; with
        // a shortened one the decoder would slice backwards and panic.
        assert!(!looks_like_sentinel("=?base64?="));
        assert_eq!(decode_header_value("=?base64?=").unwrap(), "=?base64?=");
    }

    #[test]
    fn each_declared_capability_is_read_independently() {
        let meta = |caps: Value| RequestMeta {
            protocol_version: MODERN_PROTOCOL_VERSION.to_string(),
            client_info: None,
            client_capabilities: caps,
            log_level: None,
        };

        // Declared → true; absent → false. Both directions, per capability:
        // a predicate stuck at either constant passes a one-sided test.
        let all = meta(json!({"sampling": {}, "elicitation": {}, "roots": {}}));
        assert!(all.supports_sampling());
        assert!(all.supports_elicitation());
        assert!(all.supports_roots());

        let none = meta(json!({}));
        assert!(!none.supports_sampling());
        assert!(!none.supports_elicitation());
        assert!(!none.supports_roots());

        // And they must not be read from each other: declaring one must not
        // imply another, which is what a shared or duplicated arm would do.
        let only_roots = meta(json!({"roots": {}}));
        assert!(only_roots.supports_roots());
        assert!(!only_roots.supports_sampling());
        assert!(!only_roots.supports_elicitation());
    }

    #[test]
    fn every_input_request_method_is_gated_by_its_own_capability() {
        let meta = |caps: Value| RequestMeta {
            protocol_version: MODERN_PROTOCOL_VERSION.to_string(),
            client_info: None,
            client_capabilities: caps,
            log_level: None,
        };
        // One case per arm, each proving the arm exists AND that it reads the
        // matching capability rather than a neighbour's.
        for (method, cap) in [
            ("elicitation/create", "elicitation"),
            ("sampling/createMessage", "sampling"),
            ("roots/list", "roots"),
        ] {
            let declared = meta(json!({ cap: {} }));
            assert!(
                declared.supports_input_request(method),
                "{method} must be permitted when {cap} is declared"
            );
            assert!(
                !meta(json!({})).supports_input_request(method),
                "{method} must be refused when nothing is declared"
            );
        }
    }

    #[test]
    fn the_client_label_is_built_from_what_the_client_reported() {
        let meta = |info: Option<Value>| RequestMeta {
            protocol_version: MODERN_PROTOCOL_VERSION.to_string(),
            client_info: info,
            client_capabilities: json!({}),
            log_level: None,
        };
        assert_eq!(
            meta(Some(json!({"name": "ExampleClient", "version": "1.0.0"}))).client_info_label(),
            Some("ExampleClient/1.0.0".to_string())
        );
        // A name without a version is still an identity worth recording.
        assert_eq!(
            meta(Some(json!({"name": "ExampleClient"}))).client_info_label(),
            Some("ExampleClient".to_string())
        );
        // No name is no identity — never a placeholder, which would put a
        // fabricated client name on an audit row.
        assert_eq!(meta(Some(json!({"version": "1.0.0"}))).client_info_label(), None);
        assert_eq!(meta(None).client_info_label(), None);
    }

    #[test]
    fn the_log_opt_in_is_exactly_the_presence_of_a_level() {
        let meta = |level: Option<&str>| RequestMeta {
            protocol_version: MODERN_PROTOCOL_VERSION.to_string(),
            client_info: None,
            client_capabilities: json!({}),
            log_level: level.map(str::to_string),
        };
        // Both directions: § Logging makes the absence of a level a MUST NOT,
        // so a predicate stuck at either constant breaks one half silently.
        assert!(meta(Some("info")).wants_log_notifications());
        assert!(meta(Some("debug")).wants_log_notifications());
        assert!(!meta(None).wants_log_notifications());
    }

    #[test]
    fn every_renumbered_code_is_named_and_the_rest_are_left_alone() {
        // One assertion per arm. Without them an arm can be deleted and the
        // code falls through to "no change", which is silent: the client just
        // receives a code from a band it is told to assign no meaning to.
        assert_eq!(
            modernize_error_code(super::super::jsonrpc::ROUTE_NOT_FOUND),
            Some(METHOD_NOT_FOUND)
        );
        assert_eq!(
            modernize_error_code(super::super::jsonrpc::UPSTREAM_ERROR),
            Some(super::super::jsonrpc::INTERNAL_ERROR)
        );
        assert_eq!(
            modernize_error_code(super::super::jsonrpc::TOOL_NOT_FOUND),
            Some(INVALID_PARAMS)
        );
        assert_eq!(modernize_error_code(LEGACY_RESOURCE_NOT_FOUND), Some(INVALID_PARAMS));
        // Anything else passes through untouched.
        assert_eq!(modernize_error_code(INVALID_PARAMS), None);
        assert_eq!(
            modernize_error_code(super::super::jsonrpc::INTERNAL_ERROR),
            None
        );
    }

    #[test]
    fn an_empty_subscription_is_empty_only_when_every_field_is() {
        // Each field independently makes the filter non-empty; an `&&` turned
        // into an `||` would report a live subscription as empty, which is the
        // signal an operator reads to spot a filter the client got wrong.
        assert!(SubscriptionFilter::default().is_empty());
        for f in [
            SubscriptionFilter { tools_list_changed: true, ..Default::default() },
            SubscriptionFilter { prompts_list_changed: true, ..Default::default() },
            SubscriptionFilter { resources_list_changed: true, ..Default::default() },
            SubscriptionFilter {
                resource_subscriptions: vec!["stsmcp://p/a".into()],
                ..Default::default()
            },
        ] {
            assert!(!f.is_empty(), "{f:?} is not an empty subscription");
        }
    }

    #[test]
    fn a_list_change_type_needs_the_request_and_the_upstream_together() {
        // Every other test happens to set both sides true, where `&&` and `||`
        // agree — so neither operator can be told from the other. These are the
        // two discriminating cases, for each of the three flags:
        //   requested but unsupported → must be dropped (or the client waits
        //     forever on a notification nothing can source);
        //   supported but not requested → must stay dropped (the server MUST
        //     NOT send a type the client did not ask for).
        let all_supported = json!({
            "tools": {"listChanged": true},
            "prompts": {"listChanged": true},
            "resources": {"listChanged": true},
        });
        let none_supported = json!({
            "tools": {"listChanged": false},
            "prompts": {"listChanged": false},
            "resources": {"listChanged": false},
        });

        let requested_all = SubscriptionFilter {
            tools_list_changed: true,
            prompts_list_changed: true,
            resources_list_changed: true,
            ..Default::default()
        };

        // Requested, unsupported → all dropped.
        let h = requested_all.honored(&none_supported);
        assert!(!h.tools_list_changed);
        assert!(!h.prompts_list_changed);
        assert!(!h.resources_list_changed);

        // Supported, not requested → all still dropped.
        let h = SubscriptionFilter::default().honored(&all_supported);
        assert!(!h.tools_list_changed);
        assert!(!h.prompts_list_changed);
        assert!(!h.resources_list_changed);

        // Both → honored. The positive control: without it the two negatives
        // above would pass with the narrowing hard-coded to drop everything.
        let h = requested_all.honored(&all_supported);
        assert!(h.tools_list_changed);
        assert!(h.prompts_list_changed);
        assert!(h.resources_list_changed);
    }

    #[test]
    fn resource_subscriptions_survive_only_when_asked_for_and_supported() {
        let requested = SubscriptionFilter {
            resource_subscriptions: vec!["stsmcp://p/a".into()],
            ..Default::default()
        };
        // Supported by an upstream → kept.
        let honored = requested.honored(&json!({"resources": {"subscribe": true}}));
        assert_eq!(honored.resource_subscriptions, vec!["stsmcp://p/a".to_string()]);
        // Not supported → dropped, so the acknowledgement cannot promise
        // updates that are never coming.
        assert!(
            requested
                .honored(&json!({"resources": {"subscribe": false}}))
                .resource_subscriptions
                .is_empty()
        );
        // Nothing requested stays nothing even where the upstream supports it.
        assert!(
            SubscriptionFilter::default()
                .honored(&json!({"resources": {"subscribe": true}}))
                .resource_subscriptions
                .is_empty()
        );
    }

    #[test]
    fn the_acknowledgement_names_resource_subscriptions_only_when_there_are_some() {
        let with = SubscriptionFilter {
            resource_subscriptions: vec!["stsmcp://p/a".into()],
            ..Default::default()
        };
        assert_eq!(with.to_json()["resourceSubscriptions"][0], "stsmcp://p/a");
        // An empty list is omitted rather than reported as `[]` — the
        // acknowledgement lists what was honored, and nothing was.
        assert!(
            SubscriptionFilter::default()
                .to_json()
                .get("resourceSubscriptions")
                .is_none()
        );
    }

    #[test]
    fn every_notification_type_is_accepted_only_by_its_own_opt_in() {
        // One case per arm. A deleted arm falls through to the catch-all
        // `false`, which reads as a quiet server rather than as a bug.
        for (method, filter) in [
            (
                "notifications/tools/list_changed",
                SubscriptionFilter { tools_list_changed: true, ..Default::default() },
            ),
            (
                "notifications/prompts/list_changed",
                SubscriptionFilter { prompts_list_changed: true, ..Default::default() },
            ),
            (
                "notifications/resources/list_changed",
                SubscriptionFilter { resources_list_changed: true, ..Default::default() },
            ),
        ] {
            assert!(filter.accepts(method, None), "{method} was opted in to");
            assert!(
                !SubscriptionFilter::default().accepts(method, None),
                "{method} was not opted in to"
            );
        }
    }

    #[test]
    fn input_responses_report_how_many_answers_arrived() {
        // Both are read on the retry leg — `is_empty` decides whether this is
        // a retry at all, `len` is what an operator sees when diagnosing a
        // double-executed upstream tool.
        let none = InputResponses::default();
        assert!(none.is_empty());
        assert_eq!(none.len(), 0);

        let one = InputResponses::parse(Some(&json!({"inputResponses": {"a": {}}})));
        assert!(!one.is_empty());
        assert_eq!(one.len(), 1);

        let two = InputResponses::parse(Some(&json!({"inputResponses": {"a": {}, "b": {}}})));
        assert!(!two.is_empty());
        assert_eq!(two.len(), 2);
    }

    // Small helper so the loop above reads as one assertion per method.
    trait UnwrapErrOrPanic<T> {
        fn unwrap_err_or_panic(self, msg: &str) -> ModernError;
    }
    impl<T> UnwrapErrOrPanic<T> for Result<T, ModernError> {
        fn unwrap_err_or_panic(self, msg: &str) -> ModernError {
            match self {
                Ok(_) => panic!("{msg}"),
                Err(e) => e,
            }
        }
    }
}

/// Properties over the `Mcp-Name` / `Mcp-Param-*` value codec.
///
/// The codec reads attacker-chosen bytes — a tool name, a resource URI, a
/// tool argument — and both halves of the header/body comparison that gates
/// the request pass through it. A canonicaliser that is wrong here is not a
/// wrong answer but a silent header/body divergence, and the input that
/// breaks it is never the one someone wrote a case for. So the module's
/// claims are stated as properties and `proptest` hunts the counterexample.
///
/// Two things are deliberately **not** claimed:
///
/// - **Not idempotent.** Decoding is single-pass by design: a decoded value
///   that happens to look like a sentinel is the caller's data, not another
///   layer. `decode(decode(x)) == decode(x)` is false, and asserting it would
///   be asserting a bug.
/// - **Not injective from the wire.** `abc` and `=?base64?YWJj?=` are two
///   legal wire spellings of one logical value; the transport permits both,
///   so no property may require the wire form to be recoverable.
#[cfg(test)]
mod properties {
    use super::*;
    use proptest::prelude::*;

    /// Every byte an HTTP field value may carry, per RFC 9110 § 5.5 and
    /// § Value Encoding: visible ASCII, space, horizontal tab.
    fn is_wire_legal(s: &str) -> bool {
        s.chars()
            .all(|c| c == '\t' || c == ' ' || ('\u{21}'..='\u{7e}').contains(&c))
    }

    /// Strings drawn from the WHOLE of Unicode, control characters included.
    ///
    /// A `".*"` regex strategy generates almost nothing the encoder has to
    /// act on — no newlines, no C0 controls, little above ASCII — so a
    /// round-trip property over it would exercise the pass-through branch and
    /// call that a proof. The inputs that matter here are exactly the ones a
    /// well-behaved generator avoids: a tab, a NUL, a lone surrogate-adjacent
    /// scalar, a leading space a proxy will strip.
    fn hostile_text() -> impl Strategy<Value = String> {
        proptest::collection::vec(any::<char>(), 0..24)
            .prop_map(|cs| cs.into_iter().collect::<String>())
    }

    /// Arbitrary MCP-shaped request params: an object of small values, with
    /// an optional `_meta` that may already carry the keys both directions
    /// act on.
    ///
    /// The generator deliberately emits the reserved `_meta` keys and the two
    /// MRTR fields, because those are the only inputs where the two
    /// directions can disagree — a generator of innocent objects would
    /// exercise the copy branch and call it a proof.
    fn request_params() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            any::<i32>().prop_map(|n| json!(n)),
            "[a-z ]{0,8}".prop_map(Value::String),
        ];
        let meta_key = prop_oneof![
            Just(META_PROTOCOL_VERSION.to_string()),
            Just(META_CLIENT_INFO.to_string()),
            Just(META_CLIENT_CAPABILITIES.to_string()),
            Just(META_LOG_LEVEL.to_string()),
            Just("progressToken".to_string()),
            Just("traceparent".to_string()),
            "[a-z]{1,6}".prop_map(|s| s),
        ];
        let top_key = prop_oneof![
            Just("name".to_string()),
            Just("uri".to_string()),
            Just("inputResponses".to_string()),
            Just("requestState".to_string()),
            "[a-z]{1,6}".prop_map(|s| s),
        ];
        (
            proptest::collection::hash_map(top_key, leaf.clone(), 0..5),
            proptest::option::of(proptest::collection::hash_map(meta_key, leaf, 0..5)),
        )
            .prop_map(|(top, meta)| {
                let mut obj = Map::new();
                for (k, v) in top {
                    obj.insert(k, v);
                }
                if let Some(m) = meta {
                    let mut mo = Map::new();
                    for (k, v) in m {
                        mo.insert(k, v);
                    }
                    obj.insert("_meta".to_string(), Value::Object(mo));
                }
                Value::Object(obj)
            })
    }

    /// What survives a round trip through both era conversions: everything
    /// except the fields each direction owns.
    fn residue_free(original: &Value) -> Value {
        let mut obj = original.as_object().cloned().unwrap_or_default();
        obj.remove("inputResponses");
        obj.remove("requestState");
        if let Some(Value::Object(meta)) = obj.get_mut("_meta") {
            for key in MODERN_REQUEST_META_KEYS {
                meta.remove(*key);
            }
            if meta.is_empty() {
                obj.remove("_meta");
            }
        }
        Value::Object(obj)
    }

    proptest! {
        /// The module's third invariant, stated as a claim that can fail:
        /// **nothing crosses the era boundary unconverted**.
        ///
        /// Upgrading a body for a modern upstream and downgrading it back
        /// must leave no trace of the envelope. If it did, the residue would
        /// be a newer revision's reserved `_meta` key sitting in a request
        /// sent to a server that negotiated an older one — which is the exact
        /// ambiguity the era split exists to remove, and it would be
        /// invisible: the upstream would ignore the key and answer normally.
        ///
        /// The claim it deliberately does NOT make is idempotence in the
        /// other order. `downgrade` is lossy by design — it drops the MRTR
        /// retry channel, which the gateway consumes and never forwards — so
        /// `upgrade(downgrade(p))` cannot equal `p` and asserting it would be
        /// asserting a bug.
        #[test]
        fn the_envelope_leaves_no_residue(p in request_params()) {
            let upgraded = upgrade_request_params(
                Some(&p),
                &json!({"elicitation": {}}),
                &json!({"name": "gw"}),
                Some("info"),
            );
            let back = downgrade_request_params(Some(&upgraded)).unwrap();
            prop_assert_eq!(back, residue_free(&p));
        }

        /// A body bound for a modern upstream always states the three things
        /// that era requires of it, whatever the client sent.
        #[test]
        fn the_envelope_is_always_complete(p in request_params()) {
            let upgraded = upgrade_request_params(
                Some(&p),
                &json!({"sampling": {}}),
                &json!({"name": "gw"}),
                None,
            );
            let meta = &upgraded["_meta"];
            prop_assert_eq!(&meta[META_PROTOCOL_VERSION], &json!(MODERN_PROTOCOL_VERSION));
            prop_assert_eq!(&meta[META_CLIENT_CAPABILITIES], &json!({"sampling": {}}));
            prop_assert_eq!(&meta[META_CLIENT_INFO], &json!({"name": "gw"}));
            // No opt-in was granted, so the key must be absent — not present
            // and empty, and not inherited from whatever the client sent.
            prop_assert!(meta.get(META_LOG_LEVEL).is_none());
        }

        /// The same claims as below, but over input that actually reaches the
        /// encoding branch. Kept separate rather than replacing the `.*` runs:
        /// ordinary text is the common case and must not regress either.
        #[test]
        fn hostile_text_survives_the_round_trip(s in hostile_text()) {
            let wire = encode_header_value(&s);
            prop_assert!(is_wire_legal(&wire), "not a legal field value: {:?}", wire);
            prop_assert!(!wire.contains('\r') && !wire.contains('\n'));
            prop_assert_eq!(wire.trim_matches([' ', '\t']), wire.as_str());
            prop_assert_eq!(decode_header_value(&wire).unwrap(), s);
        }

        /// The claim [`decode_header_value`] makes: a value this codec
        /// produced decodes back to the identical string. Nothing else in
        /// the module is allowed to be true if this is false — the header
        /// would agree with a body value the client never sent.
        #[test]
        fn a_value_survives_the_header_round_trip(s in ".*") {
            let wire = encode_header_value(&s);
            prop_assert_eq!(decode_header_value(&wire).unwrap(), s);
        }

        /// The encoder never emits bytes a header cannot carry. This is the
        /// security half: a CR or LF reaching the wire is header injection,
        /// and leading or trailing whitespace is silently stripped by
        /// intermediaries — which would turn a matching name into a
        /// mismatching one somewhere downstream of us.
        #[test]
        fn an_encoded_value_is_always_transmissible(s in ".*") {
            let wire = encode_header_value(&s);
            prop_assert!(is_wire_legal(&wire), "not a legal field value: {:?}", wire);
            prop_assert!(!wire.contains('\r') && !wire.contains('\n'));
            prop_assert_eq!(wire.trim_matches([' ', '\t']), wire.as_str());
        }

        /// Decoding arbitrary bytes off the wire either yields a value or a
        /// `HeaderMismatch` — never a panic, and never a code that would let
        /// the request through. The input here is unfiltered attacker text,
        /// including strings that imitate the sentinel.
        #[test]
        fn decoding_hostile_input_fails_closed(s in ".*") {
            match decode_header_value(&s) {
                Ok(v) => {
                    // A successful decode of a non-sentinel is the identity;
                    // anything else would mean the codec silently rewrote a
                    // value the body must match.
                    if !looks_like_sentinel(&s) {
                        prop_assert_eq!(v, s);
                    }
                }
                Err(e) => prop_assert_eq!(e.code, HEADER_MISMATCH),
            }
        }

        /// A value that merely *looks* like the sentinel is escaped rather
        /// than passed through. Without this the far side would peel a layer
        /// the client never applied and compare the wrong string.
        #[test]
        fn a_sentinel_shaped_value_is_never_passed_through_verbatim(
            inner in "[A-Za-z0-9+/=]*"
        ) {
            let raw = format!("{B64_SENTINEL_PREFIX}{inner}{B64_SENTINEL_SUFFIX}");
            let wire = encode_header_value(&raw);
            prop_assert_ne!(&wire, &raw);
            prop_assert_eq!(decode_header_value(&wire).unwrap(), raw);
        }

        /// Header validation is decided by the decoded value, not the wire
        /// spelling: whichever of the two legal encodings a client picks for
        /// the same name, the request is accepted identically.
        #[test]
        fn either_wire_spelling_of_a_name_validates_the_same(
            name in "[a-zA-Z0-9_]{1,32}"
        ) {
            let r = JsonRpcRequest {
                jsonrpc: "2.0".into(),
                id: Some(super::super::jsonrpc::RpcId::Number(1.into())),
                method: "tools/call".into(),
                params: Some(serde_json::json!({ "name": name })),
            };
            let forced = format!(
                "{B64_SENTINEL_PREFIX}{}{B64_SENTINEL_SUFFIX}",
                B64_STD.encode(name.as_bytes())
            );
            for spelling in [name.clone(), forced] {
                let mut h = HeaderMap::new();
                h.insert("mcp-method", axum::http::HeaderValue::from_static("tools/call"));
                h.insert(
                    "mcp-name",
                    axum::http::HeaderValue::from_str(&spelling).unwrap(),
                );
                prop_assert!(
                    validate_transport_headers(&h, &r).is_ok(),
                    "spelling {:?} of {:?} was rejected",
                    spelling,
                    name
                );
            }
        }

        /// A name that disagrees with the body is refused however it is
        /// spelled. The positive control above is what keeps this from
        /// passing with validation deleted.
        #[test]
        fn a_disagreeing_name_is_refused_in_either_spelling(
            body in "[a-z]{1,16}",
            header in "[A-Z]{1,16}",
        ) {
            let r = JsonRpcRequest {
                jsonrpc: "2.0".into(),
                id: Some(super::super::jsonrpc::RpcId::Number(1.into())),
                method: "tools/call".into(),
                params: Some(serde_json::json!({ "name": body })),
            };
            let forced = format!(
                "{B64_SENTINEL_PREFIX}{}{B64_SENTINEL_SUFFIX}",
                B64_STD.encode(header.as_bytes())
            );
            for spelling in [header.clone(), forced] {
                let mut h = HeaderMap::new();
                h.insert("mcp-method", axum::http::HeaderValue::from_static("tools/call"));
                h.insert(
                    "mcp-name",
                    axum::http::HeaderValue::from_str(&spelling).unwrap(),
                );
                let err = validate_transport_headers(&h, &r).unwrap_err();
                prop_assert_eq!(err.code, HEADER_MISMATCH);
            }
        }
    }
}

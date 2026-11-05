//! Shared building blocks for the control-plane audit middlewares.
//!
//! `admin_audit`, `portal_audit`, and `security_audit` all buffer the request
//! body, redact secret-shaped keys, derive a canonical action verb from the
//! matched route, and capture the failing response body. Those mechanics live
//! here so the three middlewares share one implementation instead of drifting
//! copies. The caller IP they stamp is resolved by
//! `crate::middleware::ip_rate_limit::client_ip` — the same resolution the
//! admin-api throttles key on, which counts the browser tier as a trusted hop
//! when it proves itself. Never call core `extract_client_ip` directly here.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::Request;
use axum::http::request::Parts;
use axum::http::Method;
use axum::response::Response;
use serde_json::Value;

use crate::db::tenant::{TenantConn, TenantId};
use crate::routes::{ApiError, ApiErrorCode};

/// Bound on the detached audit-row write shared by the admin / portal / security
/// middlewares — a backpressure guard so a stalled DB write can't hold the
/// response. Kept here so the three middlewares can't drift apart.
pub const AUDIT_WRITE_TIMEOUT: Duration = Duration::from_millis(500);

/// Handle for a handler to record a structured before/after change diff that
/// the audit middleware will persist to the row's `change_diff` column.
///
/// Extracted via `Extension<AuditDiffSink>` on handlers that pre-load the row
/// they're about to mutate (`update_user`, `update_tool_rule`, …). The
/// middleware injects an empty sink before the handler runs and reads it back
/// on the way out — handlers that don't stamp anything leave the column NULL.
///
/// `request_body` captures the operator's INTENT (the redacted JSON they sent).
/// `change_diff` captures the EFFECT (what the row looked like before vs after
/// the handler). Both fields are useful side-by-side for "did this PATCH
/// actually change anything?".
///
/// A handler that answered a preview (`?dry_run=true`) and changed nothing
/// says so with [`AuditDiffSink::mark_dry_run`]: the row is then recorded
/// under its own action (`<action>_dry_run`), never as the mutation it
/// previewed. Only the handler can say it — a query string the route does not
/// read would otherwise label a real deletion a preview.
#[derive(Clone, Default)]
pub struct AuditDiffSink(Arc<Mutex<SinkState>>);

#[derive(Default)]
struct SinkState {
    diff: Option<Value>,
    dry_run: bool,
}

impl AuditDiffSink {
    /// Stamp a `{before, after}` change diff onto this request's audit row.
    /// Both fields are arbitrary JSON — typically serialized struct
    /// representations of the row before and after the mutation. Calling
    /// `set` twice replaces the previous value.
    pub fn set(&self, before: Value, after: Value) {
        let diff = serde_json::json!({ "before": before, "after": after });
        if let Ok(mut guard) = self.0.lock() {
            guard.diff = Some(diff);
        }
    }

    /// This request was a preview: the handler changed nothing.
    pub fn mark_dry_run(&self) {
        if let Ok(mut guard) = self.0.lock() {
            guard.dry_run = true;
        }
    }

    pub(crate) fn is_dry_run(&self) -> bool {
        self.0.lock().is_ok_and(|g| g.dry_run)
    }

    /// Record a structured diff from typed values. `None` serializes to JSON
    /// null (create → `before` is None; delete → `after` is None). A no-op when
    /// the two sides are equal, so a PATCH that changed nothing leaves the
    /// column NULL. Use this for the handlers the generic middleware capture
    /// can't express (settings stored as a `system_settings` JSON blob, bulk /
    /// sync summaries, composite-keyed sub-resources). Secret-shaped fields are
    /// scrubbed centrally by the middleware on the way out, so pass the natural
    /// struct — no hand-picked safe projection needed.
    pub fn record<B: serde::Serialize, A: serde::Serialize>(
        &self,
        before: Option<&B>,
        after: Option<&A>,
    ) {
        let b = before
            .map(|v| serde_json::to_value(v).unwrap_or(Value::Null))
            .unwrap_or(Value::Null);
        let a = after
            .map(|v| serde_json::to_value(v).unwrap_or(Value::Null))
            .unwrap_or(Value::Null);
        if b != a {
            self.set(b, a);
        }
    }

    pub(crate) fn take(&self) -> Option<Value> {
        self.0.lock().ok().and_then(|mut g| g.diff.take())
    }
}

#[derive(serde::Deserialize)]
struct DryRunParam {
    dry_run: Option<bool>,
}

/// A destructive endpoint's `?dry_run=true`, read once. A preview marks the
/// request's audit sink, so its row is recorded as the preview and never as
/// the mutation ([`AuditDiffSink::mark_dry_run`]): a handler
/// cannot read the flag without marking it. A handler taking it MUST change
/// nothing when it is true.
pub struct DryRun(pub bool);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for DryRun {
    type Rejection = axum::extract::rejection::QueryRejection;

    async fn from_request_parts(parts: &mut axum::http::request::Parts, state: &S) -> Result<Self, Self::Rejection> {
        let axum::extract::Query(q) = axum::extract::Query::<DryRunParam>::from_request_parts(parts, state).await?;
        let dry_run = q.dry_run.unwrap_or(false);
        if dry_run && let Some(sink) = parts.extensions.get::<AuditDiffSink>() {
            sink.mark_dry_run();
        }
        Ok(DryRun(dry_run))
    }
}

/// The action a request is recorded under: a preview the handler confirmed is
/// its own action, so an auditor never reads it as the mutation itself.
pub(crate) fn recorded_action(action: String, sink: &AuditDiffSink) -> String {
    if sink.is_dry_run() { format!("{action}_dry_run") } else { action }
}

/// Handle for a portal handler to record the **member it acted on behalf of**
/// (`portal_audit.target_user_id`). A self-service mutation leaves this NULL; a
/// workspace-manager mint/revoke-for-member stamps the target member's id.
///
/// Same seam as [`AuditDiffSink`]: `portal_audit_mw` injects an empty target
/// before the handler runs and reads it back on the way out.
#[derive(Clone, Default)]
pub struct PortalAuditTarget(Arc<Mutex<Option<uuid::Uuid>>>);

impl PortalAuditTarget {
    /// Stamp the target member this request acted on behalf of.
    pub fn set(&self, target_user_id: uuid::Uuid) {
        if let Ok(mut guard) = self.0.lock() {
            *guard = Some(target_user_id);
        }
    }

    pub(crate) fn take(&self) -> Option<uuid::Uuid> {
        self.0.lock().ok().and_then(|mut g| g.take())
    }
}

/// The most a signed-in console or portal request body may carry. It is the
/// limit the handlers read under too — the router sets it as the extractors'
/// `DefaultBodyLimit` — so the audit layer, which reads the body first, refuses
/// exactly what the handler would and hands on everything the handler accepts.
pub(crate) const CONSOLE_BODY_LIMIT: usize = 2 * 1024 * 1024;

/// The most a pre-authentication request body may carry (sign-in, setup, an
/// invite's acceptance, the OAuth endpoints): far above any such body, and small
/// enough that an anonymous caller cannot make the audit layer hold much.
pub(crate) const PRE_AUTH_BODY_LIMIT: usize = 64 * 1024;

/// The largest body the audit layers parse into the persisted `request_body`;
/// a larger one is recorded by its size alone, so a big body is never turned
/// into a JSON tree only to be truncated.
pub(crate) const MAX_PARSED_BODY_BYTES: usize = 64 * 1024;

// A pre-auth body is always parsed whole: the security row reads its attempted
// identity from the persisted body.
const _: () = assert!(PRE_AUTH_BODY_LIMIT <= MAX_PARSED_BODY_BYTES);

/// The largest `change_diff` a row keeps; a larger one is recorded by its size.
/// A console body may be up to [`CONSOLE_BODY_LIMIT`], and a diff holds the
/// changed row twice (before and after).
pub(crate) const MAX_PERSISTED_DIFF_BYTES: usize = 256 * 1024;

/// The top-level request-body fields an audit row reads its identity from: the
/// attempted login, the OAuth client, the tenant (`security_audit`) and the
/// workspace (`portal_audit`). A body recorded by its size alone still carries
/// them, so padding a request never strips its row's identity.
const IDENTITY_FIELDS: &[&str] = &["email", "client_id", "username", "tenant_slug", "workspace_id"];

/// The longest identity value a truncation marker keeps; a longer one is left
/// out, so the marker stays a small record whatever the body holds.
const MAX_IDENTITY_VALUE_BYTES: usize = 256;

/// The record of a body too large to keep: `_bytes`, the size of the body as
/// received, and the [`IDENTITY_FIELDS`] it carried as strings.
fn truncation_marker(received: usize, identity: serde_json::Map<String, Value>) -> Value {
    let mut marker = identity;
    marker.insert("_truncated".into(), Value::Bool(true));
    marker.insert("_bytes".into(), Value::from(received));
    Value::Object(marker)
}

/// One identity field as a marker keeps it: a string, no longer than
/// [`MAX_IDENTITY_VALUE_BYTES`].
fn identity_value(v: &Value) -> Option<Value> {
    identity_str(v.as_str()?)
}

/// [`identity_value`] for a string read straight from the body.
fn identity_str(s: &str) -> Option<Value> {
    (s.len() <= MAX_IDENTITY_VALUE_BYTES).then(|| Value::String(s.to_string()))
}

/// The [`IDENTITY_FIELDS`] a (redacted) parsed body carries.
fn identity_of(value: &Value) -> serde_json::Map<String, Value> {
    IDENTITY_FIELDS
        .iter()
        .filter_map(|k| Some((k.to_string(), identity_value(value.get(*k)?)?)))
        .collect()
}

/// The [`IDENTITY_FIELDS`] of a body too large to parse into a tree. A JSON
/// object is walked once: an identity field's value is read, every other value
/// skipped unbuilt; a field of another type, or repeated, costs that field
/// alone (the last string wins). A form is scanned for them.
fn identity_of_unparsed(bytes: &[u8], is_form: bool) -> serde_json::Map<String, Value> {
    if is_form {
        let mut found = serde_json::Map::new();
        for (k, v) in url::form_urlencoded::parse(bytes) {
            if IDENTITY_FIELDS.contains(&k.as_ref()) {
                // The last occurrence decides, as in a JSON body.
                match identity_str(&v) {
                    Some(v) => found.insert(k.into_owned(), v),
                    None => found.remove(k.as_ref()),
                };
            }
        }
        return found;
    }

    /// An identity field's value: a string, or `None` for any other value,
    /// which is skipped without being built.
    struct IdentityString(Option<String>);
    impl<'de> serde::Deserialize<'de> for IdentityString {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> serde::de::Visitor<'de> for V {
                type Value = IdentityString;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("any JSON value")
                }
                fn visit_str<E>(self, v: &str) -> Result<IdentityString, E> {
                    Ok(IdentityString(Some(v.to_string())))
                }
                fn visit_bool<E>(self, _: bool) -> Result<IdentityString, E> {
                    Ok(IdentityString(None))
                }
                fn visit_i64<E>(self, _: i64) -> Result<IdentityString, E> {
                    Ok(IdentityString(None))
                }
                fn visit_u64<E>(self, _: u64) -> Result<IdentityString, E> {
                    Ok(IdentityString(None))
                }
                fn visit_f64<E>(self, _: f64) -> Result<IdentityString, E> {
                    Ok(IdentityString(None))
                }
                fn visit_unit<E>(self) -> Result<IdentityString, E> {
                    Ok(IdentityString(None))
                }
                fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<IdentityString, A::Error> {
                    while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
                    Ok(IdentityString(None))
                }
                fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<IdentityString, A::Error> {
                    while map.next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?.is_some() {}
                    Ok(IdentityString(None))
                }
            }
            d.deserialize_any(V)
        }
    }

    /// Writes what it finds as it goes, so a body that breaks later keeps the
    /// fields read before the break.
    struct IdentityVisitor<'a>(&'a mut serde_json::Map<String, Value>);
    impl<'de> serde::de::Visitor<'de> for IdentityVisitor<'_> {
        type Value = ();
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a JSON object")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
            while let Some(key) = map.next_key::<std::borrow::Cow<'de, str>>()? {
                if IDENTITY_FIELDS.contains(&key.as_ref()) {
                    // Any JSON value: a non-string is skipped like a long one.
                    // The last occurrence decides, as a parsed body's would.
                    let IdentityString(v) = map.next_value()?;
                    match v.as_deref().and_then(identity_str) {
                        Some(v) => self.0.insert(key.into_owned(), v),
                        None => self.0.remove(key.as_ref()),
                    };
                } else {
                    map.next_value::<serde::de::IgnoredAny>()?;
                }
            }
            Ok(())
        }
    }
    let mut found = serde_json::Map::new();
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let _ = serde::Deserializer::deserialize_map(&mut de, IdentityVisitor(&mut found));
    found
}

/// `change_diff` as a row keeps it: whole, or by its size past
/// [`MAX_PERSISTED_DIFF_BYTES`].
pub(crate) fn capped_change_diff(diff: &Value) -> std::borrow::Cow<'_, Value> {
    let len = serialized_len(diff);
    if len > MAX_PERSISTED_DIFF_BYTES {
        std::borrow::Cow::Owned(serde_json::json!({ "_truncated": true, "_bytes": len }))
    } else {
        std::borrow::Cow::Borrowed(diff)
    }
}

/// A value's serialized length, counted without building the bytes.
fn serialized_len(v: &Value) -> usize {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 += buf.len();
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    let _ = serde_json::to_writer(&mut count, v);
    count.0
}

/// Hard cap on the redacted JSON we'll persist. Anything larger is replaced
/// with a truncation marker so the table can't be inflated by a pathological
/// request body.
pub(crate) const MAX_PERSISTED_BODY_BYTES: usize = 32 * 1024;

/// The most of a response the audit layers read — a failing call's error body,
/// a create's new id. A larger response is not read for either, and still
/// reaches the client whole. The *persisted* copy is separately capped +
/// redacted in `parse_error_body`.
pub(crate) const MAX_ERROR_BODY_BYTES: usize = 256 * 1024;

/// Keys whose values should be redacted in `request_body`. Case-insensitive
/// exact match on the key name (not substring): the secret-shaped
/// `system_settings` keys plus the obvious secret-shaped field names that
/// flow through write paths.
const REDACT_KEYS: &[&str] = &[
    // Secret-shaped `system_settings` keys — keep in step with the secret
    // keys of `config_admin_only_setting` (migration 020)
    "agent_api_key",
    "inline_ai_api_key",
    "encryption_key",
    "internal_service_secret",
    "auth_secret",
    // Auth/password fields
    "password",
    "current_password",
    "new_password",
    // Generic secret-shaped names
    "token",
    "secret",
    "api_key",
    "credential",
    "encrypted_credential",
    "key_hash",
    "real_api_key",
    "client_secret",
    // OAuth / OIDC flow material. Each is a bearer of some kind for the length
    // of a login: a PKCE verifier completes the exchange it belongs to, and the
    // sealed flow token carries the nonce and verifier of a login in progress.
    // (The authorization `code` is request-only — see `REQUEST_ONLY_REDACT_KEYS`.)
    "code_verifier",
    "flow_token",
    "refresh_token",
    "device_code",
    // Backup rclone config (rclone.conf text incl. cloud-storage credentials):
    // no appliance body accepts one, and a request carrying one is refused, but
    // the audit row records the inbound body, so it stays masked there.
    "rclone_config",
    "rclone_config_b64",
];

/// Keys that hold a secret in a **request** body and something useful anywhere
/// else, so they are redacted by scope rather than by name.
///
/// `code` is the OAuth authorization code on the way in — a bearer that redeems
/// for tokens. It is also the name of the machine-readable field in every
/// `ApiErrorResponse`, so redacting it globally would erase the error code from
/// every audited failure across all three planes and leave an operator unable to
/// tell one refusal from another. Applied at the top level only, which is where
/// OAuth parameters live.
const REQUEST_ONLY_REDACT_KEYS: &[&str] = &["code"];

/// True when a *path parameter name* holds a secret. Broader than
/// [`is_redact_key`] by exactly [`REQUEST_ONLY_REDACT_KEYS`]: `code` is scoped
/// out of body redaction because it doubles as the `ApiErrorResponse` field
/// name, but a URL has no error bodies in it — a `{code}` segment can only be
/// the OAuth authorization code, which is a bearer.
pub(crate) fn is_redact_path_param(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    is_redact_key(name) || REQUEST_ONLY_REDACT_KEYS.iter().any(|r| lower == *r)
}

/// True when a JSON key holds a secret and must be redacted. Beyond the exact
/// `REDACT_KEYS` names (matched on request/response bodies), this also covers the
/// raw DB column names surfaced by `change_diff`'s `to_jsonb(row)` snapshots:
/// every `encrypted_*` ciphertext blob, every `*_hash`, and any column whose name
/// carries `secret`, `credential`, or `nonce`. These pattern rules can't false-
/// positive on a useful field (no legitimate config field is named that way),
/// while a bare-`token` substring deliberately is NOT a pattern (it would eat
/// `tokens_per_minute` and the audit usage counters).
fn is_redact_key(k: &str) -> bool {
    let lower = k.to_ascii_lowercase();
    REDACT_KEYS.iter().any(|r| lower == *r)
        // `id_token` and the `id_token_hint` a logout carries are both complete
        // signed identity assertions — email, subject, name, groups.
        || lower.starts_with("id_token")
        || lower.starts_with("encrypted_")
        || lower.ends_with("_hash")
        || lower.contains("secret")
        || lower.contains("credential")
        || lower.contains("nonce")
}

pub(crate) fn is_mutating(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

/// Parse + redact the inbound request body into the JSON we persist. Returns
/// None for an empty or non-JSON body; a truncation marker when the redacted
/// JSON exceeds the persist cap.
pub(crate) fn parse_and_redact(bytes: &Bytes) -> Option<Value> {
    if bytes.is_empty() {
        return None;
    }
    let mut value: Value = serde_json::from_slice(bytes).ok()?;
    if let Value::Object(map) = &mut value {
        for (k, val) in map.iter_mut() {
            if REQUEST_ONLY_REDACT_KEYS
                .iter()
                .any(|r| k.eq_ignore_ascii_case(r))
            {
                *val = Value::String("[REDACTED]".into());
            }
        }
    }
    redact_in_place(&mut value);
    if serialized_len(&value) > MAX_PERSISTED_BODY_BYTES {
        return Some(truncation_marker(bytes.len(), identity_of(&value)));
    }
    Some(value)
}

/// Parse a failing response body into the JSON we store in `response_error`.
/// Prefers the typed `{code, message}` shape; falls back to a `{raw}` wrapper
/// for non-JSON bodies so the reason is never silently dropped. Secret-shaped
/// keys are redacted and the persisted value is size-capped, exactly like
/// `request_body`. Returns None for an empty body.
pub(crate) fn parse_error_body(bytes: &Bytes) -> Option<Value> {
    if bytes.is_empty() {
        return None;
    }
    let mut value = match serde_json::from_slice::<Value>(bytes) {
        Ok(v) => v,
        Err(_) => {
            let text = String::from_utf8_lossy(bytes);
            let end = text.floor_char_boundary(2048);
            return Some(serde_json::json!({ "raw": &text[..end] }));
        }
    };
    redact_in_place(&mut value);
    if serialized_len(&value) > MAX_PERSISTED_BODY_BYTES {
        return Some(truncation_marker(bytes.len(), serde_json::Map::new()));
    }
    Some(value)
}

pub(crate) fn redact_in_place(v: &mut Value) {
    match v {
        Value::Object(map) => {
            for (k, val) in map.iter_mut() {
                if is_redact_key(k) {
                    *val = Value::String("[REDACTED]".into());
                } else {
                    redact_in_place(val);
                }
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                redact_in_place(item);
            }
        }
        _ => {}
    }
}

/// Pull a string value for any of `keys` out of a parsed (already-redacted)
/// body, scanning top-level fields only. Used to extract best-effort
/// attributes the middleware records without handler changes: the attempted
/// login email, an OAuth `client_id`, the request's `workspace_id`.
pub(crate) fn first_string_field<'a>(body: Option<&'a Value>, keys: &[&str]) -> Option<&'a str> {
    let obj = body?.as_object()?;
    keys.iter().find_map(|k| obj.get(*k).and_then(|v| v.as_str()))
}

/// Lift the workspace id from a `/workspaces/{param}/...` control-plane path —
/// the raw segment following the literal `workspaces` template segment. Used to
/// scope audit rows whose mutation carries the workspace in the path rather than
/// the body (e.g. the portal manager's mint/revoke-for-member routes). The
/// template and raw path share the same mount prefix, so their segments align.
pub(crate) fn workspace_id_from_path(
    route_template: Option<&str>,
    raw_path: &str,
) -> Option<uuid::Uuid> {
    let template = route_template?;
    let t_segs: Vec<&str> = template.trim_matches('/').split('/').collect();
    let r_segs: Vec<&str> = raw_path.trim_matches('/').split('/').collect();
    let idx = t_segs.iter().position(|s| *s == "workspaces")?;
    uuid::Uuid::parse_str(r_segs.get(idx + 1)?).ok()
}

/// Curated overrides for routes whose generic derivation produces an awkward
/// verb. Each entry is `(METHOD, matched_template, action)`. The `resource_kind`
/// is taken from the first segment of `action` (split on `.`). Keep this list
/// short — only routes where the generic `<resource>.<verb>[_<sub>]` shape
/// misleads operators reading the log.
///
/// `matched_template` is the *nested* template axum reports (without the mount
/// prefix that gets stripped by `nest()`). **Split per plane on purpose:** the
/// admin and portal planes BOTH expose `/keys` + `/keys/{id}/actions/revoke`,
/// which strip to identical templates — a single shared table would let a
/// portal override relabel an admin row (and vice-versa). Each middleware
/// passes only its own plane's table to `derive_action`.
pub(crate) const ADMIN_ACTION_OVERRIDES: &[(Method, &str, &str)] = &[
    // /maintenance/{verb} — the verb already IS the action; don't prefix with `create_`.
    (Method::POST, "/maintenance/purge-audit", "maintenance.purge_audit"),
    (Method::POST, "/maintenance/wipe-sessions", "maintenance.wipe_sessions"),
    (Method::POST, "/maintenance/flush-response-cache", "maintenance.flush_response_cache"),
    // Workspace membership — "add_member" / "remove_member" reads better than
    // "create_members" / "delete_members".
    (Method::POST, "/workspaces/{id}/members", "workspaces.add_member"),
    (Method::DELETE, "/workspaces/{id}/members/{user_id}", "workspaces.remove_member"),
    // Workspace allowlist grants — "grant" / "revoke" matches the existing
    // portal / CLI vocabulary; "create" / "delete" obscures the intent.
    (Method::POST, "/workspaces/{id}/providers", "workspaces.grant_provider"),
    (Method::DELETE, "/workspaces/{id}/providers/{provider_id}", "workspaces.revoke_provider"),
    (Method::POST, "/workspaces/{id}/mcp-servers", "workspaces.grant_mcp_access"),
    (Method::DELETE, "/workspaces/{id}/mcp-servers/{server_id}", "workspaces.revoke_mcp_access"),
    (Method::POST, "/workspaces/{id}/a2a-agents", "workspaces.grant_a2a_access"),
    (Method::DELETE, "/workspaces/{id}/a2a-agents/{agent_id}", "workspaces.revoke_a2a_access"),
    // Server batch model ops.
    (Method::POST, "/servers/{id}/models", "servers.add_models"),
    (Method::DELETE, "/servers/{id}/models", "servers.delete_models_batch"),
    // Downstream routes batch create — the resource is `downstream_routes`,
    // not `downstream_providers`; the generic derivation can't see that.
    (Method::POST, "/downstream-providers/{id}/routes", "downstream_routes.create"),
    (Method::POST, "/downstream-providers/{id}/routes/actions/batch-create", "downstream_routes.batch_create"),
    (Method::POST, "/downstream-providers/{id}/routes/{route_id}/actions/flush-cache", "downstream_routes.flush_cache"),
    (Method::PATCH, "/downstream-providers/{id}/routes/{route_id}", "downstream_routes.update"),
    (Method::DELETE, "/downstream-providers/{id}/routes/{route_id}", "downstream_routes.delete"),
    // MCP per-user connection deletion — the resource is the connection.
    (Method::DELETE, "/mcp/upstreams/{id}/connections/{user_id}", "mcp_connections.delete"),
    // A2A CRUD — same singular-noun curation as the MCP entries below.
    (Method::POST, "/a2a/agents", "a2a.create_agent"),
    (Method::PATCH, "/a2a/agents/{id}", "a2a.update_agent"),
    (Method::DELETE, "/a2a/agents/{id}", "a2a.delete_agent"),
    (Method::POST, "/a2a/agents/{id}/actions/refresh-card", "a2a.refresh_agent_card"),
    // MCP CRUD — the generic fallthrough produces `mcp.update_upstream_servers`
    // (note the trailing `s`); curate the verb to the singular noun so the log
    // reads "who updated which upstream server" cleanly.
    (Method::POST, "/mcp/upstream-servers", "mcp.create_upstream_server"),
    // OAuth-endpoint discovery probe — names the action explicitly (the generic
    // derivation would read it as a create on the collection).
    (Method::POST, "/mcp/upstream-servers/actions/discover-oauth", "mcp.discover_upstream_oauth"),
    (Method::PATCH, "/mcp/upstream-servers/{id}", "mcp.update_upstream_server"),
    (Method::DELETE, "/mcp/upstream-servers/{id}", "mcp.delete_upstream_server"),
    (Method::POST, "/mcp/virtual-servers", "mcp.create_virtual_server"),
    (Method::PATCH, "/mcp/virtual-servers/{id}", "mcp.update_virtual_server"),
    (Method::DELETE, "/mcp/virtual-servers/{id}", "mcp.delete_virtual_server"),
    (Method::POST, "/mcp/virtual-routes", "mcp.create_virtual_route"),
    (Method::PATCH, "/mcp/virtual-routes/{id}", "mcp.update_virtual_route"),
    (Method::DELETE, "/mcp/virtual-routes/{id}", "mcp.delete_virtual_route"),
    (Method::POST, "/mcp/oauth-clients", "mcp.create_oauth_client"),
    (Method::PATCH, "/mcp/oauth-clients/{id}", "mcp.update_oauth_client"),
    (Method::DELETE, "/mcp/oauth-clients/{id}", "mcp.delete_oauth_client"),
    // The `/actions/revoke` suffix produces a generic `mcp.revoke`; promote
    // "token" into the verb so the action names the subject explicitly.
    (Method::POST, "/mcp/issued-tokens/{jti}/actions/revoke", "mcp.revoke_token"),
    // Same reason as above — name the subject, which here is the machine rather
    // than any one of the tokens its login chain holds.
    (Method::POST, "/cli/sessions/{id}/actions/revoke", "cli.revoke_session"),
    // Suggestion reviews — the generic `transforms.approve` / `experts.approve`
    // would not say which kind of suggestion was reviewed.
    (Method::POST, "/transforms/suggestions/{id}/actions/approve", "transforms.approve_suggestion"),
    (Method::POST, "/transforms/suggestions/{id}/actions/reject", "transforms.reject_suggestion"),
    (Method::POST, "/experts/tool-rule-suggestions/{id}/actions/approve", "experts.approve_tool_rule_suggestion"),
    (Method::POST, "/experts/tool-rule-suggestions/{id}/actions/reject", "experts.reject_tool_rule_suggestion"),
    (Method::POST, "/experts/field-profile-suggestions/{id}/actions/approve", "experts.approve_field_profile_suggestion"),
    (Method::POST, "/experts/field-profile-suggestions/{id}/actions/reject", "experts.reject_field_profile_suggestion"),
    // Changelog dismiss is a viewer state action, not a creation.
    (Method::POST, "/changelog/actions/dismiss", "changelog.dismiss"),
];

/// Overrides for the portal plane (`portal_audit_mw`) and the pre-auth/public
/// security plane (`security_audit_mw`). Combined because the two planes are
/// mounted on disjoint routers (portal self-service vs. login/invite/oauth) so
/// no entry here collides with another in-plane route — but kept SEPARATE from
/// `ADMIN_ACTION_OVERRIDES` so a portal `/keys` override never touches an admin
/// `/keys` row.
pub(crate) const CONTROL_PLANE_ACTION_OVERRIDES: &[(Method, &str, &str)] = &[
    // --- Portal plane (mounted under /api/v1/portal) ---
    (Method::POST, "/keys/{id}/actions/revoke", "portal_key.revoke"),
    (Method::POST, "/keys", "portal_key.create"),
    (Method::POST, "/mcp/connections/{upstream_id}/actions/connect", "portal_mcp.connect"),
    (Method::POST, "/mcp/connections/{upstream_id}/actions/revoke", "portal_mcp.revoke_connection"),
    (Method::POST, "/mcp/virtual-servers/{virtual_server_id}/actions/test", "portal_mcp.test"),
    // Workspace automation accounts + portal `ak-` keys (manager self-serve).
    (Method::POST, "/workspaces/{id}/automation-accounts", "portal_automation.create_account"),
    (Method::POST, "/workspaces/{id}/automation-accounts/{said}/keys", "portal_automation.mint_key"),
    (Method::POST, "/workspaces/{id}/automation-accounts/{said}/keys/{key_id}/actions/revoke", "portal_automation.revoke_key"),
    (Method::POST, "/workspaces/{id}/automation-accounts/{said}/actions/revoke", "portal_automation.revoke_account"),
    // --- Pre-auth / public security surfaces ---
    (Method::POST, "/login", "auth.login"),
    (Method::POST, "/setup", "auth.setup"),
    (Method::POST, "/oidc-exchange", "auth.oidc_exchange"),
    (Method::POST, "/auth/login", "portal_auth.login"),
    (Method::GET, "/mcp/connections/oauth/callback", "portal_mcp.oauth_callback"),
    (Method::POST, "/{token}/accept", "invite.accept"),
    (Method::POST, "/{tenant_slug}/authorize/approve", "mcp_oauth.authorize_approve"),
    (Method::POST, "/{tenant_slug}/token", "mcp_oauth.token"),
    (Method::POST, "/{tenant_slug}/register", "mcp_oauth.register_client"),
];

/// Map `(method, MatchedPath, raw_path)` to a canonical `(action,
/// resource_kind, resource_id)`. Every mutating control-plane route should
/// resolve to a row; the fallthrough handles routes not explicitly listed.
/// `prefixes` are the mount prefixes to strip from the path before deriving the
/// resource kind (e.g. `/api/v1/admin`, `/api/v1/portal`). `overrides` is the
/// caller plane's curated table — pass `ADMIN_ACTION_OVERRIDES` or
/// `CONTROL_PLANE_ACTION_OVERRIDES`, never a shared union (see their docs).
pub(crate) fn derive_action(
    method: &Method,
    matched: Option<&str>,
    raw_path: &str,
    prefixes: &[&str],
    overrides: &[(Method, &str, &str)],
) -> (String, String, Option<String>) {
    let verb = match *method {
        Method::POST => "create",
        Method::PATCH | Method::PUT => "update",
        Method::DELETE => "delete",
        _ => "call",
    };

    let strip_prefixes = |s: &str| -> String {
        let mut out = s;
        for p in prefixes {
            out = out.trim_start_matches(p);
        }
        out.trim_start_matches('/').to_string()
    };

    let template = matched.unwrap_or(raw_path);
    let trimmed = strip_prefixes(template);
    let raw_trimmed = strip_prefixes(raw_path);

    let template_segments: Vec<&str> = trimmed.split('/').collect();
    let raw_segments: Vec<&str> = raw_trimmed.split('/').collect();
    let resource_id = template_segments
        .iter()
        .enumerate()
        .rev()
        .find_map(|(i, seg)| {
            if seg.starts_with('{') && seg.ends_with('}') {
                raw_segments.get(i).map(|s| (*s).to_string())
            } else {
                None
            }
        });

    // Curated override — produces a hand-picked action verb for routes whose
    // generic derivation reads awkwardly. Match on the nested template.
    let normalized_template = format!("/{trimmed}");
    if let Some((_, _, action)) = overrides
        .iter()
        .find(|(m, t, _)| m == method && *t == normalized_template.as_str())
    {
        let resource_kind = action.split('.').next().unwrap_or("admin").to_string();
        return (action.to_string(), resource_kind, resource_id);
    }

    let resource_kind = template_segments
        .first()
        .copied()
        .filter(|s| !s.is_empty())
        .unwrap_or("admin")
        .replace('-', "_");

    // Known special-case actions — e.g. `/keys/{id}/actions/revoke`.
    if let Some(action_verb) = extract_action_verb(&template_segments) {
        let action = format!("{resource_kind}.{action_verb}");
        return (action, resource_kind, resource_id);
    }

    // Sub-resource mutation: e.g. POST /groups/{id}/members → group.create_members.
    let top_segment = template_segments.first().copied().unwrap_or("");
    let sub_verb = template_segments
        .iter()
        .skip(1)
        .rev()
        .find(|s| !s.starts_with('{') && !s.is_empty() && **s != top_segment)
        .copied()
        .unwrap_or("");
    let action = if !sub_verb.is_empty() {
        format!("{resource_kind}.{verb}_{}", sub_verb.replace('-', "_"))
    } else {
        format!("{resource_kind}.{verb}")
    };

    (action, resource_kind, resource_id)
}

/// Recognise `.../actions/{verb}` suffix. Returns the verb segment.
fn extract_action_verb(segments: &[&str]) -> Option<String> {
    let n = segments.len();
    if n >= 2 && segments[n - 2] == "actions" {
        return Some(segments[n - 1].replace('-', "_"));
    }
    None
}

/// What kind of mutation the route represents, which decides how the generic
/// `change_diff` is built (see [`resolve_diff_target`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum DiffKind {
    /// Collection `POST` — `before` is null, `after` is the freshly-created row
    /// (located by the `id` the handler returns in its response body).
    Create,
    /// `PUT`/`PATCH` on `/{id}` — snapshot the row before and after the handler.
    Update,
    /// `DELETE` on `/{id}` — snapshot the row before; `after` is null.
    Delete,
    /// `POST /{id}/actions/{verb}` that mutates one existing row (revoke, reset
    /// of a single resource) — like [`Update`](DiffKind::Update): before + after.
    Action,
}

/// A registered single-table resource the audit middleware can snapshot
/// generically. `table`/`id_col` are compile-time constants from the registry
/// (never request data), so they're safe to interpolate into the snapshot SQL.
pub(crate) struct ResolvedDiff {
    pub table: &'static str,
    pub id_col: &'static str,
    /// The row key lifted from the path (`{id}`/`{slug}`). `None` for a
    /// collection create (the key comes from the response body instead).
    pub resource_id: Option<String>,
    pub kind: DiffKind,
}

/// Map a normalised resource "base" to the backing table + key column. The base
/// is the item template with every `{param}` segment collapsed to `{}` (so it's
/// agnostic to the route's param *names*) and any trailing `/actions/{verb}` and
/// trailing `/{}` removed. One line per resource — adding a new single-table CRUD
/// resource needs only an entry here, never a handler edit. Resources NOT listed
/// (settings stored in `system_settings`, bulk/sync ops, composite-keyed
/// sub-resources) populate their own diff via [`AuditDiffSink::record`]/`set` and
/// take precedence.
fn diff_target_table(base: &str) -> Option<(&'static str, &'static str)> {
    let row = |table| Some((table, "id"));
    match base {
        "/users" => row("users"),
        "/keys" => row("api_keys"),
        // Service-account principal (a `users` row). The key sub-resource spans
        // two tables (automation_keys / api_keys) by request type, so it can't use
        // the single-table generic diff — actor attribution + request body still
        // record it; the before/after diff is simply omitted there.
        "/service-accounts" => row("users"),
        "/admin-accounts" => row("admin_accounts"),
        "/servers" => row("upstream_servers"),
        "/servers/{}/endpoints" => row("upstream_server_endpoints"),
        "/models" => row("upstream_models"),
        "/downstream-providers" => row("downstream_providers"),
        "/downstream-providers/{}/routes" => row("downstream_routes"),
        "/a2a/agents" => row("a2a_upstream_agents"),
        "/mcp/upstream-servers" => row("mcp_upstream_servers"),
        "/mcp/virtual-servers" => row("mcp_virtual_servers"),
        "/mcp/virtual-routes" => row("mcp_virtual_routes"),
        "/mcp/oauth-clients" => row("mcp_oauth_clients"),
        "/mcp/catalog" => row("mcp_catalog"),
        "/mcp/issued-tokens" => Some(("oauth_issued_tokens", "jti")),
        "/route-policies" => row("route_policies"),
        "/cache-presets" => row("cache_presets"),
        "/profiles" => row("profiles"),
        "/destination-lists" => row("destination_lists"),
        "/qos-classes" => row("qos_classes"),
        "/catalog" => row("model_catalog"),
        // Keyed by `profile_key`, which is what the `{id}` path segment
        // carries. A create is stamped by the handler instead: the response
        // serialises the key as `id`, so `capture_created_id` cannot find it
        // under this column name.
        "/client-profiles" => Some(("client_profiles", "profile_key")),
        "/transforms/programs" => row("transform_programs"),
        "/transforms/experts" => row("agent_experts"),
        "/workspaces" => row("workspaces"),
        "/edge-nodes" => row("edge_nodes"),
        // Portal manager mint/revoke of a member's key — the row is an api_key.
        "/workspaces/{}/members/{}/keys" => row("api_keys"),
        // Portal manager live-edit of a member key's budget — the row is an api_key.
        "/workspaces/{}/members/{}/keys/{}/budget" => row("api_keys"),
        // Tenants are keyed by their bookmark-stable slug, not a UUID.
        "/tenants" => Some(("tenants", "slug")),
        _ => None,
    }
}

/// Resolve a mutating route to the single-table snapshot target the generic
/// `change_diff` capture should use, or `None` for routes not in the registry
/// (which leave the diff to the handler). `prefixes` are the mount prefixes
/// stripped before matching (same set passed to [`derive_action`]).
pub(crate) fn resolve_diff_target(
    method: &Method,
    matched: Option<&str>,
    raw_path: &str,
    prefixes: &[&str],
) -> Option<ResolvedDiff> {
    let strip = |s: &str| -> String {
        let mut out = s;
        for p in prefixes {
            out = out.trim_start_matches(p);
        }
        out.trim_start_matches('/').to_string()
    };
    let template = matched.unwrap_or(raw_path);
    let trimmed_t = strip(template);
    let trimmed_r = strip(raw_path);
    let t_segs: Vec<&str> = trimmed_t.split('/').collect();
    let r_segs: Vec<&str> = trimmed_r.split('/').collect();

    // Row key = the trailing `{param}` value lifted from the raw path.
    let resource_id = t_segs.iter().enumerate().rev().find_map(|(i, seg)| {
        if seg.starts_with('{') && seg.ends_with('}') {
            r_segs.get(i).map(|s| (*s).to_string())
        } else {
            None
        }
    });

    let is_action = t_segs.len() >= 2 && t_segs[t_segs.len() - 2] == "actions";

    // Base = template with every `{param}` collapsed to `{}` (name-agnostic),
    // minus a trailing `/actions/{verb}` and a trailing `/{}`.
    let mut base_segs: Vec<&str> = t_segs
        .iter()
        .map(|s| if s.starts_with('{') { "{}" } else { *s })
        .collect();
    if is_action {
        base_segs.truncate(base_segs.len() - 2);
    }
    if base_segs.last() == Some(&"{}") {
        base_segs.pop();
    }
    let base = format!("/{}", base_segs.join("/"));
    let (table, id_col) = diff_target_table(&base)?;

    let kind = if is_action {
        DiffKind::Action
    } else {
        match *method {
            Method::POST => DiffKind::Create,
            Method::PUT | Method::PATCH => DiffKind::Update,
            Method::DELETE => DiffKind::Delete,
            _ => return None,
        }
    };

    Some(ResolvedDiff {
        table,
        id_col,
        resource_id,
        kind,
    })
}

/// Snapshot one row as redacted JSON via `to_jsonb`, over a tenant-scoped
/// connection so RLS confines the read to `tenant_id` (global tables — tenants,
/// edge_nodes — carry no policy and read by key alone). Returns `None` when the row
/// is absent (already deleted, wrong tenant, or never existed).
///
/// `table`/`id_col` are `&'static str` on purpose: they are the only parts of this
/// query that are interpolated rather than bound, so the type makes it impossible
/// to reach them with request data (a `String` from a path or body will not coerce).
/// They come from the `diff_target_table` registry. The row key `id` IS request
/// data, and is bound as `$1`.
pub(crate) async fn snapshot_row(
    pool: &crate::db::Db,
    tenant_id: TenantId,
    table: &'static str,
    id_col: &'static str,
    id: &str,
) -> Option<Value> {
    let mut db = TenantConn::acquire(pool, tenant_id).await.ok()?;
    let sql = format!("SELECT to_jsonb(t) FROM {table} t WHERE {id_col}::text = $1");
    let mut value: Option<Value> = sqlx::query_scalar(sqlx::AssertSqlSafe(&*sql))
        .bind(id)
        .fetch_optional(db.conn())
        .await
        .ok()
        .flatten();
    if let Some(v) = value.as_mut() {
        redact_in_place(v);
    }
    value
}

/// Wrap a before/after pair into the persisted `{before, after}` diff shape,
/// or `None` when nothing changed (so an effect-free mutation leaves the column
/// NULL). Both sides are already redacted by [`snapshot_row`].
pub(crate) fn wrap_diff(before: Value, after: Value) -> Option<Value> {
    if before == after {
        return None;
    }
    Some(serde_json::json!({ "before": before, "after": after }))
}

/// Assemble the generic `change_diff` for a registered resource from the
/// pre-handler `before` snapshot, the resolved target, and (for a create) the
/// `id` returned in the response body. Re-reads the post-mutation row for
/// update/action. Returns `None` when nothing changed or the row can't be
/// located.
pub(crate) async fn build_generic_diff(
    pool: &crate::db::Db,
    tenant_id: TenantId,
    resolved: &ResolvedDiff,
    before: Option<Value>,
    created_id: Option<&str>,
) -> Option<Value> {
    match resolved.kind {
        DiffKind::Create => {
            let id = created_id?;
            let after =
                snapshot_row(pool, tenant_id, resolved.table, resolved.id_col, id).await?;
            wrap_diff(Value::Null, after)
        }
        DiffKind::Update | DiffKind::Action | DiffKind::Delete => {
            // Re-read the row after the handler. For a delete it's gone → `after`
            // is null; for an update/action it's the new state. Re-reading (vs.
            // hard-coding null for delete) is what makes a *dry-run* or soft-
            // failed delete correctly produce no diff: the row is still there, so
            // `after == before` and `wrap_diff` returns None.
            let id = resolved.resource_id.as_deref()?;
            let after = snapshot_row(pool, tenant_id, resolved.table, resolved.id_col, id)
                .await
                .unwrap_or(Value::Null);
            wrap_diff(before.unwrap_or(Value::Null), after)
        }
    }
}

/// Whether a resolved target needs a pre-handler `before` snapshot (everything
/// but a collection create, which has no prior row).
pub(crate) fn needs_before_snapshot(resolved: &ResolvedDiff) -> bool {
    matches!(
        resolved.kind,
        DiffKind::Update | DiffKind::Delete | DiffKind::Action
    ) && resolved.resource_id.is_some()
}

/// Read up to `cap` bytes of a response body to look at it, handing the body
/// on unchanged whatever happens: the bytes when it ended within `cap`; `None`
/// when it is larger or its read failed, the body then passed on as it came —
/// the chunks read, then the rest (or the error) behind them. Never an empty
/// body in its place: the client receives what the handler answered.
async fn peek_body(body: Body, cap: usize) -> (Body, Option<Bytes>) {
    use futures::StreamExt;
    let mut stream = body.into_data_stream();
    let mut seen: Vec<Bytes> = Vec::new();
    let mut len = 0;
    loop {
        match stream.next().await {
            None => {
                let whole = if seen.len() == 1 {
                    seen.pop().unwrap_or_default()
                } else {
                    let mut whole = Vec::with_capacity(len);
                    for chunk in &seen {
                        whole.extend_from_slice(chunk);
                    }
                    Bytes::from(whole)
                };
                return (Body::from(whole.clone()), Some(whole));
            }
            Some(Ok(chunk)) => {
                len += chunk.len();
                seen.push(chunk);
                if len > cap {
                    break;
                }
            }
            Some(Err(e)) => {
                let head = futures::stream::iter(seen.into_iter().map(Ok::<_, axum::Error>));
                return (Body::from_stream(head.chain(futures::stream::once(async move { Err(e) }))), None);
            }
        }
    }
    let head = futures::stream::iter(seen.into_iter().map(Ok::<_, axum::Error>));
    (Body::from_stream(head.chain(stream)), None)
}

/// Read a successful (`2xx`) response body for the key field the created row
/// is identified by (`id_field` = the registry `id_col`, e.g. `id` or `slug`),
/// used to locate the row a collection `POST` just created. The client receives
/// the response unchanged.
///
/// Read up to `MAX_ERROR_BODY_BYTES`, the same bound the error-body path uses;
/// a larger body (a row holding a large value) yields no id, and so no create
/// diff, rather than a wrong one. Note `Content-Length` is not yet on the
/// response at this layer (hyper sets it downstream), so we can't pre-screen on
/// it.
pub(crate) async fn capture_created_id(
    resp: Response,
    id_field: &str,
) -> (Response, Option<String>) {
    let (parts, body) = resp.into_parts();
    let (body, bytes) = peek_body(body, MAX_ERROR_BODY_BYTES).await;
    let id = bytes
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .and_then(|v| v.get(id_field).and_then(|i| i.as_str().map(str::to_string)));
    (Response::from_parts(parts, body), id)
}

/// The longest a refused body is read on before the refusal is answered.
const REFUSAL_DRAIN_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Why the audit layer could not read a request body whole.
pub(crate) enum BodyUnread {
    /// It carried more than the plane's limit.
    TooLarge { limit: usize },
    /// It broke off, or did not arrive within its deadline; the read error.
    Incomplete(String),
}

impl BodyUnread {
    fn message(&self) -> String {
        match self {
            Self::TooLarge { limit } => format!("request body larger than {limit} bytes"),
            Self::Incomplete(cause) => format!("request body not read in full: {cause}"),
        }
    }

    /// The refusal in the console's error envelope: a 413 for a body over the
    /// limit, a 400 for one that did not arrive whole.
    pub(crate) fn into_api_error(self) -> ApiError {
        let message = self.message();
        match self {
            Self::TooLarge { .. } => ApiError::payload_too_large(message),
            Self::Incomplete(_) => ApiError::bad_request(message).code(ApiErrorCode::RequestBodyIncomplete),
        }
    }

    /// A body whose first read fails with this refusal — for a plane whose
    /// handlers answer a body they cannot read in their own grammar (the RFC
    /// OAuth endpoints' extractors), so the refusal is theirs to shape.
    pub(crate) fn into_failing_body(self) -> Body {
        let error = std::io::Error::other(self.message());
        Body::from_stream(futures::stream::once(async move { Err::<Bytes, _>(error) }))
    }
}

/// What a client is told of a body read that failed: the deadline, which is
/// ours to name, or a fixed sentence — the transport's own error text stays in
/// the log.
fn incomplete_cause(e: &axum::Error) -> String {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = source {
        if let Some(deadline) = err.downcast_ref::<streamscope_core::middleware::body_deadline::BodyDeadlineExceeded>() {
            return deadline.to_string();
        }
        source = err.source();
    }
    tracing::info!(error = %e, "request body read failed");
    "the connection broke off".to_string()
}

/// Read the inbound request body whole, up to `limit` bytes, parse + redact it
/// into the JSON we persist, and rebuild the request so downstream extractors
/// see the same bytes. A body over `limit`, broken off, or past its deadline is
/// [`BodyUnread`], handed back with the request's head: the caller refuses the
/// request — never hands the handler an empty body in its place, which a
/// handler would read as sent empty. Shared by all three audit middlewares.
pub(crate) async fn buffer_request_body(
    req: Request,
    limit: usize,
) -> Result<(Request, Option<Value>), Box<(Parts, BodyUnread)>> {
    use axum::body::HttpBody as _;
    use crate::body_read::{read_capped, read_through};
    let (parts, body) = req.into_parts();
    let declared = usize::try_from(body.size_hint().lower()).unwrap_or(usize::MAX);
    // A refused body is read on, discarded, up to another limit's worth and for
    // at most `REFUSAL_DRAIN_WAIT`: a client that sent a body this size whole is
    // then waiting for the answer, so the close after the refusal leaves
    // nothing unread — unread bytes would make it a reset, which can discard the
    // answer before the client reads it. A body larger or slower still is cut
    // off; a client that stalls does not hold the refusal.
    let mut stream = body.into_data_stream();
    if declared > limit {
        // Refused on its word. A client waiting on `Expect: 100-continue` has
        // sent nothing, and reading would invite it to send it all: answer it.
        let waits_to_send = parts
            .headers
            .get(axum::http::header::EXPECT)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("100-continue"));
        if !waits_to_send {
            let _ = tokio::time::timeout(REFUSAL_DRAIN_WAIT, read_through(&mut stream, limit.saturating_mul(2))).await;
        }
        return Err(Box::new((parts, BodyUnread::TooLarge { limit })));
    }
    // Sized to the declared length only up to the parse bound: a declared
    // length is the client's word, and a connection that sends nothing must
    // not hold a large buffer.
    let buf = match read_capped(&mut stream, limit, declared.min(MAX_PARSED_BODY_BYTES)).await {
        Ok(Some(buf)) => buf,
        Ok(None) => {
            let _ = tokio::time::timeout(REFUSAL_DRAIN_WAIT, read_through(&mut stream, limit)).await;
            return Err(Box::new((parts, BodyUnread::TooLarge { limit })));
        }
        Err(e) => return Err(Box::new((parts, BodyUnread::Incomplete(incomplete_cause(&e))))),
    };
    let bytes = Bytes::from(buf);
    // The RFC OAuth endpoints are form-encoded, as their spec requires. Parsing
    // JSON only would leave `request_body` — and with it `actor_identity`, which
    // is lifted from `client_id` — NULL for every grant attempt, quietly turning
    // the busiest security-audit surface into blank rows.
    let is_form = parts
        .headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(';')
                .next()
                .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/x-www-form-urlencoded"))
        });
    let json = if bytes.len() > MAX_PARSED_BODY_BYTES {
        Some(truncation_marker(bytes.len(), identity_of_unparsed(&bytes, is_form)))
    } else if is_form {
        parse_form_and_redact(&bytes)
    } else {
        parse_and_redact(&bytes)
    };
    Ok((Request::from_parts(parts, Body::from(bytes)), json))
}

/// Parse a form-encoded body into the flat JSON object we persist.
///
/// Redaction then runs exactly as it does for JSON, so the same key rules apply
/// — including `code`, which is a bearer here and reaches us on this path.
/// Repeated keys keep the last value; RFC 6749 §3.1 forbids repeating a
/// parameter, so a body that does has already failed on the way to the handler.
pub(crate) fn parse_form_and_redact(bytes: &Bytes) -> Option<Value> {
    if bytes.is_empty() {
        return None;
    }
    let mut map = serde_json::Map::new();
    for (k, v) in url::form_urlencoded::parse(bytes) {
        map.insert(k.into_owned(), Value::String(v.into_owned()));
    }
    if map.is_empty() {
        return None;
    }
    let mut value = Value::Object(map);
    if let Value::Object(m) = &mut value {
        for (k, val) in m.iter_mut() {
            if REQUEST_ONLY_REDACT_KEYS
                .iter()
                .any(|r| k.eq_ignore_ascii_case(r))
            {
                *val = Value::String("[REDACTED]".into());
            }
        }
    }
    redact_in_place(&mut value);
    if serialized_len(&value) > MAX_PERSISTED_BODY_BYTES {
        return Some(truncation_marker(bytes.len(), identity_of(&value)));
    }
    Some(value)
}

/// On a failure status (>=400), buffer the response body to capture the typed
/// `{code, message}` error reason and rebuild the response so the client still
/// receives it unchanged. Success responses pass through untouched (no
/// buffering — they carry no failure reason and can be large). Shared by all
/// three audit middlewares.
pub(crate) async fn capture_error_body(resp: Response, status: u16) -> (Response, Option<Value>) {
    if status < 400 {
        return (resp, None);
    }
    let (parts, body) = resp.into_parts();
    let (body, bytes) = peek_body(body, MAX_ERROR_BODY_BYTES).await;
    let json = bytes.and_then(|b| parse_error_body(&b));
    (Response::from_parts(parts, body), json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use serde_json::json;

    const ADMIN_PREFIX: &[&str] = &["/api/v1/admin"];
    const PORTAL_PREFIX: &[&str] = &["/api/v1/portal"];

    fn json_request(body: Body) -> Request {
        Request::builder()
            .method(Method::PATCH)
            .uri("/x")
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(body)
            .unwrap()
    }

    /// `{"v":"xx…"}` of exactly `len` bytes.
    fn json_of_len(len: usize) -> Vec<u8> {
        format!(r#"{{"v":"{}"}}"#, "x".repeat(len - 8)).into_bytes()
    }

    /// The body as read; panics when it was refused.
    async fn read(req: Request, limit: usize) -> (Request, Option<Value>) {
        match buffer_request_body(req, limit).await {
            Ok(read) => read,
            Err(_) => panic!("the body was refused"),
        }
    }

    /// The refusal; panics when the body was read.
    async fn refuse(req: Request, limit: usize) -> (Parts, BodyUnread) {
        match buffer_request_body(req, limit).await {
            Ok(_) => panic!("the body was read"),
            Err(refused) => *refused,
        }
    }

    /// The limit a refusal names, `None` for an incomplete body.
    fn too_large(unread: &BodyUnread) -> Option<usize> {
        match unread {
            BodyUnread::TooLarge { limit } => Some(*limit),
            BodyUnread::Incomplete(_) => None,
        }
    }

    /// What an incomplete-body refusal tells the client, `None` for a size one.
    fn cause(unread: &BodyUnread) -> Option<&str> {
        match unread {
            BodyUnread::Incomplete(cause) => Some(cause),
            BodyUnread::TooLarge { .. } => None,
        }
    }

    #[tokio::test]
    async fn a_body_up_to_the_limit_reaches_the_handler_whole_and_one_byte_more_is_refused() {
        const LIMIT: usize = 100;
        let (req, json) = read(json_request(Body::from(json_of_len(LIMIT))), LIMIT).await;
        assert_eq!(json.unwrap()["v"].as_str().unwrap().len(), LIMIT - 8);
        let handed_on = axum::body::to_bytes(req.into_body(), usize::MAX).await.unwrap();
        assert_eq!(handed_on.len(), LIMIT);

        let (parts, unread) = refuse(json_request(Body::from(json_of_len(LIMIT + 1))), LIMIT).await;
        assert_eq!(too_large(&unread), Some(LIMIT));
        assert_eq!(parts.uri, "/x", "the request's head comes back with the refusal");
        let err = unread.into_api_error();
        assert_eq!((err.status, err.code), (StatusCode::PAYLOAD_TOO_LARGE, ApiErrorCode::PayloadTooLarge));
    }

    #[tokio::test]
    async fn the_limit_counts_the_whole_body_not_one_frame() {
        const LIMIT: usize = 100;
        let framed = |sizes: &'static [usize]| {
            json_request(Body::from_stream(futures::stream::iter(
                sizes.iter().map(|n| Ok::<_, std::io::Error>(Bytes::from(vec![b' '; *n]))),
            )))
        };
        // No frame is over the limit; the body is, by one byte, or exactly at it.
        let (_, unread) = refuse(framed(&[40, 40, 21]), LIMIT).await;
        assert_eq!(too_large(&unread), Some(LIMIT));
        let (req, _) = read(framed(&[40, 40, 20]), LIMIT).await;
        assert_eq!(axum::body::to_bytes(req.into_body(), usize::MAX).await.unwrap().len(), LIMIT);
    }

    #[tokio::test]
    async fn a_body_too_large_to_keep_still_names_who_sent_it() {
        let pad = "x".repeat(MAX_PARSED_BODY_BYTES);
        let unparsed = serde_json::to_vec(&json!({"pad": pad, "workspace_id": "w-1", "password": "p"})).unwrap();
        let (_, json) = read(json_request(Body::from(unparsed.clone())), CONSOLE_BODY_LIMIT).await;
        assert_eq!(json, Some(json!({ "_truncated": true, "_bytes": unparsed.len(), "workspace_id": "w-1" })));

        // Parsed, but over the persist cap: the same record.
        let parsed = serde_json::to_vec(&json!({"email": "a@b.c", "pad": "x".repeat(MAX_PERSISTED_BODY_BYTES)})).unwrap();
        assert_eq!(
            parse_and_redact(&Bytes::from(parsed.clone())),
            Some(json!({ "_truncated": true, "_bytes": parsed.len(), "email": "a@b.c" })),
        );
    }

    #[test]
    fn a_change_diff_past_its_cap_is_recorded_by_its_size() {
        let small = json!({"before": {"a": 1}, "after": {"a": 2}});
        assert_eq!(*capped_change_diff(&small), small);
        let at_cap = json!({"a": "x".repeat(MAX_PERSISTED_DIFF_BYTES - 8)});
        assert_eq!(serde_json::to_vec(&at_cap).unwrap().len(), MAX_PERSISTED_DIFF_BYTES);
        assert_eq!(*capped_change_diff(&at_cap), at_cap);
        let big = json!({"a": "x".repeat(MAX_PERSISTED_DIFF_BYTES - 7)});
        let len = serde_json::to_vec(&big).unwrap().len();
        assert_eq!(*capped_change_diff(&big), json!({ "_truncated": true, "_bytes": len }));
    }

    #[test]
    fn identity_survives_a_stray_field_and_never_carries_a_long_value() {
        let id = "w-1";
        let body = format!(
            r#"{{"email": 5, "workspace_id": "{id}", "username": "{long}", "nested": {{"email": "no"}}, "client_id": "a", "client_id": "b"}}"#,
            long = "u".repeat(MAX_IDENTITY_VALUE_BYTES + 1),
        );
        assert_eq!(
            Value::Object(identity_of_unparsed(body.as_bytes(), false)),
            json!({ "workspace_id": id, "client_id": "b" }),
        );
        let form = format!("email=a%40b.c&pad=x&tenant_slug={}", "t".repeat(MAX_IDENTITY_VALUE_BYTES + 1));
        assert_eq!(Value::Object(identity_of_unparsed(form.as_bytes(), true)), json!({ "email": "a@b.c" }));
        assert!(identity_of_unparsed(b"[1, 2]", false).is_empty());
        // A value exactly at the bound is kept.
        let at = "e".repeat(MAX_IDENTITY_VALUE_BYTES);
        let at_bound = format!(r#"{{"email": "{at}"}}"#);
        assert_eq!(Value::Object(identity_of_unparsed(at_bound.as_bytes(), false)), json!({ "email": at }));
        // A form's later bad value removes an earlier good one, as in JSON.
        let repeated = format!("workspace_id=A&workspace_id={}", "w".repeat(MAX_IDENTITY_VALUE_BYTES + 1));
        assert!(identity_of_unparsed(repeated.as_bytes(), true).is_empty());
        // The last occurrence decides, as on a parsed body.
        assert!(identity_of_unparsed(br#"{"workspace_id": "A", "workspace_id": null}"#, false).is_empty());
        // Broken after the field: what was read before the break is kept.
        let broken = br#"{"workspace_id": "w-2", "pad": "x", oops"#;
        assert_eq!(Value::Object(identity_of_unparsed(broken, false)), json!({ "workspace_id": "w-2" }));
    }

    #[tokio::test]
    async fn a_body_past_its_deadline_is_refused_naming_the_deadline() {
        use streamscope_core::middleware::body_deadline::DeadlineBody;
        let never = futures::stream::pending::<Result<Bytes, std::io::Error>>();
        let body = Body::new(DeadlineBody::new(Body::from_stream(never), std::time::Duration::from_secs(1)));
        let (_, unread) = refuse(json_request(body), 1024).await;
        assert_eq!(cause(&unread), Some("request body not received in full within 1s"));
    }

    /// A body declaring `len` bytes that sends none: it ends at once, or
    /// (`stalls`) never answers a read.
    struct Declared {
        len: u64,
        stalls: bool,
    }
    impl http_body::Body for Declared {
        type Data = Bytes;
        type Error = std::io::Error;
        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
            if self.stalls { std::task::Poll::Pending } else { std::task::Poll::Ready(None) }
        }
        fn size_hint(&self) -> http_body::SizeHint {
            http_body::SizeHint::with_exact(self.len)
        }
    }

    #[tokio::test]
    async fn a_client_waiting_to_send_is_refused_without_being_asked_for_its_body() {
        let mut req = json_request(Body::new(Declared { len: 101, stalls: true }));
        req.headers_mut().insert(axum::http::header::EXPECT, "100-continue".parse().unwrap());
        let (_, unread) = tokio::time::timeout(std::time::Duration::from_secs(1), refuse(req, 100))
            .await
            .expect("answered without reading the body");
        assert_eq!(too_large(&unread), Some(100));
    }

    #[tokio::test]
    async fn a_stalled_refused_body_does_not_hold_its_refusal() {
        let (_, unread) = tokio::time::timeout(
            REFUSAL_DRAIN_WAIT + std::time::Duration::from_secs(2),
            refuse(json_request(Body::new(Declared { len: 101, stalls: true })), 100),
        )
        .await
        .expect("answered once the drain gives up");
        assert_eq!(too_large(&unread), Some(100));
    }

    #[tokio::test]
    async fn a_body_declared_over_the_limit_is_refused_on_its_word() {
        let (_, unread) = refuse(json_request(Body::new(Declared { len: 101, stalls: false })), 100).await;
        assert_eq!(too_large(&unread), Some(100));
        let (_, json) = read(json_request(Body::new(Declared { len: 100, stalls: false })), 100).await;
        assert_eq!(json, None, "a declared length at the limit is read");
    }

    #[tokio::test]
    async fn a_body_that_breaks_off_is_refused_never_handed_on_empty() {
        let parts = futures::stream::iter([
            Ok(Bytes::from_static(br#"{"v":"#)),
            Err(std::io::Error::other("connection reset")),
        ]);
        let (_, unread) = refuse(json_request(Body::from_stream(parts)), 1024).await;
        // The transport's own text stays in the log; the client reads a fixed one.
        assert_eq!(cause(&unread), Some("the connection broke off"));
        let err = unread.into_api_error();
        assert_eq!((err.status, err.code), (StatusCode::BAD_REQUEST, ApiErrorCode::RequestBodyIncomplete));
    }

    #[tokio::test]
    async fn a_refusal_handed_to_the_handler_fails_its_read() {
        let body = BodyUnread::TooLarge { limit: 7 }.into_failing_body();
        let err = axum::body::to_bytes(body, usize::MAX).await.unwrap_err();
        assert!(err.to_string().contains("larger than 7 bytes"), "{err}");
    }

    #[tokio::test]
    async fn a_body_over_the_parse_bound_is_recorded_by_its_size_and_handed_on_whole() {
        // Not JSON, so a parse records nothing and the size marker shows the
        // body was not parsed.
        let raw = |len: usize| json_request(Body::from(vec![b'x'; len]));
        let (_, at_bound) = read(raw(MAX_PARSED_BODY_BYTES), CONSOLE_BODY_LIMIT).await;
        assert_eq!(at_bound, None, "a body at the bound is parsed");
        let len = MAX_PARSED_BODY_BYTES + 1;
        let (req, json) = read(raw(len), CONSOLE_BODY_LIMIT).await;
        assert_eq!(json, Some(json!({ "_truncated": true, "_bytes": len })));
        assert_eq!(axum::body::to_bytes(req.into_body(), usize::MAX).await.unwrap().len(), len);
    }

    #[tokio::test]
    async fn a_response_too_large_to_read_reaches_the_client_whole() {
        let big = format!(r#"{{"id":"r-1","v":"{}"}}"#, "x".repeat(MAX_ERROR_BODY_BYTES));
        let resp = Response::new(Body::from(big.clone()));
        let (resp, id) = capture_created_id(resp, "id").await;
        assert_eq!(id, None, "a body past the cap is not read for an id");
        let sent = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(sent, big.as_bytes());

        // Within the cap: read, and still handed on.
        let small = r#"{"id":"r-2"}"#;
        let (resp, id) = capture_created_id(Response::new(Body::from(small)), "id").await;
        assert_eq!(id.as_deref(), Some("r-2"));
        assert_eq!(axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap(), small.as_bytes());

        // Exactly at the cap: read.
        let at_cap = format!(r#"{{"id":"r-3","v":"{}"}}"#, "x".repeat(MAX_ERROR_BODY_BYTES - 19));
        assert_eq!(at_cap.len(), MAX_ERROR_BODY_BYTES);
        let (_, id) = capture_created_id(Response::new(Body::from(at_cap)), "id").await;
        assert_eq!(id.as_deref(), Some("r-3"));

        let error = Response::builder().status(500).body(Body::from(big.clone())).unwrap();
        let (resp, json) = capture_error_body(error, 500).await;
        assert_eq!(json, None);
        assert_eq!(axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap(), big.as_bytes());
    }

    #[test]
    fn redact_object_top_level() {
        let mut v = json!({"email": "x@y.z", "password": "hunter2"});
        redact_in_place(&mut v);
        assert_eq!(v["email"], "x@y.z");
        assert_eq!(v["password"], "[REDACTED]");
    }

    #[test]
    fn rclone_config_is_redacted_from_the_audit_row() {
        // A refused backup body is recorded too: its rclone config holds cloud credentials.
        let mut v = json!({"destination": "b:x", "rclone_config": "[b]\nsecret_access_key = k\n"});
        redact_in_place(&mut v);
        assert_eq!(v["rclone_config"], "[REDACTED]");
        assert_eq!(v["destination"], "b:x");
    }

    #[test]
    fn redact_nested() {
        let mut v = json!({"upstream": {"name": "anthropic", "api_key": "sk-..."}});
        redact_in_place(&mut v);
        assert_eq!(v["upstream"]["api_key"], "[REDACTED]");
        assert_eq!(v["upstream"]["name"], "anthropic");
    }

    #[test]
    fn redact_inside_arrays() {
        let mut v = json!({"items": [{"token": "abc"}, {"token": "def"}]});
        redact_in_place(&mut v);
        assert_eq!(v["items"][0]["token"], "[REDACTED]");
        assert_eq!(v["items"][1]["token"], "[REDACTED]");
    }

    #[test]
    fn redact_case_insensitive() {
        let mut v = json!({"API_KEY": "x", "Password": "y"});
        redact_in_place(&mut v);
        assert_eq!(v["API_KEY"], "[REDACTED]");
        assert_eq!(v["Password"], "[REDACTED]");
    }

    #[test]
    fn redact_substring_not_matched() {
        let mut v = json!({"key": "k"});
        redact_in_place(&mut v);
        assert_eq!(v["key"], "k");
    }

    #[test]
    fn first_string_field_picks_first_present() {
        let v = json!({"client_id": "abc", "email": "x@y.z"});
        assert_eq!(first_string_field(Some(&v), &["email", "client_id"]), Some("x@y.z"));
        assert_eq!(first_string_field(Some(&v), &["username", "client_id"]), Some("abc"));
        assert_eq!(first_string_field(Some(&v), &["missing"]), None);
        assert_eq!(first_string_field(None, &["email"]), None);
    }

    #[test]
    fn workspace_id_from_path_lifts_manager_route() {
        let ws = "11111111-1111-1111-1111-111111111111";
        let member = "22222222-2222-2222-2222-222222222222";
        let template = "/api/v1/portal/workspaces/{id}/members/{uid}/keys";
        let raw = format!("/api/v1/portal/workspaces/{ws}/members/{member}/keys");
        assert_eq!(
            workspace_id_from_path(Some(template), &raw),
            Some(uuid::Uuid::parse_str(ws).unwrap())
        );
    }

    #[test]
    fn workspace_id_from_path_none_without_segment() {
        // A self-service key route carries no `workspaces` segment → None.
        assert_eq!(
            workspace_id_from_path(Some("/api/v1/portal/keys"), "/api/v1/portal/keys"),
            None
        );
        // No template (unmatched) → None.
        assert_eq!(workspace_id_from_path(None, "/api/v1/portal/workspaces/x/y"), None);
    }

    #[test]
    fn derive_action_simple_create() {
        let (action, kind, id) = derive_action(
            &Method::POST, Some("/users"), "/api/v1/admin/users",
            ADMIN_PREFIX, ADMIN_ACTION_OVERRIDES,
        );
        assert_eq!(action, "users.create");
        assert_eq!(kind, "users");
        assert_eq!(id, None);
    }

    #[test]
    fn derive_action_with_id() {
        let (action, kind, id) = derive_action(
            &Method::PATCH, Some("/users/{id}"), "/api/v1/admin/users/abc-123",
            ADMIN_PREFIX, ADMIN_ACTION_OVERRIDES,
        );
        assert_eq!(action, "users.update");
        assert_eq!(kind, "users");
        assert_eq!(id.as_deref(), Some("abc-123"));
    }

    #[test]
    fn derive_action_admin_keys_not_shadowed_by_portal() {
        // The admin plane uses ADMIN_ACTION_OVERRIDES, which has NO `/keys`
        // entry — so admin key create/revoke derive generically as `keys.*`,
        // never the portal plane's `portal_key.*`. Guards the cross-plane
        // override-collision regression.
        let (create, ck, _) = derive_action(
            &Method::POST, Some("/keys"), "/api/v1/admin/keys",
            ADMIN_PREFIX, ADMIN_ACTION_OVERRIDES,
        );
        assert_eq!(create, "keys.create");
        assert_eq!(ck, "keys");
        let (revoke, rk, id) = derive_action(
            &Method::POST, Some("/keys/{id}/actions/revoke"),
            "/api/v1/admin/keys/k-9/actions/revoke",
            ADMIN_PREFIX, ADMIN_ACTION_OVERRIDES,
        );
        assert_eq!(revoke, "keys.revoke");
        assert_eq!(rk, "keys");
        assert_eq!(id.as_deref(), Some("k-9"));
    }

    #[test]
    fn derive_action_subresource_fallthrough() {
        let (action, _kind, _id) = derive_action(
            &Method::POST, Some("/widgets/{id}/labels"),
            "/api/v1/admin/widgets/w1/labels",
            ADMIN_PREFIX, ADMIN_ACTION_OVERRIDES,
        );
        assert_eq!(action, "widgets.create_labels");
    }

    #[test]
    fn derive_action_kebab_normalised() {
        let (action, kind, _id) = derive_action(
            &Method::POST, Some("/tool-rules"), "/api/v1/admin/tool-rules",
            ADMIN_PREFIX, ADMIN_ACTION_OVERRIDES,
        );
        assert_eq!(action, "tool_rules.create");
        assert_eq!(kind, "tool_rules");
    }

    #[test]
    fn derive_action_override_maintenance_purge() {
        let (action, kind, id) = derive_action(
            &Method::POST, Some("/maintenance/purge-audit"),
            "/api/v1/admin/maintenance/purge-audit",
            ADMIN_PREFIX, ADMIN_ACTION_OVERRIDES,
        );
        assert_eq!(action, "maintenance.purge_audit");
        assert_eq!(kind, "maintenance");
        assert_eq!(id, None);
    }

    #[test]
    fn derive_action_override_add_member() {
        let (action, kind, id) = derive_action(
            &Method::POST, Some("/workspaces/{id}/members"),
            "/api/v1/admin/workspaces/w-1/members",
            ADMIN_PREFIX, ADMIN_ACTION_OVERRIDES,
        );
        assert_eq!(action, "workspaces.add_member");
        assert_eq!(kind, "workspaces");
        assert_eq!(id.as_deref(), Some("w-1"));
    }

    #[test]
    fn derive_action_security_login() {
        // Security plane uses CONTROL_PLANE_ACTION_OVERRIDES; the override
        // matches on the nested template regardless of mount prefix.
        let (action, kind, _id) = derive_action(
            &Method::POST, Some("/login"), "/api/v1/auth/login",
            &["/api/v1/auth"], CONTROL_PLANE_ACTION_OVERRIDES,
        );
        assert_eq!(action, "auth.login");
        assert_eq!(kind, "auth");
    }

    #[test]
    fn derive_action_portal_keys() {
        // Portal plane DOES get the distinct portal_key.* naming.
        let (create, ck, _) = derive_action(
            &Method::POST, Some("/keys"), "/api/v1/portal/keys",
            PORTAL_PREFIX, CONTROL_PLANE_ACTION_OVERRIDES,
        );
        assert_eq!(create, "portal_key.create");
        assert_eq!(ck, "portal_key");
        let (revoke, rk, _) = derive_action(
            &Method::POST, Some("/keys/{id}/actions/revoke"),
            "/api/v1/portal/keys/k-1/actions/revoke",
            PORTAL_PREFIX, CONTROL_PLANE_ACTION_OVERRIDES,
        );
        assert_eq!(revoke, "portal_key.revoke");
        assert_eq!(rk, "portal_key");
    }

    /// The authorization code is a bearer on the way in and must never be
    /// persisted; the PKCE verifier and sealed flow token likewise.
    #[test]
    fn a_request_bodys_oauth_material_is_redacted() {
        let body = Bytes::from(
            serde_json::json!({
                "code": "authz-code-abc",
                "code_verifier": "pkce-verifier-xyz",
                "flow_token": "sealed-blob",
                "id_token_hint": "eyJhbGciOiJSUzI1NiJ9.payload.sig",
                "grant_type": "authorization_code",
            })
            .to_string(),
        );
        let out = parse_and_redact(&body).expect("parses");
        for key in ["code", "code_verifier", "flow_token", "id_token_hint"] {
            assert_eq!(out[key], "[REDACTED]", "{key} must not be persisted");
        }
        // Non-secret context has to survive, or the row says nothing.
        assert_eq!(out["grant_type"], "authorization_code");
    }

    /// `code` names two different things, and only one of them is a secret.
    ///
    /// In a request body it is the OAuth authorization code. In an error body it
    /// is `ApiErrorCode` — the field the whole audit trail is read by. Redacting
    /// it there would blind an operator to *why* anything was refused, across
    /// every plane, which is the opposite of what the audit is for.
    #[test]
    fn an_error_bodys_code_is_kept_because_it_is_the_error_code() {
        let body = Bytes::from(
            serde_json::json!({
                "error": {
                    "message": "the identity provider did not verify this email address",
                    "type": "forbidden",
                    "code": "oidc_email_not_verified",
                }
            })
            .to_string(),
        );
        let out = parse_error_body(&body).expect("parses");
        assert_eq!(out["error"]["code"], "oidc_email_not_verified");
    }

    /// A secret keeps its name wherever it appears — only `code` is scoped.
    #[test]
    fn an_error_bodys_genuine_secrets_are_still_redacted() {
        let body = Bytes::from(
            serde_json::json!({"error": {"code": "bad_request", "client_secret": "shh"}})
                .to_string(),
        );
        let out = parse_error_body(&body).expect("parses");
        assert_eq!(out["error"]["code"], "bad_request");
        assert_eq!(out["error"]["client_secret"], "[REDACTED]");
    }

    /// The token endpoints are form-encoded, so this is the shape the busiest
    /// security-audit surface actually arrives in. Parsing it is what keeps
    /// `actor_identity` (lifted from `client_id`) from going NULL on every
    /// grant attempt.
    #[test]
    fn a_form_encoded_grant_is_parsed_and_redacted() {
        let body = Bytes::from(concat!(
            "grant_type=authorization_code",
            "&code=authz-abc",
            "&client_id=cli",
            "&code_verifier=pkce-xyz",
            "&redirect_uri=http%3A%2F%2F127.0.0.1%3A8731%2Fcb",
        ));
        let out = parse_form_and_redact(&body).expect("parses");
        assert_eq!(out["grant_type"], "authorization_code");
        assert_eq!(out["client_id"], "cli", "actor_identity is lifted from this");
        assert_eq!(out["redirect_uri"], "http://127.0.0.1:8731/cb", "percent-decoded");
        assert_eq!(out["code"], "[REDACTED]");
        assert_eq!(out["code_verifier"], "[REDACTED]");
    }

    #[test]
    fn an_empty_or_unparseable_form_yields_nothing_rather_than_an_empty_row() {
        assert!(parse_form_and_redact(&Bytes::new()).is_none());
    }

    #[test]
    fn parse_and_redact_oversized_truncated() {
        let big = "x".repeat(MAX_PERSISTED_BODY_BYTES + 1);
        let raw = serde_json::to_vec(&json!({"value": big})).unwrap();
        let result = parse_and_redact(&Bytes::from(raw)).unwrap();
        assert_eq!(result["_truncated"], true);
    }
}

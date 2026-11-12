//! MCP header inputs on the admin and portal surfaces.
//!
//! The model — a `server.json` remote whose declared headers are filled by the
//! administrator, the user or the calling client — lives in
//! [`streamscope_core::mcp::header_inputs`]; every rule about a declaration,
//! its fillers and a value is read from there, never restated here. This
//! module holds what the HTTP surfaces add on top: the error codes, the
//! three-state value patch both surfaces accept, one ciphertext per stored
//! value, the per-virtual-server client-header facts, and the collision rule's
//! locking.
//!
//! A value travels under `inputs` when its input is not secret and ONLY under
//! `secret_inputs` when it is, and a secret sent under `inputs` is refused: an
//! input id (`X-Jira-Token`) says nothing about secrecy, so the split is what
//! tells the console and the API which values may be shown back. The audit
//! redactor blanks both maps of a request body whole.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use streamscope_core::mcp::header_inputs::{
    self as hi, Filler, InputSpec, KeyValueInput, Remote, RemoteError,
};
use uuid::Uuid;

use super::{ApiError, ApiErrorCode};
use crate::db::tenant::Scoped;

/// The 400 for a declaration, filler set or value the core model refuses: its
/// `Display` is the message. `Authorization` on an OAuth upstream has its own
/// code.
pub(crate) fn remote_error(e: &RemoteError) -> ApiError {
    let code = match e {
        RemoteError::ReservedForOauth => ApiErrorCode::McpInputReserved,
        _ => ApiErrorCode::McpRemoteInvalid,
    };
    ApiError::bad_request(e.to_string()).code(code)
}

/// Whether a stored `auth_mode` adds the user's OAuth token.
pub(crate) fn is_oauth(auth_mode: &str) -> bool {
    auth_mode == "per_user_oauth"
}

/// The inputs of a remote a caller is saving, with their fillers.
pub(crate) fn specs_of(remote: &Remote, auth_mode: &str) -> Result<Vec<InputSpec>, ApiError> {
    hi::validate_fillers(remote, is_oauth(auth_mode)).map_err(|e| remote_error(&e))
}

/// The inputs of a STORED remote. Every row the admin API writes validates; a
/// row that does not reads as `None` (logged), so a reader fails closed on it
/// rather than failing the request.
pub(crate) fn stored_specs(upstream_id: Uuid, remote: &Remote, auth_mode: &str) -> Option<Vec<InputSpec>> {
    match hi::validate_fillers(remote, is_oauth(auth_mode)) {
        Ok(specs) => Some(specs),
        Err(e) => {
            tracing::warn!(%upstream_id, error = %e, "stored MCP remote does not validate");
            None
        }
    }
}

fn header_of<'a>(remote: &'a Remote, spec: &InputSpec) -> Option<&'a KeyValueInput> {
    remote.headers.iter().find(|h| h.name == spec.declared.header)
}

/// Whether an input's value is secret (its own flag, or its header's). An
/// input whose header cannot be found reads as secret — fail closed.
pub(crate) fn is_secret(remote: &Remote, spec: &InputSpec) -> bool {
    header_of(remote, spec).is_none_or(|h| spec.declared.is_secret(h))
}

/// The ids a filler must supply before the upstream is usable: required, with
/// no default.
pub(crate) fn required_ids(specs: &[InputSpec], filler: Filler) -> Vec<String> {
    specs
        .iter()
        .filter(|s| s.filler == filler && s.declared.required && s.declared.input.default.is_none())
        .map(|s| s.declared.id.clone())
        .collect()
}

/// The lowercased client-filled header names of a set of inputs, deduplicated.
pub(crate) fn client_headers(specs: &[InputSpec]) -> Vec<String> {
    hi::client_header_names(specs).into_iter().collect::<BTreeSet<_>>().into_iter().collect()
}

/// Whether a set of inputs has the client fill `Authorization` — the header a
/// sign-in (OAuth) client spends on the gateway's own token.
pub(crate) fn reads_client_authorization(specs: &[InputSpec]) -> bool {
    specs
        .iter()
        .any(|s| s.filler == Filler::Client && s.declared.header.eq_ignore_ascii_case("authorization"))
}

// ── URL variables ───────────────────────────────────────────────────────────

/// The values a URL finished from `given` was built with: each declared
/// variable's given value, else its default. What an upstream row stores, so
/// a later edit of one variable keeps the others.
pub(crate) fn url_values_used(remote: &Remote, given: &HashMap<String, String>) -> BTreeMap<String, String> {
    remote
        .variables
        .iter()
        .filter_map(|(name, input)| {
            given.get(name).or(input.default.as_ref()).map(|v| (name.clone(), v.clone()))
        })
        .collect()
}

/// The values a PATCH finishes an upstream's URL with: the stored value of
/// every variable the (possibly new) remote still declares, overlaid with the
/// body's. A variable the URL template uses must have one or the other — its
/// default fills it only at create and adopt, so a PATCH never repoints the
/// URL through a default standing in for a value it was finished with, nor
/// through one standing in for a value the row does not hold. A body naming a
/// variable the remote does not declare is refused by [`hi::finish_url`].
pub(crate) fn merged_url_variables(
    remote: &Remote,
    stored: &BTreeMap<String, String>,
    body: Option<&HashMap<String, String>>,
) -> Result<HashMap<String, String>, RemoteError> {
    let mut vars: HashMap<String, String> = stored
        .iter()
        .filter(|(k, _)| remote.variables.contains_key(*k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    if let Some(body) = body {
        vars.extend(body.iter().map(|(k, v)| (k.clone(), v.clone())));
    }
    if let Some(missing) = remote
        .variables
        .keys()
        .find(|name| !vars.contains_key(*name) && remote.url.contains(&format!("{{{name}}}")))
    {
        return Err(RemoteError::MissingUrlVariable(missing.clone()));
    }
    Ok(vars)
}

// ── the three-state value patch ─────────────────────────────────────────────

/// One change to a filler's stored values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ValueOp {
    /// Store this plaintext (encrypted) under the id.
    Set { id: String, value: String },
    /// Drop the id's stored value.
    Remove(String),
}

/// Why a value patch was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PatchRefusal {
    /// A user named an input the administrator fills.
    Locked(String),
    /// An id the remote does not declare for this filler.
    Unknown(String),
    /// A secret input's value sent under `inputs`.
    SecretUnderInputs(String),
    /// The same id under both `inputs` and `secret_inputs`.
    Twice(String),
    /// The value breaks the input's declaration.
    Invalid(RemoteError),
}

impl PatchRefusal {
    pub(crate) fn into_api(self) -> ApiError {
        match self {
            Self::Locked(id) => ApiError::bad_request(format!(
                "input '{id}' is set by your administrator and cannot be changed"
            ))
            .code(ApiErrorCode::McpInputLocked),
            Self::Unknown(id) => {
                ApiError::bad_request(format!("'{id}' is not an input you can set on this server"))
                    .code(ApiErrorCode::McpInputUnknown)
            }
            Self::SecretUnderInputs(id) => ApiError::bad_request(format!(
                "input '{id}' is secret: send its value under secret_inputs"
            ))
            .code(ApiErrorCode::McpRemoteInvalid),
            Self::Twice(id) => ApiError::bad_request(format!(
                "input '{id}' is under both inputs and secret_inputs"
            ))
            .code(ApiErrorCode::McpRemoteInvalid),
            Self::Invalid(e) => remote_error(&e),
        }
    }
}

/// Plan a patch of `filler`'s values from the two request maps:
///
/// - `inputs`: a value sets, `null` clears;
/// - `secret_inputs`: a value sets, `""` clears, `null` keeps.
///
/// Only ids `filler` fills are accepted; a user naming an admin input is told
/// it is locked. Every value is checked against its declaration. The ops come
/// out in id order, so a refusal names the same id on every call.
pub(crate) fn plan_value_patch(
    remote: &Remote,
    specs: &[InputSpec],
    filler: Filler,
    inputs: &HashMap<String, Option<String>>,
    secret_inputs: &HashMap<String, Option<String>>,
) -> Result<Vec<ValueOp>, PatchRefusal> {
    let mut entries: BTreeMap<&str, (bool, &Option<String>)> = BTreeMap::new();
    for (id, v) in inputs {
        entries.insert(id.as_str(), (false, v));
    }
    for (id, v) in secret_inputs {
        if entries.insert(id.as_str(), (true, v)).is_some() {
            return Err(PatchRefusal::Twice(id.clone()));
        }
    }
    let mut ops = Vec::with_capacity(entries.len());
    for (id, (under_secret, value)) in entries {
        let Some(spec) = specs.iter().find(|s| s.declared.id == id) else {
            return Err(PatchRefusal::Unknown(id.to_string()));
        };
        if spec.filler != filler {
            return Err(if filler == Filler::User && spec.filler == Filler::Admin {
                PatchRefusal::Locked(id.to_string())
            } else {
                PatchRefusal::Unknown(id.to_string())
            });
        }
        let secret = is_secret(remote, spec);
        if secret && !under_secret {
            return Err(PatchRefusal::SecretUnderInputs(id.to_string()));
        }
        match (under_secret, value.as_deref()) {
            // `inputs: {id: null}` clears; `secret_inputs: {id: null}` keeps.
            (false, None) => ops.push(ValueOp::Remove(id.to_string())),
            (true, None) => {}
            (true, Some("")) => ops.push(ValueOp::Remove(id.to_string())),
            (_, Some(v)) => {
                hi::validate_value(id, &spec.declared.input, v).map_err(PatchRefusal::Invalid)?;
                ops.push(ValueOp::Set { id: id.to_string(), value: v.to_string() });
            }
        }
    }
    Ok(ops)
}

/// A create body's plain value maps as the three-state maps
/// [`plan_value_patch`] reads (every entry a value).
pub(crate) fn as_patch(values: &HashMap<String, String>) -> HashMap<String, Option<String>> {
    values.iter().map(|(k, v)| (k.clone(), Some(v.clone()))).collect()
}

/// The first required input of `filler` with neither a stored value nor a
/// default, as the `mcp_input_required` refusal.
pub(crate) fn require_filled(
    specs: &[InputSpec],
    filler: Filler,
    stored: &HashMap<String, String>,
) -> Result<(), ApiError> {
    match required_ids(specs, filler).into_iter().find(|id| !stored.contains_key(id)) {
        None => Ok(()),
        Some(id) => Err(ApiError::bad_request(format!("input '{id}' is required and has no value"))
            .code(ApiErrorCode::McpInputRequired)),
    }
}

/// Every stored value of `filler`'s inputs still fits its (possibly changed)
/// declaration — the gateway treats one that does not as unfilled, which for
/// an admin input would make the upstream unusable for everyone. The value is
/// never named in the error.
pub(crate) fn require_stored_values_valid(
    specs: &[InputSpec],
    filler: Filler,
    stored: &HashMap<String, String>,
) -> Result<(), ApiError> {
    let plain = decrypt_values(stored);
    for spec in specs.iter().filter(|s| s.filler == filler) {
        let id = &spec.declared.id;
        if let Some(value) = plain.get(id)
            && streamscope_core::mcp::header_inputs::validate_value(id, &spec.declared.input, value).is_err()
        {
            return Err(ApiError::bad_request(format!(
                "the stored value of '{id}' no longer fits its declaration; set a new value for it"
            ))
            .code(ApiErrorCode::McpRemoteInvalid));
        }
    }
    Ok(())
}

/// Encrypt one secret for storage: the base64 AES-256-GCM ciphertext string
/// kept in a JSONB object (an input value) or as bytes (`encrypt_mcp_credential`).
pub(crate) fn encrypt_value(plain: &str) -> Result<String, ApiError> {
    let key = streamscope_core::crypto::get_encryption_key().ok_or_else(|| {
        tracing::error!("ENCRYPTION_KEY not set — refusing to store an MCP secret");
        ApiError::server_misconfigured("ENCRYPTION_KEY not configured")
    })?;
    streamscope_core::crypto::encrypt(plain, &key).map_err(|e| {
        tracing::error!("encrypt mcp secret: {e}");
        ApiError::internal("failed to encrypt")
    })
}

/// The ops' `Set` values encrypted, and the ids they remove.
pub(crate) fn encrypt_ops(ops: &[ValueOp]) -> Result<(HashMap<String, String>, Vec<String>), ApiError> {
    let mut set = HashMap::new();
    let mut remove = Vec::new();
    for op in ops {
        match op {
            ValueOp::Set { id, value } => {
                set.insert(id.clone(), encrypt_value(value)?);
            }
            ValueOp::Remove(id) => remove.push(id.clone()),
        }
    }
    Ok((set, remove))
}

/// Decrypt a stored value map. A value that does not decrypt is left out
/// (logged): the caller then sees it as unset.
pub(crate) fn decrypt_values(stored: &HashMap<String, String>) -> HashMap<String, String> {
    decrypt_values_with(stored, true)
}

/// [`decrypt_values`], logging a value that does not decrypt only when `log`.
pub(crate) fn decrypt_values_with(stored: &HashMap<String, String>, log: bool) -> HashMap<String, String> {
    if stored.is_empty() {
        return HashMap::new();
    }
    let Some(key) = streamscope_core::crypto::get_encryption_key() else {
        tracing::error!("ENCRYPTION_KEY not set — cannot read stored MCP inputs");
        return HashMap::new();
    };
    stored
        .iter()
        .filter_map(|(id, ct)| match streamscope_core::crypto::decrypt(ct, &key) {
            Ok(v) => Some((id.clone(), v)),
            Err(_) => {
                if log {
                    tracing::warn!(input = %id, "stored MCP input does not decrypt");
                }
                None
            }
        })
        .collect()
}

/// What an upstream row shows of its admin values: the non-secret ones in
/// clear, and only the ids of the secret ones that have a value.
pub(crate) fn admin_values_view(
    remote: &Remote,
    specs: Option<&[InputSpec]>,
    stored: &HashMap<String, String>,
) -> (BTreeMap<String, String>, Vec<String>) {
    let Some(specs) = specs else {
        return (BTreeMap::new(), Vec::new());
    };
    let mut clear = BTreeMap::new();
    let mut secret_ids = Vec::new();
    let mut plain_ids: Vec<&String> = Vec::new();
    for s in specs.iter().filter(|s| s.filler == Filler::Admin) {
        let id = &s.declared.id;
        if !stored.contains_key(id) {
            continue;
        }
        if is_secret(remote, s) {
            secret_ids.push(id.clone());
        } else {
            plain_ids.push(id);
        }
    }
    if !plain_ids.is_empty() {
        let only_plain: HashMap<String, String> =
            plain_ids.iter().filter_map(|id| stored.get(*id).map(|v| ((*id).clone(), v.clone()))).collect();
        clear.extend(decrypt_values(&only_plain));
    }
    secret_ids.sort();
    (clear, secret_ids)
}

// ── virtual servers: client headers and the collision rule ─────────────────

/// What a virtual server asks of its clients: the headers its routed upstreams
/// read from the client, and whether one of them is `Authorization` (so the
/// gateway key must ride the `/fwd/{key}/mcp/<slug>` path instead).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct VsClientFacts {
    /// Lowercased, sorted, deduplicated.
    pub client_headers: Vec<String>,
    /// The same headers as the declarations spell them, in the same order.
    pub declared_names: Vec<String>,
    pub fwd_mount: bool,
    /// Every routed upstream carries only what the client sends, its own
    /// `Authorization` included (no OAuth, no admin or user input): the only
    /// servers a pass-through (`vk-`) key may reach.
    pub pass_through: bool,
}

impl VsClientFacts {
    fn from_specs<'a>(all: impl IntoIterator<Item = &'a InputSpec>) -> Self {
        let mut by_lower: BTreeMap<String, String> = BTreeMap::new();
        for s in all.into_iter().filter(|s| s.filler == Filler::Client) {
            by_lower
                .entry(s.declared.header.to_ascii_lowercase())
                .or_insert_with(|| s.declared.header.clone());
        }
        let fwd_mount = by_lower.contains_key("authorization");
        let (client_headers, declared_names) = by_lower.into_iter().unzip();
        Self { client_headers, declared_names, fwd_mount, pass_through: false }
    }
}

#[derive(sqlx::FromRow)]
struct RoutedRemote {
    virtual_server_id: Uuid,
    upstream_id: Uuid,
    remote: sqlx::types::Json<Remote>,
    auth_mode: String,
}

/// [`VsClientFacts`] of each virtual server, over its enabled routes to
/// enabled upstreams (what the gateway serves). A server with none is absent.
pub(crate) async fn vs_client_facts(
    conn: &mut Scoped,
    vs_ids: &[Uuid],
) -> Result<HashMap<Uuid, VsClientFacts>, ApiError> {
    if vs_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows = sqlx::query_as::<_, RoutedRemote>(
        r#"SELECT r.virtual_server_id, u.id AS upstream_id, u.remote, u.auth_mode
           FROM mcp_virtual_routes r
           JOIN mcp_upstream_servers u ON u.tenant_id = r.tenant_id AND u.id = r.upstream_server_id
           WHERE r.virtual_server_id = ANY($1) AND r.enabled AND u.enabled"#,
    )
    .bind(vs_ids)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("load virtual servers' client headers: {e}");
        ApiError::internal("failed to load virtual servers")
    })?;
    let mut specs: HashMap<Uuid, Vec<InputSpec>> = HashMap::new();
    let mut pass_through: HashMap<Uuid, bool> = HashMap::new();
    for r in rows {
        let entry = specs.entry(r.virtual_server_id).or_default();
        let upstream_specs = stored_specs(r.upstream_id, &r.remote, &r.auth_mode);
        let only_client = !is_oauth(&r.auth_mode)
            && upstream_specs.as_ref().is_some_and(|s| {
                s.iter().all(|i| i.filler == Filler::Client)
                    && s.iter().any(|i| i.declared.header.eq_ignore_ascii_case("authorization"))
            });
        *pass_through.entry(r.virtual_server_id).or_insert(true) &= only_client;
        if let Some(s) = upstream_specs {
            entry.extend(s);
        }
    }
    Ok(specs
        .into_iter()
        .map(|(vs, s)| {
            let mut facts = VsClientFacts::from_specs(&s);
            facts.pass_through = pass_through.get(&vs).copied().unwrap_or(false);
            (vs, facts)
        })
        .collect())
}

/// One other upstream bound to a virtual server, for the collision rule.
pub(crate) struct Bound {
    pub virtual_server_slug: String,
    pub upstream_id: Uuid,
    pub upstream_name: String,
    pub specs: Vec<InputSpec>,
}

/// The first binding `specs` (of upstream `upstream_id`) would collide with: a
/// client header another upstream on the same virtual server also reads. An
/// upstream routed twice on one server never collides with itself.
pub(crate) fn first_collision<'a>(
    upstream_id: Uuid,
    specs: &[InputSpec],
    bound: &'a [Bound],
) -> Option<(String, &'a Bound)> {
    bound
        .iter()
        .filter(|b| b.upstream_id != upstream_id)
        .find_map(|b| hi::client_header_collision(specs, &b.specs).map(|h| (h, b)))
}

/// The first upstream among `bound` whose client fills `Authorization`: on a
/// virtual server that signs its clients in with OAuth it can never be
/// reached, since the OAuth client's `Authorization` carries the gateway's
/// token and the `/fwd/{key}/mcp/<slug>` path an own `Authorization` needs
/// takes no OAuth sign-in.
pub(crate) fn first_unusable_on_oauth(bound: &[Bound]) -> Option<&Bound> {
    bound.iter().find(|b| reads_client_authorization(&b.specs))
}

fn oauth_binding_error(virtual_server_slug: &str, upstream_name: &str) -> ApiError {
    ApiError::conflict(
        format!(
            "upstream '{upstream_name}' reads the client's own Authorization header, and virtual \
             server '{virtual_server_slug}' signs its clients in with OAuth, whose Authorization \
             carries the gateway's token — such a client can never reach the upstream; turn OAuth \
             sign-in off on the virtual server, or have the administrator or each user fill \
             Authorization"
        ),
        ApiErrorCode::McpOauthClientAuthorization,
    )
}

fn collision_error(header: &str, b: &Bound) -> ApiError {
    ApiError::conflict(
        format!(
            "the client header '{header}' is already read by upstream '{}' on virtual server '{}' — \
             the gateway could not tell which upstream a client's value is for",
            b.upstream_name, b.virtual_server_slug
        ),
        ApiErrorCode::McpClientHeaderCollision,
    )
}

#[derive(sqlx::FromRow)]
struct BoundRow {
    slug: String,
    upstream_id: Uuid,
    upstream_name: String,
    remote: sqlx::types::Json<Remote>,
    auth_mode: String,
}

fn bound_of(rows: Vec<BoundRow>) -> Vec<Bound> {
    rows.into_iter()
        .map(|r| Bound {
            specs: stored_specs(r.upstream_id, &r.remote, &r.auth_mode).unwrap_or_default(),
            virtual_server_slug: r.slug,
            upstream_id: r.upstream_id,
            upstream_name: r.upstream_name,
        })
        .collect()
}

/// The collision rule, and the OAuth binding rule
/// ([`first_unusable_on_oauth`]) when the virtual server signs its clients in
/// with OAuth, for a route about to bind `upstream_id` on
/// `virtual_server_id`, inside the caller's transaction.
///
/// Lock order (shared with [`check_upstream_collisions`], keep both): the
/// virtual server row `FOR UPDATE` first, then the upstream rows `FOR SHARE`.
/// The virtual server lock serialises two route inserts on one server; the
/// upstream share lock waits for an upstream PATCH changing that upstream's
/// declaration, so the remote read here is the one that commits.
///
/// Answers `None` when the virtual server does not exist, else the new
/// upstream's existence (a route to a missing upstream is the caller's 404).
pub(crate) async fn lock_and_check_route_binding(
    conn: &mut Scoped,
    virtual_server_id: Uuid,
    upstream_id: Uuid,
) -> Result<Option<bool>, ApiError> {
    let fail = |e: sqlx::Error| {
        tracing::error!("route collision check: {e}");
        ApiError::internal("failed to validate route")
    };
    let vs: Option<(String, bool)> =
        sqlx::query_as("SELECT slug, oauth_enabled FROM mcp_virtual_servers WHERE id = $1 FOR UPDATE")
            .bind(virtual_server_id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(fail)?;
    let Some((slug, oauth_enabled)) = vs else { return Ok(None) };
    let rows = sqlx::query_as::<_, BoundRow>(
        r#"SELECT $3::text AS slug, u.id AS upstream_id, u.name AS upstream_name, u.remote, u.auth_mode
           FROM mcp_upstream_servers u
           WHERE u.id = $2
              OR u.id IN (SELECT r.upstream_server_id FROM mcp_virtual_routes r
                          WHERE r.virtual_server_id = $1)
           ORDER BY u.id
           FOR SHARE"#,
    )
    .bind(virtual_server_id)
    .bind(upstream_id)
    .bind(&slug)
    .fetch_all(&mut *conn)
    .await
    .map_err(fail)?;
    let bound = bound_of(rows);
    let Some(new) = bound.iter().find(|b| b.upstream_id == upstream_id) else {
        return Ok(Some(false));
    };
    if let Some((h, b)) = first_collision(upstream_id, &new.specs, &bound) {
        return Err(collision_error(&h, b));
    }
    if oauth_enabled && let Some(b) = first_unusable_on_oauth(std::slice::from_ref(new)) {
        return Err(oauth_binding_error(&slug, &b.upstream_name));
    }
    Ok(Some(true))
}

/// The OAuth binding rule for a virtual server turning OAuth sign-in on,
/// inside the caller's transaction after its `FOR UPDATE` lock on the virtual
/// server row (the first half of the lock order
/// [`lock_and_check_route_binding`] documents): every upstream routed on it is
/// read `FOR SHARE`, so an upstream PATCH changing its declaration commits
/// first or waits.
pub(crate) async fn check_oauth_sign_in_bindings(
    conn: &mut Scoped,
    virtual_server_id: Uuid,
    virtual_server_slug: &str,
) -> Result<(), ApiError> {
    let rows = sqlx::query_as::<_, BoundRow>(
        r#"SELECT $2::text AS slug, u.id AS upstream_id, u.name AS upstream_name, u.remote, u.auth_mode
           FROM mcp_upstream_servers u
           WHERE u.id IN (SELECT r.upstream_server_id FROM mcp_virtual_routes r
                          WHERE r.virtual_server_id = $1)
           ORDER BY u.name, u.id
           FOR SHARE"#,
    )
    .bind(virtual_server_id)
    .bind(virtual_server_slug)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("virtual server OAuth binding check: {e}");
        ApiError::internal("failed to update mcp virtual server")
    })?;
    let bound = bound_of(rows);
    match first_unusable_on_oauth(&bound) {
        Some(b) => Err(oauth_binding_error(virtual_server_slug, &b.upstream_name)),
        None => Ok(()),
    }
}

/// Lock every virtual server `upstream_id` is routed on (`FOR UPDATE`, in id
/// order) — the first half of the lock order [`lock_and_check_route_binding`]
/// documents. Returns the locked ids.
pub(crate) async fn lock_upstream_virtual_servers(
    conn: &mut Scoped,
    upstream_id: Uuid,
) -> Result<Vec<Uuid>, ApiError> {
    sqlx::query_scalar(
        r#"SELECT vs.id FROM mcp_virtual_servers vs
           WHERE vs.id IN (SELECT r.virtual_server_id FROM mcp_virtual_routes r
                           WHERE r.upstream_server_id = $1)
           ORDER BY vs.id
           FOR UPDATE"#,
    )
    .bind(upstream_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("lock upstream's virtual servers: {e}");
        ApiError::internal("failed to update mcp upstream server")
    })
}

/// The collision rule — and the OAuth binding rule
/// ([`first_unusable_on_oauth`]) — for an upstream whose declaration changes
/// to `specs`,
/// inside the caller's transaction, after [`lock_upstream_virtual_servers`]
/// and the upstream's own row lock. A route created between the two locks
/// (it committed before the row lock was granted) is locked here too.
pub(crate) async fn check_upstream_collisions(
    conn: &mut Scoped,
    upstream_id: Uuid,
    upstream_name: &str,
    specs: &[InputSpec],
    locked: &[Uuid],
) -> Result<(), ApiError> {
    let fail = |e: sqlx::Error| {
        tracing::error!("upstream collision check: {e}");
        ApiError::internal("failed to update mcp upstream server")
    };
    let now: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT virtual_server_id FROM mcp_virtual_routes WHERE upstream_server_id = $1",
    )
    .bind(upstream_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(fail)?;
    let late: Vec<Uuid> = now.iter().filter(|id| !locked.contains(id)).copied().collect();
    if !late.is_empty() {
        sqlx::query("SELECT id FROM mcp_virtual_servers WHERE id = ANY($1) ORDER BY id FOR UPDATE")
            .bind(&late)
            .execute(&mut *conn)
            .await
            .map_err(fail)?;
    }
    let rows = sqlx::query_as::<_, BoundRow>(
        r#"SELECT vs.slug, u.id AS upstream_id, u.name AS upstream_name, u.remote, u.auth_mode
           FROM mcp_virtual_routes r
           JOIN mcp_virtual_servers vs ON vs.tenant_id = r.tenant_id AND vs.id = r.virtual_server_id
           JOIN mcp_upstream_servers u ON u.tenant_id = r.tenant_id AND u.id = r.upstream_server_id
           WHERE r.virtual_server_id = ANY($1) AND u.id <> $2
           ORDER BY vs.slug, u.id"#,
    )
    .bind(&now)
    .bind(upstream_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(fail)?;
    let bound = bound_of(rows);
    if let Some((h, b)) = first_collision(upstream_id, specs, &bound) {
        return Err(collision_error(&h, b));
    }
    if reads_client_authorization(specs) {
        let oauth_vs: Option<String> = sqlx::query_scalar(
            "SELECT slug FROM mcp_virtual_servers WHERE id = ANY($1) AND oauth_enabled ORDER BY slug LIMIT 1",
        )
        .bind(&now)
        .fetch_optional(&mut *conn)
        .await
        .map_err(fail)?;
        if let Some(slug) = oauth_vs {
            return Err(oauth_binding_error(&slug, upstream_name));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;
    use streamscope_core::mcp::header_inputs::{Input, InputsMeta, RemoteMeta};

    fn header(name: &str, secret: bool, required: bool) -> KeyValueInput {
        KeyValueInput {
            name: name.into(),
            input: Input { is_secret: secret, is_required: required, ..Default::default() },
            variables: BTreeMap::new(),
        }
    }

    fn remote(headers: Vec<KeyValueInput>, fillers: &[(&str, Filler)]) -> Remote {
        Remote {
            url: "https://mcp.example/mcp".into(),
            headers,
            meta: Some(RemoteMeta {
                inputs: InputsMeta { fillers: fillers.iter().map(|(k, f)| (k.to_string(), *f)).collect() },
                ..RemoteMeta::default()
            }),
            ..Default::default()
        }
    }

    /// A stored admin value the edited declaration no longer accepts is
    /// refused (naming the input, never the value); one it still accepts is
    /// kept (the positive control).
    #[test]
    fn a_stored_admin_value_must_fit_its_changed_declaration() {
        // SAFETY: same value as every other ENCRYPTION_KEY setter in this binary.
        unsafe {
            std::env::set_var("ENCRYPTION_KEY", "test-oidc-flow-key-long-enough");
        }
        let mut region = header("X-Region", false, true);
        region.input.choices = vec!["eu".into(), "us".into()];
        let r = remote(vec![region], &[("X-Region", Filler::Admin)]);
        let specs = specs_of(&r, "headers").expect("valid");
        let stored = |v: &str| HashMap::from([("X-Region".to_string(), encrypt_value(v).expect("encrypts"))]);
        assert!(require_stored_values_valid(&specs, Filler::Admin, &stored("eu")).is_ok());
        let err = require_stored_values_valid(&specs, Filler::Admin, &stored("apac")).unwrap_err();
        assert_eq!(err.code, ApiErrorCode::McpRemoteInvalid);
        assert!(err.message.contains("X-Region") && !err.message.contains("apac"), "{}", err.message);
    }

    fn jira() -> (Remote, Vec<InputSpec>) {
        let r = remote(
            vec![
                header("X-Jira-Url", false, true),
                header("X-Jira-Token", true, true),
                header("X-Team", false, false),
                header("X-Client-Key", true, false),
            ],
            &[
                ("X-Jira-Url", Filler::Admin),
                ("X-Jira-Token", Filler::User),
                ("X-Team", Filler::User),
                ("X-Client-Key", Filler::Client),
            ],
        );
        let specs = hi::validate_fillers(&r, false).unwrap();
        (r, specs)
    }

    fn m(pairs: &[(&str, Option<&str>)]) -> HashMap<String, Option<String>> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.map(str::to_string))).collect()
    }

    #[test]
    fn inputs_null_clears_and_a_value_sets() {
        let (r, s) = jira();
        let ops = plan_value_patch(&r, &s, Filler::User, &m(&[("X-Team", Some("blue"))]), &m(&[])).unwrap();
        assert_eq!(ops, vec![ValueOp::Set { id: "X-Team".into(), value: "blue".into() }]);
        let ops = plan_value_patch(&r, &s, Filler::User, &m(&[("X-Team", None)]), &m(&[])).unwrap();
        assert_eq!(ops, vec![ValueOp::Remove("X-Team".into())]);
    }

    #[test]
    fn secret_inputs_null_keeps_blank_clears_and_a_value_sets() {
        let (r, s) = jira();
        let keep = plan_value_patch(&r, &s, Filler::User, &m(&[]), &m(&[("X-Jira-Token", None)])).unwrap();
        assert!(keep.is_empty());
        let clear = plan_value_patch(&r, &s, Filler::User, &m(&[]), &m(&[("X-Jira-Token", Some(""))])).unwrap();
        assert_eq!(clear, vec![ValueOp::Remove("X-Jira-Token".into())]);
        let set = plan_value_patch(&r, &s, Filler::User, &m(&[]), &m(&[("X-Jira-Token", Some("t"))])).unwrap();
        assert_eq!(set, vec![ValueOp::Set { id: "X-Jira-Token".into(), value: "t".into() }]);
    }

    #[test]
    fn a_secret_value_under_inputs_is_refused_and_a_plain_one_under_secret_inputs_is_kept() {
        let (r, s) = jira();
        assert_eq!(
            plan_value_patch(&r, &s, Filler::User, &m(&[("X-Jira-Token", Some("t"))]), &m(&[])),
            Err(PatchRefusal::SecretUnderInputs("X-Jira-Token".into()))
        );
        // Over-redacting a plain value costs nothing: accepted.
        assert!(plan_value_patch(&r, &s, Filler::User, &m(&[]), &m(&[("X-Team", Some("b"))])).is_ok());
    }

    #[test]
    fn a_user_naming_an_admin_input_is_told_it_is_locked_and_other_fillers_are_unknown() {
        let (r, s) = jira();
        assert_eq!(
            plan_value_patch(&r, &s, Filler::User, &m(&[("X-Jira-Url", Some("https://x"))]), &m(&[])),
            Err(PatchRefusal::Locked("X-Jira-Url".into()))
        );
        assert_eq!(
            plan_value_patch(&r, &s, Filler::User, &m(&[]), &m(&[("X-Client-Key", Some("k"))])),
            Err(PatchRefusal::Unknown("X-Client-Key".into()))
        );
        assert_eq!(
            plan_value_patch(&r, &s, Filler::User, &m(&[("X-Nope", Some("k"))]), &m(&[])),
            Err(PatchRefusal::Unknown("X-Nope".into()))
        );
        // The admin side: a user input is unknown to it, never "locked".
        assert_eq!(
            plan_value_patch(&r, &s, Filler::Admin, &m(&[("X-Team", Some("b"))]), &m(&[])),
            Err(PatchRefusal::Unknown("X-Team".into()))
        );
        // Positive control: the admin sets its own input.
        assert!(plan_value_patch(&r, &s, Filler::Admin, &m(&[("X-Jira-Url", Some("https://j"))]), &m(&[])).is_ok());
    }

    #[test]
    fn an_id_under_both_maps_and_an_invalid_value_are_refused() {
        let (r, s) = jira();
        assert_eq!(
            plan_value_patch(&r, &s, Filler::User, &m(&[("X-Team", Some("a"))]), &m(&[("X-Team", Some("b"))])),
            Err(PatchRefusal::Twice("X-Team".into()))
        );
        assert_matches!(
            plan_value_patch(&r, &s, Filler::User, &m(&[("X-Team", Some("a\nb"))]), &m(&[])),
            Err(PatchRefusal::Invalid(_))
        );
    }

    #[test]
    fn a_required_input_without_a_value_or_default_is_named() {
        let (_, s) = jira();
        let err = require_filled(&s, Filler::Admin, &HashMap::new()).unwrap_err();
        assert_eq!(err.code, ApiErrorCode::McpInputRequired);
        let filled: HashMap<String, String> = [("X-Jira-Url".to_string(), "ct".to_string())].into();
        assert!(require_filled(&s, Filler::Admin, &filled).is_ok());
        // An optional user input is never required.
        assert_eq!(required_ids(&s, Filler::User), vec!["X-Jira-Token".to_string()]);
    }

    #[test]
    fn the_admin_view_shows_plain_values_and_only_the_ids_of_secret_ones() {
        let r = remote(
            vec![header("X-Url", false, true), header("Authorization", true, true)],
            &[("X-Url", Filler::Admin), ("Authorization", Filler::Admin)],
        );
        let s = hi::validate_fillers(&r, false).unwrap();
        let stored: HashMap<String, String> =
            [("Authorization".to_string(), "not-decrypted".to_string())].into();
        let (clear, secret) = admin_values_view(&r, Some(&s), &stored);
        assert!(clear.is_empty(), "a secret's value is never shown");
        assert_eq!(secret, vec!["Authorization".to_string()]);
        // An invalid stored remote shows nothing.
        let (clear, secret) = admin_values_view(&r, None, &stored);
        assert!(clear.is_empty() && secret.is_empty());
    }

    #[test]
    fn client_facts_union_the_routed_upstreams_and_flag_authorization() {
        let a = remote(vec![header("X-Key", true, true)], &[("X-Key", Filler::Client)]);
        let b = remote(vec![header("Authorization", true, true)], &[("Authorization", Filler::Client)]);
        let c = remote(vec![header("X-Admin", false, true)], &[("X-Admin", Filler::Admin)]);
        let mut all = hi::validate_fillers(&a, false).unwrap();
        all.extend(hi::validate_fillers(&c, false).unwrap());
        let facts = VsClientFacts::from_specs(&all);
        assert_eq!(facts.client_headers, vec!["x-key".to_string()]);
        assert_eq!(facts.declared_names, vec!["X-Key".to_string()]);
        assert!(!facts.fwd_mount);
        all.extend(hi::validate_fillers(&b, false).unwrap());
        let facts = VsClientFacts::from_specs(&all);
        assert_eq!(facts.client_headers, vec!["authorization".to_string(), "x-key".to_string()]);
        assert!(facts.fwd_mount);
    }

    fn vars_remote(url: &str, vars: &[(&str, Option<&str>)]) -> Remote {
        Remote {
            url: url.into(),
            variables: vars
                .iter()
                .map(|(n, d)| ((*n).to_string(), Input { default: d.map(str::to_string), ..Default::default() }))
                .collect(),
            ..Default::default()
        }
    }

    fn sm(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    /// What a row stores is every value the URL was finished with: the given
    /// one, else the default; a variable with neither is not recorded.
    #[test]
    fn the_stored_url_values_are_the_given_ones_and_the_defaults_used() {
        let r = vars_remote("https://{region}.example/{tenant}/mcp", &[("region", Some("eu")), ("tenant", None), ("x", None)]);
        let given: HashMap<String, String> = [("tenant".to_string(), "acme".to_string())].into();
        assert_eq!(url_values_used(&r, &given), sm(&[("region", "eu"), ("tenant", "acme")]));
        let given: HashMap<String, String> =
            [("region".to_string(), "us".to_string()), ("tenant".to_string(), "acme".to_string())].into();
        assert_eq!(url_values_used(&r, &given), sm(&[("region", "us"), ("tenant", "acme")]));
    }

    /// A PATCH merges its variables onto the stored ones: one left out keeps
    /// its stored value (not the default), one sent replaces it, one the new
    /// template no longer declares is dropped, and one the template uses with
    /// neither a stored nor a sent value is refused — its default too.
    #[test]
    fn a_patch_merges_url_variables_onto_the_stored_values() {
        let r = vars_remote("https://{region}.example/{tenant}/mcp", &[("region", Some("eu")), ("tenant", None)]);
        let stored = sm(&[("region", "us"), ("tenant", "acme"), ("gone", "x")]);
        // Absent body: the stored values, never the default.
        let vars = merged_url_variables(&r, &stored, None).unwrap();
        assert_eq!(hi::finish_url(&r, &vars).unwrap(), "https://us.example/acme/mcp");
        // One sent: it replaces only its own.
        let body: HashMap<String, String> = [("tenant".to_string(), "beta".to_string())].into();
        let vars = merged_url_variables(&r, &stored, Some(&body)).unwrap();
        assert_eq!(hi::finish_url(&r, &vars).unwrap(), "https://us.example/beta/mcp");
        assert!(!vars.contains_key("gone"), "a variable the template no longer declares is dropped");
        // Neither stored nor sent: refused even with a default (a row stored
        // with no values must not be repointed through it)…
        assert_eq!(
            merged_url_variables(&r, &sm(&[("tenant", "acme")]), None),
            Err(RemoteError::MissingUrlVariable("region".into()))
        );
        assert_eq!(merged_url_variables(&r, &sm(&[]), None), Err(RemoteError::MissingUrlVariable("region".into())));
        // …and the body's value is enough (positive control).
        let body: HashMap<String, String> = [("region".to_string(), "eu".to_string())].into();
        let vars = merged_url_variables(&r, &sm(&[("tenant", "acme")]), Some(&body)).unwrap();
        assert_eq!(hi::finish_url(&r, &vars).unwrap(), "https://eu.example/acme/mcp");
        // A declared variable the template does not use needs nothing.
        let unused = vars_remote("https://fixed.example/mcp", &[("spare", None)]);
        assert!(merged_url_variables(&unused, &sm(&[]), None).is_ok());
        // A body naming an undeclared variable is refused.
        let body: HashMap<String, String> = [("nope".to_string(), "v".to_string())].into();
        assert_matches!(
            hi::finish_url(&r, &merged_url_variables(&r, &stored, Some(&body)).unwrap()),
            Err(RemoteError::UnknownUrlVariable(_))
        );
    }

    /// An upstream whose client fills `Authorization` is the one an OAuth
    /// sign-in server can never reach; one whose administrator fills it, or
    /// whose client fills another header, is reachable (the controls).
    #[test]
    fn only_a_client_filled_authorization_is_unusable_behind_oauth_sign_in() {
        let header_decl = |name: &str| header(name, true, true);
        let bound = |name: &str, h: &str, f: Filler| Bound {
            virtual_server_slug: "vs".into(),
            upstream_id: Uuid::new_v4(),
            upstream_name: name.into(),
            specs: hi::validate_fillers(&remote(vec![header_decl(h)], &[(h, f)]), false)
                .unwrap(),
        };
        let ok = vec![bound("admin", "Authorization", Filler::Admin), bound("key", "X-Key", Filler::Client)];
        assert!(first_unusable_on_oauth(&ok).is_none());
        let mut bad = ok;
        bad.push(bound("gh", "authorization", Filler::Client));
        assert_eq!(first_unusable_on_oauth(&bad).map(|b| b.upstream_name.as_str()), Some("gh"));
        assert!(reads_client_authorization(&bad[2].specs) && !reads_client_authorization(&bad[0].specs));
    }

    #[test]
    fn two_upstreams_on_one_server_may_not_share_a_client_header() {
        let mine = remote(vec![header("X-Key", true, true)], &[("X-Key", Filler::Client)]);
        let mine = hi::validate_fillers(&mine, false).unwrap();
        let other_id = Uuid::new_v4();
        let me = Uuid::new_v4();
        let bound = |r: Remote, id: Uuid| Bound {
            virtual_server_slug: "vs".into(),
            upstream_id: id,
            upstream_name: "other".into(),
            specs: hi::validate_fillers(&r, false).unwrap(),
        };
        // Same name, other case, on another upstream: collides.
        let clash = vec![bound(remote(vec![header("x-key", true, true)], &[("x-key", Filler::Client)]), other_id)];
        assert_eq!(first_collision(me, &mine, &clash).map(|(h, _)| h), Some("x-key".to_string()));
        // The same header filled by the admin there: no collision.
        let admin = vec![bound(remote(vec![header("X-Key", true, true)], &[("X-Key", Filler::Admin)]), other_id)];
        assert!(first_collision(me, &mine, &admin).is_none());
        // The same upstream routed twice never collides with itself.
        let twice = vec![bound(remote(vec![header("X-Key", true, true)], &[("X-Key", Filler::Client)]), me)];
        assert!(first_collision(me, &mine, &twice).is_none());
    }
}

//! The canonical MCP server description (`server.json`, MCP Registry schema
//! 2025-12-11) and the header inputs an upstream declares.
//!
//! A catalog entry is a [`ServerJson`] document. Adopting it picks one of its
//! [`Remote`]s; the remote's `headers[]` are [`KeyValueInput`]s, each either a
//! plain input (the header's value *is* the input) or a `{var}` template whose
//! `variables` are the inputs. Every input gets a [`Filler`] at adopt, stored
//! in the remote's `_meta` under [`INPUTS_META_KEY`]:
//!
//! - `admin` — filled once, stored encrypted on the upstream, never visible to
//!   or settable by a user;
//! - `user` — filled by each user in the portal, stored encrypted per user;
//! - `client` — sent by the calling client on every request, never stored.
//!
//! [`resolve`] turns a declaration plus the three value sources into the
//! [`UpstreamAuth`] stamped on every upstream request. Each input id has
//! exactly one filler, and [`resolve`] reads an id only from its own filler's
//! source, so a user or client value for an admin input can never reach the
//! wire (locked by `an_input_is_read_only_from_its_own_filler`).
//!
//! Templating is the spec's single-pass `{var}` splice ([`splice`]): a value is
//! never re-scanned, and an identifier with no variable stays literal.

use std::collections::{BTreeMap, HashMap};

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// The `server.json` schema revision the catalog stores.
pub const SERVER_JSON_SCHEMA: &str =
    "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json";

/// `_meta` namespace of a catalog document's gateway-specific facts.
pub const CATALOG_META_KEY: &str = "ai.streamscope/catalog";

/// `_meta` namespace on an adopted remote holding each input's filler.
pub const INPUTS_META_KEY: &str = "ai.streamscope/inputs";

/// Largest value accepted for one input, in bytes.
pub const MAX_INPUT_VALUE_BYTES: usize = 8 * 1024;
/// Most headers one remote may declare.
pub const MAX_HEADERS: usize = 32;
/// Most variables one header template or URL may declare.
pub const MAX_VARIABLES: usize = 16;
const MAX_HEADER_NAME_BYTES: usize = 128;

fn is_false(b: &bool) -> bool {
    !*b
}

// ── server.json types ──────────────────────────────────────────────────────

/// `Input.format`. `filepath` names a file on the user's own machine, which a
/// gateway cannot read, so a declaration using it is refused.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum InputFormat {
    #[default]
    String,
    Number,
    Boolean,
    Filepath,
}

impl InputFormat {
    fn is_default(&self) -> bool {
        *self == Self::String
    }
}

/// `server.json` `Input`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Input {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_required: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_secret: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub choices: Vec<String>,
    #[serde(default, skip_serializing_if = "InputFormat::is_default")]
    pub format: InputFormat,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    /// A fixed value, or a `{var}` template over `variables` (on a header).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// `server.json` `KeyValueInput` — one declared header.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct KeyValueInput {
    pub name: String,
    #[serde(flatten)]
    pub input: Input,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub variables: BTreeMap<String, Input>,
}

/// `RemoteTransport.type`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum RemoteType {
    #[default]
    #[serde(rename = "streamable-http")]
    StreamableHttp,
    #[serde(rename = "sse")]
    Sse,
}

impl RemoteType {
    /// The gateway's transport column value for this remote type.
    pub fn transport_str(self) -> &'static str {
        match self {
            Self::StreamableHttp => "streamable_http",
            Self::Sse => "sse",
        }
    }
}

/// Who supplies an input's value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Filler {
    /// Filled by the administrator, locked, stored on the upstream.
    Admin,
    /// Filled by each user in the portal, stored per user.
    User,
    /// Sent by the calling client on every request, never stored.
    Client,
}

/// The gateway's own facts on an adopted remote.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct InputsMeta {
    /// Input id → filler. Every input the remote declares has an entry.
    #[serde(default)]
    pub fillers: BTreeMap<String, Filler>,
}

impl InputsMeta {
    /// Whether no filler is set.
    pub fn is_empty(&self) -> bool {
        self.fillers.is_empty()
    }
}

/// `_meta` of a remote: the gateway's own namespace, and every other
/// namespace kept verbatim so a pasted document round-trips.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct RemoteMeta {
    /// Left out when no filler is set, so a pasted document that never had
    /// the namespace reads back exactly as pasted.
    #[serde(rename = "ai.streamscope/inputs", default, skip_serializing_if = "InputsMeta::is_empty")]
    pub inputs: InputsMeta,
    /// Reverse-DNS namespace → vendor object, for every namespace but the
    /// gateway's. The gateway never reads them. Left out of the schema: a
    /// flattened map there makes generated clients type `_meta` as an empty
    /// record, which no object carrying the gateway's namespace fits.
    #[serde(flatten)]
    #[schema(ignore)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

/// `server.json` `RemoteTransport` — a remote endpoint, its URL template and
/// the headers it expects.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Remote {
    #[serde(rename = "type", default)]
    pub kind: RemoteType,
    /// The URL template. Required by the schema, so [`ServerJson::validate`]
    /// and [`finish_url`] refuse an empty one; an adopted upstream's finished
    /// URL is its `upstream_url`, and a built-in upstream stores `{}` here.
    #[serde(default)]
    pub url: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<KeyValueInput>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub variables: BTreeMap<String, Input>,
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<RemoteMeta>,
}

impl Remote {
    /// The filler recorded for an input id.
    pub fn filler(&self, id: &str) -> Option<Filler> {
        self.meta.as_ref()?.inputs.fillers.get(id).copied()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Repository {
    pub url: String,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subfolder: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Icon {
    pub src: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sizes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub theme: Option<String>,
}

/// `server.json` `ServerDetail`. Unknown top-level members are dropped on
/// parse: the stored document is this type's serialization.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServerJson {
    #[serde(rename = "$schema", default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    pub name: String,
    pub description: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub website_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<Repository>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub icons: Vec<Icon>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remotes: Vec<Remote>,
    /// The spec's local `packages[]`, kept verbatim (this type would drop the
    /// members it does not name). The gateway proxies only remotes; a package
    /// is read, typed ([`super::local_server::PackageView`]), when the
    /// document has no remote and when it is adopted as a local server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Vec<Object>>)]
    pub packages: Option<serde_json::Value>,
    /// The spec's extension point: reverse-DNS namespace → vendor object. The
    /// gateway reads only [`CATALOG_META_KEY`]; other namespaces round-trip.
    #[serde(rename = "_meta", default, skip_serializing_if = "serde_json::Map::is_empty")]
    #[schema(value_type = Object)]
    pub meta: serde_json::Map<String, serde_json::Value>,
}

/// A tool a catalog entry advertised when it was imported.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct CatalogTool {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// OAuth endpoints an entry's server is known to use, for a per-user OAuth
/// adopt when the server publishes no metadata.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OAuthHints {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_url: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub default_scopes: Vec<String>,
}

/// `_meta["ai.streamscope/catalog"]` of a catalog document.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CatalogMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub featured: bool,
    /// `alive` | `auth_required` | `dead`, as probed when the entry was
    /// generated; absent when it was not probed (a templated URL names no host).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub liveness: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<CatalogTool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_count: Option<i32>,
    /// Present when the server authenticates users with OAuth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<OAuthHints>,
}

impl ServerJson {
    /// The gateway's catalog facts; an absent or malformed namespace reads as
    /// empty (it is validated on save by [`ServerJson::validate`]).
    pub fn catalog_meta(&self) -> CatalogMeta {
        self.meta
            .get(CATALOG_META_KEY)
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default()
    }

    pub fn set_catalog_meta(&mut self, meta: &CatalogMeta) {
        match serde_json::to_value(meta) {
            Ok(v) if v.as_object().is_some_and(|o| !o.is_empty()) => {
                self.meta.insert(CATALOG_META_KEY.to_string(), v);
            }
            _ => {
                self.meta.remove(CATALOG_META_KEY);
            }
        }
    }

    /// The display name: `title`, else `name`.
    pub fn display_name(&self) -> &str {
        self.title.as_deref().unwrap_or(&self.name)
    }

    /// Validate against the schema's constraints the gateway relies on, and
    /// every remote's header declaration (without fillers). A document
    /// declares a remote or a package: a way to reach or to start the server.
    pub fn validate(&self) -> Result<(), RemoteError> {
        if !is_valid_server_name(&self.name) {
            return Err(RemoteError::InvalidServerName);
        }
        let desc_len = self.description.chars().count();
        if !(1..=100).contains(&desc_len) {
            return Err(RemoteError::InvalidDescription);
        }
        if let Some(t) = &self.title
            && !(1..=100).contains(&t.chars().count())
        {
            return Err(RemoteError::InvalidTitle);
        }
        if !is_valid_version(&self.version) {
            return Err(RemoteError::InvalidVersion);
        }
        // A document with a remote keeps its `packages` verbatim, whatever
        // they hold: the gateway reaches the server by the remote. With no
        // remote the packages are the only way to start the server, so they
        // are read strictly — a list of typed packages.
        if self.remotes.is_empty() {
            match &self.packages {
                None => return Err(RemoteError::NoTransport),
                Some(serde_json::Value::Array(items)) if items.is_empty() => return Err(RemoteError::NoTransport),
                Some(serde_json::Value::Array(items)) if items.len() <= super::local_server::MAX_PACKAGES => {}
                Some(_) => return Err(RemoteError::InvalidPackages),
            }
            if let Some(i) = self.package_views().iter().position(Option::is_none) {
                return Err(RemoteError::InvalidPackage(i));
            }
        }
        if let Some(v) = self.meta.get(CATALOG_META_KEY)
            && serde_json::from_value::<CatalogMeta>(v.clone()).is_err()
        {
            return Err(RemoteError::InvalidCatalogMeta);
        }
        for remote in &self.remotes {
            declared_inputs(remote)?;
            validate_url_template(remote)?;
        }
        Ok(())
    }
}

/// `^[a-zA-Z0-9.-]+/[a-zA-Z0-9._-]+$`, 3..=200 characters.
pub fn is_valid_server_name(name: &str) -> bool {
    if !(3..=200).contains(&name.len()) {
        return false;
    }
    let Some((ns, local)) = name.split_once('/') else {
        return false;
    };
    !ns.is_empty()
        && !local.is_empty()
        && ns.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && local.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

/// A version string, never a range (`^1`, `~1`, `>=1`, `1 - 2`, `1 || 2`, `*`,
/// `1.x`, `1.*`) nor the registry-reserved `latest`.
pub fn is_valid_version(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 255
        && !v.eq_ignore_ascii_case("latest")
        && !v.starts_with(['^', '~', '>', '<', '=', '*'])
        && !v.contains("||")
        && !v.split('.').any(|part| matches!(part, "x" | "X" | "*"))
        && !v.chars().any(char::is_whitespace)
        && !v.chars().any(char::is_control)
}

// ── declaration ─────────────────────────────────────────────────────────────

/// Why a declaration, a filler set or a value was refused. Its `Display` is the
/// message the admin API returns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RemoteError {
    InvalidServerName,
    InvalidDescription,
    InvalidTitle,
    InvalidVersion,
    /// Neither a remote endpoint nor a package.
    NoTransport,
    /// With no remote: `packages` is not a list, or holds too many entries.
    InvalidPackages,
    /// The package at this index lacks `registryType`, `identifier` or
    /// `transport.type`.
    InvalidPackage(usize),
    InvalidCatalogMeta,
    InvalidUrl,
    TooManyHeaders,
    TooManyVariables(String),
    InvalidHeaderName(String),
    DuplicateHeader(String),
    ReservedHeader(String),
    /// `Authorization` declared on an upstream whose OAuth token owns it.
    ReservedForOauth,
    SecretWithDefault(String),
    SecretLiteral(String),
    Filepath(String),
    InvalidLiteral(String),
    MissingFiller(String),
    UnknownFiller(String),
    MixedFillers(String),
    /// A template's variables disagree on `isRequired`, so a filled required
    /// one could still leave the header unsent.
    MixedRequired(String),
    /// A client-filled input must be a whole header (no template).
    ClientTemplate(String),
    /// A legacy SSE remote keeps a long-lived connection of the gateway's own,
    /// which would go on carrying one client's value after its request.
    ClientOnSse(String),
    SecretUrlVariable(String),
    UnknownUrlVariable(String),
    MissingUrlVariable(String),
    InvalidValue { id: String, reason: &'static str },
}

impl std::fmt::Display for RemoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidServerName => f.write_str(
                "name must be reverse-DNS with exactly one '/' (e.g. io.github.user/weather), 3-200 characters",
            ),
            Self::InvalidDescription => f.write_str("description must be 1-100 characters"),
            Self::InvalidTitle => f.write_str("title must be 1-100 characters"),
            Self::InvalidVersion => f.write_str("version must be a version string, not a range"),
            Self::NoTransport => f.write_str("the server declares neither a remote endpoint nor a package"),
            Self::InvalidPackages => write!(
                f,
                "packages must be a list of at most {} packages",
                super::local_server::MAX_PACKAGES
            ),
            Self::InvalidPackage(i) => write!(
                f,
                "package {} needs a registryType, an identifier and a transport type",
                i + 1
            ),
            Self::InvalidCatalogMeta => write!(f, "_meta.\"{CATALOG_META_KEY}\" is malformed"),
            Self::InvalidUrl => f.write_str("remote url must be an http(s) URL"),
            Self::TooManyHeaders => write!(f, "a remote may declare at most {MAX_HEADERS} headers"),
            Self::TooManyVariables(h) => {
                write!(f, "'{h}' declares more than {MAX_VARIABLES} variables")
            }
            Self::InvalidHeaderName(h) => write!(f, "'{h}' is not a valid header name"),
            Self::DuplicateHeader(h) => write!(f, "header '{h}' is declared twice"),
            Self::ReservedHeader(h) => write!(f, "header '{h}' is set by the gateway and cannot be declared"),
            Self::ReservedForOauth => {
                f.write_str("Authorization carries the user's OAuth token on this server and cannot be declared")
            }
            Self::SecretWithDefault(id) => write!(f, "secret input '{id}' cannot have a default"),
            Self::SecretLiteral(h) => write!(f, "secret header '{h}' cannot carry a fixed value"),
            Self::Filepath(id) => write!(f, "input '{id}' has format filepath, which a gateway cannot read"),
            Self::InvalidLiteral(h) => write!(f, "the fixed value of header '{h}' is not a valid header value"),
            Self::MissingFiller(id) => write!(f, "input '{id}' needs a filler (admin, user or client)"),
            Self::UnknownFiller(id) => write!(f, "'{id}' is not an input this server declares"),
            Self::MixedFillers(h) => write!(f, "every variable of header '{h}' must have the same filler"),
            Self::MixedRequired(h) => write!(
                f,
                "the variables of header '{h}' must be all required or all optional (or the header itself required)"
            ),
            Self::ClientTemplate(id) => {
                write!(f, "input '{id}' is part of a header template and cannot be filled by the client")
            }
            Self::ClientOnSse(id) => write!(
                f,
                "input '{id}' cannot be filled by the client on an SSE remote; use streamable-http or another filler"
            ),
            Self::SecretUrlVariable(v) => write!(f, "URL variable '{v}' cannot be secret"),
            Self::UnknownUrlVariable(v) => write!(f, "'{v}' is not a URL variable of this remote"),
            Self::MissingUrlVariable(v) => write!(f, "URL variable '{v}' needs a value"),
            Self::InvalidValue { id, reason } => write!(f, "value of '{id}' {reason}"),
        }
    }
}

impl std::error::Error for RemoteError {}

/// Whether the gateway owns a header, so no declaration may set it. Compared
/// case-insensitively. `Authorization` is not reserved here (it is on an OAuth
/// upstream, see [`validate_fillers`]).
pub fn is_reserved_header(name: &str) -> bool {
    const EXACT: &[&str] = &[
        "host",
        "origin",
        "cookie",
        "user-agent",
        "last-event-id",
        "mcp-session-id",
        "mcp-protocol-version",
        "mcp-method",
        "mcp-name",
        "forwarded",
        "via",
        "expect",
        "range",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "connection",
        "keep-alive",
        "x-session-id",
        "x-tenant-slug",
    ];
    const PREFIX: &[&str] = &["content-", "accept", "proxy-", "sec-", "x-forwarded-", "x-auth-request-"];
    let lower = name.to_ascii_lowercase();
    EXACT.contains(&lower.as_str()) || PREFIX.iter().any(|p| lower.starts_with(p))
}

/// One input a remote declares.
#[derive(Clone, Debug, PartialEq)]
pub struct DeclaredInput {
    /// The header name for a whole-header input, `<header>/<var>` for a
    /// template variable (`/` is not a header-name character, so the two
    /// spaces never collide).
    pub id: String,
    pub header: String,
    pub var: Option<String>,
    pub input: Input,
    /// The header is not sent without this value.
    pub required: bool,
}

impl DeclaredInput {
    /// A secret is the input's own flag, or the header's for a template variable.
    pub fn is_secret(&self, header: &KeyValueInput) -> bool {
        self.input.is_secret || header.input.is_secret
    }
}

/// The `{var}` names a template references, in order of first appearance.
fn template_vars<'a>(template: &'a str, declared: &BTreeMap<String, Input>) -> Vec<&'a str> {
    let mut out: Vec<&str> = Vec::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        match after.find('}') {
            Some(close) => {
                let key = &after[..close];
                if declared.contains_key(key) {
                    if !out.contains(&key) {
                        out.push(key);
                    }
                    // A matched name is consumed whole, as `splice` does.
                    rest = &after[close + 1..];
                } else {
                    // Resume after `{` so `{{a}` still sees `{a}` (as `splice`).
                    rest = after;
                }
            }
            None => break,
        }
    }
    out
}

/// Validate a remote's header declaration and list its inputs. No filler is
/// read here.
pub fn declared_inputs(remote: &Remote) -> Result<Vec<DeclaredInput>, RemoteError> {
    if remote.headers.len() > MAX_HEADERS {
        return Err(RemoteError::TooManyHeaders);
    }
    let mut seen: Vec<String> = Vec::new();
    let mut out = Vec::new();
    for h in &remote.headers {
        if h.name.len() > MAX_HEADER_NAME_BYTES || HeaderName::from_bytes(h.name.as_bytes()).is_err() {
            return Err(RemoteError::InvalidHeaderName(h.name.clone()));
        }
        let lower = h.name.to_ascii_lowercase();
        if seen.contains(&lower) {
            return Err(RemoteError::DuplicateHeader(h.name.clone()));
        }
        seen.push(lower);
        if is_reserved_header(&h.name) {
            return Err(RemoteError::ReservedHeader(h.name.clone()));
        }
        if h.variables.len() > MAX_VARIABLES {
            return Err(RemoteError::TooManyVariables(h.name.clone()));
        }
        check_input(&h.name, &h.input)?;
        match &h.input.value {
            None => out.push(DeclaredInput {
                id: h.name.clone(),
                header: h.name.clone(),
                var: None,
                input: h.input.clone(),
                required: h.input.is_required,
            }),
            Some(template) => {
                let vars = template_vars(template, &h.variables);
                if vars.is_empty() {
                    // A fixed value: no input, and never a secret in the document.
                    if h.input.is_secret {
                        return Err(RemoteError::SecretLiteral(h.name.clone()));
                    }
                    if !is_field_value(template) {
                        return Err(RemoteError::InvalidLiteral(h.name.clone()));
                    }
                    continue;
                }
                // The template's own text must form a header value once its
                // variables are filled; checked with a stand-in for each, so a
                // template that can never be sent is refused here, not on
                // every request.
                let stand_in: HashMap<&str, &str> = vars.iter().map(|v| (*v, "x")).collect();
                if !is_field_value(&splice(template, &stand_in)) {
                    return Err(RemoteError::InvalidLiteral(h.name.clone()));
                }
                // The header is sent only when every variable has a value, so
                // a required variable beside an optional one would leave it
                // unsent with nothing reported missing.
                if !h.input.is_required
                    && vars.iter().any(|v| h.variables[*v].is_required)
                    && vars.iter().any(|v| !h.variables[*v].is_required)
                {
                    return Err(RemoteError::MixedRequired(h.name.clone()));
                }
                for var in vars {
                    let input = &h.variables[var];
                    let id = format!("{}/{var}", h.name);
                    check_input(&id, input)?;
                    // A variable of a secret header is a secret too (it is
                    // redacted as one), so it may not carry a default either.
                    if h.input.is_secret && input.default.is_some() {
                        return Err(RemoteError::SecretWithDefault(id));
                    }
                    out.push(DeclaredInput {
                        id,
                        header: h.name.clone(),
                        var: Some(var.to_string()),
                        input: input.clone(),
                        required: input.is_required || h.input.is_required,
                    });
                }
            }
        }
    }
    Ok(out)
}

fn check_input(id: &str, input: &Input) -> Result<(), RemoteError> {
    if input.format == InputFormat::Filepath {
        return Err(RemoteError::Filepath(id.to_string()));
    }
    if input.is_secret && input.default.is_some() {
        return Err(RemoteError::SecretWithDefault(id.to_string()));
    }
    // A default is sent as a value: it must be one, like any value given.
    if let Some(default) = &input.default {
        validate_value(id, input, default)?;
    }
    Ok(())
}

/// The URL template must be `http(s)://…`; its variables are never secret.
fn validate_url_template(remote: &Remote) -> Result<(), RemoteError> {
    let u = remote.url.as_str();
    let rest = u.strip_prefix("https://").or_else(|| u.strip_prefix("http://"));
    if !rest.is_some_and(|r| !r.is_empty() && !r.starts_with(['/', '?', '#']))
        || u.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(RemoteError::InvalidUrl);
    }
    if remote.variables.len() > MAX_VARIABLES {
        return Err(RemoteError::TooManyVariables("url".into()));
    }
    for (name, input) in &remote.variables {
        if input.is_secret {
            return Err(RemoteError::SecretUrlVariable(name.clone()));
        }
        if input.format == InputFormat::Filepath {
            return Err(RemoteError::Filepath(name.clone()));
        }
        // A default fills the address as a value would: checked as one.
        if let Some(default) = &input.default {
            validate_url_value(name, input, default)?;
        }
    }
    // A `{name}` the remote never declares would stay in the address as is,
    // and every request would go to a path nobody meant.
    if let Some(undeclared) = template_names(u).into_iter().find(|n| !remote.variables.contains_key(*n)) {
        return Err(RemoteError::MissingUrlVariable(undeclared.to_string()));
    }
    Ok(())
}

/// A URL variable's value (or default): a valid value of its input that
/// cannot change the address. A value is spliced as is, so one able to end
/// the host or start a path, query, fragment or userinfo would move the
/// request to another server. A `:` port is fine: alone it cannot name
/// another host.
fn validate_url_value(name: &str, input: &Input, v: &str) -> Result<(), RemoteError> {
    validate_value(name, input, v)?;
    if v.contains(['/', '?', '#', '@', '\\']) || v.chars().any(char::is_whitespace) {
        return Err(RemoteError::InvalidValue {
            id: name.to_string(),
            reason: "holds a character that would change the address (/ ? # @ \\ or a space)",
        });
    }
    Ok(())
}

/// Every `{name}` a URL template holds (a name being `[A-Za-z0-9_.-]+`).
fn template_names(template: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        match after.find('}') {
            Some(close) => {
                let name = &after[..close];
                if !name.is_empty()
                    && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
                {
                    out.push(name);
                    rest = &after[close + 1..];
                } else {
                    rest = after;
                }
            }
            None => break,
        }
    }
    out
}

/// One input with the filler an adopted remote gives it.
#[derive(Clone, Debug, PartialEq)]
pub struct InputSpec {
    pub declared: DeclaredInput,
    pub filler: Filler,
}

/// Validate an adopted remote: its declaration, then its fillers. Every input
/// has exactly one filler and no filler names an undeclared id; the variables
/// of one template share a filler; a client input is a whole header, on a
/// streamable-http remote; on an OAuth upstream, `Authorization` is the
/// token's.
pub fn validate_fillers(remote: &Remote, oauth: bool) -> Result<Vec<InputSpec>, RemoteError> {
    let declared = declared_inputs(remote)?;
    if oauth
        && remote.headers.iter().any(|h| h.name.eq_ignore_ascii_case("authorization"))
    {
        return Err(RemoteError::ReservedForOauth);
    }
    let fillers = remote.meta.as_ref().map(|m| &m.inputs.fillers);
    if let Some(fillers) = fillers {
        for id in fillers.keys() {
            if !declared.iter().any(|d| &d.id == id) {
                return Err(RemoteError::UnknownFiller(id.clone()));
            }
        }
    }
    let mut out: Vec<InputSpec> = Vec::with_capacity(declared.len());
    for d in declared {
        let filler = fillers
            .and_then(|f| f.get(&d.id).copied())
            .ok_or_else(|| RemoteError::MissingFiller(d.id.clone()))?;
        if filler == Filler::Client && d.var.is_some() {
            return Err(RemoteError::ClientTemplate(d.id.clone()));
        }
        if filler == Filler::Client && remote.kind == RemoteType::Sse {
            return Err(RemoteError::ClientOnSse(d.id.clone()));
        }
        if let Some(prev) = out.iter().find(|s| s.declared.header == d.header)
            && prev.filler != filler
        {
            return Err(RemoteError::MixedFillers(d.header.clone()));
        }
        out.push(InputSpec { declared: d, filler });
    }
    Ok(out)
}

/// The lowercased header names a client must send for an adopted remote.
pub fn client_header_names(specs: &[InputSpec]) -> Vec<String> {
    specs
        .iter()
        .filter(|s| s.filler == Filler::Client)
        .map(|s| s.declared.header.to_ascii_lowercase())
        .collect()
}

/// The ids of the user inputs a user must fill before the upstream is usable:
/// required, user-filled, with no default.
pub fn required_user_input_ids(specs: &[InputSpec]) -> Vec<String> {
    specs
        .iter()
        .filter(|s| s.filler == Filler::User && s.declared.required && s.declared.input.default.is_none())
        .map(|s| s.declared.id.clone())
        .collect()
}

/// A client header two upstreams of one virtual server would both claim, if
/// any (case-insensitive). The gateway could not tell which upstream it is
/// for, so a binding that creates one is refused.
pub fn client_header_collision(a: &[InputSpec], b: &[InputSpec]) -> Option<String> {
    let names_b = client_header_names(b);
    client_header_names(a).into_iter().find(|n| names_b.contains(n))
}

// ── values ──────────────────────────────────────────────────────────────────

/// RFC 9110 field-value: visible ASCII or obs-text, SP and HTAB inside, no
/// leading or trailing whitespace, not empty.
pub fn is_field_value(v: &str) -> bool {
    !v.is_empty()
        && !v.starts_with([' ', '\t'])
        && !v.ends_with([' ', '\t'])
        && v.bytes().all(|b| b == b'\t' || (b >= 0x20 && b != 0x7f))
}

/// Check one value an admin or user supplies for an input.
pub fn validate_value(id: &str, input: &Input, value: &str) -> Result<(), RemoteError> {
    if value.len() > MAX_INPUT_VALUE_BYTES {
        return Err(RemoteError::InvalidValue { id: id.to_string(), reason: "is too long" });
    }
    validate_sent_value(id, input, value)
}

/// [`validate_value`] without the stored-value size cap, for a value the
/// client sends on its request: its size is the inbound request's own limit
/// (a client's JWT may well pass 8 KiB), and it is never stored.
fn validate_sent_value(id: &str, input: &Input, value: &str) -> Result<(), RemoteError> {
    let err = |reason| RemoteError::InvalidValue { id: id.to_string(), reason };
    if !is_field_value(value) {
        return Err(err("is empty or holds a character a header cannot carry"));
    }
    if !input.choices.is_empty() && !input.choices.iter().any(|c| c == value) {
        return Err(err("is not one of the allowed choices"));
    }
    match input.format {
        InputFormat::Number if value.parse::<f64>().map(|n| !n.is_finite()).unwrap_or(true) => {
            Err(err("is not a number"))
        }
        InputFormat::Boolean if value != "true" && value != "false" => Err(err("is not true or false")),
        _ => Ok(()),
    }
}

/// The spec's `{var}` splice, in one pass: each `{name}` whose name is a key
/// of `vars` is replaced by its value, and an identifier with no value stays
/// literal. A substituted value is never scanned again.
pub fn splice(template: &str, vars: &HashMap<&str, &str>) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        if let Some(close) = after.find('}')
            && let Some(value) = vars.get(&after[..close])
        {
            out.push_str(value);
            rest = &after[close + 1..];
        } else {
            out.push('{');
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// Finish a remote's URL template with the admin's values (a variable's
/// default fills it when absent). Every variable is resolved; none is secret.
pub fn finish_url(remote: &Remote, values: &HashMap<String, String>) -> Result<String, RemoteError> {
    validate_url_template(remote)?;
    if let Some(unknown) = values.keys().find(|k| !remote.variables.contains_key(*k)) {
        return Err(RemoteError::UnknownUrlVariable(unknown.clone()));
    }
    let mut vars: HashMap<&str, &str> = HashMap::new();
    for (name, input) in &remote.variables {
        let value = values.get(name).or(input.default.as_ref());
        match value {
            Some(v) => {
                validate_url_value(name, input, v)?;
                vars.insert(name.as_str(), v.as_str());
            }
            None if template_vars(&remote.url, &remote.variables).contains(&name.as_str()) => {
                return Err(RemoteError::MissingUrlVariable(name.clone()));
            }
            None => {}
        }
    }
    let url = splice(&remote.url, &vars);
    match url::Url::parse(&url) {
        Ok(u) if matches!(u.scheme(), "http" | "https") && u.host().is_some() => Ok(url),
        _ => Err(RemoteError::InvalidUrl),
    }
}

// ── resolution ──────────────────────────────────────────────────────────────

/// The headers an upstream request carries, and the secret strings a body
/// echoed back from it must be redacted of. Every value is marked sensitive.
/// No `Debug` derive: a stray `{:?}` must not print a credential.
#[derive(Clone, Default)]
pub struct UpstreamAuth {
    headers: Vec<(HeaderName, HeaderValue)>,
    secrets: Vec<String>,
}

impl std::fmt::Debug for UpstreamAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamAuth")
            .field("headers", &self.headers.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl UpstreamAuth {
    /// No header at all.
    pub fn none() -> Self {
        Self::default()
    }

    /// Only `Authorization: Bearer <token>` — a per-user OAuth token with no
    /// declared header.
    pub fn bearer(token: &str) -> Option<Self> {
        let mut auth = Self::default();
        auth.push_bearer(token)?;
        Some(auth)
    }

    /// Add the user's OAuth token as `Authorization: Bearer`. `None` when the
    /// token is not a valid header value.
    pub fn push_bearer(&mut self, token: &str) -> Option<()> {
        let mut v = HeaderValue::from_str(&format!("Bearer {token}")).ok()?;
        v.set_sensitive(true);
        self.headers.push((reqwest::header::AUTHORIZATION, v));
        self.secrets.push(token.to_string());
        Some(())
    }

    pub fn headers(&self) -> &[(HeaderName, HeaderValue)] {
        &self.headers
    }

    /// The secret strings to redact from anything echoed back from upstream.
    pub fn secrets(&self) -> impl Iterator<Item = &str> {
        self.secrets.iter().map(String::as_str)
    }

    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    /// Stamp every header on an outbound request. The declaration excluded
    /// every header the gateway sets itself, so nothing here duplicates one.
    pub fn apply(&self, mut builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        for (name, value) in &self.headers {
            builder = builder.header(name.clone(), value.clone());
        }
        builder
    }
}

/// What a request lacks to call an upstream.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Missing {
    pub admin: Vec<String>,
    pub user: Vec<String>,
    pub client: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolveError {
    /// The stored declaration or filler set is invalid (never saved so by the
    /// admin API; refused at runtime too, fail closed).
    Declaration(RemoteError),
    /// A required input has no value.
    Missing(Missing),
    /// A stored or sent value cannot be carried in a header.
    InvalidValue(String),
}

/// The plaintext value sources for one upstream request.
#[derive(Clone, Copy, Default)]
pub struct InputValues<'a> {
    /// Admin input id → value (decrypted).
    pub admin: Option<&'a HashMap<String, String>>,
    /// The calling user's input id → value (decrypted).
    pub user: Option<&'a HashMap<String, String>>,
    /// The inbound request's headers, for client inputs.
    pub client: Option<&'a HeaderMap>,
}

/// Build the headers for one upstream request. Each input is read only from
/// its own filler's source; a value that does not fit the input's current
/// declaration ([`validate_value`]) is reported missing, whether the input is
/// required or not; an optional input with no value omits its header (an
/// absent value takes the declared default first); a header is sent only
/// when every one of its inputs has a value.
pub fn resolve(remote: &Remote, oauth: bool, values: InputValues<'_>) -> Result<UpstreamAuth, ResolveError> {
    let specs = validate_fillers(remote, oauth).map_err(ResolveError::Declaration)?;
    resolve_validated(remote, &specs, values)
}

/// [`resolve`] over specs already validated: `specs` MUST be what
/// [`validate_fillers`] returned for this same `remote` (and the upstream's
/// OAuth flag) — a list from another remote would fill the wrong headers.
/// Reached through `McpUpstreamServer::resolve_inputs`, which holds the two
/// together.
pub(crate) fn resolve_validated(
    remote: &Remote,
    specs: &[InputSpec],
    values: InputValues<'_>,
) -> Result<UpstreamAuth, ResolveError> {
    let mut missing = Missing::default();
    let mut auth = UpstreamAuth::default();
    for h in &remote.headers {
        let mine: Vec<&InputSpec> = specs.iter().filter(|s| s.declared.header == h.name).collect();
        let mut vars: HashMap<&str, &str> = HashMap::new();
        let mut complete = true;
        let mut secret_parts: Vec<&str> = Vec::new();
        for s in &mine {
            let id = s.declared.id.as_str();
            let given: Option<&str> = match s.filler {
                Filler::Admin => values.admin.and_then(|m| m.get(id)).map(String::as_str),
                Filler::User => values.user.and_then(|m| m.get(id)).map(String::as_str),
                Filler::Client => values
                    .client
                    .and_then(|hm| hm.get(h.name.as_str()))
                    .and_then(|v| v.to_str().ok()),
            };
            // A client header sent with bytes no `&str` holds (obs-text) is a
            // value given, not an absent one.
            let unreadable = s.filler == Filler::Client
                && given.is_none()
                && values.client.is_some_and(|hm| hm.contains_key(h.name.as_str()));
            // A given value that does not fit its input (refused by its
            // choices or format) is reported missing — never silently
            // replaced by the default, which would send something its sender
            // did not ask for. Only an absent value takes the default.
            let invalid = unreadable
                || given.is_some_and(|v| {
                    let checked = if s.filler == Filler::Client {
                        validate_sent_value(id, &s.declared.input, v)
                    } else {
                        validate_value(id, &s.declared.input, v)
                    };
                    checked.is_err()
                });
            let value = if invalid { None } else { given.or(s.declared.input.default.as_deref()) };
            match value {
                Some(v) => {
                    // A client's own value is usually its credential, whatever
                    // the declaration says: one of credential length is
                    // redacted from anything echoed back too (a short flag such
                    // as `true` is not, or every `true` in a body would go).
                    if s.declared.is_secret(h) || (s.filler == Filler::Client && v.len() >= 8) {
                        secret_parts.push(v);
                    }
                    vars.insert(s.declared.var.as_deref().unwrap_or(""), v);
                }
                None => {
                    complete = false;
                    if s.declared.required || invalid {
                        let list = match s.filler {
                            Filler::Admin => &mut missing.admin,
                            Filler::User => &mut missing.user,
                            Filler::Client => &mut missing.client,
                        };
                        list.push(s.declared.id.clone());
                    }
                }
            }
        }
        if !complete {
            continue;
        }
        let value = match &h.input.value {
            None => vars.get("").map(|v| (*v).to_string()),
            Some(template) => Some(splice(template, &vars)),
        };
        let Some(value) = value else { continue };
        if !is_field_value(&value) {
            return Err(ResolveError::InvalidValue(h.name.clone()));
        }
        let name = HeaderName::from_bytes(h.name.as_bytes())
            .map_err(|_| ResolveError::Declaration(RemoteError::InvalidHeaderName(h.name.clone())))?;
        let mut hv = HeaderValue::from_str(&value).map_err(|_| ResolveError::InvalidValue(h.name.clone()))?;
        hv.set_sensitive(true);
        if !secret_parts.is_empty() || h.input.is_secret {
            auth.secrets.extend(secret_parts.iter().map(|s| (*s).to_string()));
            auth.secrets.push(value);
        }
        auth.headers.push((name, hv));
    }
    if missing != Missing::default() {
        return Err(ResolveError::Missing(missing));
    }
    Ok(auth)
}

#[cfg(test)]
#[path = "header_inputs_tests.rs"]
mod tests;

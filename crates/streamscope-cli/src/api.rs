//! HTTP client for the gateway's CLI OAuth + portal provisioning surfaces.
//! Wire structs mirror the server's response shapes (the template /
//! placeholder types come straight from the shared
//! `streamscope-client-templates` crate, so a bundle deserializes into
//! exactly what the local renderer consumes).

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;

use streamscope_client_templates::{ClientProfileTemplate, Value};

use crate::AuthRequired;

pub const CLI_CLIENT_ID: &str = "streamscope-cli";

#[derive(Debug, Deserialize)]
pub struct ServerMetadata {
    /// Who this authorization server says it is. The login callback checks the
    /// RFC 9207 `iss` against it, so a code returned by a different server than
    /// the one discovery named is refused rather than exchanged.
    pub issuer: String,
    /// Browser-facing consent page URL (the gateway's public UI origin).
    pub authorization_endpoint: String,
    /// Token endpoint on the canonical admin-API origin.
    pub token_endpoint: String,
    /// RFC 8628 device-authorization endpoint, also on the API origin —
    /// the UI origin's passthrough is GET-only, so POSTing the device start
    /// anywhere else fails on split-vhost deploys.
    pub device_authorization_endpoint: String,
    /// The admin-API public origin — UI and API are separate vhosts on
    /// production deploys, and the discovery document may be fetched via
    /// either (the UI proxies the GET). Everything after discovery — token
    /// exchange, refresh, revoke, the portal provisioning API, downloads —
    /// targets this origin.
    pub api_origin: String,
}

#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: i64,
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct PortalMe {
    pub workspaces: Vec<PortalWorkspace>,
    pub downstream_providers: Vec<PortalProvider>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PortalWorkspace {
    pub id: uuid::Uuid,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PortalProvider {
    pub id: uuid::Uuid,
    pub name: String,
    /// `true` for a BYOK pass-through downstream (provision a `vk-` key; the
    /// client forwards its own upstream credential). `false` for a normal
    /// gateway provider (`sk-` key + curated routes).
    pub byok: bool,
    /// The protocol a BYOK pass-through's server speaks — what its default
    /// template speaks. `None` for a gateway provider.
    pub upstream_protocol: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct QuickstartClients {
    pub clients: Vec<QuickstartClientSummary>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct QuickstartClientSummary {
    pub id: String,
    pub compatible: bool,
    pub incompatibility_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ClientProfileWire {
    pub templates: Vec<ClientProfileTemplate>,
}

/// One page of a portal list (`OffsetPage` / `TotalPage`); the fields the
/// walk needs.
#[derive(Debug, Deserialize)]
struct Page<T> {
    items: Vec<T>,
    has_more: bool,
}

/// Page size the CLI asks for — the server's cap.
const PAGE_LIMIT: usize = 500;

/// Pages a list may take before the walk gives up: a gateway that never says
/// `has_more: false` must fail the command, not grow it forever.
const MAX_PAGES: usize = 200;

#[derive(Debug, Clone, Deserialize)]
pub struct QuickstartKey {
    pub id: uuid::Uuid,
    pub forward_auth: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct McpVirtualServer {
    pub id: uuid::Uuid,
    pub slug: String,
    pub name: String,
    /// Per-user connection state: `none` | `connected` | `needs_connection`.
    /// `needs_connection` → warn the user to connect in the portal first. The
    /// server sends more fields (`requires_connection`, `built_in`, …); serde
    /// ignores the ones the CLI doesn't consume.
    pub connection_status: String,
}

#[derive(Debug, Deserialize)]
pub struct BundleResponse {
    pub bundle_etag: String,
    pub key: Option<BundleKey>,
    pub minted_secrets: MintedSecrets,
    pub clients: Vec<ClientBundle>,
    /// What the workspace is offered.
    pub client_access: ClientAccess,
}

/// What a workspace is offered (`GET /portal/client-access`, and the bundle's
/// `client_access`).
#[derive(Debug, Clone, Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct ClientAccess {
    /// The ids of the clients the workspace is offered.
    pub clients: Vec<String>,
    pub sandbox: SandboxPolicy,
}

/// What the sandbox may reach besides the gateway.
#[derive(Debug, Clone, Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct SandboxPolicy {
    /// Canonical destination entries attached as allow.
    pub allow: Vec<String>,
    /// Canonical destination entries attached as block — a block wins.
    pub block: Vec<String>,
    pub settings: SandboxSettings,
    pub revision: String,
}

#[derive(Debug, Clone, Copy, Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct SandboxSettings {
    /// `ssai run --sandbox off` is refused.
    pub require_sandbox: bool,
    /// `ssai run --sandbox docker` is allowed.
    pub docker_tier: bool,
}

impl Default for SandboxSettings {
    /// The server's default: the container sandbox is allowed.
    fn default() -> Self {
        Self { require_sandbox: false, docker_tier: true }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct BundleKey {
    pub id: uuid::Uuid,
    pub name: String,
    pub key_prefix: Option<String>,
    pub forward_auth: bool,
}

#[derive(Debug, Deserialize)]
pub struct MintedSecrets {
    pub api_key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ClientBundle {
    pub client_id: String,
    pub label: String,
    pub template_index: usize,
    pub template: ClientProfileTemplate,
    pub placeholders: BTreeMap<String, Value>,
    pub rendered_body: String,
    pub rendered_instructions: Option<String>,
    /// Command that launches the tool (e.g. `claude`). `None` for GUI clients.
    pub launch_command: Option<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct BundleRequest {
    pub workspace_id: uuid::Uuid,
    pub clients: Vec<BundleSelection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<KeySpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_provider_id: Option<uuid::Uuid>,
    pub mcp_servers: Vec<McpSelection>,
}

#[derive(Debug, serde::Serialize)]
pub struct BundleSelection {
    pub client_id: String,
    pub template_index: usize,
}

#[derive(Debug, Default, serde::Serialize)]
pub struct KeySpec {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Backend derives the next free `<prefix>` / `<prefix>-N` name —
    /// CI mode mints under `ci`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reuse_key_id: Option<uuid::Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub forward_auth: bool,
    /// The caller holds the gateway key out-of-band
    /// (`STREAMSCOPE_GATEWAY_KEY`) — render with the sentinel, mint nothing.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub external: bool,
}

impl KeySpec {
    /// Mint a fresh key. `name` wins over `name_prefix` (the backend derives
    /// the next free `<prefix>` / `<prefix>-N` when only the prefix is set).
    pub fn mint(
        name: Option<String>,
        name_prefix: Option<String>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
        forward_auth: bool,
    ) -> Self {
        let name_prefix = if name.is_some() { None } else { name_prefix };
        Self {
            name,
            name_prefix,
            expires_at,
            forward_auth,
            ..Self::default()
        }
    }

    /// Reuse an existing key (its own mode wins server-side).
    pub fn reuse(key_id: uuid::Uuid, forward_auth: bool) -> Self {
        Self {
            reuse_key_id: Some(key_id),
            forward_auth,
            ..Self::default()
        }
    }

    /// A mint-nothing spec for a key supplied out-of-band; `forward_auth`
    /// states the key's mode (it decides the `/fwd/` URL shape).
    pub fn external(forward_auth: bool) -> Self {
        Self {
            forward_auth,
            external: true,
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct McpSelection {
    pub virtual_server_id: uuid::Uuid,
}

/// A refusal the gateway answered with its error envelope.
#[derive(Debug)]
pub struct GatewayError {
    /// The envelope's `code`, the one thing to branch on.
    pub code: Option<String>,
    detail: String,
}

impl std::fmt::Display for GatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "gateway error: {}", self.detail)
    }
}

impl std::error::Error for GatewayError {}

/// The code a gateway refusal carried, anywhere in `e`'s chain.
pub fn error_code(e: &anyhow::Error) -> Option<&str> {
    e.chain().find_map(|c| c.downcast_ref::<GatewayError>()).and_then(|g| g.code.as_deref())
}

/// The refusal for a client the administrator has disabled.
pub const CLIENT_DISABLED: &str = "client_disabled";

#[derive(Debug, Deserialize)]
struct ApiErrorEnvelope {
    error: ApiErrorBody,
}

#[derive(Debug, Deserialize)]
struct ApiErrorBody {
    message: String,
    #[serde(default)]
    code: Option<String>,
}

pub struct ApiClient {
    http: reqwest::Client,
    pub origin: String,
    /// Portal bearer: a provision-scoped access token or an `ak-` key.
    pub bearer: String,
}

impl ApiClient {
    pub fn new(origin: &str, bearer: &str) -> Result<Self> {
        Ok(Self {
            http: http_client()?,
            origin: origin.trim_end_matches('/').to_string(),
            bearer: bearer.to_string(),
        })
    }

    fn portal_url(&self, path: &str) -> String {
        format!("{}/api/v1/portal{}", self.origin, path)
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T> {
        let resp = self
            .http
            .get(url)
            .bearer_auth(&self.bearer)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        decode_response(resp).await
    }

    pub async fn me(&self) -> Result<PortalMe> {
        self.get_json(&self.portal_url("/auth/me")).await
    }

    /// `me` with `downstream_providers` scoped to one workspace's grants — used
    /// after the workspace pick so the provider prompt lists only that
    /// workspace's providers.
    pub async fn me_for_workspace(&self, workspace_id: uuid::Uuid) -> Result<PortalMe> {
        self.get_json(&self.portal_url(&format!("/auth/me?workspace_id={workspace_id}")))
            .await
    }

    pub async fn quickstart_clients(&self) -> Result<QuickstartClients> {
        self.get_json(&self.portal_url("/quickstart/clients")).await
    }

    pub async fn client_profile(&self, id: &str) -> Result<ClientProfileWire> {
        self.get_json(&self.portal_url(&format!("/quickstart/clients/{id}")))
            .await
    }

    /// Every item of a paged list, walking `offset` until `has_more` is false.
    /// `url` carries its own query string (or none).
    async fn get_all_pages<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<Vec<T>> {
        let sep = if url.contains('?') { '&' } else { '?' };
        let mut items = Vec::new();
        for _ in 0..MAX_PAGES {
            let page: Page<T> = self
                .get_json(&format!("{url}{sep}limit={PAGE_LIMIT}&offset={}", items.len()))
                .await?;
            let got = page.items.len();
            items.extend(page.items);
            if !page.has_more || got == 0 {
                return Ok(items);
            }
        }
        bail!("{url}: the gateway kept answering more pages after {MAX_PAGES}")
    }

    pub async fn quickstart_keys(&self, workspace_id: uuid::Uuid) -> Result<Vec<QuickstartKey>> {
        self.get_all_pages(&self.portal_url(&format!(
            "/quickstart/keys?workspace_id={workspace_id}"
        )))
        .await
    }

    pub async fn mcp_virtual_servers(&self) -> Result<Vec<McpVirtualServer>> {
        self.get_all_pages(&self.portal_url("/mcp/virtual-servers")).await
    }

    /// What `workspace_id` is offered now.
    pub async fn client_access(&self, workspace_id: uuid::Uuid) -> Result<ClientAccess> {
        self.get_json(&self.portal_url(&format!("/client-access?workspace_id={workspace_id}"))).await
    }

    pub async fn provision_bundle(&self, req: &BundleRequest) -> Result<BundleResponse> {
        let url = self.portal_url("/provision/actions/bundle");
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.bearer)
            .json(req)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        decode_response(resp).await
    }
}

/// One process-wide client — reqwest::Client is an Arc internally, so every
/// caller shares the same connection pool and TLS session cache (login's
/// metadata fetch, the token exchange, refresh, and the portal calls all
/// reuse the warm connection).
///
/// Trust is the OS store PLUS every gateway root the installer captured
/// (`gateway-ca.d/*.pem`, one per private gateway installed from): declining
/// the installer's offer to add a root to the OS store must not leave the CLI
/// unable to reach that gateway. The platform verifier reads only the OS
/// store — on Linux `SSL_CERT_FILE` replaces it, on macOS only the keychain
/// counts — so the roots are merged here.
/// An unusable file is warned about and skipped, never fatal, and costs no
/// other file its trust: a gateway with publicly-trusted TLS — and every other
/// captured gateway — must stay reachable past one stale capture.
pub fn http_client() -> Result<reqwest::Client> {
    static HTTP: std::sync::LazyLock<std::result::Result<reqwest::Client, reqwest::Error>> =
        std::sync::LazyLock::new(|| {
            let builder = || {
                reqwest::Client::builder()
                    .connect_timeout(std::time::Duration::from_secs(10))
                    .timeout(std::time::Duration::from_secs(30))
            };
            // reqwest's Display stops at "builder error": the cause is in the chain.
            let chain = |e: reqwest::Error| format!("{:#}", anyhow::Error::from(e));
            let mut files = crate::state::gateway_ca_files();
            files.sort();
            let warn = |path: &std::path::Path, why: &str| {
                crate::ui::warn("", format_args!("ignoring the gateway CA {} ({why}) — remove it, or re-run its \
                     gateway's installer if that certificate is not otherwise trusted", path.display()));
            };
            let mut parsed = Vec::new();
            for path in files {
                let certs = std::fs::read(&path)
                    .map_err(|e| format!("{:#}", anyhow::Error::from(e)))
                    .and_then(|pem| reqwest::Certificate::from_pem_bundle(&pem).map_err(chain))
                    .and_then(|certs| if certs.is_empty() { Err("no certificate in it".to_string()) } else { Ok(certs) });
                match certs {
                    Ok(certs) => parsed.push((path, certs)),
                    Err(why) => warn(&path, &why),
                }
            }
            if parsed.is_empty() {
                return builder().build();
            }
            // One build for all; only when it fails is each file tried alone,
            // to name and leave out the one the TLS stack refuses.
            let all: Vec<reqwest::Certificate> = parsed.iter().flat_map(|(_, c)| c.iter().cloned()).collect();
            if let Ok(client) = builder().tls_certs_merge(all).build() {
                return Ok(client);
            }
            let mut roots = Vec::new();
            for (path, certs) in parsed {
                match builder().tls_certs_merge(certs.clone()).build() {
                    Ok(_) => roots.extend(certs),
                    Err(e) => warn(&path, &chain(e)),
                }
            }
            builder().tls_certs_merge(roots).build()
        });
    match &*HTTP {
        Ok(c) => Ok(c.clone()),
        Err(e) => Err(anyhow!("failed to build HTTP client: {e}")),
    }
}

/// The TLS error inside one link of an error chain. The connector hands it up
/// wrapped — in an `io::Error`, and that in a boxed error — and each wrapper's
/// `source()` skips the error it wraps, so each one is opened here.
fn tls_error<'a>(e: &'a (dyn std::error::Error + 'static)) -> Option<&'a rustls::Error> {
    if let Some(tls) = e.downcast_ref::<rustls::Error>() {
        return Some(tls);
    }
    if let Some(io) = e.downcast_ref::<std::io::Error>() {
        return io.get_ref().and_then(|inner| tls_error(inner));
    }
    None
}

/// When `e` is a refused TLS certificate, what to do about it: the gateway
/// whose certificate it was, and how its root comes to be trusted here.
pub fn untrusted_certificate_hint(e: &anyhow::Error) -> Option<String> {
    // An unknown issuer only: an expired or misnamed certificate is not one
    // a captured root would make trusted.
    let unknown_issuer = e.chain().any(|c| {
        matches!(tls_error(c), Some(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)))
    });
    if !unknown_issuer {
        return None;
    }
    let url = e.chain().find_map(|c| c.downcast_ref::<reqwest::Error>().and_then(reqwest::Error::url))?;
    let origin = url.origin().ascii_serialization();
    let roots = crate::state::gateway_ca_dir().map(|p| p.display().to_string()).unwrap_or_else(|_| "gateway-ca.d".into());
    let installer = installer_url(&origin);
    Some(format!(
        "{origin} presented a certificate this machine does not trust. Install the CLI from that gateway \
         again ({installer}): its installer captures the gateway's root CA into {roots}, \
         beside any other gateway's — check the fingerprint it prints against the one the gateway's operator \
         publishes before you accept it"
    ))
}

/// The gateway's installer for this platform: the PowerShell one on Windows.
pub fn installer_url(origin: &str) -> String {
    if cfg!(windows) { format!("{origin}/api/v1/cli/install.ps1") } else { format!("{origin}/api/v1/cli/install.sh") }
}

/// Fetch the CLI OAuth metadata for `(origin, slug)`.
pub async fn fetch_metadata(origin: &str, slug: &str) -> Result<ServerMetadata> {
    let url = format!(
        "{}/api/v1/cli/oauth/{}/.well-known/oauth-authorization-server",
        origin.trim_end_matches('/'),
        slug
    );
    let resp = http_client()?
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url} — is this the right portal URL?"))?;
    let metadata: ServerMetadata = decode_response(resp).await?;

    // Everything the CLI does after this point is aimed at an address this
    // document chose, so the document is checked here rather than at each use —
    // a later caller cannot remember a rule it never sees. The RFC 9207 `iss`
    // check does not help: it compares against this same document's `issuer`,
    // so a substituted one agrees with itself.
    for (endpoint, what) in [
        (metadata.api_origin.as_str(), "its API"),
        (metadata.token_endpoint.as_str(), "its token endpoint"),
        (
            metadata.device_authorization_endpoint.as_str(),
            "its device-authorization endpoint",
        ),
        (
            metadata.authorization_endpoint.as_str(),
            "its consent page",
        ),
    ] {
        crate::oauth::check_discovered_origin(endpoint, what)?;
    }
    Ok(metadata)
}

/// Exchange an authorization code (+ PKCE verifier) for a token pair at the
/// discovery-declared token endpoint.
pub async fn exchange_code(
    token_endpoint: &str,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> Result<TokenResponse> {
    let resp = http_client()?
        .post(token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", CLI_CLIENT_ID),
            ("code_verifier", code_verifier),
        ])
        .send()
        .await
        .with_context(|| format!("POST {token_endpoint}"))?;
    decode_oauth_response(resp).await
}

/// RFC 8628 §3.4 device-grant `grant_type` value.
const DEVICE_CODE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

#[derive(Debug, Deserialize)]
pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: i64,
    pub interval: i64,
}

/// Start an RFC 8628 device-authorization flow at the metadata-declared
/// endpoint (it rides the API origin — the UI origin's passthrough is
/// GET-only, so POSTing the device start anywhere else fails on split-vhost
/// deploys). Returns the user code to display and the device code to poll
/// with.
pub async fn device_authorization(
    device_authorization_endpoint: &str,
    device_name: &str,
) -> Result<DeviceAuthorizationResponse> {
    let resp = http_client()?
        .post(device_authorization_endpoint)
        .form(&[
            ("client_id", CLI_CLIENT_ID),
            ("scope", "provision"),
            ("device_name", device_name),
        ])
        .send()
        .await
        .with_context(|| format!("POST {device_authorization_endpoint}"))?;
    decode_oauth_response(resp).await
}

/// One device-grant poll outcome. `Pending`/`SlowDown`/`Retry` mean "keep
/// polling"; only a definitive grant decision (denied, expired, unknown
/// code) surfaces as `Err`.
pub enum DevicePoll {
    Token(TokenResponse),
    Pending,
    SlowDown,
    /// Transient hiccup — transport failure or a 5xx/garbled response. The
    /// device code is still valid server-side, so the caller keeps polling
    /// until its own deadline rather than orphaning an approved login.
    Retry(String),
}

/// Poll the token endpoint with a device code (RFC 8628 §3.4-3.5).
pub async fn poll_device_token(token_endpoint: &str, device_code: &str) -> Result<DevicePoll> {
    let resp = match http_client()?
        .post(token_endpoint)
        .form(&[
            ("grant_type", DEVICE_CODE_GRANT_TYPE),
            ("device_code", device_code),
            ("client_id", CLI_CLIENT_ID),
        ])
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => return Ok(DevicePoll::Retry(format!("POST {token_endpoint}: {e}"))),
    };
    let status = resp.status();
    let bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => return Ok(DevicePoll::Retry(format!("read response: {e}"))),
    };
    if status.is_success() {
        let pair = serde_json::from_slice(&bytes).context("unexpected response shape from gateway")?;
        return Ok(DevicePoll::Token(pair));
    }
    // RFC 8628 §3.5 names these states in the `error` field itself. They are
    // what separates "the user hasn't clicked approve yet" from a real failure,
    // so reading the wrong field abandons a login mid-approval.
    let envelope = serde_json::from_slice::<OauthErrorEnvelope>(&bytes).ok();
    match envelope.as_ref().map(|e| e.error.as_str()) {
        Some("authorization_pending") => Ok(DevicePoll::Pending),
        Some("slow_down") => Ok(DevicePoll::SlowDown),
        Some("access_denied") => bail!("the login was denied on the approval page"),
        Some("expired_token") => {
            bail!("the device code expired before the login was approved — run `ssai login` again")
        }
        _ if status.is_client_error() => {
            let detail = envelope
                .map(|e| e.error_description.unwrap_or(e.error))
                .unwrap_or_else(|| format!("HTTP {status}"));
            bail!("gateway error: {detail}")
        }
        // 5xx, or a body that isn't the gateway's error envelope (a fronting
        // proxy's HTML 502, a rolling restart) — transient, keep polling.
        _ => Ok(DevicePoll::Retry(format!("HTTP {status}"))),
    }
}

/// Rotate a refresh token into a fresh access + refresh pair.
pub async fn refresh(origin: &str, slug: &str, refresh_token: &str) -> Result<TokenResponse> {
    let url = format!(
        "{}/api/v1/cli/oauth/{}/token",
        origin.trim_end_matches('/'),
        slug
    );
    let resp = http_client()?
        .post(&url)
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", CLI_CLIENT_ID),
        ])
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    decode_oauth_response(resp).await
}

/// RFC 7009 revocation — kills the refresh token and its paired access
/// token server-side.
pub async fn revoke(origin: &str, slug: &str, refresh_token: &str) -> Result<()> {
    let url = format!(
        "{}/api/v1/cli/oauth/{}/revoke",
        origin.trim_end_matches('/'),
        slug
    );
    let resp = http_client()?
        .post(&url)
        .form(&[("token", refresh_token)])
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    let _: serde_json::Value = decode_oauth_response(resp).await?;
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct CliVersionResponse {
    pub version: String,
    pub targets: Vec<CliTargetInfo>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CliTargetInfo {
    pub target: String,
    pub sha256: String,
}

/// Shipped CLI version + sha256 manifest from the gateway's public
/// distribution surface — backs `ssai update` and the passive
/// new-version notice in `sync`.
pub async fn cli_version(origin: &str) -> Result<CliVersionResponse> {
    let url = format!("{}/api/v1/cli/version", origin.trim_end_matches('/'));
    let resp = http_client()?
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    decode_response(resp).await
}

/// Download the CLI binary for `target` from the gateway.
pub async fn cli_download(origin: &str, target: &str) -> Result<bytes::Bytes> {
    let url = format!(
        "{}/api/v1/cli/download/{target}",
        origin.trim_end_matches('/')
    );
    let resp = http_client()?
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = resp.status();
    let bytes = resp.bytes().await.context("failed to read download body")?;
    if !status.is_success() {
        bail!("gateway error downloading the CLI: HTTP {status}");
    }
    Ok(bytes)
}

/// Decode a response from an RFC 6749 endpoint, whose errors are
/// `{"error": "invalid_grant", "error_description": "…"}`.
///
/// Deliberately separate from [`decode_response`]: the portal API answers with
/// a different envelope, and one function tolerating both shapes would be a
/// compatibility layer that hides which surface actually replied.
async fn decode_oauth_response<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
) -> Result<T> {
    let status = resp.status();
    let bytes = resp.bytes().await.context("failed to read response body")?;
    if status.is_success() {
        return serde_json::from_slice(&bytes).context("unexpected response shape from gateway");
    }
    let detail = serde_json::from_slice::<OauthErrorEnvelope>(&bytes)
        .map(|e| match e.error_description {
            Some(d) => format!("{d} ({})", e.error),
            None => e.error,
        })
        .unwrap_or_else(|_| format!("HTTP {status}"));
    if status == reqwest::StatusCode::UNAUTHORIZED {
        bail!(AuthRequired(format!(
            "gateway rejected the session ({detail}) — run: ssai login <portal-url>"
        )));
    }
    Err(anyhow!("gateway error: {detail}"))
}

#[derive(Debug, Deserialize)]
struct OauthErrorEnvelope {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

async fn decode_response<T: serde::de::DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
    let status = resp.status();
    let bytes = resp.bytes().await.context("failed to read response body")?;
    if status.is_success() {
        return serde_json::from_slice(&bytes).context("unexpected response shape from gateway");
    }
    let envelope = serde_json::from_slice::<ApiErrorEnvelope>(&bytes).ok();
    let code = envelope.as_ref().and_then(|e| e.error.code.clone());
    let detail = envelope
        .map(|e| match e.error.code {
            Some(code) => format!("{} ({code})", e.error.message),
            None => e.error.message,
        })
        .unwrap_or_else(|| format!("HTTP {status}"));
    if status == reqwest::StatusCode::UNAUTHORIZED {
        bail!(AuthRequired(format!(
            "gateway rejected the session ({detail}) — run: ssai login <portal-url>"
        )));
    }
    Err(GatewayError { code, detail }.into())
}

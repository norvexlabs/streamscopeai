//! Public CLI distribution surface — `GET /api/v1/cli/{version,install.sh,install.ps1,download/{target}}`.
//!
//! Serves the `ssai` CLI binary baked into this image (the same
//! artifact the e2e suite exercises), a sha256 manifest, and self-verifying
//! installer scripts: POSIX shell, and PowerShell for Windows. Unauthenticated and GET-only by design — the
//! binary is a public artifact like the web UI itself; the per-source-IP
//! pre-auth flood cap is the only gate (mounted in `main.rs`).
//!
//! Each target's binary is read from its fixed image path once and cached in
//! memory so downloads never re-touch the filesystem.

use std::sync::Arc;

use axum::extract::Path;
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use serde::Serialize;
use tokio::sync::OnceCell;
use utoipa::ToSchema;

use crate::AdminState;

use super::{ApiError, ApiErrorCode, ApiErrorResponse};

/// Linux distribution target — a static musl build, so one artifact covers
/// glibc and musl distros alike. Always present in a normal image (built
/// in-stage by `docker/Dockerfile.admin-api`).
pub const CLI_TARGET_LINUX_X86_64: &str = "linux-x86_64";

/// macOS Apple-Silicon target. Cross-building Darwin from the Debian builder
/// needs the Apple SDK (license-gated), so this artifact is produced
/// out-of-band (on an arm64 Mac or a macOS CI runner) and dropped into the
/// build context before the image build. When it isn't supplied this target
/// is simply absent and its endpoints 404, while Linux keeps working.
pub const CLI_TARGET_DARWIN_ARM64: &str = "darwin-arm64";

/// Windows x86_64 target (`ssai.exe`, a mingw-w64 build that needs no runtime
/// DLL). Always present in a normal image (built in-stage like Linux); served
/// to `install.ps1`.
pub const CLI_TARGET_WINDOWS_X86_64: &str = "windows-x86_64";

/// A distribution target: the shorthand the routes accept, the in-image path
/// the binary is baked at (see `docker/Dockerfile.admin-api`), and a lazily
/// loaded, cached artifact. `None` once loaded means the image carries no
/// binary for this target — that target's endpoints 404 while others serve.
struct Target {
    name: &'static str,
    image_path: &'static str,
    /// The file name a download is saved under.
    file_name: &'static str,
    cell: OnceCell<Option<CliArtifact>>,
}

/// All known targets, in the order `version`/`install.sh` advertise them.
static TARGETS: [Target; 3] = [
    Target {
        name: CLI_TARGET_LINUX_X86_64,
        image_path: "/usr/local/bin/ssai",
        file_name: "ssai",
        cell: OnceCell::const_new(),
    },
    Target {
        name: CLI_TARGET_DARWIN_ARM64,
        image_path: "/usr/local/share/ssai/ssai-darwin-arm64",
        file_name: "ssai",
        cell: OnceCell::const_new(),
    },
    Target {
        name: CLI_TARGET_WINDOWS_X86_64,
        image_path: "/usr/local/share/ssai/ssai-windows-x86_64.exe",
        file_name: "ssai.exe",
        cell: OnceCell::const_new(),
    },
];

pub fn router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/version", get(version))
        .route("/install.sh", get(install_sh))
        .route("/install.ps1", get(install_ps1))
        .route("/download/{target}", get(download))
        .route("/ca", get(ca))
}

struct CliArtifact {
    /// `Bytes` so each download response clones a refcounted handle, never
    /// the ~10 MB buffer.
    bytes: bytes::Bytes,
    sha256: String,
}

/// Load + cache one target's binary. `Ok(None)` when the target is unknown,
/// or known but the image carries no binary for it (a deployment built without
/// that artifact) — its endpoints then 404. Only the two *definitive* outcomes
/// are cached per target: a successful read, or ENOENT. A transient read
/// failure (fd/memory pressure) returns an error WITHOUT initialising the cell,
/// so the next request retries instead of serving permanent 404s until restart.
async fn artifact(target: &str) -> Result<Option<&'static CliArtifact>, ApiError> {
    let Some(t) = TARGETS.iter().find(|t| t.name == target) else {
        return Ok(None);
    };
    t.cell
        .get_or_try_init(|| async {
            match tokio::fs::read(t.image_path).await {
                Ok(bytes) => {
                    use sha2::{Digest, Sha256};
                    let sha256 = hex::encode(Sha256::digest(&bytes));
                    Ok(Some(CliArtifact {
                        bytes: bytes::Bytes::from(bytes),
                        sha256,
                    }))
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    tracing::warn!(
                        "no CLI binary at {} — {} distribution target disabled",
                        t.image_path,
                        t.name
                    );
                    Ok(None)
                }
                Err(e) => {
                    tracing::error!("failed to read CLI binary at {}: {e}", t.image_path);
                    Err(ApiError::internal("internal error"))
                }
            }
        })
        .await
        .map(Option::as_ref)
}

/// Collect `(target, sha256)` for every target this image actually ships, in
/// catalog order. Empty ⇒ the image carries no CLI at all.
async fn available_targets() -> Result<Vec<(&'static str, String)>, ApiError> {
    let mut out = Vec::new();
    for t in &TARGETS {
        if let Some(a) = artifact(t.name).await? {
            out.push((t.name, a.sha256.clone()));
        }
    }
    Ok(out)
}

fn cli_unavailable() -> ApiError {
    ApiError::not_found("the CLI is not available from this deployment", ApiErrorCode::CliArtifactUnavailable)
}

#[derive(Serialize, ToSchema)]
pub struct CliTargetInfo {
    /// Target triple shorthand the download route accepts (e.g. `linux-x86_64`).
    pub target: String,
    /// SHA-256 of the binary, hex — `ssai update` and the installer
    /// script verify the download against it.
    pub sha256: String,
}

#[derive(Serialize, ToSchema)]
pub struct CliVersionResponse {
    /// Application version this gateway ships (the CLI binary is built from
    /// the same release).
    pub version: String,
    pub targets: Vec<CliTargetInfo>,
}

#[utoipa::path(
    get,
    path = "/api/v1/cli/version",
    tag = "CLI Distribution",
    operation_id = "cli_dist_version",
    responses(
        (status = 200, description = "Shipped CLI version + per-target sha256 manifest", body = CliVersionResponse),
        (status = 404, description = "CLI not available from this deployment", body = ApiErrorResponse),
    )
)]
pub async fn version() -> Result<axum::Json<CliVersionResponse>, ApiError> {
    let targets = available_targets().await?;
    if targets.is_empty() {
        return Err(cli_unavailable());
    }
    Ok(axum::Json(CliVersionResponse {
        version: streamscope_core::VERSION.to_string(),
        targets: targets
            .into_iter()
            .map(|(target, sha256)| CliTargetInfo {
                target: target.to_string(),
                sha256,
            })
            .collect(),
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/cli/download/{target}",
    tag = "CLI Distribution",
    operation_id = "cli_dist_download",
    params(("target" = String, Path, description = "Distribution target (`linux-x86_64`, `darwin-arm64`, `windows-x86_64`)")),
    responses(
        (status = 200, description = "The ssai CLI binary", content_type = "application/octet-stream"),
        (status = 404, description = "Unknown target or CLI not available", body = ApiErrorResponse),
    )
)]
pub async fn download(Path(target): Path<String>) -> Result<impl IntoResponse, ApiError> {
    let Some(known_target) = TARGETS.iter().find(|t| t.name == target) else {
        let known = TARGETS
            .iter()
            .map(|t| t.name)
            .collect::<Vec<_>>()
            .join(", ");
        return Err(ApiError::not_found(format!(
            "unknown CLI target {target:?} — available: {known}"
        ), ApiErrorCode::CliArtifactUnavailable));
    };
    let artifact = artifact(&target).await?.ok_or_else(cli_unavailable)?;
    let headers = [
        (
            header::CONTENT_TYPE,
            "application/octet-stream".to_string(),
        ),
        (
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", known_target.file_name),
        ),
    ];
    Ok((headers, artifact.bytes.clone()))
}

#[utoipa::path(
    get,
    path = "/api/v1/cli/ca",
    tag = "CLI Distribution",
    operation_id = "cli_dist_ca",
    responses(
        (status = 200, description = "The gateway's root CA certificate (PEM)", content_type = "application/x-pem-file"),
        (status = 404, description = "No private CA configured — the gateway uses publicly-trusted TLS", body = ApiErrorResponse),
    )
)]
pub async fn ca() -> Result<impl IntoResponse, ApiError> {
    // The TLS handshake only ever presents leaf + intermediate; the root CA —
    // the stable anchor the installer should trust — is never sent on the wire.
    // Serve it from the path the deploy mounts (the shared `cli-ca/ca.pem` on the
    // VM appliance). Unset / unreadable / empty ⇒ 404, which the installer treats
    // as "no trustable root" and refuses, rather than trusting the served leaf.
    let path = crate::settings::admin_settings().gateway_ca_file.clone();
    if path.is_empty() {
        return Err(no_gateway_ca());
    }
    match tokio::fs::read(&path).await {
        Ok(pem) if !pem.is_empty() => Ok((
            [(header::CONTENT_TYPE, "application/x-pem-file")],
            pem,
        )),
        Ok(_) => Err(no_gateway_ca()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(no_gateway_ca()),
        Err(e) => {
            tracing::error!("failed to read gateway CA at {path}: {e}");
            Err(ApiError::internal("internal error"))
        }
    }
}

fn no_gateway_ca() -> ApiError {
    ApiError::not_found("this gateway does not publish a private CA", ApiErrorCode::CliArtifactUnavailable)
}

#[utoipa::path(
    get,
    path = "/api/v1/cli/install.sh",
    tag = "CLI Distribution",
    operation_id = "cli_dist_install_sh",
    responses(
        (status = 200, description = "Self-verifying POSIX installer script", content_type = "text/x-shellscript"),
        (status = 404, description = "CLI not available from this deployment", body = ApiErrorResponse),
    )
)]
pub async fn install_sh(
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let targets = available_targets().await?;
    if targets.is_empty() {
        return Err(cli_unavailable());
    }
    let origin = request_origin(&headers);
    let target_refs: Vec<(&str, &str)> =
        targets.iter().map(|(n, s)| (*n, s.as_str())).collect();
    let script = render_install_script(&origin, streamscope_core::VERSION, &target_refs);
    Ok((
        [(header::CONTENT_TYPE, "text/x-shellscript; charset=utf-8")],
        script,
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/cli/install.ps1",
    tag = "CLI Distribution",
    operation_id = "cli_dist_install_ps1",
    responses(
        (status = 200, description = "Self-verifying PowerShell installer script for Windows", content_type = "text/plain"),
        (status = 404, description = "No Windows CLI available from this deployment", body = ApiErrorResponse),
    )
)]
pub async fn install_ps1(
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let sha = artifact(CLI_TARGET_WINDOWS_X86_64).await?.ok_or_else(cli_unavailable)?.sha256.clone();
    let script = render_install_ps1(&request_origin(&headers), streamscope_core::VERSION, &sha);
    Ok((
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        script,
    ))
}

/// The PowerShell installer with its values filled in. Each lands inside a
/// single-quoted PowerShell string, so it is escaped for one (`'` doubled):
/// the origin comes from request headers and must stay a value, never code.
fn render_install_ps1(origin: &str, version: &str, sha256: &str) -> String {
    let quoted = |s: &str| s.replace('\'', "''");
    // The origin last: a placeholder spelled inside it stays text.
    include_str!("cli_install.ps1")
        .replace("__VERSION__", &quoted(version))
        .replace("__SHA256__", &quoted(sha256))
        .replace("__ORIGIN__", &quoted(origin))
}

/// Reconstruct the public origin the client fetched this script from, so the
/// script downloads the binary from the same gateway. TLS always terminates
/// upstream of admin-api, so the scheme comes from `X-Forwarded-Proto` when
/// a front hop sets it (Caddy, the chart ingress, and the admin-UI
/// passthrough all do) and falls back to `http` for direct (un-proxied,
/// hence plaintext) access. The host honours `X-Forwarded-Host` first — the
/// admin-UI's GET passthrough sets it so a script fetched via the UI origin
/// also downloads via it.
fn request_origin(headers: &axum::http::HeaderMap) -> String {
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .filter(|s| *s == "https" || *s == "http")
        .unwrap_or("http");
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(header::HOST))
        .and_then(|v| v.to_str().ok())
        .filter(|h| !h.is_empty())
        .unwrap_or("localhost");
    format!("{scheme}://{host}")
}

/// Map a distribution target to the `uname -s`-`uname -m` pair that selects it
/// and the human label the unsupported-platform message lists.
fn target_uname(target: &str) -> Option<(&'static str, &'static str)> {
    match target {
        CLI_TARGET_LINUX_X86_64 => Some(("Linux-x86_64", "Linux x86_64")),
        CLI_TARGET_DARWIN_ARM64 => Some(("Darwin-arm64", "macOS Apple Silicon")),
        _ => None,
    }
}

fn render_install_script(origin: &str, version: &str, targets: &[(&str, &str)]) -> String {
    // One `case` arm per target the gateway actually ships — each binds its own
    // per-target sha so a macOS download verifies against the macOS checksum,
    // not the Linux one. A platform with no shipped build falls through to the
    // `*)` arm and gets a clear "supported: …" error.
    let mut arms = String::new();
    let mut supported = Vec::new();
    for (name, sha) in targets {
        if let Some((uname, label)) = target_uname(name) {
            arms.push_str(&format!("  {uname}) target=\"{name}\"; WANT_SHA=\"{sha}\" ;;\n"));
            supported.push(label);
        }
    }
    let supported = supported.join(", ");
    format!(
        r#"#!/bin/sh
# Streamscope CLI installer — serves from {origin}
# Downloads the ssai binary, verifies its sha256, and installs it to
# $STREAMSCOPE_INSTALL_DIR (default: ~/.local/bin).
set -eu

ORIGIN="{origin}"
VERSION="{version}"

os=$(uname -s)
arch=$(uname -m)
case "$os-$arch" in
{arms}  *)
    echo "ssai: unsupported platform $os/$arch (supported: {supported})" >&2
    exit 1
    ;;
esac

dir="${{STREAMSCOPE_INSTALL_DIR:-$HOME/.local/bin}}"
mkdir -p "$dir"
tmp=$(mktemp "$dir/.ssai.XXXXXX")
trap 'rm -f "$tmp" "${{FETCHED_FILE:-}}"' EXIT

# ---- TLS trust ----------------------------------------------------------
# A self-signed / private-CA gateway is not trusted by a fresh machine, so the
# download below would fail. Detect that, capture the gateway's CA chain, and
# (with consent) install it into the OS trust store. Node / Python CLIs ignore
# the OS store, so we also build an ADDITIVE bundle (system CAs + gateway chain)
# and point THEM at it — never the gateway-only file, which would replace the
# whole trust store and break every other CA (e.g. a corporate root that already
# validates the gateway). Mirror the CLI's config_dir() (XDG_CONFIG_HOME first)
# so provisioning's gateway_ca_file()/gateway_bundle_file() find the same paths.
CA_DIR="${{XDG_CONFIG_HOME:-$HOME/.config}}/streamscopeai"
# One root per private gateway installed from, in its own file — a reinstall
# from that gateway replaces it — so the CLI, which serves several gateways,
# trusts each of them. CA_FILE is all of them together, for the tools that
# take one file.
CA_D="$CA_DIR/gateway-ca.d"
CA_FILE="$CA_DIR/gateway-ca.pem"
BUNDLE_FILE="$CA_DIR/gateway-bundle.pem"
FETCHED_FILE="$CA_DIR/.gateway-ca.fetched.pem"
# One name per gateway however its address was spelled: host[:port], lowercase.
CA_NAME="$(printf '%s' "$ORIGIN" | sed 's#^[A-Za-z]*://##; s#/.*##' | tr 'A-Z' 'a-z' | sed 's#[^a-z0-9.-]#_#g')"
ORIGIN_CA="$CA_D/$CA_NAME.pem"
CURL_CA=""

# Whether $1 holds a certificate: openssl's reading where it is installed,
# else a complete PEM block.
is_certificate() {{
  if command -v openssl >/dev/null 2>&1; then
    openssl x509 -in "$1" -noout >/dev/null 2>&1
  else
    grep -q -- '-----BEGIN CERTIFICATE-----' "$1" && grep -q -- '-----END CERTIFICATE-----' "$1"
  fi
}}

# Keep the root fetched in $1 as this gateway's ($2), then rebuild CA_FILE from
# every gateway's that is a certificate — a damaged one is left out, so it
# costs no other gateway its trust in the tools that read CA_FILE. A body that
# is not a certificate, or a step that fails, ends it with status 1 (called
# under `if`, `set -e` does not stop it).
capture_root() {{
  is_certificate "$1" || return 1
  mkdir -p "$CA_D" || return 1
  cp "$1" "$2" || return 1
  chmod 0600 "$2" 2>/dev/null || true
  for f in "$CA_D"/*.pem; do
    [ -f "$f" ] || continue
    if ! is_certificate "$f"; then
      echo "  WARNING: $f is not a certificate — left out; remove it." >&2
      continue
    fi
    cat "$f" || return 1
    echo
  done > "$CA_FILE.tmp" || return 1
  chmod 0600 "$CA_FILE.tmp" 2>/dev/null || true
  mv "$CA_FILE.tmp" "$CA_FILE" || return 1
}}

# Locate the OS's PEM CA bundle so the gateway chain can be APPENDED to it rather
# than replace it. Prints the path on stdout; returns 1 when none is found.
find_system_ca_bundle() {{
  for c in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
    [ -f "$c" ] && {{ echo "$c"; return 0; }}
  done
  od=$(openssl version -d 2>/dev/null | sed -n 's/.*"\(.*\)".*/\1/p')
  [ -n "$od" ] || return 1
  for c in "$od/cert.pem" "$od/certs/ca-certificates.crt"; do
    [ -f "$c" ] && {{ echo "$c"; return 0; }}
  done
  return 1
}}

case "$ORIGIN" in
  https://*)
    # Asked of the system store alone: a bundle this installer once printed
    # exports for (CURL_CA_BUNDLE, SSL_CERT_FILE) must not stand in for it, or a
    # root the CLI has lost is never captured again.
    if ! env -u CURL_CA_BUNDLE -u SSL_CERT_FILE curl -fsS -o /dev/null "$ORIGIN/api/health" 2>/dev/null; then
      echo "The gateway's TLS certificate is not trusted by this machine."
      mkdir -p "$CA_DIR"
      # Trust-on-first-use. The TLS handshake never sends the root CA — it
      # presents only the short-lived leaf + intermediate — so we fetch the root
      # (the stable anchor) from the gateway's CA endpoint. That fetch is over an
      # as-yet-untrusted connection, so the operator MUST validate the printed
      # fingerprint + serial out-of-band before trusting it; that validation is
      # the only thing standing between this and a MITM'd CA. If the gateway
      # publishes no root, there's nothing to trust automatically — warn + stop.
      if curl -fsSk "$ORIGIN/api/v1/cli/ca" -o "$FETCHED_FILE" 2>/dev/null && [ -s "$FETCHED_FILE" ]; then
        if ! capture_root "$FETCHED_FILE" "$ORIGIN_CA"; then
          echo "ssai: could not keep a root CA from $ORIGIN/api/v1/cli/ca in $CA_D (not a certificate, or not writable)." >&2
          exit 1
        fi
        CURL_CA="--cacert $ORIGIN_CA"
        echo "Kept the gateway root CA as $ORIGIN_CA (beside any other gateway's)"
        if command -v openssl >/dev/null 2>&1; then
          subject=$(openssl x509 -in "$ORIGIN_CA" -noout -subject 2>/dev/null | sed 's/^subject=//')
          serial=$(openssl x509 -in "$ORIGIN_CA" -noout -serial 2>/dev/null | sed 's/.*=//')
          fp=$(openssl x509 -in "$ORIGIN_CA" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//')
          echo "  Root CA subject: $subject"
          echo "  Root CA serial:  $serial"
          echo "  Root CA SHA-256: $fp"
          echo "  VALIDATE these match the gateway operator's published values before trusting."
        else
          echo "  WARNING: openssl not found — cannot show the CA serial/fingerprint to validate."
        fi
        # Additive bundle for OpenSSL/Python/curl clients: the full system trust
        # set PLUS every captured gateway root. SSL_CERT_FILE points here so every other CA
        # keeps working (the gateway-only file would discard them).
        sys_ca=$(find_system_ca_bundle || true)
        if [ -n "$sys_ca" ]; then
          cat "$sys_ca" "$CA_FILE" > "$BUNDLE_FILE"
        else
          cp "$CA_FILE" "$BUNDLE_FILE"
          echo "  WARNING: no system CA bundle found — SSL_CERT_FILE will trust ONLY the gateway."
        fi
        chmod 0600 "$BUNDLE_FILE" 2>/dev/null || true
        printf "Validated the serial/fingerprint above? Install this root CA into the system trust store (needs sudo)? [y/N] "
        if read ans </dev/tty 2>/dev/null; then :; else ans=""; fi
        case "$ans" in
          y|Y|yes|YES)
            # This gateway's root alone, one file per gateway, so the updater
            # rehashes it as a trust anchor and another gateway's stays.
            if command -v update-ca-certificates >/dev/null 2>&1 && [ -d /usr/local/share/ca-certificates ]; then
              sudo cp "$ORIGIN_CA" "/usr/local/share/ca-certificates/streamscope-gateway-$CA_NAME.crt" && sudo update-ca-certificates
            elif command -v update-ca-trust >/dev/null 2>&1 && [ -d /etc/pki/ca-trust/source/anchors ]; then
              sudo cp "$ORIGIN_CA" "/etc/pki/ca-trust/source/anchors/streamscope-gateway-$CA_NAME.crt" && sudo update-ca-trust
            elif command -v security >/dev/null 2>&1; then
              sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$ORIGIN_CA"
            else
              echo "  (no known trust-store updater found — skipping OS install)"
            fi ;;
          *) echo "  Skipped OS install — this installer uses $ORIGIN_CA directly." ;;
        esac
        rm -f "$FETCHED_FILE"
        # Confirm the fetched root — it alone, not another gateway's — validates
        # a genuine handshake. This catches a stale/misconfigured published root
        # early; the operator-validated serial/fingerprint above is what defends
        # against an active MITM.
        if curl -fsS --cacert "$ORIGIN_CA" -o /dev/null "$ORIGIN/api/v1/cli/version" 2>/dev/null; then
          echo "Verified: the gateway certificate validates against the fetched root CA."
        else
          echo "ssai: WARNING — the fetched root CA does not validate a TLS handshake to $ORIGIN." >&2
          echo "  The download below uses it anyway; if it fails, install the gateway CA manually and re-run." >&2
        fi
        echo "NOTE: Node / Python CLIs ignore the OS trust store. Add these to your shell"
        echo "      profile so the provisioned CLIs trust the gateway:"
        echo "  export NODE_EXTRA_CA_CERTS=$CA_FILE"
        echo "  export SSL_CERT_FILE=$BUNDLE_FILE"
        echo "  export REQUESTS_CA_BUNDLE=$BUNDLE_FILE"
        echo "  export CURL_CA_BUNDLE=$BUNDLE_FILE"
      else
        echo "ssai: the gateway certificate is not trusted and it publishes no root CA at $ORIGIN/api/v1/cli/ca." >&2
        echo "  Install the gateway's CA into your trust store manually, then re-run." >&2
        exit 1
      fi
    fi
    ;;
esac

echo "Downloading ssai v$VERSION ($target) from $ORIGIN ..."
# shellcheck disable=SC2086  # CURL_CA is intentionally word-split into flags
curl -fsSL $CURL_CA "$ORIGIN/api/v1/cli/download/$target" -o "$tmp"

if command -v sha256sum >/dev/null 2>&1; then
  got_sha=$(sha256sum "$tmp" | awk '{{print $1}}')
else
  got_sha=$(shasum -a 256 "$tmp" | awk '{{print $1}}')
fi
if [ "$got_sha" != "$WANT_SHA" ]; then
  echo "ssai: sha256 mismatch (got $got_sha, want $WANT_SHA) — aborting" >&2
  exit 1
fi

chmod 0755 "$tmp"
mv "$tmp" "$dir/ssai"
trap - EXIT

# $VERSION is the GATEWAY's version; the binary is a separate artifact on it.
# A gateway whose CLI artifact is stale therefore advertises its own current
# version and hands over an old client, which then speaks a wire format that
# same gateway no longer accepts — and neither side ever says so. Report what
# the installed binary says about ITSELF, and name the disagreement when there
# is one.
got_version=$("$dir/ssai" --version 2>/dev/null | awk '{{print $NF}}') || got_version=""
if [ -z "$got_version" ]; then
  echo "Installed $dir/ssai (gateway advertised v$VERSION; the binary reported no version)"
elif [ "$got_version" != "$VERSION" ]; then
  echo "ssai: WARNING - this gateway advertises v$VERSION but served a v$got_version binary." >&2
  echo "  Its CLI artifact is out of date; logging in may fail against it. Tell the gateway operator." >&2
  echo "Installed $dir/ssai (v$got_version)"
else
  echo "Installed $dir/ssai (v$VERSION)"
fi
case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "NOTE: $dir is not on your PATH — add:  export PATH=\"$dir:\$PATH\"" ;;
esac
echo "Next: ssai login <your portal URL>"
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_prefers_forwarded_proto() {
        let mut h = axum::http::HeaderMap::new();
        h.insert(header::HOST, "gw.example.com".parse().unwrap());
        h.insert("x-forwarded-proto", "https".parse().unwrap());
        assert_eq!(request_origin(&h), "https://gw.example.com");
    }

    #[test]
    fn origin_prefers_forwarded_host_over_host() {
        let mut h = axum::http::HeaderMap::new();
        h.insert(header::HOST, "admin-api:9090".parse().unwrap());
        h.insert("x-forwarded-host", "gw.example.com".parse().unwrap());
        h.insert("x-forwarded-proto", "https".parse().unwrap());
        assert_eq!(request_origin(&h), "https://gw.example.com");
    }

    #[test]
    fn origin_defaults_to_http_when_unproxied() {
        let mut h = axum::http::HeaderMap::new();
        h.insert(header::HOST, "localhost:9090".parse().unwrap());
        assert_eq!(request_origin(&h), "http://localhost:9090");
    }

    #[test]
    fn install_script_embeds_origin_version_and_sha() {
        let s = render_install_script("https://gw", "2026.5.1", &[("linux-x86_64", "abc123")]);
        assert!(s.starts_with("#!/bin/sh"));
        assert!(s.contains("ORIGIN=\"https://gw\""));
        assert!(s.contains("VERSION=\"2026.5.1\""));
        // Each target binds its own sha inside its case arm.
        assert!(s.contains("Linux-x86_64) target=\"linux-x86_64\"; WANT_SHA=\"abc123\""));
        // The braces in the heredoc-style template must survive format!().
        assert!(s.contains("${STREAMSCOPE_INSTALL_DIR:-$HOME/.local/bin}"));
        assert!(s.contains("awk '{print $1}'"));
    }

    #[test]
    fn install_script_lists_darwin_arm_only_when_shipped() {
        // Both targets shipped: each gets its own arm + per-target sha, and the
        // unsupported message lists both labels.
        let both = render_install_script(
            "https://gw",
            "2026.5.1",
            &[("linux-x86_64", "lll"), ("darwin-arm64", "ddd")],
        );
        assert!(both.contains("Linux-x86_64) target=\"linux-x86_64\"; WANT_SHA=\"lll\""));
        assert!(both.contains("Darwin-arm64) target=\"darwin-arm64\"; WANT_SHA=\"ddd\""));
        assert!(both.contains("supported: Linux x86_64, macOS Apple Silicon"));

        // Linux-only image: no Darwin arm, and the message names only Linux.
        let linux_only = render_install_script("https://gw", "2026.5.1", &[("linux-x86_64", "lll")]);
        assert!(!linux_only.contains("Darwin-arm64"));
        assert!(linux_only.contains("supported: Linux x86_64)"));
    }

    #[test]
    fn install_script_fetches_and_validates_root_ca() {
        let s = render_install_script("https://gw", "2026.5.1", &[("linux-x86_64", "abc123")]);
        // Trust-on-first-use: fetch the gateway's published ROOT CA (the handshake
        // never sends it) over an as-yet-untrusted connection, and ADD it to the
        // captured roots in gateway-ca.pem, never over another gateway's…
        assert!(s.contains("curl -fsSk \"$ORIGIN/api/v1/cli/ca\" -o \"$FETCHED_FILE\""));
        assert!(s.contains("capture_root \"$FETCHED_FILE\" \"$ORIGIN_CA\""));
        assert!(s.contains("gateway-ca.pem"));
        // …print the serial + SHA-256 fingerprint + subject for out-of-band validation…
        assert!(s.contains("-fingerprint -sha256"));
        assert!(s.contains("-noout -serial"));
        assert!(s.contains("Root CA serial:"));
        assert!(s.contains("Root CA SHA-256:"));
        // …offer an OS-trust-store install of the single root cert (Debian + RHEL + macOS)…
        assert!(s.contains("update-ca-certificates"));
        assert!(s.contains("update-ca-trust"));
        assert!(s.contains("add-trusted-cert"));
        // …build an ADDITIVE bundle (system CAs + root) and point the replace-the-store
        // env vars at THAT, never the gateway-only file…
        assert!(s.contains("gateway-bundle.pem"));
        assert!(s.contains("find_system_ca_bundle"));
        assert!(s.contains("export NODE_EXTRA_CA_CERTS=$CA_FILE"));
        assert!(s.contains("export SSL_CERT_FILE=$BUNDLE_FILE"));
        assert!(s.contains("export REQUESTS_CA_BUNDLE=$BUNDLE_FILE"));
        // …confirm a real handshake validates against the fetched root…
        assert!(s.contains("curl -fsS --cacert \"$ORIGIN_CA\""));
        // No fallback: an untrusted cert with no published root is a hard error,
        // never a silent leaf-pin (the served chain is never captured/trusted).
        assert!(!s.contains("openssl s_client"));
        assert!(s.contains("publishes no root CA"));
        // The binary download must use the fetched CA when one was needed.
        assert!(s.contains("curl -fsSL $CURL_CA"));
    }

    #[test]
    fn the_powershell_installer_embeds_its_values_as_quoted_strings() {
        let s = render_install_ps1("https://gw", "2026.5.1", "abc123");
        assert!(s.contains("$Origin = 'https://gw'"));
        assert!(s.contains("$Version = '2026.5.1'"));
        assert!(s.contains("$WantSha = 'abc123'"));
        assert!(!s.contains("__ORIGIN__") && !s.contains("__VERSION__") && !s.contains("__SHA256__"));
        // It verifies the download against that sha, and fetches the Windows build.
        assert!(s.contains("Get-FileHash -Algorithm SHA256"));
        assert!(s.contains("/api/v1/cli/download/windows-x86_64"));
        // A running ssai.exe steps aside under the name the CLI removes on its next start.
        assert!(s.contains("'ssai.old.exe'"));
    }

    /// The origin comes from request headers: a quote in it stays inside the
    /// string it lands in, so it can never end the string and run as code.
    #[test]
    fn a_quote_in_the_origin_cannot_leave_its_string() {
        let s = render_install_ps1("https://gw'; Remove-Item x; '", "v", "s");
        let line = s.lines().find(|l| l.trim_start().starts_with("$Origin = ")).unwrap();
        assert_eq!(line.trim(), "$Origin = 'https://gw''; Remove-Item x; '''");
        // Inside the outer quotes every quote is doubled: none ends the string.
        let inner = line.trim().strip_prefix("$Origin = '").unwrap().strip_suffix('\'').unwrap();
        assert!(inner.split("''").all(|part| !part.contains('\'')), "{inner}");
    }

    /// A placeholder spelled inside the origin (a request header) stays text.
    #[test]
    fn a_placeholder_in_the_origin_is_not_filled() {
        let s = render_install_ps1("https://gw__SHA256__.example", "v", "abc");
        assert!(s.contains("$Origin = 'https://gw__SHA256__.example'"));
        assert!(s.contains("$WantSha = 'abc'"));
    }
}

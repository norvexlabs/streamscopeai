//! Custom CA trust for outbound HTTPS clients.
//!
//! A platform operator can import a PEM CA bundle (super-admin setting
//! `CUSTOM_CA_BUNDLE_PEM`) so the gateway trusts upstreams served by a private
//! or internal CA. The bundle augments the system roots — it never replaces
//! them, and certificate verification is never disabled.

use std::sync::{Arc, LazyLock, RwLock};

/// The CA bundle this process trusts for outbound HTTPS beside the system
/// roots: the environment's `CUSTOM_CA_BUNDLE_PEM` at start; admin-api
/// replaces it with the bundle a super-admin uploads in the console. A client
/// that must follow an upload without a restart reads it from here.
static TRUSTED_CA: LazyLock<RwLock<Option<Arc<str>>>> = LazyLock::new(|| {
    RwLock::new(crate::settings::core_settings().custom_ca_bundle.as_deref().map(Arc::from))
});

/// The process's trusted CA bundle. An unchanged bundle stays the same `Arc`,
/// so comparing two reads (by content) settles on the pointer at once.
pub fn trusted_ca() -> Option<Arc<str>> {
    TRUSTED_CA.read().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
}

/// Replace the process's trusted CA bundle; the same text keeps the same `Arc`.
pub fn set_trusted_ca(pem: Option<&str>) {
    if trusted_ca().as_deref() == pem {
        return;
    }
    let mut held = TRUSTED_CA.write().unwrap_or_else(std::sync::PoisonError::into_inner);
    if held.as_deref() != pem {
        *held = pem.map(Arc::from);
    }
}

/// Parse + validate a PEM CA bundle, returning the number of certificates it
/// contains or a human-readable reason it is unusable. Use this to reject a
/// broken paste at **save time** (the admin runtime-config endpoint) so the
/// operator gets immediate feedback, instead of the bundle silently failing to
/// parse later when the proxy builds its outbound client. Same parser
/// [`add_custom_roots`] uses, so "validates here" ⇒ "loads there".
pub fn validate_ca_bundle(pem: &str) -> Result<usize, String> {
    let trimmed = pem.trim();
    if trimmed.is_empty() {
        return Err("empty certificate bundle".to_string());
    }
    match reqwest::Certificate::from_pem_bundle(trimmed.as_bytes()) {
        Ok(certs) if certs.is_empty() => Err(
            "no PEM certificates found — paste the full \
             -----BEGIN CERTIFICATE----- … -----END CERTIFICATE----- block(s)"
                .to_string(),
        ),
        Ok(certs) => Ok(certs.len()),
        Err(e) => Err(format!(
            "not a valid PEM certificate bundle ({e}) — check the \
             -----BEGIN/END CERTIFICATE----- markers and that the line breaks \
             were preserved when pasting"
        )),
    }
}

/// Add every certificate in a PEM bundle to a reqwest client builder, on top of
/// the system root store. A `None`/empty bundle is a no-op. A bundle that fails
/// to parse is logged and skipped — the client still builds with the system
/// roots, never fail-open with verification disabled.
pub fn add_custom_roots(
    builder: reqwest::ClientBuilder,
    pem_bundle: Option<&str>,
) -> reqwest::ClientBuilder {
    let Some(pem) = pem_bundle.map(str::trim).filter(|p| !p.is_empty()) else {
        return builder;
    };
    match reqwest::Certificate::from_pem_bundle(pem.as_bytes()) {
        Ok(certs) => {
            let mut b = builder;
            let n = certs.len();
            for cert in certs {
                b = b.add_root_certificate(cert);
            }
            tracing::info!("trusting {n} custom CA certificate(s) for outbound HTTPS");
            b
        }
        Err(e) => {
            tracing::warn!(
                "ignoring custom CA bundle — failed to parse as PEM: {e}; using system roots only"
            );
            builder
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A throwaway self-signed CA (the content doesn't matter — only that it is a
    // well-formed PEM CERTIFICATE block reqwest accepts).
    const VALID_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDDzCCAfegAwIBAgIUC5lMdmm4wBJTB293yW7MwRoymM8wDQYJKoZIhvcNAQEL\n\
BQAwFzEVMBMGA1UEAwwMdW5pdC10ZXN0LWNhMB4XDTI2MDYxODIwNDAwNFoXDTI2\n\
MDYxOTIwNDAwNFowFzEVMBMGA1UEAwwMdW5pdC10ZXN0LWNhMIIBIjANBgkqhkiG\n\
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoE9WRoMMHptXT8tn4yRg9Ss29TtbWJ6wDoNs\n\
skRwR3dGmpTZB8/SMrR4LCZZ6EBwtpnVMDooNOsJBupYCOTTWBacEWNsiuVKbjHd\n\
T0Y/G5R3NXeOmIwvm7awAU+ra5F45z7TLaiBqtfN50Px+aw8/A8WsCJTf/5X+uWv\n\
3jca/RbHyuP5LcEqUVS7HgvdNHX8lflNHyubwlbi00OGPHjhXMVHLgu1zW1hFeC7\n\
OqXpa+LSJ12TPUSljrl6KLMvsO+Oy88JyB7DnKZHNagK0dSABNYGLuAwSt9WRkzy\n\
rzYOcJjpxExFXvyOlW9GJGHZ+oKJ2zIbsf8unajOdARsC82aHwIDAQABo1MwUTAd\n\
BgNVHQ4EFgQULLMqe6+0AJqDoDh2ZvDfvGSvgO8wHwYDVR0jBBgwFoAULLMqe6+0\n\
AJqDoDh2ZvDfvGSvgO8wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC\n\
AQEAjPEeOJzkr9OEzMLSZZgsWVYRmmMdSbqTrheOEKUjoowZ1QFoDeGfnjq7A3Fp\n\
OfeRtDPZipePUrC3u99qwkWkenIJZBnqxGTtHZjFYhycEK7WVhR9kpVIqXqveXrl\n\
grIK5ySXPcz+xaVOQENp/WkuRuFD9Hpm66fhCAMIDKQcDfMkkJwHUzKYGqKjNLBT\n\
YAtdbPrnt+kUYWniPrmwC/8TvqzqeqWd7nRPvD3o9mc3H7ycUlA5PdVMCd0FWwrC\n\
9H485Pp1KVSXvQbbPnOJmLAv6RiI6L2cO1op5DWaQ3PvoNjL3oYkl8ZvMVL4j6V5\n\
sG5cRPHiPR7lBmKAUKWXVn942w==\n\
-----END CERTIFICATE-----\n";

    #[test]
    fn valid_bundle_reports_cert_count() {
        assert_eq!(validate_ca_bundle(VALID_PEM), Ok(1));
    }

    #[test]
    fn empty_or_blank_is_rejected() {
        assert!(validate_ca_bundle("").is_err());
        assert!(validate_ca_bundle("   \n  ").is_err());
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(validate_ca_bundle("not a certificate at all").is_err());
    }

    #[test]
    fn pem_with_literal_backslash_n_is_rejected() {
        // The classic broken paste: real newlines replaced with the two-character
        // sequence `\n`, so there are no actual line breaks around the base64.
        let broken = VALID_PEM.replace('\n', "\\n");
        assert!(validate_ca_bundle(&broken).is_err());
    }
}

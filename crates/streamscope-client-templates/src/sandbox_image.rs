//! The container sandbox's image and its limits, as a project's
//! `sandbox.json` names them and as a Portal & clients profile sets the
//! default for a project without one. One set of rules, read by the CLI and
//! by the server that stores a profile's default.

use std::fmt;

/// podman's path transports: an image read from this machine's files, never
/// from a registry.
const PATH_TRANSPORTS: &[&str] =
    &["dir", "oci", "oci-archive", "docker-archive", "containers-storage", "docker-daemon", "sif", "tarball", "ostree"];

/// The longest image reference taken.
pub const MAX_IMAGE_LEN: usize = 512;

/// A positional image reference from a registry: not empty, not an option,
/// one word, no path transport. Checked as podman reads it: a path transport
/// behind `docker://` is still one.
pub fn image_reference(image: &str) -> bool {
    let whole = image.len();
    let image = image.strip_prefix("docker://").unwrap_or(image);
    !image.is_empty()
        && whole <= MAX_IMAGE_LEN
        && !image.starts_with('-')
        && !image.chars().any(|c| c.is_whitespace() || c.is_control())
        && !image.split_once(':').is_some_and(|(scheme, _)| PATH_TRANSPORTS.contains(&scheme))
}

/// A podman `--memory` size: digits, then at most one unit (`b`, `k`, `m`,
/// `g`, either case) — `6g`, `512m`.
pub fn memory(size: &str) -> bool {
    let digits = size.strip_suffix(['b', 'k', 'm', 'g', 'B', 'K', 'M', 'G']).unwrap_or(size);
    !digits.is_empty() && digits.len() <= 18 && digits.bytes().all(|b| b.is_ascii_digit())
}

/// A podman `--cpus` count: above 0, at most 1024.
pub fn cpus(count: f64) -> bool {
    count > 0.0 && count <= 1024.0
}

/// A profile's default for the container sandbox: the image a project
/// without a `sandbox.json` runs in, whether it has an engine inside, and
/// its limits. A project's own `sandbox.json` replaces all of it.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DefaultImage {
    /// An image reference from a registry (`mcr.microsoft.com/devcontainers/base:ubuntu`).
    pub image: String,
    /// Run a Docker engine inside the container (it then runs privileged).
    #[serde(default)]
    pub docker: bool,
    /// The container's memory limit (`8g`); none = podman's default.
    #[serde(default)]
    pub memory: Option<String>,
    /// The container's CPU limit; none = podman's default.
    #[serde(default)]
    pub cpus: Option<f64>,
}

/// Why a [`DefaultImage`] is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefaultImageError {
    Image,
    Memory,
    Cpus,
}

impl fmt::Display for DefaultImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Image => "`image` must be an image reference from a registry (one word, no `dir:` or other path transport)",
            Self::Memory => "`memory` must be a size such as \"8g\"",
            Self::Cpus => "`cpus` must be above 0 and at most 1024",
        })
    }
}

impl DefaultImage {
    /// The rules above, on every field.
    pub fn validate(&self) -> Result<(), DefaultImageError> {
        if !image_reference(&self.image) {
            return Err(DefaultImageError::Image);
        }
        if self.memory.as_deref().is_some_and(|m| !memory(m)) {
            return Err(DefaultImageError::Memory);
        }
        if self.cpus.is_some_and(|c| !cpus(c)) {
            return Err(DefaultImageError::Cpus);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_image_is_a_registry_reference_and_nothing_else() {
        for ok in ["ubuntu", "mcr.microsoft.com/devcontainers/base:ubuntu", "docker://ghcr.io/a/b:1", "x@sha256:abc", "localhost/x:1"] {
            assert!(image_reference(ok), "{ok}");
        }
        for bad in ["", "-v", "a b", "a\nb", "oci-archive:/tmp/x", "docker://dir:/x", "dir:/x", &"a".repeat(MAX_IMAGE_LEN + 1)] {
            assert!(!image_reference(bad), "{bad:?}");
        }
        assert!(image_reference(&"a".repeat(MAX_IMAGE_LEN)));
        // The cap is on the whole text, a `docker://` prefix included.
        assert!(!image_reference(&format!("docker://{}", "a".repeat(MAX_IMAGE_LEN - 8))));
        assert!(image_reference(&format!("docker://{}", "a".repeat(MAX_IMAGE_LEN - 9))));
    }

    #[test]
    fn a_limit_is_a_size_or_a_count_in_range() {
        for ok in ["6g", "512m", "1024", "8G", "1b"] {
            assert!(memory(ok), "{ok}");
        }
        for bad in ["", "g", "6gb", "-1g", "1.5g", "6 g", "99999999999999999999g"] {
            assert!(!memory(bad), "{bad:?}");
        }
        assert!(cpus(0.5) && cpus(1024.0));
        assert!(!cpus(0.0) && !cpus(1024.01) && !cpus(-1.0) && !cpus(f64::NAN));
    }

    #[test]
    fn a_default_image_is_checked_whole() {
        let ok = DefaultImage { image: "ubuntu:24.04".into(), docker: true, memory: Some("8g".into()), cpus: Some(4.0) };
        assert_eq!(ok.validate(), Ok(()));
        assert_eq!(DefaultImage { image: "dir:/x".into(), ..ok.clone() }.validate(), Err(DefaultImageError::Image));
        assert_eq!(DefaultImage { memory: Some("lots".into()), ..ok.clone() }.validate(), Err(DefaultImageError::Memory));
        assert_eq!(DefaultImage { cpus: Some(0.0), ..ok }.validate(), Err(DefaultImageError::Cpus));
        let bare: DefaultImage = serde_json::from_str(r#"{"image": "ubuntu"}"#).unwrap();
        assert_eq!(bare, DefaultImage { image: "ubuntu".into(), docker: false, memory: None, cpus: None });
    }
}

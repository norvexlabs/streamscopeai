//! `ssai logout` — revoke this device's token pair server-side
//! (RFC 7009 kills the refresh jti and its paired access jti instantly),
//! then forget the local tokens. Provisioned config files are left in place.

use anyhow::Result;

use crate::api;
use crate::state::HostsFile;

pub async fn run(selector: Option<&str>) -> Result<()> {
    let mut hosts = HostsFile::load()?;
    let (key, entry) = hosts.select(selector)?;

    if let Err(e) = api::revoke(&entry.api_origin, &entry.tenant_slug, &entry.refresh_token).await {
        // Local forget still proceeds — the refresh token dies at its 30d
        // expiry server-side; the gateway admin can revoke it sooner.
        crate::ui::warn("", format_args!("server-side revocation failed ({e:#}); tokens forgotten locally"));
    }

    hosts.hosts.remove(&key);
    hosts.save()?;
    println!(
        "Logged out of {} (tenant {}). Provisioned config files were left untouched.",
        entry.origin, entry.tenant_slug
    );
    Ok(())
}

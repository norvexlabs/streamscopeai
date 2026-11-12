//! `ssai login <portal-url>` — OAuth against the gateway's CLI OAuth
//! surface. Two interactive grants:
//!
//! * **Loopback PKCE** (default): the browser leg authenticates the user with
//!   whatever the tenant uses (password or SSO) and lands on the consent
//!   page; the code comes back on a one-shot 127.0.0.1 listener.
//! * **Device grant** (RFC 8628, `--device` or automatic when no local
//!   browser can open): the gateway issues a short `XXXX-XXXX` code the user
//!   enters on the portal approval page from any machine, while the CLI
//!   polls the token endpoint. This is the path for SSH sessions — a printed
//!   authorize URL is useless there because its redirect targets the remote
//!   machine's own 127.0.0.1.

use anyhow::{bail, Context, Result};

use crate::api;
use crate::oauth;
use crate::state::{host_key, HostEntry, HostsFile};

use super::session::{ask_text, jwt_email};

pub async fn run(
    portal_url: Option<String>,
    no_browser: bool,
    device: bool,
    device_name: Option<String>,
) -> Result<()> {
    // No URL on the command line: ask for it (an empty stdin is an error).
    let portal_url = match portal_url {
        Some(url) => url,
        None => match ask_text("Portal URL", "https://gw.example.com/portal/t/acme", validate_portal_url) {
            Ok(url) => url,
            Err(e) if e.downcast_ref::<crate::Cancelled>().is_some() => return Err(e),
            Err(e) => {
                return Err(e.context(
                    "no portal URL — run: ssai login <portal-url> (copy it from your portal's Quickstart page)",
                ));
            }
        },
    };
    let portal_url = portal_url.as_str();
    let (origin, slug) = oauth::parse_portal_url(portal_url)?;
    let Some(slug) = slug else {
        bail!(
            "couldn't find your tenant in {portal_url:?} — copy the URL from your portal's \
             Quickstart page (it looks like https://host/portal/t/<tenant>/...)"
        );
    };

    let metadata = api::fetch_metadata(&origin, &slug).await?;
    let device_name = device_name.unwrap_or_else(default_device_name);

    let pair = if device {
        device_login(&metadata, &device_name).await?
    } else {
        loopback_login(&metadata, &device_name, no_browser).await?
    };

    let email = jwt_email(&pair.access_token);
    let mut hosts = HostsFile::load()?;
    hosts.hosts.insert(
        host_key(&origin, &slug),
        HostEntry {
            origin: origin.clone(),
            api_origin: metadata.api_origin.trim_end_matches('/').to_string(),
            tenant_slug: slug.clone(),
            access_token: pair.access_token,
            refresh_token: pair.refresh_token,
            access_expires_at: chrono::Utc::now() + chrono::Duration::seconds(pair.expires_in),
            user_email: email.clone(),
            device_name: Some(device_name),
        },
    );
    hosts.save()?;

    match email {
        Some(email) => println!(
            "{} Logged in to {} (tenant {slug}) as {email}.",
            crate::ui::check(),
            crate::ui::accent(&origin)
        ),
        None => println!("{} Logged in to {} (tenant {slug}).", crate::ui::check(), crate::ui::accent(&origin)),
    }
    println!("{} {}", crate::ui::muted("Next:"), crate::ui::accent("ssai provision"));
    Ok(())
}

/// Loopback-PKCE grant. Falls back to the device grant when no local browser
/// could be opened (and the user didn't explicitly ask for `--no-browser`).
async fn loopback_login(
    metadata: &api::ServerMetadata,
    device_name: &str,
    no_browser: bool,
) -> Result<api::TokenResponse> {
    let pkce = oauth::generate_pkce();
    let state = oauth::generate_state();

    let listener = oauth::LoopbackListener::bind().await?;
    let redirect_uri = listener.redirect_uri.clone();
    let mut authorize = url::Url::parse(&metadata.authorization_endpoint)
        .context("gateway returned an invalid authorization endpoint")?;
    authorize
        .query_pairs_mut()
        .append_pair("client_id", api::CLI_CLIENT_ID)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("state", &state)
        .append_pair("code_challenge", &pkce.challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("scope", "provision")
        .append_pair("device_name", device_name);
    let authorize_url = authorize.to_string();

    if no_browser {
        println!("Open this URL in your browser to log in:");
    } else if oauth::open_browser(&authorize_url) {
        println!("Opening your browser to log in…");
    } else {
        // Headless box: the loopback redirect only resolves on THIS machine,
        // so a printed URL can't complete from anywhere else — switch grants.
        println!("No browser available here — switching to device login.");
        return device_login(metadata, device_name).await;
    }
    println!("\n  {}\n", crate::ui::accent(&authorize_url));
    println!("Waiting for the login to complete…");

    let code = listener.receive_code(&state, &metadata.issuer).await?;
    api::exchange_code(&metadata.token_endpoint, &code, &redirect_uri, &pkce.verifier)
        .await
        .context("token exchange failed")
}

/// RFC 8628 device grant: display the user code, poll the token endpoint
/// until the user approves on the portal page (from any browser, anywhere).
async fn device_login(
    metadata: &api::ServerMetadata,
    device_name: &str,
) -> Result<api::TokenResponse> {
    let auth =
        api::device_authorization(&metadata.device_authorization_endpoint, device_name).await?;
    println!("On any device, open:\n\n  {}\n", crate::ui::accent(&auth.verification_uri));
    println!("and enter the code:    {}\n", crate::ui::accent(&auth.user_code).bold());
    println!(
        "{}",
        crate::ui::muted(format!("(or open {} directly)", auth.verification_uri_complete))
    );
    println!("Waiting for approval…");

    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(auth.expires_in.max(0) as u64);
    let mut interval = auth.interval.max(1) as u64;
    let mut reported_hiccup = false;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
        if std::time::Instant::now() >= deadline {
            bail!("the device code expired before the login was approved — run `ssai login` again");
        }
        match api::poll_device_token(&metadata.token_endpoint, &auth.device_code).await? {
            api::DevicePoll::Token(pair) => return Ok(pair),
            api::DevicePoll::Pending => {}
            // RFC 8628 §3.5: add 5 seconds to the interval on slow_down.
            api::DevicePoll::SlowDown => interval += 5,
            // The code stays valid server-side — ride out network blips and
            // gateway restarts instead of orphaning an approved login.
            api::DevicePoll::Retry(detail) => {
                if !reported_hiccup {
                    crate::ui::notice("  ", format_args!("gateway unreachable — still trying: {detail}"));
                    reported_hiccup = true;
                }
            }
        }
    }
}

/// The answer the `login` prompt accepts: what [`oauth::parse_portal_url`]
/// parses AND carries a tenant, so a pasted origin is refused at the prompt
/// instead of after it.
fn validate_portal_url(input: &str) -> Result<(), &'static str> {
    match oauth::parse_portal_url(input) {
        Ok((_, Some(_))) => Ok(()),
        Ok((_, None)) => Err("no tenant in that URL — it looks like https://host/portal/t/<tenant>/…"),
        Err(_) => Err("not an http(s) URL — copy it from your portal's address bar"),
    }
}

/// This machine's name as the OS reports it (`gethostname` on Unix,
/// `COMPUTERNAME` on Windows); `unknown-device` when it reports none.
fn default_device_name() -> String {
    Some(api::hostname().trim().to_string())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "unknown-device".to_string())
}

#[cfg(test)]
mod tests {
    use super::{default_device_name, validate_portal_url};

    /// The device a login names is the machine's own name, on every OS the
    /// CLI ships for — the OS always reports one where the tests run.
    #[test]
    fn a_login_names_the_device_after_the_machine() {
        let name = default_device_name();
        assert_ne!(name, "unknown-device");
        assert_eq!(name, crate::api::hostname().trim());
    }

    #[test]
    fn the_prompt_accepts_a_portal_url_with_a_tenant() {
        assert_eq!(validate_portal_url("https://gw.example.com/portal/t/acme"), Ok(()));
        assert_eq!(validate_portal_url("  https://gw.example.com/portal/t/acme/quickstart \n"), Ok(()));
        assert_eq!(validate_portal_url("http://127.0.0.1:8080/portal/t/acme"), Ok(()));
    }

    #[test]
    fn the_prompt_refuses_a_url_it_could_not_log_in_with() {
        // An origin alone: parses, but names no tenant.
        assert!(validate_portal_url("https://gw.example.com").is_err());
        assert!(validate_portal_url("https://gw.example.com/portal/").is_err());
        assert!(validate_portal_url("ftp://gw.example.com/portal/t/acme").is_err());
        assert!(validate_portal_url("gw.example.com/portal/t/acme").is_err());
        assert!(validate_portal_url("").is_err());
    }
}

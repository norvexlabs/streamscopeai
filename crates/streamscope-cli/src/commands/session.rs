//! Shared session plumbing: pick the host entry, keep the access token
//! fresh (refresh-grant rotation), hand out an [`ApiClient`].

use anyhow::{Context, Result};
use base64::Engine;

use crate::api::{self, ApiClient};
use crate::state::{HostEntry, HostKey, HostsFile};

pub struct ActiveSession {
    pub key: HostKey,
    pub api: ApiClient,
    /// CI mode: authenticated by a portal `ak-` automation key from
    /// `STREAMSCOPE_AK` — no token files, no prompts (implies `--yes`),
    /// workspace confined server-side to the key's bound workspace.
    pub ci: bool,
}

/// Resolve the gateway for this invocation and return a client with a live
/// access token, rotating the refresh token when the access token is at (or
/// within 60s of) expiry. When `STREAMSCOPE_AK` is set the session is the
/// non-interactive CI path instead: the `ak-` key authenticates every call
/// directly and nothing is read from or written to `hosts.json`.
pub async fn open(selector: Option<&str>) -> Result<ActiveSession> {
    if let Ok(ak) = std::env::var("STREAMSCOPE_AK")
        && !ak.is_empty()
    {
        return open_ci(selector, &ak).await;
    }

    let mut hosts = HostsFile::load()?;
    let (key, mut entry) = hosts.select(selector)?;

    if entry.access_expires_at - chrono::Utc::now() < chrono::Duration::seconds(60) {
        refresh_entry(&mut hosts, &key, &mut entry).await?;
    }

    let api = ApiClient::new(&entry.api_origin, &entry.access_token)?;
    Ok(ActiveSession { key, api, ci: false })
}

/// CI session: `STREAMSCOPE_AK` (a portal automation key) + the gateway URL
/// from `--host` / `STREAMSCOPE_URL`. The key self-identifies its tenant
/// server-side. When the URL carries `/portal/t/<slug>`, OAuth discovery
/// resolves the canonical admin-API origin (the URL may be the UI vhost,
/// which only passes the discovery GET through); a slug-less URL is taken
/// to BE the API origin.
async fn open_ci(selector: Option<&str>, ak: &str) -> Result<ActiveSession> {
    if !ak.starts_with("ak-") {
        anyhow::bail!(
            "STREAMSCOPE_AK doesn't look like a portal automation key (expected an ak-… value)"
        );
    }
    let url = match selector {
        Some(s) => s.to_string(),
        None => std::env::var("STREAMSCOPE_URL")
            .ok()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "STREAMSCOPE_AK is set but no gateway URL — set STREAMSCOPE_URL \
                     (any URL of your tenant's portal) or pass --host"
                )
            })?,
    };
    let (origin, slug) = crate::oauth::parse_portal_url(&url)
        .with_context(|| format!("STREAMSCOPE_URL {url:?} is not a valid gateway URL"))?;
    let api_origin = match &slug {
        Some(slug) => api::fetch_metadata(&origin, slug)
            .await?
            .api_origin
            .trim_end_matches('/')
            .to_string(),
        None => origin.clone(),
    };
    eprintln!("CI mode: authenticating with STREAMSCOPE_AK against {api_origin}.");
    let key = crate::state::host_key(&origin, slug.as_deref().unwrap_or("ak"));
    let api = ApiClient::new(&api_origin, ak)?;
    Ok(ActiveSession { key, api, ci: true })
}

/// Rotate the refresh token and persist the new pair. Refresh failure means
/// the session is dead (revoked / 30d idle) — exit code 2.
pub async fn refresh_entry(
    hosts: &mut HostsFile,
    key: &HostKey,
    entry: &mut HostEntry,
) -> Result<()> {
    let pair = api::refresh(&entry.api_origin, &entry.tenant_slug, &entry.refresh_token)
        .await
        .map_err(|e| {
            anyhow::Error::new(crate::AuthRequired(format!(
                "session expired or revoked ({e:#}) — run: ssai login {}/portal/t/{}",
                entry.origin, entry.tenant_slug
            )))
        })?;
    entry.access_token = pair.access_token;
    entry.refresh_token = pair.refresh_token;
    entry.access_expires_at = chrono::Utc::now() + chrono::Duration::seconds(pair.expires_in);
    hosts.hosts.insert(key.clone(), entry.clone());
    hosts.save()?;
    Ok(())
}

/// Best-effort `email` claim out of a JWT payload (display only — the
/// gateway is the verifier).
pub fn jwt_email(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get("email")?.as_str().map(str::to_string)
}

/// One entry of a pick list: what it is, plus an optional dimmed hint
/// (`connect in the portal first`, what a mode means).
pub struct Choice {
    label: String,
    hint: Option<String>,
}

impl Choice {
    pub fn new(label: impl Into<String>) -> Self {
        Self { label: label.into(), hint: None }
    }

    pub fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// The numbered-prompt rendering.
    fn plain(&self) -> String {
        match &self.hint {
            Some(h) => format!("{}  — {h}", self.label),
            None => self.label.clone(),
        }
    }

    /// The styled-prompt option, carrying its list index as the answer.
    fn option(&self, index: usize) -> demand::DemandOption<usize> {
        let option = demand::DemandOption::with_label(self.label.as_str(), index);
        match &self.hint {
            Some(h) => option.description(h),
            None => option,
        }
    }
}

/// Yes/no question whose default (Enter, or end of input) is YES; `--yes`
/// callers skip it. Styled on a terminal, `[Y/n]` otherwise; Esc / Ctrl-C
/// cancels the command.
pub fn confirm(question: &str) -> Result<bool> {
    confirm_with_default(question, true)
}

/// Confirmation whose default (Enter) is NO — for a step that writes outside
/// what the user asked for.
pub fn confirm_no(question: &str) -> Result<bool> {
    confirm_with_default(question, false)
}

fn confirm_with_default(question: &str, default: bool) -> Result<bool> {
    if crate::ui::styled_prompts() {
        return crate::ui::prompt(|| {
            demand::Confirm::new(question)
                .affirmative("Yes")
                .negative("No")
                .selected(default)
                .theme(crate::ui::theme())
                .run()
        });
    }
    use std::io::Write;
    print!("{question} {} ", if default { "[Y/n]" } else { "[y/N]" });
    std::io::stdout().flush()?;
    let mut line = String::new();
    // End of input takes the default, like an empty answer — an unattended
    // `sync --watch` (stdin at /dev/null) relies on it to re-mint a dead key.
    std::io::stdin().read_line(&mut line)?;
    let t = line.trim().to_lowercase();
    Ok(if t.is_empty() { default } else { t == "y" || t == "yes" })
}

/// Multi-select, everything ticked to start; returns the chosen indices
/// (0-based, de-duplicated, in list order). Styled on a terminal (space
/// toggles, Esc / Ctrl-C cancels the command; no filter, because space toggles
/// even while one is typed). Otherwise numbered: a comma/space list of numbers
/// (e.g. `1,3 5`), `all` (also the default on empty input and EOF), or `none`.
/// Both keep asking until at least `min` are chosen; the numbered form also
/// reprompts on any out-of-range or unparseable entry.
pub fn pick_many(question: &str, items: &[Choice], min: usize) -> Result<Vec<usize>> {
    if crate::ui::styled_prompts() {
        let options = items
            .iter()
            .enumerate()
            .map(|(i, c)| c.option(i).selected(true))
            .collect();
        let mut chosen = crate::ui::prompt(|| {
            demand::MultiSelect::new(question)
                .options(options)
                .min(min)
                .theme(crate::ui::theme())
                .run()
        })?;
        chosen.sort_unstable();
        return Ok(chosen);
    }
    use std::io::Write;
    println!("{question}");
    for (i, item) in items.iter().enumerate() {
        println!("  {}) {}", i + 1, item.plain());
    }
    loop {
        print!("Enter numbers to provision (e.g. 1,3,5 / all / none) [all]: ");
        std::io::stdout().flush()?;
        let mut line = String::new();
        // EOF (piped/non-TTY with nothing to read) defaults to "all".
        if std::io::stdin().read_line(&mut line)? == 0 {
            return Ok((0..items.len()).collect());
        }
        match parse_selection(&line, items.len()) {
            Some(mut chosen) if chosen.len() >= min => {
                chosen.sort_unstable();
                return Ok(chosen);
            }
            Some(_) => println!("pick at least {min}"),
            None => println!(
                "enter numbers between 1 and {} (comma/space separated), or 'all' / 'none'",
                items.len()
            ),
        }
    }
}

/// Parse a multi-select answer against `n` items (1-based input → 0-based,
/// de-duplicated, in entry order). `None` ⇒ unparseable/out-of-range/empty
/// selection — the caller reprompts. Empty input and `all` select everything;
/// `none` selects nothing.
fn parse_selection(input: &str, n: usize) -> Option<Vec<usize>> {
    let t = input.trim().to_lowercase();
    if t.is_empty() || t == "all" {
        return Some((0..n).collect());
    }
    if t == "none" {
        return Some(Vec::new());
    }
    let mut chosen: Vec<usize> = Vec::new();
    for tok in t.split([',', ' ', '\t']).filter(|s| !s.is_empty()) {
        match tok.parse::<usize>() {
            Ok(k) if (1..=n).contains(&k) => {
                if !chosen.contains(&(k - 1)) {
                    chosen.push(k - 1);
                }
            }
            _ => return None,
        }
    }
    (!chosen.is_empty()).then_some(chosen)
}

/// Single choice; returns the chosen index. Styled on a terminal (arrows, `/`
/// filters, Esc / Ctrl-C cancels the command), numbered otherwise, where end
/// of input is an error (there is no default to take).
pub fn pick(question: &str, items: &[Choice]) -> Result<usize> {
    if crate::ui::styled_prompts() {
        let options = items.iter().enumerate().map(|(i, c)| c.option(i)).collect();
        return crate::ui::prompt(|| {
            demand::Select::new(question)
                .options(options)
                .filterable(true)
                .theme(crate::ui::theme())
                .run()
        });
    }
    use std::io::Write;
    println!("{question}");
    for (i, item) in items.iter().enumerate() {
        println!("  {}) {}", i + 1, item.plain());
    }
    loop {
        print!("> ");
        std::io::stdout().flush()?;
        let mut line = String::new();
        // A single choice has no default, so end of input is an error
        // rather than the same question asked again forever.
        if std::io::stdin().read_line(&mut line)? == 0 {
            println!();
            anyhow::bail!("no answer to {question:?} (end of input)");
        }
        if let Ok(n) = line.trim().parse::<usize>()
            && (1..=items.len()).contains(&n)
        {
            return Ok(n - 1);
        }
        println!("enter a number between 1 and {}", items.len());
    }
}

/// Free-text answer, re-asked until `validate` accepts it. Styled on a
/// terminal (the message shows under the field); otherwise a `title:` line
/// read from stdin, and end of input is an error rather than an answer.
pub fn ask_text(
    title: &str,
    placeholder: &str,
    validate: fn(&str) -> Result<(), &str>,
) -> Result<String> {
    if crate::ui::styled_prompts() {
        let answer = crate::ui::prompt(|| {
            demand::Input::new(title)
                .placeholder(placeholder)
                .validation(validate)
                .theme(crate::ui::theme())
                .run()
        })?;
        return Ok(answer.trim().to_string());
    }
    use std::io::Write;
    loop {
        print!("{title} (e.g. {placeholder}): ");
        std::io::stdout().flush()?;
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line)? == 0 {
            println!();
            anyhow::bail!("no answer for {title:?} (end of input)");
        }
        match validate(line.trim()) {
            Ok(()) => return Ok(line.trim().to_string()),
            Err(why) => println!("{why}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_selection;

    #[test]
    fn empty_and_all_select_everything() {
        assert_eq!(parse_selection("", 3), Some(vec![0, 1, 2]));
        assert_eq!(parse_selection("  \n", 3), Some(vec![0, 1, 2]));
        assert_eq!(parse_selection("all", 3), Some(vec![0, 1, 2]));
        assert_eq!(parse_selection("ALL", 3), Some(vec![0, 1, 2]));
    }

    #[test]
    fn none_selects_nothing() {
        assert_eq!(parse_selection("none", 3), Some(vec![]));
    }

    #[test]
    fn comma_and_space_lists_map_to_zero_based_dedup() {
        assert_eq!(parse_selection("1,3", 3), Some(vec![0, 2]));
        assert_eq!(parse_selection("1 3", 3), Some(vec![0, 2]));
        assert_eq!(parse_selection("3,1,3", 3), Some(vec![2, 0])); // order kept, deduped
    }

    #[test]
    fn out_of_range_or_garbage_reprompts() {
        assert_eq!(parse_selection("0", 3), None);
        assert_eq!(parse_selection("4", 3), None);
        assert_eq!(parse_selection("1,x", 3), None);
        assert_eq!(parse_selection("foo", 3), None);
    }
}

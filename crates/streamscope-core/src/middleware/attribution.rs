//! Client attribution — identifies which app and session generated a request.
//!
//! Four-tier `app_id` detection with decreasing trust:
//! 1. `X-App-Id` header (explicit, set by the client)
//! 2. `Referer` header (matched against [`AppPattern::referer_patterns`])
//! 3. `User-Agent` header (matched against [`AppPattern::ua_patterns`])
//! 4. The opening of the system prompt (matched against
//!    [`AppPattern::prompt_patterns`]) — only when no header named the app, and
//!    only where a request carries a prompt
//!    ([`Attribution::classify_by_system_prompt`]).
//!
//! Session and parent-session IDs are extracted from `X-Session-Id` and
//! `X-Parent-Session-Id` headers for hierarchical session linking.

use axum::http::HeaderMap;

use crate::config::AppPattern;

/// Maximum User-Agent length stored in audit records, in bytes (cut at a char
/// boundary). The proxy matches the FULL header; a stored copy this long may be
/// cut.
pub const MAX_USER_AGENT_LEN: usize = 256;

/// `detection_method` of an app named by the system prompt.
pub const DETECTION_SYSTEM_PROMPT: &str = "system_prompt";

/// `detection_method` of a call the gateway made for a request — a web tool
/// call the substitution loop dispatched: it takes that request's app (none,
/// while the request has none), and follows it when the request is
/// re-classified.
pub const DETECTION_REQUEST: &str = "request";

/// `detection_method` of a web tool call no request made — a client's direct
/// `/mcp/web` call, or an operator's probe: the gateway names no app for it.
pub const DETECTION_DIRECT: &str = "direct";

/// How much of the system prompt the prompt tier reads, in characters. A
/// client's identifying sentence opens its prompt; what follows is project
/// instructions and user-supplied text (an `AGENTS.md` quoting another client's
/// prompt), which must not decide the app.
pub const SYSTEM_PROMPT_MATCH_WINDOW_CHARS: usize = 2048;

/// The shortest prompt pattern the app registry accepts. A prompt pattern is
/// tried against every request the headers left unclassified, so a short one
/// ("you are") would attribute other clients' traffic to its app.
pub const MIN_PROMPT_PATTERN_CHARS: usize = 12;

/// Forwarded end-client identity headers — set by a trusted inline gateway on the
/// inline path and honored ONLY when the authenticated key is an inline key (a
/// normal key can never make these override its own identity). Stripped before
/// the request is forwarded upstream (see the http-client allowlist).
pub const HDR_CLIENT_IP: &str = "x-client-ip";
pub const HDR_AUTHENTICATED_USER: &str = "x-authenticated-user";
pub const HDR_AUTHENTICATED_GROUPS: &str = "x-authenticated-groups";

/// Byte caps for the forwarded identity values (client-controlled strings).
const MAX_CLIENT_IP_LEN: usize = 64;
const MAX_END_USER_LEN: usize = 256;
const MAX_GROUP_LEN: usize = 128;
const MAX_GROUPS: usize = 64;

/// Three-level attribution extracted from request headers.
#[derive(Debug, Clone)]
pub struct Attribution {
    pub user_id: uuid::Uuid,
    pub app_id: Option<String>,
    pub session_id: Option<String>,
    /// Raw `X-Parent-Session-Id` header value (for hierarchical session linking).
    pub parent_session_id: Option<String>,
    /// Raw User-Agent string (truncated to 256 chars).
    pub user_agent: Option<String>,
    /// How app_id was detected: "header", "referer", "user_agent", or None.
    pub detection_method: Option<String>,
    /// Forwarded end-client IP (`X-Client-IP`) — populated only when the caller
    /// is a trusted inline key; `None` otherwise.
    pub client_ip: Option<String>,
    /// Forwarded end-client identity (`X-Authenticated-User`) — inline-key only.
    pub end_user: Option<String>,
    /// Forwarded end-client groups (`X-Authenticated-Groups`, comma-separated on
    /// the wire) — inline-key only.
    pub end_user_groups: Vec<String>,
}

/// Extract attribution from request headers.
///
/// `app_id` resolution order:
/// 1. Explicit `X-App-Id` header (custom, highest priority)
/// 2. `HTTP-Referer` header (matches referer_patterns from app registry)
/// 3. `User-Agent` header (matches ua_patterns from app registry)
///
/// `trust_forwarded` enables reading the `X-Client-IP` / `X-Authenticated-User`
/// / `X-Authenticated-Groups` end-client identity headers. It MUST be true only
/// for a trusted inline key — a normal key must never let a header override its
/// own identity (SSRF / spoofing guard).
pub fn extract_attribution(
    headers: &HeaderMap,
    user_id: uuid::Uuid,
    app_patterns: &[AppPattern],
    trust_forwarded: bool,
) -> Attribution {
    let ua = headers.get("user-agent").and_then(|v| v.to_str().ok());
    let referer = headers.get("referer").and_then(|v| v.to_str().ok());
    let explicit = headers.get("x-app-id").and_then(|v| v.to_str().ok());

    let (app_id, detection_method) = if let Some(id) = explicit {
        (Some(id.to_string()), Some("header".to_string()))
    } else if let Some(id) = infer_app_from_referer(headers, app_patterns) {
        (Some(id), Some("referer".to_string()))
    } else if let Some(id) = infer_app_from_user_agent(headers, app_patterns) {
        (Some(id), Some("user_agent".to_string()))
    } else {
        (None, None)
    };

    tracing::debug!(
        user_agent = ua,
        referer = referer,
        x_app_id = explicit,
        resolved_app_id = app_id.as_deref(),
        detection_method = detection_method.as_deref(),
        "attribution headers"
    );

    let session_id = headers
        .get("x-session-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let parent_session_id = headers
        .get("x-parent-session-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let user_agent = ua.map(|s| {
        if s.len() > MAX_USER_AGENT_LEN {
            s[..s.floor_char_boundary(MAX_USER_AGENT_LEN)].to_string()
        } else {
            s.to_string()
        }
    });

    let (client_ip, end_user, end_user_groups) = if trust_forwarded {
        let cap = |name: &str, max: usize| {
            headers.get(name).and_then(|v| v.to_str().ok()).map(|s| {
                s[..s.floor_char_boundary(max.min(s.len()))].to_string()
            })
        };
        let groups = headers
            .get(HDR_AUTHENTICATED_GROUPS)
            .and_then(|v| v.to_str().ok())
            .map(|s| {
                s.split(',')
                    .map(str::trim)
                    .filter(|g| !g.is_empty())
                    .take(MAX_GROUPS)
                    .map(|g| g[..g.floor_char_boundary(MAX_GROUP_LEN.min(g.len()))].to_string())
                    .collect()
            })
            .unwrap_or_default();
        (cap(HDR_CLIENT_IP, MAX_CLIENT_IP_LEN), cap(HDR_AUTHENTICATED_USER, MAX_END_USER_LEN), groups)
    } else {
        (None, None, Vec::new())
    };

    Attribution {
        user_id,
        app_id,
        session_id,
        parent_session_id,
        user_agent,
        detection_method,
        client_ip,
        end_user,
        end_user_groups,
    }
}

/// Infer app_id from HTTP-Referer header using app registry patterns.
fn infer_app_from_referer(headers: &HeaderMap, app_patterns: &[AppPattern]) -> Option<String> {
    let referer = headers
        .get("referer")
        .or_else(|| headers.get("http-referer"))
        .and_then(|v| v.to_str().ok())?;
    let lower = referer.to_ascii_lowercase();

    for app in app_patterns {
        for pattern in &app.referer_patterns {
            if lower.contains(pattern) {
                return Some(app.app_id.clone());
            }
        }
    }
    None
}

/// Infer app_id from User-Agent header using app registry patterns.
fn infer_app_from_user_agent(headers: &HeaderMap, app_patterns: &[AppPattern]) -> Option<String> {
    let ua = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())?;
    let lower = ua.to_ascii_lowercase();

    for app in app_patterns {
        for pattern in &app.ua_patterns {
            if lower.contains(pattern) {
                return Some(app.app_id.clone());
            }
        }
    }
    None
}

/// A registry pattern list as the matchers read it: trimmed, ASCII-lowercased,
/// and without any entry shorter than `min_chars` (an empty pattern would match
/// every request). The proxy's config fold reads every pattern through this.
///
/// Matching ignores the case of ASCII letters only, as the proxy reads a
/// visible-ASCII header.
pub fn normalize_patterns(patterns: &[String], min_chars: usize) -> Vec<String> {
    patterns
        .iter()
        .map(|p| p.trim().to_ascii_lowercase())
        .filter(|p| !p.is_empty() && p.chars().count() >= min_chars)
        .collect()
}

impl Attribution {
    /// The fourth tier: when no header named the app, name it from the opening
    /// of the system prompt. Run by every path that carries a prompt, after
    /// [`extract_attribution`] and before anything reads `app_id` — an
    /// app-scoped tool rule and the audit row must see the same answer.
    pub fn classify_by_system_prompt(
        &mut self,
        system_prompt: Option<&str>,
        app_patterns: &[AppPattern],
    ) {
        // Nothing to try when a header named the app or no app declares a
        // prompt pattern — the scan lowercases up to a 2 KiB window.
        if self.app_id.is_some() || app_patterns.iter().all(|a| a.prompt_patterns.is_empty()) {
            return;
        }
        if let Some(id) = system_prompt.and_then(|p| infer_app_from_system_prompt(p, app_patterns)) {
            self.app_id = Some(id);
            self.detection_method = Some(DETECTION_SYSTEM_PROMPT.to_string());
        }
    }
}

/// The app whose prompt pattern occurs in the first
/// [`SYSTEM_PROMPT_MATCH_WINDOW_CHARS`] characters of `system_prompt`, ignoring
/// the case of ASCII letters (see [`normalize_patterns`]). A client sends the same prompt opening on every turn, so
/// each request is classified on its own — no session state is needed.
pub fn infer_app_from_system_prompt(
    system_prompt: &str,
    app_patterns: &[AppPattern],
) -> Option<String> {
    let end = system_prompt
        .char_indices()
        .nth(SYSTEM_PROMPT_MATCH_WINDOW_CHARS)
        .map_or(system_prompt.len(), |(i, _)| i);
    let head = system_prompt[..end].to_ascii_lowercase();
    app_patterns
        .iter()
        .find(|app| app.prompt_patterns.iter().any(|p| head.contains(p.as_str())))
        .map(|app| app.app_id.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    /// Default app patterns matching the seeded app registry.
    fn test_patterns() -> Vec<AppPattern> {
        vec![
            AppPattern { app_id: "claude-code".into(), ua_patterns: vec!["claude-code".into(), "claude-cli".into()], referer_patterns: vec!["claude.ai".into()], prompt_patterns: vec![] },
            AppPattern { app_id: "cursor".into(), ua_patterns: vec!["cursor/".into()], referer_patterns: vec!["cursor.sh".into(), "cursor.com".into()], prompt_patterns: vec![] },
            AppPattern { app_id: "windsurf".into(), ua_patterns: vec!["windsurf/".into(), "codeium/".into()], referer_patterns: vec!["windsurf.ai".into(), "windsurf.com".into(), "codeium.com".into()], prompt_patterns: vec![] },
            AppPattern { app_id: "cline".into(), ua_patterns: vec!["cline/".into()], referer_patterns: vec!["cline.bot".into()], prompt_patterns: vec![] },
            AppPattern { app_id: "roo-code".into(), ua_patterns: vec!["roo-code".into(), "roocode".into()], referer_patterns: vec!["roocode.com".into()], prompt_patterns: vec![] },
            AppPattern { app_id: "aider".into(), ua_patterns: vec!["aider/".into()], referer_patterns: vec!["aider.chat".into()], prompt_patterns: vec![] },
            AppPattern { app_id: "opencode".into(), ua_patterns: vec!["opencode/".into(), "runtime/bun".into()], referer_patterns: vec!["opencode.ai".into()], prompt_patterns: vec![] },
            AppPattern { app_id: "github-copilot".into(), ua_patterns: vec!["copilot".into()], referer_patterns: vec!["copilot.github.com".into()], prompt_patterns: vec![] },
            AppPattern { app_id: "anthropic-sdk".into(), ua_patterns: vec!["anthropic-typescript".into(), "anthropic-python".into()], referer_patterns: vec![], prompt_patterns: vec![] },
            AppPattern { app_id: "openai-sdk".into(), ua_patterns: vec!["openai-python".into(), "openai-node".into()], referer_patterns: vec![], prompt_patterns: vec![] },
            AppPattern { app_id: "gemini-cli".into(), ua_patterns: vec!["geminicli".into(), "gemini-cli".into()], referer_patterns: vec![], prompt_patterns: vec![] },
        ]
    }

    #[test]
    fn test_explicit_x_app_id_takes_priority() {
        let mut headers = HeaderMap::new();
        headers.insert("x-app-id", HeaderValue::from_static("my-custom-app"));
        headers.insert("user-agent", HeaderValue::from_static("claude-code/1.0"));
        let attr = extract_attribution(&headers, uuid::Uuid::nil(), &test_patterns(), false);
        assert_eq!(attr.app_id.as_deref(), Some("my-custom-app"));
        assert_eq!(attr.detection_method.as_deref(), Some("header"));
    }

    #[test]
    fn test_infer_from_user_agent_claude_code() {
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", HeaderValue::from_static("claude-code/1.0.12 Node/22"));
        let attr = extract_attribution(&headers, uuid::Uuid::nil(), &test_patterns(), false);
        assert_eq!(attr.app_id.as_deref(), Some("claude-code"));
        assert_eq!(attr.detection_method.as_deref(), Some("user_agent"));
        assert_eq!(attr.user_agent.as_deref(), Some("claude-code/1.0.12 Node/22"));
    }

    #[test]
    fn forwarded_identity_only_honored_when_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert(HDR_CLIENT_IP, HeaderValue::from_static("203.0.113.7"));
        headers.insert(HDR_AUTHENTICATED_USER, HeaderValue::from_static("alice@example.com"));
        headers.insert(HDR_AUTHENTICATED_GROUPS, HeaderValue::from_static("eng, admins , ,ops"));

        // A normal key (untrusted): the forwarded-identity headers are ignored
        // entirely — a request cannot spoof its own identity.
        let untrusted = extract_attribution(&headers, uuid::Uuid::nil(), &test_patterns(), false);
        assert_eq!(untrusted.client_ip, None);
        assert_eq!(untrusted.end_user, None);
        assert!(untrusted.end_user_groups.is_empty());

        // An inline key (trusted): parsed; groups split, trimmed, blanks dropped.
        let trusted = extract_attribution(&headers, uuid::Uuid::nil(), &test_patterns(), true);
        assert_eq!(trusted.client_ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(trusted.end_user.as_deref(), Some("alice@example.com"));
        assert_eq!(
            trusted.end_user_groups,
            vec!["eng".to_string(), "admins".to_string(), "ops".to_string()]
        );
    }

    #[test]
    fn test_infer_from_user_agent_cursor() {
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", HeaderValue::from_static("Cursor/0.48.1"));
        let attr = extract_attribution(&headers, uuid::Uuid::nil(), &test_patterns(), false);
        assert_eq!(attr.app_id.as_deref(), Some("cursor"));
    }

    #[test]
    fn test_infer_from_user_agent_aider() {
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", HeaderValue::from_static("aider/0.82.0"));
        let attr = extract_attribution(&headers, uuid::Uuid::nil(), &test_patterns(), false);
        assert_eq!(attr.app_id.as_deref(), Some("aider"));
    }

    #[test]
    fn test_infer_from_user_agent_gemini_cli() {
        // Gemini CLI's User-Agent carries a per-surface token: bare
        // `GeminiCLI/<version>/...` on older builds, `GeminiCLI-<surface>/...`
        // on current ones (e.g. `GeminiCLI-tui/0.42.0/free (...)`). The
        // pattern matches the slash-free `geminicli` token so any surface
        // suffix is covered.
        for ua in [
            "GeminiCLI/0.13.0/gemini-2.5-pro (linux; x64; cli)",
            "GeminiCLI-tui/0.42.0/free (linux; x64; terminal)",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert("user-agent", HeaderValue::from_str(ua).unwrap());
            let attr = extract_attribution(&headers, uuid::Uuid::nil(), &test_patterns(), false);
            assert_eq!(attr.app_id.as_deref(), Some("gemini-cli"), "UA: {ua}");
            assert_eq!(attr.detection_method.as_deref(), Some("user_agent"), "UA: {ua}");
        }
    }

    #[test]
    fn test_infer_from_user_agent_opencode_bun_runtime() {
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", HeaderValue::from_static(
            "ai-sdk/openai-compatible/1.0.32 ai-sdk/provider-utils/3.0.20 runtime/bun/1.3.10"
        ));
        let attr = extract_attribution(&headers, uuid::Uuid::nil(), &test_patterns(), false);
        assert_eq!(attr.app_id.as_deref(), Some("opencode"));
        assert_eq!(attr.detection_method.as_deref(), Some("user_agent"));
    }

    #[test]
    fn test_infer_from_referer() {
        let mut headers = HeaderMap::new();
        headers.insert("referer", HeaderValue::from_static("https://opencode.ai"));
        let attr = extract_attribution(&headers, uuid::Uuid::nil(), &test_patterns(), false);
        assert_eq!(attr.app_id.as_deref(), Some("opencode"));
        assert_eq!(attr.detection_method.as_deref(), Some("referer"));
    }

    #[test]
    fn test_referer_takes_priority_over_user_agent() {
        let mut headers = HeaderMap::new();
        headers.insert("referer", HeaderValue::from_static("https://cursor.sh"));
        headers.insert("user-agent", HeaderValue::from_static("aider/0.82.0"));
        let attr = extract_attribution(&headers, uuid::Uuid::nil(), &test_patterns(), false);
        assert_eq!(attr.app_id.as_deref(), Some("cursor"));
        assert_eq!(attr.detection_method.as_deref(), Some("referer"));
    }

    #[test]
    fn test_unknown_user_agent_returns_none() {
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", HeaderValue::from_static("python-requests/2.31.0"));
        let attr = extract_attribution(&headers, uuid::Uuid::nil(), &test_patterns(), false);
        assert_eq!(attr.app_id, None);
        assert_eq!(attr.detection_method, None);
        assert_eq!(attr.user_agent.as_deref(), Some("python-requests/2.31.0"));
    }

    #[test]
    fn test_anthropic_sdk() {
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", HeaderValue::from_static("anthropic-python/0.40.0"));
        let attr = extract_attribution(&headers, uuid::Uuid::nil(), &test_patterns(), false);
        assert_eq!(attr.app_id.as_deref(), Some("anthropic-sdk"));
    }

    #[test]
    fn test_user_agent_truncated() {
        let mut headers = HeaderMap::new();
        let long_ua = "x".repeat(300);
        headers.insert("user-agent", HeaderValue::from_str(&long_ua).unwrap());
        let attr = extract_attribution(&headers, uuid::Uuid::nil(), &test_patterns(), false);
        assert_eq!(attr.user_agent.as_ref().unwrap().len(), MAX_USER_AGENT_LEN);
    }

    #[test]
    fn test_parent_session_id_extracted() {
        let mut headers = HeaderMap::new();
        headers.insert("x-parent-session-id", HeaderValue::from_static("parent-abc-123"));
        let attr = extract_attribution(&headers, uuid::Uuid::nil(), &test_patterns(), false);
        assert_eq!(attr.parent_session_id.as_deref(), Some("parent-abc-123"));
    }

    #[test]
    fn test_parent_session_id_absent() {
        let headers = HeaderMap::new();
        let attr = extract_attribution(&headers, uuid::Uuid::nil(), &test_patterns(), false);
        assert_eq!(attr.parent_session_id, None);
    }

    fn prompt_patterns() -> Vec<AppPattern> {
        let mut patterns = test_patterns();
        patterns.push(AppPattern {
            app_id: "goose".into(),
            prompt_patterns: vec!["ai agent called goose".into()],
            ..Default::default()
        });
        patterns
    }

    const GOOSE_PROMPT: &str = "You are a general-purpose AI agent called goose, created by AAIF.";

    #[test]
    fn an_unclassified_request_is_named_by_its_prompt_opening() {
        let mut attr = extract_attribution(&HeaderMap::new(), uuid::Uuid::nil(), &prompt_patterns(), false);
        attr.classify_by_system_prompt(Some(GOOSE_PROMPT), &prompt_patterns());
        assert_eq!(attr.app_id.as_deref(), Some("goose"));
        assert_eq!(attr.detection_method.as_deref(), Some(DETECTION_SYSTEM_PROMPT));

        // A prompt no pattern occurs in, or no prompt at all, names nothing.
        for prompt in [Some("You are a helpful assistant."), None] {
            let mut attr = extract_attribution(&HeaderMap::new(), uuid::Uuid::nil(), &prompt_patterns(), false);
            attr.classify_by_system_prompt(prompt, &prompt_patterns());
            assert_eq!(attr.app_id, None, "{prompt:?}");
            assert_eq!(attr.detection_method, None, "{prompt:?}");
        }
    }

    #[test]
    fn a_header_match_outranks_the_prompt() {
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", HeaderValue::from_static("claude-cli/2.1.278"));
        let mut attr = extract_attribution(&headers, uuid::Uuid::nil(), &prompt_patterns(), false);
        attr.classify_by_system_prompt(Some(GOOSE_PROMPT), &prompt_patterns());
        assert_eq!(attr.app_id.as_deref(), Some("claude-code"));
        assert_eq!(attr.detection_method.as_deref(), Some("user_agent"));
    }

    #[test]
    fn the_prompt_tier_reads_only_the_opening_window() {
        let pattern = "ai agent called goose";
        let n = pattern.chars().count();
        // Multibyte padding, so a byte-counted window would cut elsewhere.
        let prompt_ending_at = |last_char: usize| {
            format!("{}{pattern} and more text", "é".repeat(last_char + 1 - n))
        };
        // The pattern's last character is the window's last character: matched.
        let inside = prompt_ending_at(SYSTEM_PROMPT_MATCH_WINDOW_CHARS - 1);
        assert_eq!(infer_app_from_system_prompt(&inside, &prompt_patterns()).as_deref(), Some("goose"));
        // One character later it straddles the edge: not matched.
        let outside = prompt_ending_at(SYSTEM_PROMPT_MATCH_WINDOW_CHARS);
        assert_eq!(infer_app_from_system_prompt(&outside, &prompt_patterns()), None);
    }

    /// The prompt tier reads attacker-chosen text, so its claims are
    /// properties, not examples: the ASCII case of a prompt never changes the
    /// answer, text past the window never does, and a prompt opening with a
    /// declared pattern is always named by it. Deliberately NOT a property:
    /// case beyond ASCII — `Ê` and `ê` differ
    /// (see `normalize_patterns`).
    mod properties {
        use super::*;
        use proptest::prelude::*;

        fn flip_ascii_case(text: &str, flips: &[bool]) -> String {
            text.chars()
                .zip(flips.iter().copied().chain(std::iter::repeat(false)))
                .map(|(c, flip)| if flip && c.is_ascii_alphabetic() {
                    if c.is_ascii_lowercase() { c.to_ascii_uppercase() } else { c.to_ascii_lowercase() }
                } else {
                    c
                })
                .collect()
        }

        fn registry(pattern: &str) -> Vec<AppPattern> {
            vec![AppPattern {
                app_id: "declared".into(),
                prompt_patterns: normalize_patterns(&[pattern.to_string()], MIN_PROMPT_PATTERN_CHARS),
                ..Default::default()
            }]
        }

        proptest! {
            #[test]
            fn the_ascii_case_of_a_prompt_never_changes_the_answer(
                prompt in "\\PC{0,200}",
                pattern in "[a-z][a-z ]{10,23}[a-z]",
                flips in prop::collection::vec(any::<bool>(), 0..200),
            ) {
                let apps = registry(&pattern);
                let with_pattern = format!("{prompt}{pattern}");
                for text in [prompt.as_str(), with_pattern.as_str()] {
                    prop_assert_eq!(
                        infer_app_from_system_prompt(text, &apps),
                        infer_app_from_system_prompt(&flip_ascii_case(text, &flips), &apps)
                    );
                }
            }

            #[test]
            fn text_past_the_window_never_changes_the_answer(
                head in "\\PC{0,64}",
                pattern in "[a-z][a-z ]{10,23}[a-z]",
                tail_a in "\\PC{0,64}",
                tail_b in "\\PC{0,64}",
            ) {
                let apps = registry(&pattern);
                let pad = SYSTEM_PROMPT_MATCH_WINDOW_CHARS.saturating_sub(head.chars().count());
                let window = format!("{head}{}", "~".repeat(pad));
                prop_assert_eq!(
                    infer_app_from_system_prompt(&format!("{window}{tail_a}"), &apps),
                    infer_app_from_system_prompt(&format!("{window}{pattern}{tail_b}"), &apps)
                );
            }

            #[test]
            fn a_prompt_opening_with_a_declared_pattern_is_named_by_it(
                pattern in "[a-z][a-z ]{10,23}[a-z]",
                rest in "\\PC{0,200}",
                flips in prop::collection::vec(any::<bool>(), 0..40),
            ) {
                let apps = registry(&pattern);
                let prompt = format!("{}{rest}", flip_ascii_case(&pattern, &flips));
                let named = infer_app_from_system_prompt(&prompt, &apps);
                prop_assert_eq!(named.as_deref(), Some("declared"));
            }
        }
    }
}

//! Which MCP server a tool name the LLM sees belongs to.
//!
//! A client exposes a gateway virtual server's tool to its model under a name
//! it builds itself, from the server key the provisioned config writes (the
//! virtual server's slug) and the tool name the virtual server lists. The MCP
//! specification fixes only the tool name within one server, so every client
//! joins the two its own way:
//!
//! | Client | Name |
//! |---|---|
//! | Claude Code, Codex, Qwen Code | `mcp__<server>__<tool>` |
//! | Gemini CLI, Crush | `mcp_<server>_<tool>` |
//! | OpenCode | `<server>_<tool>` |
//!
//! [`resolve_tool_name`] is the ONE place a tool name is split into the name
//! the field profiles know and the MCP server it belongs to — on the request,
//! on the answer, and in the console's read-time classification — so a call is
//! classified the same wherever it is read. A virtual server's slug is mapped
//! to the upstream behind its route: that upstream's name is what the MCP
//! gateway itself stamps on a call, and what an MCP-scoped field profile names.
//!
//! What it does not do: a name a client truncated or hashed to fit a length
//! cap, or a server key the developer chose, is never placed on a virtual
//! server; it resolves as the client wrote it.

use std::collections::HashMap;

use crate::config::mcp::resolve_route_prefix;
use crate::config::tool_rules::{FieldProfileSet, matches_glob};

/// The clients whose MCP tool name is the BARE `<server>_<tool>` — no lead
/// that marks it as an MCP tool, so it is read only for a client known to
/// write it, and only when the whole name is not one of the client's own
/// tools ([`FieldProfileSet::names_tool_literally`]). Globs over `app_id`, as
/// a field profile's `app_filter`. Every other client's forms
/// (`mcp__…__`, `mcp_…_`) mark themselves and are read for any client.
const BARE_FORM_CLIENTS: &[&str] = &["opencode|opencode*"];

/// One route of a virtual server, as the resolver needs it.
#[derive(Debug, Clone)]
pub struct ToolNameRoute {
    pub virtual_server_slug: String,
    pub prefix: String,
    pub upstream_name: String,
    /// Orders routes sharing a prefix across virtual servers: the lowest id
    /// wins the bare `<prefix>__<tool>` reading.
    pub route_id: uuid::Uuid,
}

#[derive(Debug, Clone)]
struct VirtualServerNames {
    slug: String,
    /// `(prefix, upstream name)` per route, `""` for the empty-prefix route.
    routes: Vec<(String, String)>,
}

impl VirtualServerNames {
    /// The upstream a tool name under this virtual server routes to, and the
    /// name that upstream knows the tool by — the gateway's own dispatch
    /// ([`resolve_route_prefix`]).
    fn route<'a>(&'a self, tool: &'a str) -> Option<(&'a str, &'a str)> {
        let prefixes: Vec<&str> = self.routes.iter().map(|(p, _)| p.as_str()).collect();
        let (prefix, local) = resolve_route_prefix(tool, &prefixes)?;
        let upstream = self.routes.iter().find(|(p, _)| p == prefix)?;
        Some((upstream.1.as_str(), local))
    }
}

/// A tenant's virtual servers, indexed for [`resolve_tool_name`]. Built once
/// per configuration (the proxy's snapshot, the console's read) through
/// [`McpToolNames::new`], so both read the same index.
#[derive(Debug, Clone, Default)]
pub struct McpToolNames {
    /// Longest slug first: where two slugs both fit a name, the longer one is
    /// read (`web-tools_x` is `web-tools` + `x`, not `web` + `tools_x`).
    servers: Vec<VirtualServerNames>,
    /// Every non-empty route prefix → the upstream of its lowest-id route.
    prefixes: HashMap<String, String>,
}

impl McpToolNames {
    pub fn new(routes: Vec<ToolNameRoute>) -> Self {
        let mut by_slug: HashMap<String, VirtualServerNames> = HashMap::new();
        let mut prefixed: Vec<&ToolNameRoute> = Vec::new();
        for r in &routes {
            by_slug
                .entry(r.virtual_server_slug.clone())
                .or_insert_with(|| VirtualServerNames { slug: r.virtual_server_slug.clone(), routes: Vec::new() })
                .routes
                .push((r.prefix.clone(), r.upstream_name.clone()));
            if !r.prefix.is_empty() {
                prefixed.push(r);
            }
        }
        let mut servers: Vec<VirtualServerNames> = by_slug.into_values().collect();
        servers.sort_by(|a, b| b.slug.len().cmp(&a.slug.len()).then_with(|| a.slug.cmp(&b.slug)));
        prefixed.sort_by(|a, b| a.prefix.cmp(&b.prefix).then(a.route_id.cmp(&b.route_id)));
        let mut prefixes: HashMap<String, String> = HashMap::new();
        for r in prefixed {
            match prefixes.entry(r.prefix.clone()) {
                std::collections::hash_map::Entry::Vacant(slot) => {
                    slot.insert(r.upstream_name.clone());
                }
                std::collections::hash_map::Entry::Occupied(kept) => {
                    if kept.get() != &r.upstream_name {
                        tracing::warn!(
                            prefix = %r.prefix,
                            kept_upstream = %kept.get(),
                            ignored_upstream = %r.upstream_name,
                            ignored_route_id = %r.route_id,
                            "MCP route prefix shared by routes to different upstreams; a bare `<prefix>__<tool>` name the LLM sees resolves to the lowest route id. Keep prefixes unique within a tenant."
                        );
                    }
                }
            }
        }
        Self { servers, prefixes }
    }
}

/// `slug` as a client may write it: a client that keeps only `[A-Za-z0-9_]`
/// writes its `-` as `_`.
fn slug_eq(slug: &str, written: &str) -> bool {
    slug.len() == written.len()
        && slug.bytes().zip(written.bytes()).all(|(s, w)| {
            let fold = |b: u8| if b == b'-' { b'_' } else { b.to_ascii_lowercase() };
            fold(s) == fold(w)
        })
}

/// `name` with `slug` (as a client may write it) and then `sep` cut from its
/// front, or `None` when it does not start that way.
fn strip_slug<'n>(name: &'n str, slug: &str, sep: &str) -> Option<&'n str> {
    let head = name.get(..slug.len())?;
    slug_eq(slug, head).then(|| name[slug.len()..].strip_prefix(sep)).flatten()
}

/// A tool name split for the field profiles: the name its server knows it by,
/// and the MCP server it belongs to (`None` for a tool of no MCP server).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolName<'a> {
    pub local: &'a str,
    pub mcp_server: Option<&'a str>,
    /// The name was read as a tool of one of the tenant's virtual servers —
    /// a tool the gateway itself serves — rather than one the client brought.
    pub gateway: bool,
}

impl<'a> ToolName<'a> {
    fn bare(name: &'a str) -> Self {
        Self { local: name, mcp_server: None, gateway: false }
    }

    fn served(local: &'a str, upstream: &'a str) -> Self {
        Self { local, mcp_server: Some(upstream), gateway: true }
    }
}

/// Split the tool name `name` a model saw (or called) into the name its MCP
/// server knows it by and that server. In order:
///
/// 1. `mcp__<server>__<tool>`: a virtual server's slug whose `<tool>` routes
///    on that server resolves to the route's upstream; any other `<server>`
///    (one the developer wrote into the client themselves) is kept as written,
///    split at its first `__`.
/// 2. `mcp_<slug>_<tool>`, for a virtual server's slug, when `<tool>` routes
///    on that server.
/// 3. `<slug>_<tool>`, the same — only for a client in [`BARE_FORM_CLIENTS`],
///    and never for a whole name the client's own field profiles name
///    literally (its `web_search` is its own tool, not virtual server `web`).
/// 4. `<prefix>__<tool>`, a route prefix of the tenant, read as that route's
///    upstream.
/// 5. Otherwise the whole name, of no MCP server.
///
/// A `-` in a slug matches a client's `_` ([`slug_eq`]); where two slugs fit,
/// the longer is read. `app_id` is what the client claims to be: it only adds
/// form 3, read after the self-delimiting forms, so it never takes away a
/// reading they give.
pub fn resolve_tool_name<'a>(
    name: &'a str,
    app_id: Option<&str>,
    servers: Option<&'a McpToolNames>,
    profiles: Option<&FieldProfileSet>,
) -> ToolName<'a> {
    if let Some(body) = name.strip_prefix("mcp__") {
        // A virtual server's slug is matched whole rather than cut at the
        // first `__`: a slug ending in `-`, written `_`, runs into the separator.
        if let Some(found) = servers.and_then(|s| read_slug_form(body, s, "__", false)) {
            return found;
        }
        return match body.split_once("__") {
            Some((server, tool)) if !server.is_empty() && !tool.is_empty() => {
                ToolName { local: tool, mcp_server: Some(server), gateway: false }
            }
            _ => ToolName::bare(name),
        };
    }
    let Some(servers) = servers else {
        return ToolName::bare(name);
    };
    if let Some(rest) = name.strip_prefix("mcp_")
        && let Some(found) = read_slug_form(rest, servers, "_", false)
    {
        return found;
    }
    if app_id.is_some_and(|app| BARE_FORM_CLIENTS.iter().any(|g| matches_glob(app, g)))
        && let Some(found) = read_slug_form(name, servers, "_", true)
        && !profiles.is_some_and(|p| p.names_tool_literally(name, app_id))
    {
        return found;
    }
    if let Some((prefix, local)) = name.split_once("__")
        && !local.is_empty()
        && let Some(upstream) = servers.prefixes.get(prefix)
    {
        return ToolName::served(local, upstream.as_str());
    }
    ToolName::bare(name)
}

/// `<slug><sep><tool>` for the longest virtual-server slug whose `<tool>`
/// routes on that server. In the `bare` form a slug `mcp` is never read: there
/// it is the lead of another client's form, not a server.
fn read_slug_form<'a>(
    rest: &'a str,
    servers: &'a McpToolNames,
    sep: &str,
    bare: bool,
) -> Option<ToolName<'a>> {
    servers.servers.iter().filter(|vs| !(bare && vs.slug == "mcp")).find_map(|vs| {
        let tool = strip_slug(rest, &vs.slug, sep).filter(|t| !t.is_empty())?;
        let (upstream, local) = vs.route(tool)?;
        Some(ToolName::served(local, upstream))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tool_rules::FieldProfile;
    use proptest::prelude::*;

    fn names(routes: &[(&str, &str, &str)]) -> McpToolNames {
        McpToolNames::new(
            routes
                .iter()
                .map(|(slug, prefix, upstream)| ToolNameRoute {
                    virtual_server_slug: slug.to_string(),
                    prefix: prefix.to_string(),
                    upstream_name: upstream.to_string(),
                    route_id: uuid::Uuid::new_v4(),
                })
                .collect(),
        )
    }

    fn profile(json: serde_json::Value) -> FieldProfile {
        serde_json::from_value(json).expect("a valid field profile")
    }

    /// The seeded profiles a gateway web call and a client's own web tool meet.
    fn web_profiles() -> FieldProfileSet {
        FieldProfileSet::new(vec![
            profile(serde_json::json!({"tool_id": "web_fetch", "tool_pattern": "web_fetch",
                "mcp_server": "builtin-web", "field": "url", "normalizer": "url"})),
            profile(serde_json::json!({"tool_id": "web_search", "tool_pattern": "web_search|websearch",
                "field": "query", "normalizer": "raw"})),
        ])
    }

    fn resolve<'a>(name: &'a str, app: Option<&str>, servers: &'a McpToolNames) -> (&'a str, Option<&'a str>) {
        let t = resolve_tool_name(name, app, Some(servers), Some(&web_profiles()));
        (t.local, t.mcp_server)
    }

    #[test]
    fn a_gateway_tool_resolves_to_its_upstream_under_every_clients_form() {
        let web = names(&[("web", "", "builtin-web")]);
        for (name, app) in [
            ("mcp__web__web_fetch", Some("claude-code")),
            ("mcp__web__web_fetch", Some("codex")),
            ("mcp_web_web_fetch", Some("gemini-cli")),
            ("mcp_web_web_fetch", Some("crush")),
            ("web_web_fetch", Some("opencode")),
        ] {
            assert_eq!(resolve(name, app, &web), ("web_fetch", Some("builtin-web")), "{name} under {app:?}");
            let t = resolve_tool_name(name, app, Some(&web), Some(&web_profiles()));
            assert_eq!(
                web_profiles().resolve_tool_id(t.local, app, t.mcp_server),
                Some("web_fetch"),
                "{name} must reach the upstream's own profile"
            );
        }
    }

    #[test]
    fn a_bare_name_is_read_only_for_a_client_that_writes_it_and_not_for_its_own_tool() {
        let web = names(&[("web", "", "builtin-web")]);
        assert_eq!(resolve("web_web_fetch", Some("opencode"), &web), ("web_fetch", Some("builtin-web")));
        // The client's own tool, named literally by a profile, stays its own.
        assert_eq!(resolve("web_search", Some("opencode"), &web), ("web_search", None));
        // Another client's bare name is never read as a server's.
        assert_eq!(resolve("web_web_fetch", Some("claude-code"), &web), ("web_web_fetch", None));
        assert_eq!(resolve("web_web_fetch", None, &web), ("web_web_fetch", None));
    }

    #[test]
    fn the_longer_slug_wins_and_a_dash_matches_an_underscore() {
        let both = names(&[("web", "", "builtin-web"), ("web-tools", "", "tools-up")]);
        assert_eq!(resolve("mcp_web_tools_x", None, &both), ("x", Some("tools-up")));
        assert_eq!(resolve("mcp__web_tools__x", None, &both), ("x", Some("tools-up")));
        assert_eq!(resolve("mcp__web-tools__x", None, &both), ("x", Some("tools-up")));
        assert_eq!(resolve("web-tools_x", Some("opencode"), &both), ("x", Some("tools-up")));
        assert_eq!(resolve("mcp_web_x", None, &both), ("x", Some("builtin-web")));
    }

    #[test]
    fn a_server_that_is_not_a_virtual_server_keeps_its_written_name() {
        let web = names(&[("web", "", "builtin-web")]);
        assert_eq!(resolve("mcp__github__create_issue", None, &web), ("create_issue", Some("github")));
        assert_eq!(resolve("mcp_github_create_issue", None, &web), ("mcp_github_create_issue", None));
        assert_eq!(resolve("Bash", Some("opencode"), &web), ("Bash", None));
        // An empty server or tool segment is no MCP name.
        assert_eq!(resolve("mcp____web_fetch", None, &web), ("mcp____web_fetch", None));
        assert_eq!(resolve("mcp__github__", None, &web), ("mcp__github__", None));
        // Without the tenant's servers only the self-delimiting form is read.
        let t = resolve_tool_name("mcp__web__web_fetch", None, None, None);
        assert_eq!((t.local, t.mcp_server), ("web_fetch", Some("web")));
        let t = resolve_tool_name("mcp_web_web_fetch", None, None, None);
        assert_eq!((t.local, t.mcp_server), ("mcp_web_web_fetch", None));
    }

    #[test]
    fn a_route_prefix_resolves_under_a_server_and_bare() {
        let gh = names(&[("gh-tools", "gh", "github-up"), ("gh-tools", "", "plain-up")]);
        assert_eq!(resolve("mcp__gh-tools__gh__create_issue", None, &gh), ("create_issue", Some("github-up")));
        assert_eq!(resolve("mcp__gh-tools__list", None, &gh), ("list", Some("plain-up")));
        assert_eq!(resolve("gh_tools_gh__create_issue", Some("opencode"), &gh), ("create_issue", Some("github-up")));
        assert_eq!(resolve("gh__create_issue", None, &gh), ("create_issue", Some("github-up")));
        // A name claiming a prefix with nothing after it is no route's.
        assert_eq!(resolve("mcp__gh-tools__gh__", None, &gh), ("gh__", Some("gh-tools")));
    }

    #[test]
    fn a_slug_named_mcp_is_never_read_in_the_bare_form() {
        let m = names(&[("mcp", "", "m-up")]);
        assert_eq!(resolve("mcp_x", Some("opencode"), &m), ("mcp_x", None));
        assert_eq!(resolve("mcp_mcp_x", None, &m), ("x", Some("m-up")));
        assert_eq!(resolve("mcp__mcp__x", None, &m), ("x", Some("m-up")));
    }

    #[test]
    fn servers_sharing_an_upstream_or_named_like_another_resolve_by_their_own_routes() {
        let s = names(&[("a", "", "b"), ("b", "", "c"), ("d", "", "b")]);
        assert_eq!(resolve("mcp__a__t", None, &s), ("t", Some("b")));
        assert_eq!(resolve("mcp__b__t", None, &s), ("t", Some("c")));
        assert_eq!(resolve("mcp__d__t", None, &s), ("t", Some("b")));
    }

    /// A gateway call's server is the upstream behind the virtual server, as on
    /// the MCP path: a profile keyed on the slug matches only where the
    /// tenant's virtual servers are not known. The call is the gateway's.
    #[test]
    fn a_profile_keyed_on_a_slug_gives_way_to_the_upstreams() {
        let web = names(&[("web", "", "builtin-web")]);
        let by_slug = FieldProfileSet::new(vec![profile(serde_json::json!({"tool_id": "slug_keyed",
            "tool_pattern": "web_fetch", "mcp_server": "web", "field": "url", "normalizer": "url"}))]);
        let unknown_servers = resolve_tool_name("mcp__web__web_fetch", None, None, Some(&by_slug));
        assert_eq!(by_slug.resolve_tool_id(unknown_servers.local, None, unknown_servers.mcp_server), Some("slug_keyed"));
        assert!(!unknown_servers.gateway);
        let known_servers = resolve_tool_name("mcp__web__web_fetch", None, Some(&web), Some(&by_slug));
        assert_eq!(by_slug.resolve_tool_id(known_servers.local, None, known_servers.mcp_server), None);
        assert!(known_servers.gateway);
    }

    fn slug() -> impl Strategy<Value = String> {
        "[a-z][a-z0-9-]{0,12}".prop_filter("not the bare lead", |s| s != "mcp")
    }
    fn prefix() -> impl Strategy<Value = String> {
        prop_oneof![Just(String::new()), "[a-z][a-z0-9]{0,5}"]
    }
    fn tool() -> impl Strategy<Value = String> {
        "[A-Za-z][A-Za-z0-9.-]{0,10}(_[A-Za-z0-9]{1,4}){0,2}"
    }

    proptest! {
        /// Every form a client writes a gateway tool under reads back as the
        /// upstream's name for the tool and that upstream.
        #[test]
        fn every_written_form_reads_back_the_upstreams_tool(slug in slug(), prefix in prefix(), tool in tool()) {
            let servers = names(&[(&slug, &prefix, "the-upstream")]);
            let wire = if prefix.is_empty() { tool.clone() } else { format!("{prefix}__{tool}") };
            let underscored = slug.replace('-', "_");
            for (name, app) in [
                (format!("mcp__{slug}__{wire}"), "claude-code"),
                (format!("mcp__{underscored}__{wire}"), "codex"),
                (format!("mcp_{slug}_{wire}"), "gemini-cli"),
                (format!("{underscored}_{wire}"), "opencode"),
            ] {
                let t = resolve_tool_name(&name, Some(app), Some(&servers), None);
                prop_assert_eq!((t.local, t.mcp_server), (tool.as_str(), Some("the-upstream")), "{}", name);
            }
        }

        /// A whole name the client's profiles name literally is never read as
        /// a virtual server's, in the bare form.
        #[test]
        fn a_literal_builtin_never_reads_as_a_server(slug in slug(), tool in tool()) {
            let servers = names(&[(&slug, "", "the-upstream")]);
            let name = format!("{}_{tool}", slug.replace('-', "_"));
            let own = FieldProfileSet::new(vec![profile(serde_json::json!({"tool_id": "own",
                "tool_pattern": name.clone(), "app_filter": "opencode", "field": "x", "normalizer": "raw"}))]);
            let t = resolve_tool_name(&name, Some("opencode"), Some(&servers), Some(&own));
            prop_assert_eq!((t.local, t.mcp_server), (name.as_str(), None));
        }

        /// A server whose slug a name does not carry never changes how the
        /// name reads.
        #[test]
        fn an_unrelated_server_changes_nothing(slug in slug(), other in slug(), tool in tool()) {
            let fold = |s: &str| s.replace('-', "_");
            prop_assume!(!fold(&tool).contains(&fold(&other)) && !fold(&slug).contains(&fold(&other)));
            let one = names(&[(&slug, "", "u1")]);
            let two = names(&[(&slug, "", "u1"), (&other, "", "u2")]);
            for name in [
                format!("mcp__{slug}__{tool}"),
                format!("mcp_{slug}_{tool}"),
                format!("{}_{tool}", fold(&slug)),
                tool.clone(),
            ] {
                let a = resolve_tool_name(&name, Some("opencode"), Some(&one), None);
                let b = resolve_tool_name(&name, Some("opencode"), Some(&two), None);
                prop_assert_eq!(a, b, "{}", name);
            }
        }
    }
}

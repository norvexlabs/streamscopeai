//! MCP virtualization mechanics — namespace prefix strip-and-stamp,
//! capability merging, per-route allow/deny filters.
//!
//! A virtual server has zero or more routes; each route binds an upstream
//! MCP server with an optional namespace prefix (`<prefix>__<name>`). When
//! we receive a `tools/list` we fan out to every route, apply the route's
//! filter, stamp the prefix onto each tool name, and concatenate. When we
//! receive a `tools/call` we strip the prefix off the wire name to identify
//! the route, then forward the underlying name to that upstream.
//!
//! Capability merging is union-of-supported — we advertise the union of
//! `tools | resources | prompts` capabilities from all upstreams.

use streamscope_core::config::mcp::{McpRouteFilter, McpVirtualRoute, resolve_route_prefix, routes_back_to};

/// Stamp every tool/prompt entry's `name` field with the route's prefix and
/// drop entries denied by the route's filter. Other fields pass through
/// untouched.
///
/// Operates on the JSON-RPC `result.tools` (or `result.prompts`) array.
/// Non-array values pass through unmodified — we don't synthesize structure
/// the upstream didn't send.
pub fn stamp_named_array(
    arr: &mut serde_json::Value,
    prefix: &str,
    filter: Option<&McpRouteFilter>,
) {
    let Some(items) = arr.as_array_mut() else {
        return;
    };
    items.retain_mut(|item| {
        let Some(obj) = item.as_object_mut() else {
            return true;
        };
        let name_str = match obj.get("name").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return true,
        };
        if let Some(f) = filter
            && !f.permits(&name_str)
        {
            return false;
        }
        if !prefix.is_empty() {
            let stamped = format!("{prefix}__{name_str}");
            obj.insert("name".into(), serde_json::Value::String(stamped));
        }
        true
    });
}

/// Rewrite every resource entry's `uri` to the gateway's virtualized form
/// (`stsmcp://<prefix>/<b64(original)>`) and drop entries denied by
/// `resources_filter`. The encoded URI carries the route in its prefix so
/// `resources/read` is fully self-routing — any proxy on any replica can
/// decode and forward to the owning upstream without consulting per-session
/// state.
pub fn rewrite_resource_uris(
    arr: &mut serde_json::Value,
    prefix: &str,
    filter: Option<&McpRouteFilter>,
) {
    let Some(items) = arr.as_array_mut() else {
        return;
    };
    items.retain_mut(|item| {
        let Some(obj) = item.as_object_mut() else {
            return true;
        };
        let uri = match obj.get("uri").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return true,
        };
        let name = obj.get("name").and_then(|v| v.as_str()).map(str::to_string);
        if let Some(f) = filter
            && let Some(n) = &name
            && !f.permits(n)
        {
            return false;
        }
        let encoded = streamscope_core::mcp::tokens::encode_resource_uri(prefix, &uri);
        obj.insert("uri".into(), serde_json::Value::String(encoded));
        true
    });
}

/// Rewrite every template entry's `uriTemplate` to the gateway's template
/// envelope (`stsmcp+<prefix>+<scheme>://<rest>`) and drop entries denied by
/// `resources_filter`. Mirror of [`rewrite_resource_uris`] for
/// `resources/templates/list` results — the envelope is structured so RFC
/// 6570 placeholder expansion on the agent side preserves the route prefix
/// (the agent substitutes inside `<rest>`, the prefix stays intact).
///
/// Templates whose `uriTemplate` lacks `://`, or carry `+` in the orig-scheme
/// (rare per RFC 3986), are dropped with a debug log — they can't be
/// virtualised and would otherwise smuggle an unrouted URI to the agent.
pub fn rewrite_resource_template_uris(
    arr: &mut serde_json::Value,
    prefix: &str,
    filter: Option<&McpRouteFilter>,
) {
    let Some(items) = arr.as_array_mut() else {
        return;
    };
    items.retain_mut(|item| {
        let Some(obj) = item.as_object_mut() else {
            return true;
        };
        let template = match obj.get("uriTemplate").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return true,
        };
        let name = obj.get("name").and_then(|v| v.as_str()).map(str::to_string);
        if let Some(f) = filter
            && let Some(n) = &name
            && !f.permits(n)
        {
            return false;
        }
        match streamscope_core::mcp::tokens::encode_resource_template(prefix, &template) {
            Ok(encoded) => {
                obj.insert("uriTemplate".into(), serde_json::Value::String(encoded));
                true
            }
            Err(err) => {
                tracing::debug!(
                    %err,
                    template = %template,
                    prefix = %prefix,
                    "templates/list: dropping unencodable uriTemplate"
                );
                false
            }
        }
    });
}

/// Resolve the route a stamped tool/prompt name belongs to, and the name its
/// upstream knows it by — by [`resolve_route_prefix`], the one rule the
/// portal's catalog preview shares. Every routed call, and the policy that
/// judges it, resolves through here, so they cannot disagree on the route.
pub fn route_for_name<'r, 'n>(
    routes: &'r [McpVirtualRoute],
    name: &'n str,
) -> Option<(&'r McpVirtualRoute, &'n str)> {
    let prefixes: Vec<&str> = routes.iter().map(|r| r.prefix.as_str()).collect();
    let (prefix, local) = resolve_route_prefix(name, &prefixes)?;
    route_for_prefix(routes, Some(prefix)).map(|r| (r, local))
}

/// Keep only the entries of one route's stamped `tools`/`prompts` array whose
/// name routes back to that route ([`routes_back_to`]), so every name the
/// merged list advertises is one a call reaches the advertising upstream
/// with: an empty-prefix upstream's name a sibling's prefix claims would
/// otherwise be listed twice and called on the sibling.
pub fn retain_routable(arr: &mut serde_json::Value, routes: &[McpVirtualRoute], route: &McpVirtualRoute) {
    let Some(items) = arr.as_array_mut() else {
        return;
    };
    let prefixes: Vec<&str> = routes.iter().map(|r| r.prefix.as_str()).collect();
    items.retain(|item| {
        let Some(name) = item.get("name").and_then(|v| v.as_str()) else {
            return true;
        };
        let routable = routes_back_to(name, &prefixes, &route.prefix);
        if !routable {
            tracing::debug!(
                name = %name,
                route = %route.id,
                prefix = %route.prefix,
                "MCP list: dropping a name that would not route back to the upstream listing it"
            );
        }
        routable
    });
}

/// Find the route whose `prefix` matches the given prefix. The empty prefix
/// matches the server's no-namespacing route.
pub fn route_for_prefix<'a>(
    routes: &'a [McpVirtualRoute],
    prefix: Option<&str>,
) -> Option<&'a McpVirtualRoute> {
    let target = prefix.unwrap_or("");
    routes.iter().find(|r| r.prefix == target)
}

/// Capability merge — union the upstream-advertised capabilities so the
/// gateway claims to support whatever any upstream supports. Returns a
/// JSON object suitable for the `capabilities` field of `initialize`.
///
/// **Honesty filter** (load-bearing): we MUST NOT advertise a capability we
/// can't actually route through the gateway. The dispatcher classifies
/// methods via `jsonrpc::classify_method`; anything in the `Other` arm is
/// blind passthrough to the first route, which silently misroutes for
/// multi-route VSs and breaks `stsmcp://` URI virtualization. So the merge
/// strips top-level capabilities the gateway hasn't taught the dispatcher
/// to understand:
///
/// - `tasks` (NEW in 2025-11-25) — `tasks/*` methods aren't classified yet;
///   if any upstream declares it, the agent would receive a `tasks/list`
///   that fans out to one route only, so it is stripped.
///
/// What is kept (we DO route correctly): `tools`, `resources` (incl. the
/// `subscribe` sub-cap because subscribe/unsubscribe route by URI prefix and
/// `resources/templates/list` is aggregated under the `stsmcp+<prefix>+...://`
/// envelope), `prompts`, `completions` (we route by `ref` type), `logging`
/// (we fan out `logging/setLevel` to every enabled route), `experimental`.
pub fn merge_capabilities(per_upstream: &[serde_json::Value]) -> serde_json::Value {
    let mut merged = serde_json::Map::new();
    for caps in per_upstream {
        let Some(obj) = caps.as_object() else {
            continue;
        };
        for (k, v) in obj {
            if !is_routable_capability(k) {
                tracing::debug!(
                    capability = %k,
                    "MCP merge_capabilities: stripping advertised-but-unrouted capability"
                );
                continue;
            }
            // Deep-merge object values; later upstreams may add fields.
            //
            // Boolean sub-capabilities (`listChanged`, `subscribe`) are OR-ed,
            // not first-wins. This merge advertises the UNION of what the
            // routes support, and every one of those flags means "at least one
            // upstream can do this". First-wins would let a route that
            // advertises `listChanged: false` mask a sibling that advertises
            // `true`, so the gateway would tell the client it cannot deliver
            // a notification it is in fact about to deliver — and a modern
            // client, which opts in per notification type against exactly
            // these flags, would never ask for it.
            match (merged.get_mut(k), v) {
                (Some(existing), serde_json::Value::Object(new_obj)) if existing.is_object() => {
                    let target = existing.as_object_mut().unwrap();
                    for (sk, sv) in new_obj {
                        match (target.get_mut(sk), sv) {
                            (
                                Some(serde_json::Value::Bool(current)),
                                serde_json::Value::Bool(incoming),
                            ) => *current = *current || *incoming,
                            // A non-boolean sub-field has no union we can
                            // compute, so the first upstream to name it wins.
                            (Some(_), _) => {}
                            (None, _) => {
                                target.insert(sk.clone(), sv.clone());
                            }
                        }
                    }
                }
                (Some(serde_json::Value::Bool(current)), serde_json::Value::Bool(incoming)) => {
                    *current = *current || *incoming;
                }
                _ => {
                    merged.entry(k.clone()).or_insert(v.clone());
                }
            }
        }
    }
    serde_json::Value::Object(merged)
}

/// Whether a top-level capability key is one the gateway dispatcher knows
/// how to route. Append-only — extending this list MUST be paired with a
/// new dispatch arm so we don't regress the over-advertisement bug this
/// guard exists to prevent.
fn is_routable_capability(key: &str) -> bool {
    matches!(
        key,
        "tools" | "resources" | "prompts" | "completions" | "logging" | "experimental"
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use streamscope_core::config::mcp::McpRouteFilter;
    use uuid::Uuid;

    pub(crate) fn route(prefix: &str) -> McpVirtualRoute {
        McpVirtualRoute {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            virtual_server_id: Uuid::new_v4(),
            upstream_server_id: Uuid::new_v4(),
            prefix: prefix.to_string(),
            tools_filter: None,
            resources_filter: None,
            prompts_filter: None,
            enabled: true,
            position: 0,
        }
    }

    #[test]
    fn stamp_prefix_onto_tool_array() {
        let mut tools = serde_json::json!([
            {"name": "search", "description": "x"},
            {"name": "fetch", "description": "y"},
        ]);
        stamp_named_array(&mut tools, "gh", None);
        let arr = tools.as_array().unwrap();
        assert_eq!(arr[0]["name"], "gh__search");
        assert_eq!(arr[1]["name"], "gh__fetch");
    }

    #[test]
    fn stamp_with_empty_prefix_is_noop_on_name() {
        let mut tools = serde_json::json!([{"name": "search"}]);
        stamp_named_array(&mut tools, "", None);
        assert_eq!(tools[0]["name"], "search");
    }

    #[test]
    fn stamp_drops_denied_entries() {
        let mut tools = serde_json::json!([
            {"name": "ok"},
            {"name": "blocked"},
        ]);
        let f = McpRouteFilter {
            allow: None,
            deny: Some(vec!["blocked".into()]),
        };
        stamp_named_array(&mut tools, "ns", Some(&f));
        let arr = tools.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["name"], "ns__ok");
    }

    fn resolve<'r, 'n>(routes: &'r [McpVirtualRoute], name: &'n str) -> Option<(&'r str, &'n str)> {
        route_for_name(routes, name).map(|(r, local)| (r.prefix.as_str(), local))
    }

    #[test]
    fn a_prefixed_route_receives_the_name_without_its_prefix() {
        let routes = vec![route("gh"), route("g_h")];
        assert_eq!(resolve(&routes, "gh__search"), Some(("gh", "search")));
        assert_eq!(resolve(&routes, "gh__a__b"), Some(("gh", "a__b")));
        assert_eq!(resolve(&routes, "gh___search"), Some(("gh", "_search")));
        assert_eq!(resolve(&routes, "g_h__search"), Some(("g_h", "search")));
        // Without an empty-prefix route, a name no prefix claims is unrouted.
        assert_eq!(resolve(&routes, "aws__search"), None);
        assert_eq!(resolve(&routes, "search"), None);
    }

    /// An upstream that names its own tools with `__` (the AWS Knowledge
    /// server's `aws___search_documentation`) behind an empty-prefix route.
    #[test]
    fn an_empty_prefix_route_receives_a_name_containing_the_separator_untouched() {
        let routes = vec![route("")];
        assert_eq!(
            resolve(&routes, "aws___search_documentation"),
            Some(("", "aws___search_documentation"))
        );
        assert_eq!(resolve(&routes, "__bad"), Some(("", "__bad")));
        assert_eq!(resolve(&routes, "plain"), Some(("", "plain")));
    }

    #[test]
    fn prefixed_and_empty_prefix_routes_share_one_server() {
        let routes = vec![route(""), route("gh")];
        assert_eq!(resolve(&routes, "gh__search"), Some(("gh", "search")));
        assert_eq!(resolve(&routes, "aws___search"), Some(("", "aws___search")));
    }

    /// A name a prefixed route claims is never handed to the empty-prefix
    /// upstream instead: one stamped by a prefix ending in `_`, or the empty
    /// tool name stamped as `gh__`, is unrouted.
    #[test]
    fn a_name_a_prefixed_route_claims_never_falls_to_the_empty_prefix_route() {
        let routes = vec![route(""), route("gh_")];
        assert_eq!(resolve(&routes, "gh___search"), None);
        let routes = vec![route(""), route("gh")];
        assert_eq!(resolve(&routes, "gh__"), None);
        assert_eq!(resolve(&routes, "ghx__search"), Some(("", "ghx__search")));
    }

    #[test]
    fn a_listed_name_is_kept_only_when_it_routes_back_to_its_upstream() {
        let routes = vec![route(""), route("ns")];
        let mut empty_route = serde_json::json!([
            {"name": "aws___search"},
            {"name": "ns__delete_repo"},
        ]);
        retain_routable(&mut empty_route, &routes, &routes[0]);
        assert_eq!(empty_route, serde_json::json!([{"name": "aws___search"}]));

        let mut prefixed = serde_json::json!([{"name": "delete_repo"}, {"name": ""}]);
        stamp_named_array(&mut prefixed, "ns", None);
        retain_routable(&mut prefixed, &routes, &routes[1]);
        assert_eq!(prefixed, serde_json::json!([{"name": "ns__delete_repo"}]));
    }

    #[test]
    fn route_for_prefix_resolves_empty_and_named() {
        let routes = vec![route(""), route("gh"), route("aws")];
        assert_eq!(route_for_prefix(&routes, None).unwrap().prefix, "");
        assert_eq!(route_for_prefix(&routes, Some("gh")).unwrap().prefix, "gh");
        assert!(route_for_prefix(&routes, Some("missing")).is_none());
    }

    /// The merge advertises the UNION of what the routes support, so a
    /// boolean sub-capability is true when ANY upstream offers it. First-wins
    /// would let a route that cannot do something mask a sibling that can —
    /// and a modern client opts in per notification type against exactly
    /// these flags, so it would then never ask for a notification the gateway
    /// is about to deliver.
    #[test]
    fn merge_capabilities_ors_boolean_subcapabilities() {
        let quiet = serde_json::json!({
            "resources": {"subscribe": false, "listChanged": false},
            "tools": {"listChanged": false},
        });
        let chatty = serde_json::json!({
            "resources": {"subscribe": true, "listChanged": true},
            "tools": {"listChanged": true},
        });
        // Order must not matter: the union is the same either way round.
        for pair in [[quiet.clone(), chatty.clone()], [chatty, quiet]] {
            let merged = merge_capabilities(&pair);
            assert_eq!(merged["resources"]["subscribe"], true);
            assert_eq!(merged["resources"]["listChanged"], true);
            assert_eq!(merged["tools"]["listChanged"], true);
        }
    }

    /// The other half of the union: when no upstream offers it, the merged
    /// view must still say so. Without this the OR above would pass with the
    /// flag hard-coded to `true`.
    #[test]
    fn merge_capabilities_leaves_a_universally_absent_capability_false() {
        let merged = merge_capabilities(&[
            serde_json::json!({"resources": {"subscribe": false, "listChanged": false}}),
            serde_json::json!({"resources": {"subscribe": false}}),
        ]);
        assert_eq!(merged["resources"]["subscribe"], false);
        assert_eq!(merged["resources"]["listChanged"], false);
    }

    #[test]
    fn merge_capabilities_unions_objects() {
        let a = serde_json::json!({"tools": {"listChanged": true}, "resources": {}});
        let b = serde_json::json!({"prompts": {}, "tools": {"streaming": true}});
        let merged = merge_capabilities(&[a, b]);
        let obj = merged.as_object().unwrap();
        assert!(obj.contains_key("tools"));
        assert!(obj.contains_key("resources"));
        assert!(obj.contains_key("prompts"));
        let tools = obj["tools"].as_object().unwrap();
        assert!(tools.contains_key("listChanged"));
        assert!(tools.contains_key("streaming"));
    }

    #[test]
    fn merge_capabilities_strips_unrouted_capabilities() {
        // `tasks` is NEW in MCP 2025-11-25 and the dispatcher doesn't yet
        // classify `tasks/*` methods. The merge guard MUST drop it so the
        // gateway never advertises it (otherwise the agent issues `tasks/list`
        // which falls through to `Other` → first-route passthrough → broken
        // for multi-route VSs).
        let upstream_with_tasks = serde_json::json!({
            "tools": {},
            "tasks": { "list": {}, "cancel": {} },
            "experimental": { "foo": true },
        });
        let merged = merge_capabilities(&[upstream_with_tasks]);
        let obj = merged.as_object().unwrap();
        assert!(obj.contains_key("tools"), "tools must survive");
        assert!(obj.contains_key("experimental"), "experimental must survive");
        assert!(!obj.contains_key("tasks"), "tasks MUST be stripped");
    }

    #[test]
    fn merge_capabilities_keeps_routable_subcapabilities() {
        // `resources.subscribe` (subscribe/unsubscribe routing landed
        // alongside the merge guard) and `completions` (completion/complete
        // routing landed alongside) are now first-class.
        let upstream = serde_json::json!({
            "resources": { "subscribe": true, "listChanged": true },
            "completions": {},
            "logging": {},
        });
        let merged = merge_capabilities(&[upstream]);
        let obj = merged.as_object().unwrap();
        assert_eq!(obj["resources"]["subscribe"], serde_json::Value::Bool(true));
        assert!(obj.contains_key("completions"));
        assert!(obj.contains_key("logging"));
    }

    #[test]
    fn merge_capabilities_strips_unknown_top_level_keys() {
        // Defensive: any future spec capability we haven't taught the
        // dispatcher about gets stripped. Forces the next contributor to
        // pair an `is_routable_capability` extension with a dispatch arm.
        let upstream = serde_json::json!({
            "tools": {},
            "future_thing": { "v": 1 },
        });
        let merged = merge_capabilities(&[upstream]);
        let obj = merged.as_object().unwrap();
        assert!(obj.contains_key("tools"));
        assert!(!obj.contains_key("future_thing"));
    }

    #[test]
    fn rewrite_resource_template_uris_wraps_each_entry() {
        let mut templates = serde_json::json!([
            {"uriTemplate": "file:///{path}", "name": "fs"},
            {"uriTemplate": "git:///{repo}/{ref}", "name": "git"},
        ]);
        rewrite_resource_template_uris(&mut templates, "ns", None);
        let arr = templates.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["uriTemplate"], "stsmcp+ns+file:///{path}");
        assert_eq!(arr[1]["uriTemplate"], "stsmcp+ns+git:///{repo}/{ref}");
    }

    #[test]
    fn rewrite_resource_template_uris_drops_unencodable() {
        // Templates whose orig-scheme contains `+` (e.g. `git+ssh`) and
        // schemeless templates are dropped — both are footguns the agent
        // shouldn't see.
        let mut templates = serde_json::json!([
            {"uriTemplate": "file:///{path}", "name": "ok"},
            {"uriTemplate": "git+ssh://example.com/{repo}", "name": "scheme_plus"},
            {"uriTemplate": "no-scheme/{x}", "name": "no_scheme"},
        ]);
        rewrite_resource_template_uris(&mut templates, "ns", None);
        let arr = templates.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["name"], "ok");
    }

    #[test]
    fn rewrite_resource_template_uris_honours_filter() {
        let mut templates = serde_json::json!([
            {"uriTemplate": "file:///{path}", "name": "ok"},
            {"uriTemplate": "file:///{denied}", "name": "blocked"},
        ]);
        let f = McpRouteFilter {
            allow: None,
            deny: Some(vec!["blocked".into()]),
        };
        rewrite_resource_template_uris(&mut templates, "ns", Some(&f));
        let arr = templates.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["name"], "ok");
    }

    #[test]
    fn rewrite_resource_uris_encodes_each_entry() {
        let mut resources = serde_json::json!([
            {"uri": "file:///a", "name": "a"},
            {"uri": "file:///b", "name": "b"},
        ]);
        rewrite_resource_uris(&mut resources, "fs", None);
        let arr = resources.as_array().unwrap();
        for item in arr {
            let uri = item["uri"].as_str().unwrap();
            assert!(uri.starts_with("stsmcp://fs/"), "got {uri}");
        }
        let first = arr[0]["uri"].as_str().unwrap();
        let (prefix, original) =
            streamscope_core::mcp::tokens::decode_resource_uri(first).unwrap();
        assert_eq!(prefix, "fs");
        assert_eq!(original, "file:///a");
    }
}

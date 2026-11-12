//! What a client-access profile hides in the portal, and the fences that hold
//! it.
//!
//! Two switches, each hidden for a caller when **every** workspace they act in
//! resolves to a profile that hides it (a member of none follows the Default;
//! an `ak-` key, its one bound workspace):
//!
//! - `sessions` — the Sessions page AND every conversation's content: a
//!   request's detail, its web calls, its media and its tool definitions are
//!   refused, and the request list is answered without content
//!   (`portal_view::WithoutContent`);
//! - `requests` — the Requests page, the per-request list.
//!
//! `portal_auth` resolves both once per request
//! ([`client_access_profiles::hidden_pages`], the one reader) and attaches the
//! [`HiddenPages`] to the request; the fences here, the request list, the Home
//! and `GET /portal/auth/me` read that. Hiding is enforced on the routes, not
//! only in the portal's navigation.
//!
//! [`client_access_profiles::hidden_pages`]: super::client_access_profiles::hidden_pages

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use axum::Extension;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{ApiError, ApiErrorCode};

/// A switch of a profile's Portal pages. The keys are sent
/// (`hidden_pages`): append-only. Each is a column of `client_access_portal`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PortalPage {
    /// **Conversations**: the Sessions page and all conversation content —
    /// request details, media, tool definitions.
    Sessions,
    /// **Requests page**: the list of requests (model, tokens, cost, status).
    Requests,
}

/// What the portal hides for one caller (or what one profile hides).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct HiddenPages {
    sessions: bool,
    requests: bool,
}

impl HiddenPages {
    pub(crate) fn new(sessions: bool, requests: bool) -> Self {
        Self { sessions, requests }
    }

    /// The set a request body names; a page named twice is hidden once.
    pub(crate) fn from_pages(pages: &[PortalPage]) -> Self {
        Self {
            sessions: pages.contains(&PortalPage::Sessions),
            requests: pages.contains(&PortalPage::Requests),
        }
    }

    pub(crate) fn hides(self, page: PortalPage) -> bool {
        match page {
            PortalPage::Sessions => self.sessions,
            PortalPage::Requests => self.requests,
        }
    }

    /// Whether conversation content is withheld from the caller — what hiding
    /// `sessions` means beyond the page.
    pub(crate) fn content_hidden(self) -> bool {
        self.sessions
    }

    /// `sessions` before `requests`, as the API sends them.
    pub(crate) fn into_vec(self) -> Vec<PortalPage> {
        [PortalPage::Sessions, PortalPage::Requests].into_iter().filter(|p| self.hides(*p)).collect()
    }
}

/// What a group of portal routes is fenced by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PageFence {
    /// The Sessions page's own reads: the session list, a session's
    /// conversation and its linked sessions.
    Sessions,
    /// Conversation content, wherever it is opened from: a request's detail,
    /// its web calls, its media, its tool definitions.
    Content,
    /// The Requests page's list.
    Requests,
    /// The filter options both pages read; they carry no content.
    Options,
}

impl PageFence {
    /// Whether the fence refuses a caller for whom `hidden` is hidden.
    /// Content follows `sessions` alone: with Requests hidden and Sessions
    /// shown it stays open (the Sessions page reads it), and with Sessions
    /// hidden it is refused whatever Requests is. The options are refused only
    /// when neither page is left to read them.
    pub(crate) fn refuses(self, hidden: HiddenPages) -> bool {
        match self {
            PageFence::Sessions => hidden.hides(PortalPage::Sessions),
            PageFence::Content => hidden.content_hidden(),
            PageFence::Requests => hidden.hides(PortalPage::Requests),
            PageFence::Options => hidden.hides(PortalPage::Sessions) && hidden.hides(PortalPage::Requests),
        }
    }
}

/// The refusal for a route hidden for the caller.
pub(crate) fn page_hidden() -> ApiError {
    ApiError::forbidden("this page is not available for your workspaces").code(ApiErrorCode::PortalPageHidden)
}

/// Refuse the request when `fence` does for this caller, else run it. Reads
/// the [`HiddenPages`] `portal_auth` attached: a route that reaches a fence
/// without it is answered 500 by the extractor, never served.
async fn fenced(fence: PageFence, hidden: HiddenPages, req: Request, next: Next) -> Result<Response, ApiError> {
    if fence.refuses(hidden) {
        return Err(page_hidden());
    }
    Ok(next.run(req).await)
}

/// [`PageFence::Sessions`] as a route layer.
pub async fn sessions_fence(Extension(hidden): Extension<HiddenPages>, req: Request, next: Next) -> Result<Response, ApiError> {
    fenced(PageFence::Sessions, hidden, req, next).await
}

/// [`PageFence::Content`] as a route layer.
pub async fn content_fence(Extension(hidden): Extension<HiddenPages>, req: Request, next: Next) -> Result<Response, ApiError> {
    fenced(PageFence::Content, hidden, req, next).await
}

/// [`PageFence::Requests`] as a route layer.
pub async fn requests_fence(Extension(hidden): Extension<HiddenPages>, req: Request, next: Next) -> Result<Response, ApiError> {
    fenced(PageFence::Requests, hidden, req, next).await
}

/// [`PageFence::Options`] as a route layer.
pub async fn options_fence(Extension(hidden): Extension<HiddenPages>, req: Request, next: Next) -> Result<Response, ApiError> {
    fenced(PageFence::Options, hidden, req, next).await
}

// ---------------------------------------------------------------------------
// Which portal route is in which group
// ---------------------------------------------------------------------------
//
// The lists are what the tests below hold the routers to: they exist for the
// check, so they are compiled with it.

/// The routes of [`PageFence::Sessions`] (`portal_sessions_router`).
#[cfg(test)]
pub(crate) const SESSIONS_ROUTES: &[&str] = &["/sessions", "/sessions/{id}/conversation", "/sessions/{id}/linked"];

/// The routes of [`PageFence::Content`] (`portal_content_router`).
#[cfg(test)]
pub(crate) const CONTENT_ROUTES: &[&str] = &[
    "/audit/media/{hash}",
    "/audit/tool-definitions/{hash}",
    "/audit/{request_id}",
    "/audit/{request_id}/web",
];

/// The routes of [`PageFence::Requests`] (`portal_requests_router`).
#[cfg(test)]
pub(crate) const REQUESTS_ROUTES: &[&str] = &["/audit"];

/// The routes of [`PageFence::Options`] (`portal_activity_options_router`).
#[cfg(test)]
pub(crate) const OPTIONS_ROUTES: &[&str] = &["/audit/filter-options"];

/// Every other portal route (`portal_router`), each read and judged not to
/// answer with a session, a request or its content. A route added to
/// `portal_router` fails
/// `every_portal_route_is_in_a_page_group_or_on_the_not_fenced_list` until it
/// is listed here — or moved to the group of the page that reads it, where it
/// belongs if it returns per-session or per-request rows, or content.
#[cfg(test)]
pub(crate) const NOT_FENCED_ROUTES: &[&str] = &[
    // The caller, their keys, their MCP servers and connections, their
    // client configs, their workspace's members, limits and automation.
    "/auth/me",
    "/keys",
    "/keys/{id}/actions/revoke",
    "/mcp/virtual-servers",
    "/mcp/local-servers",
    "/mcp/connections",
    "/mcp/connections/{upstream_id}/actions/connect",
    "/mcp/connections/{upstream_id}/actions/revoke",
    "/mcp/connections/{upstream_id}/inputs",
    "/mcp/virtual-servers/{virtual_server_id}/actions/test",
    "/quickstart/clients",
    "/quickstart/clients/{id}",
    "/quickstart/routes",
    "/quickstart/keys",
    "/quickstart/actions/render",
    "/provision/actions/bundle",
    "/client-access",
    "/workspaces/{id}/members",
    "/workspaces/{id}/members/{uid}/keys",
    "/workspaces/{id}/members/{uid}/keys/{key_id}/actions/revoke",
    "/workspaces/{id}/members/{uid}/keys/{key_id}/budget",
    "/workspaces/{id}/limits",
    "/workspaces/{id}/member-exceptions",
    "/workspaces/{id}/members/{uid}/limits",
    "/workspaces/{id}/automation-accounts",
    "/workspaces/{id}/automation-accounts/{said}/keys",
    "/workspaces/{id}/automation-accounts/{said}/keys/{key_id}/actions/revoke",
    "/workspaces/{id}/automation-accounts/{said}/actions/revoke",
    // Aggregates over the caller's activity — counts, tokens and spend, per
    // key or per member, never a session or a request: deliberately open.
    "/stats",
    "/workspaces/{id}/stats",
    "/workspaces/{id}/my-limits",
    // The Home: aggregates, plus the caller's latest sessions — which its
    // handler leaves out when Sessions is hidden.
    "/home",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_group_is_refused_by_the_switch_that_hides_what_it_reads() {
        let cases: [((bool, bool), [bool; 4]); 4] = [
            // (sessions, requests)   Sessions Content Requests Options
            ((false, false), [false, false, false, false]),
            ((true, false), [true, true, false, false]),
            ((false, true), [false, false, true, false]),
            ((true, true), [true, true, true, true]),
        ];
        for ((s, r), [sessions, content, requests, options]) in cases {
            let h = HiddenPages::new(s, r);
            assert_eq!(PageFence::Sessions.refuses(h), sessions, "{h:?}: Sessions");
            assert_eq!(PageFence::Content.refuses(h), content, "{h:?}: Content");
            assert_eq!(PageFence::Requests.refuses(h), requests, "{h:?}: Requests");
            assert_eq!(PageFence::Options.refuses(h), options, "{h:?}: Options");
            assert_eq!(h.content_hidden(), s, "{h:?}: content follows sessions alone");
        }
    }

    #[test]
    fn the_refusal_is_a_403_with_its_own_code() {
        let refusal = page_hidden();
        assert_eq!(refusal.status, axum::http::StatusCode::FORBIDDEN);
        assert_eq!(refusal.code, ApiErrorCode::PortalPageHidden);
    }

    #[test]
    fn the_hidden_set_is_sent_sessions_first_and_a_page_named_twice_counts_once() {
        use PortalPage::{Requests, Sessions};
        assert_eq!(HiddenPages::new(true, true).into_vec(), vec![Sessions, Requests]);
        assert_eq!(HiddenPages::new(false, true).into_vec(), vec![Requests]);
        assert_eq!(HiddenPages::default().into_vec(), Vec::<PortalPage>::new());
        assert_eq!(HiddenPages::from_pages(&[Requests, Sessions, Requests]), HiddenPages::new(true, true));
        assert_eq!(HiddenPages::from_pages(&[Sessions, Sessions]).into_vec(), vec![Sessions]);
        assert_eq!(HiddenPages::from_pages(&[]), HiddenPages::default());
        // The keys are sent as written here; they are append-only.
        assert_eq!(serde_json::to_value(vec![Sessions, Requests]).unwrap(), serde_json::json!(["sessions", "requests"]));
        assert!(serde_json::from_value::<PortalPage>(serde_json::json!("usage")).is_err());
    }

    /// The body of `pub fn <name>()` in `src`, up to its closing brace.
    fn body_of<'a>(src: &'a str, name: &str) -> &'a str {
        let start = src.find(&format!("pub fn {name}()")).unwrap_or_else(|| panic!("no fn {name}"));
        let body = &src[start..];
        // The body ends at the first line that is a lone closing brace.
        let end = body.find("\n}\n").unwrap_or_else(|| panic!("fn {name} has no end"));
        &body[..end]
    }

    /// The `.route("<path>"` paths in `body`.
    fn routes_in(body: &str) -> Vec<String> {
        let mut paths = Vec::new();
        let mut rest = body;
        while let Some(at) = rest.find(".route(") {
            rest = &rest[at + ".route(".len()..];
            let open = rest.find('"').expect("a route path");
            let close = rest[open + 1..].find('"').expect("a route path's end") + open + 1;
            paths.push(rest[open + 1..close].to_string());
            rest = &rest[close..];
        }
        paths
    }

    fn sorted(paths: &[impl AsRef<str>]) -> Vec<String> {
        let mut v: Vec<String> = paths.iter().map(|p| p.as_ref().to_string()).collect();
        v.sort();
        v
    }

    /// Each fenced router, its fence and its routes.
    const FENCED: [(&str, &str, &[&str]); 4] = [
        ("portal_sessions_router", "sessions_fence", SESSIONS_ROUTES),
        ("portal_content_router", "content_fence", CONTENT_ROUTES),
        ("portal_requests_router", "requests_fence", REQUESTS_ROUTES),
        ("portal_activity_options_router", "options_fence", OPTIONS_ROUTES),
    ];

    #[test]
    fn every_portal_route_is_in_a_page_group_or_on_the_not_fenced_list() {
        let src = include_str!("mod.rs");
        // Each fenced router serves exactly its group's routes…
        for (router, _, routes) in FENCED {
            assert_eq!(sorted(&routes_in(body_of(src, router))), sorted(routes), "{router}");
        }
        // …and every other portal route is one somebody listed as not fenced.
        let open = routes_in(body_of(src, "portal_router"));
        assert!(open.len() > 20, "the scan read the open router: {open:?}");
        assert_eq!(sorted(&open), sorted(NOT_FENCED_ROUTES));
        // No route is in two places.
        let mut all: Vec<&str> =
            [SESSIONS_ROUTES, CONTENT_ROUTES, REQUESTS_ROUTES, OPTIONS_ROUTES, NOT_FENCED_ROUTES].concat();
        all.sort_unstable();
        let before = all.len();
        all.dedup();
        assert_eq!(all.len(), before);
        // An activity path is never open: what lives under these prefixes
        // answers with sessions or requests.
        for path in NOT_FENCED_ROUTES {
            assert!(!path.starts_with("/sessions") && !path.starts_with("/audit"), "{path}");
        }
    }

    /// What `check_mounts` holds: `routers` is `routes/mod.rs`, `main` is
    /// `main.rs`. Returns the first thing wrong.
    fn check_mounts(routers: &str, main: &str) -> Result<(), String> {
        let squeeze = |s: &str| s.split_whitespace().collect::<String>();
        // A fenced router carries its fence itself, as its one layer, after
        // its last route — so it cannot be mounted without it.
        for (router, fence, _) in FENCED {
            let body = squeeze(body_of(routers, router));
            let layer = format!(".route_layer(axum::middleware::from_fn(portal_pages::{fence}))");
            if !body.ends_with(&layer) {
                return Err(format!("{router} does not end with its fence {fence}"));
            }
            if body.matches(".route_layer(").count() != 1 || body.contains(".layer(") {
                return Err(format!("{router} carries a layer besides its fence"));
            }
            if body.contains(".nest(") || body.contains(".merge(") {
                return Err(format!("{router} nests or merges another router"));
            }
        }
        // The open router is routes only: a router nested or merged into it
        // would bring routes no list names.
        let open = squeeze(body_of(routers, "portal_router"));
        if open.contains(".nest(") || open.contains(".merge(") || open.contains("layer(") {
            return Err("portal_router nests, merges or layers".into());
        }
        // The portal's authenticated router is the open one and the four
        // fenced ones, each merged once, and nothing else.
        let main = squeeze(main);
        let start = main.find("letportal_routes=").ok_or("main.rs has no portal_routes")?;
        let mount = &main[start..];
        let mount = &mount[..mount.find(';').ok_or("portal_routes has no end")?];
        let mut expected = "letportal_routes=routes::portal_router()".to_string();
        for (router, _, _) in FENCED {
            expected.push_str(&format!(".merge(routes::{router}())"));
        }
        if !mount.starts_with(&expected) {
            return Err("portal_routes is not the open router and the four fenced ones, in order".into());
        }
        let layers = &mount[expected.len()..];
        if layers.contains(".merge(") || layers.contains(".nest(") || layers.contains(".route(") {
            return Err("portal_routes merges, nests or routes something besides the five routers".into());
        }
        for (router, _, _) in FENCED {
            if main.matches(&format!("routes::{router}()")).count() != 1 {
                return Err(format!("{router} is mounted more than once"));
            }
        }
        if main.matches("routes::portal_router()").count() != 1 {
            return Err("portal_router is mounted more than once".into());
        }
        // Under `/api/v1/portal`: that router, the sign-in routes and the
        // header-auth session check — a router nobody listed is not.
        let nested: Vec<&str> = main
            .match_indices(".nest(\"/api/v1/portal\",")
            .map(|(at, pat)| {
                let rest = &main[at + pat.len()..];
                &rest[..rest.find(')').unwrap_or(rest.len())]
            })
            .collect();
        if nested != ["portal_routes", "portal_auth_routes", "portal_header_session_routes"] {
            return Err(format!("unexpected routers under /api/v1/portal: {nested:?}"));
        }
        Ok(())
    }

    #[test]
    fn each_fenced_router_is_mounted_once_behind_its_own_fence_and_nothing_else_is_under_the_portal() {
        let routers = include_str!("mod.rs");
        let main = include_str!("../main.rs");
        assert_eq!(check_mounts(routers, main), Ok(()));

        // The check sees each way a fence could be lost.
        let broken = |what: &str, routers: String, main: String| {
            assert!(check_mounts(&routers, &main).is_err(), "not caught: {what}");
        };
        let swap = |src: &str, from: &str, to: &str| {
            assert!(src.contains(from), "the fixture reads {from:?}");
            src.replacen(from, to, 1)
        };
        broken(
            "a fenced router merged a second time",
            routers.into(),
            swap(main, ".merge(routes::portal_requests_router())", ".merge(routes::portal_requests_router()).merge(routes::portal_requests_router())"),
        );
        broken(
            "a fenced router mounted outside the portal router",
            routers.into(),
            swap(main, ".nest(\"/api/v1/portal\", portal_auth_routes)", ".nest(\"/api/v1/portal\", portal_auth_routes.merge(routes::portal_content_router()))"),
        );
        broken(
            "a fenced router behind another's fence",
            swap(routers, "from_fn(portal_pages::content_fence)", "from_fn(portal_pages::options_fence)"),
            main.into(),
        );
        broken(
            "a fenced router without its fence",
            swap(routers, ".route_layer(axum::middleware::from_fn(portal_pages::sessions_fence))", ""),
            main.into(),
        );
        broken(
            "a router nested into the open router",
            swap(routers, ".route(\"/auth/me\", get(portal::me))", ".nest(\"/x\", portal_content_router()).route(\"/auth/me\", get(portal::me))"),
            main.into(),
        );
        broken(
            "a router merged into the open router",
            swap(routers, ".route(\"/auth/me\", get(portal::me))", ".merge(other_router()).route(\"/auth/me\", get(portal::me))"),
            main.into(),
        );
        broken(
            "an unknown router under /api/v1/portal",
            routers.into(),
            swap(main, ".nest(\"/api/v1/portal\", portal_auth_routes)", ".nest(\"/api/v1/portal\", portal_auth_routes).nest(\"/api/v1/portal\", extra_routes)"),
        );
        broken(
            "a router merged into the portal router besides the five",
            routers.into(),
            swap(main, ".merge(routes::portal_activity_options_router())", ".merge(routes::portal_activity_options_router()).merge(routes::extra_router())"),
        );
    }
}

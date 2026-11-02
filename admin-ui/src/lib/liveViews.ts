// The console views auto-refresh runs on: pages a viewer READS — dashboards,
// the server pages, sessions, the audit and tool-call logs. The portal has no
// auto-refresh (many members: each refreshes by hand). Pages a viewer EDITS (keys, gateways, edge,
// policy, settings) are refreshed by hand only:
// a reload landing around a save there can put the pre-save state back, so a
// timer must never run one. A page joins only if nothing is saved on it, or
// its one action re-reads through a latest-read-wins loader (the Users
// dashboard's dormant-key revoke). The console layout hands it to
// <RefreshButton>.

/** `subtree`: the route and every route under it; `exact`: the route alone. */
type LiveRoute = { id: string; match: 'subtree' | 'exact' };

const LIVE_ROUTES: readonly LiveRoute[] = [
	{ id: '/t/[slug]/dashboard', match: 'subtree' },
	{ id: '/t/[slug]/admin/overview', match: 'exact' },
	{ id: '/t/[slug]/sessions', match: 'subtree' },
	{ id: '/t/[slug]/audit', match: 'exact' },
	{ id: '/t/[slug]/tool-calls', match: 'exact' },
	{ id: '/t/[slug]/admin-audit', match: 'exact' },
];

/** Whether auto-refresh runs on the view at this route id. */
export function isLiveView(routeId: string | null | undefined): boolean {
	if (!routeId) return false;
	return LIVE_ROUTES.some((r) => routeId === r.id || (r.match === 'subtree' && routeId.startsWith(`${r.id}/`)));
}

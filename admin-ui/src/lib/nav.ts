/**
 * Typed sidebar navigation structure for the admin app.
 *
 * Three node kinds:
 *   - cluster: section header + items (Observability / Governance / Configuration).
 *   - subtree: parent leaf with an expandable child list (Dashboard, Gateways).
 *   - leaf:    a single navigable route.
 *
 * Visibility flags propagate from a subtree to its children when applied to
 * the parent — kept on individual leaves only when they need to differ.
 *
 * The renderer applies two propagation rules:
 *   - a subtree parent auto-hides when ALL its children hide
 *   - a cluster header auto-hides when ALL its items hide
 */

import type { IconName } from './icons';
import { m } from './paraglide/messages.js';

export type NavLeaf = {
	kind: 'leaf';
	href: string;
	label: string;
	icon: IconName;
	hideForSystem?: boolean;
	superAdminOnly?: boolean;
	/** Only render on the Kairos VM appliance (the host daemon is configured). */
	applianceOnly?: boolean;
	/** Portal: only render for a manager (of any of their workspaces). */
	managerOnly?: boolean;
};

export type NavSubtree = {
	kind: 'subtree';
	href: string; // parent route — clicked goes to an index page
	label: string;
	icon: IconName;
	children: NavLeaf[];
	hideForSystem?: boolean;
	superAdminOnly?: boolean;
	applianceOnly?: boolean;
};

export type NavCluster = {
	kind: 'cluster';
	label: string;
	items: (NavLeaf | NavSubtree)[];
};

// Portal sidebar — same `<SidebarNav>` component as admin. Home is the landing
// page and stands alone at the top; then what a member reads most (activity),
// what they set up once, their MCP tools, and the team page a manager runs.
// Every leaf is bookmarkable; no tabs anywhere in the portal.
//
// Built lazily (not a module-level const) because the labels are localized via
// `m.*()`: those must resolve in the active request/render locale, so call this
// inside a component `$derived`, never at module load.
export function buildPortalNav(): NavCluster[] {
	return [
		{
			kind: 'cluster',
			label: '',
			items: [{ kind: 'leaf', href: '/portal/home', label: m.nav_portal_home(), icon: 'home' }],
		},
		{
			kind: 'cluster',
			label: m.nav_portal_cluster_activity(),
			items: [
				{ kind: 'leaf', href: '/portal/sessions', label: m.nav_portal_sessions(), icon: 'chat' },
				{ kind: 'leaf', href: '/portal/audit', label: m.nav_portal_requests(), icon: 'requests' },
				{ kind: 'leaf', href: '/portal/usage', label: m.nav_portal_usage(), icon: 'trendingUp' },
			],
		},
		{
			kind: 'cluster',
			label: m.nav_portal_cluster_set_up(),
			items: [
				{ kind: 'leaf', href: '/portal/quickstart', label: m.nav_portal_quickstart(), icon: 'compass' },
				{ kind: 'leaf', href: '/portal/keys', label: m.nav_portal_api_keys(), icon: 'key' },
			],
		},
		{
			kind: 'cluster',
			label: m.nav_portal_cluster_mcp_tools(),
			items: [
				{ kind: 'leaf', href: '/portal/mcp/connections', label: m.nav_portal_sign_ins(), icon: 'lock' },
				{ kind: 'leaf', href: '/portal/mcp/test', label: m.nav_portal_try_server(), icon: 'wrench' },
			],
		},
		{
			kind: 'cluster',
			label: m.nav_portal_cluster_team(),
			items: [
				{ kind: 'leaf', href: '/portal/team', label: m.nav_portal_members_limits(), icon: 'users', managerOnly: true },
			],
		},
	];
}

/** The gateways, in sidebar order — the one list both the Gateways subtree and
 *  the `/gateways` landing page render. A gateway added here must also get a
 *  landing tile: the page keys its tile content by `GatewayHref`, so a missing
 *  entry fails svelte-check instead of shipping a hub that omits it. */
export const gatewayNav = [
	{ kind: 'leaf', href: '/gateways/llm', label: 'LLM', icon: 'bars3' },
	{ kind: 'leaf', href: '/gateways/mcp', label: 'MCP', icon: 'bolt' },
	{ kind: 'leaf', href: '/gateways/a2a', label: 'A2A', icon: 'users' },
] as const satisfies readonly NavLeaf[];

export type GatewayHref = (typeof gatewayNav)[number]['href'];

export const adminNav: NavCluster[] = [
	{
		// Platform-operator surface. Every item is superAdminOnly, so the whole
		// cluster auto-hides for regular tenants — it is visible only inside the
		// SYSTEM tenant.
		kind: 'cluster',
		label: 'Platform',
		items: [
			{ kind: 'leaf', href: '/admin/overview', label: 'Overview', icon: 'home', superAdminOnly: true },
			{ kind: 'leaf', href: '/admin/tenants', label: 'Tenants', icon: 'building', superAdminOnly: true },
			{ kind: 'leaf', href: '/admin/edge', label: 'Edge Nodes', icon: 'edge', superAdminOnly: true },
			{ kind: 'leaf', href: '/admin/appliance', label: 'Appliance', icon: 'cube', superAdminOnly: true, applianceOnly: true },
		],
	},
	{
		kind: 'cluster',
		label: 'Observability',
		items: [
			{
				kind: 'subtree',
				href: '/dashboard',
				label: 'Dashboard',
				icon: 'home',
				hideForSystem: true,
				children: [
					{ kind: 'leaf', href: '/dashboard', label: 'Overview', icon: 'home' },
					{ kind: 'leaf', href: '/dashboard/llm', label: 'LLM', icon: 'bars3' },
					{ kind: 'leaf', href: '/dashboard/servers', label: 'Servers', icon: 'edge' },
					{ kind: 'leaf', href: '/dashboard/media', label: 'Media', icon: 'image' },
					{ kind: 'leaf', href: '/dashboard/mcp', label: 'MCP', icon: 'bolt' },
					{ kind: 'leaf', href: '/dashboard/web', label: 'Web', icon: 'globe' },
					{ kind: 'leaf', href: '/dashboard/a2a', label: 'A2A', icon: 'users' },
					{ kind: 'leaf', href: '/dashboard/users', label: 'Users', icon: 'users' },
					{ kind: 'leaf', href: '/dashboard/tools', label: 'Tools', icon: 'settings' },
					{ kind: 'leaf', href: '/dashboard/transforms', label: 'Transforms', icon: 'bolt' },
					{ kind: 'leaf', href: '/dashboard/experts', label: 'Experts', icon: 'lightbulb' },
					{ kind: 'leaf', href: '/dashboard/proxy', label: 'Proxy', icon: 'arrowRight' },
				],
			},
			{ kind: 'leaf', href: '/sessions', label: 'Sessions', icon: 'chat', hideForSystem: true },
			{ kind: 'leaf', href: '/tool-calls', label: 'Tool Calls', icon: 'bag', hideForSystem: true },
			{ kind: 'leaf', href: '/audit', label: 'Audit Log', icon: 'audit', hideForSystem: true },
		],
	},
	{
		kind: 'cluster',
		label: 'Governance',
		items: [
			{ kind: 'leaf', href: '/workspaces', label: 'Workspaces', icon: 'building', hideForSystem: true },
			// Keys stays visible in SYSTEM scope: that's where Operator (super-admin)
			// automation keys are minted/revoked for system service accounts.
			{ kind: 'leaf', href: '/users', label: 'Keys', icon: 'users' },
			{ kind: 'leaf', href: '/policy', label: 'Tool Policy', icon: 'policy', hideForSystem: true },
			{ kind: 'leaf', href: '/guardrail', label: 'Guardrail', icon: 'shield', hideForSystem: true },
			{ kind: 'leaf', href: '/transforms', label: 'Transforms', icon: 'bolt', hideForSystem: true },
			{ kind: 'leaf', href: '/experts', label: 'Experts', icon: 'lightbulb', hideForSystem: true },
			{ kind: 'leaf', href: '/client-access', label: 'Client access', icon: 'clipboardCheck', hideForSystem: true },
			{ kind: 'leaf', href: '/destinations', label: 'Destinations', icon: 'compass', hideForSystem: true },
		],
	},
	{
		kind: 'cluster',
		label: 'Configuration',
		items: [
			{ kind: 'leaf', href: '/clients', label: 'Clients', icon: 'desktop', hideForSystem: true },
			{
				kind: 'subtree',
				href: '/gateways',
				label: 'Gateways',
				icon: 'cube',
				hideForSystem: true,
				children: [...gatewayNav],
			},
			{ kind: 'leaf', href: '/auth', label: 'Auth', icon: 'lock' },
			{ kind: 'leaf', href: '/admin-audit', label: 'Audit', icon: 'audit' },
			{ kind: 'leaf', href: '/settings', label: 'Settings', icon: 'cog' },
		],
	},
];

/** Filter the nav tree against the current viewer's flags. Empty subtrees and
 *  empty clusters auto-hide. Returns a new array — never mutates input. */
export function filterNavForViewer(
	nav: NavCluster[],
	ctx: { isSystemTenant: boolean; isSuperAdmin: boolean; isAppliance?: boolean; isManager?: boolean },
): NavCluster[] {
	const visible = (item: NavLeaf | NavSubtree): boolean => {
		if ('managerOnly' in item && item.managerOnly && !ctx.isManager) return false;
		if (item.superAdminOnly && !ctx.isSuperAdmin) return false;
		if (item.hideForSystem && ctx.isSystemTenant) return false;
		if (item.applianceOnly && !ctx.isAppliance) return false;
		return true;
	};

	const out: NavCluster[] = [];
	for (const cluster of nav) {
		const items: (NavLeaf | NavSubtree)[] = [];
		for (const item of cluster.items) {
			if (!visible(item)) continue;
			if (item.kind === 'subtree') {
				const children = item.children.filter((c) => visible(c) && visible(item));
				if (children.length === 0) continue;
				items.push({ ...item, children });
			} else {
				items.push(item);
			}
		}
		if (items.length > 0) out.push({ ...cluster, items });
	}
	return out;
}

/** Return a copy of the nav tree with every href mapped through `scope` — used to
 *  prefix tenant-relative hrefs with the per-tenant URL scope (/t/<slug>,
 *  /portal/t/<slug>) before rendering. The sidebar then matches against the full
 *  pathname and navigates to the scoped href with no scope-awareness of its own. */
export function scopeNav(nav: NavCluster[], scope: (href: string) => string): NavCluster[] {
	return nav.map((cluster) => ({
		...cluster,
		items: cluster.items.map((item) =>
			item.kind === 'subtree'
				? {
						...item,
						href: scope(item.href),
						children: item.children.map((c) => ({ ...c, href: scope(c.href) })),
					}
				: { ...item, href: scope(item.href) },
		),
	}));
}

/** Find which subtree (if any) contains the given pathname. Returns the subtree
 *  href so the renderer can auto-expand the right group. Exact match wins;
 *  prefix matches handle nested routes (`/dashboard/llm` → `/dashboard`). */
export function activeSubtreeHref(nav: NavCluster[], pathname: string): string | null {
	for (const cluster of nav) {
		for (const item of cluster.items) {
			if (item.kind !== 'subtree') continue;
			if (item.children.some((c) => c.href === pathname)) return item.href;
			if (pathname.startsWith(item.href + '/')) return item.href;
		}
	}
	return null;
}

/** One breadcrumb: a label and the tenant-RELATIVE href it links to (`''` for
 *  a cluster heading, which is not a route). */
export type Crumb = { label: string; href: string };

/** A path segment naming one row rather than a page, when the route is not
 *  known: a UUID or a number. */
const ID_SEGMENT = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|\d+)$/i;

/** The label for the path below the deepest nav entry: its last segment that
 *  names a page (`/profiles/<uuid>` → "Profiles"), or "Details" when every
 *  segment names a row. A row's id or slug never becomes a label. */
function tailLabel(tail: string[], isRow: (segment: string, index: number) => boolean): string {
	const named = tail.filter((s, i) => !isRow(s, i));
	const last = named[named.length - 1];
	if (!last) return 'Details';
	const words = last.replace(/[-_]+/g, ' ');
	return words.charAt(0).toUpperCase() + words.slice(1);
}

/** The header breadcrumb for a tenant-RELATIVE pathname: the deepest nav entry
 *  the path is at or under, with its cluster (and subtree parent), then — for a
 *  path below that entry — one last crumb for the page itself. Every crumb's
 *  href is distinct, so the list can be keyed by it.
 *
 *  `routeId` is the matched route, tenant-relative (`/admin/tenants/[detail]`):
 *  a segment its `[param]` names is a row, whatever it looks like (a slug
 *  included). Without it, a UUID or a number is taken for a row. */
export function breadcrumbFor(nav: NavCluster[], pathname: string, routeId?: string | null): Crumb[] {
	if (pathname === '/') return [{ label: 'Dashboard', href: '/dashboard' }];
	// A `(group)` segment never reaches the URL; a rest or optional parameter
	// spans a variable number of segments, so such a route cannot be aligned
	// segment by segment and the id check stands in for it.
	const routeSegments =
		routeId && !/\[\[|\[\.\.\./.test(routeId)
			? routeId.split('/').filter((seg) => seg && !/^\(.+\)$/.test(seg))
			: null;
	const pathSegments = pathname.split('/').filter(Boolean);
	const isRowAt = (segment: string, index: number) =>
		routeSegments ? /^\[.+\]$/.test(routeSegments[index] ?? '') : ID_SEGMENT.test(segment);
	let best: { href: string; crumbs: Crumb[] } | null = null;
	const consider = (href: string, crumbs: Crumb[]) => {
		if (href !== pathname && !pathname.startsWith(href + '/')) return;
		if (!best || href.length > best.href.length) best = { href, crumbs };
	};
	for (const cluster of nav) {
		const heading: Crumb = { label: cluster.label, href: '' };
		for (const item of cluster.items) {
			const own: Crumb = { label: item.label, href: item.href };
			consider(item.href, [heading, own]);
			if (item.kind !== 'subtree') continue;
			for (const child of item.children) {
				// A subtree's index leaf shares the parent's href: the parent
				// crumb already names it.
				if (child.href === item.href) continue;
				consider(child.href, [heading, own, { label: child.label, href: child.href }]);
			}
		}
	}
	const found = best as { href: string; crumbs: Crumb[] } | null;
	const depth = found ? found.href.split('/').filter(Boolean).length : 0;
	const tail = pathSegments.slice(depth);
	const label = tailLabel(tail, (seg, i) => isRowAt(seg, depth + i));
	if (!found) return [{ label, href: pathname }];
	if (tail.length === 0) return found.crumbs;
	return [...found.crumbs, { label, href: pathname }];
}

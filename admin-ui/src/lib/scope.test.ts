import { beforeEach, describe, expect, it, vi } from 'vitest';

// The tenant is the URL's `slug`; a test moves between tenants by changing it.
const route = vi.hoisted(() => ({ params: { slug: 'a' } as Record<string, string | undefined> }));
vi.mock('$app/state', () => ({ page: route }));

// Each profile read waits until the test answers it, in any order.
const pending: ((names: string[] | null) => void)[] = [];
vi.mock('#lib/api-client.js', () => ({
	adminApi: {
		GET: () =>
			new Promise((resolve) =>
				pending.push((names) =>
					resolve(names === null
						? { error: { code: 'internal' } }
						: { data: { items: names.map((name) => ({ id: name, name, is_default: false })) } }),
				),
			),
	},
}));

const stored = new Map<string, string>();
let writes = 0;
vi.stubGlobal('localStorage', {
	getItem: (k: string) => stored.get(k) ?? null,
	setItem: (k: string, v: string) => void (writes++, stored.set(k, v)),
	removeItem: (k: string) => void (writes++, stored.delete(k)),
});

const {
	consoleScope,
	currentWorkspaceQuery,
	loadPersistedAuditFilters,
	persistAuditFilters,
	portalScope,
	profileLists,
	reconcilePortalWorkspace,
	reconcileWorkspace,
	resolvePortalWorkspace,
	workspaceIdsQuery,
} = await import('#lib/scope.svelte.js');
const { refreshCycle } = await import('#lib/refreshCycle.svelte.js');

const W1 = '11111111-1111-4111-8111-111111111111';
const W2 = '22222222-2222-4222-8222-222222222222';
const AGENT = '33333333-3333-4333-8333-333333333333';
const LIST = [
	{ id: W1, name: 'one', role: 'default' as const },
	{ id: W2, name: 'two', role: 'standard' as const },
	{ id: AGENT, name: 'agent', role: 'agent' as const },
];

let tenant = 0;
beforeEach(() => {
	// A tenant no earlier test has touched: the pins are module state.
	route.params.slug = `t${++tenant}`;
	consoleScope.workspaces = LIST;
});

describe('the header workspace pin', () => {
	it('a_pin_is_remembered_per_tenant', () => {
		const a = route.params.slug;
		consoleScope.workspace = W1;
		expect(stored.get(`streamscope.workspace.${a}`)).toBe(W1);
		route.params.slug = 'other';
		expect(consoleScope.workspace).toBe('all');
		route.params.slug = a;
		expect(consoleScope.workspace).toBe(W1);
	});

	it('a_tenant_named_like_an_object_member_reads_its_own_pin', () => {
		route.params.slug = 'constructor';
		expect(consoleScope.workspace).toBe('all');
		consoleScope.workspace = W1;
		expect(consoleScope.workspace).toBe(W1);
		consoleScope.workspace = 'all';
	});

	// What keeps a reconcile run from an effect (the portal layout's, on every
	// run) from waking that effect again.
	it('an_unchanged_pick_writes_nothing', () => {
		consoleScope.workspace = W1;
		const before = writes;
		consoleScope.workspace = W1;
		expect(writes).toBe(before);
		consoleScope.workspace = W2;
		expect(writes).toBe(before + 1);
	});

	it('a_pick_storage_refuses_still_holds_in_the_tab', () => {
		const setItem = localStorage.setItem;
		localStorage.setItem = () => {
			throw new Error('QuotaExceededError');
		};
		try {
			consoleScope.workspace = W2;
			expect(consoleScope.workspace).toBe(W2);
		} finally {
			localStorage.setItem = setItem;
		}
	});

	it('a_fresh_tab_reads_the_stored_pin_and_all_forgets_it', () => {
		const slug = route.params.slug;
		stored.set(`streamscope.workspace.${slug}`, W2);
		expect(consoleScope.workspace).toBe(W2);
		consoleScope.workspace = 'all';
		expect(stored.has(`streamscope.workspace.${slug}`)).toBe(false);
	});

	it('a_pin_the_list_no_longer_has_falls_back_to_all_and_an_empty_list_changes_nothing', () => {
		consoleScope.workspace = W1;
		reconcileWorkspace([]);
		expect(consoleScope.workspace).toBe(W1);
		reconcileWorkspace(LIST);
		expect(consoleScope.workspace).toBe(W1);
		reconcileWorkspace(LIST.filter((w) => w.id !== W1));
		expect(consoleScope.workspace).toBe('all');
	});
});

describe('what is held per tenant', () => {
	it('a_workspace_list_is_never_read_under_another_tenant', () => {
		const a = route.params.slug;
		expect(consoleScope.workspaces).toEqual(LIST);
		route.params.slug = 'elsewhere';
		expect(consoleScope.workspaces).toEqual([]);
		expect(currentWorkspaceQuery()).toEqual({});
		route.params.slug = a;
		expect(consoleScope.workspaces).toEqual(LIST);
	});

	it('the_remembered_audit_filters_are_the_tenants_own', () => {
		const a = route.params.slug;
		persistAuditFilters({ days: '7', workspace_ids: W1 });
		expect(loadPersistedAuditFilters()).toEqual({ days: '7', workspace_ids: W1 });
		route.params.slug = 'elsewhere-audit';
		expect(loadPersistedAuditFilters()).toEqual({});
		route.params.slug = a;
		persistAuditFilters({});
		expect(stored.has(`streamscope.audit_filters.${a}`)).toBe(false);
	});
});

describe('the profile lists', () => {
	it('only_the_latest_read_lands_and_a_failed_one_keeps_the_list', async () => {
		pending.length = 0;
		const older = profileLists.load('tools');
		const newer = profileLists.load('tools');
		pending[1](['new']);
		pending[0](['old']);
		await Promise.all([older, newer]);
		expect(profileLists.tools.map((p) => p.name)).toEqual(['new']);
		const failed = profileLists.load('tools');
		pending[2](null);
		await failed;
		expect(profileLists.tools.map((p) => p.name)).toEqual(['new']);
	});

	it('an_answer_lands_only_if_newer_than_the_last_landed', () => {
		const early = profileLists.begin('transform');
		const late = profileLists.begin('transform');
		profileLists.land(late, [{ id: W2, name: 'late', is_default: false }]);
		profileLists.land(early, [{ id: W1, name: 'early', is_default: false }]);
		expect(profileLists.transform.map((p) => p.name)).toEqual(['late']);
		// A newer read that fails lands nothing, and does not cost an older
		// one's answer.
		const older = profileLists.begin('transform');
		profileLists.begin('transform');
		profileLists.land(older, [{ id: W1, name: 'older', is_default: false }]);
		expect(profileLists.transform.map((p) => p.name)).toEqual(['older']);
		const a = route.params.slug;
		const asked = profileLists.begin('transform');
		route.params.slug = 'switched';
		profileLists.land(asked, [{ id: W1, name: 'for-a', is_default: false }]);
		expect(profileLists.transform).toEqual([]);
		route.params.slug = a;
		expect(profileLists.transform.map((p) => p.name)).toEqual(['older']);
	});

	it('a_list_is_never_read_under_another_tenant_nor_lands_there', async () => {
		pending.length = 0;
		const a = route.params.slug;
		const read = profileLists.load('expert');
		route.params.slug = 'moved-on';
		pending[0](['for-a']);
		await read;
		expect(profileLists.expert).toEqual([]);
		route.params.slug = a;
		expect(profileLists.expert).toEqual([]);
		const again = profileLists.load('expert');
		pending[1](['for-a']);
		await again;
		expect(profileLists.expert.map((p) => p.name)).toEqual(['for-a']);
		route.params.slug = 'moved-on';
		expect(profileLists.expert).toEqual([]);
	});
});

describe('the workspace query', () => {
	it('all_is_every_workspace_but_the_agent_one_and_a_pin_narrows_to_it', () => {
		expect(currentWorkspaceQuery()).toEqual({ workspace_ids: `${W1},${W2}` });
		consoleScope.workspace = AGENT;
		expect(currentWorkspaceQuery()).toEqual({ workspace_ids: AGENT });
		consoleScope.workspace = 'not-an-id';
		expect(currentWorkspaceQuery()).toEqual({ workspace_ids: `${W1},${W2}` });
	});

	it('an_inline_selection_keeps_its_ids_and_drops_a_token_that_is_not_one', () => {
		expect(workspaceIdsQuery(`${W2}, junk,${AGENT}`, LIST)).toEqual({ workspace_ids: `${W2},${AGENT}` });
		expect(workspaceIdsQuery('', LIST)).toEqual({ workspace_ids: `${W1},${W2}` });
		expect(workspaceIdsQuery(undefined, [])).toEqual({});
	});

	it('the_list_key_moves_with_membership_not_with_a_new_array', () => {
		const key = consoleScope.workspacesKey;
		consoleScope.workspaces = [...LIST].reverse();
		expect(consoleScope.workspacesKey).toBe(key);
		consoleScope.workspaces = LIST.slice(1);
		expect(consoleScope.workspacesKey).not.toBe(key);
	});
});

describe('the portal workspace', () => {
	const MEMBERS = [
		{ id: W1, name: 'one', role: 'member', shares_with_members: false },
		{ id: W2, name: 'two', role: 'manager', shares_with_members: true },
	];

	it('a_remembered_membership_is_kept_else_the_first_one_is_taken', () => {
		portalScope.activeWorkspace = W2;
		reconcilePortalWorkspace(MEMBERS);
		expect(portalScope.activeWorkspace).toBe(W2);
		reconcilePortalWorkspace(MEMBERS.slice(0, 1));
		expect(portalScope.activeWorkspace).toBe(W1);
		expect(stored.get(`streamscope.portal.workspace.${route.params.slug}`)).toBe(W1);
	});

	it('the_resolved_workspace_is_the_remembered_membership_else_the_first_else_none', () => {
		expect(resolvePortalWorkspace(MEMBERS, W2)).toBe(W2);
		expect(resolvePortalWorkspace(MEMBERS.slice(0, 1), W2)).toBe(W1);
		expect(resolvePortalWorkspace(MEMBERS, null)).toBe(W1);
		expect(resolvePortalWorkspace([], W1)).toBeNull();
		expect(resolvePortalWorkspace([], null)).toBeNull();
	});

	it('no_membership_clears_the_choice', () => {
		portalScope.activeWorkspace = W1;
		reconcilePortalWorkspace([]);
		expect(portalScope.activeWorkspace).toBeNull();
		expect(stored.has(`streamscope.portal.workspace.${route.params.slug}`)).toBe(false);
	});
});

describe('the refresh cycle', () => {
	it('a_listener_runs_once_per_refresh_at_the_refresh_until_it_stops', () => {
		const seen: number[] = [];
		const stop = refreshCycle.listen(() => seen.push(refreshCycle.sequence));
		const start = refreshCycle.sequence;
		refreshCycle.refresh();
		refreshCycle.refresh();
		expect(seen).toEqual([start + 1, start + 2]);
		stop();
		refreshCycle.refresh();
		expect(seen).toEqual([start + 1, start + 2]);
	});
});

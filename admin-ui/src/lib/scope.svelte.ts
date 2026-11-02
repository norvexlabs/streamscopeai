import { untrack } from 'svelte';
import { page } from '$app/state';
import { adminApi } from '#lib/api-client.js';
import { isWorkspaceId } from './filter-values';

/**
 * Tagged union of period selector states. Either a rolling lookback in days
 * (matches the `<PeriodSelector>` 1d / 7d / 30d preset pills) or an absolute
 * range (matches the custom date picker). Every analytics-shaped admin
 * endpoint accepts both forms via the canonical `TimeWindow` query primitive.
 */
export type PeriodValue =
  | { kind: 'rolling'; days: number }
  | { kind: 'absolute'; start: string; end: string };

/** Spread into adminApi query params: yields `{ days }` OR `{ start, end }`. */
function periodQuery(p: PeriodValue): { days?: number; start?: string; end?: string } {
    return p.kind === 'rolling' ? { days: p.days } : { start: p.start, end: p.end };
}

/**
 * The current header period as query params. A snapshot for a request, read
 * untracked: what re-runs a loader is `usePeriodicLoad`'s reload signals, never
 * an effect that happens to call it.
 */
export function currentPeriodQuery(): { days?: number; start?: string; end?: string } {
    return periodQuery(untrack(() => consoleScope.period));
}

// ---------------------------------------------------------------------------
// URL-bound period for the investigative (audit) pages
// ---------------------------------------------------------------------------
// The audit pages don't read the global header period — they own a per-page
// `<PeriodSelector>` whose value lives in the URL (via the page's `UrlFilters`)
// so a filtered audit view is shareable. A rolling window serializes as a
// single `days` key; a custom range as `start` + `end`. These keys + defaults
// register straight into the page's `UrlFilters`; the converters map between
// the URL strings and the canonical `PeriodValue` the selector emits.

/** Filter keys an audit page adds to its `UrlFilters` to URL-bind the period. */
export const PERIOD_FILTER_KEYS = ['days', 'start', 'end'] as const;

/** Default period filter values — 30-day rolling (omitted from the URL). */
export const PERIOD_FILTER_DEFAULTS = { days: '30' } as const;

/** Decode URL filter strings into a `PeriodValue` (absolute wins; else rolling, 30d fallback). */
export function periodFromFilters(v: { days?: string; start?: string; end?: string }): PeriodValue {
    if (v.start && v.end) return { kind: 'absolute', start: v.start, end: v.end };
    const d = parseInt(v.days ?? '', 10);
    return { kind: 'rolling', days: Number.isFinite(d) && d > 0 ? d : 30 };
}

/** Encode a `PeriodValue` back into the three URL filter strings (the unused pair is blanked). */
export function periodToFilters(p: PeriodValue): { days: string; start: string; end: string } {
    return p.kind === 'absolute'
        ? { days: '', start: p.start, end: p.end }
        : { days: String(p.days), start: '', end: '' };
}

// ---------------------------------------------------------------------------
// Cross-view persistence for the investigative (audit) filter bar
// ---------------------------------------------------------------------------
// The investigative pages (/audit, /sessions, /tool-calls, /admin-audit) each
// own a per-page `UrlFilters`, so sidebar navigation between them would drop
// the time range + workspace scope back to the page default. To make the lens
// follow the operator across all four views (and survive reload), we mirror the
// period (`days`/`start`/`end`) + inline `workspace_ids` into localStorage —
// the same idiom the header workspace (`consoleScope.workspace`) uses. The URL stays the shareable
// source of truth (a link wins on load); the remembered lens seeds a page only
// on a BARE navigation (no query string). Any query-bearing URL — a deep-link
// or a shared link — is authoritative and takes page defaults for what it
// omits, so it is never silently narrowed by the viewer's remembered scope.
// The all-or-nothing seed lives in `useAuditPeriod` (hooks.svelte.ts).

/** The investigative filter keys that persist across views via localStorage. */
export const AUDIT_PERSIST_KEYS = ['days', 'start', 'end', 'workspace_ids'] as const;

const AUDIT_FILTERS_LS_KEY = 'streamscope.audit_filters';

/** The tenant the page is under — the URL's `slug`, the same on both planes. */
function tenantSlug(): string {
    return page.params.slug ?? '';
}

/** A localStorage key of this tenant's own: one tenant's remembered choice
 *  never scopes another's queries. */
function tenantKey(key: string): string {
    return `${key}.${tenantSlug()}`;
}

/** Read the remembered investigative filters; `{}` when absent or corrupt (never throws). */
export function loadPersistedAuditFilters(): Partial<Record<string, string>> {
    if (typeof localStorage === 'undefined') return {};
    const raw = localStorage.getItem(tenantKey(AUDIT_FILTERS_LS_KEY));
    if (!raw) return {};
    try {
        const parsed = JSON.parse(raw) as Record<string, unknown>;
        const out: Record<string, string> = {};
        for (const k of AUDIT_PERSIST_KEYS) {
            const v = parsed[k];
            if (typeof v === 'string' && v) out[k] = v;
        }
        return out;
    } catch {
        return {};
    }
}

/** Remember the persisted subset of the current investigative filters (drops empties). */
export function persistAuditFilters(values: Record<string, string>): void {
    if (typeof localStorage === 'undefined') return;
    const out: Record<string, string> = {};
    for (const k of AUDIT_PERSIST_KEYS) {
        const v = values[k];
        if (v) out[k] = v;
    }
    if (Object.keys(out).length === 0) localStorage.removeItem(tenantKey(AUDIT_FILTERS_LS_KEY));
    else localStorage.setItem(tenantKey(AUDIT_FILTERS_LS_KEY), JSON.stringify(out));
}

/** The dashboard header selector's workspace: `'all'` or one workspace id. */
export type WorkspaceValue = 'all' | string;

/**
 * A choice remembered per tenant, in localStorage under `tenantKey(key)`.
 * Storage is read once per tenant in a tab (another tab's pick is seen after a
 * reload); setting `fallback` forgets the stored pick.
 */
class TenantPin<T extends string | null> {
    // Moves on every change made in this tab — what makes a read reactive.
    #picks = $state(0);
    // The tenant's value as this tab knows it. A plain map: a read may run
    // inside a derived, which must not write state.
    readonly #known = new Map<string, T>();

    constructor(
        private readonly key: string,
        private readonly fallback: T,
    ) {}

    get value(): T {
        void this.#picks;
        const slug = tenantSlug();
        if (!this.#known.has(slug)) {
            const stored = typeof localStorage === 'undefined' ? null : (localStorage.getItem(tenantKey(this.key)) as T | null);
            this.#known.set(slug, stored ?? this.fallback);
        }
        return this.#known.get(slug) as T;
    }

    set value(v: T) {
        // An unchanged value writes nothing and wakes no reader — a reconcile
        // run from an effect must not re-run it.
        if (untrack(() => this.value) === v) return;
        this.#known.set(tenantSlug(), v);
        untrack(() => (this.#picks += 1));
        // Remembering is best effort: storage that refuses (full, or blocked)
        // leaves the pick in force for this tab.
        try {
            if (typeof localStorage === 'undefined') return;
            if (v === this.fallback || v === null) localStorage.removeItem(tenantKey(this.key));
            else localStorage.setItem(tenantKey(this.key), v);
        } catch {
            /* kept in this tab only */
        }
    }
}

/**
 * A value that belongs to the tenant it was set under: read under any other
 * tenant it is `fallback`, never the previous tenant's. Replaced whole.
 */
class TenantHeld<T> {
    #held = $state.raw<{ tenant: string; value: T } | null>(null);

    constructor(private readonly fallback: T) {}

    get value(): T {
        const held = this.#held;
        return held !== null && held.tenant === tenantSlug() ? held.value : this.fallback;
    }

    set value(v: T) {
        this.#held = { tenant: tenantSlug(), value: v };
    }
}

/** A workspace's role — mirrors the backend `WorkspaceRole` enum. */
type WorkspaceRole = 'standard' | 'default' | 'agent' | 'inline';

/** Lightweight workspace identity for the selector + inline filter. */
export type WorkspaceLite = {
    id: string;
    name: string;
    role: WorkspaceRole;
};

/**
 * The dashboard live lens, shared by every dashboard page: the header period
 * and workspace selectors, and the tenant's workspace list they choose from.
 * Investigative pages own URL-bound filters instead and read only `workspaces`.
 * Values are replaced whole, never mutated in place.
 */
class ConsoleScope {
    /** The header period. Default: 1 day rolling. In memory only. */
    period = $state.raw<PeriodValue>({ kind: 'rolling', days: 1 });

    /**
     * The period as a day count, for labels: the rolling `days`, else the
     * absolute window's length rounded up (a 25-hour window reads "2d").
     */
    periodDays = $derived.by((): number => {
        const p = this.period;
        if (p.kind === 'rolling') return p.days;
        const ms = new Date(p.end).getTime() - new Date(p.start).getTime();
        return Math.max(1, Math.ceil(ms / (24 * 60 * 60 * 1000)));
    });

    #workspace = new TenantPin<WorkspaceValue>('streamscope.workspace', 'all');

    /**
     * The header workspace: `'all'` aggregates every workspace but the Agent
     * one; an id pins the dashboards (`/dashboard/*` + `/admin/overview`) to
     * it. Unlike the period it survives a reload (per tenant), and
     * `reconcileWorkspace` drops a pinned id that no longer exists.
     */
    get workspace(): WorkspaceValue {
        return this.#workspace.value;
    }

    set workspace(v: WorkspaceValue) {
        this.#workspace.value = v;
    }

    #workspaces = new TenantHeld<WorkspaceLite[]>([]);

    /** The tenant's workspaces, loaded by the tenant layout — empty under
     *  another tenant until its own list lands, never the previous one's. */
    get workspaces(): WorkspaceLite[] {
        return this.#workspaces.value;
    }

    set workspaces(list: WorkspaceLite[]) {
        this.#workspaces.value = list;
    }

    /** Number of workspaces — the selector + inline filter hide when `<= 1`. */
    workspaceCount = $derived(this.workspaces.length);

    /** The list's membership — its sorted ids — so a reader re-runs when the
     *  set changes, never for an identical list set again on a navigation. */
    workspacesKey = $derived(this.workspaces.map((w) => w.id).sort().join(','));
}

export const consoleScope = new ConsoleScope();

/**
 * Reconcile the persisted/global workspace against a freshly-loaded list:
 * drop a pinned id that no longer exists (deleted workspace) back to `'all'`.
 * Call after populating `consoleScope.workspaces`.
 */
export function reconcileWorkspace(list: WorkspaceLite[]): void {
    // Every tenant has its default workspace: an empty list answers nothing.
    if (list.length === 0) return;
    const current = untrack(() => consoleScope.workspace);
    if (current !== 'all' && !list.some((w) => w.id === current)) {
        consoleScope.workspace = 'all';
    }
}

/**
 * The workspace filter is multi-valued: the API takes a comma-separated set of
 * workspace ids (`workspace_ids`) and matches any of them. The **default view
 * excludes the Agent workspace** — agent traffic is just another workspace you
 * can opt back in by selecting it; there is no separate "hide agent" toggle.
 * The default is expressed by sending the explicit non-agent id set (the API
 * stays generic: an omitted filter means *all* workspaces, agent included).
 */
function nonAgentIds(list: WorkspaceLite[]): string[] {
    return list.filter((w) => w.role !== 'agent').map((w) => w.id);
}

/**
 * Spread into adminApi query params for the inline (multi-select) filter. `csv`
 * is the page filter's selected-id CSV (URL-bound). An empty/absent selection
 * falls back to the default — every workspace except the Agent one.
 */
export function workspaceIdsQuery(
    csv: string | undefined,
    list: WorkspaceLite[]
): { workspace_ids?: string } {
    // A token that is not an id (a stale or hand-edited URL) is dropped: the
    // API refuses the whole list for one.
    const sel = (csv ?? '')
        .split(',')
        .map((s) => s.trim())
        .filter(isWorkspaceId);
    const ids = sel.length > 0 ? sel : nonAgentIds(list);
    return ids.length > 0 ? { workspace_ids: ids.join(',') } : {};
}

/**
 * The dashboard header selector as query params. A pinned single workspace
 * narrows to it (the Agent workspace is selectable like any other); `'all'`
 * means every workspace **except** the Agent one. A snapshot read untracked,
 * like `currentPeriodQuery`.
 */
export function currentWorkspaceQuery(): { workspace_ids?: string } {
    return untrack(() => {
        const w = consoleScope.workspace;
        // A persisted pick that is not an id (hand-edited storage) reads as 'all'
        // until the workspace list reconciles it: the API refuses a bad id.
        if (w && w !== 'all' && isWorkspaceId(w)) return { workspace_ids: w };
        const ids = nonAgentIds(consoleScope.workspaces);
        return ids.length > 0 ? { workspace_ids: ids.join(',') } : {};
    });
}

/**
 * A dashboard's live scope (header workspace selector + period) as investigative
 * deep-link params, so a metric/breakdown row-link opens `/audit` (or
 * `/sessions`) on exactly what the dashboard shows. Pure over the two global
 * values so callers can wrap it in a `$derived(…)` over `consoleScope` and
 * get a fully reactive scope. A pinned workspace is carried explicitly; the
 * `'all'` aggregate is left off — it maps to the investigative page's own
 * default (every workspace except Agent), so the link stays short and still
 * reproduces the shown scope. The period is always carried so the target window
 * matches the dashboard's rather than falling back to the page default.
 */
export function dashboardScopeParams(
    p: PeriodValue,
    w: WorkspaceValue
): { workspace_ids?: string; days?: string; start?: string; end?: string } {
    const f = periodToFilters(p);
    const out: { workspace_ids?: string; days?: string; start?: string; end?: string } = {
        ...dashboardWorkspaceParam(w),
    };
    if (f.days) out.days = f.days;
    if (f.start) out.start = f.start;
    if (f.end) out.end = f.end;
    return out;
}

/**
 * The workspace half of {@link dashboardScopeParams}, without the period. Use
 * for deep-links off a surface whose figures are NOT scoped by the header
 * period — a persistent notification feed, or the attention tiles' fixed
 * short backend window — where carrying the period would open a window that
 * excludes the very rows the count is about. A pinned workspace is carried; the
 * `'all'` aggregate is left off (it maps to the page default).
 */
export function dashboardWorkspaceParam(w: WorkspaceValue): { workspace_ids?: string } {
    return w && w !== 'all' && isWorkspaceId(w) ? { workspace_ids: w } : {};
}

// ---------------------------------------------------------------------------
// Portal active-workspace context
// ---------------------------------------------------------------------------
// The portal operates *within* one of the signed-in user's workspaces at a
// time (unlike the admin selector's `'all'` aggregate — the portal always
// acts inside a concrete workspace, because keys are workspace-bound and the
// manager Team panel targets one workspace). Self-hides when the user has a
// single membership. Persisted to localStorage and validated against the live
// membership list, mirroring `consoleScope.workspace`.

/**
 * A portal workspace membership — the workspace plus the caller's role in it —
 * exactly as `/portal/auth/me` returns it. There is no `slug`: the portal
 * addresses a workspace by `id` everywhere.
 */
export type PortalWorkspaceMembership = {
    id: string;
    name: string;
    role: string;
    /** Workspace shares members' usage/sessions/audit with one another. */
    shares_with_members: boolean;
};

/** The portal's workspace context. Values are replaced whole. */
class PortalScope {
    #workspaces = new TenantHeld<PortalWorkspaceMembership[]>([]);

    /** The signed-in user's workspace memberships, hydrated from `me` in the
     *  layout — empty under another tenant until its own arrive. */
    get workspaces(): PortalWorkspaceMembership[] {
        return this.#workspaces.value;
    }

    set workspaces(list: PortalWorkspaceMembership[]) {
        this.#workspaces.value = list;
        this.#loaded.value = true;
    }

    #loaded = new TenantHeld<boolean>(false);

    /** The layout has set this tenant's memberships (possibly none): until
     *  then an empty list means "not known yet", not "a member of nothing". */
    get membershipsLoaded(): boolean {
        return this.#loaded.value;
    }

    /** Membership count — the portal selector self-hides when `<= 1`. */
    workspaceCount = $derived(this.workspaces.length);

    #activeWorkspace = new TenantPin<string | null>('streamscope.portal.workspace', null);

    /** Active portal workspace id, or `null` until memberships hydrate.
     *  Remembered per tenant. */
    get activeWorkspace(): string | null {
        return this.#activeWorkspace.value;
    }

    set activeWorkspace(v: string | null) {
        this.#activeWorkspace.value = v;
    }

    /** The full membership object for the active workspace, or `null`. */
    activeMembership = $derived.by(() => {
        const id = this.activeWorkspace;
        return this.workspaces.find((w) => w.id === id) ?? null;
    });
}

export const portalScope = new PortalScope();

/** The name of one of the caller's workspaces, or `undefined` for none (the
 *  caller's own rows) or an id that is not a membership. */
export function portalWorkspaceName(id: string | undefined): string | undefined {
    return id === undefined ? undefined : portalScope.workspaces.find((w) => w.id === id)?.name;
}

/**
 * Reconcile the active portal workspace against a freshly-loaded membership
 * list: keep the persisted id when still a member, else fall back to the first
 * membership (Default-first ordering from the `me` query). Call after
 * populating `portalScope.workspaces`.
 */
export function reconcilePortalWorkspace(list: PortalWorkspaceMembership[]): void {
    const current = untrack(() => portalScope.activeWorkspace);
    const resolved = resolvePortalWorkspace(list, current);
    if (resolved !== current) portalScope.activeWorkspace = resolved;
}

/**
 * The workspace the portal works in, given the memberships and the remembered
 * choice: that choice while still a membership, else the first membership,
 * else none. The one rule behind the header picker's reconcile and a page that
 * must read its workspace before the layout has reconciled (the Home's first
 * load, from the server-loaded memberships).
 */
export function resolvePortalWorkspace(list: PortalWorkspaceMembership[], remembered: string | null): string | null {
    if (remembered && list.some((w) => w.id === remembered)) return remembered;
    return list.length > 0 ? list[0].id : null;
}

/** Lightweight profile identity for the per-kind workspace profile pickers. */
export type ProfileLite = { id: string; name: string; is_default: boolean };

export type ProfileListKind = 'tools' | 'guardrail' | 'transform' | 'expert';

const PROFILE_LIST_KINDS: readonly ProfileListKind[] = ['tools', 'guardrail', 'transform', 'expert'];

/** A read of one profile list: its order among that kind's reads, and the
 *  tenant it asked for. */
type ProfileRead = { kind: ProfileListKind; n: number; tenant: string };

/**
 * The tenant's profiles of each kind, for the workspace profile pickers — read
 * by the tenant layout (`load`) and by the profiles manager (`begin` before it
 * asks, `land` with its answer). Every read takes its place in one order per
 * kind: an answer lands only if it is newer than the last one landed, and only
 * for the tenant it asked for. A failed read lands nothing, so the list it had
 * stays — never an empty picker under a form being filled.
 */
class ProfileLists {
    readonly #lists: Record<ProfileListKind, TenantHeld<ProfileLite[]>> = {
        tools: new TenantHeld<ProfileLite[]>([]),
        guardrail: new TenantHeld<ProfileLite[]>([]),
        transform: new TenantHeld<ProfileLite[]>([]),
        expert: new TenantHeld<ProfileLite[]>([]),
    };
    readonly #reads: Record<ProfileListKind, number> = { tools: 0, guardrail: 0, transform: 0, expert: 0 };
    readonly #landed: Record<ProfileListKind, number> = { tools: 0, guardrail: 0, transform: 0, expert: 0 };

    get tools(): ProfileLite[] { return this.#lists.tools.value; }
    get guardrail(): ProfileLite[] { return this.#lists.guardrail.value; }
    get transform(): ProfileLite[] { return this.#lists.transform.value; }
    get expert(): ProfileLite[] { return this.#lists.expert.value; }

    begin(kind: ProfileListKind): ProfileRead {
        return { kind, n: ++this.#reads[kind], tenant: tenantSlug() };
    }

    land(read: ProfileRead, list: ProfileLite[]): void {
        if (read.n <= this.#landed[read.kind] || read.tenant !== tenantSlug()) return;
        this.#landed[read.kind] = read.n;
        this.#lists[read.kind].value = list;
    }

    /** Read every kind. */
    loadAll(): void {
        for (const kind of PROFILE_LIST_KINDS) void this.load(kind);
    }

    /** Read one kind. */
    async load(kind: ProfileListKind): Promise<void> {
        const read = this.begin(kind);
        const { data } = await adminApi
            .GET('/api/v1/admin/profiles', { params: { query: { kind, limit: 200 } } })
            .catch(() => ({ data: undefined }));
        if (data) this.land(read, data.items.map((p) => ({ id: p.id, name: p.name, is_default: p.is_default })));
    }
}

export const profileLists = new ProfileLists();

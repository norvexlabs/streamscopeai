import { onMount, onDestroy, tick, untrack } from 'svelte';
import { consoleScope, periodFromFilters, periodToFilters, loadPersistedAuditFilters, persistAuditFilters, AUDIT_PERSIST_KEYS, type PeriodValue } from '#lib/scope.svelte.js';
import { beforeNavigate, goto } from '$app/navigation';
import { page } from '$app/state';
import { getTabFromUrl, setTabParam } from '#lib/tabs.js';
import { singleFlight } from '#lib/singleFlight.js';
import { Pagination, type ClientList } from '#lib/pagination.svelte.js';
export { Pagination, type ClientList };
import { refreshCycle, PageLoads, reloadCause, type ReloadCause, type ReloadSignals } from '#lib/refreshCycle.svelte.js';

/**
 * Run `fn` on every refresh (↻, R, an auto-refresh tick) after this call —
 * never for the trigger's value at mount, which the page's own mount load
 * covers. Called from the refresh itself, once per refresh and outside any
 * effect, so nothing `fn` reads is tracked: a loader reading the pager or a
 * scope is not re-run when they change. For a page that loads on its own
 * rather than through `usePeriodicLoad`.
 */
export function onRefresh(fn: () => void) {
	onDestroy(refreshCycle.listen(fn));
}

/** Convenience constructor for inline usage: `const pg = usePagination({ limit: 25 });`. */
export function usePagination(opts?: { limit?: number; list?: ClientList }): Pagination {
	return new Pagination(opts);
}

/** Page loads in flight across every mounted page loader. */
const pageLoads = new PageLoads();

/**
 * Composable that handles the common data-loading lifecycle:
 * 1. Calls `onMountFn` once on mount (initial load + any page-specific setup)
 * 2. Re-calls `reloadFn` whenever the header period, the refresh sequence, the
 *    pinned header workspace, or the loaded workspace list changes (skipping
 *    the initial mount). Tracking the list is load-bearing: the default
 *    workspace filter is derived from it, and it populates asynchronously after
 *    mount.
 * 3. Publishes the refresh cycle for the trend chips (`#lib/refreshCycle.svelte.js`):
 *    a scope signal or a URL change moves `scopeGeneration`, and once every
 *    page load in flight has finished, `loadsSettled` names the current refresh.
 *
 * Must be called at the top level of a component's <script> block (not inside event handlers).
 *
 * @param onMountFn  Called once on mount. Typically loads initial data + any extra setup.
 * @param reloadFn   Called on each later signal change. Defaults to `onMountFn` if omitted.
 */
export function usePeriodicLoad(
	onMountFn: () => Promise<void> | void,
	reloadFn?: (cause: ReloadCause) => Promise<void> | void,
) {
	const reload: (cause: ReloadCause) => Promise<void> | void = reloadFn ?? (() => onMountFn());

	// The reload signals, read by the effect at the end: the period (the
	// tagged union, as JSON, so rolling-day and absolute-range changes both
	// count), the refresh sequence, the pinned header workspace, and the
	// workspace LIST. The list is loaded asynchronously by the tenant layout,
	// after a page has already mounted and issued its first query, and the
	// default filter (every workspace except the Agent one) is derived from it
	// — an empty list at first-query time silently degrades to "all
	// workspaces incl. agent". So its arrival re-fires the loader with the
	// right default. It is compared by its membership signature: the layout
	// re-sets an identical list on every navigation, which must not reload.
	const signals = (): ReloadSignals => ({
		period: JSON.stringify(consoleScope.period),
		refresh: refreshCycle.sequence,
		workspace: consoleScope.workspace,
		workspaces: consoleScope.workspacesKey,
	});

	// The mount load and every signal-triggered reload share one exclusion, which
	// is what makes the async `workspaces` arrival safe for EVERY consumer
	// (dashboards included): the initial unfiltered query completes, then the
	// corrective default-filtered reload runs after it — never overlapping, so a
	// slower earlier load cannot clobber a faster later one. Coalescing semantics
	// live with the runner in `#lib/singleFlight.js`. A page's OWN direct loader
	// calls (pagination, applyFilters) bypass this and are guarded page-side.
	//
	// The reload is told its cause; a trailing run that coalesced several
	// triggers is a scope change if any of them was one.
	let trailingCause: ReloadCause | null = null;
	const runExclusive = singleFlight(
		served(() => {
			const cause = trailingCause ?? 'refresh';
			trailingCause = null;
			return reload(cause);
		}),
	);

	// Settling for the trend chips (`#lib/refreshCycle.svelte.js`) follows the loads that
	// actually RUN: each trigger joins the page-wide set when it fires and
	// leaves it when the run serving it ends — the run it started, or the
	// trailing run it was coalesced into. Following the whole coalesced flight
	// instead would never settle while ticks keep re-arming a slow reload.
	// A trigger still waiting when the page goes away is dropped, never waited on.
	let waiting: number[] = [];
	const mine = new Set<number>();
	onDestroy(() => {
		for (const id of mine) pageLoads.drop(id);
		mine.clear();
		waiting = [];
	});
	function served(task: () => Promise<void> | void): () => Promise<void> {
		return async () => {
			const ids = waiting;
			waiting = [];
			try {
				await task();
			} finally {
				for (const id of ids) finish(id);
			}
		};
	}
	function finish(id: number): void {
		if (!mine.delete(id)) return;
		const settled = pageLoads.end(id, Date.now());
		if (settled === null) return;
		// Let the loaded values reach their cards before the loads are declared
		// settled — a card must observe its new reading first. A load begun
		// during that tick settles itself when it ends.
		void tick().then(() => {
			if (!pageLoads.busy(Date.now())) refreshCycle.loadsSettled = { refresh: settled };
		});
	}
	function trigger(task: () => Promise<void> | void, refresh: number, cause?: ReloadCause): void {
		if (cause) trailingCause = trailingCause === 'scope' ? 'scope' : cause;
		const id = pageLoads.begin(refresh, Date.now());
		mine.add(id);
		waiting.push(id);
		void runExclusive(served(task));
	}

	// The first run is the mount: it records the signals and runs `onMountFn`;
	// later runs reload only when a signal's VALUE moved (`reloadCause`), so an
	// identical re-emit never issues a second load.
	//
	// The body is `untrack`ed because callers commonly do a read-modify-write
	// like `nonce += 1`, which expands to `set(nonce, get(nonce) + 1)`. Without
	// `untrack`, the `get(nonce)` would register `nonce` as a dependency of this
	// effect and the subsequent `set(nonce, ...)` would re-fire the effect,
	// producing `effect_update_depth_exceeded`.
	let seen: ReloadSignals | null = null;
	$effect(() => {
		const next = signals();
		untrack(() => {
			const first = seen === null;
			const cause = reloadCause(seen, next);
			seen = next;
			if (first) {
				trigger(onMountFn, next.refresh);
			} else if (cause === 'scope' || cause === 'refresh') {
				if (cause === 'scope') refreshCycle.noteScopeChange();
				// Run now (it clears the trailing cause it set), or coalesced
				// into the trailing run, which reads it.
				trigger(() => {
					trailingCause = null;
					return reload(cause);
				}, next.refresh, cause);
			}
		});
	});

	// A URL change (another record, a tab, a page filter) is a scope change for
	// the trend chips; it does not reload — the page loads its own URL state.
	// The hash is left out: an in-page anchor changes nothing the page shows.
	let seenUrl: string | null = null;
	$effect(() => {
		const href = page.url.pathname + page.url.search;
		untrack(() => {
			if (seenUrl !== null && seenUrl !== href) refreshCycle.noteScopeChange();
			seenUrl = href;
		});
	});
}

/**
 * URL-bound filter state. Initial values seed from `page.url.searchParams`,
 * and any in-page mutation pushes back into the URL via `goto({ replace })`
 * so a browser refresh — or a copy-pasted URL — preserves the operator's view.
 *
 * Usage (canonical pattern):
 *
 *   const filters = new UrlFilters(['user_email', 'kind', 'model']);
 *   // <input bind:value={filters.values.user_email} />
 *   // <select bind:value={filters.values.kind}> … </select>
 *   //
 *   // After the first data load completes, arm() so the URL starts
 *   // tracking changes:
 *   await loadData();
 *   filters.arm();
 *
 * Why arm() is explicit: page-level state on first mount is already in
 * sync with the URL (we just seeded from it), so the initial $effect
 * tick must not trigger a redundant `goto`. arm() flips the gate.
 */
export class UrlFilters<K extends string = string> {
	values = $state<Record<string, string>>({});
	private keys: readonly string[];
	private defaults: Readonly<Partial<Record<K, string>>>;
	private ready = $state(false);
	// Debounce handle so a typing user doesn't trigger one `goto()` per
	// keystroke (200 ms idle window — long enough to coalesce typing,
	// short enough to feel instant when the user pauses).
	private flushTimer: ReturnType<typeof setTimeout> | null = null;
	private static readonly FLUSH_DEBOUNCE_MS = 200;

	/**
	 * @param keys     The filter keys this instance manages.
	 * @param defaults Per-key default values. When a value matches its
	 *   default, it is OMITTED from the URL — keeps clean URLs for the
	 *   common case (e.g. `kind: 'llm'` on /audit, `status: 'active'`
	 *   on the Tokens tab).
	 */
	constructor(keys: readonly K[], defaults: Readonly<Partial<Record<K, string>>> = {} as Readonly<Partial<Record<K, string>>>) {
		this.keys = keys;
		this.defaults = defaults;
		// Seed from URL once at construction; fall back to per-key default.
		const seed: Record<string, string> = {};
		for (const k of keys) {
			const fromUrl = page.url.searchParams.get(k);
			seed[k] = fromUrl ?? (defaults[k] ?? '');
		}
		this.values = seed;

		// Push state → URL whenever any value changes (after arm()),
		// debounced so per-keystroke binding doesn't fire one `goto()`
		// per character.
		$effect(() => {
			// Touch every key so the effect re-runs on any change.
			for (const k of this.keys) void this.values[k];
			if (!this.ready) return;
			if (this.flushTimer != null) clearTimeout(this.flushTimer);
			this.flushTimer = setTimeout(() => {
				this.flushTimer = null;
				this.flush();
			}, UrlFilters.FLUSH_DEBOUNCE_MS);
		});
	}

	/** Mark the filters as ready to track. Call after first load completes. */
	arm() {
		this.ready = true;
	}

	/**
	 * Force the current values into the URL immediately (bypassing the debounce).
	 * Call once right after `arm()` to surface values that were seeded from a
	 * source other than the URL (e.g. localStorage-hydrated investigative
	 * filters) so the view is shareable. A no-op when the URL already matches —
	 * `flush()` skips when the target equals the current location.
	 */
	pushToUrl() {
		this.flush();
	}

	/** Read a single value (returns '' if unset). */
	get(key: K): string {
		return this.values[key] ?? '';
	}

	/** Mutate a single value — triggers the URL push via the watching $effect. */
	set(key: K, value: string) {
		this.values = { ...this.values, [key]: value };
	}

	/** Clear every key (resets to its declared default). Useful for a
	 *  "Clear filters" button. */
	clear() {
		const next: Record<string, string> = {};
		for (const k of this.keys) {
			next[k] = (this.defaults as Record<string, string | undefined>)[k] ?? '';
		}
		this.values = next;
	}

	/** Project the current values as a plain object — for passing into a fetch. */
	snapshot(): Record<K, string> {
		const out = {} as Record<K, string>;
		for (const k of this.keys) out[k as K] = (this.values[k] ?? '') as string;
		return out;
	}

	/** Push current state into the URL via `goto({ replace })`.
	 *  Values matching their declared default are omitted to keep URLs
	 *  short and consistent. Idempotent. */
	private flush() {
		const next = new URLSearchParams(page.url.search);
		const defaults = this.defaults as Record<string, string | undefined>;
		for (const k of this.keys) {
			const v = this.values[k];
			const isDefault = (v ?? '') === (defaults[k] ?? '');
			if (v && !isDefault) next.set(k, v);
			else next.delete(k);
		}
		const qs = next.toString();
		const target = qs ? `${page.url.pathname}?${qs}` : page.url.pathname;
		if (target !== `${page.url.pathname}${page.url.search}`) {
			void goto(target, { replace: true, reset: false });
		}
	}
}

/**
 * Period + cross-view persistence for an investigative (audit) page's filter
 * bar. Wraps the page's `UrlFilters` to:
 *
 *  1. Hydrate the time range (`days`/`start`/`end`) + inline `workspace_ids`
 *     from localStorage on a BARE navigation only (no query string) — so the
 *     lens the operator picked on one investigative view follows them to the
 *     next (and survives reload). A URL that carries any query is authoritative:
 *     a deep-link / shared link shows exactly what it names and takes page
 *     defaults for the rest, so it can never be silently narrowed by the
 *     viewer's remembered scope.
 *  2. Write the persisted subset back to localStorage on every change.
 *  3. Expose the `<PeriodSelector>` contract: `value` (the canonical
 *     `PeriodValue`) + `change(p)` (updates the URL-bound filters, then
 *     reloads the page's data).
 *
 * The inline `<WorkspaceFilter>` keeps binding `filters.values.workspace_ids`
 * directly — its persistence is covered by the same write-through effect. Pass
 * `{ persistWorkspace: false }` on a page whose `workspace_ids` is a distinct
 * filter (admin-audit's portal-plane scope) so it doesn't share the audit
 * family's remembered workspace.
 *
 * Pass `{ persist: false }` where the remembered lens must not apply (the
 * portal: a member's views never share the console's remembered filters): the
 * period is then the URL's, or the page default, and nothing is remembered.
 *
 * Pair with `filters.pushToUrl()` right after `filters.arm()` so a
 * localStorage-hydrated lens is reflected in the URL (shareable).
 *
 * Usage:
 *
 *   const filters = new UrlFilters([...PERIOD_FILTER_KEYS, 'workspace_ids', …], {…});
 *   const period = useAuditPeriod(filters, applyFilters);
 *   // <PeriodSelector selected={period.value} onchange={period.change} />
 *   // … after first load: filters.arm(); filters.pushToUrl();
 */
export function useAuditPeriod(
	filters: UrlFilters,
	reload: () => Promise<void> | void,
	opts?: { persistWorkspace?: boolean; persist?: boolean }
): { readonly value: PeriodValue; change: (p: PeriodValue) => void } {
	const lens = {
		get value() {
			return periodFromFilters(filters.values);
		},
		change(p: PeriodValue) {
			filters.values = { ...filters.values, ...periodToFilters(p) };
			void reload();
		},
	};
	if (opts?.persist === false) return lens;
	const persistWorkspace = opts?.persistWorkspace ?? true;
	// The page owns only the keys it persists — admin-audit excludes
	// `workspace_ids` so its portal-plane scope never bleeds into the shared blob.
	const persistKeys: readonly string[] = persistWorkspace
		? AUDIT_PERSIST_KEYS
		: ['days', 'start', 'end'];

	// Persist only this page's keys — `persistAuditFilters` reads from the values
	// object, so blank a non-owned `workspace_ids` before handing it over.
	function persistOwned() {
		persistAuditFilters(persistWorkspace ? filters.values : { ...filters.values, workspace_ids: '' });
	}

	// Seed the remembered lens (period + workspace) ONLY on a bare navigation —
	// a sidebar click or a reload of an unfiltered view, where the URL carries no
	// query at all. A URL that carries ANY query is authoritative: a dashboard
	// deep-link (`?kind=a2a&user_id=…`) or a shared link shows exactly what it
	// names and takes page defaults for whatever it omits, so it can never be
	// silently narrowed by the viewer's remembered workspace (which would strand
	// the link on an empty list whenever that scope holds none of the linked
	// rows — e.g. a remembered Agent-workspace filter over user/LLM traffic). The
	// "a link wins on load" contract, enforced all-or-nothing per visit.
	const urlIsBare = page.url.search === '';
	if (urlIsBare) {
		const saved = loadPersistedAuditFilters();
		const patch: Record<string, string> = {};
		for (const k of ['days', 'start', 'end']) if (saved[k]) patch[k] = saved[k] as string;
		if (persistWorkspace && saved.workspace_ids) patch.workspace_ids = saved.workspace_ids;
		if (Object.keys(patch).length > 0) filters.values = { ...filters.values, ...patch };
	}

	// Write-through: remember the lens whenever it changes. Skip the initial
	// (mount) run on a deep-link so merely FOLLOWING a link never overwrites the
	// remembered lens with the link's default scope — only a bare visit's
	// hydrated values or a later explicit user edit are persisted.
	let skipMountPersist = !urlIsBare;
	$effect(() => {
		for (const k of persistKeys) void filters.values[k];
		if (skipMountPersist) {
			skipMountPersist = false;
			return;
		}
		persistOwned();
	});

	// Drop a hydrated workspace scope that no longer exists (deleted workspace) —
	// mirrors `reconcileWorkspace` for the global lens. Reactive because the
	// workspace list isn't populated yet at component-init time, so we can't
	// validate during hydration; this fires once the list loads.
	//
	// Track the membership SIGNATURE, not the array identity: the tenant layout
	// re-emits `consoleScope.workspaces = newArray` on every navigation, so a
	// reference-keyed effect would re-run — and re-issue its `reload()` — on each
	// nav (and, after `reload()` triggers a `goto`, feed itself). The reconcile's
	// `reload()` runs OUTSIDE `usePeriodicLoad`'s single-flight, so that re-entry
	// is the reload-loop risk. Keying off the signature (`workspacesKey`, the
	// same value-guard `usePeriodicLoad` uses) fires the effect only when the
	// live set actually changes or `workspace_ids` itself changes; an identical
	// re-emit is inert.
	let reconcileMounted = false;
	onMount(() => { reconcileMounted = true; });
	$effect(() => {
		void consoleScope.workspacesKey; // a genuine membership change, not a same-set re-emit
		if (!persistWorkspace) return;
		const csv = filters.values.workspace_ids;
		const wsList = untrack(() => consoleScope.workspaces);
		if (!csv || wsList.length === 0) return;
		const sel = csv.split(',').map((s) => s.trim()).filter(Boolean);
		const live = sel.filter((id) => wsList.some((w) => w.id === id));
		if (live.length === sel.length) return;
		filters.values = { ...filters.values, workspace_ids: live.join(',') };
		if (reconcileMounted) untrack(() => void reload());
	});

	return lens;
}

/**
 * Unsaved-changes guard for form-bearing pages. Tracks a `dirty` flag and
 * registers a `beforeNavigate` hook that prompts the user before navigating
 * away when the form is dirty. Pair with a Modal's `onCloseRequest` to also
 * guard the X / Esc / Cancel paths on modal-hosted forms.
 *
 * Usage:
 *
 *   const form = useDirtyForm();
 *   // <input bind:value={...} oninput={form.markDirty} />
 *   // on save success: form.markClean();
 *
 *   <Modal onCloseRequest={form.confirmDiscard}> ... </Modal>
 *   // Render ONE themed ConfirmDialog bound to the hook state. FormModal
 *   // does this automatically; standalone callers render <ConfirmDialog
 *   //   open={form.confirmOpen}
 *   //   onconfirm={form.acceptDiscard}
 *   //   oncancel={form.rejectDiscard}
 *   //   confirmLabel="Discard" destructive
 *   //   title="Discard changes?" message="You have unsaved edits…"
 *   // /> themselves.
 *
 * `confirmDiscard()` returns a Promise that resolves to true (discard) or
 * false (keep editing). The cross-page `beforeNavigate` hook reuses the
 * same dialog: it cancels the navigation synchronously, then re-issues it
 * once the user confirms — `goto(target)` within the app, a document
 * navigation for one that leaves it.
 */
export function useDirtyForm() {
	let dirty = $state(false);
	let confirmOpen = $state(false);
	let pendingResolver: ((ok: boolean) => void) | null = null;

	function ask(): Promise<boolean> {
		confirmOpen = true;
		return new Promise<boolean>((res) => {
			pendingResolver = res;
		});
	}

	function settle(ok: boolean) {
		confirmOpen = false;
		const r = pendingResolver;
		pendingResolver = null;
		r?.(ok);
	}

	beforeNavigate((nav) => {
		if (!dirty) return;
		const target = nav.to?.url;
		nav.cancel();
		if (!target) return;
		void ask().then((ok) => {
			if (!ok) return;
			dirty = false;
			// `goto` takes only a route of this app; a navigation that leaves
			// it (an external link, a document download) is re-issued as one.
			if (nav.willUnload) window.location.href = target.href;
			else void goto(target);
		});
	});

	return {
		get dirty() {
			return dirty;
		},
		/** True while the themed discard dialog is awaiting user input. */
		get confirmOpen() {
			return confirmOpen;
		},
		markDirty: () => {
			dirty = true;
		},
		markClean: () => {
			dirty = false;
		},
		/** Async discard prompt suitable for Modal.onCloseRequest and Cancel buttons. */
		confirmDiscard: (): Promise<boolean> => (dirty ? ask() : Promise.resolve(true)),
		/** Wire to ConfirmDialog.onconfirm — resolves the pending prompt as "discard". */
		acceptDiscard: () => settle(true),
		/** Wire to ConfirmDialog.oncancel — resolves the pending prompt as "keep editing". */
		rejectDiscard: () => settle(false),
	};
}

/**
 * Reactive `?tab=` reader/writer. Seeds from the URL on first read (using
 * `getTabFromUrl`) and pushes back via `setTabParam` whenever `current` is
 * assigned. Thin wrapper around the existing helpers in `#lib/tabs.js` —
 * callers that just need read-once-and-forget behaviour can keep using
 * `getTabFromUrl` directly.
 *
 * Usage:
 *
 *   const tab = useTabState(['llm', 'mcp'] as const, 'llm');
 *   // <button onclick={() => tab.current = 'mcp'}>MCP</button>
 *   // {#if tab.current === 'llm'} ... {/if}
 */
export function useTabState<T extends string>(validIds: readonly T[], defaultId: T): { current: T } {
	const initial = getTabFromUrl([...validIds] as T[], defaultId);
	const state = $state<{ current: T }>({ current: initial });
	// Track the URL's ?tab= so a cross-tab deep-link (e.g. a card navigating to
	// ?tab=field-profiles) actually switches the tab. A
	// query-only same-route navigation doesn't remount the page, so reading the
	// URL once at init isn't enough. The ONLY tracked dependency must be
	// `page.url`: a user tab-click writes via setTabParam (raw
	// history.replaceState, which does NOT update `page`), so the read/write of
	// state.current here is untracked — otherwise the click would re-fire this
	// effect and snap the tab back to the now-stale URL value.
	$effect(() => {
		const fromUrl = page.url.searchParams.get('tab') as T | null;
		if (!fromUrl || !validIds.includes(fromUrl)) return;
		untrack(() => {
			if (fromUrl !== state.current) state.current = fromUrl;
		});
	});
	return {
		get current() {
			return state.current;
		},
		set current(next: T) {
			if (!validIds.includes(next)) return;
			state.current = next;
			setTabParam(next);
		},
	};
}


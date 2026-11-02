// The signals behind a page reload, shared by `usePeriodicLoad` (which loads),
// <RefreshButton> (which refreshes) and <TrendingValue> (which decides whether
// a change is a trend — see `#lib/trend.js`).

class RefreshCycle {
	/** The refresh sequence: the refresh button, the R key and every
	 *  auto-refresh tick bump it. */
	sequence = $state(0);

	/** Auto-refresh is on and not held by an edit (owned by <RefreshButton>).
	 *  A view with a poll of its own polls only while this is true; otherwise
	 *  it reads on `sequence` like every other loader, so nothing on screen
	 *  moves without the viewer. */
	autoRefreshing = $state(false);

	/** Moves whenever what the page shows changes: period, pinned workspace,
	 *  workspace list, URL. */
	scopeGeneration = $state(0);

	/** The refresh sequence current when every page load in flight (mount,
	 *  scope change or refresh) last finished. A fresh object on every settle,
	 *  so a reader hears a second settle at the same refresh (a scope reload
	 *  after a refresh). */
	loadsSettled = $state.raw<{ refresh: number }>({ refresh: 0 });

	readonly #listeners = new Set<() => void>();

	/** A refresh: moves the sequence, then calls every listener, in order. */
	refresh(): void {
		this.sequence += 1;
		for (const fn of [...this.#listeners]) fn();
	}

	/** Call `fn` on every later refresh, until the returned function is called. */
	listen(fn: () => void): () => void {
		const entry = () => fn();
		this.#listeners.add(entry);
		return () => this.#listeners.delete(entry);
	}

	noteScopeChange(): void {
		this.scopeGeneration += 1;
	}
}

export const refreshCycle = new RefreshCycle();

/** The reload signals `usePeriodicLoad` watches, as comparable values. */
export interface ReloadSignals {
	period: string;
	refresh: number;
	workspace: string | null;
	workspaces: string;
}

/** Why a page reloads: what it shows changed, or the viewer asked again. */
export type ReloadCause = 'scope' | 'refresh';

/**
 * Why the signals moved: `null` for the first reading (the mount load covers
 * it) and for an identical re-emit; `scope` when anything the page shows
 * changed — even alongside a refresh, since a scope change must reset every
 * trend baseline; otherwise `refresh`.
 */
export function reloadCause(prev: ReloadSignals | null, next: ReloadSignals): ReloadCause | null {
	if (prev === null) return null;
	if (prev.period !== next.period || prev.workspace !== next.workspace || prev.workspaces !== next.workspaces) {
		return 'scope';
	}
	return prev.refresh !== next.refresh ? 'refresh' : null;
}

/** A load still running after this long no longer holds the cycle open: a
 *  request that never answers must not stop every later refresh settling.
 *  Well above a slow analytics query, so a long period still settles only
 *  after its own values land. */
export const LOAD_STALE_MS = 120_000;

/**
 * The page loads in flight across every mounted loader. `end` names the
 * settled refresh — the highest refresh sequence any of them began at — once
 * none is left running; a load older than `LOAD_STALE_MS` is not counted.
 */
export class PageLoads {
	private nextId = 0;
	private highest = 0;
	private readonly open = new Map<number, number>();

	begin(refresh: number, now: number): number {
		const id = ++this.nextId;
		this.open.set(id, now);
		this.highest = Math.max(this.highest, refresh);
		return id;
	}

	/** Forget a load without settling — its page is gone. */
	drop(id: number): void {
		this.open.delete(id);
	}

	/** The settled refresh when no load is left running; null otherwise. */
	end(id: number, now: number): number | null {
		this.open.delete(id);
		return this.busy(now) ? null : this.highest;
	}

	busy(now: number): boolean {
		for (const [id, startedAt] of this.open) {
			if (now - startedAt < LOAD_STALE_MS) return true;
			this.open.delete(id);
		}
		return false;
	}
}

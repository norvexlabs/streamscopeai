// Opt-in auto-refresh: once switched on it refreshes every
// `AUTO_REFRESH_INTERVAL_MS` for `AUTO_REFRESH_WINDOW_MS` of VISIBLE time.
// While the tab is hidden nothing is requested and the window does not run
// down; on return the page refreshes once if a tick fell due while it was
// away. While the viewer is editing (`held`) a due tick waits: it lands at the
// first clock tick after the edit ends, never under it.
//
// Pure: every function takes the clock as `now`, so the timing is asserted
// directly (`autoRefresh.test.ts`). <RefreshButton> owns the timers.

export const AUTO_REFRESH_WINDOW_MS = 60 * 60 * 1000;
export const AUTO_REFRESH_INTERVAL_MS = 30 * 1000;

export interface AutoRefresh {
	/** Visible time left in the window, as of `since` (or frozen while hidden). */
	remainingMs: number;
	/** When the visible stretch began, or null while the tab is hidden. */
	since: number | null;
	/** When the page was last refreshed. */
	lastRefreshAt: number;
}

/** Start (or restart) the window; the caller has just refreshed. */
export function startAuto(now: number, visible: boolean): AutoRefresh {
	return { remainingMs: AUTO_REFRESH_WINDOW_MS, since: visible ? now : null, lastRefreshAt: now };
}

export function remainingMs(s: AutoRefresh, now: number): number {
	if (s.since === null) return s.remainingMs;
	return Math.max(0, s.remainingMs - (now - s.since));
}

/** The tab went hidden: freeze the window. */
export function hideAuto(s: AutoRefresh, now: number): AutoRefresh {
	if (s.since === null) return s;
	return { ...s, remainingMs: remainingMs(s, now), since: null };
}

/** The tab is visible again: resume the window, refreshing once if a tick fell
 *  due and nothing holds it. `state: null` when the window had already run
 *  out — no refresh. */
export function showAuto(s: AutoRefresh, now: number, held = false): { state: AutoRefresh | null; refresh: boolean } {
	if (s.since !== null) return { state: s, refresh: false };
	if (s.remainingMs <= 0) return { state: null, refresh: false };
	const refresh = !held && now - s.lastRefreshAt >= AUTO_REFRESH_INTERVAL_MS;
	return { state: { ...s, since: now, lastRefreshAt: refresh ? now : s.lastRefreshAt }, refresh };
}

/**
 * A clock tick. `state: null` means the window ran out — auto-refresh stops.
 * A hidden tab never refreshes; a held one keeps the tick due.
 */
export function tickAuto(s: AutoRefresh, now: number, held = false): { state: AutoRefresh | null; refresh: boolean } {
	if (s.since === null) return { state: s, refresh: false };
	if (remainingMs(s, now) <= 0) return { state: null, refresh: false };
	if (!held && now - s.lastRefreshAt >= AUTO_REFRESH_INTERVAL_MS) {
		return { state: { ...s, lastRefreshAt: now }, refresh: true };
	}
	return { state: s, refresh: false };
}

/** Whole minutes left, rounded up — "42" while 41 min 10 s remain. */
export function minutesLeft(ms: number): number {
	return Math.ceil(ms / 60_000);
}

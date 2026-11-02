// The ↑/↓ chip on a dashboard stat card (<TrendingValue>): what moved since
// the previous refresh, and nothing else.
//
// A card observes its value whenever it changes and reads two global counters
// at that moment (`TrendEpoch`): the refresh sequence (bumped by the refresh
// button, the R key and each auto-refresh tick) and the scope generation
// (bumped by any change of what the page is looking at — period, workspace,
// workspace list, URL). The rules:
//
//  - A chip is shown only for a change that lands during a refresh cycle the
//    card has a same-scope baseline for. The comparison point is the value the
//    card held when that cycle began, so a value that lands in parts during
//    one cycle is still compared with the pre-cycle reading.
//  - A change outside a refresh cycle (mount, a page's own filter, a late
//    load) never shows a chip; it only moves the baseline.
//  - A scope change drops the baseline — a chip never compares two scopes.
//    The new scope's first reading is its baseline; if the value did not
//    change, there is no reading, so the card adopts the value it holds when
//    the page's loads settle.
//  - A missing reading (`undefined`: not loaded yet, failed fetch) resets the
//    baseline; the next reading starts over.
//  - When a refresh cycle settles, a card whose value did not move in it
//    drops its chip: the chip means "moved in the latest refresh".
//
// A cycle is open from the card's first reading in it until it settles, so a
// change a page loads on its own inside that window is counted with the
// refresh — the window is the refresh's own loads plus one render.

export type Trend = 'up' | 'down' | null;

/** The global counters read at the moment a value is observed. */
export interface TrendEpoch {
	refresh: number;
	scope: number;
}

export interface TrendState {
	/** The latest reading, or null when there is no baseline. */
	value: number | null;
	/** The reading the current refresh cycle is compared with. */
	base: number | null;
	/** The refresh cycle this state last took part in. */
	refresh: number;
	/** The scope generation of `value`. */
	scope: number;
	/** The refresh cycle is still open for this card (not yet settled). */
	open: boolean;
	trend: Trend;
}

export function initialTrend(epoch: TrendEpoch): TrendState {
	return { value: null, base: null, refresh: epoch.refresh, scope: epoch.scope, open: false, trend: null };
}

function compare(v: number, base: number | null): Trend {
	if (base === null) return null;
	return v > base ? 'up' : v < base ? 'down' : null;
}

/** A fresh baseline: no chip, no open cycle. */
function rebase(value: number | null, epoch: TrendEpoch): TrendState {
	return { value, base: null, refresh: epoch.refresh, scope: epoch.scope, open: false, trend: null };
}

export function observeTrend(s: TrendState, value: number | undefined, epoch: TrendEpoch): TrendState {
	if (value === undefined || !Number.isFinite(value)) return rebase(null, epoch);
	if (s.value === null || epoch.scope !== s.scope) return rebase(value, epoch);
	if (epoch.refresh > s.refresh) {
		// First reading of a new refresh cycle: compare with the value held
		// when the cycle began.
		return { value, base: s.value, refresh: epoch.refresh, scope: s.scope, open: true, trend: compare(value, s.value) };
	}
	if (s.open) {
		// A further reading inside the same open cycle: still compared with the
		// pre-cycle value.
		return { ...s, value, trend: compare(value, s.base) };
	}
	// Outside any refresh cycle: never a chip.
	return rebase(value, epoch);
}

/** The scope moved: drop the baseline. Whatever lands next — even inside a
 *  refresh cycle begun before the new scope's load finished — is a baseline,
 *  never compared with the previous scope. */
export function rescopeTrend(s: TrendState, epoch: TrendEpoch): TrendState {
	if (epoch.scope === s.scope) return s;
	return rebase(null, epoch);
}

/**
 * The page's loads have settled at refresh `refresh`; `current` is the value
 * the card holds now. A card without a baseline (a scope change whose value did
 * not move, so it saw no reading) adopts `current`.
 */
export function settleTrend(s: TrendState, refresh: number, current?: number): TrendState {
	if (s.value === null) {
		if (current === undefined || !Number.isFinite(current)) return s;
		return rebase(current, { refresh: Math.max(refresh, s.refresh), scope: s.scope });
	}
	if (refresh < s.refresh) return s;
	if (refresh > s.refresh) {
		// The value did not move during this cycle: it is the new baseline and
		// the previous cycle's chip no longer describes the latest refresh.
		return { ...s, base: null, refresh, open: false, trend: null };
	}
	return { ...s, open: false };
}

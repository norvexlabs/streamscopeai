import { describe, expect, it } from 'vitest';
import { initialTrend, observeTrend, rescopeTrend, settleTrend, type TrendEpoch, type TrendState } from '#lib/trend.js';

const at = (refresh: number, scope = 0): TrendEpoch => ({ refresh, scope });

/** Mount at `epoch`, then observe `values` in order at that same epoch. */
function mounted(epoch: TrendEpoch, ...values: (number | undefined)[]): TrendState {
	let s = initialTrend(epoch);
	for (const v of values) s = observeTrend(s, v, epoch);
	return s;
}

describe('trend chip — a refresh cycle', () => {
	it('shows ↑ / ↓ for a change that lands in a refresh cycle — the positive control', () => {
		const base = mounted(at(0), 10);
		expect(observeTrend(base, 12, at(1)).trend).toBe('up');
		expect(observeTrend(base, 8, at(1)).trend).toBe('down');
	});

	it('shows no chip when a refresh reads the same value', () => {
		const base = mounted(at(0), 10);
		expect(observeTrend(base, 10, at(1)).trend).toBeNull();
	});

	it('compares a value landing in parts with the pre-cycle reading', () => {
		// 10 → (refresh) 14 → 9 inside the same open cycle: 9 < 10 → ↓.
		let s = mounted(at(0), 10);
		s = observeTrend(s, 14, at(1));
		expect(s.trend).toBe('up');
		s = observeTrend(s, 9, at(1));
		expect(s.trend).toBe('down');
	});

	it('keeps the chip when the cycle settles after the value moved in it', () => {
		let s = observeTrend(mounted(at(0), 10), 12, at(1));
		s = settleTrend(s, 1);
		expect(s.trend).toBe('up');
	});

	it('drops the chip when a later cycle settles with the value unmoved', () => {
		let s = settleTrend(observeTrend(mounted(at(0), 10), 12, at(1)), 1);
		s = settleTrend(s, 2);
		expect(s.trend).toBeNull();
		// …and the next moving refresh compares with the unmoved reading.
		expect(observeTrend(s, 11, at(3)).trend).toBe('down');
	});

	it('ignores a settle for a cycle older than the card', () => {
		const s = observeTrend(mounted(at(0), 10), 12, at(2));
		expect(settleTrend(s, 1)).toEqual(s);
	});
});

describe('trend chip — every other load only moves the baseline', () => {
	it('shows no chip on the first reading after mount', () => {
		expect(mounted(at(5), 10).trend).toBeNull();
	});

	it('shows no chip for a change outside a refresh cycle (a page filter, a late load)', () => {
		const s = settleTrend(observeTrend(mounted(at(0), 10), 12, at(1)), 1);
		const moved = observeTrend(s, 50, at(1));
		expect(moved.trend).toBeNull();
		expect(moved.value).toBe(50);
	});

	it('never compares two scopes — a scope change inside a refresh cycle resets', () => {
		// A period switch while a refresh is in flight: the new-scope reading
		// is not a movement.
		const s = mounted(at(0, 0), 10);
		const crossed = observeTrend(s, 500, at(1, 1));
		expect(crossed.trend).toBeNull();
		// A further reading in that cycle is not compared with the old scope.
		expect(observeTrend(crossed, 600, at(1, 1)).trend).toBeNull();
		// The next refresh compares within the new scope.
		expect(observeTrend(crossed, 600, at(2, 1)).trend).toBe('up');
	});

	it('an old-scope load landing late does not chip the new scope', () => {
		// Scope moves (gen 1); the old-scope load lands after it, then the
		// new-scope load: neither is a refresh, so neither shows a chip.
		let s = mounted(at(0, 0), 10);
		s = observeTrend(s, 11, at(0, 1)); // late old-scope reading
		s = observeTrend(s, 900, at(0, 1)); // the new scope's own load
		expect(s.trend).toBeNull();
	});

	it('a missing reading (not loaded, failed fetch) resets the baseline', () => {
		let s = observeTrend(mounted(at(0), 10), 12, at(1));
		s = observeTrend(s, undefined, at(2));
		expect(s.trend).toBeNull();
		expect(s.value).toBeNull();
		// The first reading after the gap is a baseline, not a movement.
		expect(observeTrend(s, 3, at(3)).trend).toBeNull();
	});

	it('treats a non-finite reading as missing', () => {
		const s = observeTrend(mounted(at(0), 10), Number.NaN, at(1));
		expect(s.value).toBeNull();
		expect(s.trend).toBeNull();
	});

	it('a scope change that leaves the value unchanged adopts it when loads settle, so the next refresh chips', () => {
		let s = mounted(at(0, 0), 10);
		s = rescopeTrend(s, at(0, 1));
		expect(s.value).toBeNull();
		// The new scope's load returned the same 10: no reading reached the card.
		s = settleTrend(s, 0, 10);
		expect(s.trend).toBeNull();
		expect(observeTrend(s, 12, at(1, 1)).trend).toBe('up');
	});

	it('a refresh begun before the new scope loaded never compares the two scopes', () => {
		// Period switch at 29.5 s; the 30 s tick bumps the refresh while the
		// scope reload is in flight; the new-scope reading lands in that cycle.
		let s = mounted(at(0, 0), 10);
		s = rescopeTrend(s, at(0, 1));
		s = observeTrend(s, 500, at(1, 1));
		expect(s.trend).toBeNull();
		// …and the next tick compares within the new scope.
		expect(observeTrend(settleTrend(s, 1, 500), 520, at(2, 1)).trend).toBe('up');
	});

	it('a scope change clears a chip describing the previous view', () => {
		let s = observeTrend(mounted(at(0, 0), 10), 12, at(1, 0));
		expect(s.trend).toBe('up');
		s = rescopeTrend(s, at(1, 1));
		expect(s.trend).toBeNull();
	});

	it('an unchanged scope is left alone', () => {
		const s = observeTrend(mounted(at(0, 0), 10), 12, at(1, 0));
		expect(rescopeTrend(s, at(1, 0))).toBe(s);
	});

	it('settling without a baseline or a reading stays without one', () => {
		const s = rescopeTrend(mounted(at(0, 0), 10), at(0, 1));
		expect(settleTrend(s, 3, undefined)).toEqual(s);
	});
});

import { describe, expect, it } from 'vitest';
import {
	AUTO_REFRESH_INTERVAL_MS as TICK,
	AUTO_REFRESH_WINDOW_MS as WINDOW,
	hideAuto,
	minutesLeft,
	remainingMs,
	showAuto,
	startAuto,
	tickAuto,
} from '#lib/autoRefresh.js';

const T0 = 1_000_000;

describe('auto-refresh — ticks', () => {
	it('refreshes when a full interval has passed, not one millisecond before', () => {
		const s = startAuto(T0, true);
		expect(tickAuto(s, T0 + TICK - 1).refresh).toBe(false);
		const due = tickAuto(s, T0 + TICK);
		expect(due.refresh).toBe(true);
		expect(due.state?.lastRefreshAt).toBe(T0 + TICK);
	});

	it('stops when the window runs out, and runs until then', () => {
		const s = startAuto(T0, true);
		expect(tickAuto(s, T0 + WINDOW - 1).state).not.toBeNull();
		const end = tickAuto(s, T0 + WINDOW);
		expect(end.state).toBeNull();
		expect(end.refresh).toBe(false);
	});

	it('restarting gives a full window again', () => {
		const later = startAuto(T0 + WINDOW - 5, true);
		expect(remainingMs(later, T0 + WINDOW - 5)).toBe(WINDOW);
	});
});

describe('auto-refresh — a hidden tab', () => {
	it('never refreshes and never runs the window down while hidden', () => {
		let s = startAuto(T0, true);
		s = hideAuto(s, T0 + 10_000);
		const t = tickAuto(s, T0 + 10 * WINDOW);
		expect(t.refresh).toBe(false);
		expect(t.state).not.toBeNull();
		expect(remainingMs(s, T0 + 10 * WINDOW)).toBe(WINDOW - 10_000);
	});

	it('counts only visible time toward the hour', () => {
		let s = startAuto(T0, true);
		s = hideAuto(s, T0 + 20 * 60_000); // 20 min visible
		s = showAuto(s, T0 + 5 * WINDOW).state!; // long away
		expect(remainingMs(s, T0 + 5 * WINDOW)).toBe(40 * 60_000);
	});

	it('refreshes once on return when a tick fell due while away', () => {
		let s = startAuto(T0, true);
		s = hideAuto(s, T0 + 5_000);
		const back = showAuto(s, T0 + TICK);
		expect(back.refresh).toBe(true);
		expect(back.state?.lastRefreshAt).toBe(T0 + TICK);
	});

	it('does not refresh on a quick return before a tick fell due', () => {
		let s = startAuto(T0, true);
		s = hideAuto(s, T0 + 5_000);
		expect(showAuto(s, T0 + TICK - 1).refresh).toBe(false);
	});

	it('a window that ran out while hidden stops on return, without a last refresh', () => {
		// Hidden between the window's end and the clock tick that would stop it.
		let s = startAuto(T0, true);
		s = hideAuto(s, T0 + WINDOW + 2_000);
		const back = showAuto(s, T0 + WINDOW + 60_000);
		expect(back.state).toBeNull();
		expect(back.refresh).toBe(false);
	});

	it('starting in a hidden tab waits for the tab to show', () => {
		const s = startAuto(T0, false);
		expect(tickAuto(s, T0 + 2 * TICK).refresh).toBe(false);
		expect(remainingMs(s, T0 + 2 * TICK)).toBe(WINDOW);
	});
});

describe('auto-refresh — held while editing', () => {
	it('a held tick stays due and lands at the first tick after the hold', () => {
		const s = startAuto(T0, true);
		const held = tickAuto(s, T0 + TICK, true);
		expect(held.refresh).toBe(false);
		expect(held.state?.lastRefreshAt).toBe(T0);
		// Positive control: the same tick, no longer held, refreshes.
		const after = tickAuto(held.state!, T0 + TICK + 5_000, false);
		expect(after.refresh).toBe(true);
		expect(after.state?.lastRefreshAt).toBe(T0 + TICK + 5_000);
	});

	it('a hold never keeps the window from running out', () => {
		const s = startAuto(T0, true);
		expect(tickAuto(s, T0 + WINDOW, true).state).toBeNull();
	});

	it('returning to the tab while held resumes without refreshing, and the tick stays due', () => {
		let s = startAuto(T0, true);
		s = hideAuto(s, T0 + 5_000);
		const back = showAuto(s, T0 + TICK, true);
		expect(back.refresh).toBe(false);
		expect(back.state?.since).toBe(T0 + TICK);
		expect(tickAuto(back.state!, T0 + TICK + 5_000).refresh).toBe(true);
	});
});

describe('minutesLeft', () => {
	it('rounds up to whole minutes', () => {
		expect(minutesLeft(WINDOW)).toBe(60);
		expect(minutesLeft(41 * 60_000 + 10_000)).toBe(42);
		expect(minutesLeft(1)).toBe(1);
		expect(minutesLeft(0)).toBe(0);
	});
});

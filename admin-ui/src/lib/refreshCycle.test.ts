import { describe, expect, it } from 'vitest';
import { LOAD_STALE_MS, PageLoads, reloadCause, type ReloadSignals } from '#lib/refreshCycle.svelte.js';

const base: ReloadSignals = { period: '{"days":7}', refresh: 3, workspace: null, workspaces: 'a,b' };

describe('reloadCause', () => {
	it('is null on the first reading — the mount load covers it', () => {
		expect(reloadCause(null, base)).toBeNull();
	});

	it('is null for an identical re-emit — no duplicate load', () => {
		expect(reloadCause(base, { ...base })).toBeNull();
	});

	it('is refresh when only the refresh sequence moved', () => {
		expect(reloadCause(base, { ...base, refresh: 4 })).toBe('refresh');
	});

	it('is scope for each scope signal', () => {
		expect(reloadCause(base, { ...base, period: '{"days":30}' })).toBe('scope');
		expect(reloadCause(base, { ...base, workspace: 'w1' })).toBe('scope');
		expect(reloadCause(base, { ...base, workspaces: 'a,b,c' })).toBe('scope');
	});

	it('is scope when a scope signal moves together with a refresh', () => {
		expect(reloadCause(base, { ...base, refresh: 4, workspace: 'w1' })).toBe('scope');
	});
});

describe('PageLoads', () => {
	const T = 1_000;

	it('settles only when the last load in flight ends, naming the highest refresh', () => {
		const loads = new PageLoads();
		const a = loads.begin(4, T);
		const b = loads.begin(5, T);
		expect(loads.end(a, T + 1)).toBeNull();
		expect(loads.busy(T + 1)).toBe(true);
		expect(loads.end(b, T + 2)).toBe(5);
		expect(loads.busy(T + 2)).toBe(false);
	});

	it('settles a lone load — the positive control', () => {
		const loads = new PageLoads();
		expect(loads.end(loads.begin(7, T), T + 1)).toBe(7);
	});

	it('is busy again as soon as a later load begins', () => {
		const loads = new PageLoads();
		expect(loads.end(loads.begin(1, T), T)).toBe(1);
		loads.begin(2, T + 1);
		expect(loads.busy(T + 1)).toBe(true);
	});

	it('stops counting a load that never ends — on both sides of the bound', () => {
		const loads = new PageLoads();
		loads.begin(1, T); // hangs forever
		const b = loads.begin(2, T + 5);
		expect(loads.end(b, T + LOAD_STALE_MS - 1)).toBeNull();
		const c = loads.begin(3, T + LOAD_STALE_MS);
		expect(loads.end(c, T + LOAD_STALE_MS)).toBe(3);
	});

	it('a dropped load (its page is gone) no longer holds the cycle', () => {
		const loads = new PageLoads();
		const gone = loads.begin(1, T);
		const b = loads.begin(1, T);
		loads.drop(gone);
		expect(loads.end(b, T + 1)).toBe(1);
	});
});

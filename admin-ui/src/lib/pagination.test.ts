import { afterEach, describe, expect, it, vi } from 'vitest';
import { Pagination } from '#lib/pagination.svelte.js';

// A list pager reads the list's length through `count`; each step below writes
// the offset (state), which is what makes it read the length again.
function listPager(length: { n: number }): Pagination {
	return new Pagination({ limit: 50, list: { count: () => length.n } });
}

afterEach(() => vi.restoreAllMocks());

describe('Pagination over a list held in full', () => {
	it('keeps the page asked for — the positive control', () => {
		const pager = listPager({ n: 1313 });
		pager.offset = 650;
		expect([pager.offset, pager.hasMore, pager.total, pager.page]).toEqual([650, true, 1313, 14]);
	});

	it('clamps a page asked for past the end onto the last page', () => {
		const pager = listPager({ n: 60 });
		pager.offset = 650;
		expect([pager.offset, pager.hasMore]).toEqual([50, false]);
	});

	it('starts at the first page when a filter is typed and when it is cleared', () => {
		// The page resets its pagers on every change of the normalised filter.
		const length = { n: 1313 };
		const pager = listPager(length);
		pager.offset = 650;
		length.n = 120; // a filter typed
		pager.reset();
		expect(pager.offset).toBe(0);
		pager.next();
		expect(pager.offset).toBe(50);
		length.n = 1313; // the filter cleared
		pager.reset();
		expect([pager.offset, pager.total]).toEqual([0, 1313]);
	});

	it('refuses, loudly, a total or an absorb meant for a server-paged list', () => {
		const error = vi.spyOn(console, 'error').mockImplementation(() => {});
		const pager = listPager({ n: 120 });
		pager.total = 5;
		pager.hasMore = false;
		pager.absorbTotal({ items: [], has_more: false, total: 5 });
		expect([pager.total, pager.hasMore]).toEqual([120, true]);
		expect(error).toHaveBeenCalledTimes(3);
	});

	it('still takes them on a server-paged list — the positive control', () => {
		const error = vi.spyOn(console, 'error').mockImplementation(() => {});
		const pager = new Pagination({ limit: 50 });
		pager.absorbTotal({ items: [], has_more: true, total: 5 });
		expect([pager.total, pager.hasMore]).toEqual([5, true]);
		pager.reset();
		expect([pager.total, pager.hasMore, pager.offset]).toEqual([null, false, 0]);
		expect(error).not.toHaveBeenCalled();
	});
});

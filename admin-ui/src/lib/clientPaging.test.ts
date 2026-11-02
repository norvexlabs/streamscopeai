import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { clientPage, pageStartFor } from '#lib/clientPaging.js';

describe('pageStartFor', () => {
	it('puts a row on the page that holds it — both sides of a page boundary', () => {
		expect(pageStartFor(0, 50)).toBe(0);
		expect(pageStartFor(49, 50)).toBe(0);
		expect(pageStartFor(50, 50)).toBe(50);
		expect(pageStartFor(1282, 50)).toBe(1250);
	});
});

describe('clientPage', () => {
	it('says a page follows only while rows remain past this one — both sides of the boundary', () => {
		expect(clientPage(50, 0, 50)).toEqual({ offset: 0, hasMore: false });
		expect(clientPage(51, 0, 50)).toEqual({ offset: 0, hasMore: true });
		expect(clientPage(100, 50, 50)).toEqual({ offset: 50, hasMore: false });
		expect(clientPage(101, 50, 50)).toEqual({ offset: 50, hasMore: true });
	});

	it('lands a list that shrank under its page on its last page, never an empty one', () => {
		expect(clientPage(120, 500, 50)).toEqual({ offset: 100, hasMore: false });
		expect(clientPage(100, 100, 50)).toEqual({ offset: 50, hasMore: false });
		expect(clientPage(101, 100, 50)).toEqual({ offset: 100, hasMore: false });
	});

	it('keeps an offset that is still inside the list — the positive control', () => {
		expect(clientPage(1313, 650, 50)).toEqual({ offset: 650, hasMore: true });
	});

	it('sits an empty list at the first page', () => {
		expect(clientPage(0, 0, 50)).toEqual({ offset: 0, hasMore: false });
		expect(clientPage(0, 150, 50)).toEqual({ offset: 0, hasMore: false });
	});

	it('always shows a non-empty slice of a non-empty list, from a page boundary it was given', () => {
		fc.assert(
			fc.property(
				fc.integer({ min: 1, max: 5000 }),
				fc.integer({ min: 1, max: 200 }),
				fc.integer({ min: 0, max: 100 }),
				(total, limit, page) => {
					const { offset, hasMore } = clientPage(total, page * limit, limit);
					expect(offset % limit).toBe(0);
					expect(offset).toBeGreaterThanOrEqual(0);
					expect(offset).toBeLessThan(total);
					expect(hasMore).toBe(offset + limit < total);
				},
			),
		);
	});
});

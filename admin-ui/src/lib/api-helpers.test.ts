import { describe, expect, it } from 'vitest';
import { fetchAllPages } from '#lib/api-helpers.js';

/** A paged endpoint over `rows`. */
function pager<T>(rows: T[]) {
  return async (offset: number, limit: number) => ({
    data: { items: rows.slice(offset, offset + limit), has_more: offset + limit < rows.length },
  });
}

describe('fetchAllPages', () => {
  it('returns every row across pages', async () => {
    const rows = [1, 2, 3, 4, 5].map((n) => ({ id: `r${n}` }));
    expect(await fetchAllPages(pager(rows), 2)).toEqual(rows);
  });

  it('throws on an error page rather than returning a partial list', async () => {
    const failing = async () => ({ data: null, error: { error: { message: 'boom' } } });
    await expect(fetchAllPages(failing)).rejects.toThrow();
  });
});

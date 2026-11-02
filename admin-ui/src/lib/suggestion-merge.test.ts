import { describe, expect, it } from 'vitest';
import { acceptNewer, mergeSuggestions, type Revisable } from './suggestion-merge';

const row = (id: string, content_hash: string, status = 'pending', title = content_hash): Revisable & { title: string } =>
  ({ id, content_hash, status, title });

describe('mergeSuggestions', () => {
  it('keeps a shown pending row whose content changed, and holds the newer copy beside it', () => {
    const m = mergeSuggestions([row('a', 'h1')], [row('a', 'h2')]);
    expect(m.rows).toEqual([row('a', 'h1')]);
    expect(m.newer).toEqual({ a: row('a', 'h2') });
  });
  it('takes the server copy when the content did not change (positive control)', () => {
    const fetched = row('a', 'h1', 'pending', 'retitled');
    const m = mergeSuggestions([row('a', 'h1')], [fetched]);
    expect(m.rows[0]).toBe(fetched);
    expect(m.newer).toEqual({});
  });
  it('takes a new suggestion as it arrives, in the server order', () => {
    const m = mergeSuggestions([row('a', 'h1')], [row('b', 'x'), row('a', 'h1')]);
    expect(m.rows.map((r) => r.id)).toEqual(['b', 'a']);
  });
  it('takes a row reviewed elsewhere — its status left pending', () => {
    const m = mergeSuggestions([row('a', 'h1')], [row('a', 'h2', 'approved')]);
    expect(m.rows).toEqual([row('a', 'h2', 'approved')]);
    expect(m.newer).toEqual({});
  });
  it('drops a row the server no longer lists', () => {
    expect(mergeSuggestions([row('a', 'h1')], []).rows).toEqual([]);
  });
  it('holds again on the next reload if the admin has still not swapped', () => {
    const first = mergeSuggestions([row('a', 'h1')], [row('a', 'h2')]);
    const second = mergeSuggestions(first.rows, [row('a', 'h3')]);
    expect(second.rows).toEqual([row('a', 'h1')]);
    expect(second.newer).toEqual({ a: row('a', 'h3') });
  });
});

describe('acceptNewer', () => {
  it('swaps in the newer copy and forgets it', () => {
    const m = acceptNewer(mergeSuggestions([row('a', 'h1'), row('b', 'x')], [row('a', 'h2'), row('b', 'x')]), 'a');
    expect(m.rows).toEqual([row('a', 'h2'), row('b', 'x')]);
    expect(m.newer).toEqual({});
  });
  it('changes nothing for a row with no newer copy', () => {
    const m = mergeSuggestions([row('a', 'h1')], [row('a', 'h1')]);
    expect(acceptNewer(m, 'a')).toBe(m);
  });
});

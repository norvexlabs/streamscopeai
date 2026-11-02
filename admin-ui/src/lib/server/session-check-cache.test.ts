import { describe, expect, it } from 'vitest';
import { SessionCheckCache } from './session-check-cache';

function clock(start = 1_000) {
  let t = start;
  return { now: () => t, advance: (ms: number) => (t += ms) };
}

const acme = (name = 'alice') => ({ tenant_slug: 'acme', name });

describe('SessionCheckCache', () => {
  it('answers within the ttl and not at it', () => {
    const c = clock();
    const cache = new SessionCheckCache<ReturnType<typeof acme>>(5_000, 10, c.now);
    cache.remember('tok', 'acme', acme());
    c.advance(4_999);
    expect(cache.reusable('tok', 'acme', true)?.name).toBe('alice');
    c.advance(1);
    expect(cache.reusable('tok', 'acme', true)).toBeUndefined();
    // The expired entry is gone, not merely hidden.
    expect(cache.size).toBe(0);
  });

  it('keys by the token: another token is a miss', () => {
    const cache = new SessionCheckCache<ReturnType<typeof acme>>(5_000, 10);
    cache.remember('tok-a', 'acme', acme());
    expect(cache.reusable('tok-b', 'acme', true)).toBeUndefined();
    expect(cache.reusable('tok-a', 'acme', true)?.name).toBe('alice');
  });

  it('forgets on request', () => {
    const cache = new SessionCheckCache<ReturnType<typeof acme>>(5_000, 10);
    cache.remember('tok', 'acme', acme());
    cache.forget('tok');
    expect(cache.reusable('tok', 'acme', true)).toBeUndefined();
  });

  it('never grows past its bound, dropping the oldest first', () => {
    const cache = new SessionCheckCache<ReturnType<typeof acme>>(60_000, 3);
    for (let i = 0; i < 3; i++) cache.remember(`t${i}`, 'acme', acme(`u${i}`));
    expect(cache.size).toBe(3);
    cache.remember('t3', 'acme', acme('u3'));
    expect(cache.size).toBe(3);
    expect(cache.reusable('t0', 'acme', true)).toBeUndefined();
    expect(cache.reusable('t1', 'acme', true)?.name).toBe('u1');
    expect(cache.reusable('t3', 'acme', true)?.name).toBe('u3');
  });

  it('re-setting a token refreshes its place and its ttl', () => {
    const c = clock();
    const cache = new SessionCheckCache<ReturnType<typeof acme>>(5_000, 2, c.now);
    cache.remember('a', 'acme', acme('a'));
    cache.remember('b', 'acme', acme('b'));
    c.advance(4_000);
    cache.remember('a', 'acme', acme('a')); // a is now the newest
    cache.remember('c', 'acme', acme('c')); // evicts b, the oldest
    expect(cache.reusable('b', 'acme', true)).toBeUndefined();
    c.advance(4_000); // 8s after a's first set, 4s after its refresh
    expect(cache.reusable('a', 'acme', true)?.name).toBe('a');
  });
});

describe('reuse rules', () => {
  it('is reused only on an API proxy path, and only for the slug it confirmed', () => {
    const cache = new SessionCheckCache<{ tenant_slug?: string | null }>(5_000, 10);
    cache.remember('tok', 'acme', { tenant_slug: 'acme' });
    expect(cache.reusable('tok', 'acme', true)).toBeDefined();
    // A page render always asks: nothing re-verifies the token behind it.
    expect(cache.reusable('tok', 'acme', false)).toBeUndefined();
    // Another tenant's URL never borrows this answer.
    expect(cache.reusable('tok', 'other', true)).toBeUndefined();
  });

  it('never remembers an answer that did not confirm the slug', () => {
    const cache = new SessionCheckCache<{ tenant_slug?: string | null }>(5_000, 10);
    for (const answer of [{}, { tenant_slug: null }, { tenant_slug: 'other' }]) {
      cache.remember('tok', 'acme', answer);
      expect(cache.size, JSON.stringify(answer)).toBe(0);
    }
    // Positive control.
    cache.remember('tok', 'acme', { tenant_slug: 'acme' });
    expect(cache.size).toBe(1);
  });
});

describe('shared', () => {
  it('runs one check for concurrent callers of one token', async () => {
    const cache = new SessionCheckCache<{ tenant_slug?: string }>(5_000, 10);
    let calls = 0;
    let release: (v: string) => void = () => {};
    const check = () => {
      calls++;
      return new Promise<string>((r) => (release = r));
    };
    const all = Promise.all([cache.shared('tok', check), cache.shared('tok', check), cache.shared('tok', check)]);
    // Another token is its own check.
    const other = cache.shared('tok-2', () => Promise.resolve('other'));
    release('answer');
    expect(await all).toEqual(['answer', 'answer', 'answer']);
    expect(await other).toBe('other');
    expect(calls).toBe(1);
  });

  it('lets the next caller check again once a check settles, failed or not', async () => {
    const cache = new SessionCheckCache<{ tenant_slug?: string }>(5_000, 10);
    await expect(cache.shared('tok', () => Promise.reject(new Error('down')))).rejects.toThrow('down');
    let calls = 0;
    await cache.shared('tok', async () => calls++);
    await cache.shared('tok', async () => calls++);
    expect(calls).toBe(2);
  });
});

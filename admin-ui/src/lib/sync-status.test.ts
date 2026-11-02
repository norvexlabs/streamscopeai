import { describe, expect, it } from 'vitest';
import { formatAge, formatTimeAgo } from './formatters';
import { syncStatus } from './sync-status';

// A fixed instant so the "… ago" text is stable; only the ok/failed split, the
// delta and the presence of a time are asserted, never its exact wording.
const AT = new Date(Date.now() - 60_000).toISOString();

describe('syncStatus', () => {
  it('is absent only when nothing at all has been recorded', () => {
    expect(syncStatus(null)).toBeNull();
    expect(syncStatus(undefined)).toBeNull();
    expect(syncStatus({})).toBeNull();
    expect(syncStatus({ last_auto_sync_at: null, last_auto_sync_status: null })).toBeNull();
  });

  it('reports a failed run as failed, with the provider reason', () => {
    // The timestamp is stamped by a failed run too, so reading it alone would
    // present this as a healthy sync.
    const s = syncStatus({
      last_auto_sync_at: AT,
      last_auto_sync_status: { ok: false, reason: 'discovery failed: provider returned 401' },
    });
    expect(s?.ok).toBe(false);
    expect(s?.label).toMatch(/^Failed /);
    expect(s?.detail).toContain('provider returned 401');
  });

  it('reports a failure that carries no time', () => {
    // A path that must leave the server due records the reason WITHOUT stamping
    // the attempt. That row must still read as failed.
    const s = syncStatus({ last_auto_sync_status: { ok: false, reason: 'provider returned 401' } });
    expect(s?.ok).toBe(false);
    expect(s?.label).toBe('Failed');
    expect(s?.detail).toBe('Failed — provider returned 401');
    expect(s?.ago).toBeNull();
    expect(s?.age).toBeNull();
  });

  it('times a failure by its OWN `at`, not by the last successful run', () => {
    // `last_auto_sync_at` is the worker's due window, and a sync that must
    // leave the server due cannot move it. Reading the column would date a
    // failure that just happened to the previous SUCCESS — "Failed 3 days ago"
    // sends the operator looking at the wrong day.
    const threeDaysAgo = new Date(Date.now() - 3 * 24 * 60 * 60_000).toISOString();
    const justNow = new Date(Date.now() - 5_000).toISOString();
    const s = syncStatus({
      last_auto_sync_at: threeDaysAgo,
      last_auto_sync_status: { ok: false, reason: 'provider returned 401', at: justNow },
    });
    expect(s?.ok).toBe(false);
    expect(s?.ago).toBe(formatTimeAgo(justNow));
    expect(s?.ago).not.toBe(formatTimeAgo(threeDaysAgo));
    // The card's compact figure reads the SAME instant as the phrase.
    expect(s?.age).toBe(formatAge(justNow));
    expect(s?.age).not.toBe(formatAge(threeDaysAgo));
    // Positive control: with no `at` of its own, the column is what is left.
    const fallback = syncStatus({
      last_auto_sync_at: threeDaysAgo,
      last_auto_sync_status: { ok: false, reason: 'x' },
    });
    expect(fallback?.ago).toBe(formatTimeAgo(threeDaysAgo));
    expect(fallback?.age).toBe(formatAge(threeDaysAgo));
  });

  it('falls back to a bare failure when no reason was recorded', () => {
    const s = syncStatus({ last_auto_sync_at: AT, last_auto_sync_status: { ok: false } });
    expect(s?.ok).toBe(false);
    expect(s?.detail).toBe(s?.label);
  });

  it('reads a RECORDED status that is not an explicit success as a failure', () => {
    // A run that recorded something unreadable is not evidence that it worked.
    for (const status of [{}, { ok: 'true' }, { ok: 1 }, { ok: null }, { reason: 'x' }]) {
      expect(syncStatus({ last_auto_sync_at: AT, last_auto_sync_status: status })?.ok).toBe(false);
    }
  });

  it('does not call a row with no status at all a failure', () => {
    // Nothing was recorded either way — which is not the same claim as "it
    // failed", and colouring it red would cry wolf on every such row.
    for (const status of [null, undefined, 'ok', 42]) {
      const s = syncStatus({ last_auto_sync_at: AT, last_auto_sync_status: status });
      expect(s?.ok).toBe(true);
      expect(s?.label).toMatch(/^Ran /);
      expect(s?.detail).toContain('nothing was recorded');
    }
  });

  it('reports a successful run, with the models it moved', () => {
    const s = syncStatus({
      last_auto_sync_at: AT,
      last_auto_sync_status: { ok: true, added: 3, models_removed: 1 },
    });
    expect(s?.ok).toBe(true);
    expect(s?.label).toContain('(+3 -1)');
  });

  it('omits a delta nothing moved, and each half independently', () => {
    const none = syncStatus({ last_auto_sync_at: AT, last_auto_sync_status: { ok: true, added: 0, models_removed: 0 } });
    expect(none?.label).not.toContain('(');
    const onlyAdded = syncStatus({ last_auto_sync_at: AT, last_auto_sync_status: { ok: true, added: 2 } });
    expect(onlyAdded?.label).toContain('(+2)');
    const onlyRemoved = syncStatus({ last_auto_sync_at: AT, last_auto_sync_status: { ok: true, models_removed: 5 } });
    expect(onlyRemoved?.label).toContain('(-5)');
  });

  it('does not let a non-numeric count reach the label', () => {
    const s = syncStatus({
      last_auto_sync_at: AT,
      last_auto_sync_status: { ok: true, added: 'many', models_removed: null },
    });
    expect(s?.ok).toBe(true);
    expect(s?.label).not.toContain('(');
  });

  it('reports a run whose time does not parse without a time, never as "--"', () => {
    const s = syncStatus({ last_auto_sync_status: { ok: true, at: 'garbage' } });
    expect(s?.label).toBe('Synced');
    expect(s?.ago).toBeNull();
    expect(s?.age).toBeNull();
    // Positive control: a parseable time is reported.
    expect(syncStatus({ last_auto_sync_status: { ok: true, at: AT } })?.ago).not.toBeNull();
  });
});

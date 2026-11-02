import { describe, expect, it } from 'vitest';
import { diffSides, isTruncated, truncatedBytes } from './audit-record';

describe('truncatedBytes', () => {
  it('reads the size of a truncation marker', () => {
    expect(truncatedBytes({ _truncated: true, _bytes: 300000 })).toBe(300000);
  });
  it('is null for a record that holds its content', () => {
    expect(truncatedBytes({ before: { a: 1 }, after: { a: 2 } })).toBeNull();
    expect(truncatedBytes({ _truncated: false, _bytes: 1 })).toBeNull();
    expect(truncatedBytes(null)).toBeNull();
    expect(truncatedBytes([{ _truncated: true }])).toBeNull();
  });
  it('is null for a marker without a size, never a guessed one — still a marker', () => {
    expect(truncatedBytes({ _truncated: true })).toBeNull();
    expect(isTruncated({ _truncated: true })).toBe(true);
    expect(isTruncated({ before: 1 })).toBe(false);
  });
});

describe('diffSides', () => {
  it('reads both sides, null where missing', () => {
    expect(diffSides({ before: { a: 1 }, after: { a: 2 } })).toEqual({ before: { a: 1 }, after: { a: 2 } });
    expect(diffSides({ after: 3 })).toEqual({ before: null, after: 3 });
    expect(diffSides('x')).toEqual({ before: null, after: null });
  });
});

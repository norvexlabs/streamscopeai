import { describe, expect, it } from 'vitest';
import { MIN_SEARCH_CHARS, searchTooShort } from '#lib/browse/search.js';

describe('searchTooShort', () => {
  it('a blank term is no search, never too short', () => {
    expect(searchTooShort(undefined)).toBe(false);
    expect(searchTooShort(null)).toBe(false);
    expect(searchTooShort('')).toBe(false);
    expect(searchTooShort('  \t ')).toBe(false);
  });

  it('refuses below the minimum and accepts at it, once trimmed', () => {
    expect(MIN_SEARCH_CHARS).toBe(3);
    expect(searchTooShort('a')).toBe(true);
    expect(searchTooShort('ab')).toBe(true);
    expect(searchTooShort('  ab  ')).toBe(true);
    expect(searchTooShort('abc')).toBe(false);
    expect(searchTooShort(' abc ')).toBe(false);
  });

  it('counts characters, not UTF-16 units', () => {
    // Two emoji are four UTF-16 units but two characters.
    expect(searchTooShort('😀😀')).toBe(true);
    expect(searchTooShort('😀😀😀')).toBe(false);
  });
});

import { describe, expect, it } from 'vitest';
import { canExpand, EXPAND_LIMIT, listLinkage, MAX_DEPTH, nests, unlisted } from './sessionTree';

describe('listLinkage', () => {
  it('asks for the top level when the viewer chose nothing and no search runs', () => {
    expect(listLinkage(undefined, undefined)).toBe('top_level');
    expect(nests(listLinkage(undefined, undefined))).toBe(true);
  });

  it('lists flat under a search, and never nests it', () => {
    expect(listLinkage(undefined, 'osprey')).toBeUndefined();
    expect(nests(listLinkage(undefined, 'osprey'))).toBe(false);
  });

  it('lists flat under an alert filter, and nests again without one', () => {
    expect(listLinkage(undefined, undefined, 'major')).toBeUndefined();
    expect(listLinkage(undefined, undefined, '')).toBe('top_level');
    expect(listLinkage(undefined, undefined, undefined)).toBe('top_level');
  });

  it('keeps the viewer’s own choice, flat, with or without a search', () => {
    for (const choice of ['has_children', 'has_parent', 'unlinked'] as const) {
      expect(listLinkage(choice, undefined)).toBe(choice);
      expect(listLinkage(choice, 'osprey')).toBe(choice);
      expect(nests(listLinkage(choice, undefined))).toBe(false);
    }
  });
});

describe('canExpand', () => {
  it('offers an expand only on a nested list, for a row with sub-agents, above the depth cap', () => {
    expect(canExpand(true, 0, 2)).toBe(true);
    expect(canExpand(true, MAX_DEPTH - 1, 1)).toBe(true);
    expect(canExpand(true, MAX_DEPTH, 1)).toBe(false);
    expect(canExpand(true, 0, 0)).toBe(false);
    expect(canExpand(true, 0, undefined)).toBe(false);
    expect(canExpand(false, 0, 2)).toBe(false);
  });
});

describe('unlisted', () => {
  it('counts what an expand left out, never below zero', () => {
    expect(unlisted(30, EXPAND_LIMIT)).toBe(30 - EXPAND_LIMIT);
    expect(unlisted(EXPAND_LIMIT, EXPAND_LIMIT)).toBe(0);
    expect(unlisted(EXPAND_LIMIT - 1, EXPAND_LIMIT)).toBe(0);
    expect(unlisted(undefined, 0)).toBe(0);
  });

  it('says nothing is left out when the expand stopped short of its cap', () => {
    // The badge counted a sub-agent whose session is not on record.
    expect(unlisted(3, 2)).toBe(0);
    expect(unlisted(EXPAND_LIMIT + 1, EXPAND_LIMIT - 1)).toBe(0);
  });
});

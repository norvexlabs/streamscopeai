import { describe, expect, it } from 'vitest';
import { isWorkspaceId, oneOf, SESSION_LINKAGE, TOOL_CALL_OUTCOMES } from './filter-values';

describe('oneOf', () => {
  it('keeps a value the API accepts', () => {
    expect(oneOf(SESSION_LINKAGE, 'unlinked')).toBe('unlinked');
  });

  it('drops an unknown, empty or missing value rather than sending it', () => {
    expect(oneOf(SESSION_LINKAGE, 'has_child')).toBeUndefined();
    expect(oneOf(SESSION_LINKAGE, '')).toBeUndefined();
    expect(oneOf(SESSION_LINKAGE, undefined)).toBeUndefined();
  });
});

describe('the filter sets', () => {
  it('list every value the API names, once', () => {
    expect([...SESSION_LINKAGE].sort()).toEqual(['has_children', 'has_parent', 'unlinked']);
    expect([...TOOL_CALL_OUTCOMES].sort()).toEqual(['args_modified', 'blocked', 'ok', 'redacted']);
  });
});

describe('isWorkspaceId', () => {
  it('accepts a UUID in either case and refuses anything else', () => {
    expect(isWorkspaceId('6f1c0a3e-0000-4000-8000-000000000001')).toBe(true);
    expect(isWorkspaceId('6F1C0A3E-0000-4000-8000-000000000001')).toBe(true);
    expect(isWorkspaceId('abc')).toBe(false);
    expect(isWorkspaceId('6f1c0a3e-0000-4000-8000-00000000000')).toBe(false);
  });
});

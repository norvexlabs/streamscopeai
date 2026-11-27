import { describe, expect, it } from 'vitest';
import { observedRuleCounts } from '#lib/toolEnforcement.js';
import type { components } from '#lib/generated/api-types.js';

type ToolRuleListItem = components['schemas']['ToolRuleListItem'];

const rule = (kind: string, enabled?: boolean): ToolRuleListItem =>
  ({ id: kind, phase: 'request', scope: 'tool_calls', risk: 'danger', action: { kind }, enabled }) as unknown as ToolRuleListItem;

describe('observedRuleCounts', () => {
  it('counts the enabled block and rewrite rules only', () => {
    const rules = [
      rule('block'), rule('block', true), rule('block', false),
      rule('replace'), rule('replace', false),
      rule('classify'), rule('substitute'), rule('intercept_only'),
    ];
    expect(observedRuleCounts(rules)).toEqual({ block: 2, rewrite: 1 });
  });

  it('counts nothing in an empty or classify-only set', () => {
    expect(observedRuleCounts([])).toEqual({ block: 0, rewrite: 0 });
    expect(observedRuleCounts([rule('classify')])).toEqual({ block: 0, rewrite: 0 });
  });
});

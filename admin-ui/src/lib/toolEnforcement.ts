// Tool-policy profile modes: what the console offers and what an observing
// profile's rules would do.
import type { components } from '#lib/generated/api-types.js';

type ToolRuleListItem = components['schemas']['ToolRuleListItem'];

/** A tool profile's mode as the console offers it: its own value, or (a
 *  Layered profile) `follow` — no value of its own, the Default's mode. */
export type ToolEnforcementChoice = components['schemas']['ToolEnforcement'] | 'follow';

/** How many enabled rules of a profile's effective set would block and how
 *  many would rewrite — what an observing profile records and an enforcing one
 *  applies. Classify and the web-substitution rules act the same in both modes
 *  and are not counted. */
export function observedRuleCounts(rules: readonly ToolRuleListItem[]): { block: number; rewrite: number } {
  let block = 0;
  let rewrite = 0;
  for (const rule of rules) {
    if (rule.enabled === false) continue;
    if (rule.action.kind === 'block') block += 1;
    else if (rule.action.kind === 'replace') rewrite += 1;
  }
  return { block, rewrite };
}

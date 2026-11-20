// The session list as a tree: which linkage the list asks the API for, and
// when a row offers to expand its sub-agents. Presentation only — which
// sessions a caller sees, which links and alerts they carry, and how many
// sub-agents one expand returns are the API's decisions.

import type { components } from '#lib/generated/api-types.js';

type SessionLinkage = components['schemas']['SessionLinkage'];

/** The most sub-agents one expand lists; past it the row says how many more. */
export const EXPAND_LIMIT = 25;
/** Nesting stops at this depth: a deeper sub-agent opens from its own session
 *  (one parent per child does not exclude a cycle). */
export const MAX_DEPTH = 3;

/** The linkage a list asks for: the viewer's choice when they made one (a flat
 *  list), else the tree's top level — except when the list finds rows rather
 *  than browses them: under a search (whose lookup walks the matching
 *  sessions themselves) or an alert filter, a match inside a sub-agent would
 *  sit behind its parent's badge, and the rows would not add up to the count
 *  that linked there, so both list flat. */
export function listLinkage(
  choice: SessionLinkage | undefined,
  search: string | undefined,
  alertLevel?: string,
): SessionLinkage | undefined {
  if (choice) return choice;
  return search || alertLevel ? undefined : 'top_level';
}

/** Whether a list asked for `linkage` shows its rows as a tree. */
export function nests(linkage: SessionLinkage | undefined): boolean {
  return linkage === 'top_level';
}

/** Whether a row at `depth` (0 = top level) offers to expand its sub-agents. */
export function canExpand(nested: boolean, depth: number, subAgents: number | undefined): boolean {
  return nested && depth < MAX_DEPTH && (subAgents ?? 0) > 0;
}

/** How many of the `counted` sub-agents an expand that listed `listed` left
 *  out: none unless the expand reached its cap — the badge's count also names
 *  a sub-agent whose session is not on record, which no read lists. */
export function unlisted(counted: number | undefined, listed: number): number {
  return listed < EXPAND_LIMIT ? 0 : Math.max(0, (counted ?? 0) - listed);
}

import type { components } from './generated/api-types';

type SessionLinkage = components['schemas']['SessionLinkage'];
type ToolCallOutcome = components['schemas']['ToolCallOutcome'];
type AlertLevel = components['schemas']['AlertLevel'];

/**
 * A filter value read from the URL or a select, narrowed to the set the API
 * accepts. The API refuses an unknown value with a 400, so a stale or hand-typed
 * URL drops the filter here instead of failing the page.
 */
export function oneOf<T extends string>(allowed: readonly T[], value: string | null | undefined): T | undefined {
  return allowed.find((a) => a === value);
}

/** Every member of a generated union, listed once: a member added to the API
 *  and not here fails svelte-check instead of being dropped silently. */
function members<T extends string>(all: Record<T, true>): readonly T[] {
  return Object.keys(all) as T[];
}

export const SESSION_LINKAGE = members<SessionLinkage>({ has_children: true, has_parent: true, unlinked: true });
export const ALERT_LEVELS = members<AlertLevel>({ major: true, minor: true, info: true });
export const TOOL_CALL_OUTCOMES = members<ToolCallOutcome>({ ok: true, blocked: true, not_applied: true, redacted: true, args_modified: true });

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** A workspace id token the API will accept in `workspace_ids`; the API refuses
 *  the whole list for one token that is not. */
export function isWorkspaceId(token: string): boolean {
  return UUID.test(token);
}

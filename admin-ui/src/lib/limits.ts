// Limit fields and the effective-limit stack: the decisions behind every limits
// surface (workspace pool, member default, member exception, portal My limits).
//
// A stored limit column encodes several states in one nullable number, and the
// encoding differs by field. The UI never shows an encoding — it shows the
// state (Inherit / Unlimited / Value) — so the translation lives here, once.

import { m } from './paraglide/messages.js';
import { formatKeyLabel } from './formatters.js';

/** What a limit field says, independent of how it is stored. */
export type LimitState =
  | { kind: 'inherit' }
  | { kind: 'unlimited' }
  | { kind: 'value'; value: number };

/**
 * How a stored field encodes its states.
 * - `exception`: a member exception — null inherits the workspace default,
 *   0 is explicitly unlimited, a positive value is the member's own.
 * - `pool_budget`: a workspace pool budget — null inherits the tenant default
 *   budget, 0 is explicitly unlimited, a positive value is the cap.
 * - `pool_rate`: a workspace pool rate — there is no tenant default rate, so
 *   null (or 0) is unlimited.
 * - `member_default`: the workspace's default member limit — null (or 0) is
 *   "no default", i.e. members are limited only by the pool.
 */
export type LimitEncoding = 'exception' | 'pool_budget' | 'pool_rate' | 'member_default';

export function allowsInherit(enc: LimitEncoding): boolean {
  return enc === 'exception' || enc === 'pool_budget';
}

export function decodeLimit(stored: number | null | undefined, enc: LimitEncoding): LimitState {
  if (stored == null) return allowsInherit(enc) ? { kind: 'inherit' } : { kind: 'unlimited' };
  if (stored <= 0) return { kind: 'unlimited' };
  return { kind: 'value', value: stored };
}

/** The stored encoding of a field. A `value` must be valid ([`isValidLimit`])
 *  — hosts gate Save on it — and an invalid one THROWS rather than encode:
 *  0 on an inheriting field means "unlimited", so quietly writing it for a
 *  half-typed field would lift the member's limit. */
export function encodeLimit(state: LimitState, enc: LimitEncoding): number | null {
  switch (state.kind) {
    case 'inherit':
      return null;
    case 'unlimited':
      return allowsInherit(enc) ? 0 : null;
    case 'value':
      if (!isValidLimit(state)) throw new Error(`invalid limit value: ${state.value}`);
      return state.value;
  }
}

/** Whether a field can be saved: a value must be a positive number. A field
 *  showing "Set a limit" with an empty or zero input is NOT saved as unlimited
 *  or as its previous value — Save stays blocked until it says something. */
export function isValidLimit(state: LimitState): boolean {
  return state.kind !== 'value' || (Number.isFinite(state.value) && state.value > 0);
}

/** The cap that applies (null = unlimited), given what an `inherit` resolves to. */
export function effectiveCap(state: LimitState, inherited: number | null | undefined): number | null {
  switch (state.kind) {
    case 'inherit':
      return inherited != null && inherited > 0 ? inherited : null;
    case 'unlimited':
      return null;
    case 'value':
      // A half-typed field (empty, 0) caps nothing yet.
      return state.value > 0 ? state.value : null;
  }
}

/** Whether an exception field lets the member past the workspace pool's cap
 *  (null = the pool has none). An inherited field is the default's business,
 *  not this exception's, so it never warns; a half-typed value neither. */
export function exceedsPool(state: LimitState, poolCap: number | null | undefined): boolean {
  if (poolCap == null || poolCap <= 0) return false;
  switch (state.kind) {
    case 'inherit':
      return false;
    case 'unlimited':
      return true;
    case 'value':
      return state.value > poolCap;
  }
}

/** How a member exception compares with the workspace default, for the ▲/▼ chip. */
export type Comparison = 'inherits' | 'raised' | 'lowered' | 'same';

export function compareToDefault(exception: LimitState, defaultCap: number | null | undefined): Comparison {
  if (exception.kind === 'inherit') return 'inherits';
  const def = defaultCap != null && defaultCap > 0 ? defaultCap : null;
  const own = exception.kind === 'unlimited' ? null : exception.value;
  if (own === def) return 'same';
  if (own === null) return 'raised';
  if (def === null) return 'lowered';
  return own > def ? 'raised' : 'lowered';
}

/** The four limit fields an exception and a default share. */
const LIMIT_FIELDS = ['requests_per_minute', 'tokens_per_minute', 'daily_budget', 'monthly_budget'] as const;
export type LimitField = (typeof LIMIT_FIELDS)[number];

/** Whether an exception raises and/or lowers ANY field against the workspace
 *  default — the ▲/▼ chips of an exception row (both can hold at once). */
export function exceptionDirections(
  exception: Partial<Record<LimitField, number | null>>,
  defaults: Partial<Record<LimitField, number | null>>,
): { raised: boolean; lowered: boolean } {
  const rel = LIMIT_FIELDS.map((f) => compareToDefault(decodeLimit(exception[f], 'exception'), defaults[f]));
  return { raised: rel.includes('raised'), lowered: rel.includes('lowered') };
}

/** use / cap, or null when there is no cap. */
export function meterRatio(used: number, cap: number | null | undefined): number | null {
  if (cap == null || cap <= 0) return null;
  return Math.max(0, used) / cap;
}

/** The meter's severity — the same bands the budget notifications use. */
export function meterTone(ratio: number | null): 'ok' | 'warning' | 'error' {
  if (ratio == null) return 'ok';
  if (ratio >= 1) return 'error';
  if (ratio >= 0.8) return 'warning';
  return 'ok';
}

/** Which limit refused a request (the typed `bucket` of a 429 / audit row). */
export type LimitBucket = 'organisation' | 'workspace' | 'member' | 'key';

const BUCKETS: readonly LimitBucket[] = ['organisation', 'workspace', 'member', 'key'];

export function asLimitBucket(v: string | null | undefined): LimitBucket | null {
  return BUCKETS.find((b) => b === v) ?? null;
}

/** How a limit bucket is named to its reader — the limits stack and the portal Home. */
export function limitBucketLabel(bucket: LimitBucket, keyName?: string | null, keyPrefix?: string | null): string {
  switch (bucket) {
    case 'organisation': return m.limits_bucket_organisation();
    case 'workspace': return m.limits_bucket_workspace();
    case 'member': return m.limits_bucket_member();
    case 'key': return m.limits_bucket_key({ name: formatKeyLabel(keyName, keyPrefix) });
  }
}

/**
 * Typed helpers for common openapi-fetch patterns.
 * Eliminates `as any` casts for settings access and error extraction.
 */

import { adminApi } from './api-client';
import { settingsPatchBody } from './settings-patch';
import type { components } from './generated/api-types';

/** Wire-shape of the per-tenant settings surface (GET/PATCH /api/v1/admin/settings). */
export type TenantSettings = components['schemas']['TenantSettings'];

/** Read-only block on `GET /api/v1/admin/settings` carrying the effective
 * value for every SYSTEM-defaulted setting after layering tenant override
 * over the SYSTEM default. A `null` field means *neither* layer is set. */
export type InheritedDefaults = components['schemas']['InheritedDefaults'];

/** Full settings response — flattened TenantSettings plus the read-only
 * `inherited` block. */
export type GetSettingsResponse = components['schemas']['GetSettingsResponse'];

/** Pull the inherited-defaults block off a settings response. Returns an
 * empty object when absent so callers can chain `inh.proxy_public_url`. */
export function extractInheritedDefaults(
  data: GetSettingsResponse | undefined | null,
): InheritedDefaults {
  return (data?.inherited ?? {}) as InheritedDefaults;
}

/** Identity accessor for a GET /api/v1/admin/settings response — returns the
 * typed settings object or an empty partial when the payload is absent. Kept
 * as a helper so callers share a single null-safe seam and can branch on
 * named fields (`s.agent_enabled`) instead of string-indexing a Record. */
export function extractSettings(data: TenantSettings | undefined | null): Partial<TenantSettings> {
  return (data ?? {}) as Partial<TenantSettings>;
}

/** Extract error message from an openapi-fetch or HTTP error response.
 *
 * Handles multiple shapes defensively:
 *   - `{ error: { message: "..." } }` — admin-api ApiErrorResponse
 *   - `{ error: "..." }`              — string-valued error
 *   - `{ message: "..." }`            — raw ApiErrorBody
 *   - plain string                    — fallthrough
 */
export function extractError(err: unknown, fallback = 'Unknown error'): string {
  if (typeof err === 'string' && err.trim()) return err;
  if (err && typeof err === 'object') {
    const e = err as { error?: unknown; message?: string };
    if (typeof e.error === 'object' && e.error && 'message' in e.error) {
      const msg = (e.error as { message?: string }).message;
      if (msg) return msg;
    }
    if (typeof e.error === 'string' && e.error.trim()) return e.error;
    if (typeof e.message === 'string' && e.message.trim()) return e.message;
  }
  return fallback;
}

/** Extract the optional `code` discriminator from an admin-api error envelope.
 * Returns null when absent. Used to switch UI behavior on specific error
 * conditions (e.g. `"upstream_unreachable"` offers a force bypass). */
export function extractErrorCode(err: unknown): string | null {
  if (err && typeof err === 'object') {
    const e = err as { error?: unknown };
    if (typeof e.error === 'object' && e.error && 'code' in e.error) {
      const code = (e.error as { code?: unknown }).code;
      if (typeof code === 'string' && code) return code;
    }
  }
  return null;
}

/** The refusals a server or endpoint write offers "Save anyway" for.
 *
 * Both are the reachability check reporting on the upstream rather than on the
 * request: nothing answered, or what answered refused the credential. Both are
 * an operator's to overrule — a provider may refuse the model list to a key
 * that serves chat perfectly well. Stated once, because a surface that offers
 * the override and one that does not disagree about whether the write is even
 * possible. */
const OVERRIDABLE_UPSTREAM_ERRORS = ['upstream_unreachable', 'upstream_credential_rejected'];

export function isOverridableUpstreamError(code: string | null | undefined): boolean {
  return !!code && OVERRIDABLE_UPSTREAM_ERRORS.includes(code);
}

/** Type-safe wrapper for PATCH /api/v1/admin/settings. Accepts a partial
 * TenantSettings so callers can ship only the fields they want to change.
 *
 * On the wire a `null` deletes the tenant's override (the setting falls back to
 * the platform default), so a `null` is sent only for a key named in `clears`.
 * Any other `null` — an emptied number input binds one — is dropped, leaving
 * that setting as it is rather than resetting it behind the operator's back. */
export function updateSettings(
  settings: Partial<TenantSettings>,
  clears: readonly (keyof TenantSettings)[] = [],
) {
  return adminApi.PATCH('/api/v1/admin/settings', {
    body: settingsPatchBody(settings, clears) as TenantSettings,
  });
}


/** Loop an OffsetPage-returning endpoint until has_more is false and return
 * every item. Use when the caller wants the full list (no <Pagination> UI).
 * Designed to wrap `adminApi.GET(...)` directly — the `{ data, error }`
 * shape is handled here so 4xx/5xx from the backend surfaces as a thrown
 * Error in the caller's try/catch rather than being silently turned into
 * an empty array. */
export async function fetchAllPages<T>(
  fetchPage: (offset: number, limit: number) => Promise<{
    data?: { items?: T[] | null; has_more?: boolean | null } | null;
    error?: unknown;
  }>,
  pageSize = 500,
): Promise<T[]> {
  const all: T[] = [];
  let offset = 0;
  while (all.length < 200_000) {
    const { data, error } = await fetchPage(offset, pageSize);
    if (error) throw new Error(extractError(error, 'Failed to fetch page'));
    const items = data?.items ?? [];
    all.push(...items);
    if (!data?.has_more || items.length === 0) break;
    offset += items.length;
  }
  if (all.length >= 200_000) {
    console.warn('fetchAllPages: hit 200k safety cap, results may be truncated');
  }
  return all;
}

type ActionImpact = components['schemas']['ActionImpact'];

/** How many downstream routes a delete left pointing at nothing. */
export function orphanedRoutes(data: { impact?: ActionImpact | null } | undefined | null): number {
  return data?.impact?.orphaned_routes ?? 0;
}

/** How many keys a member removal revoked. */
export function keysRevoked(data: { impact?: ActionImpact | null } | undefined | null): number {
  return data?.impact?.keys_revoked ?? 0;
}

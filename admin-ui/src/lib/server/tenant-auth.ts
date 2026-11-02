/**
 * Public (pre-login) tenant facts the login pages need.
 *
 * Both endpoints are unauthenticated by design — a sign-in page has to know how
 * this tenant signs people in before anyone has signed in — so these go out
 * through the typed client with no credential attached.
 */

import { adminServer } from '#lib/admin-server-client.js';
import { extractErrorCode } from '#lib/api-helpers.js';
import type { components } from '#lib/generated/api-types.js';

export type TenantAuthInfo = components['schemas']['TenantAuthInfoResponse'];
export type SetupStatus = components['schemas']['SetupStatusResponse'];

/**
 * Public auth info for a tenant (never secrets); `'not_found'` when the slug
 * names no active tenant, `'unavailable'` for any other answer — a database
 * restart, a throttle, the API not answering — which a login page must not
 * report as a missing tenant.
 */
export async function getTenantAuthInfo(slug: string): Promise<TenantAuthInfo | 'not_found' | 'unavailable'> {
  try {
    const { data, error, response } = await adminServer.GET('/api/v1/tenants/{slug}/auth-info', {
      params: { path: { slug } },
    });
    if (data) return data;
    // Only the gateway saying the slug names no active tenant is "not found";
    // anything else — an outage, a throttle, a fault — says nothing about the
    // tenant, and the page offers a retry.
    const code = extractErrorCode(error);
    return response.status === 404 && (code === 'tenant_not_found' || code === 'tenant_inactive')
      ? 'not_found'
      : 'unavailable';
  } catch {
    return 'unavailable';
  }
}

/**
 * First-run setup status, plus the sole tenant slug on a single-tenant install.
 *
 * An unreachable API answers "no setup needed": the alternative is bouncing a
 * working deployment into the first-run wizard because one request failed.
 */
export async function getSetupStatus(): Promise<SetupStatus> {
  try {
    const { data } = await adminServer.GET('/api/v1/auth/setup/status');
    return data ?? { needs_setup: false, single_tenant_slug: null };
  } catch {
    return { needs_setup: false, single_tenant_slug: null };
  }
}

/** Whether the deployment has no admin accounts yet. */
export async function checkSetupNeeded(): Promise<boolean> {
  return (await getSetupStatus()).needs_setup;
}

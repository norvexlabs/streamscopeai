import { SYSTEM_TENANT_SLUG } from './oidc-urls';
import { pthref } from './tenant';

/** The fields of the signed-in console account a landing decision reads. */
export interface LandingUser {
  is_super_admin?: boolean;
  tenant_slug?: string | null;
}

/**
 * Whether the account may use the Platform pages: a super-admin of the SYSTEM
 * tenant — the same test the admin API's super-admin guard applies, so the
 * console never sends an account to a page whose every call it would refuse.
 * The Platform pages' guard and the sidebar's Platform links read it.
 */
export function isPlatformOperator(user: LandingUser | null | undefined): boolean {
  return user?.tenant_slug === SYSTEM_TENANT_SLUG && user.is_super_admin === true;
}

/** Whether the /dashboard tree admits the account: the SYSTEM tenant has no workloads. */
export function dashboardAdmits(user: LandingUser | null | undefined): boolean {
  return user?.tenant_slug !== SYSTEM_TENANT_SLUG;
}

/**
 * Where a console account lands, tenant-relative. The one decision every
 * landing redirect reads: a platform operator → the Platform overview; any
 * other SYSTEM account → Keys (its dashboard is not admitted); everyone else →
 * the dashboard. Each target admits the account it is chosen for, so no two
 * guards can send an account back and forth (locked by `home.test.ts`).
 */
export function homePath(user: LandingUser | null | undefined): string {
  if (isPlatformOperator(user)) return '/admin/overview';
  if (!dashboardAdmits(user)) return '/users';
  return '/dashboard';
}

/**
 * Where a portal member lands: the portal Home of the tenant, for everyone —
 * the one target every portal landing redirect reads (the `/` entry, the
 * tenant root, the sign-in page).
 */
export function portalHomePath(slug: string): string {
  return pthref(slug, '/home');
}

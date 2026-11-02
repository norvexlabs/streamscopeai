/**
 * Tenant-scope URL helpers.
 *
 * Authenticated admin and portal routes live under a per-tenant URL prefix so a
 * single browser jar can hold concurrent sessions for several tenants — the
 * `session` / `portal_session` cookies are path-scoped to that prefix and the
 * browser auto-selects the right one by request URL:
 *   admin:  /audit        -> /t/<slug>/audit
 *   portal: /portal/keys  -> /portal/t/<slug>/keys
 *
 * `nav.ts` hrefs and most in-tree links stay tenant-RELATIVE (`/audit`,
 * `/portal/keys`); call `thref` / `pthref` to scope them at render/use time, and
 * `untenant` to strip the prefix back to a relative path for active-nav and
 * breadcrumb matching.
 */

const ADMIN_BASE = '/t';
const PORTAL_BASE = '/portal/t';

function withScope(base: string, slug: string, path: string): string {
  if (!slug) return path;
  if (!path.startsWith('/')) path = '/' + path;
  // Idempotent: don't double-prefix an already-scoped path.
  if (path === `${base}/${slug}` || path.startsWith(`${base}/${slug}/`)) return path;
  return `${base}/${slug}${path}`;
}

/** Scope a tenant-relative admin path. `thref('acme', '/audit')` -> `/t/acme/audit`. */
export function thref(slug: string, path: string): string {
  return withScope(ADMIN_BASE, slug, path);
}

/**
 * Scope a portal path under the tenant prefix. Accepts either a portal-relative
 * path (`/keys`) or a full portal path (`/portal/keys`); both yield
 * `/portal/t/<slug>/keys`.
 */
export function pthref(slug: string, path: string): string {
  if (path.startsWith('/portal/t/')) return path; // already scoped
  if (path.startsWith('/portal/')) path = path.slice('/portal'.length);
  else if (path === '/portal') path = '/';
  return withScope(PORTAL_BASE, slug, path);
}

/**
 * Scope an in-app link for the tenant plane it is rendered in, leaving external
 * URLs, fragments, query-only hrefs, and already-scoped paths untouched. Use
 * this INSIDE shared link-rendering components (cards, panels, rows) so call
 * sites pass plain tenant-relative paths (`/sessions`, `/gateways/mcp`) and get
 * a correct `/t/<slug>/…` or `/portal/t/<slug>/…` href by construction — the
 * same relative-then-scope contract `nav.ts` + the typed API client follow.
 *
 * `pathname` (page.url.pathname) selects admin vs portal base: the portal plane
 * is detected by a leading `/portal`. Idempotent — re-scoping an already-scoped
 * path is a no-op, so callers may pass either relative or absolute hrefs.
 */
export function scopeHref(slug: string, pathname: string, href: string): string;
export function scopeHref(slug: string, pathname: string, href: string | undefined): string | undefined;
export function scopeHref(
  slug: string,
  pathname: string,
  href: string | undefined,
): string | undefined {
  if (!href || !href.startsWith('/')) return href; // external, mailto:, #, query-only, relative
  if (href.startsWith('/t/') || href.startsWith('/portal/t/')) return href; // already scoped
  return pathname.startsWith('/portal') ? pthref(slug, href) : thref(slug, href);
}

/**
 * Strip a `/t/<slug>` or `/portal/t/<slug>` prefix back to the tenant-relative
 * path used by `nav.ts` and breadcrumb matching:
 *   /t/acme/audit         -> /audit
 *   /portal/t/acme/keys   -> /portal/keys
 */
export function untenant(pathname: string): string {
  const admin = pathname.match(/^\/t\/[^/]+(\/.*|$)/);
  if (admin) return admin[1] || '/';
  const portal = pathname.match(/^\/portal\/t\/[^/]+(\/.*|$)/);
  if (portal) {
    // A bare prefix — or one with nothing but a trailing slash — is the portal
    // plane's own root, which `nav.ts` spells `/portal`. Returning `/portal/`
    // would match no nav href, the same way the admin branch returns `/` rather
    // than the empty string.
    const rest = portal[1];
    return rest && rest !== '/' ? '/portal' + rest : '/portal';
  }
  return pathname;
}

/**
 * The API path under a plane's proxy mount — `/t/<slug>/api/…` (console) or
 * `/portal/t/<slug>/api/…` (portal) — as given (still percent-encoded when
 * `pathname` is), or `null` when the path is not under one. The one reading
 * of the mount: the hook decides on it which requests are API calls, and the
 * proxy relays exactly this path.
 */
export function apiPathOf(pathname: string): string | null {
  const m = /^(?:\/portal)?\/t\/[^/]+\/api\/(.*)$/.exec(pathname);
  return m ? m[1] : null;
}

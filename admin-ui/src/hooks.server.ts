import { portalHomePath } from '#lib/home.js';
import { redirect, type RequestEvent } from '@sveltejs/kit';
import { sequence, type Handle } from '@sveltejs/kit/hooks';
import { unauthorizedJson } from '#lib/server/api-errors.js';
import { apiPathOf } from '#lib/tenant.js';
import { paraglideMiddleware } from '#lib/paraglide/server.js';
import { getTextDirection } from '#lib/paraglide/runtime.js';
import { isHeaderAuth } from '#lib/server/auth-mode.js';
import { isCrossOriginRequest } from '#lib/server/cross-origin.js';
import { safeSlug } from '#lib/server/slug.js';
import { adminServer } from '#lib/admin-server-client.js';
import { portalServer } from '#lib/portal-server-client.js';
import { isPresentableSessionToken, sessionVerdict } from '#lib/server/session-verdict.js';
import { SessionCheckCache, type SlugBoundAnswer } from '#lib/server/session-check-cache.js';
import { NETWORK_UNREACHABLE } from '#lib/network-error.js';
import { consoleUser } from '#lib/server/console-user.js';
import { PAGE_BODY_LIMIT, pageBodyVerdict } from '#lib/server/page-body-limit.js';

// Accepted `/auth/me` answers, read ONLY on the `…/api/*` proxy paths: admin-api
// re-verifies the token on the proxied call itself, so a remembered answer
// spares a second round trip without letting a revoked session through. Pages
// always ask. A refusal — at the check or on a proxied call — forgets the entry.
const SESSION_CHECK_TTL_MS = 5_000;
const SESSION_CHECK_MAX_ENTRIES = 2_000;
const adminSessionChecks = new SessionCheckCache<NonNullable<App.Locals['user']>>(
  SESSION_CHECK_TTL_MS,
  SESSION_CHECK_MAX_ENTRIES,
);
const portalSessionChecks = new SessionCheckCache<NonNullable<App.Locals['portal_me']>>(
  SESSION_CHECK_TTL_MS,
  SESSION_CHECK_MAX_ENTRIES,
);

/** Serve a proxied API call; its own 401 forgets any remembered check for the
 *  token. A 403 is an authorization answer about one request, not about the
 *  session, so it keeps the entry — the next call is still verified. */
async function resolveProxiedApiCall<T extends SlugBoundAnswer>(
  cache: SessionCheckCache<T>,
  token: string,
  event: RequestEvent,
  resolve: Parameters<Handle>[0]['resolve'],
): Promise<Response> {
  const response = await resolve(event);
  if (response.status === 401) cache.forget(token);
  return addSecurityHeaders(response);
}

if (isHeaderAuth()) {
  console.warn(
    '[SECURITY] AUTH_MODE=header: trusting X-Auth-Request-User header. ' +
    'admin-api MUST NOT be directly accessible from untrusted networks. ' +
    'Use a reverse proxy (Authelia, Authentik, OAuth2 Proxy) in front.'
  );
}

/** Add security headers to all responses. */
function addSecurityHeaders(response: Response): Response {
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  // Strict-Transport-Security is deliberately NOT set here. It belongs where
  // TLS terminates, because only that layer knows whether the certificate is
  // publicly trusted: `tls_mode: internal` runs a local CA, and an HSTS pin on
  // such a host makes the certificate warning non-bypassable — locking the
  // operator out of their own console. Caddy sets it for every mode but
  // `internal`; the Kubernetes chart sets it on the Ingress.
  return response;
}

/** The tenant slug embedded in an authenticated path, or null. */
function adminSlugOf(path: string): string | null {
  if (!path.startsWith('/t/')) return null;
  return safeSlug(path.split('/')[2]);
}
function portalSlugOf(path: string): string | null {
  if (!path.startsWith('/portal/t/')) return null;
  return safeSlug(path.split('/')[3]);
}

/** First-party OAuth consent surfaces that must observe their query params
 *  before any auth redirect (their +page.server.ts owns the login dance):
 *  the MCP/CLI authorize pages and the CLI device-grant approval page. */
function isOauthConsentPath(path: string): boolean {
  return (
    path.includes('/mcp/authorize') ||
    path.includes('/cli/authorize') ||
    path.includes('/cli/device')
  );
}

/** admin-api's answer to a session check that carried no verdict. */
interface Unanswered {
  status: number;
  error: unknown;
  retryAfter: string | null;
}

/** Thrown to leave a session check's try block once it has no verdict. */
const NO_VERDICT = Symbol('no verdict');

/** Whether an openapi-fetch `error` is admin-api's `{ error: { … } }` envelope. */
function isErrorEnvelope(value: unknown): value is { error: Record<string, unknown> } {
  return (
    typeof value === 'object' &&
    value !== null &&
    'error' in value &&
    typeof (value as { error: unknown }).error === 'object' &&
    (value as { error: unknown }).error !== null
  );
}

/** Text made safe for an HTML attribute or element body. */
function escapeHtml(text: string): string {
  return text
    .replaceAll('&', '&amp;')
    .replaceAll('"', '&quot;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}

/** How a request reads its answer — each kind parses a different shape. */
type AnswerKind = 'api' | 'data' | 'action' | 'page';

/**
 * The API proxy reads admin-api's envelope; SvelteKit's client-side data load
 * (`event.isDataRequest`) reads a JSON body as the page error, so it needs a
 * top-level `message`; an enhanced form action reads an `ActionResult`; anything
 * else is a page.
 */
function answerKind(event: RequestEvent, isApi: boolean): AnswerKind {
  if (isApi) return 'api';
  if (event.isDataRequest) return 'data';
  if (event.request.headers.get('x-sveltekit-action') === 'true') return 'action';
  return 'page';
}

/**
 * The answer to a request whose session check got no verdict (see
 * `session-verdict.ts`): the cookie is kept and the outage reported. When
 * admin-api answered with an error, the caller gets that status, code and
 * `Retry-After` — a throttle stays `rate_limit_exceeded`, a degraded boot stays
 * `migration_failed`. Only when admin-api could not be reached at all is the
 * code `network_unreachable`, the same code the browser's own clients use for a
 * console they cannot reach. A page gets a 503 carrying `link` — the way back
 * to sign-in, or, for a page that must keep its URL, a retry of it.
 */
function sessionCheckUnavailable(
  kind: AnswerKind,
  link: { href: string; label: string },
  answered?: Unanswered,
): Response {
  const message = 'The console cannot reach its API right now — try again shortly.';
  const retry = { 'Retry-After': answered?.retryAfter ?? '5' };
  if (answered && answered.status >= 300 && answered.status < 400) {
    console.error(
      `admin-api answered a session check with a redirect (${answered.status}); ADMIN_API_URL must address admin-api directly`,
    );
  }
  // Only an error status can carry the error body a caller branches on.
  const status =
    answered && answered.status >= 400 && answered.status <= 599 ? answered.status : 503;
  let error: Record<string, unknown> & { message: string; code: string } = {
    message,
    code: answered ? 'internal_error' : NETWORK_UNREACHABLE,
  };
  if (answered && isErrorEnvelope(answered.error)) {
    const upstream = answered.error.error;
    error = {
      ...upstream,
      message: typeof upstream.message === 'string' ? upstream.message : message,
      code: typeof upstream.code === 'string' ? upstream.code : 'internal_error',
    };
  }
  const json = (body: unknown, httpStatus: number) =>
    new Response(JSON.stringify(body), {
      status: httpStatus,
      headers: { ...retry, 'Content-Type': 'application/json' },
    });
  switch (kind) {
    case 'api':
      return json({ error: { type: 'unavailable', ...error } }, status);
    case 'data':
      return json({ message: error.message, code: error.code }, status);
    case 'action':
      // An error ActionResult is served with its status, which the enhanced
      // form reads as the result's status; the error carries it too.
      return json({ type: 'error', error: { message: error.message, code: error.code, status } }, status);
    case 'page': {
      const html =
        '<!doctype html><meta charset="utf-8"><title>Temporarily unavailable</title>' +
        `<p>${message}</p><p><a href="${escapeHtml(link.href)}">${escapeHtml(link.label)}</a></p>`;
      return new Response(html, {
        status: 503,
        headers: { ...retry, 'Content-Type': 'text/html; charset=utf-8' },
      });
    }
  }
}

/** A refusal in the shape the request reads its answer in (`answerKind`): the
 *  API envelope, a page-data load's top-level `message`, an enhanced form
 *  action's error `ActionResult`; a page gets the envelope too. */
function refusal(kind: AnswerKind, status: number, code: string, message: string, type: string): Response {
  const body = kind === 'data'
    ? { message, code }
    : kind === 'action'
      ? { type: 'error', error: { message, code, status } }
      : { error: { code, message, type } };
  return addSecurityHeaders(new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  }));
}

/** The refusal of a body a non-forwarder route must not read, or `null`. */
function pageBodyRefusal(event: RequestEvent): Response | null {
  const { request } = event;
  const verdict = pageBodyVerdict(event.url.pathname, request.body !== null, request.headers.get('content-length'));
  if (verdict === 'ok') return null;
  return refusal(answerKind(event, false), 413, 'payload_too_large',
    `A request body may be at most ${PAGE_BODY_LIMIT} bytes here.`, 'invalid_request');
}

/**
 * The identity a forward-auth proxy asserted, as admin-api's header path reads
 * it. The tenant is the PROXY's `X-Tenant-Slug`, never the URL's: admin-api
 * honours it only where an operator stated that their proxy sets it, while the
 * URL's slug is only what the browser asked for — the landings and sign-in
 * pages put every visitor under `system` before the tenant is known, and SYSTEM
 * holds no users.
 */
function forwardAuthHeaders(request: Request): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const name of ['X-Auth-Request-User', 'X-Auth-Request-Email', 'X-Auth-Request-Groups', 'X-Tenant-Slug']) {
    const value = request.headers.get(name);
    if (value) headers[name] = value;
  }
  return headers;
}

/**
 * A header-mode request whose URL names a tenant other than the one admin-api
 * answered for. The tenant is the gateway's to decide (operator configuration,
 * never the request), so a page navigation follows the answer and keeps the
 * rest of its address. Anything else — an API call, a form action — is
 * refused: serving it would hand one tenant's answer under another tenant's
 * name. `null` when the two agree; a `HEAD` is read as its `GET`.
 */
function followGatewayTenant(
  event: RequestEvent,
  prefix: '/t' | '/portal/t',
  urlSlug: string,
  answeredSlug: string | null | undefined,
  isApi: boolean,
): Response | null {
  if (!answeredSlug || answeredSlug === urlSlug) return null;
  const method = event.request.method;
  // A page-data load follows too: SvelteKit answers a redirect thrown here
  // with one the client follows as a navigation.
  if ((method === 'GET' || method === 'HEAD') && !isApi) {
    const rest = event.url.pathname.slice(`${prefix}/${urlSlug}`.length);
    redirect(303, `${prefix}/${answeredSlug}${rest}${event.url.search}`);
  }
  return refusal(answerKind(event, isApi), 403, 'permission_denied',
    'This address belongs to another organisation than the one you are signed in to.', 'forbidden');
}

/** Resolve the request locale (cookie → Accept-Language → English) into an
 *  async-local context for the duration of the request and stamp the document
 *  `lang`/`dir`. Runs before `authHandle` so server-rendered `m.*()` messages
 *  pick up the right locale. The locale lives in a path-`/` cookie, never the
 *  URL, so the `/t/<slug>` + `/portal/t/<slug>` prefix and the path-scoped
 *  session cookies are untouched. */
const i18nHandle: Handle = ({ event, resolve }) =>
  // No `url` strategy, so the middleware's request carries the inbound URL
  // unchanged: the event keeps its own (read-only) request.
  paraglideMiddleware(event.request, ({ locale }) => {
    return resolve(event, {
      transformPageChunk: ({ html }) =>
        html.replace('%lang%', locale).replace('%dir%', getTextDirection(locale)),
    });
  });

const authHandle: Handle = async ({ event, resolve }) => {
  const path = event.url.pathname;

  // The probes' route answers before any auth mode's branch can redirect it.
  if (path === '/api/live') return addSecurityHeaders(await resolve(event));

  // Before any branch: a cookie (or, in header mode, the proxy's identity
  // headers) would otherwise lend another site's page this browser's session.
  if (isCrossOriginRequest(event.request.method, event.request.headers, event.url.origin)) {
    console.warn(`[SECURITY] refused a cross-origin ${event.request.method} to ${path}`);
    return addSecurityHeaders(new Response(
      JSON.stringify({ error: { code: 'request_refused', message: 'Cross-origin request refused.', type: 'forbidden' } }),
      { status: 403, headers: { 'Content-Type': 'application/json' } },
    ));
  }

  const tooLarge = pageBodyRefusal(event);
  if (tooLarge) return tooLarge;

  if (isHeaderAuth()) {
    // --- Header auth mode: trust reverse proxy headers (Authelia, Authentik) ---

    // Portal plane, `/` included: it is the users' entry.
    if (path === '/' || path.startsWith('/portal')) {
      // The landing + login pages → into the (header-mode default) tenant scope.
      if (path === '/' || path === '/portal/login' || path.startsWith('/portal/login/')) {
        redirect(303, portalHomePath('system'));
      }
      // First-party OAuth consent pages (/portal/t/<slug>/{mcp,cli}/authorize
      // + the /cli/device approval page) observe their query params before
      // any redirect — but in header mode the trusted proxy headers ARE the
      // session, so exchange them for a portal token first (best-effort:
      // without it the page's own login redirect dead-ends on the
      // header-mode login bounce and consent is impossible).
      if (isOauthConsentPath(path)) {
        const slug = portalSlugOf(path);
        if (event.request.headers.get('x-auth-request-email') && slug) {
          let token: string | undefined;
          let answeredSlug: string | undefined;
          try {
            const { data } = await portalServer.GET('/api/v1/portal/auth/header-me', {
              headers: forwardAuthHeaders(event.request),
            });
            token = data?.token;
            answeredSlug = data?.tenant_slug;
          } catch {
            // Page renders its own error/login state.
          }
          // The authorize request lives in the query, so following the
          // gateway's tenant keeps it; a token for another tenant is never
          // stored under this one's name.
          if (token) {
            const isApi = apiPathOf(path) !== null;
            const elsewhere = followGatewayTenant(event, '/portal/t', slug, answeredSlug, isApi);
            if (elsewhere) return elsewhere;
            event.locals.portal_token = token;
          }
        }
        const response = await resolve(event);
        return addSecurityHeaders(response);
      }

      const slug = portalSlugOf(path);
      if (!slug) redirect(303, portalHomePath('system'));

      const portalEmail = event.request.headers.get('x-auth-request-email');
      if (!portalEmail) {
        return new Response('Portal requires X-Auth-Request-Email header', { status: 401 });
      }
      let answeredSlug: string | undefined;
      try {
        const { data, response: res } = await portalServer.GET('/api/v1/portal/auth/header-me', {
          headers: forwardAuthHeaders(event.request),
        });
        if (!data) {
          // An answer that says nothing about the identity (an outage, a
          // throttle, a success with no identity in it) is not an
          // authentication failure.
          if (res.ok || sessionVerdict(res.status) === 'no_verdict') {
            return new Response('Portal authentication service unavailable', { status: 503 });
          }
          return new Response('Portal authentication failed', { status: 401 });
        }
        event.locals.portal_token = data.token;
        answeredSlug = data.tenant_slug;
      } catch {
        return new Response('Portal authentication service unavailable', { status: 503 });
      }
      const elsewhere = followGatewayTenant(
        event, '/portal/t', slug, answeredSlug, apiPathOf(path) !== null,
      );
      if (elsewhere) return elsewhere;

      const response = await resolve(event);
      return addSecurityHeaders(response);
    }

    // Admin plane. The landings + login land in the default tenant scope.
    if (path === '/admin' || path === '/system' || path === '/login' || path.startsWith('/login/')) {
      redirect(303, '/t/system/');
    }
    const slug = adminSlugOf(path);
    if (!slug) {
      // Old top-level admin bookmark in header mode — bounce into the scope.
      redirect(303, '/t/system/');
    }

    if (!event.request.headers.get('x-auth-request-user')) {
      return new Response('Authentication required', { status: 401 });
    }
    try {
      const { data, response: res } = await adminServer.GET('/api/v1/auth/me', {
        headers: forwardAuthHeaders(event.request),
      });
      if (data) {
        const { user, token } = consoleUser(data);
        // Without this, a deployment pinned to a tenant other than `system`
        // serves every page under a slug that does not match the token, and
        // the API proxy's claim that `locals` were validated for this slug is
        // simply untrue.
        const elsewhere = followGatewayTenant(
          event, '/t', slug, user.tenant_slug, apiPathOf(path) !== null,
        );
        if (elsewhere) return elsewhere;
        event.locals.user = user;
        event.locals.token = token;
      } else if (res.ok || sessionVerdict(res.status) === 'no_verdict') {
        // An outage, a throttle or a success with no identity in it says
        // nothing about the identity.
        return new Response('Authentication service unavailable', { status: 503 });
      } else {
        return new Response('Authentication failed', { status: 401 });
      }
    } catch (e) {
      // A redirect is thrown, so it arrives here looking like a failure. Let it
      // through before reporting the service unreachable, or the tenant
      // correction above turns into a 503.
      if (e instanceof Response || (e && typeof e === 'object' && 'status' in e)) throw e;
      return new Response('Authentication service unavailable', { status: 503 });
    }

    const response = await resolve(event);
    return addSecurityHeaders(response);
  }

  // --- Standard mode: per-tenant auth (internal/OIDC, configured in DB) ---

  // Public routes — no auth required.
  if (
    path === '/login' || path.startsWith('/login/') ||
    path.startsWith('/auth/oidc/') ||
    path.startsWith('/invite/') ||
    path === '/setup' ||
    path === '/portal/login' || path.startsWith('/portal/login/')
  ) {
    const response = await resolve(event);
    return addSecurityHeaders(response);
  }

  // Landing routes own their own redirect (their loaders read the cross-path
  // *_tenant hint cookie). The path-scoped session cookies are not sent here.
  if (path === '/' || path === '/admin' || path === '/system' || path === '/api/health') {
    const response = await resolve(event);
    return addSecurityHeaders(response);
  }

  // --- Portal plane: /portal/t/<slug>/* uses the path-scoped portal_session ---
  if (path.startsWith('/portal/t/')) {
    // The first-party OAuth consent pages (/portal/t/<slug>/mcp/authorize for
    // MCP clients, /portal/t/<slug>/cli/authorize for `ssai login`,
    // /portal/t/<slug>/cli/device for the device-grant approval page) must
    // observe their query parameters before any redirect to login, so on
    // missing/invalid auth we let the page render — its +page.server.ts
    // handles the login redirect preserving the return URL. When a valid
    // cookie IS present we still populate locals so it skips login. They live
    // under the tenant prefix so the path-scoped portal_session cookie
    // reaches them after auth.
    const isOauthConsent = isOauthConsentPath(path);
    const slug = portalSlugOf(path);
    const isPortalApi = !!slug && apiPathOf(path) !== null;

    const failRedirect = () => {
      if (isOauthConsent) return null;
      if (isPortalApi) return unauthorizedJson();
      return redirect(303, slug ? `/portal/login/${slug}` : '/portal/login');
    };

    let portalToken = event.cookies.get('portal_session');
    if (portalToken && !isPresentableSessionToken(portalToken)) {
      // Could never validate — and cannot even be sent as a header.
      if (slug) event.cookies.delete('portal_session', { path: `/portal/t/${slug}` });
      portalToken = undefined;
    }
    if (!portalToken) {
      if (isOauthConsent) {
        const response = await resolve(event);
        return addSecurityHeaders(response);
      }
      const f = failRedirect();
      if (f instanceof Response) return f;
      throw f;
    }

    if (slug && path === `/portal/t/${slug}/logout`) portalSessionChecks.forget(portalToken);
    const rememberedPortal = slug ? portalSessionChecks.reusable(portalToken, slug, isPortalApi) : undefined;
    if (rememberedPortal) {
      event.locals.portal_me = rememberedPortal;
      event.locals.portal_token = portalToken;
      return resolveProxiedApiCall(portalSessionChecks, portalToken, event, resolve);
    }

    // No verdict on the session. Signing out still goes ahead: it clears this
    // browser's cookies whatever the API can be told.
    const portalNoVerdict = async (answered?: Unanswered) => {
      if (slug && path === `/portal/t/${slug}/logout`) {
        event.locals.portal_token = portalToken;
        return addSecurityHeaders(await resolve(event));
      }
      // A consent page must keep its URL — the authorize request lives in it —
      // so it is offered a retry of itself rather than a sign-in that drops it.
      // Rendering it signed-out instead would tell the user their tenant or
      // session is gone.
      const link = isOauthConsent
        ? { href: `${event.url.pathname}${event.url.search}`, label: 'Try again' }
        : {
            href: slug ? `/portal/login/${encodeURIComponent(slug)}` : '/portal/login',
            label: 'Sign in again',
          };
      return sessionCheckUnavailable(answerKind(event, isPortalApi), link, answered);
    };

    // Set when the check got no verdict: admin-api's answer, or null when it
    // could not be reached. Handled after the try, so nothing the logout action
    // throws is mistaken for a failed check.
    let portalUnanswered: Unanswered | null | undefined;
    try {
      const { data, error, response: res } = await portalSessionChecks.shared(portalToken, () =>
        portalServer.GET('/api/v1/portal/auth/me', {
          headers: { Authorization: `Bearer ${portalToken}` },
        }),
      );
      if (sessionVerdict(res.status) === 'no_verdict') {
        portalUnanswered = { status: res.status, error, retryAfter: res.headers.get('retry-after') };
        throw NO_VERDICT;
      }
      if (!res.ok || !data) {
        portalSessionChecks.forget(portalToken);
        if (slug) event.cookies.delete('portal_session', { path: `/portal/t/${slug}` });
        if (isOauthConsent) {
          const response = await resolve(event);
          return addSecurityHeaders(response);
        }
        const f = failRedirect();
        if (f instanceof Response) return f;
        throw f;
      }
      // The validated token's tenant must be the one the URL names. The browser
      // only sends the path-scoped cookie, so these agree in normal operation —
      // but if they ever diverge, every read below is scoped to the TOKEN's
      // tenant while the page claims the URL's, which shows one tenant's data
      // under another's name. Refuse instead. (The admin plane has always done
      // this; the portal plane had not.)
      if (data.tenant_slug && data.tenant_slug !== slug) {
        portalSessionChecks.forget(portalToken);
        if (slug) event.cookies.delete('portal_session', { path: `/portal/t/${slug}` });
        if (isOauthConsent) {
          const response = await resolve(event);
          return addSecurityHeaders(response);
        }
        const f = failRedirect();
        if (f instanceof Response) return f;
        throw f;
      }
      // Identity for the tenant layout: this call already fetched it, so the
      // layout must not repeat it.
      event.locals.portal_me = data;
      if (slug && path !== `/portal/t/${slug}/logout`) portalSessionChecks.remember(portalToken, slug, data);
    } catch (e) {
      if (e instanceof Response || (e && typeof e === 'object' && 'status' in e)) throw e;
      // Otherwise a transport failure: no verdict on the session either.
      if (e !== NO_VERDICT) portalUnanswered = null;
    }
    if (portalUnanswered !== undefined) return portalNoVerdict(portalUnanswered ?? undefined);

    event.locals.portal_token = portalToken;
    if (isPortalApi) return resolveProxiedApiCall(portalSessionChecks, portalToken, event, resolve);
    const response = await resolve(event);
    return addSecurityHeaders(response);
  }

  // --- Admin plane: /t/<slug>/* uses the path-scoped session cookie ---
  if (path.startsWith('/t/')) {
    const slug = adminSlugOf(path);
    if (!slug) redirect(303, '/login');
    const isAdminApi = apiPathOf(path) !== null;

    const token = event.cookies.get('session');
    if (!token || !isPresentableSessionToken(token)) {
      // A malformed cookie could never validate — and cannot even be sent as a header.
      if (token) event.cookies.delete('session', { path: `/t/${slug}` });
      if (isAdminApi) return unauthorizedJson();
      redirect(303, `/login/${slug}`);
    }

    const isLogout = path === `/t/${slug}/logout`;
    if (isLogout) adminSessionChecks.forget(token);
    const rememberedAdmin = adminSessionChecks.reusable(token, slug, isAdminApi);
    if (rememberedAdmin) {
      event.locals.user = rememberedAdmin;
      event.locals.token = token;
      return resolveProxiedApiCall(adminSessionChecks, token, event, resolve);
    }

    // No verdict on the session. Signing out still goes ahead: it clears this
    // browser's cookies whatever the API can be told.
    const noVerdict = async (answered?: Unanswered) => {
      if (isLogout) {
        event.locals.token = token;
        return addSecurityHeaders(await resolve(event));
      }
      return sessionCheckUnavailable(
        answerKind(event, isAdminApi),
        { href: `/login/${encodeURIComponent(slug)}`, label: 'Sign in again' },
        answered,
      );
    };

    // Set when the check got no verdict — see the portal branch.
    let unanswered: Unanswered | null | undefined;
    try {
      const { data: user, error, response: res } = await adminSessionChecks.shared(token, () =>
        adminServer.GET('/api/v1/auth/me', {
          headers: { Authorization: `Bearer ${token}` },
        }),
      );
      if (sessionVerdict(res.status) === 'no_verdict') {
        unanswered = { status: res.status, error, retryAfter: res.headers.get('retry-after') };
        throw NO_VERDICT;
      }
      if (!res.ok || !user) {
        adminSessionChecks.forget(token);
        event.cookies.delete('session', { path: `/t/${slug}` });
        if (isAdminApi) return unauthorizedJson();
        redirect(303, `/login/${slug}`);
      }
      // Defensive: the validated token's tenant must match the URL slug. The
      // browser only sends the path-scoped cookie, but refuse rather than serve
      // a mismatched/half-authed UI if they ever desync.
      if (user.tenant_slug && user.tenant_slug !== slug) {
        adminSessionChecks.forget(token);
        event.cookies.delete('session', { path: `/t/${slug}` });
        if (isAdminApi) return unauthorizedJson();
        redirect(303, `/login/${slug}`);
      }
      const kept = consoleUser(user).user;
      event.locals.user = kept;
      event.locals.token = token;
      if (!isLogout) adminSessionChecks.remember(token, slug, kept);
    } catch (e) {
      if (e instanceof Response || (e && typeof e === 'object' && 'status' in e)) throw e;
      // Otherwise a transport failure: no verdict on the session either.
      if (e !== NO_VERDICT) unanswered = null;
    }
    if (unanswered !== undefined) return noVerdict(unanswered ?? undefined);

    if (isAdminApi) return resolveProxiedApiCall(adminSessionChecks, token, event, resolve);
    const response = await resolve(event);
    return addSecurityHeaders(response);
  }

  // Anything else — old top-level admin/portal bookmarks (`/audit`, `/tools`, …)
  // and genuinely unknown paths — falls through to SvelteKit's 404. Clean break:
  // pre-prefix URLs are gone, not redirected.
  const response = await resolve(event);
  return addSecurityHeaders(response);
};

// i18n locale context must be established before auth runs `resolve`, so the
// locale handle is first in the sequence.
export const handle: Handle = sequence(i18nHandle, authHandle);

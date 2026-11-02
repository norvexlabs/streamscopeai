import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { pthref, scopeHref, thref, untenant } from '#lib/tenant.js';

/**
 * The tenant scopers are canonicalisers over a path, and the path decides
 * whether the browser sends a session cookie: `session` / `portal_session` are
 * path-scoped to `/t/<slug>` and `/portal/t/<slug>`, so a link that escapes the
 * prefix is not a cosmetic bug but a 401.
 *
 * The `lint-tenant-prefix.sh` lint is the other half of the guard and cannot see the
 * half that matters — a path held in a variable or passed as a component prop
 * is scoped downstream by `scopeHref`, which a regex cannot follow. So the
 * claims below are the only thing holding `scopeHref` itself.
 *
 * Claims asserted as PROPERTIES (from the module's own doc comments):
 *  - scoping is idempotent — re-scoping an already-scoped path is a no-op;
 *  - a scoped path always starts with its plane's base;
 *  - `untenant` inverts the scoper for both planes;
 *  - `scopeHref` passes through anything that is not an in-app absolute path.
 *
 * The inversion is claimed only over paths that do not THEMSELVES begin with a
 * plane prefix — see `appPath` below for why that is the module's real claim
 * rather than a convenience. Deliberately NOT claimed: that `untenant` recovers
 * the slug. It exists to strip the prefix for nav matching, nothing more.
 */

/** Slugs as the router produces them: non-empty, no `/`. */
const slug = () => fc.stringMatching(/^[a-z0-9][a-z0-9-]{0,30}$/);

/**
 * In-app absolute paths, including the awkward bare `/`.
 *
 * `t` and `portal` are excluded as a FIRST segment, and that exclusion is the
 * claim rather than a convenience: both scopers treat a path already beginning
 * with their own base as already-scoped and return it untouched, which is the
 * idempotence the tests above rely on. So `/portal/keys` is not a
 * portal-relative path that gets scoped — it is the full portal spelling, which
 * `pthref` strips. Feeding either through the inversion properties would assert
 * a round-trip the module never promised, and fast-check would eventually find
 * it.
 */
const RESERVED_FIRST_SEGMENT = new Set(['t', 'portal']);
const segment = () => fc.stringMatching(/^[a-z0-9][a-z0-9._-]{0,20}$/);
const appPath = () =>
	fc.oneof(
		fc.constant('/'),
		fc
			.array(segment(), { minLength: 1, maxLength: 4 })
			.filter((segs) => !RESERVED_FIRST_SEGMENT.has(segs[0]))
			.map((segs) => '/' + segs.join('/')),
	);

describe('thref', () => {
	it('is idempotent', () => {
		fc.assert(
			fc.property(slug(), appPath(), (s, p) => {
				const once = thref(s, p);
				expect(thref(s, once)).toBe(once);
			}),
		);
	});

	it('always lands under the admin base', () => {
		fc.assert(
			fc.property(slug(), appPath(), (s, p) => {
				expect(thref(s, p).startsWith(`/t/${s}`)).toBe(true);
			}),
		);
	});

	it('leaves the path alone when there is no slug — the pre-login case', () => {
		expect(thref('', '/audit')).toBe('/audit');
	});

	it('scopes a relative path by anchoring it first', () => {
		expect(thref('acme', 'audit')).toBe('/t/acme/audit');
	});

	it('does not treat a slug prefix as an already-scoped path', () => {
		// `/t/acme-corp/...` must not satisfy the `/t/acme` idempotence check.
		expect(thref('acme', '/t/acme-corp/audit')).toBe('/t/acme/t/acme-corp/audit');
	});
});

describe('pthref', () => {
	it('is idempotent', () => {
		fc.assert(
			fc.property(slug(), appPath(), (s, p) => {
				const once = pthref(s, p);
				expect(pthref(s, once)).toBe(once);
			}),
		);
	});

	it('accepts both the portal-relative and the full portal spelling', () => {
		expect(pthref('acme', '/keys')).toBe('/portal/t/acme/keys');
		expect(pthref('acme', '/portal/keys')).toBe('/portal/t/acme/keys');
	});

	it('maps the portal root under the prefix, symmetrically with the admin plane', () => {
		// Both planes spell their root as the prefix plus a trailing slash, and
		// SvelteKit normalises that away on navigation. What matters is that the
		// root lands INSIDE the prefix — outside it the session cookie is not sent.
		expect(pthref('acme', '/portal')).toBe('/portal/t/acme/');
		expect(thref('acme', '/')).toBe('/t/acme/');
		expect(untenant(pthref('acme', '/portal'))).toBe('/portal');
	});
});

describe('untenant', () => {
	it('inverts the admin scoper', () => {
		fc.assert(
			fc.property(slug(), appPath(), (s, p) => {
				expect(untenant(thref(s, p))).toBe(p);
			}),
		);
	});

	it('inverts the portal scoper', () => {
		fc.assert(
			fc.property(slug(), appPath(), (s, p) => {
				const portalRelative = p === '/' ? '/portal' : `/portal${p}`;
				expect(untenant(pthref(s, p))).toBe(portalRelative);
			}),
		);
	});

	it('passes an unscoped path through unchanged', () => {
		expect(untenant('/audit')).toBe('/audit');
		expect(untenant('/portal/keys')).toBe('/portal/keys');
	});

	it('strips a bare prefix to the root of its plane', () => {
		expect(untenant('/t/acme')).toBe('/');
		expect(untenant('/portal/t/acme')).toBe('/portal');
	});
});

describe('scopeHref', () => {
	it('picks the plane from the current pathname', () => {
		expect(scopeHref('acme', '/t/acme/dashboard', '/sessions')).toBe('/t/acme/sessions');
		expect(scopeHref('acme', '/portal/t/acme/keys', '/sessions')).toBe(
			'/portal/t/acme/sessions',
		);
	});

	it('is idempotent on both planes', () => {
		fc.assert(
			fc.property(slug(), appPath(), fc.boolean(), (s, p, portal) => {
				const pathname = portal ? `/portal/t/${s}/x` : `/t/${s}/x`;
				const once = scopeHref(s, pathname, p);
				expect(scopeHref(s, pathname, once)).toBe(once);
			}),
		);
	});

	it('never rewrites an href that is not an in-app absolute path', () => {
		// The passthrough set the doc comment names: external, fragment,
		// query-only, protocol-relative, and the blob:/data: URLs the audit
		// media viewer builds. Rewriting any of these would break the link.
		const untouched = [
			'https://example.com/x',
			'mailto:ops@example.com',
			'#section',
			'?tab=keys',
			'blob:https://example.com/abcd',
			'data:image/png;base64,AAAA',
			'relative/path',
		];
		for (const href of untouched) {
			expect(scopeHref('acme', '/t/acme/audit', href)).toBe(href);
		}
	});

	it('passes an absent href straight through so a caller can spread it', () => {
		expect(scopeHref('acme', '/t/acme/audit', undefined)).toBeUndefined();
	});

	it('leaves a path already scoped to ANOTHER tenant alone', () => {
		// Cross-tenant links are rare but legitimate (super-admin drill-down),
		// and re-scoping one would silently retarget it at the current tenant.
		expect(scopeHref('acme', '/t/acme/audit', '/t/globex/audit')).toBe('/t/globex/audit');
	});
});

import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { adminNav, breadcrumbFor, buildPortalNav, filterNavForViewer } from '#lib/nav.js';

const UUID = 'e380e405-a1cb-40ac-9959-a2ff5ae15e89';

const labels = (path: string) => breadcrumbFor(adminNav, path).map((c) => c.label);

describe('breadcrumbFor', () => {
  it('names a leaf with its cluster', () => {
    expect(labels('/experts')).toEqual(['Governance', 'Experts']);
  });

  it('names a subtree child under its parent, and the index leaf once', () => {
    expect(labels('/dashboard/llm')).toEqual(['Observability', 'Dashboard', 'LLM']);
    expect(labels('/dashboard')).toEqual(['Observability', 'Dashboard']);
  });

  it('names a drill-down by its page, never by the row id', () => {
    expect(labels(`/experts/profiles/${UUID}`)).toEqual(['Governance', 'Experts', 'Profiles']);
    expect(labels(`/gateways/llm/servers/${UUID}`)).toEqual([
      'Configuration', 'Gateways', 'LLM', 'Servers',
    ]);
  });

  it('calls a row-only tail "Details"', () => {
    expect(labels(`/sessions/${UUID}`)).toEqual(['Observability', 'Sessions', 'Details']);
    expect(labels(`/dashboard/servers/${UUID}`)).toEqual([
      'Observability', 'Dashboard', 'Servers', 'Details',
    ]);
  });

  it('links the drill-down crumb to the page itself', () => {
    const crumbs = breadcrumbFor(adminNav, `/experts/profiles/${UUID}`);
    expect(crumbs[crumbs.length - 1].href).toBe(`/experts/profiles/${UUID}`);
    expect(crumbs[1].href).toBe('/experts');
  });

  it('does not take a sibling sharing a prefix for an ancestor', () => {
    // `/admin-audit` starts with `/admin` but is not under it.
    expect(labels('/admin-audit')).toEqual(['Configuration', 'Audit']);
  });

  it('takes a route parameter for a row, a slug included', () => {
    expect(
      breadcrumbFor(adminNav, '/admin/tenants/acme-corp', '/admin/tenants/[detail]').map((c) => c.label),
    ).toEqual(['Platform', 'Tenants', 'Details']);
    // Positive control: a static segment of the same route still names the page.
    expect(
      breadcrumbFor(adminNav, `/experts/profiles/${UUID}`, '/experts/profiles/[id]').map((c) => c.label),
    ).toEqual(['Governance', 'Experts', 'Profiles']);
  });

  it('aligns a route past its groups, and falls back to the id check for a rest parameter', () => {
    expect(
      breadcrumbFor(adminNav, '/admin/tenants/acme-corp', '/(console)/admin/tenants/[detail]').map((c) => c.label),
    ).toEqual(['Platform', 'Tenants', 'Details']);
    expect(
      breadcrumbFor(adminNav, `/sessions/${UUID}`, '/sessions/[...rest]').map((c) => c.label),
    ).toEqual(['Observability', 'Sessions', 'Details']);
  });

  it('labels an unknown route from its path', () => {
    expect(labels('/nowhere/at_all')).toEqual(['At all']);
    expect(labels(`/nowhere/${UUID}`)).toEqual(['Nowhere']);
  });

  it('keys every crumb uniquely and never shows an id, for any drill-down', () => {
    const hrefs = adminNav.flatMap((c) =>
      c.items.flatMap((i) => [i.href, ...(i.kind === 'subtree' ? i.children.map((ch) => ch.href) : [])]),
    );
    const segment = fc.oneof(
      fc.uuid(),
      fc.nat().map(String),
      fc.stringMatching(/^[a-z][a-z_-]{0,11}$/),
    );
    fc.assert(
      fc.property(fc.constantFrom(...hrefs), fc.array(segment, { maxLength: 3 }), (base, tail) => {
        const path = [base, ...tail].join('/');
        const crumbs = breadcrumbFor(adminNav, path);
        const keys = crumbs.map((c) => c.href);
        expect(new Set(keys).size).toBe(keys.length);
        for (const c of crumbs) {
          expect(c.label).not.toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-/i);
          expect(c.label).not.toMatch(/^\d+$/);
        }
      }),
    );
  });
});

describe('portal nav', () => {
	const hrefs = (isManager: boolean) =>
		filterNavForViewer(buildPortalNav(), { isSystemTenant: false, isSuperAdmin: false, isManager })
			.flatMap((c) => c.items)
			.map((i) => i.href);

	it('shows the team page to a manager of the header workspace only', () => {
		expect(hrefs(true)).toContain('/portal/team');
		expect(hrefs(false)).not.toContain('/portal/team');
	});

	it('opens on Home and keeps every other page for a member', () => {
		const member = hrefs(false);
		expect(member[0]).toBe('/portal/home');
		expect(member).toEqual(hrefs(true).filter((h) => h !== '/portal/team'));
	});

	it('gives each page its own icon', () => {
		const icons = buildPortalNav().flatMap((c) => c.items).map((i) => i.icon);
		expect(new Set(icons).size).toBe(icons.length);
	});
});

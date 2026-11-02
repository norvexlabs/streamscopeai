import { describe, expect, it } from 'vitest';
import { dashboardAdmits, homePath, isPlatformOperator, portalHomePath, type LandingUser } from './home';

describe('isPlatformOperator', () => {
  it('needs both the SYSTEM tenant and the super-admin grant', () => {
    expect(isPlatformOperator({ tenant_slug: 'system', is_super_admin: true })).toBe(true);
    expect(isPlatformOperator({ tenant_slug: 'system', is_super_admin: false })).toBe(false);
    expect(isPlatformOperator({ tenant_slug: 'system' })).toBe(false);
    expect(isPlatformOperator({ tenant_slug: 'acme', is_super_admin: true })).toBe(false);
    expect(isPlatformOperator(null)).toBe(false);
    expect(isPlatformOperator(undefined)).toBe(false);
  });
});

describe('homePath', () => {
  it('sends each kind of account to a page it can use', () => {
    expect(homePath({ tenant_slug: 'system', is_super_admin: true })).toBe('/admin/overview');
    expect(homePath({ tenant_slug: 'system', is_super_admin: false })).toBe('/users');
    expect(homePath({ tenant_slug: 'acme', is_super_admin: true })).toBe('/dashboard');
    expect(homePath({ tenant_slug: 'acme' })).toBe('/dashboard');
    expect(homePath(undefined)).toBe('/dashboard');
  });

  it('never lands an account on a tree whose guard sends it elsewhere', () => {
    // The guards that redirect are the Platform pages' and the dashboard's; Keys has none.
    const admits: Record<string, (u: LandingUser) => boolean> = {
      '/admin/overview': isPlatformOperator,
      '/dashboard': dashboardAdmits,
      '/users': () => true,
    };
    for (const tenant_slug of ['system', 'acme', undefined]) {
      for (const is_super_admin of [true, false, undefined]) {
        const user = { tenant_slug, is_super_admin };
        const home = homePath(user);
        expect(admits[home], home).toBeDefined();
        expect(admits[home](user), `${home} for ${JSON.stringify(user)}`).toBe(true);
      }
    }
  });
});

describe('portalHomePath', () => {
  it('lands every portal member on the Home of their tenant, under the portal prefix', () => {
    expect(portalHomePath('acme')).toBe('/portal/t/acme/home');
    expect(portalHomePath('system')).toBe('/portal/t/system/home');
  });
});

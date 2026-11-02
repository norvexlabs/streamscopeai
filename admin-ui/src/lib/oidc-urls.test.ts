import { describe, expect, it } from 'vitest';
import {
  loginPath,
  oidcRedirectUri,
  oidcRegistration,
  postLogoutRedirectUri,
  switchAccountLoginPath,
} from './oidc-urls';

describe('oidc registration URLs', () => {
  it('builds the single callback on the origin', () => {
    expect(oidcRedirectUri('https://ui.example.com')).toBe('https://ui.example.com/auth/oidc/callback');
  });

  it('never doubles a slash when the origin carries a trailing one', () => {
    expect(oidcRedirectUri('https://ui.example.com/')).toBe('https://ui.example.com/auth/oidc/callback');
    expect(postLogoutRedirectUri('https://ui.example.com//', 'admin', 'acme')).toBe(
      'https://ui.example.com/login/acme',
    );
  });

  it('sends each plane back to its own login page', () => {
    expect(loginPath('admin', 'acme')).toBe('/login/acme');
    expect(loginPath('portal', 'acme')).toBe('/portal/login/acme');
    expect(postLogoutRedirectUri('https://ui.example.com', 'portal', 'acme')).toBe(
      'https://ui.example.com/portal/login/acme',
    );
  });

  // The provider ended its own session, so the URI it is asked to return to
  // carries no prompt; only the local-only sign-out asks for the chooser.
  it('asks for the account chooser only when the provider session survives', () => {
    expect(postLogoutRedirectUri('https://ui.example.com', 'admin', 'acme')).not.toContain('prompt');
    expect(switchAccountLoginPath('admin', 'acme')).toBe('/login/acme?prompt=select_account');
    expect(switchAccountLoginPath('portal', 'acme')).toBe('/portal/login/acme?prompt=select_account');
  });

  it('shows exactly the values the handlers send', () => {
    const origin = 'https://ui.example.com';
    expect(oidcRegistration(origin, 'acme')).toEqual({
      redirectUri: oidcRedirectUri(origin),
      adminPostLogoutUri: postLogoutRedirectUri(origin, 'admin', 'acme'),
      portalPostLogoutUri: postLogoutRedirectUri(origin, 'portal', 'acme'),
    });
  });

  it('offers the SYSTEM tenant no portal URI — it has no portal', () => {
    const reg = oidcRegistration('https://ui.example.com', 'system');
    expect(reg.portalPostLogoutUri).toBeNull();
    expect(reg.adminPostLogoutUri).toBe('https://ui.example.com/login/system');
    expect(reg.redirectUri).toBe('https://ui.example.com/auth/oidc/callback');
  });
});

import { describe, expect, it } from 'vitest';
import {
  classifyBeginRefusal,
  classifyCallbackRefusal,
  forcesAccountChooser,
  parseLoginFailure,
} from './oidc-login-errors';

// The codes below are the ones the gateway's refusals actually carry:
// `ApiError::forbidden` defaults to `permission_denied`, `bad_request` to
// `validation_failed`; an account bound to another identity is
// `oidc_identity_conflict`.
describe('classifyCallbackRefusal', () => {
  it('names the address-claim failures', () => {
    expect(classifyCallbackRefusal('oidc_email_claim_missing')).toBe('email_missing');
    expect(classifyCallbackRefusal('oidc_email_not_verified')).toBe('email_unverified');
  });

  it('reads a provisioning refusal as a decision about this identity', () => {
    expect(classifyCallbackRefusal('permission_denied')).toBe('access_denied');
    expect(classifyCallbackRefusal('oidc_identity_conflict')).toBe('access_denied');
    expect(classifyCallbackRefusal('domain_not_allowed')).toBe('access_denied');
  });

  it('reads an outage — the database or the identity provider not answering — as temporary', () => {
    expect(classifyCallbackRefusal('maintenance_in_progress')).toBe('unavailable');
    expect(classifyCallbackRefusal('oidc_provider_unreachable')).toBe('unavailable');
  });

  it('treats everything else, including no answer at all, as a failed sign-in', () => {
    expect(classifyCallbackRefusal('oidc_exchange_failed')).toBe('sign_in_failed');
    expect(classifyCallbackRefusal('validation_failed')).toBe('sign_in_failed');
    expect(classifyCallbackRefusal('auth_mode_mismatch')).toBe('sign_in_failed');
    expect(classifyCallbackRefusal('internal_error')).toBe('sign_in_failed');
    expect(classifyCallbackRefusal(null)).toBe('sign_in_failed');
    expect(classifyCallbackRefusal(undefined)).toBe('sign_in_failed');
  });
});

describe('classifyBeginRefusal', () => {
  it('reads the gateway saying its database could not be asked as temporary', () => {
    expect(classifyBeginRefusal('maintenance_in_progress', 503)).toBe('unavailable');
  });

  it('reads an identity provider that could not be reached as temporary, never as not set up', () => {
    expect(classifyBeginRefusal('oidc_provider_unreachable', 503)).toBe('unavailable');
    expect(classifyBeginRefusal('oidc_exchange_failed', 500)).toBe('not_configured');
  });

  it('reads a deployment missing a secret as not set up, though it answers 503', () => {
    expect(classifyBeginRefusal('server_misconfigured', 503)).toBe('not_configured');
  });

  it('reads a proxy answering for an unreachable gateway as temporary', () => {
    expect(classifyBeginRefusal(null, 502)).toBe('unavailable');
    expect(classifyBeginRefusal(null, 503)).toBe('unavailable');
    expect(classifyBeginRefusal(null, 504)).toBe('unavailable');
  });

  it('reads every other refusal as the tenant not being set up', () => {
    expect(classifyBeginRefusal('tenant_not_found', 404)).toBe('not_configured');
    expect(classifyBeginRefusal('permission_denied', 403)).toBe('not_configured');
    expect(classifyBeginRefusal('internal_error', 500)).toBe('not_configured');
    expect(classifyBeginRefusal(null, 500)).toBe('not_configured');
    expect(classifyBeginRefusal(null, 501)).toBe('not_configured');
    expect(classifyBeginRefusal(undefined, 404)).toBe('not_configured');
  });
});

describe('parseLoginFailure', () => {
  it('round-trips every class', () => {
    for (const f of ['access_denied', 'email_missing', 'email_unverified', 'idp_refused', 'sign_in_failed'] as const) {
      expect(parseLoginFailure(f)).toBe(f);
    }
  });

  it('ignores anything outside the vocabulary', () => {
    expect(parseLoginFailure(null)).toBeNull();
    expect(parseLoginFailure('')).toBeNull();
    expect(parseLoginFailure('<script>')).toBeNull();
    expect(parseLoginFailure('ACCESS_DENIED')).toBeNull();
  });
});

describe('forcesAccountChooser', () => {
  it('asks for the chooser only when another account could pass', () => {
    expect(forcesAccountChooser('access_denied')).toBe(true);
    for (const f of ['email_missing', 'email_unverified', 'idp_refused', 'sign_in_failed'] as const) {
      expect(forcesAccountChooser(f)).toBe(false);
    }
    expect(forcesAccountChooser(null)).toBe(false);
  });
});

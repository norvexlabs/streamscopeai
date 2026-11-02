/**
 * Why an OIDC sign-in did not complete, as the login page names it.
 *
 * A closed vocabulary, because it rides a URL (`?error=`) that anyone can
 * write: the login page renders a fixed sentence per value and ignores
 * anything else, so the query string can never put text on the page.
 *
 * The classes are distinct because they call for different actions. Only
 * `access_denied` means "this identity is valid but has no access here" — the
 * one case where switching account can help, and so the only one that asks the
 * provider for its account chooser. The others are the provider's or the
 * tenant's configuration, and a chooser would just repeat them (or, at a
 * provider that cannot show one, turn a clear message into a provider error).
 */

export type LoginFailure =
  | 'access_denied'
  | 'email_missing'
  | 'email_unverified'
  | 'idp_refused'
  | 'sign_in_failed'
  | 'unavailable';

const LOGIN_FAILURES: readonly LoginFailure[] = [
  'access_denied',
  'email_missing',
  'email_unverified',
  'idp_refused',
  'sign_in_failed',
  'unavailable',
];

/**
 * Classify the gateway's refusal of a callback by its machine code — never the
 * message or the status. `permission_denied` (no console group, a disabled
 * account), `domain_not_allowed` and `oidc_identity_conflict` (the account is bound
 * to another identity) are decisions about THIS identity, which a different
 * account may pass. A tenant-configuration refusal carries its own code
 * (`auth_mode_mismatch`, `oidc_exchange_failed`, `validation_failed`) and is a
 * failed sign-in, which no account switch fixes. An outage — the gateway's
 * database (`maintenance_in_progress`) or the identity provider
 * (`oidc_provider_unreachable`) not answering — is temporary: try again.
 */
export function classifyCallbackRefusal(code: string | null | undefined): LoginFailure {
  switch (code) {
    case 'oidc_email_claim_missing':
      return 'email_missing';
    case 'oidc_email_not_verified':
      return 'email_unverified';
    case 'permission_denied':
    case 'oidc_identity_conflict':
    case 'domain_not_allowed':
      return 'access_denied';
    case 'maintenance_in_progress':
    case 'oidc_provider_unreachable':
      return 'unavailable';
    default:
      return 'sign_in_failed';
  }
}

/**
 * Why the gateway would not START a login. Temporary — worth retrying — when
 * the gateway says its database or the identity provider could not be asked
 * (`maintenance_in_progress`, `oidc_provider_unreachable`) or when a proxy answered for an unreachable gateway: its 502/503/504 carries
 * no API code (a request that got no response at all is the caller's to treat
 * as unavailable). Every
 * other refusal — no OIDC config, a suspended tenant, an unknown one — is the
 * tenant's configuration.
 */
export function classifyBeginRefusal(
  code: string | null | undefined,
  status: number,
): 'unavailable' | 'not_configured' {
  if (code === 'maintenance_in_progress' || code === 'oidc_provider_unreachable') return 'unavailable';
  // A deployment missing a secret answers 503 too, but no retry fixes it.
  if (code === 'server_misconfigured') return 'not_configured';
  if (status === 502 || status === 503 || status === 504) return 'unavailable';
  return 'not_configured';
}

/** Read the login page's `?error=` back into the vocabulary; anything else is no error. */
export function parseLoginFailure(raw: string | null | undefined): LoginFailure | null {
  return LOGIN_FAILURES.find((f) => f === raw) ?? null;
}

/** Whether the next sign-in should ask the provider for its account chooser. */
export function forcesAccountChooser(failure: LoginFailure | null): boolean {
  return failure === 'access_denied';
}

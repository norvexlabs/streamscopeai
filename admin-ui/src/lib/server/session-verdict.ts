/**
 * What a session check's answer says about the session.
 *
 * A client error is about THIS session (bad token, account or tenant gone), so
 * it ends the session and sends the user to sign in. A throttle, a timeout, a
 * server error or no answer at all says nothing about it: the cookie stays and
 * the request is told the service is unavailable. Ending the session on those
 * would sign every user out for the length of an upgrade.
 */
export type SessionVerdict = 'accepted' | 'refused' | 'no_verdict';

export function sessionVerdict(status: number): SessionVerdict {
  if (status >= 200 && status < 300) return 'accepted';
  if (status === 408 || status === 429) return 'no_verdict';
  if (status >= 400 && status < 500) return 'refused';
  return 'no_verdict';
}

/**
 * Whether a session cookie can be presented at all. A session token is a JWT —
 * base64url segments joined by dots — so anything else is refused outright:
 * it could never validate, and a value that is not a legal header byte string
 * would make the check itself throw, which would read as "no verdict" forever.
 */
export function isPresentableSessionToken(token: string): boolean {
  return token.length > 0 && token.length <= 8192 && /^[A-Za-z0-9_\-.]+$/.test(token);
}

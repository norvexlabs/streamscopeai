import { createHash } from 'node:crypto';

/** An accepted `/auth/me` answer, as far as reuse needs to read it. */
export interface SlugBoundAnswer {
  tenant_slug?: string | null;
}

/**
 * A short-lived memory of accepted session checks, keyed by a hash of the
 * session token (the token itself is never held).
 *
 * **Reused ONLY where admin-api re-verifies the same token on the same
 * request** — the `/t/<slug>/api/*` and `/portal/t/<slug>/api/*` proxies
 * (`reusable` takes the path kind and refuses anything else).
 * There an entry only spares the second `/auth/me` round trip: a revoked or
 * expired session is still refused by the proxied call itself. A page render
 * has no such second check, so it must always ask.
 *
 * Only an ACCEPTED answer that confirmed the URL's tenant slug is stored
 * (`remember`); a refusal, a check without a verdict, or an answer
 * that could not name its tenant never is. An entry lives `ttlMs`, the oldest
 * goes first once `maxEntries` is reached, and concurrent checks of one token
 * share one call (`shared`) — a dashboard refresh fires its API
 * calls together, after any earlier entry has expired.
 */
export class SessionCheckCache<T extends SlugBoundAnswer> {
  private readonly entries = new Map<string, { value: T; expires: number }>();
  private readonly inflight = new Map<string, Promise<unknown>>();

  constructor(
    private readonly ttlMs: number,
    private readonly maxEntries: number,
    private readonly now: () => number = Date.now,
  ) {}

  /** The remembered answer for `token`, when this request may reuse one. */
  reusable(token: string, slug: string, isApiProxyPath: boolean): T | undefined {
    if (!isApiProxyPath) return undefined;
    const hit = this.get(token);
    return hit && hit.tenant_slug === slug ? hit : undefined;
  }

  /** Remember an accepted answer, if it confirmed `slug`. */
  remember(token: string, slug: string, answer: T): void {
    if (answer.tenant_slug === slug) this.set(token, answer);
  }

  /** Run `check` for `token`, or join the one already running for it. */
  shared<R>(token: string, check: () => Promise<R>): Promise<R> {
    const key = keyOf(token);
    const running = this.inflight.get(key);
    if (running) return running as Promise<R>;
    const p = check().finally(() => this.inflight.delete(key));
    this.inflight.set(key, p);
    return p;
  }

  private get(token: string): T | undefined {
    const key = keyOf(token);
    const hit = this.entries.get(key);
    if (!hit) return undefined;
    if (this.now() >= hit.expires) {
      this.entries.delete(key);
      return undefined;
    }
    return hit.value;
  }

  private set(token: string, value: T): void {
    const key = keyOf(token);
    this.entries.delete(key);
    while (this.entries.size >= this.maxEntries) {
      const oldest = this.entries.keys().next();
      if (oldest.done) break;
      this.entries.delete(oldest.value);
    }
    this.entries.set(key, { value, expires: this.now() + this.ttlMs });
  }

  /** Drop the entry — the session was refused, or signed out. */
  forget(token: string): void {
    this.entries.delete(keyOf(token));
  }

  get size(): number {
    return this.entries.size;
  }
}

function keyOf(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

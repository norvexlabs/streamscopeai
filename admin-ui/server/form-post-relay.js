/**
 * The OIDC `response_mode=form_post` landing.
 *
 * A provider using form_post (OAuth 2.0 Form Post Response Mode) answers with a
 * cross-site `POST` of `code`/`state` to the redirect URI. SvelteKit refuses
 * every cross-origin form POST before any hook runs, and its only allowance is a
 * BUILD-time origin list — while the provider is chosen per tenant at runtime.
 * So this runs in front of SvelteKit and converts the POST into a `303` GET to
 * the SAME callback with the same parameters: the callback then runs exactly as
 * it does for `response_mode=query`, and the Lax `oidc_state` cookie — withheld
 * from the cross-site POST — rides the top-level GET, which Lax allows.
 *
 * Invariants to keep when changing this: it forwards ONLY the parameters the
 * callback reads (anything else a provider posts stays behind), it never sets a
 * cookie or reads one, and it trusts nothing it relays — the callback still
 * checks `state` against the sealed flow, exactly as for a query-mode return.
 */

export const CALLBACK_PATH = '/auth/oidc/callback';

/** A form_post body is a code and a state — kilobytes at most. */
export const MAX_FORM_BYTES = 16 * 1024;

/** The parameters the callback reads, and so the only ones carried over. */
const RELAYED = ['code', 'state', 'error'];

/**
 * Whether this request is a provider's form_post return.
 * @param {{ method?: string, url?: string, headers: Record<string, string | string[] | undefined> }} req
 */
export function isFormPostCallback(req) {
  if (req.method !== 'POST') return false;
  const path = (req.url ?? '').split('?', 1)[0];
  const type = String(req.headers['content-type'] ?? '').toLowerCase();
  return path === CALLBACK_PATH && type.startsWith('application/x-www-form-urlencoded');
}

/**
 * Where the browser goes next: the GET callback carrying the relayed parameters.
 * @param {string} body the urlencoded form body
 */
export function relayLocation(body) {
  const form = new URLSearchParams(body);
  const out = new URLSearchParams();
  for (const name of RELAYED) {
    const value = form.get(name);
    if (value !== null) out.set(name, value);
  }
  return `${CALLBACK_PATH}?${out}`;
}

/**
 * Read the form (bounded) and answer with the redirect.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 */
export function relayFormPost(req, res) {
  let size = 0;
  /** @type {Buffer[]} */
  const chunks = [];
  let refused = false;
  req.on('data', (chunk) => {
    if (refused) return;
    size += chunk.length;
    if (size > MAX_FORM_BYTES) {
      refused = true;
      // Drop the connection only once the refusal has been flushed, or the
      // client sees a reset instead of the answer.
      res.on('finish', () => req.destroy());
      res.writeHead(413, { 'Content-Type': 'text/plain; charset=utf-8', Connection: 'close' });
      res.end('Sign-in response too large');
      return;
    }
    chunks.push(chunk);
  });
  req.on('end', () => {
    if (refused) return;
    res.writeHead(303, {
      Location: relayLocation(Buffer.concat(chunks).toString('utf8')),
      'Cache-Control': 'no-store',
      // The code now sits in a URL; keep it out of any onward Referer.
      'Referrer-Policy': 'no-referrer',
    });
    res.end();
  });
  req.on('error', () => {
    if (res.writableEnded) return;
    if (!res.headersSent) res.writeHead(400);
    res.end();
  });
}

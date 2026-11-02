/**
 * The UI's process entrypoint: SvelteKit's request handler behind a server that
 * first takes the one request SvelteKit cannot — a provider's OIDC form_post
 * return (see `form-post-relay.js`). Everything else goes to SvelteKit as-is.
 *
 * It replaces the adapter's `build/index.js` because SvelteKit offers no
 * per-route exemption from its origin check (it runs before any hook), so the
 * relay must sit in front of the handler. Invariant when upgrading
 * `@sveltejs/adapter-node`: re-read its `files/index.js` and carry over any
 * server behaviour a deploy shape relies on — this file does not inherit it.
 *
 * It also gives the handler the deployment's origin, which the adapter reads
 * from no runtime setting — see `origin.js`.
 *
 * Mirrors the adapter's own `build/index.js` for what the deployment relies on:
 * `HOST`/`PORT`, the optional `KEEP_ALIVE_TIMEOUT`/`HEADERS_TIMEOUT` (seconds),
 * and a graceful shutdown on SIGTERM/SIGINT bounded by `SHUTDOWN_TIMEOUT`
 * (seconds, default 30) that emits `sveltekit:shutdown`. Socket activation and
 * `SOCKET_PATH` are not supported — no deploy shape uses them.
 *
 * Every line the process logs through `console`, and an uncaught exception,
 * is a timestamped JSON line — see `log.js`. The modules imported above it
 * log nothing when they load.
 */

import http from 'node:http';
import { isFormPostCallback, relayFormPost } from './form-post-relay.js';
import { HOST_HEADER, PROTOCOL_HEADER, parseOrigin, pinOrigin } from './origin.js';
import { installJsonConsole } from './log.js';

installJsonConsole();

// Every deploy shape sets ORIGIN, and the image runs as production: without it
// the handler would take the origin from the request's own `Host`, so it is
// refused there. Outside production (a local run) that fallback stands.
if (!process.env.ORIGIN && process.env.NODE_ENV === 'production') {
  throw new Error('ORIGIN is required: the origin this console is served from');
}
const origin = process.env.ORIGIN ? parseOrigin(process.env.ORIGIN) : undefined;
if (origin) {
  // The handler reads these when its module loads, hence the dynamic import —
  // a static one would load it before they are set, unpinned. No header may
  // add a port to the pinned host either.
  process.env.PROTOCOL_HEADER = PROTOCOL_HEADER;
  process.env.HOST_HEADER = HOST_HEADER;
  delete process.env.PORT_HEADER;
}
// A specifier the type checker does not follow: the handler is the build's
// generated output, not source this project checks.
const HANDLER = '../build/handler.js';
const { handler } = await import(HANDLER);

const host = process.env.HOST || '0.0.0.0';
const port = Number(process.env.PORT || '3000');
const shutdownTimeout = Number.parseInt(process.env.SHUTDOWN_TIMEOUT || '30', 10);

/** @param {string} name */
function seconds(name) {
  const raw = process.env[name];
  if (!raw) return undefined;
  const value = Number.parseInt(raw, 10);
  if (Number.isNaN(value) || value < 0) throw new Error(`invalid ${name}: ${raw}`);
  return value;
}

const server = http.createServer((req, res) => {
  if (origin) pinOrigin(req.headers, origin);
  if (isFormPostCallback(req)) {
    relayFormPost(req, res);
    return;
  }
  // The adapter's handler is async; a rejection must answer this request with
  // a 500, never escape as an unhandled rejection that ends the process for
  // every user.
  Promise.resolve(
    handler(req, res, () => {
      res.statusCode = 404;
      res.end('Not found');
    }),
  ).catch((error) => {
    console.error('request failed:', error);
    if (!res.headersSent) res.writeHead(500);
    res.end();
  });
});

const keepAlive = seconds('KEEP_ALIVE_TIMEOUT');
if (keepAlive !== undefined) server.keepAliveTimeout = keepAlive * 1000;
const headersTimeout = seconds('HEADERS_TIMEOUT');
if (headersTimeout !== undefined) server.headersTimeout = headersTimeout * 1000;

server.listen(port, host, () => {
  console.log(`Listening on http://${host}:${port}`);
});

/** @type {NodeJS.Timeout | undefined} */
let forceClose;
server.on('request', (req) => {
  // Once shutting down, drop a keep-alive connection as soon as it idles.
  req.on('close', () => {
    if (forceClose) server.closeIdleConnections();
  });
});

/** @param {NodeJS.Signals} reason */
function shutdown(reason) {
  if (forceClose) return;
  server.closeIdleConnections();
  server.close((error) => {
    if (error) return;
    clearTimeout(forceClose);
    // @ts-expect-error custom event, as the adapter emits it
    process.emit('sveltekit:shutdown', reason);
  });
  forceClose = setTimeout(() => server.closeAllConnections(), shutdownTimeout * 1000);
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

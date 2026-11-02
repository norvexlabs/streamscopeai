/**
 * Turning a failed *connection* into an ordinary API error.
 *
 * `openapi-fetch` returns `{ error }` only for a response the server actually
 * sent. When `fetch` itself rejects — the gateway is down, DNS fails, the TLS
 * handshake is refused — it RETHROWS, so every `const { data, error } = await
 * api.GET(…)` call site throws instead of taking its error branch. A caller
 * that did not wrap the call in try/catch loses its whole control flow: an
 * `await` inside a polling loop kills the loop, and a `void`-ed call turns into
 * a silent unhandled rejection.
 *
 * That is not hypothetical here: an appliance upgrade stops caddy for the whole
 * kairos-agent run, so EVERY request from an already-loaded page rejects at the
 * network layer for minutes. The upgrade tracker's own "the console is offline,
 * keep retrying" branch could never run, and the panel stayed frozen on
 * "Upgrade in progress" until the operator reloaded the page by hand.
 *
 * Registering [`networkErrorMiddleware`] on a client makes such a rejection
 * arrive as a synthetic 503 body in the SAME `ApiErrorResponse` shape the
 * server uses, so `extractError` / `extractErrorCode` and every existing error
 * branch work unchanged.
 */

/**
 * Error code for a request that never reached admin-api — synthesized here when
 * the browser cannot reach the console, and by the console's own server
 * (`hooks.server.ts`) when it cannot reach admin-api. Deliberately NOT a member
 * of admin-api's `ApiErrorCode`: admin-api never sends it, so a UI branch on
 * this code always means "the API is out of reach, keep retrying".
 */
export const NETWORK_UNREACHABLE = 'network_unreachable';

/** Human-readable message paired with {@link NETWORK_UNREACHABLE}. */
const NETWORK_UNREACHABLE_MESSAGE =
  'Cannot reach the server — it may be restarting.';

/**
 * A `fetch` rejection rendered as the error envelope the rest of the app
 * already understands. 503 (not 0 or 502): the request never reached a server,
 * which is exactly "service unavailable", and any `response.ok` check must see
 * false.
 */
export function networkErrorResponse(): Response {
  return new Response(
    JSON.stringify({
      error: { code: NETWORK_UNREACHABLE, message: NETWORK_UNREACHABLE_MESSAGE },
    }),
    { status: 503, statusText: 'Service Unavailable', headers: { 'Content-Type': 'application/json' } }
  );
}

/**
 * `openapi-fetch` middleware mapping a transport-level rejection to
 * {@link networkErrorResponse}.
 *
 * Only a genuine transport failure is converted. An `AbortError` is the
 * caller's own cancellation (a superseded request, an unmounted component) and
 * is rethrown untouched — swallowing it into a 503 would make every cancelled
 * request look like an outage and raise a toast the user never caused.
 */
export const networkErrorMiddleware = {
  onError({ error }: { error: unknown }): Response | undefined {
    // Matched on `name` rather than a constructor: an abort surfaces as a
    // `DOMException` in the browser and in undici, and whether that extends
    // `Error` is a runtime detail this must not depend on.
    if ((error as { name?: unknown } | null)?.name === 'AbortError') return undefined;
    return networkErrorResponse();
  },
};

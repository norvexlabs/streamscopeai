/**
 * The error envelopes the UI server answers an API path with itself, in the
 * API's own shape (`{ error: { message, type, code } }`) and with the API's
 * own codes, so the typed clients branch on `error.code` the same way whoever
 * answered.
 */

function errorJson(status: number, message: string, type: string, code: string): Response {
  return new Response(JSON.stringify({ error: { message, type, code } }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/** A 401 for an API path with no valid session — the typed clients turn it
 *  into a login redirect; a 303 would be followed and return login HTML as 200. */
export function unauthorizedJson(): Response {
  return errorJson(401, 'Session expired — please log in again.', 'auth_error', 'session_expired');
}

/** A 404 for a path no API surface relayed here answers. */
export function notFoundJson(): Response {
  return errorJson(404, 'Not found.', 'not_found', 'api_route_not_found');
}

/** A 504 when the API did not answer: in time, or at all. */
export function upstreamErrorJson(timedOut: boolean): Response {
  return timedOut
    ? errorJson(504, 'The API did not respond in time.', 'upstream_error', 'upstream_timeout')
    : errorJson(504, 'Could not reach the API.', 'upstream_error', 'upstream_unreachable');
}

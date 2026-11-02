/**
 * The most a console route other than the API forwarders reads of a request
 * body: sign-in and the other form actions read theirs whole, under no
 * deadline. The server's own limit (`BODY_SIZE_LIMIT`, set on the image) is
 * sized for the forwarders, which hand admin-api every body it decides on.
 */
export const PAGE_BODY_LIMIT = 512 * 1024;

/** The routes that forward a request body to admin-api: the two planes' API
 *  prefixes (the CLI's passthrough is GET-only, so it is held to the limit). */
export function isApiForwarder(path: string): boolean {
  return /^\/(portal\/)?t\/[^/]+\/api\//.test(path);
}

/**
 * Whether a request's body may be read on `path`, judged on its declared
 * length — the server ends a body that runs past its `Content-Length`. A body
 * declaring none (re-framed as chunked by a front, from an HTTP/2 client) is
 * bounded by the server's own limit alone: refusing it would refuse sign-in
 * through such a front.
 */
export function pageBodyVerdict(
  path: string,
  hasBody: boolean,
  declaredLength: string | null,
): 'ok' | 'too_large' {
  if (!hasBody || declaredLength === null || isApiForwarder(path)) return 'ok';
  if (!/^\d+$/.test(declaredLength) || Number(declaredLength) > PAGE_BODY_LIMIT) return 'too_large';
  return 'ok';
}

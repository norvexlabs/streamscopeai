/**
 * Ready-to-paste curl snippets for freshly minted keys — resolved against the
 * real deployment endpoints, never placeholder variables. `ak-` admin/portal
 * keys are scripted against the admin-API, which production deploys serve on a
 * separate vhost (`api_public_url`) from this console — so the snippet targets
 * that origin when configured, falling back to this console's origin only for
 * co-resident single-domain installs. The gateway uses the tenant's configured
 * `proxy_public_url` the same way.
 */

function consoleOrigin(): string {
  return typeof window === 'undefined' ? '' : window.location.origin;
}

function adminKeySnippet(key: string, apiBaseUrl?: string | null): string {
  const base = apiBaseUrl || consoleOrigin();
  return (
    `curl -H "Authorization: Bearer ${key}" \\\n` +
    `     "${base}/api/v1/admin/users"`
  );
}

export function portalKeySnippet(
  key: string,
  workspaceId: string,
  apiBaseUrl?: string | null,
): string {
  const base = apiBaseUrl || consoleOrigin();
  return (
    `curl -H "Authorization: Bearer ${key}" \\\n` +
    `     "${base}/api/v1/portal/workspaces/${workspaceId}/members"`
  );
}

export function gatewayKeySnippet(key: string, proxyBaseUrl?: string | null): string {
  const base = proxyBaseUrl || consoleOrigin();
  return (
    `curl -H "Authorization: Bearer ${key}" \\\n` +
    `     -H "Content-Type: application/json" \\\n` +
    `     "${base}/v1/chat/completions" \\\n` +
    `     -d '{"model": "<alias>", "messages": [{"role": "user", "content": "ping"}]}'`
  );
}

/** BYOK (`vk-`) keys authenticate the /fwd mount, carrying the client's own
 *  upstream credential. */
export function byokKeySnippet(key: string, proxyBaseUrl?: string | null): string {
  const base = proxyBaseUrl || consoleOrigin();
  return (
    `curl -H "Content-Type: application/json" \\\n` +
    `     -H "Authorization: Bearer <your-upstream-credential>" \\\n` +
    `     "${base}/fwd/${key}/v1/chat/completions" \\\n` +
    `     -d '{"model": "<alias>", "messages": [{"role": "user", "content": "ping"}]}'`
  );
}

/** One dispatch for every reveal-once surface: pick the snippet by the key's
 *  plane as the mint/rotate response reports it. */
export function mintedKeySnippet(
  plane: string,
  key: string,
  opts: {
    proxyBaseUrl?: string | null;
    apiBaseUrl?: string | null;
    workspaceId?: string | null;
  } = {},
): string {
  if (plane === 'admin') return adminKeySnippet(key, opts.apiBaseUrl);
  if (plane === 'portal') {
    return portalKeySnippet(key, opts.workspaceId ?? '<workspace-id>', opts.apiBaseUrl);
  }
  return gatewayKeySnippet(key, opts.proxyBaseUrl);
}

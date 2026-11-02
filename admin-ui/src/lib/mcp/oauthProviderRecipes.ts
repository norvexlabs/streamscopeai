// Client-side helpers over the seed-backed OAuth provider recipes.
//
// The recipe *data* lives in `seeds/mcp_servers/oauth_provider_recipes.json`
// and is served by `GET /api/v1/admin/mcp/oauth-provider-recipes`. Only the
// bits that depend on live UI state stay here: host-based provider detection
// and the generic-fallback pick (the `redirect`/`homepage` field values are
// resolved from tenant settings at render time, in the component).

import type { components } from '#lib/generated/api-types.js';

export type OauthProviderRecipe = components['schemas']['OauthProviderRecipe'];

/** The seed reserves this id for the host-agnostic fallback recipe. */
const GENERIC_RECIPE_ID = 'generic';

/** Extract a lowercase host from a URL string, or `null` if unparseable. */
function hostOf(url: string): string | null {
  const trimmed = url.trim();
  if (trimmed === '') return null;
  try {
    return new URL(trimmed).host.toLowerCase();
  } catch {
    return null;
  }
}

/**
 * Best-effort provider detection from the upstream URL (falling back to the
 * issuer URL). Returns `null` when nothing matches — the caller shows the
 * generic recipe. A recipe matches when a host needle is the host or a
 * dot-suffix of it (`atlassian.com` matches `mcp.atlassian.com`).
 */
export function detectProviderRecipe(
  recipes: OauthProviderRecipe[],
  upstreamUrl: string,
  issuerUrl: string,
): OauthProviderRecipe | null {
  const host = hostOf(upstreamUrl) ?? hostOf(issuerUrl);
  if (!host) return null;
  return (
    recipes.find((r) =>
      (r.host_patterns ?? []).some((p) => host === p || host.endsWith(`.${p}`)),
    ) ?? null
  );
}

/** The generic-fallback recipe, or the last entry if the seed lacks one. */
export function genericRecipe(recipes: OauthProviderRecipe[]): OauthProviderRecipe | null {
  return recipes.find((r) => r.id === GENERIC_RECIPE_ID) ?? recipes.at(-1) ?? null;
}

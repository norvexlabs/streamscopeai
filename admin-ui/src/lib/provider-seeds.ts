// The provider catalog as the RUNNING admin-api serves it, so a seed edit
// reaches the forms without rebuilding the UI. Fetched once per page load and
// shared by every surface that fills a server form from a provider.
//
// `transport` is not on the wire: it is read from the catalog compiled into
// this build, which comes from the same provider seed. Keep it that way unless
// the endpoint starts serving it.
import { adminApi } from '#lib/api-client.js';
import { providerDefaultTransport } from '#lib/generated/providers.js';
import type { ProviderSeeds } from '#lib/server-form.js';

let cached: ProviderSeeds | null = null;
let inflight: Promise<ProviderSeeds> | null = null;

/** Never rejects — enforced here, not just promised. A catalog that did not
 *  load leaves `seedFor` answering from the build's own copy, which is a stale
 *  answer rather than no answer; callers put this in a `Promise.all` beside the
 *  data their page is made of, and a rejection would take that page down with
 *  it. A failure is also never memoised, so the next page load asks again. */
export function providerSeeds(): Promise<ProviderSeeds> {
  if (cached) return Promise.resolve(cached);
  if (inflight) return inflight;
  inflight = (async () => {
    try {
      const { data } = await adminApi.GET('/api/v1/admin/servers/provider-defaults');
      const map: ProviderSeeds = {};
      for (const p of data?.items ?? []) {
        map[p.value] = {
          url: p.default_url ?? '',
          apiFormat: p.default_upstream_api_format,
          chatEndpointPath: p.default_chat_endpoint_path ?? '',
          transport: providerDefaultTransport(p.value),
        };
      }
      // Only a catalog that actually arrived is worth keeping — caching an
      // empty map would pin every later form to the build's copy for the whole
      // session.
      if (Object.keys(map).length > 0) cached = map;
      return map;
    } catch {
      return {};
    } finally {
      inflight = null;
    }
  })();
  return inflight;
}

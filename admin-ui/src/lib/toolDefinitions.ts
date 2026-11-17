import { adminApi } from '#lib/api-client.js';
import { portalApi } from '#lib/portal-client.js';
import { workspaceQuery } from '#lib/selfScoped.js';
import type { components } from '#lib/generated/api-types.js';

type ApiVersion = components['schemas']['ApiVersion'];
type ToolDefinition = components['schemas']['ToolDefinitionBlobResponse'];

/** The plane a shared leaf renders on: read with `isSelfScoped()` and
 *  `portalWorkspace()` at component init (both read Svelte context). */
export interface ToolDefinitionPlane {
  selfScoped: boolean;
  workspaceId: () => string | undefined;
}

/** One stored tool catalog by its hash, on the caller's plane — the portal reads
 *  it through its own ownership-gated route, in the workspace being viewed. With
 *  `protocol`, the answer's `tools` is the catalog read in that protocol.
 *  `null` when the read fails. */
export async function fetchToolDefinition(
  plane: ToolDefinitionPlane,
  hash: string,
  protocol?: ApiVersion,
): Promise<ToolDefinition | null> {
  const protocolQuery = protocol ? { protocol } : {};
  const { data, error } = plane.selfScoped
    ? await portalApi.GET('/api/v1/portal/audit/tool-definitions/{hash}', {
        params: { path: { hash }, query: { ...workspaceQuery(plane.workspaceId()), ...protocolQuery } },
      })
    : await adminApi.GET('/api/v1/admin/audit/tool-definitions/{hash}', {
        params: { path: { hash }, query: protocolQuery },
      });
  return error ? null : (data ?? null);
}

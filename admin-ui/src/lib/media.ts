// Plane-aware media-blob URL builder for native loads (`<img>`/`<audio>`/
// download `<a>`) inside the shared conversation/audit renderers.
//
// Native browser loads bypass the typed API client, so they must carry the
// `/t/<slug>` (admin) or `/portal/t/<slug>` (portal) prefix themselves or the
// path-scoped session cookie isn't sent. `scopeHref` adds the right prefix
// from the current pathname.
//
// The two planes hit different routes:
//   admin  → /api/v1/admin/audit/media/{hash}?blob_type=…
//   portal → /api/v1/portal/audit/media/{hash}?blob_type=…&request_id=…[&workspace_id=…]
// The portal route is ownership-gated by `request_id` (a request in the
// viewer's scope that references the blob), so the request id is REQUIRED
// there, and a teammate's blob in a shared workspace also needs the workspace
// being viewed.

import { scopeHref } from '#lib/tenant.js';

export function mediaUrl(
  slug: string,
  pathname: string,
  hash: string,
  blobType: string,
  requestId?: string,
  workspaceId?: string,
): string {
  // Every part is encoded: a hash can come from a client's own `blob_ref`
  // part, and a `../` in a path would point the viewer's cookie elsewhere.
  const path = `${encodeURIComponent(hash)}?blob_type=${encodeURIComponent(blobType)}`;
  if (pathname.startsWith('/portal')) {
    // Without its owning request the portal cannot prove the blob is the
    // viewer's: no URL rather than one the route can only refuse.
    if (!requestId) return '';
    const ws = workspaceId ? `&workspace_id=${encodeURIComponent(workspaceId)}` : '';
    return (
      scopeHref(
        slug,
        pathname,
        `/api/v1/portal/audit/media/${path}&request_id=${encodeURIComponent(requestId)}${ws}`,
      ) ?? ''
    );
  }
  return scopeHref(slug, pathname, `/api/v1/admin/audit/media/${path}`) ?? '';
}

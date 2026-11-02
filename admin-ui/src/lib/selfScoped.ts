// Self-scoped (portal member) rendering signal.
//
// The conversation/audit rendering leaves are shared between the admin
// investigative pages and the portal member surface. In the portal member
// plane the caller sees only their OWN data, and the admin-only destinations a
// few leaves deep-link to (tool-policy rules, the clients/detection page, the
// MCP gateways page, cross-user pivots) do NOT exist. Those links must render
// as plain text there, not as dead `<a>`s.
//
// Threading a `selfScoped` prop through the whole event tree
// (ConversationView → Message → ToolCall → …) would be heavy prop-drilling, so
// the page sets it ONCE as context and the leaves read it. This is an explicit
// semantic signal (not pathname-sniffing): the page owns the decision because
// it owns which routes exist in its plane.

import { getContext, setContext } from 'svelte';
import { scopeHref } from '#lib/tenant.js';

const KEY = Symbol('selfScoped');

/** Set by a page/root that renders shared leaves in the portal member plane. */
export function setSelfScoped(value: boolean): void {
  setContext(KEY, value);
}

/** Read by a shared leaf to decide whether to suppress admin-only links.
 *  Defaults to `false` (admin behavior) when no provider set it. */
export function isSelfScoped(): boolean {
  return getContext<boolean>(KEY) ?? false;
}

const WORKSPACE_KEY = Symbol('portalWorkspace');

/** Set by a portal page whose rows may come from a workspace that shares with
 *  its members: the workspace being viewed. Every portal detail route a shared
 *  leaf calls (a trace, a stored media blob, a tool definition) takes it, or
 *  the server narrows to the caller's own rows and a teammate's row 404s. The
 *  server re-checks sharing and membership; this only says which workspace is
 *  being viewed. A getter, so a page whose scope changes is read live. */
export function setPortalWorkspace(get: () => string | undefined): void {
  setContext(WORKSPACE_KEY, get);
}

/** The viewed workspace's getter; `undefined` (own rows only) when no portal
 *  page set it — always so on the console. */
export function portalWorkspace(): () => string | undefined {
  return getContext<(() => string | undefined) | undefined>(WORKSPACE_KEY) ?? (() => undefined);
}

/** The `workspace_id` query a portal detail route takes, empty when no
 *  workspace is being viewed. */
export function workspaceQuery(workspaceId: string | undefined): { workspace_id?: string } {
  return workspaceId ? { workspace_id: workspaceId } : {};
}

/** A link to a session, on the plane the page is on, in the portal workspace
 *  being viewed: a teammate's session in a workspace that shares opens only in
 *  that workspace's scope. Every session link a shared leaf renders is built
 *  here. */
export function sessionHref(slug: string, pathname: string, sessionId: string, workspaceId?: string): string {
  const href = scopeHref(slug, pathname, `/sessions/${encodeURIComponent(sessionId)}`);
  return workspaceId ? `${href}?workspace_id=${encodeURIComponent(workspaceId)}` : href;
}

// The plane seam of the shared browse views (Sessions, Audit, the session
// view): the console and the portal render the same components, and this
// adapter is the one place that differs per plane — which API answers, which
// filter keys the URL carries, which controls name whose rows are shown.
//
// Whose rows are shown is the SERVER's decision on the portal (the caller's
// own, or a sharing workspace's); the portal adapter only says which workspace
// is being viewed. Nothing here can widen a member's scope.

import type { paths } from '#lib/generated/api-types.js';
import type { AuditLogRow, ConversationResponse, CrossSessionIssue, LinkedSessionsResponse, SessionSummary } from '#lib/api-types.js';
import type { components } from '#lib/generated/api-types.js';
import { adminApi } from '#lib/api-client.js';
import { portalApi } from '#lib/portal-client.js';
import { fetchAllPages } from '#lib/api-helpers.js';
import { AUDIT_FILTER_KEYS, SESSIONS_FILTER_KEYS } from '#lib/deeplinks.js';
import { PERIOD_FILTER_DEFAULTS, consoleScope, workspaceIdsQuery } from '#lib/scope.svelte.js';

type WebAuditLogEntry = components['schemas']['WebAuditLogEntry'];

type PortalAuditQuery = NonNullable<paths['/api/v1/portal/audit']['get']['parameters']['query']>;
type PortalSessionQuery = NonNullable<paths['/api/v1/portal/sessions']['get']['parameters']['query']>;

/** The audit filters both planes apply: the portal's query without its scope. */
export type AuditFilterQuery = Omit<PortalAuditQuery, 'workspace_id'>;
/** The session filters both planes apply: the portal's query without its scope. */
export type SessionFilterQuery = Omit<PortalSessionQuery, 'workspace_id'>;

/** One page of a list, as both planes answer it. */
interface ListPage<T> {
  items: T[];
  has_more: boolean;
  offset: number;
  limit: number;
  scan_cut?: boolean;
}

/** An API answer: data, or the typed error envelope. */
type Answer<T> = { data?: T; error?: unknown };

/** Display names the audit filters and details resolve ids through. */
export interface AuditOptions {
  /** app_id → name. */
  apps: Map<string, { name?: string }>;
  virtualServers: { id: string; name: string }[];
  upstreamServers: { id: string; name: string }[];
  /** By slug, the filter's key. */
  a2aAgents: { id: string; name: string }[];
  /** QoS class id → name. */
  qosClassNames: Map<string, string>;
}

export interface BrowsePlane {
  readonly portal: boolean;
  /** The URL keys whose values say whose rows are shown. */
  readonly scopeKeys: readonly string[];
  /** URL filter keys of the Audit view (scope keys included). */
  readonly auditKeys: readonly string[];
  /** URL filter keys of the Sessions view (scope keys included). */
  readonly sessionKeys: readonly string[];
  /** Default period, omitted from the URL. */
  readonly periodDefaults: Readonly<Record<string, string>>;
  /** Whether the period follows the viewer across the views (console only). */
  readonly persistPeriod: boolean;
  /** Whether the expert alert filter and order are offered. The portal
   *  server withholds expert findings, so it does not offer them. */
  readonly offersAlerts: boolean;
  listAudit(q: AuditFilterQuery, scope: Record<string, string>): Promise<Answer<ListPage<AuditLogRow>>>;
  listSessions(q: SessionFilterQuery, scope: Record<string, string>): Promise<Answer<ListPage<SessionSummary>>>;
  auditOptions(): Promise<AuditOptions>;
  /** app_id → display name: the Sessions list's one option. */
  apps(): Promise<Map<string, { name?: string }>>;
  conversation(id: string, workspaceId: string | undefined): Promise<Answer<ConversationResponse>>;
  linked(id: string, workspaceId: string | undefined): Promise<Answer<LinkedSessionsResponse>>;
  webCalls(requestId: string, workspaceId: string | undefined): Promise<Answer<{ items: WebAuditLogEntry[] }>>;
  /** The cross-session expert issues a session appears in, or `null` when
   *  the read failed. They name other users' sessions, so the portal never
   *  reads them: always empty there. */
  issues(id: string): Promise<CrossSessionIssue[] | null>;
  /** Whether a teammate filter applies in the current scope: on the portal,
   *  only in a shared-workspace view (the server ignores it on own rows). */
  filtersByUser(scope: Record<string, string>): boolean;
}

const blank = (v: string | undefined) => (v ? v : undefined);
const ws = (workspaceId: string | undefined) => (workspaceId ? { workspace_id: workspaceId } : {});
/** The portal's teammate filter, sent only in a team view (the server ignores
 *  it on the caller's own rows, and a stale one must not ride along). */
const teammate = (scope: Record<string, string>) => (scope.workspace_id ? blank(scope.user_email) : undefined);

/** Console scope keys: a user, a workspace set, an MCP token. */
const CONSOLE_SCOPE_KEYS = ['user_email', 'user_id', 'workspace_ids', 'jti'] as const;
/** Portal scope keys: the workspace being viewed, and a teammate in it. */
const PORTAL_SCOPE_KEYS = ['workspace_id', 'user_email'] as const;

const CONSOLE_ONLY = new Set<string>(['user_id', 'workspace_ids', 'jti']);

export const consolePlane: BrowsePlane = {
  portal: false,
  scopeKeys: CONSOLE_SCOPE_KEYS,
  auditKeys: AUDIT_FILTER_KEYS,
  sessionKeys: SESSIONS_FILTER_KEYS,
  periodDefaults: PERIOD_FILTER_DEFAULTS,
  persistPeriod: true,
  offersAlerts: true,
  listAudit: (q, scope) =>
    adminApi.GET('/api/v1/admin/audit', {
      params: {
        query: {
          ...q,
          user_email: blank(scope.user_email),
          user_id: blank(scope.user_id),
          ...workspaceIdsQuery(scope.workspace_ids ?? '', consoleScope.workspaces), // workspace-reload-ok: called only from the browse components' usePeriodicLoad loaders
          jti: blank(scope.jti),
        },
      },
    }),
  listSessions: (q, scope) =>
    adminApi.GET('/api/v1/admin/sessions', {
      params: {
        query: {
          ...q,
          user_email: blank(scope.user_email),
          user_id: blank(scope.user_id),
          ...workspaceIdsQuery(scope.workspace_ids ?? '', consoleScope.workspaces), // workspace-reload-ok: called only from the browse components' usePeriodicLoad loaders
        },
      },
    }),
  async auditOptions() {
    const [apps, vs, up, agents, qos] = await Promise.all([
      this.apps(),
      adminApi.GET('/api/v1/admin/mcp/virtual-servers', { params: { query: { limit: 200 } } }),
      adminApi.GET('/api/v1/admin/mcp/upstream-servers', { params: { query: { limit: 200 } } }),
      adminApi.GET('/api/v1/admin/a2a/agents', { params: { query: { limit: 200 } } }),
      adminApi.GET('/api/v1/admin/qos-classes', {}),
    ]);
    return {
      apps,
      virtualServers: (vs.data?.items ?? []).map((v) => ({ id: v.id, name: v.slug })),
      upstreamServers: (up.data?.items ?? []).map((u) => ({ id: u.id, name: u.name })),
      a2aAgents: (agents.data?.items ?? []).map((a) => ({ id: a.slug, name: a.slug })),
      qosClassNames: new Map((qos.data?.items ?? []).map((c) => [c.id, c.name])),
    };
  },
  conversation: (id) =>
    adminApi.GET('/api/v1/admin/sessions/{session_id}/conversation', {
      params: { path: { session_id: id }, query: { format: 'parsed_raw' } },
    }),
  linked: (id) => adminApi.GET('/api/v1/admin/sessions/{session_id}/linked', { params: { path: { session_id: id } } }),
  webCalls: (requestId) =>
    adminApi.GET('/api/v1/admin/audit/{request_id}/web', { params: { path: { request_id: requestId }, query: {} } }),
  async apps() {
    const apps = await fetchAllPages((offset, limit) =>
      adminApi.GET('/api/v1/admin/analytics/apps', { params: { query: { offset, limit } } }));
    return new Map(apps.map((a) => [a.id, { name: a.name }]));
  },
  issues: async (id) => {
    const { data, error } = await adminApi.GET('/api/v1/admin/experts/cross-session-issues', {
      params: { query: { session_id: id, days: 365, limit: 20 } },
    });
    return error ? null : (data?.items ?? []);
  },
  filtersByUser: () => true,
};

export const portalPlane: BrowsePlane = {
  portal: true,
  scopeKeys: PORTAL_SCOPE_KEYS,
  auditKeys: [...AUDIT_FILTER_KEYS.filter((k) => !CONSOLE_ONLY.has(k)), 'workspace_id'],
  sessionKeys: [...SESSIONS_FILTER_KEYS.filter((k) => !CONSOLE_ONLY.has(k)), 'workspace_id'],
  periodDefaults: { days: '7' },
  persistPeriod: false,
  offersAlerts: false,
  listAudit: (q, scope) =>
    portalApi.GET('/api/v1/portal/audit', {
      params: { query: { ...q, ...ws(scope.workspace_id), user_email: teammate(scope) } },
    }),
  listSessions: (q, scope) =>
    portalApi.GET('/api/v1/portal/sessions', {
      params: { query: { ...q, ...ws(scope.workspace_id), user_email: teammate(scope) } },
    }),
  async auditOptions() {
    const { data } = await portalApi.GET('/api/v1/portal/audit/filter-options', {});
    return {
      apps: new Map((data?.apps ?? []).map((a) => [a.id, { name: a.name }])),
      virtualServers: data?.mcp_virtual_servers ?? [],
      upstreamServers: data?.mcp_upstream_servers ?? [],
      a2aAgents: data?.a2a_agents ?? [],
      qosClassNames: new Map((data?.qos_classes ?? []).map((c) => [c.id, c.name])),
    };
  },
  async apps() {
    const { data } = await portalApi.GET('/api/v1/portal/audit/filter-options', {});
    return new Map((data?.apps ?? []).map((a) => [a.id, { name: a.name }]));
  },
  conversation: (id, workspaceId) =>
    portalApi.GET('/api/v1/portal/sessions/{id}/conversation', { params: { path: { id }, query: ws(workspaceId) } }),
  linked: (id, workspaceId) =>
    portalApi.GET('/api/v1/portal/sessions/{id}/linked', { params: { path: { id }, query: ws(workspaceId) } }),
  webCalls: (requestId, workspaceId) =>
    portalApi.GET('/api/v1/portal/audit/{request_id}/web', {
      params: { path: { request_id: requestId }, query: ws(workspaceId) },
    }),
  issues: async () => [],
  filtersByUser: (scope) => !!scope.workspace_id,
};

// Canonical deep-links into the investigative pages (/audit, /sessions).
//
// Each page reads its filters from the URL via `UrlFilters`, seeding only the
// keys it lists. A deep-link that carries a key the page does NOT list is
// silently dropped — the operator lands on an unfiltered list. To make that
// drift impossible, this module owns the single source of truth for each
// page's filter keys AND the typed builders every caller must use: a dropped
// or misspelled param fails to compile instead of failing silently at runtime.
//
// Builders return a tenant-RELATIVE path (`/audit?…`, `/sessions?…`); scope it
// at the call site with `thref`/`pthref` or `scopeHref` exactly as before.

// ── /audit ──────────────────────────────────────────────────────────────────

/** Filter keys the /audit page reads from the URL and forwards to the backend
 *  `/api/v1/admin/audit` query. The page derives its `FilterKey` union and its
 *  `UrlFilters` key array from this one list, so the two never drift. Period
 *  keys (days/start/end) come from `PERIOD_FILTER_KEYS`. Append a key here the
 *  moment a deep-link or a filter control needs it — and the matching field
 *  must exist on the backend `AuditQuery`. */
export const AUDIT_FILTER_KEYS = [
  // Cross-kind (applied on every arm; `has_guardrail` ignored on MCP).
  'user_email', 'user_id', 'workspace_ids', 'app_id', 'error_category',
  'search', 'kind', 'jti', 'has_guardrail',
  // LLM-only.
  'model', 'finish_reason', 'upstream_server', 'api_version', 'media_type', 'has_blocked',
  // Web-only.
  'surface', 'operation',
  // MCP-only.
  'tool_id', 'resource_uri', 'prompt_id', 'virtual_server_id', 'upstream_server_id',
  // A2A-only.
  'agent_slug', 'task_state', 'methods',
] as const;

type AuditFilterKey = (typeof AUDIT_FILTER_KEYS)[number];

/** Period keys carried by a scoped deep-link so the target window matches the
 *  originating dashboard (a bare deep-link would otherwise fall back to the
 *  investigative page's own default window). `workspace_ids` is already a
 *  filter key. See `dashboardScopeParams`. */
type PeriodLinkKey = 'days' | 'start' | 'end';

/** Non-filter deep-link key the /audit page understands specially:
 *  `request_id` focuses + auto-expands a single row (bypasses the period
 *  window). */
/** `workspace_id` is the portal's: the workspace a team view reads. */
type AuditLinkKey = AuditFilterKey | PeriodLinkKey | 'request_id' | 'workspace_id';

/** Build a tenant-relative `/audit` deep-link. Only keys the page honours are
 *  accepted (compile-checked); empty/nullish values are omitted; values are
 *  URL-encoded by `URLSearchParams`. */
export function auditHref(params: Partial<Record<AuditLinkKey, string | null>>): string {
  return buildHref('/audit', params);
}

// ── /sessions ─────────────────────────────────────────────────────────────────

/** Filter keys the /sessions page reads from the URL. Single source of truth,
 *  mirrored into the page's `FilterKey` union + `UrlFilters` array. Period keys
 *  come from `PERIOD_FILTER_KEYS`. */
export const SESSIONS_FILTER_KEYS = [
  'user_email', 'user_id', 'workspace_ids', 'app_id', 'model', 'search', 'alert_level', 'linked',
] as const;

export type SessionsFilterKey = (typeof SESSIONS_FILTER_KEYS)[number];

/** Build a tenant-relative `/sessions` list deep-link (the filtered list, not a
 *  single session — that is a plain `/sessions/{id}` path). `workspace_id` is
 *  the portal's: the workspace a team view reads. */
export function sessionsHref(
  params: Partial<Record<SessionsFilterKey | PeriodLinkKey | 'workspace_id', string | null>>,
): string {
  return buildHref('/sessions', params);
}

// ── /tool-calls ─────────────────────────────────────────────────────────────

/** Filter keys the /tool-calls page reads from the URL. Single source of truth,
 *  mirrored into the page's `FilterKey` union + `UrlFilters` array. Period keys
 *  come from `PERIOD_FILTER_KEYS`. */
export const TOOLCALLS_FILTER_KEYS = [
  'user_email', 'user_id', 'workspace_ids', 'app_id', 'search', 'kind',
  // LLM-only.
  'tool_name', 'risk', 'outcome',
  // MCP-only.
  'tool_id', 'resource_uri', 'prompt_id', 'virtual_server_id', 'upstream_server_id',
  // Web-only.
  'surface', 'operation',
] as const;

export type ToolCallsFilterKey = (typeof TOOLCALLS_FILTER_KEYS)[number];

/** Non-filter deep-link keys the /tool-calls page understands specially:
 *  `request_id` / `invocation_id` focus a single row (bypassing the period
 *  window). */
type ToolCallsLinkKey = ToolCallsFilterKey | PeriodLinkKey | 'request_id' | 'invocation_id';

/** Build a tenant-relative `/tool-calls` deep-link. Only keys the page honours
 *  are accepted (compile-checked); empty/nullish values are omitted. */
export function toolCallsHref(params: Partial<Record<ToolCallsLinkKey, string | null>>): string {
  return buildHref('/tool-calls', params);
}

// ── shared ────────────────────────────────────────────────────────────────────

function buildHref(base: string, params: Record<string, string | null | undefined>): string {
  const qs = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value != null && value !== '') qs.set(key, value);
  }
  const s = qs.toString();
  return s ? `${base}?${s}` : base;
}

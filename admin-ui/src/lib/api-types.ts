/**
 * Convenience re-exports from the generated OpenAPI types.
 *
 * Usage:
 *   import type { UserResponse, KeyListItem } from '#lib/api-types.js';
 */
import type { components } from './generated/api-types';

// ─── Users ───
export type UserResponse = components['schemas']['UserResponse'];
export type AdminAccountResponse = components['schemas']['AdminAccountResponse'];

// ─── API Keys ───
export type KeyListItem = components['schemas']['KeyListItem'];

// ─── Servers ───
export type ServerResponse = components['schemas']['ServerResponse'];
export type DiscoveredModel = components['schemas']['DiscoveredModel'];
export type RemovedModelInfo = components['schemas']['RemovedModelInfo'];
export type ModelSyncResponse = components['schemas']['ModelSyncResponse'];
export type ModelResponse = components['schemas']['ModelResponse'];

// ─── Model Catalog ───
export type CatalogEntry = components['schemas']['CatalogEntry'];

// ─── Downstream Providers ───
export type DownstreamProvider = components['schemas']['ProviderResponse'];
export type DownstreamRoute = components['schemas']['RouteResponse'];

// ─── Audit ───
export type AuditLogRow = components['schemas']['AuditLogRow'];
export type AuditKind = components['schemas']['AuditKind'];
export type ToolCallKind = components['schemas']['ToolCallKind'];

// ─── Settings ───
export type DbStatsResponse = components['schemas']['DbStatsResponse'];

// ─── Edge Nodes ───
// `EdgeNode` = per-tenant/global list row (metadata carries live proxy stats).
// `EdgeProxyStats` = the typed stats block nested under `metadata.stats`.
export type EdgeNode = components['schemas']['EdgeNodeResponse'];

// ─── Analytics ───
export type UsageSummary = components['schemas']['UsageSummary'];
export type BreakdownEntry = components['schemas']['BreakdownEntry'];
export type TimeseriesBucket = components['schemas']['TimeseriesBucket'];
// A window's spend decomposed per pricing unit. The plainer `SpendTotal` shape
// needs no alias — `formatSpend` takes the `amount` + `currency` pair both
// carry, so a call site never names the wire type.
export type SpendBreakdown = components['schemas']['SpendBreakdown'];
export type ErrorAnalytics = components['schemas']['ErrorAnalytics'];
export type TransformStatsResponse = components['schemas']['TransformStatsResponse'];

// ─── Proxy Dashboard ───
export type ProxyDashboardData = components['schemas']['ProxyDashboard'];

// ─── Sessions ───
export type SessionSummary = components['schemas']['SessionSummary'];
export type ConversationResponse = components['schemas']['ConversationResponse'];
/** Discriminated union from the generated spec — narrows via `event.type ===
 * 'message'` inside `{#if}` blocks. Helpers below extract cross-variant
 * fields (`metadata`, `raw`, `turn`) that the session-replay derivations scan
 * across all events without narrowing. */
export type ConversationEvent = components['schemas']['ConversationEvent'];
/** Metadata is present on message, tool_call, and media_api_call variants —
 * this guard lets cross-variant scans (e.g. building a turn → metadata map)
 * pull it safely. Dropping `media_api_call` silently loses model/cost/latency
 * for media-only turns in session replay. */
export function eventMetadata(ev: ConversationEvent): components['schemas']['TurnMetadata'] | null {
  if ((ev.type === 'message' || ev.type === 'tool_call' || ev.type === 'media_api_call') && ev.metadata) {
    return ev.metadata;
  }
  return null;
}
/** Raw wire payload — present on most variants. Returns `null` when absent. */
export function eventRaw(ev: ConversationEvent): unknown {
  return 'raw' in ev ? ev.raw ?? null : null;
}
/** Turn number — present on every variant except `context_reset` and
 * `turn_boundary`, which carry `before_turn` instead. Callers get a single
 * positional integer they can key a map by. */
export function eventTurn(ev: ConversationEvent): number | null {
  if ('turn' in ev && typeof ev.turn === 'number') return ev.turn;
  return null;
}
/** Exhaustiveness guard for discriminated-union switches. Reaching this at
 * runtime means an unhandled variant slipped past the branches; the real value
 * is the compile error — the argument is typed `never`, so adding a new
 * `ConversationEvent` variant (regen after a Rust enum change) makes any switch
 * that forgot a branch fail `svelte-check`. */
export function assertNever(x: never): never {
  throw new Error(`unhandled variant: ${JSON.stringify(x)}`);
}
export type DomainRequestMeta = components['schemas']['DomainRequestMeta'];
export type DomainToolSummary = components['schemas']['DomainToolSummary'];
export type LinkedSessionsResponse = components['schemas']['LinkedSessions'];
export type LinkedSession = components['schemas']['SessionSummary'];

// ─── Users & Keys Dashboard ───
export type UsersKeysDashboardResponse = components['schemas']['UsersKeysDashboard'];

// ─── Tools ───
export type ToolInventoryTool = components['schemas']['ToolEntry'];
export type ToolInventorySummary = components['schemas']['ToolSummary'];
export type ToolInvocation = components['schemas']['ToolInvocation'];
/** Cross-protocol tool-call row. `kind: 'llm' | 'mcp' | 'web'` discriminated. */
export type ToolCallRow = components['schemas']['ToolCallRow'];

// ─── App Registry ───
export type AppInfo = components['schemas']['AppInfo'];

// ─── Transforms ───
export type TransformProgram = components['schemas']['ProgramResponse'];
export type TransformSuggestion = components['schemas']['SuggestionResponse'];
export type ToolRuleSuggestion = components['schemas']['ToolRuleSuggestionResponse'];
export type FieldProfileSuggestion = components['schemas']['FieldProfileSuggestionResponse'];

// ─── Experts / Agent ───
export type AgentExpert = components['schemas']['ExpertResponse'];
export type AgentModelOption = components['schemas']['AgentModelEntry'];
export type ExpertDashboardResponse = components['schemas']['ExpertDashboardResponse'];
export type CrossSessionIssue = components['schemas']['CrossSessionIssue'];

// ─── Workspaces ───
export type WorkspaceSummary = components['schemas']['WorkspaceSummary'];
export type WorkspaceDetail = components['schemas']['WorkspaceDetail'];
export type WorkspaceMemberRow = components['schemas']['MemberRow'];
export type WorkspaceProvider = components['schemas']['WorkspaceProvider'];
export type WorkspaceMcpServer = components['schemas']['WorkspaceMcpServer'];
export type WorkspaceA2aAgent = components['schemas']['WorkspaceA2aAgent'];

// ─── A2A Gateway ───
export type A2aAgentRow = components['schemas']['A2aAgentRow'];

// ─── Auth Config ───
export type AuthConfig = components['schemas']['AuthConfigResponse'];
export type OidcTestResult = components['schemas']['OidcTestResponse'];

// ─── Global / Platform ───
export type GlobalUsageSummary = components['schemas']['GlobalUsageSummary'];
export type GlobalEdgeStats = components['schemas']['GlobalEdgeStatsResponse'];
export type EdgeStatsSeries = components['schemas']['EdgeStatsSeries'];

// ─── Prompt Snippets ───
export type PromptSnippet = components['schemas']['PromptSnippet'];

// ─── Portal types ───
export type PortalMe = components['schemas']['PortalMeResponse'];
export type Me = components['schemas']['MeResponse'];
export type DomainMediaCall = components['schemas']['DomainMediaCall'];
export type McpAuthMode = components['schemas']['McpAuthMode'];
export type PortalKey = components['schemas']['PortalKeyInfo'];
export type PortalStats = components['schemas']['PortalStats'];
export type PortalHome = components['schemas']['PortalHome'];

// ─── Portal workspace-manager types ───
export type WorkspaceMemberInfo = components['schemas']['WorkspaceMemberInfo'];
export type WorkspaceMemberUsage = components['schemas']['WorkspaceMemberUsage'];

// ─── Portal workspace automation (ak- keys) types ───
export type WsAutomationAccount = components['schemas']['WsAutomationAccount'];
export type WsAutomationKeyItem = components['schemas']['WsAutomationKeyItem'];

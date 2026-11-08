// Audit-badge registry. Single source of truth for label/icon/color/tooltip
// per `AuditBadge` code. Extends with each new variant added to the enum
// in `streamscope_core::audit::AuditBadge` — codes are append-only.

import { formatCost } from './formatters';
import type { components } from './generated/api-types';
import type { IconName } from './icons';

export type AuditBadge = components['schemas']['AuditBadge'];

/** Optional extra context the chip tooltip can use to add concrete detail. */
export type BadgeContext = {
  /** Distinct transform/program names that touched the content (drives the
   *  Modified tooltip). Pull from `transform_diff.injection_blocks[].transform`. */
  modifyingTransforms?: string[];
  /** Message count before/after compression (drives the Compressed tooltip).
   *  Pull from `transform_diff.messages_original_count` / `messages_after_count`. */
  messageCount?: { before: number; after: number };
  /** Catch-all request path + method (drives the Catchall tooltip). Pull from
   *  the audit record's `catchall_method` / `catchall_path` columns. */
  catchall?: { method?: string | null; path?: string | null };
};

type BadgeRegistryEntry = {
  /** Short user-facing label rendered in the chip. */
  label: string;
  /** Single-line tooltip. Receives the badge + optional context so variants
   *  can interpolate concrete detail (program names, etc.). */
  tooltip: (badge: AuditBadge, context?: BadgeContext) => string;
  /** Tailwind utility classes for the chip. */
  classes: string;
  /** Registry icon name (rendered by `<Icon>` with currentColor). */
  iconName: IconName;
};

const PROTOCOL_LABELS: Record<string, string> = {
  chat_completions: 'OpenAI Chat Completions',
  responses: 'OpenAI Responses',
  anthropic_messages: 'Anthropic Messages',
  google_gemini: 'Google Gemini',
};

function prettyProtocol(p: string): string {
  return PROTOCOL_LABELS[p] ?? p;
}

export const GUARDRAIL_CATEGORY_LABELS: Record<string, string> = {
  prompt_injection: 'prompt injection',
  jailbreak: 'jailbreak',
  pii: 'PII',
};

/** One inline-guardrail finding attached to a rendered conversation event — a
 *  web tool-result (`phase: response`) or an inbound message (`phase: request`).
 *  Carries the category, raw confidence (bucketed for display), and outcome. */
export type GuardrailInfo = components['schemas']['GuardrailStepDiff'];

/** Tone for a guardrail finding: an enforce-mode block is the strongest signal
 *  (error tone); an observe-mode flag and a detector error are advisory
 *  (warning tone). Single source for the banner, badge, and bubble border. */
export function guardrailTone(g: Pick<GuardrailInfo, 'outcome'>): 'error' | 'warning' {
  return g.outcome === 'blocked' ? 'error' : 'warning';
}

/** Strongest tone across a set of guardrail findings on one message — an
 *  enforce-mode block anywhere in the set dominates. Drives the single bubble
 *  border when several banners stack on one event. */
export function guardrailsTone(gs: Pick<GuardrailInfo, 'outcome'>[]): 'error' | 'warning' {
  return gs.some((g) => g.outcome === 'blocked') ? 'error' : 'warning';
}

/** Category-distinct glyph for a guardrail finding, so a stack of findings on
 *  one message (injection + PII + jailbreak can all fire) is legible at a
 *  glance: PII renders a person, a jailbreak verdict a lock, everything else
 *  (prompt injection, no-verdict detector errors) the shield. The outcome
 *  stays on the tone (`guardrailTone`), never on the glyph — single source
 *  for the pill and the banner. */
export function guardrailIcon(g: Pick<GuardrailInfo, 'name' | 'category'>): IconName {
  if (g.name === 'guardrail:pii') return 'user';
  if (g.category === 'jailbreak') return 'lock';
  return 'shield';
}

/** Bucket a raw confidence into Low/Med/High — the UI never shows the raw f32
 *  (that lives only in the audit detail). */
export function severityBucket(confidence: number): string {
  if (confidence >= 0.95) return 'High';
  if (confidence >= 0.85) return 'Medium';
  return 'Low';
}

/** Badge codes worth surfacing on the collapsed audit row — the security,
 *  policy, and failure signals an operator scanning the list must spot at a
 *  glance (a guardrail flag, a blocked tool, an SSRF refusal, a script error).
 *  Informational / benign badges (protocol translation, cache, sanitised tool
 *  names, …) stay in the expanded detail only so the list keeps scanning fast.
 *  Append-only alongside the registry — every code here MUST exist in
 *  BADGE_REGISTRY below. */
export const ATTENTION_BADGE_CODES: ReadonlySet<AuditBadge['code']> = new Set([
  // An unpriced row records a floor of zero, which in a list of costs is
  // indistinguishable from a request that was genuinely free — the one place
  // the difference has to be visible without opening the row.
  'unpriced',
  'guardrail',
  'guardrail_error',
  'modified_not_applied',
  'tool_blocked',
  'tool_block_not_applied',
  'tool_blocked_overflow',
  'block_overflow',
  'script_error',
  'agent_alert',
  'session_alert',
  // The row is missing what it was too large to deliver.
  'record_stripped',
  // The row names a body (a message, tool set, system prompt, media) that
  // never reached the console.
  'content_unavailable',
  'mcp_rpc_error',
  'web_blocked',
  'web_url_filtered',
  'web_rate_limited',
  'web_ssrf_refused',
  'web_scheme_refused',
  'web_substitution_tool_error',
  'web_substitution_forward_failed',
  'web_substitution_serialize_failed',
  'web_substitution_mixed_pending_splice_failed',
]);

/** Human-readable elapsed time from a second count. The cache badges carry how
 *  long an entry had been resident, which is a duration — not a timestamp, so
 *  `formatTimeAgo` does not apply. */
function formatCacheAge(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  return `${(seconds / 3600).toFixed(1)}h`;
}

/** Severity rank for `agent_alert` levels, so the collapsed chip keeps the
 *  MOST-severe instance's payload (axis/level/tooltip) rather than whichever
 *  happened to be emitted first — a later `major` must never hide behind an
 *  earlier `minor`. Keyed to the exact `AlertLevel` wire union so any enum
 *  drift is a compile error; the `?? 0` guard below stays as belt-and-braces. */
const AGENT_ALERT_LEVEL_RANK: Record<components['schemas']['AlertLevel'], number> = {
  major: 3,
  minor: 2,
  info: 1,
};

/** Collapse badges to one per code, preserving first-seen order. Several audit
 *  badges legitimately repeat on a single row — e.g. one `tool_blocked` per
 *  blocked call — but the chips are at-a-glance indicators and the
 *  keyed `{#each … (badge.code)}` renders require unique keys, so a repeated code
 *  would throw `each_key_duplicate` and blank the whole list. Render each distinct
 *  code once here; the full per-instance breakdown lives in the kind-specific
 *  detail body. For `agent_alert` the representative kept is the highest-severity
 *  instance (by `level`), so the collapsed chip's tooltip names the worst alert. */
export function dedupeBadgesByCode(badges: readonly AuditBadge[] | null | undefined): AuditBadge[] {
  const order: AuditBadge['code'][] = [];
  const repr = new Map<AuditBadge['code'], AuditBadge>();
  for (const b of badges ?? []) {
    const existing = repr.get(b.code);
    if (!existing) {
      order.push(b.code);
      repr.set(b.code, b);
      continue;
    }
    // Keep the most-severe agent_alert; every other code keeps first-seen (its
    // repeated instances are equivalent for the collapsed chip).
    if (b.code === 'agent_alert' && existing.code === 'agent_alert') {
      const better = (AGENT_ALERT_LEVEL_RANK[b.level] ?? 0) > (AGENT_ALERT_LEVEL_RANK[existing.level] ?? 0);
      if (better) repr.set(b.code, b);
    }
  }
  return order.map((c) => repr.get(c) as AuditBadge);
}

/** Badge codes that state a fact about the SESSION rather than the individual
 *  request. The `/audit` feed adds the session's alert to each of its rows, so
 *  the row-oriented feed — which has no session column — can surface it; a
 *  view that already renders the session-level signal in its own right must
 *  not repeat the same fact once per turn. Append-only alongside the registry. */
const SESSION_SCOPED_BADGE_CODES: ReadonlySet<AuditBadge['code']> = new Set([
  'agent_alert',
  'session_alert',
]);

/** Drop the session-scoped badges from a row's list, leaving only what the
 *  pipeline established while serving that one request. For the conversation
 *  renderer, whose page header carries the session alert banner already. */
export function turnScopedBadges(badges: readonly AuditBadge[] | null | undefined): AuditBadge[] {
  return (badges ?? []).filter((b) => !SESSION_SCOPED_BADGE_CODES.has(b.code));
}

export const BADGE_REGISTRY: Record<AuditBadge['code'], BadgeRegistryEntry> = {
  modified: {
    label: 'Modified',
    tooltip: (_b, ctx) => {
      const names = ctx?.modifyingTransforms ?? [];
      if (names.length === 0) {
        return 'Transforms modified the request or response (system prompt injection or content change)';
      }
      return `Modified by: ${names.join(', ')}`;
    },
    classes: 'bg-emerald-900/20 text-emerald-300 border border-emerald-500/30',
    iconName: 'pencil',
  },
  modified_not_applied: {
    label: 'Not applied',
    tooltip: () =>
      'Policy produced a rewrite or a refusal that did not reach the wire — the submitting enforcement point is verdict-only, the analyzed answer had already reached the client, or the block was a signed thinking block the provider requires back unchanged',
    classes: 'bg-amber-900/20 text-amber-300 border border-amber-500/30',
    iconName: 'pencil',
  },
  compressed: {
    label: 'Compressed',
    tooltip: (_b, ctx) => {
      const mc = ctx?.messageCount;
      if (mc && mc.before !== mc.after) {
        return `Context compressed: ${mc.before} → ${mc.after} messages (new session baseline)`;
      }
      return 'Context-window compression engaged — turn was treated as a new session baseline';
    },
    classes: 'bg-(--warning)/10 text-(--warning) border border-(--warning)',
    iconName: 'arrowDown',
  },
  json_healed: {
    label: 'JSON Healed',
    tooltip: () => 'Upstream returned malformed JSON; the gateway repaired it before forwarding',
    classes: 'bg-(--success)/10 text-(--success) border border-(--success)',
    iconName: 'checkCircle',
  },
  tool_blocked: {
    label: 'Tool Blocked',
    tooltip: (b) => {
      if (b.code !== 'tool_blocked') return '';
      const phase = b.phase === 'request' ? 'Request' : 'Response';
      const list = b.names.length > 0 ? `: ${b.names.join(', ')}` : '';
      return `${phase}-phase tool policy blocked ${b.count} tool call(s)${list}`;
    },
    classes: 'bg-red-900/20 text-red-300 border border-red-500/30',
    iconName: 'shield',
  },
  tool_block_not_applied: {
    label: 'Would block',
    tooltip: (b) => {
      if (b.code !== 'tool_block_not_applied') return '';
      const phase = b.phase === 'request' ? 'Request' : 'Response';
      const list = b.names.length > 0 ? `: ${b.names.join(', ')}` : '';
      return `${phase}-phase tool policy would have blocked ${b.count} tool call(s)${list}, and they were not stopped: the submitting enforcement point is verdict-only, or the analyzed answer had already reached the client`;
    },
    classes: 'bg-amber-900/20 text-amber-300 border border-amber-500/30',
    iconName: 'shield',
  },
  tool_blocked_overflow: {
    label: 'Tool Block Overflow',
    tooltip: (b) => {
      if (b.code !== 'tool_blocked_overflow') return '';
      const list = b.names.length > 0 ? `: ${b.names.join(', ')}` : '';
      return `Tool block exceeded the analysis window — fail-closed dropped ${b.count} call(s)${list}`;
    },
    classes: 'bg-red-900/20 text-red-300 border border-red-500/30',
    iconName: 'alert',
  },
  block_overflow: {
    label: 'Block Overflow',
    tooltip: (b) => {
      if (b.code !== 'block_overflow') return '';
      return `${b.kind === 'text' ? 'Text' : 'Thinking'} block exceeded the buffered-event cap — ${b.count} block(s) dropped (fail-closed)`;
    },
    classes: 'bg-red-900/20 text-red-300 border border-red-500/30',
    iconName: 'alert',
  },
  script_error: {
    label: 'Script Error',
    tooltip: (b) => {
      if (b.code !== 'script_error') return '';
      const phase = b.phase === 'request' ? 'request' : 'response';
      const progs = b.programs.length > 0 ? `: ${b.programs.join(', ')}` : '';
      return `${b.count} ${phase}-phase script(s) failed in fail-closed mode${progs}`;
    },
    classes: 'bg-red-900/20 text-red-300 border border-red-500/30',
    iconName: 'alert',
  },
  protocol_translated: {
    label: 'Protocol Translated',
    tooltip: (b) => {
      if (b.code !== 'protocol_translated') return '';
      const base = `Cross-protocol translation: ${prettyProtocol(b.from)} → ${prettyProtocol(b.to)}`;
      const dropped = b.not_carried ?? [];
      return dropped.length ? `${base}. Not carried to the upstream: ${dropped.join('; ')}` : base;
    },
    classes: 'bg-zinc-800 text-zinc-300 border border-zinc-700',
    iconName: 'arrowsLR',
  },
  upstream_adapted: {
    label: 'Adapted to upstream',
    tooltip: (b) => {
      if (b.code !== 'upstream_adapted') return '';
      const api =
        b.dialect === 'mistral' ? 'Mistral' : b.dialect === 'anthropic' ? 'Anthropic' : 'OpenAI-compatible';
      const parts = [`The request was adapted to the ${api} API`];
      const adapted = b.adapted ?? [];
      const dropped = b.not_carried ?? [];
      if (adapted.length) parts.push(`Rewritten: ${adapted.join('; ')}`);
      if (dropped.length) parts.push(`Not carried to the upstream: ${dropped.join('; ')}`);
      return parts.join('. ');
    },
    classes: 'bg-(--bg-elevated) text-(--text-secondary) border border-(--border)',
    iconName: 'arrowsLR',
  },
  capability_rerouted: {
    label: 'Rerouted',
    tooltip: (b) => {
      if (b.code !== 'capability_rerouted') return '';
      return `${b.from} cannot serve this request — ${b.reason} The gateway forwarded it to the next model on this alias that can.`;
    },
    classes: 'bg-(--bg-elevated) text-(--text-secondary) border border-(--border)',
    iconName: 'compass',
  },
  catchall: {
    label: 'Catchall',
    tooltip: (_b, ctx) => {
      const c = ctx?.catchall;
      if (c && (c.method || c.path)) {
        const m = c.method ?? '?';
        const p = c.path ?? '?';
        return `Catch-all: ${m} ${p}`;
      }
      return 'Hit the catch-all proxy — request path did not match a dedicated handler';
    },
    classes: 'bg-zinc-800 text-zinc-300 border border-zinc-700',
    iconName: 'compass',
  },
  sanitized_tool_names: {
    label: 'Tool Names Sanitized',
    tooltip: (b) => {
      if (b.code !== 'sanitized_tool_names') return '';
      return `${b.count} tool name(s) rewritten before forwarding upstream`;
    },
    classes: 'bg-zinc-800 text-zinc-300 border border-zinc-700',
    iconName: 'broom',
  },
  response_sanitized_tool_names: {
    label: 'Response Tool Names Sanitized',
    tooltip: (b) => {
      if (b.code !== 'response_sanitized_tool_names') return '';
      return `${b.count} tool name(s) emitted by the model rewritten before delivery to the client (see transform_diff.injection_blocks for the original→sanitized mapping)`;
    },
    classes: 'bg-zinc-800 text-zinc-300 border border-zinc-700',
    iconName: 'broom',
  },
  agent_alert: {
    label: 'Agent Alert',
    tooltip: (b) => {
      if (b.code !== 'agent_alert') return '';
      return `Agent expert "${b.axis}" raised a ${b.level} alert`;
    },
    classes: 'bg-amber-900/20 text-amber-300 border border-amber-500/30',
    iconName: 'bell',
  },
  session_alert: {
    label: 'Session Alert',
    tooltip: (b) => {
      if (b.code !== 'session_alert') return '';
      // The session's most severe level and every expert that raised an alert
      // on it; the per-expert breakdown is in the session detail.
      return `Session alert (${b.level}, the most severe) raised by ${b.experts.join(', ')} — open the session for the per-expert breakdown`;
    },
    classes: 'bg-amber-900/20 text-amber-300 border border-amber-500/30',
    iconName: 'bell',
  },
  // MCP-specific signals. Both share the operator-attention treatment so
  // they show up alongside `tool_blocked` etc. with the same visual weight.
  mcp_rpc_error: {
    label: 'RPC Error',
    tooltip: (b) => {
      if (b.code !== 'mcp_rpc_error') return '';
      // Authoritative list lives in `crates/streamscope-proxy/src/mcp/jsonrpc.rs`
      // — keep this map in sync with the constants there.
      const codeMap: Record<number, string> = {
        [-32001]: 'route not found',
        [-32002]: 'auth mode unsupported',
        [-32003]: 'upstream error',
        [-32004]: 'tool not found',
        [-32401]: 'auth required',
        [-32429]: 'rate limited',
        [-32500]: 'upstream credential unavailable',
        [-32501]: 'user credential missing',
        [-32502]: 'user credential expired',
        [-32503]: 'user oauth refresh failed',
        [-32504]: 'oauth client not configured',
        [-32505]: 'ssrf refused',
        [-32506]: 'blocked by policy',
        [-32507]: 'upstream session lost',
        [-32600]: 'invalid request',
        [-32601]: 'method not found',
        [-32602]: 'invalid params',
        [-32603]: 'internal error',
        [-32700]: 'parse error',
      };
      const label = codeMap[b.rpc_code] ?? `code ${b.rpc_code}`;
      return `JSON-RPC error ${b.rpc_code} — ${label}`;
    },
    classes: 'bg-red-900/20 text-red-300 border border-red-500/30',
    iconName: 'alert',
  },
  mcp_legacy_sse: {
    label: 'Legacy SSE',
    tooltip: () =>
      'Upstream is using the legacy text/event-stream GET transport — has not migrated to Streamable HTTP (MCP spec 2025-03-26+)',
    classes: 'bg-zinc-800 text-zinc-300 border border-zinc-700',
    iconName: 'arrowsLR',
  },
  mcp_sampling_intercepted: {
    label: 'Sampling Intercepted',
    tooltip: () =>
      'Upstream sampling/createMessage was answered by the gateway via the LLM pipeline (auth, budgets, audit, transforms) instead of being forwarded to the agent',
    classes: 'bg-(--accent)/15 text-(--accent) border border-(--accent)',
    iconName: 'shield',
  },
  llm_synthetic_sampling: {
    label: 'Synthetic Sampling',
    tooltip: () =>
      'LLM call synthesized by the gateway in response to an MCP sampling/createMessage interception (not initiated by an upstream client)',
    classes: 'bg-(--accent)/15 text-(--accent) border border-(--accent)',
    iconName: 'shield',
  },
  // Web-search signals — emitted by the built-in `/mcp/web` virtual server
  // and (when enabled) the cross-protocol substitution loop.
  web_blocked: {
    label: 'Web Blocked',
    tooltip: () =>
      'Web-search request was blocked by tool policy before reaching the upstream search engine',
    classes: 'bg-red-900/20 text-red-300 border border-red-500/30',
    iconName: 'shield',
  },
  web_url_filtered: {
    label: 'URL Filtered',
    tooltip: (b) => {
      if (b.code !== 'web_url_filtered') return '';
      return `${b.count} fetched URL(s) dropped by the per-tenant URL filter chain (denylist / scheme / host)`;
    },
    classes: 'bg-amber-900/20 text-amber-300 border border-amber-500/30',
    iconName: 'shield',
  },
  web_all_results_filtered: {
    label: 'All Results Filtered',
    tooltip: () =>
      'Every result returned by the upstream search engine was filtered out by tenant policy — empty result list returned to the model',
    classes: 'bg-amber-900/20 text-amber-300 border border-amber-500/30',
    iconName: 'shield',
  },
  web_rate_limited: {
    label: 'Rate Limited',
    tooltip: () => 'Web-search call rejected: per-tenant rate limit exceeded',
    classes: 'bg-amber-900/20 text-amber-300 border border-amber-500/30',
    iconName: 'alert',
  },
  web_content_stripped: {
    label: 'Content Stripped',
    tooltip: (b) => {
      if (b.code !== 'web_content_stripped') return '';
      return `Web-fetch content stripped before reaching the model: ${b.reason}`;
    },
    classes: 'bg-amber-900/20 text-amber-300 border border-amber-500/30',
    iconName: 'broom',
  },
  record_stripped: {
    label: 'Record Stripped',
    tooltip: (b) => {
      if (b.code !== 'record_stripped') return '';
      const why = b.reason === 'too_deep' ? 'nested too deep' : 'too large';
      return `This record was ${why} for the gateway to deliver whole: its structured payloads (parameters, results, diffs) were not stored and long text may be replaced by a size note — identity, status, tokens and cost were kept`;
    },
    classes: 'bg-amber-900/20 text-amber-300 border border-amber-500/30',
    iconName: 'broom',
  },
  content_unavailable: {
    label: 'Content Unavailable',
    tooltip: () =>
      'Some content this request named — a conversation message, its tool definitions, its system prompt or a media file — never reached the console: the gateway could not deliver it, or the console could not store it. The request is recorded and its conversation renders without that content',
    classes: 'bg-amber-900/20 text-amber-300 border border-amber-500/30',
    iconName: 'alert',
  },
  web_ssrf_refused: {
    label: 'SSRF Refused',
    tooltip: () =>
      'Web-fetch URL pointed at a private / link-local / loopback address — refused by the SSRF guard before any network call',
    classes: 'bg-red-900/20 text-red-300 border border-red-500/30',
    iconName: 'shield',
  },
  web_scheme_refused: {
    label: 'Scheme Refused',
    tooltip: () =>
      'Web-fetch URL used a non-http(s) scheme (file:, gopher:, javascript:, …) — refused by the scheme allowlist',
    classes: 'bg-red-900/20 text-red-300 border border-red-500/30',
    iconName: 'shield',
  },
  web_substituted_server: {
    label: 'Server Tool Substituted',
    tooltip: (b) => {
      if (b.code !== 'web_substituted_server') return '';
      return `Native server-tool ${b.server_type} replaced with the gateway's filtered web executor`;
    },
    classes: 'bg-(--accent)/15 text-(--accent) border border-(--accent)',
    iconName: 'arrowsLR',
  },
  web_substituted_client: {
    label: 'Client Tool Substituted',
    tooltip: (b) => {
      if (b.code !== 'web_substituted_client') return '';
      return `Client tool ${b.client_label} routed through the gateway's filtered web executor`;
    },
    classes: 'bg-(--accent)/15 text-(--accent) border border-(--accent)',
    iconName: 'arrowsLR',
  },
  web_substitution_max_iter: {
    label: 'Substitution Max Iter',
    tooltip: () =>
      'Substitution loop hit the per-request iteration cap and stopped — final upstream output was forwarded as-is',
    classes: 'bg-amber-900/20 text-amber-300 border border-amber-500/30',
    iconName: 'alert',
  },
  web_substitution_tool_error: {
    label: 'Substitution Error',
    tooltip: () =>
      'Substituted web call returned an executor error — the model received the error and continued',
    classes: 'bg-red-900/20 text-red-300 border border-red-500/30',
    iconName: 'alert',
  },
  web_substitution_truncated_stream: {
    label: 'Substitution Truncated',
    tooltip: () =>
      'Upstream stream ended without a Done event while pending intercepts were queued — the loop forwarded the last bytes as-is and dropped the pending intercepts',
    classes: 'bg-amber-900/20 text-amber-300 border border-amber-500/30',
    iconName: 'alert',
  },
  web_substitution_mixed_pending: {
    label: 'Substitution Mixed-Pending',
    tooltip: () =>
      'One upstream turn emitted both intercepted and real tool_use blocks. The agent loop dispatched the intercepted call for audit and parked the result; the next request in the same session splices it back into history.',
    classes: 'bg-amber-900/20 text-amber-300 border border-amber-500/30',
    iconName: 'alert',
  },
  web_substitution_mixed_pending_spliced: {
    label: 'Substitution Mixed-Pending Spliced',
    tooltip: (b) => {
      if (b.code !== 'web_substitution_mixed_pending_spliced') return '';
      return `${b.count} parked mixed-pending result${b.count === 1 ? '' : 's'} from a prior request in this session were folded into the conversation as synthesised assistant tool_use → user tool_result pairs before forwarding upstream`;
    },
    classes: 'bg-emerald-900/20 text-emerald-300 border border-emerald-500/30',
    iconName: 'alert',
  },
  web_substitution_mixed_pending_splice_failed: {
    label: 'Substitution Mixed-Pending Splice Failed',
    tooltip: (b) => {
      if (b.code !== 'web_substitution_mixed_pending_splice_failed') return '';
      return `${b.count} parked mixed-pending result${b.count === 1 ? '' : 's'} were drained from the cross-request cache but could not be folded into the upstream request (translation or re-parse failed) and were dropped — see injection_blocks for the underlying error`;
    },
    classes: 'bg-red-900/20 text-red-300 border border-red-500/30',
    iconName: 'alert',
  },
  web_substitution_forward_failed: {
    label: 'Substitution Forward Failed',
    tooltip: () =>
      'Re-issuing the upstream call after a substitution round failed (transport / HTTP error / closure missing); the agent loop stopped and yielded a synthetic error marker to the client',
    classes: 'bg-red-900/20 text-red-300 border border-red-500/30',
    iconName: 'alert',
  },
  web_substitution_serialize_failed: {
    label: 'Substitution Serialize Failed',
    tooltip: () =>
      'Re-serializing the cumulative DomainRequest for the next substitution round failed; the agent loop stopped and yielded a synthetic error marker',
    classes: 'bg-red-900/20 text-red-300 border border-red-500/30',
    iconName: 'alert',
  },
  web_substitution_non_streaming: {
    label: 'Substitution Non-Streaming',
    tooltip: () =>
      'A non-streaming request matched a substitution rule, but the agent loop is streaming-only — the upstream tool_use was forwarded to the client unchanged',
    classes: 'bg-amber-900/20 text-amber-300 border border-amber-500/30',
    iconName: 'alert',
  },
  web_substitution_history_cap: {
    label: 'Substitution History Cap',
    tooltip: () =>
      'Cumulative DomainRequest body for the next substitution round exceeded web.substitution_history_max_bytes — the loop dropped its oldest tool_use/tool_result splices to bring the body under cap',
    classes: 'bg-amber-900/20 text-amber-300 border border-amber-500/30',
    iconName: 'alert',
  },
  web_substitution_cancelled: {
    label: 'Substitution Cancelled',
    tooltip: () =>
      'Substitution agent loop was cancelled mid-flight (client SSE disconnect or upstream timeout) — pending intercepted calls were dropped without dispatching, no further upstream egress was incurred',
    classes: 'bg-amber-900/20 text-amber-300 border border-amber-500/30',
    iconName: 'alert',
  },
  // Inline injection guardrail — screens untrusted web search/fetch content
  // before it is folded back into the model.
  guardrail: {
    label: 'Guardrail',
    tooltip: (b) => {
      if (b.code !== 'guardrail') return '';
      const cats = b.categories
        .map((c) => GUARDRAIL_CATEGORY_LABELS[c] ?? c)
        .join(', ');
      const verb =
        b.action === 'block'
          ? 'blocked (content stripped to a placeholder)'
          : 'flagged (content left untouched — observe mode)';
      return `Injection guardrail ${verb}: ${cats} — ${severityBucket(b.max_confidence)} confidence`;
    },
    classes: 'bg-amber-900/20 text-amber-300 border border-amber-500/30',
    iconName: 'shield',
  },
  cache_hit: {
    label: 'Cached',
    tooltip: (b) => {
      if (b.code !== 'cache_hit') return '';
      const saved = b.avoided_cost > 0
        ? ` Saved ${formatCost(b.avoided_cost)} of upstream spend.`
        : '';
      const sim = b.similarity != null
        ? ` Matched at ${(b.similarity * 100).toFixed(1)}% similarity.`
        : '';
      return `Answered from the response cache — no upstream call was made, so this request cost nothing.${saved}${sim} The stored answer was ${formatCacheAge(b.age_seconds)} old.`;
    },
    classes: 'bg-(--tag-teal-bg) text-(--tag-teal-text) border border-(--success)/30',
    iconName: 'bolt',
  },
  cache_observe_hit: {
    label: 'Cache Observed',
    tooltip: (b) => {
      if (b.code !== 'cache_observe_hit') return '';
      const sim = b.similarity != null
        ? ` at ${(b.similarity * 100).toFixed(1)}% similarity`
        : '';
      return `The cache held a ${formatCacheAge(b.age_seconds)}-old answer that would have matched this request${sim}, but the preset is in observe mode — the request went upstream and was billed normally. Switch the preset to Exact or Semantic to start serving these.`;
    },
    classes: 'bg-(--tag-blue-bg) text-(--tag-blue-text) border border-(--tag-blue-mark)/30',
    iconName: 'search',
  },
  cache_store_skipped: {
    label: 'Not Cached',
    tooltip: (b) => {
      if (b.code !== 'cache_store_skipped') return '';
      const why: Record<string, string> = {
        tool_calls: 'the response contains tool calls, which the cache does not store',
        generated_media: 'the response contains generated media, which the cache does not store',
        error_status: 'the request ended in an error',
        incomplete_response: 'the response was cut short (client disconnect or stream timeout)',
        zero_completion: 'the upstream returned no completion tokens',
        empty_response: 'the response had no text content',
        unrenderable_response:
          'the response text could not be read back reliably, so replaying it could have altered it',
        multi_choice:
          'the response contains more than one alternative answer, which the cache does not store',
        entry_too_large: 'the response exceeds the tenant\'s maximum cached entry size',
        cache_full: 'this edge replica\'s cache is at its memory ceiling',
        client_bypass: 'the client sent Cache-Control: no-cache',
      };
      return `This response was not stored in the cache because ${why[b.reason] ?? b.reason}.`;
    },
    classes: 'bg-(--bg-elevated) text-(--text-secondary) border border-(--border)',
    iconName: 'info',
  },
  cache_semantic_skipped: {
    label: 'No Similarity Match',
    tooltip: (b) => {
      if (b.code !== 'cache_semantic_skipped') return '';
      const why: Record<string, string> = {
        no_embedding_alias:
          'no embedding alias is configured — set one under Settings → Response Cache',
        embedding_alias_unresolved:
          'the configured embedding alias is not one this key can reach',
        embedding_failed: 'the embedding model did not return a usable vector',
        embedding_timeout: 'the embedding model did not answer within the time limit',
      };
      return `This alias is set to Semantic, but prompts could not be compared by meaning because ${why[b.reason] ?? b.reason}. The request was answered normally, and word-for-word cache matching still applied.`;
    },
    classes: 'bg-(--tag-amber-bg) text-(--tag-amber-text) border border-(--warning)/30',
    iconName: 'alert',
  },
  queued: {
    label: 'Queued',
    tooltip: (b) => {
      if (b.code !== 'queued') return '';
      const seconds = b.wait_ms / 1000;
      const waited = seconds >= 1 ? `${seconds.toFixed(1)}s` : `${b.wait_ms}ms`;
      return `The model had no capacity free, so the gateway held this request for ${waited} before sending it. For a request then served, that wait is part of its latency; it is never the model's own time — it is time spent waiting for a turn, ahead of other callers or behind them depending on the request's priority class.`;
    },
    classes: 'bg-(--tag-blue-bg) text-(--tag-blue-text) border border-(--accent)/30',
    iconName: 'clock',
  },
  spilled: {
    label: 'Moved replica',
    tooltip: () =>
      'The replica this request was routed to had no room — under gateway-managed QoS, not even after the few seconds a request waits for its own replica — so the gateway sent it to another replica of the same model instead. The answer is the same — this is not a failover to a different provider — but a session pinned to a replica for its prompt cache loses that cache for this turn, and a fleet doing this constantly is a fleet that needs more capacity.',
    classes: 'bg-(--tag-blue-bg) text-(--tag-blue-text) border border-(--accent)/30',
    iconName: 'refresh',
  },
  unpriced: {
    label: 'Unpriced',
    tooltip: () =>
      'Something this request consumed had no rate, or its cost could not be stated in the accounting currency — so the recorded cost is a floor of zero, which is not the same as free. A zero-cost request never accrues against a budget, so any budget covering it will not enforce. Set a price list on the model under its provider (or link it to a catalog entry), and add a conversion rate under Settings → Accounting for any currency it is priced in.',
    classes: 'bg-(--tag-amber-bg) text-(--tag-amber-text) border border-(--warning)/30',
    iconName: 'alert',
  },
  guardrail_error: {
    label: 'Guardrail Error',
    tooltip: (b) => {
      if (b.code !== 'guardrail_error') return '';
      // An incomplete scan is not a detector failure: the detector answered, but
      // only over part of the content (window cap, empty extraction, truncated
      // stream capture), so the rest was never screened either way.
      if (b.reason === 'incomplete_scan') {
        return 'Injection guardrail could not screen the content in full — it exceeded the scan window cap, yielded no readable text, or was captured only in part. The unscreened remainder was never classified: in observe mode it was delivered and only recorded; in enforce mode the per-profile fail-mode decided whether it passed.';
      }
      return `Injection guardrail detector errored (${b.reason}) — fail-mode decided the outcome; content went unscored`;
    },
    classes: 'bg-red-900/20 text-red-300 border border-red-500/30',
    iconName: 'alert',
  },
};

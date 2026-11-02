// Upstream servers and their replica endpoints: the decisions the pages make
// about them — which status an endpoint and a server show, what the dashboard's
// health tile says, where an endpoint moves in the order, what a membership
// cell says, and how a removal preview reads.
import type { components } from '#lib/generated/api-types.js';
import type { IconName, Tone } from '#lib/icons.js';

type Endpoint = components['schemas']['EndpointResponse'];
type Cell = components['schemas']['MembershipCell'];
type Removal = components['schemas']['EndpointRemovalResponse'];

export type EndpointStatus = 'disabled' | 'breaker_open' | 'discovery_failed' | 'healthy';

/** One status per endpoint, the one an operator must act on first: taken out
 *  by an operator, then taken out by a gateway's breaker, then a failed
 *  discovery (traffic still flows — its models are kept), then healthy. */
export function endpointStatus(e: Pick<Endpoint, 'enabled' | 'health' | 'last_discovery'>): EndpointStatus {
  if (!e.enabled) return 'disabled';
  if (e.health.status === 'breaker_open') return 'breaker_open';
  if (e.last_discovery && !e.last_discovery.ok) return 'discovery_failed';
  return 'healthy';
}

/** How each status reads: an icon AND a word AND a tone, never colour alone. */
export const ENDPOINT_STATUS: Record<EndpointStatus, { label: string; icon: IconName; tone: Tone }> = {
  healthy: { label: 'Healthy', icon: 'checkCircle', tone: 'success' },
  breaker_open: { label: 'Breaker open', icon: 'errorCircle', tone: 'error' },
  discovery_failed: { label: 'Discovery failed', icon: 'triangleAlert', tone: 'warning' },
  disabled: { label: 'Disabled', icon: 'blocked', tone: 'neutral' },
};

type ServerHealth = components['schemas']['ServerHealth'];
type AttentionUpstreams = components['schemas']['AttentionUpstreams'];

/** How a server's health reads, as the connected gateways report it. */
export const SERVER_HEALTH: Record<ServerHealth, { label: string; icon: IconName; tone: Tone }> = {
  healthy: { label: 'Healthy', icon: 'checkCircle', tone: 'success' },
  degraded: { label: 'Degraded', icon: 'triangleAlert', tone: 'warning' },
  down: { label: 'Down', icon: 'errorCircle', tone: 'error' },
  disabled: { label: 'Disabled', icon: 'blocked', tone: 'neutral' },
};

/** Fleet order: the servers an operator must act on first — down, then
 *  degraded — then by traffic, busiest first, then by name. Disabled servers
 *  go last: they take no traffic by an operator's choice. */
export function fleetOrder<T extends { health: ServerHealth; requests: number; name: string }>(rows: readonly T[]): T[] {
  const rank: Record<ServerHealth, number> = { down: 0, degraded: 1, healthy: 2, disabled: 3 };
  return [...rows].sort(
    (a, b) => rank[a.health] - rank[b.health] || b.requests - a.requests || a.name.localeCompare(b.name),
  );
}

/** A pass-through (BYOK) server — or the provider linked to one — that is
 *  turned off. It does not exist for the gateway, so the console leaves it out
 *  wherever it would be used or granted; it is switched on from the Upstream
 *  list. */
export function isOffPassthrough(x: { byok: boolean; enabled: boolean }): boolean {
  return x.byok && !x.enabled;
}

/** Why a server reads the way it does, for its chip's tooltip. `null` when
 *  there is nothing to explain. */
export function serverHealthReason(s: { health: ServerHealth; endpoints_down: number }): string | null {
  switch (s.health) {
    case 'down':
      return 'Every enabled endpoint is out of rotation on every gateway that routes to it';
    case 'degraded':
      return `${s.endpoints_down} endpoint${s.endpoints_down === 1 ? '' : 's'} out of rotation on a connected gateway — the others carry the traffic`;
    case 'disabled':
      return 'Turned off by an operator';
    case 'healthy':
      return null;
  }
}

/** What a server — or one of its endpoints — was actually sent: its attempts
 *  less the ones its pool refused. A refusal is not a failure, so a failure or
 *  wait share is taken over this, never over the attempts. An endpoint has no
 *  refusals (a refused attempt reached none), so its sent is its attempts. */
export function sentOf(t: { requests: number; refusals: number }): number {
  return Math.max(0, t.requests - t.refusals);
}

export type AttentionSeverity = 'critical' | 'warning' | 'info' | 'ok';

/** The dashboard's Upstream health tile. Critical while a server can serve
 *  nothing (every enabled endpoint out of rotation); a warning while one is
 *  degraded, capacity ran out, or an engine the gateway reads went quiet; ok
 *  otherwise. The count is the servers that are not whole. A single down server
 *  opens its own page — that is where the operator acts — anything else the
 *  fleet list. Paths are tenant-relative. */
export function upstreamAttention(u: AttentionUpstreams): {
  count: number;
  severity: AttentionSeverity;
  subtitle: string;
  href: string;
} {
  const severity: AttentionSeverity =
    u.down > 0 ? 'critical' : u.degraded > 0 || u.refused > 0 || u.engines_silent > 0 ? 'warning' : 'ok';
  const parts: string[] = [];
  if (u.down > 0) parts.push(`${u.down} down`);
  if (u.degraded > 0) parts.push(`${u.degraded} degraded`);
  if (u.refused > 0) parts.push(`${u.refused} refused`);
  if (u.engines_silent > 0) parts.push(`${u.engines_silent} engine${u.engines_silent === 1 ? '' : 's'} silent`);
  const subtitle =
    parts.length > 0
      ? parts.join(' · ')
      : `${u.servers_total} server${u.servers_total === 1 ? '' : 's'} healthy`;
  const href = u.down_server_id ? `/dashboard/servers/${u.down_server_id}` : '/dashboard/servers';
  return { count: u.down + u.degraded, severity, subtitle, href };
}

/** The order after moving `id` one place (`delta` -1 = up, +1 = down), or
 *  null when it is already at that end or not in the list. */
export function moveEndpoint(ids: readonly string[], id: string, delta: -1 | 1): string[] | null {
  const from = ids.indexOf(id);
  const to = from + delta;
  if (from < 0 || to < 0 || to >= ids.length) return null;
  const next = [...ids];
  [next[from], next[to]] = [next[to], next[from]];
  return next;
}

export type CellGlyph = 'listed' | 'assumed' | 'not_served' | 'missing';

/** What a membership cell shows. An endpoint that answered "model not found"
 *  for the model since its last discovery answer is flagged whatever the
 *  membership claims — the claim is what that answer contradicts. */
export function cellGlyph(c: Pick<Cell, 'state' | 'model_missing_reports'>): CellGlyph {
  if ((c.model_missing_reports ?? 0) > 0) return 'missing';
  return c.state;
}

/** The sentence a removal preview shows. */
export function removalSummary(r: Pick<Removal, 'retired_models' | 'routes_deleted' | 'routes_disabled'>, url: string): string {
  if (r.retired_models.length === 0) {
    return `Remove ${url}? Every model it serves is also served by another endpoint, so nothing is retired.`;
  }
  const names = r.retired_models.join(', ');
  const parts = [`Remove ${url}? It is the only endpoint serving ${names}, which will be retired`];
  if (r.routes_disabled > 0) {
    parts.push(`${r.routes_disabled} hand-built route${r.routes_disabled === 1 ? '' : 's'} will be disabled and flagged`);
  }
  if (r.routes_deleted > 0) {
    parts.push(`${r.routes_deleted} automatic route${r.routes_deleted === 1 ? '' : 's'} removed`);
  }
  return `${parts.join('; ')}.`;
}

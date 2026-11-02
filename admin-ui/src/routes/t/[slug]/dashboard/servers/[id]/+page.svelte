<script lang="ts">
  // One LLM upstream server: can it serve now, what did it handle, how fast,
  // who waited for it and why requests were refused — and, where the gateway
  // gates it, its live load per endpoint. Health and configuration come from
  // the server and endpoint resources; the figures from
  // /analytics/servers/{id}; class names from the tenant's classes. All joined
  // by id — nothing here re-derives what those resources already say.
  import { untrack } from 'svelte';
  import { adminApi } from '#lib/api-client.js';
  import { extractError, extractErrorCode } from '#lib/api-helpers.js';
  import type { components } from '#lib/generated/api-types.js';
  import { consoleScope, currentWorkspaceQuery, currentPeriodQuery } from '#lib/scope.svelte.js';
  import { onRefresh, usePeriodicLoad } from '#lib/hooks.svelte.js';
  import { refreshCycle } from '#lib/refreshCycle.svelte.js';
  import { thref } from '#lib/tenant.js';
  import { formatCount, formatDuration, formatShare, formatTokens } from '#lib/formatters.js';
  import { ENDPOINT_STATUS, SERVER_HEALTH, endpointStatus, sentOf, serverHealthReason } from '#lib/endpoints.js';
  import DashboardScaffold from '#lib/components/dashboard/DashboardScaffold.svelte';
  import MetricCard from '#lib/components/dashboard/MetricCard.svelte';
  import MetricGrid from '#lib/components/dashboard/MetricGrid.svelte';
  import Panel from '#lib/components/dashboard/Panel.svelte';
  import BreakdownPanel from '#lib/components/dashboard/BreakdownPanel.svelte';
  import TimeSeriesChart, { type ChartRow, type ChartSeries } from '#lib/components/charts/TimeSeriesChart.svelte';
  import LiveHistoryChart from '#lib/components/charts/LiveHistoryChart.svelte';
  import { chartHasValue, seriesColor } from '#lib/chartHelpers.js';
  import StatusChip from '#lib/components/StatusChip.svelte';
  import LimitMeter from '#lib/components/limits/LimitMeter.svelte';
  import Copyable from '#lib/components/Copyable.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import { ADAPTIVE_STATE, SCHEDULER_STATE, schedulerState } from '#lib/qos.js';
  import type { PageProps } from './$types';

  let { params }: PageProps = $props();

  type Server = components['schemas']['ServerDetailResponse'];
  type Endpoint = components['schemas']['EndpointResponse'];
  type Dashboard = components['schemas']['ServerDashboardResponse'];
  type QosClass = components['schemas']['QosClass'];

  const REFUSAL_LABEL: Record<string, string> = {
    shed: 'Shed (class not queued)',
    queue_timeout: 'Waited past its deadline',
    gateway_saturated: 'Gateway holding its maximum',
    shutting_down: 'Gateway replica shutting down',
    superseded: 'Sent again while waiting',
  };

  let slug = $derived(params.slug);
  let serverId = $derived(params.id);

  let server = $state<Server | null>(null);
  let endpoints = $state<Endpoint[]>([]);
  let dash = $state<Dashboard | null>(null);
  let classes = $state<QosClass[]>([]);
  let loading = $state(true);
  let error = $state('');
  let notFound = $state(false);

  // The route param can change under a mounted page (history, a link from one
  // server's page to another): reload for the new id, and drop the old one's
  // figures rather than show them under the new URL. A plain variable, so the
  // effect below tracks only the param.
  let loadedFor = '';
  let loadGen = 0;
  $effect(() => {
    const id = serverId;
    if (loadedFor && id !== loadedFor) void load();
  });

  async function load() {
    const id = serverId;
    const gen = ++loadGen;
    if (id !== loadedFor) {
      server = null;
      dash = null;
      endpoints = [];
    }
    loadedFor = id;
    loading = true;
    error = '';
    const [s, e, d, c] = await Promise.all([
      adminApi.GET('/api/v1/admin/servers/{id}', { params: { path: { id } } }),
      adminApi.GET('/api/v1/admin/servers/{id}/endpoints', { params: { path: { id }, query: { limit: 500 } } }),
      adminApi.GET('/api/v1/admin/analytics/servers/{id}', {
        params: { path: { id }, query: { ...currentPeriodQuery(), ...currentWorkspaceQuery() } },
      }),
      adminApi.GET('/api/v1/admin/qos-classes', {}),
    ]);
    // A newer load (another id, or the next tick) owns the page now.
    if (gen !== loadGen) return;
    notFound = extractErrorCode(s.error) === 'server_not_found';
    // Every fetch that fails says so: an empty endpoint list or unnamed classes
    // shown as facts would be wrong facts, not a missing view.
    const failed = [s.error, e.error, d.error, c.error].find((x) => x != null);
    error = failed && !notFound ? extractError(failed) : '';
    if (!s.error) server = s.data ?? null;
    if (!e.error) endpoints = e.data?.items ?? [];
    if (!d.error) dash = d.data ?? null;
    if (!c.error) classes = c.data?.items ?? [];
    loading = false;
  }

  usePeriodicLoad(load);

  // ── The last minutes ─────────────────────────────────────────────────
  // Independent of the period: it always ends now. Read on load and on every
  // refresh; while auto-refresh is on, also polled once per bucket — two
  // gateway heartbeats, the grain the figures change at — while the tab is
  // visible. With auto-refresh off nothing on the page moves on its own. A
  // tick whose server changed under it is dropped. A failed tick keeps the
  // last figures, so one dropped request does not blank the cards, and is
  // said on the recent panes — never read as "no reading".
  type Recent = components['schemas']['ServerRecentLoadResponse'];
  let recent = $state<Recent | null>(null);
  let recentLoading = $state(true);
  let recentError = $state('');
  let recentFor = '';
  let recentInFlight = false;
  let recentAgain = false;
  /** Seconds until the next poll: the bucket, within 5 s – 60 s. */
  let recentEvery = 10;
  const RECENT_TIMEOUT_MS = 10_000;
  /** `asked`: a refresh or a new server — queued behind a read in flight, so
   *  it is never lost. A poll tick is not: one in flight already answers it. */
  async function loadRecent(asked: boolean) {
    const id = serverId;
    // Clearing on a server change is the poll effect's; an answer for another
    // server than the page's is dropped on arrival.
    if (!id) return;
    if (recentInFlight) {
      if (asked) recentAgain = true;
      return;
    }
    recentInFlight = true;
    try {
      // Bounded: a request that never answers would hold every later tick
      // back (one at a time) and never say so.
      const { data, error: e } = await adminApi.GET('/api/v1/admin/analytics/servers/{id}/recent-load', {
        params: { path: { id } },
        signal: AbortSignal.timeout(RECENT_TIMEOUT_MS),
      });
      if (id !== serverId) return;
      if (!e && data) {
        recent = data;
        recentEvery = Math.min(60, Math.max(5, data.bucket_secs));
      }
      recentError = e ? extractError(e) : '';
      recentLoading = false;
    } finally {
      recentInFlight = false;
      // The server changed while this one was in flight (its answer was
      // dropped), or a read was asked for meanwhile: read now, not at the
      // next tick.
      if (id !== serverId || recentAgain) {
        recentAgain = false;
        readRecent(true);
      }
    }
  }
  // Only where a recent pane is drawn: the load cards show for a server the
  // gateway gates or whose engines it reads (`observed`, which itself reads
  // `recent` — so this keys on what does not).
  const pollRecent = $derived((server?.gated ?? false) || (server?.engine_metrics ?? false) || (dash?.load_series.length ?? 0) > 0);
  /** An abort or a throw is one lost read, never the end of the poll — and a
   *  failure, not a load still under way. */
  const readRecent = (asked: boolean) =>
    void loadRecent(asked).catch((e: unknown) => {
      recentError = extractError(e);
      recentLoading = false;
    });
  // A new server drops the previous one's figures at once, whether or not
  // this one is read: they must never stand under another server's URL. Its
  // first read happens as soon as it has a recent pane to draw.
  $effect(() => {
    if (serverId !== recentFor) {
      recent = null;
      recentLoading = true;
      recentError = '';
      recentFor = serverId;
    }
    if (pollRecent) untrack(() => readRecent(true));
  });
  // Every refresh re-reads — asked for, so whether or not the tab shows.
  onRefresh(() => {
    if (pollRecent) readRecent(true);
  });
  // While auto-refresh runs, also once per bucket while the tab is visible.
  // Switching it on, and coming back to the tab once a tick fell due, are
  // refreshes themselves (read above), so the poll adds no read of its own
  // for either.
  $effect(() => {
    if (!pollRecent || !refreshCycle.autoRefreshing) return;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = () => {
      if (document.visibilityState === 'visible') readRecent(false);
      timer = setTimeout(tick, recentEvery * 1000);
    };
    timer = setTimeout(tick, recentEvery * 1000);
    return () => clearTimeout(timer);
  });

  const hourly = $derived(dash?.interval === 'hour');
  const t = $derived(dash?.traffic);
  const live = $derived(dash?.live ?? null);
  // "Now" — on the cards, beside the recent charts and in the endpoints table —
  // is the recent poll's own, so it moves with them; the page's last full load
  // stands in only until the first poll answers. Once it has, its answer
  // stands, "no gateway reporting" included. While the poll is failing, the
  // fresher of its last answer and the page's own load stands — by when each
  // was read — and every place that shows "now" says it may be stale. ONE
  // choice, read by the cards, the chart titles and the endpoints table alike.
  const nowFromRecent = $derived.by(() => {
    if (!recent) return false;
    if (!recentError) return true;
    const polled = recent.live?.sampled_at;
    const loaded = live?.sampled_at;
    return polled != null && (loaded == null || polled >= loaded);
  });
  const nowLive = $derived(nowFromRecent ? (recent?.live ?? null) : live);
  const nowStale = $derived(recentError !== '' && recent != null);
  const gated = $derived(server?.gated ?? false);
  const className = (id: string | null | undefined) =>
    id ? (classes.find((c) => c.id === id)?.name ?? 'Removed class') : 'No class';
  const endpointById = $derived(new Map(endpoints.map((e) => [e.id, e])));
  // An endpoint is named by its host (and port); its path joins in only when
  // two endpoints share a host — a legend of full URLs reads as noise.
  const hostOf = (u: string) => {
    try {
      return new URL(u).host;
    } catch {
      return u.replace(/^https?:\/\//, '');
    }
  };
  const sharedHosts = $derived.by(() => {
    const seen = new Map<string, number>();
    for (const e of endpoints) seen.set(hostOf(e.url), (seen.get(hostOf(e.url)) ?? 0) + 1);
    return new Set([...seen].filter(([, n]) => n > 1).map(([h]) => h));
  });
  const endpointLabel = (id: string, url?: string | null) => {
    const u = endpointById.get(id)?.url ?? url ?? id;
    const host = hostOf(u);
    return sharedHosts.has(host) ? u.replace(/^https?:\/\//, '') : host;
  };
  /** The per-replica in-flight limit an endpoint is held to, and whose it is:
   *  the endpoint's own, else the server's — the order the gateway applies. */
  function limitOf(id: string): { perReplica: number; source: 'endpoint' | 'server' } | null {
    const own = endpointById.get(id)?.max_in_flight;
    if (own != null) return { perReplica: own, source: 'endpoint' };
    return server?.max_in_flight != null ? { perReplica: server.max_in_flight, source: 'server' } : null;
  }
  /** The engine-queue bound an endpoint is held to, and whose it is. */
  function queueBoundOf(id: string): { value: number; source: 'endpoint' | 'server' } | null {
    const own = endpointById.get(id)?.waiting_threshold;
    if (own != null) return { value: own, source: 'endpoint' };
    return server?.waiting_threshold != null ? { value: server.waiting_threshold, source: 'server' } : null;
  }

  const cards = $derived([
    {
      label: 'Requests',
      period: `${consoleScope.periodDays}d`,
      value: t ? formatCount(t.requests) : '--',
      subtitle: t ? `${formatTokens(t.prompt_tokens)} in · ${formatTokens(t.completion_tokens)} out` : undefined,
      icon: 'requests' as const,
      trendValue: t?.requests,
    },
    {
      label: 'Failed',
      period: `${consoleScope.periodDays}d`,
      // Of what was sent: a refusal is not a failure.
      value: t ? formatShare(t.errors, sentOf(t)) : '--',
      subtitle: t
        ? `${formatCount(t.errors)} failed${t.failed_over > 0 ? ` (${formatCount(t.failed_over)} failed over)` : ''} · ${formatCount(t.refusals)} refused${t.passed_on > 0 ? ` (${formatCount(t.passed_on)} moved on)` : ''}`
        : undefined,
      icon: 'reliability' as const,
      valueColor: t && t.errors > 0 ? 'var(--error)' : undefined,
      // No link: the count leaves refusals out, and the audit list has no
      // filter for "every error but a refusal".
      trendValue: t?.errors,
    },
    {
      label: 'Upstream latency P50',
      period: `${consoleScope.periodDays}d`,
      value: t?.latency_p50_ms != null ? formatDuration(t.latency_p50_ms) : '--',
      // `null` means no request succeeded — there is nothing to measure, which
      // is not a fast server.
      subtitle: `P95 ${t?.latency_p95_ms != null ? formatDuration(t.latency_p95_ms) : '--'} · P99 ${t?.latency_p99_ms != null ? formatDuration(t.latency_p99_ms) : '--'}`,
      subtitle2: t?.ttft_p95_ms != null ? `TTFT P95 ${formatDuration(t.ttft_p95_ms)} · excludes the wait` : 'Excludes the wait for capacity',
      icon: 'clock' as const,
      // The chip sits beside the P50 figure, so it follows P50.
      trendValue: t?.latency_p50_ms ?? undefined,
    },
    {
      label: 'Waited for capacity',
      period: `${consoleScope.periodDays}d`,
      value: t ? formatShare(t.queued, sentOf(t)) : '--',
      subtitle: t?.queue_wait_p95_ms != null
        ? `P50 ${t.queue_wait_p50_ms != null ? formatDuration(t.queue_wait_p50_ms) : '--'} · P95 ${formatDuration(t.queue_wait_p95_ms)}`
        : 'No request waited',
      subtitle2: t ? `${formatCount(t.queued)} requests · ${formatCount(t.spilled)} moved replica` : undefined,
      icon: 'clock' as const,
      iconTone: 'warning' as const,
      trendValue: t?.queued,
    },
    {
      label: 'In flight now',
      value: nowLive?.gated ? formatCount(nowLive.in_flight) : '--',
      subtitle: nowLive?.gated
        ? `${nowLive.capacity != null ? `of ${formatCount(nowLive.capacity)} slots · ` : ''}${formatCount(nowLive.held)} held`
        : nowLive
          ? 'Not gated — engines read for the charts only'
          : gated
          ? 'No reading from a gateway lately'
          : 'Not gated — no bound is set',
      subtitle2: nowStale
        ? 'Stale — the last update failed'
        : nowLive
          ? `${nowLive.replicas} gateway replica${nowLive.replicas === 1 ? '' : 's'} reporting`
          : undefined,
      icon: 'bolt' as const,
      valueColor: nowLive?.gated && nowLive.capacity != null && nowLive.in_flight >= nowLive.capacity ? 'var(--warning)' : undefined,
    },
  ]);

  // ── Traffic over the period ──────────────────────────────────────────
  const trafficRows = $derived<ChartRow[]>(
    (dash?.bucket_starts ?? []).map((ts, i) => {
      const b = dash?.series[i];
      return {
        timestamp: new Date(ts),
        requests: b?.requests ?? 0,
        errors: b?.errors ?? 0,
        refusals: b?.refusals ?? 0,
        queued: b?.queued ?? 0,
        // An empty bucket reads 0, as on the LLM dashboard: a line that breaks
        // on every quiet hour reads as missing data.
        latency: b?.latency_p95_ms ?? 0,
        ttft: b?.ttft_p95_ms ?? 0,
        wait: b?.queue_wait_p95_ms ?? 0,
      };
    }),
  );
  const TRAFFIC_SERIES: ChartSeries[] = [
    { key: 'requests', label: 'Requests', color: 'var(--accent)', fill: true },
    { key: 'queued', label: 'Waited', color: 'var(--warning)', width: 1.5 },
    { key: 'refusals', label: 'Refused', color: 'var(--chart-2)', width: 1.5, dashArray: '4,3' },
    { key: 'errors', label: 'Failed', color: 'var(--error)', width: 1.5 },
  ];
  const LATENCY_SERIES: ChartSeries[] = [
    { key: 'latency', label: 'Latency P95', color: 'var(--warning)' },
    { key: 'ttft', label: 'TTFT P95', color: 'var(--success)' },
    { key: 'wait', label: 'Wait P95', color: 'var(--text-secondary)', dashArray: '4,3' },
  ];

  // ── Load, one series per endpoint, at two time scales ────────────────
  // Every gauge is plotted as each bucket's PEAK — gateways report the highest
  // value since their previous heartbeat, and a bucket's mean would dilute a
  // burst by the bucket's length — with the mean beside it in the tooltip.
  // Each gauge card holds the last minutes (`recent`, polled) beside the
  // period (`dash`), one colour per endpoint across both.
  type Gauges = components['schemas']['EndpointGaugeSeries'];
  type GaugeKey = 'in_flight' | 'engine_waiting' | 'engine_running' | 'engine_kv_usage';
  // In the server's own endpoint order, then any endpoint it no longer lists:
  // a colour stays with its endpoint as the recent window's set changes.
  // Joined into a string, so what follows recomputes only when the SET of
  // endpoints changes — not on every poll that returns the same ones.
  // The colour index is the endpoint's place among ALL the server's endpoints
  // (then any it no longer lists), never among those that reported — so one
  // starting or stopping to report recolours no other.
  const gaugeEndpointKey = $derived.by(() => {
    const reported = new Set([...(dash?.load_series ?? []), ...(recent?.load_series ?? [])].map((s) => s.endpoint_id));
    const configured = endpoints.map((e) => e.id);
    return JSON.stringify({
      order: [...configured, ...[...reported].filter((id) => !configured.includes(id)).sort()],
      reported: [...reported].sort(),
    });
  });
  const loadSeriesDefs = $derived.by(() => {
    const { order, reported } = JSON.parse(gaugeEndpointKey) as { order: string[]; reported: string[] };
    return order
      .map((id, i) => ({ id, key: `e${i}`, label: endpointLabel(id), color: seriesColor(i) }))
      .filter((d) => reported.includes(d.id));
  });
  const gaugeEndpoints = $derived(loadSeriesDefs.map((d) => d.id));
  /** The peak lines, then their means as tooltip-only lines. */
  function gaugeSeries(defs: typeof loadSeriesDefs, extra: ChartSeries[] = []): ChartSeries[] {
    const peaks = defs.map((d) => ({ key: d.key, label: d.label, color: d.color }));
    const means = defs.map((d) => ({ key: `${d.key}m`, label: `${d.label} · mean`, color: d.color, tooltipOnly: true }));
    return [...peaks, ...extra, ...means];
  }
  /** One row per bucket of `axis`, one peak and one mean per endpoint. The
   *  gateway's own counts (`zero`) read 0 in a bucket with no sample, like any
   *  other count here; an engine's gauges keep the gap — an engine not heard
   *  from is not idle. */
  function gaugeRows(axis: string[], series: Gauges[], key: GaugeKey, { zero = false }: { zero?: boolean } = {}): ChartRow[] {
    const meanKey = `${key}_mean` as const;
    return axis.map((ts, i) => {
      const row: ChartRow = { timestamp: new Date(ts) };
      for (const s of series) {
        const d = loadSeriesDefs.find((x) => x.id === s.endpoint_id);
        if (!d) continue;
        row[d.key] = s[key][i] ?? (zero ? 0 : null);
        row[`${d.key}m`] = s[meanKey][i] ?? (zero ? 0 : null);
        // What the gateways let through to it, where that is learned: a gap
        // where it is not, never a zero limit.
        if (key === 'in_flight') row[`${d.key}l`] = s.learned_limit[i] ?? null;
      }
      return row;
    });
  }
  const historyRows = (key: GaugeKey, opts?: Parameters<typeof gaugeRows>[3]) =>
    gaugeRows(dash?.bucket_starts ?? [], dash?.load_series ?? [], key, opts);
  const recentRows = (key: GaugeKey, opts?: Parameters<typeof gaugeRows>[3]) =>
    gaugeRows(recent?.bucket_starts ?? [], recent?.load_series ?? [], key, opts);
  /** Two row sets on one axis as one: `b`'s keys renamed with `suffix`, so a
   *  card can draw two figures per endpoint (running and waiting, say). */
  function pairRows(a: ChartRow[], b: ChartRow[], suffix: string): ChartRow[] {
    return a.map((row, i) => {
      const out: ChartRow = { ...row };
      for (const [k, v] of Object.entries(b[i] ?? {})) {
        if (k !== 'timestamp') out[`${k}${suffix}`] = v as number | null;
      }
      return out;
    });
  }
  type LoadSeries = components['schemas']['EndpointLoadSeries'];
  type Side = 'recent' | 'history';
  /** One of the engine's counter-derived series, one per endpoint (gaps
   *  kept), for the last minutes (`recent`) or the period (`dash`). */
  function counterRows(side: Side, pick: (s: LoadSeries, i: number) => number | null | undefined): ChartRow[] {
    const src = side === 'recent' ? recent : dash;
    return (src?.bucket_starts ?? []).map((ts, i) => {
      const row: ChartRow = { timestamp: new Date(ts) };
      for (const s of src?.load_series ?? []) {
        const d = loadSeriesDefs.find((x) => x.id === s.endpoint_id);
        if (d) row[d.key] = pick(s, i) ?? null;
      }
      return row;
    });
  }
  /** Whether a pane holds a value of `pick`; `positive` asks for one above
   *  zero, for a card that would otherwise hold only zeros. */
  const paneHas = (side: Side, pick: (s: LoadSeries) => (number | null)[], positive = false) =>
    ((side === 'recent' ? recent : dash)?.load_series ?? []).some((s) =>
      pick(s).some((v) => v != null && (!positive || v > 0)),
    );
  const eitherHas = (pick: (s: LoadSeries) => (number | null)[], positive = false) =>
    paneHas('recent', pick, positive) || paneHas('history', pick, positive);
  const reads = (series: Gauges[] | undefined, key: GaugeKey) =>
    (series ?? []).some((s) => s[key].some((v) => v != null));
  const anyReading = (key: GaugeKey) => reads(dash?.load_series, key) || reads(recent?.load_series, key);
  /** Whether each pane has a reading of its own — never the other pane's. */
  const recentReads = (key: GaugeKey) => reads(recent?.load_series, key);
  const periodReads = (key: GaugeKey) => reads(dash?.load_series, key);
  const recentHasLoad = $derived((recent?.load_series.length ?? 0) > 0);
  const periodHasLoad = $derived((dash?.load_series.length ?? 0) > 0);
  const hasLoadHistory = $derived(gaugeEndpoints.length > 0);
  // Only endpoints the gateway counts: one read only for its engine metrics
  // has no in-flight series at all, which is not the same as none in flight.
  const allGauges = $derived([...(dash?.load_series ?? []), ...(recent?.load_series ?? [])]);
  /** The endpoints with any reading of `pick`, as a joined string: what is
   *  built from it recomputes only when the SET changes, not on every poll. */
  const idsWith = (pick: (s: Gauges) => (number | null)[]) =>
    [...new Set(allGauges.filter((s) => pick(s).some((v) => v != null)).map((s) => s.endpoint_id))].sort().join(',');
  const learnedKey = $derived(idsWith((s) => s.learned_limit));
  const inFlightKey = $derived(idsWith((s) => s.in_flight));
  const engineKey = $derived(idsWith((s) => s.engine_waiting));
  const learnedDefs = $derived(loadSeriesDefs.filter((d) => learnedKey.split(',').includes(d.id)));
  const inFlightSeries = $derived(
    gaugeSeries(
      loadSeriesDefs.filter((d) => inFlightKey.split(',').includes(d.id)),
      // The learned (dynamic) limit, in its endpoint's colour, dashed.
      learnedDefs.map((d) => ({ key: `${d.key}l`, label: `${d.label} · learned limit`, color: d.color, dashArray: '6,4', width: 1.5 })),
    ),
  );
  /** Rules for the values the gateway applies now, dotted: per endpoint, its
   *  fixed in-flight limit across the replicas reporting (the series sums them)
   *  — its own, else the server's, and the label says which. A learned limit is
   *  its own dashed line instead. */
  const inFlightReferences = $derived(
    loadSeriesDefs.flatMap((d) => {
      const now = liveEndpoints.find((e) => e.endpoint_id === d.id)?.live;
      const limit = limitOf(d.id);
      if (!now?.gated || now.adaptive || !limit) return [];
      const total = limit.perReplica * now.replicas;
      const many = loadSeriesDefs.length > 1 ? `${d.label}: ` : '';
      const split = now.replicas > 1 ? ` (${formatCount(limit.perReplica)} × ${now.replicas} gateways)` : '';
      return [{
        value: total,
        label: `${many}limit ${formatCount(total)}${split} · ${limit.source}`,
        short: `limit ${formatCount(total)}`,
        color: d.color,
      }];
    }),
  );
  /** The engine-queue bound each engine is held to: shared by every replica,
   *  so drawn as is. */
  const queueReferences = $derived.by(() =>
    engineDefs.flatMap((d) => {
      const bound = queueBoundOf(d.id);
      if (!bound) return [];
      const many = engineDefs.length > 1 ? `${d.label}: ` : '';
      return [{
        value: bound.value,
        label: `${many}queue bound ${formatCount(bound.value)} · ${bound.source}`,
        short: `queue ${formatCount(bound.value)}`,
        color: d.color,
      }];
    }),
  );
  // Where each engine queues — the most it ran while still keeping requests
  // waiting, which is not a capacity — as a labelled rule on the running
  // card. Engines queueing from the same count share one rule, naming each.
  const runningReferences = $derived.by(() => {
    const byValue = new Map<number, typeof loadSeriesDefs>();
    for (const d of engineDefs) {
      const queueing = dash?.load_series.find((s) => s.endpoint_id === d.id)?.engine_queueing_at;
      if (queueing != null) byValue.set(queueing, [...(byValue.get(queueing) ?? []), d]);
    }
    const many = engineDefs.length > 1;
    return [...byValue].map(([value, defs]) => ({
      value,
      label: `${many ? `${defs.map((d) => d.label).join(', ')}: ` : ''}queueing from ${formatCount(value)} running`,
      short: `queueing from ${formatCount(value)}`,
      color: defs.length === 1 ? defs[0].color : 'var(--text-secondary)',
    }));
  });

  // ── The figure now, beside each card's recent caption ──
  const liveEndpoints = $derived(
    nowFromRecent && recent
      ? recent.endpoints_live
      : (dash?.endpoints ?? []).flatMap((e) => (e.live ? [{ endpoint_id: e.endpoint_id, live: e.live }] : [])),
  );
  const sumNow = (pick: (e: (typeof liveEndpoints)[number]) => number | null | undefined) => {
    const vals = liveEndpoints.map(pick).filter((v): v is number => v != null);
    return vals.length ? vals.reduce((a, b) => a + b, 0) : null;
  };
  const inFlightNote = $derived(
    nowLive?.gated
      ? `now ${formatCount(nowLive.in_flight)}${nowLive.capacity != null ? ` / ${formatCount(nowLive.capacity)}` : ''} · ${formatCount(nowLive.held)} held`
      : undefined,
  );
  const waitingNow = $derived(sumNow((e) => e.live?.engine?.waiting));
  const runningNow = $derived(sumNow((e) => e.live?.engine?.running));
  const kvNow = $derived(
    liveEndpoints.map((e) => e.live?.engine?.kv_usage).filter((v): v is number => v != null).reduce<number | null>((a, b) => Math.max(a ?? 0, b), null),
  );
  // Held now, per class.
  const heldNote = $derived.by(() => {
    const now = nowLive;
    if (!now) return undefined;
    if (now.held === 0) return 'now 0 held';
    const parts = now.held_by_class.filter((h) => h.held > 0).map((h) => `${className(h.qos_class_id)} ${formatCount(h.held)}`);
    return `now ${parts.join(' · ')}`;
  });
  // The engine cards name only endpoints whose engine is read: one the gateway
  // only counts would sit in every legend reading "—", like an engine gone
  // silent. Colours stay the endpoints' own.
  const engineDefs = $derived(loadSeriesDefs.filter((d) => engineKey.split(',').includes(d.id)));
  const engineSeries = $derived(gaugeSeries(engineDefs));
  // Running solid, waiting dashed in the same colour: the queue appears where
  // running reaches full.
  const runWaitSeries = $derived<ChartSeries[]>([
    ...engineDefs.map((d) => ({ key: d.key, label: `${d.label} · running`, color: d.color })),
    ...engineDefs.map((d) => ({ key: `${d.key}w`, label: `${d.label} · waiting`, color: d.color, dashArray: '4,3' })),
    ...engineDefs.map((d) => ({ key: `${d.key}m`, label: `${d.label} · running, mean`, color: d.color, tooltipOnly: true })),
    ...engineDefs.map((d) => ({ key: `${d.key}mw`, label: `${d.label} · waiting, mean`, color: d.color, tooltipOnly: true })),
  ]);
  const runWaitRows = (side: 'recent' | 'history') => {
    const rows = side === 'recent' ? recentRows : historyRows;
    return pairRows(rows('engine_running'), rows('engine_waiting'), 'w');
  };
  const counterSeries = $derived<ChartSeries[]>(engineDefs.map((d) => ({ key: d.key, label: d.label, color: d.color })));
  // Each card's rows, built when their own data changes — not on every
  // render: the period's rows do not move when the recent poll lands.
  const inFlightRecent = $derived(recentRows('in_flight', { zero: true }));
  const inFlightHistory = $derived(historyRows('in_flight', { zero: true }));
  const runWaitRecent = $derived(runWaitRows('recent'));
  const runWaitHistory = $derived(runWaitRows('history'));
  const kvRecent = $derived(recentRows('engine_kv_usage'));
  const kvHistory = $derived(historyRows('engine_kv_usage'));
  const preemptionRowsOf = (side: Side) => counterRows(side, (s, i) => s.engine_preemptions_per_min[i]);
  const preemptionRecent = $derived(preemptionRowsOf('recent'));
  const preemptionHistory = $derived(preemptionRowsOf('history'));
  // Generated solid, prompt served dashed, prompt computed dotted: computed
  // above served's share of misses is a history being recomputed.
  const tokenRowsOf = (side: Side) =>
    pairRows(
      pairRows(
        counterRows(side, (s, i) => s.engine_generation_tokens_per_s[i]),
        counterRows(side, (s, i) => s.engine_prompt_tokens_per_s[i]),
        'b',
      ),
      counterRows(side, (s, i) => s.engine_computed_prompt_tokens_per_s[i]),
      'c',
    );
  const tokenRecent = $derived(tokenRowsOf('recent'));
  const tokenHistory = $derived(tokenRowsOf('history'));
  const tokenSeries = $derived<ChartSeries[]>(
    engineDefs.flatMap((d) => [
      { key: d.key, label: `${d.label} · generated`, color: d.color },
      { key: `${d.key}b`, label: `${d.label} · prompt served`, color: d.color, dashArray: '4,3' },
      { key: `${d.key}c`, label: `${d.label} · prompt computed`, color: d.color, dashArray: '1,3' },
    ]),
  );
  // Time between tokens rides the tooltip: tens of milliseconds on a card of
  // seconds would draw as a flat line on the axis.
  const insideRowsOf = (side: Side) =>
    pairRows(
      pairRows(
        counterRows(side, (s, i) => s.engine_queue_time_ms[i]),
        counterRows(side, (s, i) => s.engine_ttft_ms[i]),
        'b',
      ),
      counterRows(side, (s, i) => s.engine_itl_ms[i]),
      'i',
    );
  const insideRecent = $derived(insideRowsOf('recent'));
  const insideHistory = $derived(insideRowsOf('history'));
  const insideSeries = $derived<ChartSeries[]>(
    engineDefs.flatMap((d) => [
      { key: d.key, label: `${d.label} · in its queue`, color: d.color },
      { key: `${d.key}b`, label: `${d.label} · to first token`, color: d.color, dashArray: '4,3' },
      { key: `${d.key}i`, label: `${d.label} · between tokens`, color: d.color, tooltipOnly: true },
    ]),
  );
  const prefixRowsOf = (side: Side) => counterRows(side, (s, i) => s.engine_prefix_hit_rate[i]);
  const prefixRecent = $derived(prefixRowsOf('recent'));
  const prefixHistory = $derived(prefixRowsOf('history'));
  // A learned limit's token-latency target, and the engine's time between
  // tokens against it: its own card, as the target is what the limit holds.
  // Kept while the limit is fixed, where it governs nothing: shown only while
  // the limit is learned, and a target is on. An automatic one is the slowest
  // engine's figure as the gateways report it now (each engine is held to its
  // own), and none while it is still learning.
  const itlSetting = $derived(server?.adaptive_concurrency ? server.adaptive_itl_target : null);
  const itlAuto = $derived(itlSetting?.type === 'auto');
  const itlTarget = $derived(
    itlSetting?.type === 'fixed' ? itlSetting.ms : itlAuto ? (server?.auto_itl_target_ms ?? null) : null,
  );
  const itlNote = $derived(
    itlTarget != null
      ? `${itlAuto ? 'automatic target' : 'target'} ${formatDuration(itlTarget)}, held against the median, which leaves out the pauses for new prompts that the mean counts`
      : 'automatic target learning (needs time between tokens at low load)',
  );
  const itlRowsOf = (side: Side) => counterRows(side, (s, i) => s.engine_itl_ms[i]);
  const itlRecent = $derived(itlRowsOf('recent'));
  const itlHistory = $derived(itlRowsOf('history'));
  const itlSeries = $derived<ChartSeries[]>(
    engineDefs.map((d) => ({ key: d.key, label: `${d.label} · between tokens`, color: d.color })),
  );
  // The target as set now, marked like the in-flight limits — a rule, not a
  // series, so a far-off target does not flatten the measured lines.
  const itlReferences = $derived(
    itlTarget == null
      ? []
      : [{ value: itlTarget, label: `${itlAuto ? 'Automatic target, slowest engine' : 'Target'} ${formatDuration(itlTarget)} (median)`, color: 'var(--warning)', short: formatDuration(itlTarget) }],
  );
  // What the learned limits did, summed over the server's endpoints and the
  // replicas: one line per kind of decision, the causes of a back-off in the
  // tooltip.
  const decisionRowsOf = (side: Side): ChartRow[] => {
    const src = side === 'recent' ? recent : dash;
    return (src?.bucket_starts ?? []).map((ts, i) => {
      const sum = (...picks: ((s: LoadSeries) => (number | null)[])[]) => {
        const vals = (src?.load_series ?? []).flatMap((s) => picks.map((p) => p(s)[i])).filter((v): v is number => v != null);
        return vals.length ? vals.reduce((a, b) => a + b, 0) : null;
      };
      return {
        timestamp: new Date(ts),
        grew: sum((s) => s.adaptive_grew),
        stepped_down: sum((s) => s.adaptive_stepped_down),
        cut: sum((s) => s.adaptive_cut_preemption, (s) => s.adaptive_cut_kv_full),
        cut_preemption: sum((s) => s.adaptive_cut_preemption),
        cut_kv_full: sum((s) => s.adaptive_cut_kv_full),
      };
    });
  };
  const decisionRecent = $derived(decisionRowsOf('recent'));
  const decisionHistory = $derived(decisionRowsOf('history'));
  const decisionSeries: ChartSeries[] = [
    { key: 'grew', label: 'Raised', color: 'var(--success)' },
    { key: 'stepped_down', label: 'Stepped down · token latency above target', color: 'var(--warning)', dashArray: '4,3' },
    { key: 'cut', label: 'Backed off', color: 'var(--error)' },
    { key: 'cut_preemption', label: 'Backed off · engine preempted', color: 'var(--error)', tooltipOnly: true },
    { key: 'cut_kv_full', label: 'Backed off · KV cache full', color: 'var(--error)', tooltipOnly: true },
  ];
  const decided = (s: LoadSeries) => s.adaptive_grew;
  const learnsLimit = $derived((server?.adaptive_concurrency ?? false) || eitherHas(decided));
  const growthLabel = $derived(
    itlTarget != null
      ? `token latency target ${formatDuration(itlTarget)}`
      : itlAuto
        ? 'grows while memory has room; latency target learning'
        : 'grows while memory has room',
  );
  // The hit rate now: the last minute that has one, any endpoint.
  const hitNow = $derived.by(() => {
    for (let i = (recent?.bucket_starts.length ?? 0) - 1; i >= 0; i--) {
      const vals = (recent?.load_series ?? []).map((s) => s.engine_prefix_hit_rate[i]).filter((v): v is number => v != null);
      if (vals.length) return vals.reduce((a, b) => a + b, 0) / vals.length;
    }
    return null;
  });
  // Shown only when they say something: a card of zeros teaches nothing.
  const preemptionsSeen = $derived(eitherHas((s) => s.engine_preemptions_per_min, true));
  const prefixPublished = $derived(eitherHas((s) => s.engine_prefix_hit_rate));

  // Any reading at all: an idle engine reads 0 and must draw a zero line, not
  // the empty state — zero is a reading, a gap is not.
  const engineRead = $derived(anyReading('engine_waiting'));
  const periodLabel = $derived(`Period · ${hourly ? 'hourly' : 'daily'} peak`);
  const recentLabel = $derived(recent ? `Last ${Math.round(recent.window_secs / 60)} min` : 'Last minutes');

  const formatKv = (v: number) => formatShare(v, 1);
  // A gauge the engine does not publish is absent, never a zero.
  const gauge = (v: number | null | undefined, fmt: (n: number) => string) => (v == null ? '--' : fmt(v));
  const refusalTotal = $derived((dash?.refusals ?? []).reduce((n, r) => n + r.count, 0));
  // Engine charts beyond the queue: shown once any throughput was derived.
  const engineCounters = $derived(eitherHas((s) => s.engine_generation_tokens_per_s));
  const observed = $derived(gated || (server?.engine_metrics ?? false) || hasLoadHistory);

  // ── The scheduler now ────────────────────────────────────────────────
  // "Now" is the current hour, and only an hourly axis has one: a day bucket,
  // or a period that ended in the past, says nothing about now.
  const refusedNow = $derived.by(() => {
    const last = dash?.bucket_starts.at(-1);
    if (!dash || dash.interval !== 'hour' || !last) return 0;
    return Date.now() - new Date(last).getTime() < 3_600_000 ? (dash.series.at(-1)?.refusals ?? 0) : 0;
  });
  const schedState = $derived(SCHEDULER_STATE[schedulerState(nowLive, refusedNow)]);

  // ── Per class ────────────────────────────────────────────────────────
  // One colour per class across every per-class chart: the class list's order,
  // then any class only the held series names.
  type ClassHeld = components['schemas']['ClassHeldSeries'];
  const heldKey = (h: ClassHeld) => h.qos_class_id ?? null;
  // In the tenant's class order (then "no class", then any class since
  // removed), so a colour never moves when
  // the period or the recent poll first names a class.
  // Joined into a string (no class is the empty string), so the colours and
  // rows built on it recompute only when the set of classes changes.
  const classOrderKey = $derived.by(() => {
    const seen = new Set<string | null>([
      ...(dash?.class_series ?? []).map((c) => c.qos_class_id ?? null),
      ...[...(dash?.class_held_series ?? []), ...(recent?.class_held_series ?? [])].map(heldKey),
    ]);
    const known = classes.map((c) => c.id).filter((id) => seen.has(id));
    const rest = [...seen].filter((id) => id === null || !known.includes(id));
    rest.sort((a, b) => (a === null ? -1 : b === null ? 1 : a.localeCompare(b)));
    return JSON.stringify([...known, ...rest]);
  });
  const classOrder = $derived(JSON.parse(classOrderKey) as (string | null)[]);
  /** A class's colour is its place in the TENANT's class list, so a class
   *  first held or first seen in the period never recolours another; one the
   *  list does not hold (no class, removed) follows it. */
  const classColorIndex = (id: string | null, i: number) => {
    const at = id ? classes.findIndex((c) => c.id === id) : -1;
    return at >= 0 ? at : classes.length + i;
  };
  const classSeries = $derived<ChartSeries[]>(
    classOrder.map((id, i) => ({ key: `c${i}`, label: className(id), color: seriesColor(classColorIndex(id, i)) })),
  );
  function classRows(pick: (classId: string | null, i: number) => number | null | undefined): ChartRow[] {
    return (dash?.bucket_starts ?? []).map((ts, i) => {
      const row: ChartRow = { timestamp: new Date(ts) };
      classOrder.forEach((id, j) => {
        row[`c${j}`] = pick(id, i) ?? 0;
      });
      return row;
    });
  }
  const classTraffic = (id: string | null, i: number) =>
    dash?.class_series.find((c) => (c.qos_class_id ?? null) === id)?.series[i];
  // Held per class: each bucket's peak drawn, its mean in the tooltip.
  const classHeldSeries = $derived<ChartSeries[]>([
    ...classSeries,
    ...classSeries.map((c) => ({ ...c, key: `${c.key}m`, label: `${c.label} · mean`, tooltipOnly: true })),
  ]);
  /** Held per class on `axis`: each class's peak and mean per bucket, 0 where
   *  it held nothing (a held count is the gateway's own, never unread). */
  function classHeldRowsOf(axis: string[], series: ClassHeld[]): ChartRow[] {
    return axis.map((ts, i) => {
      const row: ChartRow = { timestamp: new Date(ts) };
      classOrder.forEach((id, j) => {
        const c = series.find((x) => heldKey(x) === id);
        row[`c${j}`] = c?.held[i] ?? 0;
        row[`c${j}m`] = c?.held_mean[i] ?? 0;
      });
      return row;
    });
  }
  const classHeldRows = $derived(classHeldRowsOf(dash?.bucket_starts ?? [], dash?.class_held_series ?? []));
  const recentClassHeldRows = $derived(
    classHeldRowsOf(recent?.bucket_starts ?? [], recent?.class_held_series ?? []),
  );
  // Held per class is shown only when something was held: a card of zeros
  // teaches nothing, and an ungated server never holds.
  const heldSeen = $derived(
    chartHasValue(classHeldRows, classSeries) || chartHasValue(recentClassHeldRows, classSeries),
  );
  const hasClasses = $derived(classOrder.length > 0);
</script>

<DashboardScaffold
  title={server?.name ?? 'Server'}
  subtitle={server ? `${server.provider} · ${endpoints.length} endpoint${endpoints.length === 1 ? '' : 's'} · latency excludes the wait for capacity` : undefined}
>
  {#snippet filters()}
    {#if server}
      {#if observed}
        <!-- What the gateway is doing with this server's requests now. -->
        <span data-scheduler-state={schedulerState(nowLive, refusedNow)}>
          <StatusChip
            label={schedState.label}
            icon={schedState.icon}
            tone={schedState.tone}
            title={nowStale ? `${schedState.detail} (stale — the last update failed)` : schedState.detail}
          />
        </span>
      {/if}
      <StatusChip {...SERVER_HEALTH[server.health]} status={server.health} title={serverHealthReason(server) ?? undefined} />
      <a
        href={thref(slug, `/gateways/llm/servers/${serverId}`)}
        class="text-xs font-medium text-(--accent) hover:underline"
      >Configure</a>
    {/if}
  {/snippet}

  {#if notFound}
    <EmptyState title="Server not found" body="It may have been removed, or it belongs to another tenant." />
  {:else}
    {#if error}
      <div class="bg-(--error-bg) border border-(--error-border) rounded-lg p-3 mb-4 text-sm text-(--error-text)">
        {error}
      </div>
    {/if}

    <MetricGrid class="mb-6">
      {#each cards as card (card.label)}
        <MetricCard {...card} loading={loading && dash == null} />
      {/each}
    </MetricGrid>

    <!-- Traffic and latency -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
      <TimeSeriesChart
        title="Requests"
          counts
        loading={loading && dash == null}
        rows={trafficRows}
        series={TRAFFIC_SERIES}
        formatY={formatCount}
        {hourly}
        nowRule
        legend
      />
      <TimeSeriesChart
        title="Latency"
        loading={loading && dash == null}
        rows={trafficRows}
        series={LATENCY_SERIES}
        formatY={formatDuration}
        {hourly}
        nowRule
        legend
      />
    </div>

    <!-- Load: where requests are — held at the gateway, in flight to each
         endpoint, inside each engine — each card the last minutes beside the
         period. Only where the gateway gates this server or reads its engines;
         a card that would hold only zeros is left out. -->
    {#if observed}
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6" data-load-charts>
        {#if heldSeen}
          <LiveHistoryChart
            title="Held at the gateway per class"
          counts
            series={classHeldSeries}
            formatY={formatCount}
            {hourly}
            recent={{ rows: recentClassHeldRows, label: recentLabel, loading: recentLoading, error: recentError, note: heldNote, emptyText: 'Nothing held lately' }}
            history={{ rows: classHeldRows, label: periodLabel, loading: loading && dash == null, emptyText: 'Nothing held in this period' }}
            legend
          />
        {/if}
        <LiveHistoryChart
          title="In flight per endpoint"
          counts
          series={inFlightSeries}
          formatY={formatCount}
          {hourly}
          recent={{ rows: inFlightRecent, label: recentLabel, loading: recentLoading, error: recentError, empty: !recentHasLoad, note: inFlightNote }}
          history={{ rows: inFlightHistory, label: periodLabel, loading: loading && dash == null, empty: !periodHasLoad }}
          references={inFlightReferences}
          legend
        />
        {#if engineRead}
          <LiveHistoryChart
            title="Engine: running and waiting"
          counts
            series={runWaitSeries}
            formatY={formatCount}
            {hourly}
            recent={{ rows: runWaitRecent, label: recentLabel, loading: recentLoading, error: recentError, empty: !recentReads('engine_running') && !recentReads('engine_waiting'), note: runningNow != null ? `now ${formatCount(runningNow)} running · ${formatCount(waitingNow ?? 0)} waiting` : undefined }}
            history={{ rows: runWaitHistory, label: periodLabel, empty: !periodReads('engine_running') && !periodReads('engine_waiting') }}
            references={[...runningReferences, ...queueReferences]}
            legend
          />
          <LiveHistoryChart
            title="KV cache per endpoint"
            series={engineSeries}
            formatY={formatKv}
            yFloor={1}
            {hourly}
            recent={{ rows: kvRecent, label: recentLabel, loading: recentLoading, error: recentError, empty: !recentReads('engine_kv_usage'), note: kvNow != null ? `now ${formatKv(kvNow)}` : undefined }}
            history={{ rows: kvHistory, label: periodLabel, empty: !periodReads('engine_kv_usage') }}
            legend
          />
        {:else}
          <Panel title="Inside each engine">
            <EmptyState
              title="Engine metrics are not read"
              body="Turn on Read engine metrics on the server's QoS tab (on by default for vLLM), or set an engine queue bound."
            />
          </Panel>
        {/if}
        {#if learnsLimit}
          <!-- What each replica's learned limit did, per minute and over the
               period: the in-flight card shows where it stood, this one why. -->
          <LiveHistoryChart
            title="Learned limit: what it did"
            counts
            series={decisionSeries}
            formatY={formatCount}
            {hourly}
            recent={{ rows: decisionRecent, label: recentLabel, loading: recentLoading, error: recentError, note: growthLabel, emptyText: 'No change lately' }}
            history={{ rows: decisionHistory, label: periodLabel, emptyText: 'No change in this period' }}
            legend
          />
        {/if}
        {#if engineCounters}
          {#if preemptionsSeen}
            <LiveHistoryChart
              title="Preemptions per minute"
              series={counterSeries}
              formatY={formatCount}
              {hourly}
              recent={{ rows: preemptionRecent, label: recentLabel, loading: recentLoading, error: recentError, emptyText: 'None lately' }}
              history={{ rows: preemptionHistory, label: periodLabel }}
              legend
            />
          {/if}
          <LiveHistoryChart
            title="Tokens per second"
            series={tokenSeries}
            formatY={formatCount}
            {hourly}
            recent={{ rows: tokenRecent, label: recentLabel, loading: recentLoading, error: recentError, empty: !paneHas('recent', (s) => s.engine_generation_tokens_per_s) }}
            history={{ rows: tokenHistory, label: periodLabel, empty: !paneHas('history', (s) => s.engine_generation_tokens_per_s) }}
            legend
          />
          <LiveHistoryChart
            title="Inside the engine (mean)"
            series={insideSeries}
            formatY={formatDuration}
            {hourly}
            recent={{ rows: insideRecent, label: recentLabel, loading: recentLoading, error: recentError, empty: !paneHas('recent', (s) => s.engine_ttft_ms) }}
            history={{ rows: insideHistory, label: periodLabel, empty: !paneHas('history', (s) => s.engine_ttft_ms) }}
            legend
          />
          {#if learnsLimit && itlSetting != null && itlSetting.type !== 'off'}
            <LiveHistoryChart
              title="Time between tokens (mean)"
              series={itlSeries}
              formatY={formatDuration}
              {hourly}
              recent={{ rows: itlRecent, label: recentLabel, loading: recentLoading, error: recentError, empty: !paneHas('recent', (s) => s.engine_itl_ms), note: itlNote }}
              history={{ rows: itlHistory, label: periodLabel, empty: !paneHas('history', (s) => s.engine_itl_ms) }}
              references={itlReferences}
              legend
            />
          {/if}
          {#if prefixPublished}
            <LiveHistoryChart
              title="Prefix cache hit rate"
              series={counterSeries}
              formatY={formatKv}
              yFloor={1}
              {hourly}
              recent={{ rows: prefixRecent, label: recentLabel, loading: recentLoading, error: recentError, empty: !paneHas('recent', (s) => s.engine_prefix_hit_rate), note: hitNow != null ? `now ${formatKv(hitNow)}` : undefined }}
              history={{ rows: prefixHistory, label: periodLabel, empty: !paneHas('history', (s) => s.engine_prefix_hit_rate) }}
              legend
            />
          {/if}
        {/if}
      </div>
      {#if !heldSeen && gated}
        <p class="text-xs text-(--text-tertiary) -mt-3 mb-2" data-nothing-held>Nothing was held at the gateway in this period.</p>
      {/if}
      {#if !preemptionsSeen && engineCounters}
        <p class="text-xs text-(--text-tertiary) {heldSeen || !gated ? '-mt-3' : ''} mb-2" data-no-preemptions>The engine preempted nothing in this period.</p>
      {/if}
      {#if dash}
        <p class="text-xs text-(--text-tertiary) mb-6">Live load history covers the last {dash.live_history_days} days.</p>
      {/if}
    {/if}

    <!-- Endpoints -->
    <div class="mb-6">
      <Panel
        title="Endpoints"
        subtitle="Replicas of this server: health now, traffic over the period, load now"
        flush
        {loading}
        empty={!loading && endpoints.length === 0 && (dash?.endpoints.length ?? 0) === 0}
      >
        <div class="overflow-x-auto">
          <table class="w-full text-sm" data-server-endpoints>
            <thead>
              <tr class="border-b border-(--border) text-xs text-(--text-secondary) uppercase tracking-wider">
                <th class="px-5 py-2.5 text-left font-medium">Endpoint</th>
                <th class="px-3 py-2.5 text-left font-medium">Status</th>
                <th class="px-3 py-2.5 text-right font-medium">Share</th>
                <th class="px-3 py-2.5 text-right font-medium">Failed</th>
                <th class="px-3 py-2.5 text-right font-medium">P95 latency</th>
                <th class="px-3 py-2.5 text-right font-medium">Moved here</th>
                <th class="px-3 py-2.5 text-left font-medium w-44">
                  In flight now{#if nowStale}<span class="ml-1 normal-case tracking-normal text-(--warning-text)" title={recentError} data-table-stale>· stale</span>{/if}
                </th>
                <th class="px-5 py-2.5 text-left font-medium">Engine now</th>
              </tr>
            </thead>
            <tbody>
              {#each endpoints as e (e.id)}
                {@const a = dash?.endpoints.find((x) => x.endpoint_id === e.id)}
                {@const now = liveEndpoints.find((x) => x.endpoint_id === e.id)?.live}
                {@const status = endpointStatus(e)}
                <tr class="border-b border-(--border) last:border-0" data-endpoint-row={e.url}>
                  <td class="px-5 py-3"><Copyable value={e.url} /></td>
                  <td class="px-3 py-3"><StatusChip {...ENDPOINT_STATUS[status]} {status} /></td>
                  <td class="px-3 py-3 text-right font-mono tabular-nums">{a && t ? formatShare(a.traffic.requests, sentOf(t)) : '--'}</td>
                  <td class="px-3 py-3 text-right font-mono tabular-nums">{a ? formatShare(a.traffic.errors, sentOf(a.traffic)) : '--'}</td>
                  <td class="px-3 py-3 text-right font-mono tabular-nums">{a?.traffic.latency_p95_ms != null ? formatDuration(a.traffic.latency_p95_ms) : '--'}</td>
                  <td class="px-3 py-3 text-right font-mono tabular-nums">{formatCount(a?.traffic.spilled ?? 0)}</td>
                  <td class="px-3 py-3">
                    {#if now?.gated}
                      {@const limit = limitOf(e.id)}
                      <LimitMeter label="In flight" used={now.in_flight} cap={now.capacity} fmt={formatCount} />
                      {#if !now.adaptive && limit}
                        <!-- Whose limit this is: the endpoint's own wins over the server's. -->
                        <span class="block text-[10px] text-(--text-tertiary) mt-0.5" data-limit-source={limit.source}>
                          {formatCount(limit.perReplica)} per gateway · {limit.source === 'endpoint' ? "endpoint's own" : 'server default'}
                        </span>
                      {/if}
                      {#if now.adaptive}
                        {@const learned = ADAPTIVE_STATE[now.adaptive.state]}
                        <div class="mt-1.5" data-adaptive-state={now.adaptive.state}>
                          <StatusChip {...learned} title={learned.detail} status={now.adaptive.state} />
                          <span class="block text-[10px] text-(--text-tertiary) mt-0.5">Learned limit</span>
                        </div>
                      {/if}
                    {:else}
                      <span class="text-xs text-(--text-tertiary)">{gated && !now ? 'No reading' : 'Not gated'}</span>
                    {/if}
                  </td>
                  <td class="px-5 py-3 text-xs">
                    {#if now?.engine}
                      <span class="font-mono">{formatCount(now.engine.waiting)} waiting · {gauge(now.engine.running, formatCount)} running · KV {gauge(now.engine.kv_usage, formatKv)}</span>
                      {#if now.engine_silent_replicas > 0}
                        <span class="block text-(--warning-text)" title={now.queue_bounded || now.adaptive ? 'These gateway replicas have stopped hearing from the engine and are not applying its queue bound or learned limit' : 'These gateway replicas have stopped hearing from the engine: its charts have a gap'}>Silent on {now.engine_silent_replicas} gateway replica{now.engine_silent_replicas === 1 ? '' : 's'}</span>
                      {/if}
                    {:else if now?.engine_read}
                      <span class="text-(--warning-text)" title={now.queue_bounded || now.adaptive ? "The gateway reads this engine's gauges and none arrived lately — its queue bound or learned limit is not being applied" : "The gateway reads this engine's metrics and none arrived lately — check that /metrics is reachable, or turn Read engine metrics off"}>Silent</span>
                    {:else}
                      <span class="text-(--text-tertiary)">Not read</span>
                    {/if}
                  </td>
                </tr>
              {/each}
              <!-- An endpoint removed since: its rows still count. -->
              {#each (dash?.endpoints ?? []).filter((x) => !endpointById.has(x.endpoint_id)) as a (a.endpoint_id)}
                <tr class="border-b border-(--border) last:border-0 text-(--text-secondary)">
                  <td class="px-5 py-3 font-mono text-xs">{endpointLabel(a.endpoint_id, a.url)}</td>
                  <td class="px-3 py-3 text-xs">Removed</td>
                  <td class="px-3 py-3 text-right font-mono tabular-nums">{t ? formatShare(a.traffic.requests, sentOf(t)) : '--'}</td>
                  <td class="px-3 py-3 text-right font-mono tabular-nums">{formatShare(a.traffic.errors, sentOf(a.traffic))}</td>
                  <td class="px-3 py-3 text-right font-mono tabular-nums">{a.traffic.latency_p95_ms != null ? formatDuration(a.traffic.latency_p95_ms) : '--'}</td>
                  <td class="px-3 py-3 text-right font-mono tabular-nums">{formatCount(a.traffic.spilled)}</td>
                  <td class="px-3 py-3"></td>
                  <td class="px-5 py-3"></td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>

    <!-- Per class, over the period -->
    {#if hasClasses && classSeries.length > 0}
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6" data-class-charts>
        <TimeSeriesChart
          title="Requests per class"
          rows={classRows((id, i) => classTraffic(id, i)?.requests)}
          series={classSeries}
          formatY={formatCount}
          {hourly}
          nowRule
          legend
        />
        <TimeSeriesChart
          title="Wait P95 per class"
          rows={classRows((id, i) => classTraffic(id, i)?.queue_wait_p95_ms)}
          series={classSeries}
          formatY={formatDuration}
          {hourly}
          legend
        />
      </div>
    {/if}

    <!-- Scheduling -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <BreakdownPanel
        title="Priority classes"
        subtitle="Requests per class · how many waited · refusals"
        loading={loading && dash == null}
        items={dash?.classes ?? []}
        getKey={(c) => c.qos_class_id ?? 'none'}
        getValue={(c) => c.traffic.requests}
        getRow={(c, max) => ({
          label: className(c.qos_class_id),
          value: formatCount(c.traffic.requests),
          sub: [
            `${formatShare(c.traffic.queued, sentOf(c.traffic))} waited`,
            c.traffic.queue_wait_p95_ms != null ? `P95 wait ${formatDuration(c.traffic.queue_wait_p95_ms)}` : null,
            c.refusals.length > 0
              ? c.refusals.map((r) => `${formatCount(r.count)} ${r.reason.replace(/_/g, ' ')}`).join(', ')
              : null,
          ].filter(Boolean).join(' · '),
          percent: (c.traffic.requests / max) * 100,
          barColor: 'var(--chart-2)',
        })}
      >
        {#snippet emptySlot()}
          <EmptyState title="No traffic in this window" body="Nothing was sent to this server during the selected period." />
        {/snippet}
      </BreakdownPanel>

      <BreakdownPanel
        title="Refusals"
        subtitle={t && t.passed_on > 0
          ? `Why this server's capacity ran out — ${formatCount(t.passed_on)} moved on to another target`
          : "Why this server's capacity ran out"}
        loading={loading && dash == null}
        items={dash?.refusals ?? []}
        getKey={(r) => r.reason}
        maxValue={refusalTotal}
        getRow={(r, max) => ({
          label: REFUSAL_LABEL[r.reason] ?? r.reason,
          value: formatCount(r.count),
          percent: (r.count / max) * 100,
          // No drill-down: a refusal a request moved on from is on the row of
          // the target it moved to, which names another server.
          barColor: 'var(--warning)',
        })}
      >
        {#snippet emptySlot()}
          <EmptyState title="Nothing refused" body="Every request sent to this server was given capacity." />
        {/snippet}
      </BreakdownPanel>

      <BreakdownPanel
        title="Who waited most"
        subtitle="Total time spent waiting for this server"
        loading={loading && dash == null}
        items={dash?.top_waiters ?? []}
        getKey={(w) => w.user_id}
        getValue={(w) => w.wait_ms_total}
        getRow={(w, max) => ({
          label: w.label,
          value: formatDuration(w.wait_ms_total),
          sub: `${formatCount(w.queued)} of ${formatCount(w.requests)} waited${w.queue_wait_p95_ms != null ? ` · P95 ${formatDuration(w.queue_wait_p95_ms)}` : ''}`,
          percent: (w.wait_ms_total / max) * 100,
          // No drill-down: a wait here before an attempt the request moved on
          // from is on the row of the target it moved to, which names another
          // server.
          barColor: 'var(--chart-4)',
        })}
      >
        {#snippet emptySlot()}
          <EmptyState title="Nobody waited" body="No request to this server waited for capacity in this window." />
        {/snippet}
      </BreakdownPanel>
    </div>
  {/if}
</DashboardScaffold>

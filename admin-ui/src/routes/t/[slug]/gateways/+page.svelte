<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { fetchAllPages } from '#lib/api-helpers.js';
  import { onMount } from 'svelte';
  import { thref } from '#lib/tenant.js';
  import { gatewayNav, type GatewayHref } from '#lib/nav.js';
  import type { PageProps } from './$types';

  let { params }: PageProps = $props();

  const slug = $derived(params.slug);

  type CountState = number | null;

  let llmProviders = $state<CountState>(null);
  let llmServers = $state<CountState>(null);
  let llmModels = $state<CountState>(null);
  let llmPassthroughOn = $state<CountState>(null);

  let mcpUpstreams = $state<CountState>(null);
  let mcpEndpoints = $state<CountState>(null);
  let mcpOauthClients = $state<CountState>(null);
  let webSearchEnabled = $state<boolean | null>(null);

  let a2aAgents = $state<CountState>(null);
  let a2aEnabled = $state<CountState>(null);

  /** Every row of a list, or null when a page failed — a failed request reads
   *  '—' on its tile, never 0, so an error cannot pass for an empty registry. */
  async function allRows<T>(fetchPage: Parameters<typeof fetchAllPages<T>>[0]): Promise<T[] | null> {
    try {
      return await fetchAllPages(fetchPage);
    } catch {
      return null;
    }
  }

  async function loadCounts() {
    // A plain count reads the server's `total`; a count over a filtered subset
    // reads every row. Neither is the length of one page.
    const [
      providerRows,
      serverRows,
      modelsRes,
      mcpUpstreamRows,
      mcpVsRes,
      mcpOauthRows,
      wsRes,
      a2aRows,
    ] = await Promise.all([
      allRows((offset, limit) =>
        adminApi.GET('/api/v1/admin/downstream-providers', { params: { query: { offset, limit } } })),
      allRows((offset, limit) =>
        adminApi.GET('/api/v1/admin/servers', { params: { query: { offset, limit } } })),
      adminApi.GET('/api/v1/admin/models', { params: { query: { limit: 1 } } }),
      allRows((offset, limit) =>
        adminApi.GET('/api/v1/admin/mcp/upstream-servers', { params: { query: { offset, limit } } })),
      adminApi.GET('/api/v1/admin/mcp/virtual-servers', { params: { query: { limit: 1 } } }),
      allRows((offset, limit) =>
        adminApi.GET('/api/v1/admin/mcp/oauth-clients', { params: { query: { offset, limit } } })),
      adminApi.GET('/api/v1/admin/settings/web'),
      allRows((offset, limit) =>
        adminApi.GET('/api/v1/admin/a2a/agents', { params: { query: { offset, limit } } })),
    ]);

    // As the LLM gateway lists them: key-managed entries apart from the
    // pass-through providers, which count only while switched on.
    llmProviders = providerRows?.filter((p) => !p.byok).length ?? null;
    llmServers = serverRows?.filter((s) => !s.byok).length ?? null;
    llmPassthroughOn = providerRows?.filter((p) => p.byok && p.enabled).length ?? null;
    llmModels = modelsRes.data?.total ?? null;

    mcpUpstreams = mcpUpstreamRows?.filter((s) => s.built_in !== true).length ?? null;
    mcpEndpoints = mcpVsRes.data?.total ?? null;
    mcpOauthClients = mcpOauthRows?.length ?? null;
    webSearchEnabled = wsRes.data ? wsRes.data.backend != null : null;

    a2aAgents = a2aRows?.length ?? null;
    a2aEnabled = a2aRows?.filter((a) => a.enabled).length ?? null;
  }

  onMount(loadCounts);

  function fmt(n: CountState): string {
    return n === null ? '—' : String(n);
  }

  type TileContent = {
    title: string;
    tagline: string;
    blurb: string;
    stats: { label: string; value: string }[];
  };

  // Keyed by the nav's own gateway list, so every gateway in the sidebar has
  // a tile here — one missing is a type error, not a hub that omits it.
  const content: Record<GatewayHref, TileContent> = $derived({
    '/gateways/llm': {
      title: 'LLM Gateway',
      tagline: 'One endpoint, every model.',
      blurb:
        'Your apps call /v1/… with a Streamscope key; we route to OpenAI, Anthropic, and Gemini and translate protocols on the fly. Budgets, audit, and request/response transforms apply centrally.',
      stats: [
        { label: 'Downstream providers', value: fmt(llmProviders) },
        { label: 'Upstream servers', value: fmt(llmServers) },
        { label: 'Upstream models', value: fmt(llmModels) },
        { label: 'Pass-through on', value: fmt(llmPassthroughOn) },
      ],
    },
    '/gateways/mcp': {
      title: 'MCP Gateway',
      tagline: 'One URL, every tool server.',
      blurb:
        'Agents connect to /mcp/<slug>; we hold the upstream credentials (shared headers, values or an OAuth sign-in per user, or headers the client sends), enforce tool & resource policy, and audit every call. Built-in web search included.',
      stats: [
        { label: 'Upstream tool servers', value: fmt(mcpUpstreams) },
        { label: 'Endpoints', value: fmt(mcpEndpoints) },
        { label: 'OAuth clients', value: fmt(mcpOauthClients) },
        {
          label: 'Web search',
          value: webSearchEnabled === null ? '—' : webSearchEnabled ? 'Enabled' : 'Disabled',
        },
      ],
    },
    '/gateways/a2a': {
      title: 'A2A Gateway',
      tagline: 'One mount, every remote agent.',
      blurb:
        'Clients delegate whole tasks to /a2a/<slug>; we fetch and screen each remote agent’s card, hold its credential, enforce workspace access and policy, and audit every call.',
      stats: [
        { label: 'Remote agents', value: fmt(a2aAgents) },
        { label: 'Enabled', value: fmt(a2aEnabled) },
      ],
    },
  });

  const tiles = $derived(gatewayNav.map((g) => ({ href: g.href, ...content[g.href] })));
</script>

<div class="max-w-5xl mx-auto py-12 px-6"><!-- page-container-ok: deliberate centered landing/hub, not a standard content page -->
  <header class="mb-8">
    <h1 class="text-2xl font-semibold text-(--text-primary) mb-2">Gateways</h1>
    <p class="text-sm text-(--text-secondary) max-w-2xl">
      The policy and routing boundaries Streamscope puts in front of your AI traffic.
      Each gateway is independently configured.
    </p>
  </header>

  <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
    {#each tiles as tile (tile.href)}
      <a
        href={thref(slug, tile.href)}
        class="block rounded-lg border border-(--border) bg-(--bg-card) p-6 hover:border-(--accent) hover:bg-(--bg-elevated) transition-colors group"
      >
        <div class="flex items-baseline justify-between gap-3 mb-2">
          <h2
            class="text-base font-semibold text-(--text-primary) group-hover:text-(--accent) transition-colors"
          >
            {tile.title}
          </h2>
          <span class="text-xs text-(--text-tertiary)">{tile.tagline}</span>
        </div>

        <p class="text-sm text-(--text-secondary) leading-relaxed">
          {tile.blurb}
        </p>

        <dl class="mt-5 grid grid-cols-2 gap-x-4 gap-y-3">
          {#each tile.stats as stat (stat.label)}
            <div>
              <dt class="text-[11px] uppercase tracking-wider text-(--text-tertiary)">
                {stat.label}
              </dt>
              <dd class="text-base font-mono text-(--text-primary) mt-0.5">
                {stat.value}
              </dd>
            </div>
          {/each}
        </dl>
      </a>
    {/each}
  </div>
</div>

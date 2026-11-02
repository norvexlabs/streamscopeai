<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractError, extractErrorCode } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import type { components } from '#lib/generated/api-types.js';
  import NumberSetting from '#lib/components/forms/NumberSetting.svelte';
  import AttachmentsEditor from '#lib/components/destinations/AttachmentsEditor.svelte';
  import type { Attachment } from '#lib/destinationAttachments.js';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import { onMount } from 'svelte';

  type WebSettings = components['schemas']['WebSettings'];
  type SearchResult = components['schemas']['SearchResult'];
  type WebProvider = components['schemas']['WebProvider'];
  type FetchProvider = components['schemas']['FetchProvider'];
  type DestinationList = components['schemas']['DestinationList'];

  /** Defaults mirror `WebSettings::default()` in core. Used when the
   * tenant has nothing configured yet so the form renders sensible
   * placeholders rather than blank/zero fields. */
  const DEFAULTS: Required<Omit<WebSettings, 'backend' | 'endpoint' | 'engine_id'>> & {
    backend: WebProvider | '';
    endpoint: string;
    engine_id: string;
  } = {
    backend: '',
    endpoint: '',
    engine_id: '',
    fetch_provider: 'builtin' as FetchProvider,
    max_results: 5,
    fetch_max_bytes: 10 * 1024 * 1024,
    audit_provider_response_max_kb: 1024,
    substitution_max_iterations: 5,
    substitution_max_parallel: 8,
    substitution_round_max_bytes: 8 * 1024 * 1024,
    substitution_history_max_bytes: 32 * 1024 * 1024,
    mixed_pending_cache_ttl_seconds: 3600,
  };

  // Form state — `backend`/`endpoint`/`engine_id` are typed strings here
  // (Option<X> on the wire). Empty string = unset, sent as `null` on PATCH,
  // which CLEARS the stored value (an absent field would leave it unchanged).
  let backend = $state<WebProvider | ''>('');
  let endpoint = $state('');
  let engineId = $state('');
  let fetchProvider = $state<FetchProvider>('builtin');
  let maxResults = $state(5);
  // The destination lists the Web tool attaches; saved on their own, at once.
  let attachments = $state<Attachment[]>([]);
  let lists = $state<DestinationList[]>([]);
  let fetchMaxBytes = $state(DEFAULTS.fetch_max_bytes);
  let auditProviderResponseMaxKb = $state(1024);
  let substitutionMaxIterations = $state(5);
  let substitutionMaxParallel = $state(8);
  let substitutionRoundMaxBytes = $state(DEFAULTS.substitution_round_max_bytes);
  let substitutionHistoryMaxBytes = $state(DEFAULTS.substitution_history_max_bytes);
  let mixedPendingCacheTtlSeconds = $state(3600);

  // Credential state — write-only on the wire. `hasCredential` reflects
  // backend storage; `credentialDraft` is the pending rotation value.
  let hasCredential = $state(false);
  let credentialDraft = $state('');
  let rotateCredential = $state(false);

  let loading = $state(true);
  let saving = $state(false);

  // Test-search panel state
  let testQuery = $state('');
  let testRunning = $state(false);
  let testResult = $state<SearchResult | null>(null);
  let testError = $state('');
  let testRequestId = $state<string | null>(null);

  function applySettings(s: WebSettings) {
    backend = s.backend ?? '';
    endpoint = s.endpoint ?? '';
    engineId = s.engine_id ?? '';
    fetchProvider = s.fetch_provider ?? 'builtin';
    maxResults = s.max_results ?? DEFAULTS.max_results;
    fetchMaxBytes = s.fetch_max_bytes ?? DEFAULTS.fetch_max_bytes;
    auditProviderResponseMaxKb = s.audit_provider_response_max_kb ?? DEFAULTS.audit_provider_response_max_kb;
    substitutionMaxIterations = s.substitution_max_iterations ?? DEFAULTS.substitution_max_iterations;
    substitutionMaxParallel = s.substitution_max_parallel ?? DEFAULTS.substitution_max_parallel;
    substitutionRoundMaxBytes = s.substitution_round_max_bytes ?? DEFAULTS.substitution_round_max_bytes;
    substitutionHistoryMaxBytes = s.substitution_history_max_bytes ?? DEFAULTS.substitution_history_max_bytes;
    mixedPendingCacheTtlSeconds = s.mixed_pending_cache_ttl_seconds ?? DEFAULTS.mixed_pending_cache_ttl_seconds;
  }

  async function load() {
    loading = true;
    const { data, error: err } = await adminApi.GET('/api/v1/admin/settings/web');
    if (err) {
      toast.error('Failed to load web settings', { body: extractError(err), code: extractErrorCode(err) ?? undefined });
    } else if (data) {
      applySettings(data);
      hasCredential = data.has_credential;
      attachments = data.destination_lists.map((d) => ({ list_id: d.list_id, mode: d.mode }));
      credentialDraft = '';
      rotateCredential = false;
    }
    const all = await adminApi.GET('/api/v1/admin/destination-lists', { params: { query: { limit: 500 } } });
    lists = all.data?.items ?? [];
    loading = false;
  }

  // The editor is disabled while a save is in flight: the next change is
  // built from the attachments the last save returned.
  let savingAttachments = $state(false);

  async function saveAttachments(next: Attachment[]) {
    savingAttachments = true;
    const { data, error: err } = await adminApi.PATCH('/api/v1/admin/settings/web', { body: { destination_lists: next } });
    savingAttachments = false;
    if (err) {
      toast.error('Failed to save the destination lists', { body: extractError(err), code: extractErrorCode(err) ?? undefined });
      return;
    }
    if (data) attachments = data.destination_lists.map((d) => ({ list_id: d.list_id, mode: d.mode }));
    toast.success('Web destination lists saved');
  }

  function buildBody(): components['schemas']['UpdateWebSettingsRequest'] {
    return {
      backend: backend === '' ? null : backend,
      endpoint: endpoint.trim() === '' ? null : endpoint.trim(),
      engine_id: engineId.trim() === '' ? null : engineId.trim(),
      fetch_provider: fetchProvider,
      max_results: maxResults,
      fetch_max_bytes: fetchMaxBytes,
      audit_provider_response_max_kb: auditProviderResponseMaxKb,
      substitution_max_iterations: substitutionMaxIterations,
      substitution_max_parallel: substitutionMaxParallel,
      substitution_round_max_bytes: substitutionRoundMaxBytes,
      substitution_history_max_bytes: substitutionHistoryMaxBytes,
      mixed_pending_cache_ttl_seconds: mixedPendingCacheTtlSeconds,
      // Credential is write-only; null = leave existing in place. Empty
      // string clears the stored ciphertext (handled by the admin endpoint).
      credential: rotateCredential ? credentialDraft : null,
    };
  }

  async function save() {
    saving = true;
    const { data, error: err } = await adminApi.PATCH(
      '/api/v1/admin/settings/web',
      { body: buildBody() },
    );
    saving = false;
    if (err) {
      toast.error('Failed to save settings', { body: extractError(err), code: extractErrorCode(err) ?? undefined });
      return;
    }
    if (data) {
      applySettings(data);
      hasCredential = data.has_credential;
      credentialDraft = '';
      rotateCredential = false;
    }
    toast.success('Web-search settings saved');
  }

  async function runTestSearch() {
    if (testQuery.trim().length === 0) return;
    testRunning = true;
    testError = '';
    testResult = null;
    testRequestId = null;
    const { data, error: err } = await adminApi.POST(
      '/api/v1/admin/web/actions/test',
      { body: { query: testQuery, max_results: Math.min(maxResults, 10) } },
    );
    testRunning = false;
    if (err) {
      testError = extractError(err, 'Test search failed');
      return;
    }
    if (data) {
      testRequestId = data.request_id;
      testResult = {
        backend: data.backend,
        hits: data.hits,
        total_filtered: data.total_filtered,
      };
    }
  }

  onMount(load);
</script>

<section class="space-y-4 max-w-4xl">
  {#if loading}
    <div class="bg-(--bg-card) rounded-xl p-5 border border-(--border)">
      <div class="w-32 h-4 bg-(--bg-primary) rounded-sm animate-pulse"></div>
    </div>
  {:else}
    <!-- Backend selection -->
    <div class="bg-(--bg-card) rounded-xl border border-(--border) p-5">
      <h3 class="text-sm font-semibold text-(--text-primary)">Search Backend</h3>
      <p class="text-xs text-(--text-secondary) mb-3">
        Pick a search provider for the built-in <code class="font-mono bg-(--bg-primary) px-1 py-0.5 rounded-sm text-xs">/mcp/web</code> tools.
        SearXNG is the only no-credential option; everything else needs an API key. Page fetch
        (<code class="font-mono bg-(--bg-primary) px-1 py-0.5 rounded-sm text-xs">web_fetch</code>) needs no provider and is served to every
        workspace granted the web server — withhold that grant to keep a workspace off the web.
      </p>
      <label class="block">
        <span class="text-[10px] text-(--text-secondary) uppercase tracking-wider">Backend</span>
        <SelectInput bind:value={backend} class="mt-1">
          <option value="">None — page fetch only</option>
          <option value="searxng">SearXNG (self-hosted, free)</option>
          <option value="brave" disabled>Brave Search (coming soon)</option>
          <option value="tavily" disabled>Tavily (coming soon)</option>
          <option value="google_cse" disabled>Google Custom Search (coming soon)</option>
          <option value="serper" disabled>Serper.dev (coming soon)</option>
        </SelectInput>
      </label>

      {#if backend === 'searxng'}
        <p class="text-xs text-(--text-secondary) mt-2">
          A SearXNG instance with its JSON API on — set the endpoint below.
        </p>
      {/if}

      {#if backend === 'searxng' || backend === 'brave' || backend === 'tavily' || backend === 'serper'}
        <label class="block mt-3">
          <span class="text-[10px] text-(--text-secondary) uppercase tracking-wider">
            Endpoint URL{backend === 'searxng' ? ' (required)' : ' (optional override)'}
          </span>
          <input
            type="url"
            bind:value={endpoint}
            placeholder="https://searx.example.com/search"
            class="w-full mt-1 px-2.5 py-1.5 bg-(--bg-primary) border border-(--border) rounded-lg text-sm font-mono text-(--text-primary) focus:outline-hidden focus:border-(--accent) transition-colors"
          />
        </label>
      {/if}

      {#if backend === 'google_cse'}
        <label class="block mt-3">
          <span class="text-[10px] text-(--text-secondary) uppercase tracking-wider">CSE Engine ID (cx)</span>
          <input
            type="text"
            bind:value={engineId}
            placeholder="012345678901234567890:abcdefg"
            class="w-full mt-1 px-2.5 py-1.5 bg-(--bg-primary) border border-(--border) rounded-lg text-sm font-mono text-(--text-primary) focus:outline-hidden focus:border-(--accent) transition-colors"
          />
        </label>
      {/if}
    </div>

    <!-- Credential -->
    {#if backend && backend !== 'searxng'}
      <div class="bg-(--bg-card) rounded-xl border border-(--border) p-5">
        <h3 class="text-sm font-semibold text-(--text-primary)">Credential</h3>
        <p class="text-xs text-(--text-secondary) mb-3">
          API key for the selected backend. Encrypted at rest with AES-256-GCM (HKDF-SHA256 from <code>ENCRYPTION_KEY</code>); never echoed back.
        </p>
        {#if hasCredential && !rotateCredential}
          <div class="flex items-center gap-3">
            <span class="inline-flex items-center gap-1.5 px-2.5 py-1 bg-(--success-bg) text-(--success-text) border border-(--success-border) rounded-md text-xs font-medium">
              ✓ Credential configured
            </span>
            <button
              type="button"
              onclick={() => { rotateCredential = true; credentialDraft = ''; }}
              class="px-3 py-1.5 text-xs font-medium text-(--accent) hover:underline"
            >Rotate or clear</button>
          </div>
        {:else}
          <label class="block">
            <span class="text-[10px] text-(--text-secondary) uppercase tracking-wider">
              {hasCredential ? 'New credential (leave blank and save to clear)' : 'Credential'}
            </span>
            <input
              type="password"
              bind:value={credentialDraft}
              placeholder="sk-…"
              autocomplete="new-password"
              class="w-full mt-1 px-2.5 py-1.5 bg-(--bg-primary) border border-(--border) rounded-lg text-sm font-mono text-(--text-primary) focus:outline-hidden focus:border-(--accent) transition-colors"
            />
          </label>
          {#if hasCredential}
            <button
              type="button"
              onclick={() => { rotateCredential = false; credentialDraft = ''; }}
              class="mt-2 px-3 py-1.5 text-xs font-medium text-(--text-secondary) hover:underline"
            >Cancel rotation</button>
          {/if}
        {/if}
      </div>
    {/if}

    <!-- Result limits -->
    <div class="bg-(--bg-card) rounded-xl border border-(--border) p-5">
      <h3 class="text-sm font-semibold text-(--text-primary) mb-3">Result Limits</h3>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <NumberSetting
          label="Default Max Results"
          description="Hits returned when the caller doesn't specify (hard cap 50)"
          bind:value={maxResults}
          min={1}
          max={50}
        />
        <NumberSetting
          label="Fetch Max Bytes"
          description="Largest single response the built-in fetcher will read"
          bind:value={fetchMaxBytes}
          min={1024}
          unit="bytes"
        />
        <NumberSetting
          label="Audit Provider Response Max"
          description="Cap for `web_audit.provider_response`; oversized → Stripped marker"
          help="Bounds what we keep on the audit row from each upstream search/fetch response. When a payload exceeds this, the audit stores a `Stripped` marker (size_bytes + reason: 'oversized') instead of the body — the search itself still completes, only the audit copy is truncated."
          bind:value={auditProviderResponseMaxKb}
          min={1}
          unit="KB"
        />
        <label class="block">
          <span class="text-[10px] text-(--text-secondary) uppercase tracking-wider">Fetch Provider</span>
          <span class="block text-xs text-(--text-secondary) mt-0.5 normal-case tracking-normal">Where `web_fetch` extracts content from</span>
          <SelectInput bind:value={fetchProvider} class="mt-1.5">
            <option value="builtin">Builtin (HTML → markdown, SSRF-guarded)</option>
            <option value="tavily" disabled>Tavily extract API (coming soon)</option>
          </SelectInput>
        </label>
      </div>
    </div>

    <!-- Destination lists -->
    <div class="bg-(--bg-card) rounded-xl border border-(--border) p-5">
      <h3 class="text-sm font-semibold text-(--text-primary)">Destination Lists</h3>
      <p class="text-xs text-(--text-secondary) mb-3">
        Applied to every URL the Web tool considers (search hits and fetch targets). With a list attached as allow, only
        what an allowed list names passes; a blocked list always wins. Saved as soon as you change it.
      </p>
      <AttachmentsEditor
        {lists}
        value={attachments}
        emptyText="Nothing attached: every public site passes."
        disabled={savingAttachments}
        onchange={saveAttachments}
      />
    </div>

    <!-- Substitution agent loop -->
    <div class="bg-(--bg-card) rounded-xl border border-(--border) p-5">
      <h3 class="text-sm font-semibold text-(--text-primary)">Substitution Agent Loop</h3>
      <p class="text-xs text-(--text-secondary) mb-3">
        Caps for the gateway-managed substitution loop that intercepts client tool definitions and routes them through the built-in backend.
      </p>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <NumberSetting
          label="Max Iterations"
          description="Substitution rounds before forwarding the upstream's last response unmodified."
          help="One round = one LLM turn whose tool_calls trigger backend dispatch + a follow-up LLM turn. After this many rounds the agent stops intercepting and the last upstream response is forwarded verbatim — the audit row carries a `substitution_iteration_cap_hit` badge so operators can spot loops."
          bind:value={substitutionMaxIterations}
          min={1}
          max={20}
        />
        <NumberSetting
          label="Max Parallel Dispatches"
          description="Concurrent backend calls within a single round."
          bind:value={substitutionMaxParallel}
          min={1}
          max={64}
        />
        <NumberSetting
          label="Round Buffer Cap"
          description="Total bytes of buffered SSE events per round."
          bind:value={substitutionRoundMaxBytes}
          min={64 * 1024}
          unit="bytes"
        />
        <NumberSetting
          label="History Cap"
          description="Cumulative DomainRequest body size across rounds."
          bind:value={substitutionHistoryMaxBytes}
          min={64 * 1024}
          unit="bytes"
        />
        <NumberSetting
          label="Mixed-Pending Cache TTL"
          description="Cross-request splicing window. Set to 0 to disable."
          help="When a single LLM response mixes substitution-bound tool_calls with caller-bound ones, the proxy splices: it runs the substitution side and stashes the caller-bound block for the next request to retrieve. This TTL bounds how long the stash lives — beyond it the partial state is discarded. 0 disables splicing entirely."
          bind:value={mixedPendingCacheTtlSeconds}
          min={0}
          max={86400}
          unit="sec"
        />
      </div>
    </div>

    <!-- Save bar -->
    <div class="flex items-center gap-3">
      <button
        onclick={save}
        disabled={saving}
        class="px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) text-(--accent-fg) text-sm font-medium rounded-lg transition-colors disabled:opacity-50"
      >
        {saving ? 'Saving…' : 'Save Settings'}
      </button>
    </div>

    <!-- Test panel -->
    <div class="bg-(--bg-card) rounded-xl border border-(--border) p-5">
      <h3 class="text-sm font-semibold text-(--text-primary)">Test Search</h3>
      <p class="text-xs text-(--text-secondary) mb-3">
        Dispatch one search through the configured backend. The audit row lands in <code class="font-mono bg-(--bg-primary) px-1 py-0.5 rounded-sm text-xs">web_audit</code> with <code>surface = "admin_test"</code>.
      </p>
      <div class="flex items-center gap-2">
        <input
          type="text"
          bind:value={testQuery}
          placeholder="example query"
          disabled={testRunning || backend === ''}
          onkeydown={(e: KeyboardEvent) => { if (e.key === 'Enter') runTestSearch(); }}
          class="flex-1 min-w-0 px-2.5 py-1.5 bg-(--bg-primary) border border-(--border) rounded-lg text-sm text-(--text-primary) focus:outline-hidden focus:border-(--accent) transition-colors disabled:opacity-50"
        />
        <button
          onclick={runTestSearch}
          disabled={testRunning || backend === '' || testQuery.trim().length === 0}
          class="px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) text-(--accent-fg) text-sm font-medium rounded-lg transition-colors disabled:opacity-50"
        >{testRunning ? 'Searching…' : 'Run Test'}</button>
      </div>

      {#if backend === ''}
        <p class="text-xs text-(--text-secondary) mt-2">Pick a backend above to enable Test Search.</p>
      {/if}

      {#if testError}
        <div class="mt-3 p-3 rounded-lg bg-(--error-bg) border border-(--error-border) text-(--error-text) text-sm">
          {testError}
        </div>
      {/if}

      {#if testResult}
        <div class="mt-3">
          <div class="flex items-center gap-2 text-xs text-(--text-secondary) mb-2">
            <span>Backend: <code class="font-mono text-(--text-primary)">{testResult.backend}</code></span>
            <span>·</span>
            <span>Hits: <span class="text-(--text-primary)">{testResult.hits.length}</span></span>
            <span>·</span>
            <span>Filtered: <span class="text-(--text-primary)">{testResult.total_filtered}</span></span>
            {#if testRequestId}
              <span>·</span>
              <span>request_id: <code class="font-mono text-(--text-primary)">…{testRequestId.slice(-8)}</code></span>
            {/if}
          </div>
          <ul class="space-y-2">
            {#each testResult.hits as hit, idx (idx)}
              <li class="border border-(--border) rounded-lg p-3 bg-(--bg-primary)">
                <div class="text-sm font-medium text-(--text-primary) truncate">{hit.title}</div>
                <a href={hit.url} target="_blank" rel="noopener noreferrer" class="block text-xs text-(--accent) hover:underline truncate mt-0.5">{hit.url}</a>
                {#if hit.snippet}
                  <p class="text-xs text-(--text-secondary) mt-1.5 line-clamp-2">{hit.snippet}</p>
                {/if}
              </li>
            {:else}
              <li class="text-xs text-(--text-secondary)">No hits returned.</li>
            {/each}
          </ul>
        </div>
      {/if}
    </div>
  {/if}
</section>

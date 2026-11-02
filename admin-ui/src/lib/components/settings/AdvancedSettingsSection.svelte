<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractError } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import Copyable from '#lib/components/Copyable.svelte';
  import TagBadge from '#lib/components/TagBadge.svelte';
  import Skeleton from '#lib/components/Skeleton.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import type { components } from '#lib/generated/api-types.js';
  import { onMount } from 'svelte';

  type RuntimeConfig = components['schemas']['RuntimeConfigResponse'];
  type SettingDescriptor = components['schemas']['SettingDescriptor'];

  let loading = $state(true);
  let cfg = $state<RuntimeConfig | null>(null);
  let editValues = $state<Record<string, string>>({});
  let original = $state<Record<string, string>>({});
  let saving = $state(false);

  /** Snapshot the overridable tokens' current override values. */
  function snapshot(c: RuntimeConfig): Record<string, string> {
    const out: Record<string, string> = {};
    for (const s of c.catalog) {
      if (s.overridable) out[s.token] = s.override_value ?? '';
    }
    return out;
  }

  async function load() {
    loading = true;
    const { data, error } = await adminApi.GET('/api/v1/admin/global/runtime-config');
    if (error) {
      toast.error(extractError(error, 'Failed to load runtime config'));
    } else if (data) {
      cfg = data;
      original = snapshot(data);
      editValues = { ...original };
    }
    loading = false;
  }

  onMount(load);

  let dirty = $derived(
    Object.keys(original).some((t) => (editValues[t] ?? '') !== original[t]),
  );

  async function save() {
    if (!dirty || saving) return;
    saving = true;
    const overrides: Record<string, string | null> = {};
    for (const t of Object.keys(original)) {
      const current = (editValues[t] ?? '').trim();
      if (current !== original[t]) {
        overrides[t] = current === '' ? null : current;
      }
    }
    const { data, error } = await adminApi.PATCH('/api/v1/admin/global/runtime-config', {
      body: { overrides },
    });
    if (error) {
      toast.error(extractError(error, 'Failed to save overrides'));
    } else if (data) {
      cfg = data;
      original = snapshot(data);
      editValues = { ...original };
      toast.success('Overrides saved — restart affected edges to apply.');
    }
    saving = false;
  }

  function discard() {
    editValues = { ...original };
  }

  /** Group a descriptor list into category buckets, first-seen order.
   *  Robust to non-contiguous catalog ordering — categories never split. */
  function byCategory(entries: SettingDescriptor[]): { category: string; items: SettingDescriptor[] }[] {
    const groups = new Map<string, { category: string; items: SettingDescriptor[] }>();
    for (const e of entries) {
      let g = groups.get(e.category);
      if (!g) {
        g = { category: e.category, items: [] };
        groups.set(e.category, g);
      }
      g.items.push(e);
    }
    return [...groups.values()];
  }

  // The custom CA bundle is a multi-line PEM — rendered in its own textarea
  // panel below, not as a single-line row in the generic table.
  const CA_TOKEN = 'CUSTOM_CA_BUNDLE_PEM';
  let edgeGroups = $derived(
    cfg
      ? byCategory(
          cfg.catalog.filter(
            (s) => (s.group === 'core' || s.group === 'proxy') && s.token !== CA_TOKEN,
          ),
        )
      : [],
  );
  let caDescriptor = $derived(cfg?.catalog.find((s) => s.token === CA_TOKEN) ?? null);
  let adminGroups = $derived(
    cfg ? byCategory(cfg.catalog.filter((s) => s.group === 'admin')) : [],
  );
  let secretGroups = $derived(
    cfg ? byCategory(cfg.catalog.filter((s) => s.group === 'secret')) : [],
  );

  // Representative edge for the "Effective" column — first edge that has
  // reported a runtime block. The per-edge strip below shows all of them.
  let repEdge = $derived(
    cfg?.edges.find((e) => Object.keys(e.effective).length > 0) ?? cfg?.edges[0] ?? null,
  );
  let pendingTokens = $derived(new Set(cfg?.edges.flatMap((e) => e.restart_pending) ?? []));

  function effective(token: string): string {
    return repEdge?.effective[token] ?? '—';
  }
</script>

<div class="space-y-8">
  <div
    class="p-4 rounded-lg bg-(--info-bg) border border-(--info-border) text-(--info-text) text-sm"
  >
    <p class="font-semibold mb-1">Deploy-time settings</p>
    <p>
      These are process environment settings. Edits to edge values are pushed to every edge node
      but take effect only after the edge process <strong>restarts</strong> — they do not apply
      live like the other Settings tabs.
    </p>
  </div>

  {#if loading}
    <div class="space-y-2">
      {#each Array(8) as _, i (i)}
        <Skeleton variant="row" />
      {/each}
    </div>
  {:else if !cfg}
    <EmptyState title="Failed to load runtime config" body="Try refreshing the page." />
  {:else}
    <!-- Per-edge status -->
    <section>
      <h3 class="text-lg font-semibold text-(--text-primary) mb-3">Edge nodes</h3>
      {#if cfg.edges.length === 0}
        <EmptyState title="No edge nodes" body="No proxy has connected yet." />
      {:else}
        <div class="flex flex-wrap gap-3">
          {#each cfg.edges as edge (edge.node_id)}
            <div
              class="bg-(--bg-card) rounded-lg border border-(--border) px-4 py-3 flex items-center gap-3"
            >
              <span class="font-medium text-(--text-primary) text-sm">{edge.node_name}</span>
              <TagBadge color={edge.connected ? 'teal' : 'neutral'}>
                {edge.connected ? 'connected' : 'offline'}
              </TagBadge>
              {#if edge.restart_pending.length > 0}
                <TagBadge color="amber">
                  {edge.restart_pending.length} restart pending
                </TagBadge>
              {/if}
            </div>
          {/each}
        </div>
      {/if}
    </section>

    <!-- Edge runtime config — editable -->
    <section>
      <div class="flex items-center justify-between mb-4">
        <div>
          <h3 class="text-lg font-semibold text-(--text-primary)">Edge runtime config</h3>
          <p class="text-xs text-(--text-secondary) mt-0.5">
            Core + proxy settings. An empty override falls back to the edge's environment variable,
            then the compiled default.
          </p>
        </div>
        <div class="flex items-center gap-2">
          {#if dirty}
            <button
              onclick={discard}
              class="px-4 py-2 border border-(--border) rounded-lg text-sm text-(--text-secondary) hover:bg-(--bg-elevated) transition-colors"
            >Discard</button>
          {/if}
          <button
            onclick={save}
            disabled={!dirty || saving}
            class="px-5 py-2 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-sm font-medium transition-colors disabled:opacity-50"
          >{saving ? 'Saving…' : 'Save changes'}</button>
        </div>
      </div>

      {#if caDescriptor}
        <!-- Trusted CAs — multi-line PEM, its own panel (not a table row). -->
        <div class="bg-(--bg-card) rounded-xl border border-(--border) p-4 mb-4">
          <div class="flex items-center gap-2 mb-1.5">
            <h4 class="text-sm font-semibold text-(--text-primary)">Trusted CAs</h4>
            {#if pendingTokens.has(CA_TOKEN)}
              <TagBadge color="amber" title="A restart is needed to apply this on the edge">
                restart pending
              </TagBadge>
            {/if}
          </div>
          <p class="text-xs text-(--text-secondary) mb-3">
            PEM CA bundle trusted for all outbound HTTPS — upstream providers, the liveness probe,
            and model discovery — on top of the system roots. Paste one or more
            <span class="font-mono">-----BEGIN CERTIFICATE-----</span> blocks. Adding/validating a
            server picks this up immediately; proxy traffic applies it on the edge's next restart.
          </p>
          <textarea
            bind:value={editValues[CA_TOKEN]}
            rows="8"
            spellcheck="false"
            placeholder={'-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----'}
            class="w-full px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-xs font-mono focus:outline-hidden focus:border-(--accent) transition-colors resize-y"
          ></textarea>
        </div>
      {/if}

      <div class="bg-(--bg-card) rounded-xl border border-(--border) overflow-hidden">
        <table class="w-full text-sm">
          <thead>
            <tr class="border-b border-(--border) text-(--text-tertiary) text-xs uppercase tracking-wider">
              <th class="text-left font-medium px-4 py-2.5">Token</th>
              <th class="text-left font-medium px-4 py-2.5 w-40">
                Effective{repEdge ? ` · ${repEdge.node_name}` : ''}
              </th>
              <th class="text-left font-medium px-4 py-2.5 w-44">Override</th>
              <th class="text-left font-medium px-4 py-2.5">Description</th>
            </tr>
          </thead>
          <tbody>
            {#each edgeGroups as group (group.category)}
              <tr class="bg-(--bg-secondary)">
                <td colspan="4" class="px-4 py-1.5 text-xs font-semibold text-(--text-secondary) uppercase tracking-wider">
                  {group.category}
                </td>
              </tr>
              {#each group.items as s (s.token)}
                <tr class="border-t border-(--border)">
                  <td class="px-4 py-2.5 align-top">
                    <Copyable value={s.token} />
                    {#if pendingTokens.has(s.token)}
                      <span class="ml-2 align-middle">
                        <TagBadge color="amber" title="A restart is needed to apply this override">
                          restart pending
                        </TagBadge>
                      </span>
                    {/if}
                  </td>
                  <td class="px-4 py-2.5 align-top font-mono text-xs text-(--text-secondary)">
                    {effective(s.token)}
                  </td>
                  <td class="px-4 py-2.5 align-top">
                    <input
                      type="text"
                      inputmode={s.kind === 'integer' ? 'numeric' : 'text'}
                      bind:value={editValues[s.token]}
                      placeholder={s.default || '(default)'}
                      class="w-full px-2 py-1 bg-(--bg-primary) border border-(--border) rounded-sm text-(--text-primary) text-xs font-mono focus:outline-hidden focus:border-(--accent) transition-colors"
                    />
                  </td>
                  <td class="px-4 py-2.5 align-top text-xs text-(--text-secondary)">
                    {s.description}
                    <span class="text-(--text-tertiary)">Default: <span class="font-mono">{s.default || '—'}</span></span>
                  </td>
                </tr>
              {/each}
            {/each}
          </tbody>
        </table>
      </div>
    </section>

    <!-- Admin API — read-only -->
    <section>
      <h3 class="text-lg font-semibold text-(--text-primary) mb-1">Admin API</h3>
      <p class="text-xs text-(--text-secondary) mb-4">
        Live values from the admin-api process — read-only (set via the admin-api deploy environment).
      </p>
      <div class="bg-(--bg-card) rounded-xl border border-(--border) overflow-hidden">
        <table class="w-full text-sm">
          <thead>
            <tr class="border-b border-(--border) text-(--text-tertiary) text-xs uppercase tracking-wider">
              <th class="text-left font-medium px-4 py-2.5">Token</th>
              <th class="text-left font-medium px-4 py-2.5 w-44">Value</th>
              <th class="text-left font-medium px-4 py-2.5">Description</th>
            </tr>
          </thead>
          <tbody>
            {#each adminGroups as group (group.category)}
              <tr class="bg-(--bg-secondary)">
                <td colspan="3" class="px-4 py-1.5 text-xs font-semibold text-(--text-secondary) uppercase tracking-wider">
                  {group.category}
                </td>
              </tr>
              {#each group.items as s (s.token)}
                <tr class="border-t border-(--border)">
                  <td class="px-4 py-2.5 align-top"><Copyable value={s.token} /></td>
                  <td class="px-4 py-2.5 align-top font-mono text-xs text-(--text-secondary)">
                    {cfg.admin_values[s.token] || s.default || '—'}
                  </td>
                  <td class="px-4 py-2.5 align-top text-xs text-(--text-secondary)">{s.description}</td>
                </tr>
              {/each}
            {/each}
          </tbody>
        </table>
      </div>
    </section>

    <!-- Secrets & bootstrap — presence only -->
    <section>
      <h3 class="text-lg font-semibold text-(--text-primary) mb-1">Secrets &amp; bootstrap</h3>
      <p class="text-xs text-(--text-secondary) mb-4">
        Presence of secret and bootstrap variables in the admin-api process — values are never displayed.
      </p>
      <div class="bg-(--bg-card) rounded-xl border border-(--border) overflow-hidden">
        <table class="w-full text-sm">
          <thead>
            <tr class="border-b border-(--border) text-(--text-tertiary) text-xs uppercase tracking-wider">
              <th class="text-left font-medium px-4 py-2.5">Token</th>
              <th class="text-left font-medium px-4 py-2.5 w-44">Status</th>
              <th class="text-left font-medium px-4 py-2.5">Description</th>
            </tr>
          </thead>
          <tbody>
            {#each secretGroups as group (group.category)}
              <tr class="bg-(--bg-secondary)">
                <td colspan="3" class="px-4 py-1.5 text-xs font-semibold text-(--text-secondary) uppercase tracking-wider">
                  {group.category}
                </td>
              </tr>
              {#each group.items as s (s.token)}
                <tr class="border-t border-(--border)">
                  <td class="px-4 py-2.5 align-top"><Copyable value={s.token} /></td>
                  <td class="px-4 py-2.5 align-top">
                    <TagBadge color={cfg.secrets_present[s.token] ? 'teal' : 'rose'}>
                      {cfg.secrets_present[s.token] ? 'set' : 'not set'}
                    </TagBadge>
                  </td>
                  <td class="px-4 py-2.5 align-top text-xs text-(--text-secondary)">{s.description}</td>
                </tr>
              {/each}
            {/each}
          </tbody>
        </table>
      </div>
    </section>
  {/if}
</div>

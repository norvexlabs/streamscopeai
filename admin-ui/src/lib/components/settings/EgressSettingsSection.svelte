<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractError } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import Skeleton from '#lib/components/Skeleton.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import type { components } from '#lib/generated/api-types.js';
  import { onMount } from 'svelte';

  type Egress = components['schemas']['EgressSettings'];
  type Surface = Extract<keyof Egress, string>;

  const SURFACES: { id: Surface; label: string; hint: string }[] = [
    { id: 'llm', label: 'LLM providers', hint: 'Gateway requests to a provider, liveness checks, model discovery, replica endpoints.' },
    { id: 'mcp', label: 'MCP servers', hint: 'Upstream MCP servers and their OAuth endpoints.' },
    { id: 'a2a', label: 'A2A agents', hint: 'Upstream agents and their agent cards.' },
    { id: 'oidc', label: 'Identity providers', hint: 'OpenID Connect issuers: discovery, signing keys, token exchange.' },
    { id: 'extensions', label: 'Extensions', hint: 'The web search backend and the guardrail classifier an organisation sets.' },
    { id: 'upstream_token', label: 'Upstream token endpoints', hint: 'Token endpoints a minting provider exchanges its stored credential at.' },
    { id: 'web', label: 'Web fetch', hint: 'URLs the built-in web tool fetches — chosen by end users and models.' },
    { id: 'cimd', label: 'Client metadata documents', hint: 'OAuth client metadata URLs a client advertises — reachable without signing in.' },
  ];

  let loading = $state(true);
  let saving = $state(false);
  let original = $state<Record<Surface, string> | null>(null);
  let edit = $state<Record<Surface, string> | null>(null);

  function toText(e: Egress): Record<Surface, string> {
    const out = {} as Record<Surface, string>;
    for (const s of SURFACES) out[s.id] = e[s.id].join('\n');
    return out;
  }

  function toList(text: string): string[] {
    return text
      .split(/[\n,]/)
      .map((v) => v.trim())
      .filter((v) => v !== '');
  }

  async function load() {
    loading = true;
    const { data, error } = await adminApi.GET('/api/v1/admin/global/egress');
    if (error) {
      toast.error(extractError(error, 'Failed to load the egress lists'));
    } else if (data) {
      original = toText(data);
      edit = { ...original };
    }
    loading = false;
  }

  onMount(load);

  let changed = $derived(
    original && edit
      ? SURFACES.filter((s) => toList(edit![s.id]).join('\n') !== toList(original![s.id]).join('\n')).map((s) => s.id)
      : [],
  );

  async function save() {
    if (!edit || changed.length === 0 || saving) return;
    saving = true;
    const body: components['schemas']['UpdateEgressSettings'] = {};
    for (const id of changed) body[id] = toList(edit[id]);
    const { data, error } = await adminApi.PATCH('/api/v1/admin/global/egress', { body });
    if (error) {
      toast.error(extractError(error, 'Failed to save the egress lists'));
    } else if (data) {
      original = toText(data);
      edit = { ...original };
      toast.success('Egress lists saved — gateways apply them within seconds, no restart.');
    }
    saving = false;
  }

  function discard() {
    if (original) edit = { ...original };
  }
</script>

<div class="space-y-6">
  <div class="p-4 rounded-lg bg-(--info-bg) border border-(--info-border) text-(--info-text) text-sm">
    <p class="font-semibold mb-1">Internal egress</p>
    <p>
      Which private-network destinations each kind of outbound call may reach. Public addresses are
      always reachable and the cloud metadata endpoint never is. One entry per line:
      <span class="font-mono">*</span> (every private address), an IP address, a CIDR prefix
      (<span class="font-mono">10.0.0.0/8</span>) or a host name (that exact name). An empty list
      reaches no private address. Changes apply to every gateway without a restart.
    </p>
  </div>

  {#if loading}
    <div class="space-y-2">
      {#each Array(6) as _, i (i)}
        <Skeleton variant="row" />
      {/each}
    </div>
  {:else if !edit}
    <EmptyState title="Failed to load the egress lists" body="Try refreshing the page." />
  {:else}
    <div class="flex items-center justify-end gap-2">
      {#if changed.length > 0}
        <button
          onclick={discard}
          class="px-4 py-2 border border-(--border) rounded-lg text-sm text-(--text-secondary) hover:bg-(--bg-elevated) transition-colors"
        >Discard</button>
      {/if}
      <button
        onclick={save}
        disabled={changed.length === 0 || saving}
        class="px-5 py-2 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-sm font-medium transition-colors disabled:opacity-50"
      >{saving ? 'Saving…' : 'Save changes'}</button>
    </div>

    <div class="grid gap-4 md:grid-cols-2">
      {#each SURFACES as s (s.id)}
        <div class="bg-(--bg-card) rounded-xl border border-(--border) p-4">
          <label for={`egress-${s.id}`} class="block text-sm font-semibold text-(--text-primary)">{s.label}</label>
          <p class="text-xs text-(--text-secondary) mt-0.5 mb-2">{s.hint}</p>
          <textarea
            id={`egress-${s.id}`}
            data-surface={s.id}
            bind:value={edit[s.id]}
            rows="4"
            spellcheck="false"
            placeholder="No private address"
            class="w-full px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-xs font-mono focus:outline-hidden focus:border-(--accent) transition-colors resize-y"
          ></textarea>
        </div>
      {/each}
    </div>
  {/if}
</div>

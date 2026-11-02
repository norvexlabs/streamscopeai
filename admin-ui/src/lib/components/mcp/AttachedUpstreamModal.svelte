<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractError } from '#lib/api-helpers.js';
  import type { components } from '#lib/generated/api-types.js';
  import Modal from '#lib/components/Modal.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';

  type VirtualServerRow = components['schemas']['McpVirtualServerRow'];
  type UpstreamRow = components['schemas']['McpUpstreamServerRow'];
  type VirtualRouteRow = components['schemas']['McpVirtualRouteRow'];

  interface Props {
    open: boolean;
    editing: VirtualRouteRow | null;
    /** Endpoint the new route is being attached to (the user expanded that
     * endpoint's card to invoke this modal). Ignored on edit. */
    defaultVirtualServerId?: string;
    /** Position to assign on create — caller computes "append at end" from
     * existing siblings. Ignored on edit (reorder via row-level arrows). */
    defaultPosition?: number;
    virtualServers: VirtualServerRow[];
    upstreams: UpstreamRow[];
    onclose: () => void;
    onsaved: () => void;
  }

  let {
    open,
    editing,
    defaultVirtualServerId,
    defaultPosition,
    virtualServers,
    upstreams,
    onclose,
    onsaved,
  }: Props = $props();

  type FilterMode = 'none' | 'allow' | 'deny';

  type FilterState = { mode: FilterMode; list: string };

  function filterFromJson(value: unknown): FilterState {
    if (!value || typeof value !== 'object') return { mode: 'none', list: '' };
    const v = value as { allow?: unknown; deny?: unknown };
    if (Array.isArray(v.allow) && v.allow.length > 0) {
      return { mode: 'allow', list: v.allow.filter((x): x is string => typeof x === 'string').join(', ') };
    }
    if (Array.isArray(v.deny) && v.deny.length > 0) {
      return { mode: 'deny', list: v.deny.filter((x): x is string => typeof x === 'string').join(', ') };
    }
    return { mode: 'none', list: '' };
  }

  function filterToJson(state: FilterState): Record<string, string[]> | null {
    if (state.mode === 'none') return null;
    const items = state.list
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (items.length === 0) return null;
    return { [state.mode]: items };
  }

  let form = $state({
    virtual_server_id: '',
    upstream_server_id: '',
    prefix: '',
    enabled: true,
    position: 0,
    tools: { mode: 'none', list: '' } as FilterState,
    resources: { mode: 'none', list: '' } as FilterState,
    prompts: { mode: 'none', list: '' } as FilterState,
  });
  let formError = $state('');
  let advancedOpen = $state(false);

  $effect(() => {
    if (open) {
      if (editing) {
        // Build the filter states as locals first: this effect writes `form`,
        // so it must not also *read* `form` — a self-referential dependency
        // re-triggers the effect on every write. Derive `advancedOpen` from
        // the locals instead.
        const tools = filterFromJson(editing.tools_filter);
        const resources = filterFromJson(editing.resources_filter);
        const prompts = filterFromJson(editing.prompts_filter);
        form = {
          virtual_server_id: editing.virtual_server_id,
          upstream_server_id: editing.upstream_server_id,
          prefix: editing.prefix,
          enabled: editing.enabled,
          position: editing.position,
          tools,
          resources,
          prompts,
        };
        advancedOpen = resources.mode !== 'none' || prompts.mode !== 'none';
      } else {
        form = {
          virtual_server_id: defaultVirtualServerId ?? '',
          upstream_server_id: upstreams[0]?.id ?? '',
          prefix: '',
          enabled: true,
          position: defaultPosition ?? 0,
          tools: { mode: 'none', list: '' },
          resources: { mode: 'none', list: '' },
          prompts: { mode: 'none', list: '' },
        };
        advancedOpen = false;
      }
      formError = '';
    }
  });

  function upstreamName(id: string): string {
    return upstreams.find((u) => u.id === id)?.name ?? id;
  }

  function endpointSlug(id: string): string {
    return virtualServers.find((v) => v.id === id)?.slug ?? '(unknown)';
  }

  async function save() {
    formError = '';
    const tools_filter = filterToJson(form.tools);
    const resources_filter = filterToJson(form.resources);
    const prompts_filter = filterToJson(form.prompts);

    if (editing) {
      const { error } = await adminApi.PATCH(
        '/api/v1/admin/mcp/virtual-routes/{id}',
        {
          params: { path: { id: editing.id } },
          body: {
            prefix: form.prefix,
            enabled: form.enabled,
            tools_filter,
            resources_filter,
            prompts_filter,
          },
        },
      );
      if (error) {
        formError = extractError(error);
        return;
      }
    } else {
      const { error } = await adminApi.POST(
        '/api/v1/admin/mcp/virtual-routes',
        {
          body: {
            virtual_server_id: form.virtual_server_id,
            upstream_server_id: form.upstream_server_id,
            prefix: form.prefix,
            enabled: form.enabled,
            position: form.position,
            tools_filter,
            resources_filter,
            prompts_filter,
          },
        },
      );
      if (error) {
        formError = extractError(error);
        return;
      }
    }
    onsaved();
  }
</script>

{#if open}
  <Modal {open} title={editing ? 'Edit attached upstream' : 'Attach upstream'} {onclose}>
    {#if formError}
      <div class="bg-(--error-bg) border border-(--error-border) text-(--error-text) p-2 rounded-sm mb-3 text-sm">
        {formError}
      </div>
    {/if}

    <div class="space-y-4">
      <!-- Endpoint is always locked — create flow inherits it from the
           expanded card, edit flow cannot change it (immutable column). -->
      <div>
        <p class="text-xs text-(--text-secondary) uppercase tracking-wider">Endpoint</p>
        <p class="text-sm text-(--text-primary) font-mono mt-1">/mcp/{endpointSlug(form.virtual_server_id)}</p>
      </div>

      {#if editing}
        <div>
          <p class="text-xs text-(--text-secondary) uppercase tracking-wider">Upstream (locked)</p>
          <p class="text-sm text-(--text-primary) font-mono mt-1">{upstreamName(form.upstream_server_id)}</p>
        </div>
      {:else}
        <label class="block">
          <span class="text-sm font-medium text-(--text-primary)">Upstream</span>
          <SelectInput class="mt-1" bind:value={form.upstream_server_id}>
            {#each upstreams as u (u.id)}
              <option value={u.id}>{u.name}</option>
            {/each}
          </SelectInput>
        </label>
      {/if}

      <label class="block">
        <span class="text-sm font-medium text-(--text-primary)">Namespace prefix</span>
        <TextInput
          mono
          class="mt-1"
          placeholder="(empty = first attached, no namespacing)"
          bind:value={form.prefix} />
        <span class="text-xs text-(--text-secondary)"
          >If non-empty: up to 16 lowercase letters, digits and single underscores, starting with a
          letter and not ending in an underscore. Tools/prompts surface as
          <code>&lt;prefix&gt;__&lt;name&gt;</code>.</span>
      </label>

      <!-- Tools filter — primary filter, always visible -->
      <fieldset class="border border-(--border) rounded-lg p-3">
        <legend class="px-1 text-sm font-medium text-(--text-primary)">Tools filter</legend>
        <div class="space-y-2">
          <label class="flex items-center gap-2 text-sm text-(--text-primary)">
            <input type="radio" bind:group={form.tools.mode} name="tools-mode" value="none" />
            <span>No filter (all tools surface)</span>
          </label>
          <label class="flex items-center gap-2 text-sm text-(--text-primary)">
            <input type="radio" bind:group={form.tools.mode} name="tools-mode" value="allow" />
            <span>Allow only</span>
          </label>
          <label class="flex items-center gap-2 text-sm text-(--text-primary)">
            <input type="radio" bind:group={form.tools.mode} name="tools-mode" value="deny" />
            <span>Deny only</span>
          </label>
          {#if form.tools.mode !== 'none'}
            <TextInput
              mono
              placeholder="create_issue, list_pulls, …"
              bind:value={form.tools.list} />
            <span class="block text-xs text-(--text-secondary)">Comma- or space-separated tool names. Empty list = no filter.</span>
          {/if}
        </div>
      </fieldset>

      <!-- Advanced disclosure for resources + prompts (rarely used) -->
      <div class="border border-(--border) rounded-lg">
        <button
          type="button"
          class="w-full flex items-center justify-between px-3 py-2 text-sm text-(--text-primary) hover:bg-(--bg-elevated)"
          onclick={() => (advancedOpen = !advancedOpen)}>
          <span>
            <span class="text-(--text-secondary)">{advancedOpen ? '▾' : '▸'}</span>
            Advanced filters (resources, prompts — rarely used)
          </span>
          {#if (form.resources.mode !== 'none' || form.prompts.mode !== 'none') && !advancedOpen}
            <span class="text-xs text-(--accent)">configured</span>
          {/if}
        </button>
        {#if advancedOpen}
          <div class="px-3 pb-3 pt-1 space-y-3">
            <!-- Resources -->
            <fieldset class="border border-(--border) rounded-lg p-3">
              <legend class="px-1 text-sm font-medium text-(--text-primary)">Resources filter</legend>
              <div class="space-y-2">
                <label class="flex items-center gap-2 text-sm text-(--text-primary)">
                  <input type="radio" bind:group={form.resources.mode} name="res-mode" value="none" />
                  <span>No filter</span>
                </label>
                <label class="flex items-center gap-2 text-sm text-(--text-primary)">
                  <input type="radio" bind:group={form.resources.mode} name="res-mode" value="allow" />
                  <span>Allow only</span>
                </label>
                <label class="flex items-center gap-2 text-sm text-(--text-primary)">
                  <input type="radio" bind:group={form.resources.mode} name="res-mode" value="deny" />
                  <span>Deny only</span>
                </label>
                {#if form.resources.mode !== 'none'}
                  <TextInput
                    mono
                    placeholder="resource://repo/main, …"
                    bind:value={form.resources.list} />
                  <span class="block text-xs text-(--text-secondary)">Comma- or space-separated resource URIs.</span>
                {/if}
              </div>
            </fieldset>
            <!-- Prompts -->
            <fieldset class="border border-(--border) rounded-lg p-3">
              <legend class="px-1 text-sm font-medium text-(--text-primary)">Prompts filter</legend>
              <div class="space-y-2">
                <label class="flex items-center gap-2 text-sm text-(--text-primary)">
                  <input type="radio" bind:group={form.prompts.mode} name="prompt-mode" value="none" />
                  <span>No filter</span>
                </label>
                <label class="flex items-center gap-2 text-sm text-(--text-primary)">
                  <input type="radio" bind:group={form.prompts.mode} name="prompt-mode" value="allow" />
                  <span>Allow only</span>
                </label>
                <label class="flex items-center gap-2 text-sm text-(--text-primary)">
                  <input type="radio" bind:group={form.prompts.mode} name="prompt-mode" value="deny" />
                  <span>Deny only</span>
                </label>
                {#if form.prompts.mode !== 'none'}
                  <TextInput
                    mono
                    placeholder="summarise_pr, …"
                    bind:value={form.prompts.list} />
                  <span class="block text-xs text-(--text-secondary)">Comma- or space-separated prompt ids.</span>
                {/if}
              </div>
            </fieldset>
          </div>
        {/if}
      </div>

      <label class="flex items-center gap-2">
        <input type="checkbox" bind:checked={form.enabled} />
        <span class="text-sm">Enabled</span>
      </label>
    </div>

    <div class="flex justify-end gap-2 mt-4">
      <button
        type="button"
        class="px-3 py-1 rounded-lg border border-(--border) text-sm text-(--text-secondary) hover:text-(--text-primary) hover:bg-(--bg-elevated) transition-colors"
        onclick={onclose}>Cancel</button>
      <button
        type="button"
        class="px-3 py-1 bg-(--accent) hover:bg-(--accent-hover) text-(--accent-fg) rounded-lg text-sm font-medium"
        onclick={save}>Save</button>
    </div>
  </Modal>
{/if}

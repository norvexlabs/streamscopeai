<script lang="ts">
  /**
   * Portal — the user's own values for an MCP upstream's inputs (an API
   * token, an organisation…), generated from the inputs the upstream
   * declares. A non-secret field is prefilled with the user's own stored
   * value (emptying it erases it); a stored secret is never shown: it reads
   * "set", a blank field keeps it, and Clear erases it. Values the
   * administrator set are not listed at all.
   */
  import { portalApi } from '#lib/portal-client.js';
  import { extractError } from '#lib/api-helpers.js';
  import { portalInputsInitial, portalInputsMissing, portalInputsPatch } from '#lib/mcp/headerInputs.js';
  import type { components } from '#lib/generated/api-types.js';
  import Modal from '#lib/components/Modal.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import { m } from '#lib/paraglide/messages.js';
  import { untrack } from 'svelte';

  type Connection = components['schemas']['PortalConnectionItem'];

  interface Props {
    /** The connection whose inputs are edited; `null` closes the modal. */
    item: Connection | null;
    onclose: () => void;
    onsaved: () => void;
  }

  let { item, onclose, onsaved }: Props = $props();

  let values = $state<Record<string, string>>({});
  let cleared = $state<Set<string>>(new Set());
  let error = $state('');
  let saving = $state(false);

  // Before the fields render: each binds to a key this sets.
  $effect.pre(() => {
    const it = item;
    if (!it) return;
    untrack(() => {
      values = portalInputsInitial(it.inputs);
      cleared = new Set();
      error = '';
    });
  });

  function toggleClear(id: string, on: boolean) {
    const next = new Set(cleared);
    if (on) next.add(id);
    else {
      next.delete(id);
      // Undo puts the prefilled value back: a blank prefilled field would
      // otherwise read as "erase it" on save.
      const initial = item ? portalInputsInitial(item.inputs)[id] : undefined;
      if (initial !== undefined && (values[id] ?? '') === '') values = { ...values, [id]: initial };
    }
    cleared = next;
    if (on) values[id] = '';
  }

  async function save() {
    if (!item) return;
    error = '';
    const missing = portalInputsMissing(item.inputs, values, cleared);
    if (missing.length > 0) {
      error = m.portal_mcp_inputs_required_missing({ fields: missing.join(', ') });
      return;
    }
    const body = portalInputsPatch(item.inputs, values, cleared);
    saving = true;
    const { error: err } = await portalApi.PATCH('/api/v1/portal/mcp/connections/{upstream_id}/inputs', {
      params: { path: { upstream_id: item.upstream_server_id } },
      body,
    });
    saving = false;
    if (err) {
      error = extractError(err, m.portal_mcp_inputs_failed());
      return;
    }
    onsaved();
  }
</script>

<Modal
  open={item !== null}
  title={item ? m.portal_mcp_inputs_title({ name: item.upstream_name }) : ''}
  {onclose}
  maxWidth="max-w-lg"
>
  {#if item}
    <div class="space-y-3 text-sm" data-testid="mcp-inputs-form">
      <p class="text-xs text-(--text-secondary)">{m.portal_mcp_inputs_intro({ name: item.upstream_name })}</p>
      {#each item.inputs as input (input.id)}
        {@const isCleared = cleared.has(input.id)}
        {@const keepsBlank = input.filled && (input.is_secret || input.value == null)}
        <div class="space-y-1" data-testid="mcp-input" data-input-id={input.id}>
          <div class="flex items-center gap-2">
            <span class="text-xs font-mono text-(--text-primary)">{input.id}</span>
            {#if input.is_required}<span class="text-xs text-(--warning-text)">*</span>{/if}
            {#if input.filled && !isCleared}
              <span class="px-1.5 py-0.5 text-[10px] rounded-sm bg-(--success-bg) text-(--success-text)" data-testid="input-set">{m.portal_mcp_inputs_set()}</span>
              <button type="button" class="text-xs text-(--error) hover:bg-(--error-bg) px-1 rounded-sm" data-testid="input-clear" onclick={() => toggleClear(input.id, true)}>{m.portal_mcp_inputs_clear()}</button>
            {/if}
          </div>
          {#if input.description}
            <p class="text-xs text-(--text-secondary)">{input.description}</p>
          {/if}
          {#if isCleared}
            <div class="flex items-center gap-2 text-xs text-(--warning-text)">
              {m.portal_mcp_inputs_cleared()}
              <button type="button" class="text-(--accent) hover:text-(--accent-hover)" onclick={() => toggleClear(input.id, false)}>{m.portal_mcp_inputs_undo()}</button>
            </div>
          {:else if input.choices.length > 0 || input.format === 'boolean'}
            <SelectInput bind:value={values[input.id]} data-testid="input-value">
              <option value="">{keepsBlank ? m.portal_mcp_inputs_keep_placeholder() : m.portal_mcp_inputs_choose()}</option>
              {#each input.choices.length > 0 ? input.choices : ['true', 'false'] as c}
                <option value={c}>{c}</option>
              {/each}
            </SelectInput>
          {:else}
            <TextInput
              type={input.is_secret ? 'password' : 'text'}
              inputmode={input.format === 'number' ? 'decimal' : undefined}
              mono
              autocomplete="off"
              placeholder={keepsBlank ? m.portal_mcp_inputs_keep_placeholder() : (input.placeholder ?? input.default ?? '')}
              bind:value={values[input.id]}
              data-testid="input-value" />
          {/if}
        </div>
      {/each}
      {#if item.kind === 'oauth_inputs' && item.status !== 'connected'}
        <p class="text-xs text-(--text-secondary)">{m.portal_mcp_inputs_then_sign_in()}</p>
      {/if}
      <p class="text-xs text-(--text-secondary)" data-testid="inputs-propagation">{m.portal_mcp_inputs_propagation()}</p>
      {#if error}
        <div class="rounded-lg border border-(--error-border) bg-(--error-bg) px-3 py-2 text-xs text-(--error-text)" data-testid="inputs-error">{error}</div>
      {/if}
    </div>
  {/if}

  {#snippet footer()}
    <button
      type="button"
      class="rounded-lg border border-(--border) px-3 py-2 text-sm text-(--text-secondary) hover:bg-(--bg-primary)"
      onclick={onclose}
      disabled={saving}
    >{m.portal_mcp_inputs_cancel()}</button>
    <button
      type="button"
      data-testid="inputs-save"
      class="rounded-lg bg-(--accent) px-3 py-2 text-sm font-medium text-(--accent-fg) hover:bg-(--accent-hover) disabled:opacity-50"
      onclick={save}
      disabled={saving}
    >{m.portal_mcp_inputs_save()}</button>
  {/snippet}
</Modal>

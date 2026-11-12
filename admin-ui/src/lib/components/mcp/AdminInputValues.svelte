<script lang="ts">
  /**
   * Value fields for the administrator-filled inputs of an upstream. A
   * non-secret value is shown and edited in place; a stored secret is never
   * shown — it reads "set" and can be replaced or cleared.
   */
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import type { DeclaredInput, SecretEdit } from '#lib/mcp/headerInputs.js';

  interface Props {
    /** The administrator-filled inputs, in declaration order. */
    inputs: DeclaredInput[];
    plain: Record<string, string>;
    secrets: Record<string, SecretEdit>;
    /** Secret ids that already hold a stored value. */
    storedSecrets?: string[];
  }

  let { inputs, plain = $bindable(), secrets = $bindable(), storedSecrets = [] }: Props = $props();

  // Every input gets its entry before it renders, so each field binds to a
  // value that exists: a stored secret starts as "keep", any other as empty.
  $effect.pre(() => {
    for (const d of inputs) {
      if (d.isSecret && !secrets[d.id]) {
        secrets[d.id] = { action: storedSecrets.includes(d.id) ? 'keep' : 'replace', value: '' };
      }
      if (!d.isSecret && plain[d.id] === undefined) plain[d.id] = '';
    }
  });
</script>

{#if inputs.length > 0}
  <div class="space-y-2 rounded-lg border border-(--border) p-3" data-testid="admin-input-values">
    <div class="text-xs uppercase tracking-wide text-(--text-secondary)">Administrator values</div>
    {#each inputs as d (d.id)}
      {@const stored = storedSecrets.includes(d.id)}
      <div class="block" data-testid="admin-input" data-input-id={d.id}>
        <span class="text-xs text-(--text-primary) font-mono">
          {d.id}{#if d.isRequired}<span class="text-(--warning-text)"> *</span>{/if}
        </span>
        {#if d.input.description}
          <span class="text-xs text-(--text-secondary) ml-1">{d.input.description}</span>
        {/if}
        {#if d.isSecret}
          {@const s = secrets[d.id] ?? { action: 'replace', value: '' }}
          {#if !secrets[d.id]}
            <!-- filled in by the effect above before the next paint -->
          {:else if stored && s.action === 'keep'}
            <div class="flex items-center gap-2 mt-1">
              <span class="px-1.5 py-0.5 text-[10px] rounded-sm bg-(--success-bg) text-(--success-text)" data-testid="secret-set">set</span>
              <button type="button" class="text-xs text-(--accent) hover:text-(--accent-hover)" data-testid="secret-replace" onclick={() => (secrets[d.id] = { action: 'replace', value: '' })}>Replace</button>
              <button type="button" class="text-xs text-(--error) hover:bg-(--error-bg) px-1 rounded-sm" data-testid="secret-clear" onclick={() => (secrets[d.id] = { action: 'clear', value: '' })}>Clear</button>
            </div>
          {:else if s.action === 'clear'}
            <div class="flex items-center gap-2 mt-1 text-xs text-(--warning-text)">
              Cleared on save.
              <button type="button" class="text-(--accent) hover:text-(--accent-hover)" onclick={() => (secrets[d.id] = { action: 'keep', value: '' })}>Undo</button>
            </div>
          {:else}
            <div class="flex items-center gap-2 mt-1">
              <TextInput
                type="password"
                mono
                autocomplete="off"
                placeholder={stored ? 'new value' : 'secret value, encrypted at rest'}
                bind:value={secrets[d.id].value}
                data-testid="admin-input-value" />
              {#if stored}
                <button type="button" class="text-xs text-(--text-secondary) hover:text-(--text-primary) shrink-0" onclick={() => (secrets[d.id] = { action: 'keep', value: '' })}>Keep current</button>
              {/if}
            </div>
          {/if}
        {:else if plain[d.id] === undefined}
          <!-- filled in by the effect above before the next paint -->
        {:else if (d.input.choices ?? []).length > 0}
          <SelectInput bind:value={plain[d.id]} class="mt-1" data-testid="admin-input-value">
            <option value="">—</option>
            {#each d.input.choices ?? [] as c}
              <option value={c}>{c}</option>
            {/each}
          </SelectInput>
        {:else}
          <TextInput
            mono
            class="mt-1"
            placeholder={d.input.placeholder ?? d.input.default ?? ''}
            bind:value={plain[d.id]}
            data-testid="admin-input-value" />
        {/if}
      </div>
    {/each}
  </div>
{/if}

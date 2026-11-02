<script lang="ts">
  // Unified role/scope picker — the single "pick an authority level" control.
  // Used everywhere an account role or key scope is chosen (console role on the
  // Accounts tab, ak- key scope in the automation mint modal) so the levels
  // always read the same way: a stacked radio-card per option with the label
  // and a one-line description of what it grants.
  export interface ScopeOption {
    value: string;
    label: string;
    description: string;
    disabled?: boolean;
  }

  let {
    options,
    value = $bindable(),
    label,
  }: {
    options: ScopeOption[];
    value: string;
    /** Optional uppercase field label above the cards. */
    label?: string;
  } = $props();
</script>

<div>
  {#if label}
    <span class="text-[10px] text-(--text-secondary) uppercase tracking-wider mb-1.5 block">{label}</span>
  {/if}
  <div class="space-y-1.5" role="radiogroup" aria-label={label}>
    {#each options as opt (opt.value)}
      <label
        class="flex items-start gap-3 px-3 py-2 rounded-lg border cursor-pointer transition-colors
          {value === opt.value
            ? 'border-(--accent) bg-(--accent)/10'
            : 'border-(--border) bg-(--bg-primary) hover:border-(--text-secondary)'}
          {opt.disabled ? 'opacity-50 cursor-not-allowed' : ''}"
      >
        <input
          type="radio"
          bind:group={value}
          value={opt.value}
          disabled={opt.disabled}
          data-option={opt.value}
          class="mt-1 accent-(--accent)"
        />
        <span class="min-w-0">
          <span class="block text-sm font-medium text-(--text-primary)">{opt.label}</span>
          <span class="block text-xs text-(--text-secondary)">{opt.description}</span>
        </span>
      </label>
    {/each}
  </div>
</div>

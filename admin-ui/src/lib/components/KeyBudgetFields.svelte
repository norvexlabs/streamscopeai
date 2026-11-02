<script lang="ts">
  import BudgetModeToggle from '#lib/components/BudgetModeToggle.svelte';
  import { m } from '#lib/paraglide/messages.js';

  // Per-key budget inputs (daily/monthly cap + enforce|alert-only mode), shared
  // by the create-key form, the manager mint form, and the edit-budget modal.
  // `string | number`: Svelte coerces `bind:value` on `type="number"` inputs to
  // a number — `buildKeyBudget`/`parseCap` accept both.
  interface Props {
    daily: string | number;
    monthly: string | number;
    mode: 'enforce' | 'alert_only';
  }
  let { daily = $bindable(), monthly = $bindable(), mode = $bindable() }: Props = $props();
</script>

<div>
  <span class="text-[10px] text-(--text-secondary) uppercase tracking-wider mb-1.5 block">{m.portal_comp_per_key_budget()} <span class="normal-case text-(--text-secondary)">{m.portal_comp_optional_paren()}</span></span>
  <div class="flex items-center gap-2">
    <div class="flex-1">
      <div class="relative">
        <span class="absolute left-3 top-1/2 -translate-y-1/2 text-sm text-(--text-secondary)">$</span>
        <input
          type="number" min="0" step="0.01" inputmode="decimal"
          bind:value={daily}
          placeholder={m.portal_comp_daily()}
          class="w-full pl-6 pr-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-sm text-(--text-primary) placeholder:text-(--text-secondary) focus:outline-hidden focus:border-(--accent)"
        />
      </div>
    </div>
    <div class="flex-1">
      <div class="relative">
        <span class="absolute left-3 top-1/2 -translate-y-1/2 text-sm text-(--text-secondary)">$</span>
        <input
          type="number" min="0" step="0.01" inputmode="decimal"
          bind:value={monthly}
          placeholder={m.portal_comp_monthly()}
          class="w-full pl-6 pr-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-sm text-(--text-primary) placeholder:text-(--text-secondary) focus:outline-hidden focus:border-(--accent)"
        />
      </div>
    </div>
  </div>
  <div class="mt-2">
    <BudgetModeToggle bind:mode />
  </div>
  <p class="text-[10px] text-(--text-secondary) mt-1">
    {mode === 'alert_only'
      ? m.portal_comp_overcap_alert()
      : m.portal_comp_overcap_enforce()}
  </p>
</div>

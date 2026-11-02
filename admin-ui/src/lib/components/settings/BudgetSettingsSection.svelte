<script lang="ts">
  // Org-total budget ceiling: one cap across every workspace in the tenant.
  // Distinct from a workspace's own budget (set on the workspace) — this one
  // bounds what the whole organisation can spend in a window.
  import { adminApi } from '#lib/api-client.js';
  import { extractSettings, extractError, extractErrorCode, updateSettings } from '#lib/api-helpers.js';
  import FormField from '#lib/components/forms/FormField.svelte';
  import NumberInput from '#lib/components/forms/NumberInput.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import { accountingCurrency } from '#lib/currency.svelte.js';
  import { toast } from '#lib/toast.svelte.js';
  import { onMount } from 'svelte';

  let dailyBudget = $state(0);
  let monthlyBudget = $state(0);
  let mode = $state<'enforce' | 'alert_only'>('enforce');
  let saving = $state(false);

  const uncapped = $derived(dailyBudget <= 0 && monthlyBudget <= 0);

  async function loadConfig() {
    const { data, error: err } = await adminApi.GET('/api/v1/admin/settings');
    if (err) {
      toast.error('Failed to load budget settings', {
        body: extractError(err),
        code: extractErrorCode(err) ?? undefined,
      });
      return;
    }
    if (!data) return;
    const s = extractSettings(data);
    dailyBudget = s.tenant_daily_budget ?? 0;
    monthlyBudget = s.tenant_monthly_budget ?? 0;
    mode = s.tenant_budget_mode === 'alert_only' ? 'alert_only' : 'enforce';
  }

  async function handleSave() {
    saving = true;
    const { error: err } = await updateSettings({
      tenant_daily_budget: dailyBudget,
      tenant_monthly_budget: monthlyBudget,
      tenant_budget_mode: mode,
    });
    if (err) {
      toast.error('Failed to save the organisation ceiling', {
        body: extractError(err),
        code: extractErrorCode(err) ?? undefined,
      });
    } else {
      toast.success('Organisation ceiling saved');
    }
    saving = false;
  }

  onMount(loadConfig);
</script>

<div class="space-y-4">
  <div>
    <h3 class="text-lg font-semibold text-(--text-primary)">Organisation Ceiling</h3>
    <p class="text-sm text-(--text-secondary) mt-1">
      A single cap across every workspace. Each workspace's spend counts toward it, so it bounds
      total spend even when no individual workspace is over its own budget. Set either window to 0
      to leave it uncapped.
    </p>
  </div>

  <div class="bg-(--bg-card) rounded-xl p-6 border border-(--border)">
    <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
      <FormField label="Daily ceiling ({accountingCurrency()})" for="tenant-daily-budget" help="0 = uncapped">
        <NumberInput id="tenant-daily-budget" bind:value={dailyBudget} min="0" step="1" mono />
      </FormField>
      <FormField label="Monthly ceiling ({accountingCurrency()})" for="tenant-monthly-budget" help="0 = uncapped">
        <NumberInput id="tenant-monthly-budget" bind:value={monthlyBudget} min="0" step="1" mono />
      </FormField>
      <FormField
        label="When over cap"
        for="tenant-budget-mode"
        help="Alert only keeps serving requests and still raises the crossing alert."
      >
        <SelectInput id="tenant-budget-mode" bind:value={mode}>
          <option value="enforce">Reject requests</option>
          <option value="alert_only">Alert only</option>
        </SelectInput>
      </FormField>
    </div>

    <div class="flex items-center gap-3 mt-5">
      <button
        onclick={handleSave}
        disabled={saving}
        class="px-5 py-2 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-sm font-medium transition-colors disabled:opacity-50"
      >{saving ? 'Saving…' : 'Save'}</button>
      {#if uncapped}
        <span class="text-xs text-(--text-secondary)">
          No organisation ceiling — only per-workspace, per-user and per-key budgets apply.
        </span>
      {/if}
    </div>
  </div>
</div>

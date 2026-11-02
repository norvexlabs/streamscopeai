<script lang="ts">
  // Accounting — the currency every budget cap, spend aggregate and audit total
  // is reported in, plus the conversion table that gets a provider's own quote
  // into it. A model priced in a currency with no usable rate records NO spend
  // and its requests are flagged, so `unconvertible` is the operator's checklist
  // and is surfaced above everything else on this tab.
  import { adminApi } from '#lib/api-client.js';
  import { extractError, extractErrorCode } from '#lib/api-helpers.js';
  import { setAccountingCurrency } from '#lib/currency.svelte.js';
  import Callout from '#lib/components/Callout.svelte';
  import FormField from '#lib/components/forms/FormField.svelte';
  import NumberInput from '#lib/components/forms/NumberInput.svelte';
  import CurrencyInput from '#lib/components/forms/CurrencyInput.svelte';
  import TagBadge from '#lib/components/TagBadge.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import Skeleton from '#lib/components/Skeleton.svelte';
  import { toast } from '#lib/toast.svelte.js';
  import { onMount } from 'svelte';

  /** One editable conversion pair. The wire shape is `{from: {to: rate}}`; a
   *  flat row list is what an operator actually edits, and it is the only shape
   *  in which an in-progress row with a blank side can exist at all. */
  interface FxRow {
    from: string;
    to: string;
    rate: number | undefined;
  }

  let loading = $state(true);
  let saving = $state(false);
  /** The currency as the server currently holds it — the comparison that
   *  decides whether saving will restart the open spend windows. */
  let savedCurrency = $state('');
  let currency = $state('');
  let rows = $state<FxRow[]>([]);
  let currenciesInUse = $state<string[]>([]);
  let unconvertible = $state<string[]>([]);

  const currencyChanged = $derived(
    currency.trim().toUpperCase() !== savedCurrency.toUpperCase() && currency.trim().length > 0,
  );

  /** Duplicate pairs would silently drop on the way to the nested wire shape —
   *  the later row wins and the earlier one vanishes without a word. */
  const duplicatePairs = $derived.by(() => {
    const seen = new Set<string>();
    const dupes = new Set<string>();
    for (const r of rows) {
      const key = `${r.from.toUpperCase()}>${r.to.toUpperCase()}`;
      if (r.from && r.to) {
        if (seen.has(key)) dupes.add(key);
        seen.add(key);
      }
    }
    return dupes;
  });

  const incompleteRows = $derived(
    rows.some((r) => !r.from || !r.to || r.rate === undefined || !(r.rate > 0)),
  );

  function toRows(fx: Record<string, Record<string, number>>): FxRow[] {
    return Object.entries(fx).flatMap(([from, targets]) =>
      Object.entries(targets).map(([to, rate]) => ({ from, to, rate })),
    );
  }

  function toFx(list: FxRow[]): Record<string, Record<string, number>> {
    const out: Record<string, Record<string, number>> = {};
    for (const r of list) {
      const from = r.from.trim().toUpperCase();
      const to = r.to.trim().toUpperCase();
      if (!from || !to || r.rate === undefined || !(r.rate > 0)) continue;
      (out[from] ??= {})[to] = r.rate;
    }
    return out;
  }

  async function load() {
    loading = true;
    const { data, error: err } = await adminApi.GET('/api/v1/admin/settings/pricing');
    loading = false;
    if (err) {
      toast.error('Failed to load accounting settings', {
        body: extractError(err),
        code: extractErrorCode(err) ?? undefined,
      });
      return;
    }
    if (!data) return;
    savedCurrency = data.accounting_currency;
    currency = data.accounting_currency;
    rows = toRows(data.fx);
    currenciesInUse = data.currencies_in_use;
    unconvertible = data.unconvertible;
    setAccountingCurrency(data.accounting_currency);
  }

  function addRow() {
    rows = [...rows, { from: '', to: currency || '', rate: undefined }];
  }

  function removeRow(i: number) {
    rows = rows.filter((_, idx) => idx !== i);
  }

  async function handleSave() {
    saving = true;
    // `fx` replaces the table wholesale, so the full edited set goes up every
    // time — a per-pair merge would leave a deleted row alive on the server.
    const { data, error: err } = await adminApi.PATCH('/api/v1/admin/settings/pricing', {
      body: {
        accounting_currency: currency.trim().toUpperCase() || null,
        fx: toFx(rows),
      },
    });
    saving = false;
    if (err) {
      toast.error('Failed to save accounting settings', {
        body: extractError(err),
        code: extractErrorCode(err) ?? undefined,
      });
      return;
    }
    if (data) {
      savedCurrency = data.accounting_currency;
      currency = data.accounting_currency;
      rows = toRows(data.fx);
      currenciesInUse = data.currencies_in_use;
      unconvertible = data.unconvertible;
      setAccountingCurrency(data.accounting_currency);
    }
    toast.success('Accounting settings saved');
  }

  onMount(load);
</script>

<div class="space-y-4">
  <div>
    <h3 class="text-lg font-semibold text-(--text-primary)">Accounting</h3>
    <p class="text-sm text-(--text-secondary) mt-1">
      The currency this tenant's budgets, spend figures and audit totals are stated in, and the
      rates that convert a provider's own quote into it. An audit row keeps the currency it was
      written in — changing the setting restates nothing that has already been reported.
    </p>
  </div>

  {#if loading}
    <Skeleton variant="card" />
  {:else}
    {#if unconvertible.length > 0}
      <Callout severity="error" title="Some models are being billed as unstated">
        <p>
          No usable rate converts <span class="font-mono">{unconvertible.join(', ')}</span> into
          <span class="font-mono">{savedCurrency}</span>. Every request against a model priced in
          {unconvertible.length === 1 ? 'that currency' : 'those currencies'} records
          <strong>no spend</strong> and is flagged, so budgets covering those models do not enforce.
          Add a conversion rate below, or reprice the models.
        </p>
      </Callout>
    {/if}

    <div class="bg-(--bg-card) rounded-xl p-6 border border-(--border) space-y-4">
      <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <FormField
          label="Accounting currency"
          for="accounting-currency"
          help="Three-letter ISO 4217 code."
        >
          <CurrencyInput id="accounting-currency" bind:value={currency} />
        </FormField>
        <div class="sm:col-span-2">
          <span class="block text-xs uppercase tracking-wider text-(--text-secondary) mb-1">
            Currencies in use
          </span>
          {#if currenciesInUse.length === 0}
            <p class="text-xs text-(--text-secondary)">
              No model in this tenant carries a price yet.
            </p>
          {:else}
            <div class="flex flex-wrap gap-1.5">
              {#each currenciesInUse as code (code)}
                <TagBadge
                  color={unconvertible.includes(code)
                    ? 'rose'
                    : code === savedCurrency
                      ? 'teal'
                      : 'neutral'}
                  title={unconvertible.includes(code)
                    ? 'No usable rate into the accounting currency — spend against these models is not recorded'
                    : code === savedCurrency
                      ? 'The accounting currency — no conversion needed'
                      : 'Converted through the table below'}
                >{code}</TagBadge>
              {/each}
            </div>
            <p class="text-[10px] text-(--text-secondary) mt-1.5">
              Currencies this tenant's own models are priced in, across its catalog and its per-model
              overrides.
            </p>
          {/if}
        </div>
      </div>

      {#if currencyChanged}
        <Callout severity="warning" title="Changing the currency restarts the open spend windows">
          <p>
            The running daily and monthly totals are denominated in
            <span class="font-mono">{savedCurrency}</span>, so they cannot be carried over —
            saving restarts both windows at zero in
            <span class="font-mono">{currency.trim().toUpperCase()}</span>. Rows already written
            keep the currency they were written in.
          </p>
        </Callout>
      {/if}
    </div>

    <div class="bg-(--bg-card) rounded-xl p-6 border border-(--border) space-y-3">
      <div class="flex items-start justify-between gap-4">
        <div>
          <h4 class="text-sm font-semibold text-(--text-primary)">Conversion table</h4>
          <p class="text-xs text-(--text-secondary) mt-1">
            One multiplier per pair: 1 <span class="font-mono">from</span> buys this many
            <span class="font-mono">to</span>. A pair configured in one direction serves both — the
            inverse is exact, so there is no need to enter it twice.
          </p>
        </div>
        <button
          type="button"
          onclick={addRow}
          class="shrink-0 px-3 py-1.5 rounded-lg border border-(--border) text-xs font-medium text-(--text-secondary) hover:text-(--text-primary) hover:bg-(--bg-elevated) transition-colors"
        >+ Add pair</button>
      </div>

      {#if rows.length === 0}
        <p class="text-xs text-(--text-secondary) py-2">
          No conversion rates configured. Only models already priced in
          <span class="font-mono">{savedCurrency}</span> can be billed.
        </p>
      {:else}
        <div class="space-y-2">
          {#each rows as row, i (row)}
            {@const dupe = duplicatePairs.has(`${row.from.toUpperCase()}>${row.to.toUpperCase()}`)}
            <div class="flex items-center gap-2">
              <div class="w-24"><CurrencyInput bind:value={row.from} placeholder="From" /></div>
              <Icon name="chevronRight" size="sm" tone="neutral" />
              <div class="w-24"><CurrencyInput bind:value={row.to} placeholder="To" /></div>
              <div class="w-36">
                <NumberInput bind:value={row.rate} step="any" min="0" placeholder="Rate" mono />
              </div>
              {#if dupe}
                <span class="text-[10px] text-(--error-text)">Duplicate pair</span>
              {/if}
              <button
                type="button"
                aria-label="Remove this pair"
                onclick={() => removeRow(i)}
                class="ml-auto p-1.5 rounded-sm text-(--error) hover:bg-(--error-bg) transition-colors"
              >
                <Icon name="trash" size="sm" tone="error" />
              </button>
            </div>
          {/each}
        </div>
      {/if}

      <div class="flex items-center gap-3 pt-2">
        <button
          onclick={handleSave}
          disabled={saving || duplicatePairs.size > 0}
          class="px-5 py-2 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-sm font-medium transition-colors disabled:opacity-50"
        >{saving ? 'Saving…' : 'Save'}</button>
        {#if duplicatePairs.size > 0}
          <span class="text-xs text-(--error-text)">
            Two rows describe the same pair — remove one before saving.
          </span>
        {:else if incompleteRows}
          <span class="text-xs text-(--text-secondary)">
            Rows missing a currency or a positive rate are dropped on save.
          </span>
        {/if}
      </div>
    </div>
  {/if}
</div>

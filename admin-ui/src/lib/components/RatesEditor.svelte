<!--
  The price-list editor: one rate map, inherited or overridden as a whole.

  A price list is one provider's quote in one currency, so there is no per-unit
  inheritance — the toggle governs the entire block. While inheriting, the
  resolved map is shown read-only through the same inputs (values as
  placeholders), exactly as the capability editor shows its inherited fallback.

  Two distinctions the UI has to keep visible, because both look like "0":
  - A BLANK box means that unit has no price. An override whose boxes are all
    blank says "no price is known" — requests record a zero cost and are
    flagged — and does NOT fall back to the catalog. A typed `0` means free.
  - A TIERED rate is shown read-only, as the step table it is, in both states —
    a number input can hold only its base, so an inherited surcharge shown
    through one would be invisible. Typing over it would silently flatten the
    table into a single number, so replacing one takes an explicit action.
    Authoring new tiers is not offered here.
-->
<script lang="ts">
  import NumberInput from '#lib/components/forms/NumberInput.svelte';
  import CurrencyInput from '#lib/components/forms/CurrencyInput.svelte';
  import SourceBadge, { type FieldSource } from '#lib/components/SourceBadge.svelte';
  import HelpTooltip from '#lib/components/HelpTooltip.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import { formatPrice } from '#lib/formatters.js';
  import {
    RATE_UNIT_GROUPS,
    isTiered,
    formatThreshold,
    ratesAreEmpty,
    isPriced,
    type Rates,
    type RatesForm,
  } from '#lib/rates.js';

  let {
    form = $bindable(),
    /** What is in force while inheriting (this model's resolved price list). */
    resolved,
    /** Provenance of the resolved list, reported once for the whole map. */
    source,
    /** Hidden where there is nothing to inherit from (the catalog is the root
     *  of the ladder, and a new model has no row yet). */
    inheritable = true,
    idPrefix = 'rates',
  }: {
    form: RatesForm;
    resolved?: Rates | null;
    source?: FieldSource;
    inheritable?: boolean;
    idPrefix?: string;
  } = $props();

  const priced = $derived(
    Object.values(form.units).some(isPriced) || Object.keys(form.tiers).length > 0,
  );

  /** The currency the prices on screen are quoted in — the operator's while
   *  overriding, the inherited list's while inheriting. Never mixed: a step
   *  table rendered with the other list's currency would misstate every step. */
  const displayCurrency = $derived(form.overriding ? form.currency : (resolved?.currency ?? ''));

  /** Adopt an override, seeded from whatever is currently in force, so turning
   *  the toggle on never silently blanks a price the operator could see. */
  function startOverride() {
    if (form.overriding) return;
    form.currency = resolved?.currency || form.currency || 'USD';
    form.units = {};
    form.tiers = {};
    for (const [unit, rate] of Object.entries(resolved?.units ?? {})) {
      if (isTiered(rate)) form.tiers[unit] = rate;
      else form.units[unit] = rate;
    }
    form.overriding = true;
  }

  /** Release the override — the row goes back to inheriting the catalog map. */
  function stopOverride() {
    form.overriding = false;
  }

  /** Turn a tiered rate into an editable flat one, seeded from its base price.
   *  Deliberately a discrete action: the step table is discarded by this click,
   *  not by a keystroke in a box that looked ordinary. */
  function flattenTier(key: string) {
    const tiered = form.tiers[key];
    if (!tiered) return;
    delete form.tiers[key];
    form.units[key] = tiered.rate;
  }
</script>

<div class="space-y-3">
  <div class="flex items-center gap-2 flex-wrap">
    <span class="text-xs font-medium text-(--text-secondary)">Price list</span>
    {#if source}<SourceBadge {source} />{/if}
    <HelpTooltip
      body={inheritable
        ? "Prices are inherited from the catalog as one list — the currency travels with them, so a row can never take its numbers from one quote and its currency from another. Override to state this model's own prices."
        : 'This is the reference list every upstream model inherits when it states no price of its own. The currency travels with the prices, so a row can never take its numbers from one quote and its currency from another.'}
    />
    {#if inheritable}
      <div class="ml-auto inline-flex rounded-lg border border-(--border) overflow-hidden">
        <button
          type="button"
          onclick={stopOverride}
          class="px-2.5 py-1 text-xs transition-colors {form.overriding
            ? 'text-(--text-secondary) hover:bg-(--bg-elevated)'
            : 'bg-(--accent) text-(--accent-fg)'}"
        >Inherit from catalog</button>
        <button
          type="button"
          onclick={startOverride}
          class="px-2.5 py-1 text-xs transition-colors {form.overriding
            ? 'bg-(--accent) text-(--accent-fg)'
            : 'text-(--text-secondary) hover:bg-(--bg-elevated)'}"
        >Override</button>
      </div>
    {/if}
  </div>

  <div class="flex items-center gap-3">
    <label class="text-[10px] uppercase tracking-wider text-(--text-secondary) shrink-0" for="{idPrefix}-currency">
      Currency
    </label>
    <div class="w-24 shrink-0">
      {#if form.overriding}
        <CurrencyInput id="{idPrefix}-currency" bind:value={form.currency} />
      {:else}
        <CurrencyInput
          id="{idPrefix}-currency"
          disabled
          value={resolved?.currency ?? ''}
          placeholder="--"
        />
      {/if}
    </div>
    <p class="text-[10px] text-(--text-secondary)">
      Every price below is quoted in this currency. A model priced in a currency the Accounting
      settings cannot convert records no spend, and its requests are flagged.
    </p>
  </div>

  {#if form.overriding}
    <p class="text-[10px] text-(--text-secondary)">
      Leave a box <strong>blank</strong> to say that unit has no price — its requests record a cost
      of zero and are flagged. Type <strong>0</strong> to say the unit is genuinely free. The two
      are not the same, and only the second one keeps budgets enforcing.
    </p>
  {/if}

  {#each RATE_UNIT_GROUPS as group (group.label)}
    <div>
      <h5 class="text-[10px] font-medium text-(--text-secondary) uppercase tracking-wider mb-2">
        {group.label}
      </h5>
      <div class="grid grid-cols-2 sm:grid-cols-3 gap-3">
        {#each group.units as unit (unit.key)}
          {@const inherited = resolved?.units?.[unit.key]}
          {@const tiered = form.overriding
            ? form.tiers[unit.key]
            : isTiered(inherited)
              ? inherited
              : undefined}
          <div class="text-xs text-(--text-secondary)">
            <label class="block" for="{idPrefix}-{unit.key}">{unit.label}</label>
            {#if tiered}
              <!-- Tiered: shown as the step table it is, in both states. A number
                   input can only hold the base, so an inherited surcharge shown
                   through one would be invisible until the operator overrode the
                   list to look at it. Overriding adds the explicit way out. -->
              <div
                class="mt-1 flex items-center gap-2 px-2 py-1.5 rounded-lg border border-(--border) bg-(--bg-primary)"
                id="{idPrefix}-{unit.key}"
              >
                <span class="font-mono text-xs text-(--text-primary) truncate" title="Tiered rate">
                  {formatPrice(tiered.rate, displayCurrency)}{#each tiered.tiers as tier, i (i)}
                    &rarr; {formatPrice(tier.rate, displayCurrency)} above {formatThreshold(tier.above)}{/each}
                </span>
                {#if form.overriding}
                  <button
                    type="button"
                    title="Discard the tiers and replace them with a single flat price"
                    onclick={() => flattenTier(unit.key)}
                    class="ml-auto shrink-0 text-[10px] text-(--accent) hover:text-(--accent-hover) font-medium"
                  >Make flat</button>
                {/if}
              </div>
            {:else if form.overriding}
              <NumberInput
                id="{idPrefix}-{unit.key}"
                class="mt-1"
                step="any"
                min="0"
                bind:value={form.units[unit.key]}
                placeholder="No price"
              />
            {:else}
              <!-- Inheriting: the resolved value rides the placeholder, the same
                   way the capability editor shows the value it would fall back to. -->
              <NumberInput
                id="{idPrefix}-{unit.key}"
                class="mt-1"
                disabled
                value={undefined}
                placeholder={inherited === undefined ? 'No price' : String(inherited)}
              />
            {/if}
          </div>
        {/each}
      </div>
    </div>
  {/each}

  {#if form.overriding && !priced}
    <p class="flex items-start gap-1.5 text-[10px] text-(--warning-text)">
      <span class="shrink-0 mt-px"><Icon name="alert" size="sm" tone="warning" /></span>
      <span>
        Every price is blank, so this list carries <strong>no price</strong> — requests against it
        record a cost of zero and are flagged, and no budget covering them will enforce. That is not
        the same as a price of 0, which means the model is genuinely free.{#if inheritable}
          Switch back to Inherit to take the catalog's list instead.{/if}
      </span>
    </p>
  {:else if !form.overriding && ratesAreEmpty(resolved)}
    <p class="flex items-start gap-1.5 text-[10px] text-(--warning-text)">
      <span class="shrink-0 mt-px"><Icon name="alert" size="sm" tone="warning" /></span>
      <span>
        No catalog price resolves for this model, so its requests record a cost of zero and are
        flagged. Link it to a catalog entry, or override the price list here.
      </span>
    </p>
  {/if}
</div>

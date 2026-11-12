<script lang="ts">
  // What actually limits one member in one workspace: every bucket that
  // applies, widest first, with where each one comes from and the one closest
  // to its cap marked. The server computes the stack (the same resolvers the
  // gateway enforces with); this only renders it.
  import { m } from '#lib/paraglide/messages.js';
  import type { components } from '#lib/generated/api-types.js';
  import { formatAmount, formatTokens } from '#lib/formatters.js';
  import TagBadge from '#lib/components/TagBadge.svelte';
  import LimitMeter from './LimitMeter.svelte';
  import { limitBucketLabel } from '#lib/limits.js';

  type Stack = components['schemas']['EffectiveLimitStack'];
  type Layer = components['schemas']['LimitLayer'];

  /** `compact`: for a narrow column (the portal Home) — one meter per row,
   *  and no precedence line. */
  let { stack, compact = false }: { stack: Stack; compact?: boolean } = $props();

  function bucketLabel(l: Layer): string {
    return limitBucketLabel(l.bucket, l.key_name, l.key_prefix);
  }

  function sourceLabel(source: string): string {
    switch (source) {
      case 'tenant_default': return m.limits_source_tenant_default();
      case 'member_default': return m.limits_source_member_default();
      case 'exception': return m.limits_source_exception();
      default: return m.limits_source_own();
    }
  }

  // A metric taken from its default is tagged only inside a layer that mixes
  // its own caps with the default's; a layer wholly from its default already
  // says so in its heading.
  function inheritedNote(l: Layer, meter: components['schemas']['LimitMeter']): string | undefined {
    if (!meter.inherited) return undefined;
    if (l.bucket === 'workspace' && l.source !== 'tenant_default') return m.limits_source_tenant_default();
    if (l.bucket === 'member' && l.source !== 'member_default') return m.limits_source_member_default();
    return undefined;
  }

  const money = (n: number) => formatAmount(n, stack.currency);
  const count = (n: number) => n.toLocaleString();
</script>

<div class="space-y-3">
  {#if !compact}<p class="text-[11px] text-(--text-secondary)">{m.limits_precedence()}</p>{/if}
  {#if stack.layers.length === 0}
    <p class="text-sm text-(--text-secondary)">{m.limits_none()}</p>
  {:else}
    {#each stack.layers as layer (layer.bucket + (layer.key_id ?? ''))}
      {@const binding = layer.binding}
      <div class="rounded-lg border px-3 py-2.5 space-y-2 {binding ? 'border-(--warning-border) bg-(--warning-bg)' : 'border-(--border)'}">
        <div class="flex items-center gap-2 text-sm">
          <span class="font-medium text-(--text-primary)">{bucketLabel(layer)}</span>
          <span class="text-[11px] text-(--text-secondary)">{sourceLabel(layer.source)}</span>
          {#if layer.budget_mode === 'alert_only'}<TagBadge color="amber">{m.limits_alert_only()}</TagBadge>{/if}
          {#if binding}<TagBadge color="orange" class="ml-auto">{m.limits_binding()}</TagBadge>{/if}
        </div>
        <div class="grid grid-cols-1 {compact ? '' : 'sm:grid-cols-2'} gap-x-4 gap-y-2">
          {#if layer.requests_per_minute.cap != null}<LimitMeter label={m.limits_rpm()} used={layer.requests_per_minute.used} cap={layer.requests_per_minute.cap} fmt={count} note={inheritedNote(layer, layer.requests_per_minute)} />{/if}
          {#if layer.tokens_per_minute.cap != null}<LimitMeter label={m.limits_tpm()} used={layer.tokens_per_minute.used} cap={layer.tokens_per_minute.cap} fmt={formatTokens} note={inheritedNote(layer, layer.tokens_per_minute)} />{/if}
          {#if layer.daily_budget.cap != null}<LimitMeter label={m.limits_daily_short()} used={layer.daily_budget.used} cap={layer.daily_budget.cap} fmt={money} note={inheritedNote(layer, layer.daily_budget)} />{/if}
          {#if layer.monthly_budget.cap != null}<LimitMeter label={m.limits_monthly_short()} used={layer.monthly_budget.used} cap={layer.monthly_budget.cap} fmt={money} note={inheritedNote(layer, layer.monthly_budget)} />{/if}
        </div>
      </div>
    {/each}
    <p class="text-[10px] text-(--text-secondary)">{m.limits_fleet_estimate()}</p>
  {/if}
</div>

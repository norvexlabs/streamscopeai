<script lang="ts">
  import type { KeyListItem } from '#lib/api-types.js';
  import { formatTimeAgo, formatSpend, type Spend } from '#lib/formatters.js';
  import { budgetSummary } from '#lib/keyBudget.js';
  import { keyKindLabel, scopeLabel } from '#lib/keyScopes.js';
  import Icon from '#lib/components/Icon.svelte';
  import TagBadge from '#lib/components/TagBadge.svelte';

  interface Props {
    key_data: KeyListItem;
    usage: { total_requests: number; spend: Spend | null; last_used_at: string | null } | null;
    onRevoke: (key: KeyListItem) => void;
    /** When provided, shows an "Edit budget" action (admin / manager only).
     *  Only rendered for gateway keys — automation keys carry no budget. */
    onEditBudget?: (key: KeyListItem) => void;
    /** When provided, shows a "Rotate" action (service-account keys). */
    onRotate?: (key: KeyListItem) => void;
  }

  let { key_data, usage, onRevoke, onEditBudget, onRotate }: Props = $props();

  const isGateway = $derived(key_data.kind === 'sk' || key_data.kind === 'vk');

  const isRevoked = $derived(!!key_data.revoked_at);
  const isExpired = $derived(key_data.expires_at && new Date(key_data.expires_at) < new Date());

  const status = $derived.by(() => {
    if (isRevoked) return 'Revoked';
    if (isExpired) return 'Expired';
    return 'Active';
  });

  const daysRemaining = $derived.by(() => {
    if (!key_data.expires_at || isRevoked) return null;
    const diff = new Date(key_data.expires_at).getTime() - Date.now();
    return Math.ceil(diff / (1000 * 60 * 60 * 24));
  });

  const expiryText = $derived.by(() => {
    if (!key_data.expires_at) return 'Never expires';
    if (isExpired) return 'Expired';
    if (daysRemaining !== null && daysRemaining <= 0) return 'Expired';
    return `Expires in ${daysRemaining}d`;
  });

  const expiryColor = $derived.by(() => {
    if (!key_data.expires_at) return 'text-(--text-secondary)';
    if (isExpired || (daysRemaining !== null && daysRemaining <= 0)) return 'text-(--error)';
    if (daysRemaining !== null && daysRemaining < 7) return 'text-(--warning)';
    return 'text-(--text-secondary)';
  });

  const budgetText = $derived(budgetSummary(key_data.daily_budget, key_data.monthly_budget));
  const budgetAlertOnly = $derived(key_data.budget_mode === 'alert_only');
</script>

<div class="bg-(--bg-primary) rounded-lg border border-(--border) p-3 group">
  <!-- Row 1: Name + prefix + status -->
  <div class="flex items-center gap-2">
    <span class="text-sm text-(--text-primary) font-medium truncate">
      {key_data.name || '--'}
    </span>
    <code class="text-xs text-(--text-secondary) font-mono bg-(--bg-secondary) px-1.5 py-0.5 rounded-sm shrink-0">
      {key_data.key_prefix}...
    </code>
    <span class="text-[10px] text-(--text-secondary) opacity-40">&middot;</span>
    <TagBadge color={isGateway ? 'blue' : 'violet'}>
      {keyKindLabel(key_data.kind)}{key_data.admin_scope ? ` · ${scopeLabel(key_data.admin_scope)}` : ''}
    </TagBadge>
    {#if key_data.workspace_name}
      <span class="text-[10px] text-(--text-secondary) opacity-40">&middot;</span>
      <span class="inline-flex items-center gap-1 text-[10px] text-(--accent) font-medium truncate">
        <Icon name="building" size="sm" tone="neutral" />
        {key_data.workspace_name}
      </span>
    {/if}
    <span class="ml-auto text-[10px] font-medium px-1.5 py-0.5 rounded-full shrink-0
      {status === 'Active'
        ? 'bg-(--success)/10 text-(--success) border border-(--success)'
        : 'bg-(--error)/10 text-(--error) border border-(--error)'}">
      {status}
    </span>
  </div>

  <!-- Row 2: Usage stats + expiry -->
  <div class="flex items-center gap-3 mt-1.5 text-[10px] text-(--text-secondary)">
    {#if usage}
      <span class="font-mono tabular-nums">{usage.total_requests} reqs</span>
      <span class="opacity-40">&middot;</span>
      <span class="font-mono tabular-nums">{formatSpend(usage.spend)}</span>
      <span class="opacity-40">&middot;</span>
      <span>
        {#if usage.last_used_at}
          Last used: {formatTimeAgo(usage.last_used_at)}
        {:else}
          Never used
        {/if}
      </span>
    {:else}
      <span>No usage data</span>
    {/if}
    <span class="opacity-40">&middot;</span>
    <span class={expiryColor}>{expiryText}</span>
    {#if budgetText}
      <span class="opacity-40">&middot;</span>
      <span class="inline-flex items-center gap-1">
        <Icon name="cost" size="sm" tone={budgetAlertOnly ? 'warning' : 'neutral'} />
        <span class="tabular-nums">{budgetText}</span>
        {#if budgetAlertOnly}
          <span class="text-(--warning)">(alert only)</span>
        {/if}
      </span>
    {/if}
  </div>

  <!-- Row 3: actions (hover) -->
  {#if !isRevoked}
    <div class="flex justify-end gap-1 mt-1.5 opacity-0 group-hover:opacity-100 group-focus-within:opacity-100 transition-opacity">
      {#if onEditBudget && isGateway}
        <button
          onclick={() => onEditBudget?.(key_data)}
          class="text-xs px-2 py-1 rounded-sm text-(--text-secondary) hover:bg-(--bg-secondary) hover:text-(--text-primary) transition-colors"
        >
          Edit budget
        </button>
      {/if}
      {#if onRotate}
        <button
          onclick={() => onRotate?.(key_data)}
          class="text-xs px-2 py-1 rounded-sm text-(--text-secondary) hover:bg-(--bg-secondary) hover:text-(--text-primary) transition-colors"
        >
          Rotate
        </button>
      {/if}
      <button
        onclick={() => onRevoke(key_data)}
        class="text-xs px-2 py-1 rounded-sm text-(--error) hover:bg-(--error-bg) transition-colors"
      >
        Revoke
      </button>
    </div>
  {/if}
</div>

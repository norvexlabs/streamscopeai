<script lang="ts">
  // Models × endpoints: which replica serves which model, as discovery found
  // it. The one screen that makes the model-list fusion visible.
  import type { components } from '#lib/generated/api-types.js';
  import HelpTooltip from '#lib/components/HelpTooltip.svelte';
  import TagBadge from '#lib/components/TagBadge.svelte';
  import { cellGlyph, type CellGlyph } from '#lib/endpoints.js';
  import { formatTimeAgo, formatTokens } from '#lib/formatters.js';

  type Membership = components['schemas']['ServerMembershipResponse'];
  type Cell = components['schemas']['MembershipCell'];

  let { membership }: { membership: Membership } = $props();

  const GLYPH: Record<CellGlyph, { mark: string; label: string; classes: string }> = {
    listed: { mark: '●', label: 'Listed', classes: 'text-(--success-text)' },
    assumed: { mark: '◌', label: 'Assumed', classes: 'text-(--text-secondary)' },
    not_served: { mark: '—', label: 'Not served', classes: 'text-(--text-tertiary)' },
    missing: { mark: '⚠', label: 'Answered “model not found”', classes: 'text-(--warning-text)' },
  };

  function cellTitle(c: Cell): string {
    const g = GLYPH[cellGlyph(c)];
    const bits = [g.label];
    if (c.context_window) bits.push(`window ${formatTokens(c.context_window)}`);
    if (c.identity) bits.push(`serves ${c.identity}`);
    if (c.model_missing_reports) bits.push(`${c.model_missing_reports} report(s), last ${formatTimeAgo(c.model_missing_at)}`);
    return bits.join(' · ');
  }

  function servedBy(cells: Cell[]): number {
    return cells.filter((c) => c.state !== 'not_served').length;
  }
</script>

<div class="overflow-x-auto">
  <table class="w-full text-sm" data-testid="membership-matrix">
    <thead>
      <tr class="border-b border-(--border) bg-(--bg-primary)/50">
        <th class="px-4 py-2 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Model</th>
        <th class="px-3 py-2 text-right text-xs text-(--text-secondary) uppercase tracking-wider font-medium whitespace-nowrap">
          Window
          <HelpTooltip body="The window the gateway advertises for the model: the smallest any endpoint serving it reported, so no replica is sent more than it can take." />
        </th>
        <th class="px-3 py-2 text-right text-xs text-(--text-secondary) uppercase tracking-wider font-medium whitespace-nowrap">Served by</th>
        {#each membership.endpoints as ep, i (ep.id)}
          <th class="px-3 py-2 text-center text-xs text-(--text-secondary) font-medium whitespace-nowrap" title={ep.url}>
            <span class="font-mono">ep-{i + 1}</span>
            {#if !ep.enabled}<span class="text-(--text-tertiary)"> (off)</span>{/if}
          </th>
        {/each}
      </tr>
    </thead>
    <tbody>
      {#each membership.models as m (m.model_id)}
        <tr class="border-b border-(--border)">
          <td class="px-4 py-2">
            <span class="font-mono text-xs text-(--text-primary)">{m.upstream_model}</span>
            {#if m.parent}<span class="text-[10px] text-(--text-secondary) ml-1">adapter of {m.parent}</span>{/if}
            {#if !m.enabled}<TagBadge color="neutral" class="ml-1">Retired</TagBadge>{/if}
            {#if m.window_mismatch}
              <TagBadge color="amber" class="ml-1" title="Endpoints report different context windows; the smallest is advertised.">Window differs</TagBadge>
            {/if}
            {#if m.identity_mismatch}
              <TagBadge color="rose" class="ml-1" title="Endpoints say they serve different things under this name — check they run the same weights.">Identity differs</TagBadge>
            {/if}
          </td>
          <td class="px-3 py-2 text-right font-mono text-xs text-(--text-secondary)">{m.context_window ? formatTokens(m.context_window) : '—'}</td>
          <td class="px-3 py-2 text-right font-mono text-xs text-(--text-secondary)">{servedBy(m.cells)}/{m.cells.length}</td>
          {#each m.cells as c (c.endpoint_id)}
            {@const g = GLYPH[cellGlyph(c)]}
            <td class="px-3 py-2 text-center {g.classes}" title={cellTitle(c)} data-cell={cellGlyph(c)}>
              <span aria-hidden="true">{g.mark}</span><span class="sr-only">{g.label}</span>
            </td>
          {/each}
        </tr>
      {/each}
    </tbody>
  </table>
  <p class="px-4 py-2 text-[11px] text-(--text-secondary)">
    ● listed by the endpoint · ◌ assumed (the endpoint has not listed its models, or the model was added by hand) · — not served · ⚠ the endpoint answered “model not found”
  </p>
</div>

<script lang="ts">
  /**
   * One expert, described for someone deciding whether it should run: its
   * title and axis, what it looks for, what it reads, what it can produce, and
   * how it has been running. Shared by the expert-profile membership editor
   * (`membership` set: the whole card toggles membership) and the Definitions
   * list (`control` and `actions` snippets: enable switch, edit, memory…).
   */
  import type { Snippet } from 'svelte';
  import type { AgentExpert } from '#lib/api-types.js';
  import type { CardState } from '#lib/expertMembership.js';
  import TagBadge from '#lib/components/TagBadge.svelte';
  import { expertTitle, inputTypeInfo, outputTypeInfo } from '#lib/colormaps/experts.js';
  import { formatCount, formatTimeAgo } from '#lib/formatters.js';

  interface Props {
    expert: AgentExpert;
    /** Selection mode: how the expert stands on the profile. */
    membership?: CardState;
    /** Selection mode: called with whether the profile should list the expert. */
    onselect?: (listed: boolean) => void;
    /** Selection mode: the toggle is locked (e.g. while a save is in flight). */
    disabled?: boolean;
    /** Top-right control outside selection mode (e.g. the enable switch). */
    control?: Snippet;
    /** Footer row of actions outside selection mode. */
    actions?: Snippet;
  }

  let { expert, membership, onselect, disabled = false, control, actions }: Props = $props();

  // In selection mode a label stretched over the card makes all of it toggle;
  // only the chips that carry a tooltip sit above it (`relative z-10`).
  const INHERITED_HINT = 'Runs here because the Default profile includes it. Remove it from the Default to stop it.';
  const ALSO_HINT = 'This profile lists it, and the Default includes it too: unticking removes this profile\'s own listing, and it keeps running here while the Default includes it.';

  const selectable = $derived(membership !== undefined);
  const selected = $derived(membership?.runs ?? false);
  const inherited = $derived(membership?.locked ?? false);
  const inputId = $derived(`expert-select-${expert.id}`);
  const title = $derived(expertTitle(expert.axis));
  const inputs = $derived((expert.input_types ?? []).map((t) => ({ t, ...inputTypeInfo(t) })));
  const outputs = $derived((expert.output_types ?? []).map((t) => ({ t, ...outputTypeInfo(t) })));
  // In a profile, dimmed when it will not run there: deselected, or switched
  // off everywhere. The Definitions list keeps its controls at full strength.
  const muted = $derived(selectable && (!selected || !expert.enabled));
</script>

{#snippet body()}
  <div class="flex items-start gap-3">
    <span
      class="mt-1.5 w-2.5 h-2.5 rounded-full shrink-0 {expert.color ? '' : 'bg-(--text-secondary)'}"
      style={expert.color ? `background-color: ${expert.color}` : undefined}
    ></span>
    <div class="min-w-0 flex-1">
      <div class="flex items-center gap-2 flex-wrap">
        <h3 class="text-sm font-semibold text-(--text-primary)">{title}</h3>
        <TagBadge color={expert.is_builtin ? 'blue' : 'neutral'} class="text-[10px]">
          {expert.is_builtin ? 'Built-in' : 'Custom'}
        </TagBadge>
        {#if inherited}
          <TagBadge color="teal" class="relative z-10 text-[10px]" title={INHERITED_HINT}>From Default</TagBadge>
        {:else if membership?.inDefault}
          <TagBadge color="teal" class="relative z-10 text-[10px]" title={ALSO_HINT}>Also in Default</TagBadge>
        {/if}
      </div>
      <p class="text-[11px] font-mono text-(--text-secondary)">{expert.axis}</p>
    </div>
    {#if selectable}
      <input
        id={inputId}
        type="checkbox"
        class="relative z-10 mt-1 w-4 h-4 shrink-0 accent-(--accent) cursor-pointer"
        checked={selected}
        disabled={inherited || disabled}
        title={inherited ? INHERITED_HINT : undefined}
        onchange={(e) => {
          const box = e.currentTarget as HTMLInputElement;
          onselect?.(box.checked);
          // Unticking an own listing the Default also holds leaves the expert
          // running, so `checked` stays true and a one-way binding would not
          // write the box back: set it to what now runs.
          box.checked = box.checked || (membership?.inDefault ?? false);
        }}
        aria-label="Run {title} in this profile"
      />
    {:else if control}
      <div class="shrink-0">{@render control()}</div>
    {/if}
  </div>

  {#if expert.description}
    <p class="text-sm text-(--text-secondary) leading-snug">{expert.description}</p>
  {/if}

  <dl class="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1.5 text-xs items-baseline">
    <dt class="text-(--text-secondary) uppercase tracking-wider text-[10px]">Reads</dt>
    <dd class="flex flex-wrap gap-1">
      {#each inputs as i, idx (idx)}
        <TagBadge color={i.color} title={i.hint} class="relative z-10 text-[10px]">{i.label}</TagBadge>
      {/each}
    </dd>
    <dt class="text-(--text-secondary) uppercase tracking-wider text-[10px]">Produces</dt>
    <dd class="flex flex-wrap gap-1">
      {#each outputs as o, idx (idx)}
        <TagBadge color={o.color} title={o.hint} class="relative z-10 text-[10px]">{o.label}</TagBadge>
      {/each}
    </dd>
  </dl>

  <div class="mt-auto pt-2 border-t border-(--border) flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-(--text-secondary)">
    {#if !expert.enabled}
      <span class="relative z-10 text-(--warning)" title="Switched off in Definitions: it analyzes nothing, in any profile.">Off everywhere</span>
    {/if}
    <span title="Sessions this expert has analyzed">{formatCount(expert.sessions_analyzed ?? 0)} sessions analyzed</span>
    <span title={expert.last_processed_at ?? undefined}>
      {expert.last_processed_at ? `last run ${formatTimeAgo(expert.last_processed_at)}` : 'never run'}
    </span>
    {#if expert.model_override}
      <TagBadge color="neutral" class="relative z-10 text-[10px] font-mono" title="Analyzes with its own model, whatever the profile's judge model">
        model: {expert.model_override}
      </TagBadge>
    {/if}
    {#if expert.merge_enabled === false}
      <TagBadge color="amber" class="relative z-10 text-[10px]" title="Pooled analysis off: always runs its own dedicated call">Solo</TagBadge>
    {/if}
    {#if expert.has_memory}
      <TagBadge color="violet" class="relative z-10 text-[10px]" title="Holds notes from earlier cycles">has memory</TagBadge>
    {/if}
  </div>

  {#if actions}
    <div class="flex flex-wrap items-center gap-3 text-xs">{@render actions()}</div>
  {/if}
{/snippet}

{#if selectable}
  <!-- The whole card toggles: an empty label stretched over it targets the
       checkbox, so the card's headings and lists stay valid outside a label. -->
  <div
    class="relative flex flex-col gap-3 p-4 rounded-xl border transition-colors bg-(--bg-card)
      {inherited ? '' : 'hover:border-(--accent)'}
      {selected ? 'border-(--accent)' : 'border-(--border)'} {muted ? 'opacity-60' : ''}"
  >
    <label for={inputId} class="absolute inset-0 rounded-xl {inherited ? 'cursor-default' : 'cursor-pointer'}"></label>
    {@render body()}
  </div>
{:else}
  <article
    class="flex flex-col gap-3 p-4 rounded-xl border border-(--border) bg-(--bg-card) {muted ? 'opacity-60' : ''}"
  >
    {@render body()}
  </article>
{/if}

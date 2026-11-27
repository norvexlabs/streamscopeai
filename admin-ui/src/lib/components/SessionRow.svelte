<script lang="ts">
  import { portalWorkspace, sessionHref } from '#lib/selfScoped.js';
  import { formatTimeAgo, formatTokens, formatSpend, parseAlertLines } from '#lib/formatters.js';
  import { m } from '#lib/paraglide/messages.js';
  import { linkChipLabel } from '#lib/colormaps/linkage.js';
  import Icon from '#lib/components/Icon.svelte';
  import type { SessionSummary } from '#lib/api-types.js';
  import { BADGE_REGISTRY, isAttentionCode, type BadgeCode } from '#lib/badges.js';
  import { page } from '$app/state';
  import { goto } from '$app/navigation';

  let slug = $derived(page.params.slug ?? '');

  interface Props {
    session: SessionSummary;
    appName?: (id: string | null) => string;
    /** Member self-view: the row is always the caller's own, so the redundant
     *  user identity is hidden. Default (admin) shows it. */
    selfScoped?: boolean;
    /** Shown under its parent in a tree: the indent names the parent, so a
     *  sub-agent's parent chip is dropped. */
    nested?: boolean;
    /** The sub-agents badge as a toggle that shows them under the row (a tree
     *  only). */
    expand?: { open: boolean; toggle: () => void };
    /** A badge chip was clicked: filter the list by it. Without it the chips
     *  only show. */
    onbadge?: (code: BadgeCode) => void;
    /** The badge codes the list is filtered on: shown as chips too,
     *  attention codes or not, so the row says why it matched. */
    filtered?: readonly string[];
  }

  let {
    session,
    appName = (id: string | null) => id || '',
    selfScoped = false,
    nested = false,
    expand,
    onbadge,
    filtered = [],
  }: Props = $props();

  // The session's attention badges (the rest stay filterable, not shown): a
  // few chips, then a count whose tooltip names the others.
  const CHIPS = 3;
  const attention = $derived(
    (session.badge_codes ?? []).filter((c) => isAttentionCode(c) || filtered.includes(c)),
  );
  const chips = $derived(attention.slice(0, CHIPS));
  const moreChips = $derived(attention.slice(CHIPS));

  function filterBy(e: Event, code: BadgeCode) {
    e.preventDefault();
    e.stopPropagation();
    onbadge?.(code);
  }

  // The plane comes from the pathname; on the portal the workspace whose
  // activity is being viewed rides along (`setPortalWorkspace` on the page): a
  // row may be a teammate's, and its detail narrows to the caller without it.
  const viewedWorkspace = portalWorkspace();

  const alertLines = $derived(parseAlertLines(session.alert_note, session.alert_level));
  const topAlert = $derived(alertLines[0]);
  const subAgentAlert = $derived(session.links?.sub_agent_alert);
  const parentChip = $derived(session.link && !(nested && session.link.kind === 'sub_agent') ? session.link : undefined);
  // Each metadata item is preceded by a separator only when an item is shown
  // before it (the user is hidden in a member's self-view).
  const keyShown = $derived(!!(session.key_name || session.key_prefix));
  const beforeKey = $derived(!selfScoped);
  const beforeApp = $derived(beforeKey || keyShown);
  const beforeWorkspace = $derived(beforeApp || !!session.app_id);
  const beforeModel = $derived(beforeWorkspace || !!session.workspace_name);

  function toggle(e: Event) {
    e.preventDefault();
    e.stopPropagation();
    expand?.toggle();
  }
</script>

<a
  href={sessionHref(slug, page.url.pathname, session.session_id, viewedWorkspace())}
  class="px-6 py-3 flex items-center gap-4 hover:bg-(--bg-elevated) transition-colors group block {session.alert_level === 'major' ? 'border-l-2 border-l-(--error)' : session.alert_level === 'minor' ? 'border-l-2 border-l-(--warning)' : ''}"
>
  <div class="flex-1 min-w-0">
    <!-- Line 1: prompt text (full width) -->
    <div class="flex items-center gap-2">
      <p class="text-sm text-(--text-primary) line-clamp-1 leading-snug flex-1 min-w-0">
        {#if session.alert_level}
          <span class="inline-flex px-1.5 py-0.5 text-[10px] font-semibold rounded-sm {session.alert_level === 'major' ? 'bg-(--error-bg) text-(--error)' : session.alert_level === 'minor' ? 'bg-(--warning-bg) text-(--warning)' : 'bg-(--tag-neutral-bg) text-(--tag-neutral-text)'} uppercase align-middle mr-1.5">
            {session.alert_level}
          </span>
        {/if}
        {session.first_user_prompt || session.model_used || '--'}
      </p>
      {#if !session.spend || session.spend.amount > 0}
        <span class="text-xs text-(--text-primary) font-mono shrink-0 tabular-nums" title={session.spend ? undefined : m.spend_not_stated_hint()}>{formatSpend(session.spend, m.spend_not_stated_short)}</span>
      {/if}
      <span class="text-xs text-(--text-secondary) shrink-0 tabular-nums font-mono">
        {formatTimeAgo(session.last_timestamp)}
      </span>
    </div>
    <!-- Alert note -->
    {#if topAlert}
      <p class="text-xs mt-0.5 line-clamp-1 {topAlert.level === 'major' ? 'text-(--error)/70' : topAlert.level === 'minor' ? 'text-(--warning)/70' : 'text-(--text-secondary)'}">
        {topAlert.text}
      </p>
    {/if}
    <!-- Line 2: metadata — user → key → client → route → model → stats -->
    <div class="flex items-center gap-2 mt-1 flex-wrap">
      <!-- User (hidden in self-view — always the caller) -->
      {#if !selfScoped}
        <span class="text-xs text-(--text-secondary) truncate">
          {session.user_email || (session.user_id ? session.user_id.substring(0, 8) + '...' : m.session_row_unknown())}
        </span>
      {/if}
      <!-- Key -->
      {#if keyShown}
        {#if beforeKey}<span class="text-[10px] text-(--text-secondary)">&middot;</span>{/if}
        <span class="text-[10px] text-(--text-secondary) font-mono truncate">{session.key_name || ''}{#if session.key_prefix} <code class="bg-(--bg-secondary) px-0.5 rounded-sm">{session.key_prefix}...</code>{/if}</span>
      {/if}
      <!-- Client app -->
      {#if session.app_id}
        {#if beforeApp}<span class="text-[10px] text-(--text-secondary)">&middot;</span>{/if}
        <span class="text-[10px] text-(--accent)" title={session.app_id}>
          {appName(session.app_id)}
        </span>
      {/if}
      <!-- Workspace -->
      {#if session.workspace_name}
        {#if beforeWorkspace}<span class="text-[10px] text-(--text-secondary)">&middot;</span>{/if}
        <span class="inline-flex items-center gap-1">
          <Icon name="building" size="sm" tone="neutral" />
          <span class="text-[10px] text-(--text-secondary) truncate">{session.workspace_name}</span>
        </span>
      {/if}
      <!-- Model -->
      {#if beforeModel}<span class="text-[10px] text-(--text-secondary)">&middot;</span>{/if}
      <span class="text-xs text-(--text-secondary) font-mono truncate">
        {session.model_used || session.model_requested || '--'}
      </span>
      <!-- Stats -->
      <span class="text-[10px] text-(--text-secondary)">&middot;</span>
      <span class="text-[10px] text-(--text-secondary)">
        {session.turn_count} {session.turn_count === 1 ? m.session_row_turn() : m.session_row_turns()}
      </span>
      {#if session.total_tokens}
        <span class="text-[10px] text-(--text-secondary)">&middot;</span>
        <span class="text-[10px] text-(--text-secondary) font-mono">
          {formatTokens(session.total_tokens)}{#if (session.total_cache_creation_tokens || 0) + (session.total_cache_read_tokens || 0) > 0} ({formatTokens((session.total_cache_creation_tokens || 0) + (session.total_cache_read_tokens || 0))} {m.session_row_cached()}){/if}
        </span>
      {/if}
      {#each alertLines as line}
        <span class="text-[10px] px-1 py-0.5 rounded-sm {line.level === 'major' ? 'bg-(--error-bg) text-(--error)/80' : line.level === 'minor' ? 'bg-(--warning-bg) text-(--warning)/80' : 'bg-(--tag-neutral-bg) text-(--tag-neutral-text)'}">{line.axis}</span>
      {/each}
      {#if session.links && session.links.sub_agents > 0}
        {@const label = `${session.links.sub_agents} ${session.links.sub_agents === 1 ? m.session_row_child() : m.session_row_children()}`}
        {#if expand}
          <span
            role="button"
            tabindex="0"
            aria-expanded={expand.open}
            onclick={toggle}
            onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') toggle(e); }}
            class="inline-flex items-center gap-0.5 text-[10px] px-1.5 py-0.5 rounded-sm bg-(--accent)/15 text-(--accent) border border-(--accent) hover:bg-(--accent)/25 transition-colors cursor-pointer"
          >
            {label}
            <Icon name={expand.open ? 'chevronDown' : 'chevronRight'} size="xs" tone="info" />
          </span>
        {:else}
          <span class="text-[10px] px-1.5 py-0.5 rounded-sm bg-(--accent)/15 text-(--accent) border border-(--accent)">
            {label}
          </span>
        {/if}
      {/if}
      {#if subAgentAlert}
        <span class="text-[10px] px-1.5 py-0.5 rounded-sm {subAgentAlert === 'major' ? 'bg-(--error-bg) text-(--error)/80' : subAgentAlert === 'minor' ? 'bg-(--warning-bg) text-(--warning)/80' : 'bg-(--tag-neutral-bg) text-(--tag-neutral-text)'}">
          {m.browse_subagent_alert({ level: subAgentAlert === 'major' ? m.browse_alert_major() : subAgentAlert === 'minor' ? m.browse_alert_minor() : m.browse_alert_info() })}
        </span>
      {/if}
      {#each chips as code (code)}
        {@const entry = BADGE_REGISTRY[code]}
        {#if onbadge}
          <span
            role="button"
            tabindex="0"
            title={entry.help()}
            onclick={(e) => filterBy(e, code)}
            onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') filterBy(e, code); }}
            class="text-[10px] px-1.5 py-0.5 rounded-sm cursor-pointer {entry.classes}"
          >{entry.label}</span>
        {:else}
          <span title={entry.help()} class="text-[10px] px-1.5 py-0.5 rounded-sm {entry.classes}">{entry.label}</span>
        {/if}
      {/each}
      {#if moreChips.length > 0}
        <span
          title={moreChips.map((c) => BADGE_REGISTRY[c].label).join(', ')}
          class="text-[10px] px-1.5 py-0.5 rounded-sm bg-(--tag-neutral-bg) text-(--tag-neutral-text)"
        >+{moreChips.length}</span>
      {/if}
      {#if session.links?.continued_in}
        {@const next = session.links.continued_in}
        <span
          role="link"
          tabindex="0"
          onclick={(e) => { e.preventDefault(); e.stopPropagation(); goto(sessionHref(slug, page.url.pathname, next, viewedWorkspace())); }}
          onkeydown={(e) => { if (e.key === 'Enter') { e.preventDefault(); e.stopPropagation(); goto(sessionHref(slug, page.url.pathname, next, viewedWorkspace())); } }}
          class="text-[10px] px-1.5 py-0.5 rounded-sm bg-(--accent)/10 text-(--accent) border border-(--accent) hover:bg-(--accent)/20 transition-colors cursor-pointer"
        >
          {m.session_row_continued_in()} &rarr;
        </span>
      {/if}
      {#if parentChip}
        {@const link = parentChip}
        <span
          role="link"
          tabindex="0"
          onclick={(e) => { e.preventDefault(); e.stopPropagation(); goto(sessionHref(slug, page.url.pathname, link.session_id, viewedWorkspace())); }}
          onkeydown={(e) => { if (e.key === 'Enter') { e.preventDefault(); e.stopPropagation(); goto(sessionHref(slug, page.url.pathname, link.session_id, viewedWorkspace())); } }}
          class="text-[10px] px-1.5 py-0.5 rounded-sm bg-(--accent)/10 text-(--accent) border border-(--accent) hover:bg-(--accent)/20 transition-colors cursor-pointer"
        >
          &rarr; {linkChipLabel(link.kind)}
        </span>
      {/if}
    </div>
  </div>
</a>

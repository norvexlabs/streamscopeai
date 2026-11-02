<script lang="ts">
  // The expert agent's alert about a WHOLE session, rendered once per session
  // page in both planes.
  //
  // The audit feed derives the same alert as a `session_alert` badge on each LLM
  // row of the session — the feed has no session column — and
  // `turnScopedBadges` (#lib/badges.js) keeps such a badge out of
  // the transcript's per-turn chips, which makes this banner the single place a
  // session page states the alert. Keep the two in step: a session view that
  // drops this banner loses the signal entirely rather than de-duplicating it.
  import Icon from './Icon.svelte';
  import { parseAlertLines } from '#lib/formatters.js';
  import { m } from '#lib/paraglide/messages.js';

  interface Props {
    /** `sessions.alert_level` — `major` | `minor` | `info`. */
    level: string | null | undefined;
    /** `sessions.alert_note` — one `[axis:level] text` line per flagging expert. */
    note: string | null | undefined;
  }

  let { level, note }: Props = $props();

  const lines = $derived(parseAlertLines(note, level ?? undefined));
</script>

{#if level && note}
  <div class="mb-4 rounded-xl border px-4 py-3
    {level === 'major' ? 'bg-(--error-bg) border-(--error)/30' : level === 'minor' ? 'bg-(--warning-bg) border-(--warning-border)' : 'bg-(--tag-neutral-bg) border-(--border)'}">
    <div class="flex items-center gap-2 mb-3">
      <Icon name="triangleAlert" tone={level === 'major' ? 'error' : level === 'minor' ? 'warning' : 'neutral'} />
      <span class="text-xs font-semibold uppercase tracking-wider {level === 'major' ? 'text-(--error)' : level === 'minor' ? 'text-(--warning)' : 'text-(--tag-neutral-text)'}">
        {m.conv_session_alert({ level })}
      </span>
    </div>
    <div class="space-y-2">
      {#each lines as line}
        <div class="flex items-start gap-2.5 rounded-lg px-3 py-2
          {line.level === 'major' ? 'bg-(--error-bg)' : line.level === 'minor' ? 'bg-(--warning-bg)' : 'bg-(--tag-neutral-bg)'}">
          <span class="shrink-0 mt-0.5 px-1.5 py-0.5 text-[10px] font-semibold rounded uppercase
            {line.level === 'major' ? 'bg-(--error-bg) text-(--error)' : line.level === 'minor' ? 'bg-(--warning-bg) text-(--warning)' : 'bg-(--tag-neutral-bg) text-(--tag-neutral-text)'}">
            {line.axis || line.level}
          </span>
          <p class="text-sm {line.level === 'major' ? 'text-(--error)/90' : line.level === 'minor' ? 'text-(--warning)/80' : 'text-(--text-secondary)'}">
            {line.text}
          </p>
        </div>
      {/each}
    </div>
  </div>
{/if}

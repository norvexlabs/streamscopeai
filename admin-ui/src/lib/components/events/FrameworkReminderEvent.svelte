<script lang="ts">
  import { m } from '#lib/paraglide/messages.js';
  import type { components } from '#lib/generated/api-types.js';

  // The generated variant: the Rust enum is the source of truth.
  type FrameworkReminderEvent = Extract<
    components['schemas']['ConversationEvent'],
    { type: 'framework_reminder' }
  >;

  /** The name of each volatile-block family the backend labels a reminder with. */
  const LABELS: Record<components['schemas']['VolatileLabel'], () => string> = {
    deferred_tools: () => m.conv_meta_deferred_tools(),
    system_reminder: () => m.conv_meta_system_reminder(),
    session_context: () => m.conv_meta_session_context(),
    local_command: () => m.conv_meta_local_command(),
    command: () => m.conv_meta_command(),
  };

  // `prior` marks a block from an earlier turn: the session view passes it
  // from `is_new`; the request detail shows one request, so passes nothing.
  let { event, prior = false }: { event: FrameworkReminderEvent; prior?: boolean } = $props();
  let expanded = $state(false);
</script>

<!-- A volatile block (<system-reminder>, etc.) the backend split out of a
     message's text: collapsed, its raw bytes on expand. -->
<div class="rounded-xl border border-dashed border-(--text-secondary) bg-(--bg-secondary)/30 overflow-hidden {prior ? 'opacity-40' : ''}">
  <button
    onclick={() => (expanded = !expanded)}
    class="w-full flex items-center gap-2 px-4 py-2 text-left hover:bg-(--bg-elevated) transition-colors"
  >
    <span class="inline-block text-[10px] transition-transform {expanded ? 'rotate-90' : ''} text-(--text-secondary)">&#9654;</span>
    <span class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary)">{LABELS[event.label]()}</span>
    <span class="text-[10px] text-(--text-secondary)">{m.conv_n_chars({ count: event.content.length })}</span>
    {#if prior}
      <span class="text-[9px] px-1.5 py-0.5 rounded-sm bg-(--bg-secondary) text-(--text-secondary) font-medium">{m.conv_prior()}</span>
    {/if}
  </button>
  {#if expanded}
    <div class="px-4 pb-3 text-sm text-(--text-primary)">
      <pre class="whitespace-pre-wrap font-mono text-xs">{event.content}</pre>
    </div>
  {/if}
</div>

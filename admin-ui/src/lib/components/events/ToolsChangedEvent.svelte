<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { portalApi } from '#lib/portal-client.js';
  import { isSelfScoped, portalWorkspace, workspaceQuery } from '#lib/selfScoped.js';
  import { m } from '#lib/paraglide/messages.js';
  import type { components } from '#lib/generated/api-types.js';

  // Discriminated-union extract: stays in sync with the generated
  // `ConversationEvent` whenever the variant evolves — the single source
  // of truth is the Rust enum, never the UI.
  type ToolsChangedEvent = Extract<
    components['schemas']['ConversationEvent'],
    { type: 'tools_changed' }
  >;
  type Definition = unknown;

  let { event }: { event: ToolsChangedEvent } = $props();

  // Capture the plane at init — `isSelfScoped()` reads Svelte context, which is
  // only legal during component initialization, never inside the async fetch
  // that the click handler kicks off (that would throw and wedge `loading`).
  const selfScoped = isSelfScoped();
  const viewedWorkspace = portalWorkspace();

  let expanded = $state(false);
  let loading = $state(false);
  let previous = $state<Definition | null>(null);
  let current = $state<Definition | null>(null);
  let error = $state('');

  // Plane-aware: the portal member plane has its own ownership-gated endpoint
  // and a path-scoped cookie, so an admin-path fetch there 401s. Mirror the
  // media-blob leaf, which branches the same way.
  async function fetchDefinition(hash: string): Promise<Definition | null> {
    const { data, error: err } = selfScoped
      ? await portalApi.GET('/api/v1/portal/audit/tool-definitions/{hash}', {
          params: { path: { hash }, query: workspaceQuery(viewedWorkspace()) },
        })
      : await adminApi.GET('/api/v1/admin/audit/tool-definitions/{hash}', {
          params: { path: { hash } },
        });
    if (err) {
      error = m.event_failed_fetch_tool_def({ hash: hash.slice(0, 8) });
      return null;
    }
    return data?.definition ?? null;
  }

  async function toggle() {
    expanded = !expanded;
    if (expanded && previous == null && current == null && !loading) {
      loading = true;
      error = '';
      const tasks: Promise<void>[] = [];
      if (event.previous_hash) {
        tasks.push(fetchDefinition(event.previous_hash).then((d) => { previous = d; }));
      }
      if (event.current_hash) {
        tasks.push(fetchDefinition(event.current_hash).then((d) => { current = d; }));
      }
      await Promise.all(tasks);
      loading = false;
    }
  }

  const label = $derived(
    event.kind === 'policy_modified'
      ? m.event_tools_modified_by_policy()
      : m.event_tools_changed_between_turns(),
  );
</script>

<div class="flex items-center gap-3 py-1">
  <div class="flex-1 border-t border-dashed border-(--accent)"></div>
  <button
    onclick={toggle}
    class="text-xs text-(--accent) font-medium flex items-center gap-1.5 px-3 py-1 rounded-full bg-(--accent)/10 border border-(--accent) hover:bg-(--accent)/15 transition-colors"
    aria-expanded={expanded}
  >
    <span class="inline-block text-[10px] transition-transform {expanded ? 'rotate-90' : ''}">&#9654;</span>
    {label}
  </button>
  <div class="flex-1 border-t border-dashed border-(--accent)"></div>
</div>

{#if expanded}
  <div class="rounded-lg border border-dashed border-(--accent) bg-(--accent)/5 overflow-hidden">
    {#if loading}
      <p class="px-3 py-2 text-xs text-(--text-secondary)">{m.event_loading_tool_defs()}</p>
    {:else if error}
      <p class="px-3 py-2 text-xs text-(--error)">{error}</p>
    {:else}
      <div class="grid grid-cols-1 md:grid-cols-2 divide-x divide-(--border)">
        <div class="p-3">
          <p class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary) mb-2">
            {event.kind === 'policy_modified' ? m.event_client_sent_available() : m.event_previous_turn()}
          </p>
          {#if previous != null}
            <pre class="text-[11px] font-mono whitespace-pre-wrap text-(--text-primary) max-h-64 overflow-auto">{JSON.stringify(previous, null, 2)}</pre>
          {:else}
            <p class="text-xs text-(--text-tertiary) italic">{m.event_no_tools()}</p>
          {/if}
        </div>
        <div class="p-3">
          <p class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary) mb-2">
            {event.kind === 'policy_modified' ? m.event_after_policy_effective() : m.event_this_turn()}
          </p>
          {#if current != null}
            <pre class="text-[11px] font-mono whitespace-pre-wrap text-(--text-primary) max-h-64 overflow-auto">{JSON.stringify(current, null, 2)}</pre>
          {:else}
            <p class="text-xs text-(--text-tertiary) italic">{m.event_no_tools()}</p>
          {/if}
        </div>
      </div>
    {/if}
  </div>
{/if}

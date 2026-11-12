<script lang="ts">
  /**
   * Portal Home — the To do card: one short line per thing waiting on the
   * caller, each with the way to fix it (a link, or the command to copy).
   * The lines come from `homeTodos` (`#lib/portalHome.js`); with none the
   * card is not rendered.
   */
  import type { HomeTodo } from '#lib/portalHome.js';
  import Icon from '#lib/components/Icon.svelte';
  import CopyTextButton from '#lib/components/CopyTextButton.svelte';
  import { formatDate, formatKeyLabel } from '#lib/formatters.js';
  import { pthref } from '#lib/tenant.js';
  import type { IconName, Tone } from '#lib/icons.js';
  import { m } from '#lib/paraglide/messages.js';

  let { slug, todos }: { slug: string; todos: HomeTodo[] } = $props();

  function look(t: HomeTodo): { icon: IconName; tone: Tone } {
    switch (t.kind) {
      case 'no_key': return { icon: 'key', tone: 'info' };
      case 'key': return { icon: 'key', tone: t.expired ? 'error' : 'warning' };
      case 'mcp': return { icon: 'lock', tone: 'warning' };
      case 'cli': return { icon: 'desktop', tone: 'warning' };
    }
  }

  const linkClass = 'shrink-0 text-xs font-semibold text-(--accent) hover:underline';
</script>

{#if todos.length > 0}
  <section class="rounded-lg border border-(--border) bg-(--bg-card) overflow-hidden" aria-label={m.portal_home_todo()} data-testid="home-todo">
    <header class="flex items-center gap-2 px-5 py-3 border-b border-(--border)">
      <h2 class="text-sm font-semibold text-(--text-primary)">{m.portal_home_todo()}</h2>
      <span class="px-1.5 min-w-5 text-center rounded-full text-[11px] font-semibold bg-(--warning-bg) text-(--warning)" data-testid="home-todo-count">{todos.length}</span>
    </header>
    <ul class="divide-y divide-(--border)">
      {#each todos as t, i (i)}
        {@const l = look(t)}
        <li class="flex items-center gap-3 px-5 py-2.5 text-sm" data-testid="home-todo-item" data-kind={t.kind}>
          <Icon name={l.icon} size="sm" tone={l.tone} />
          {#if t.kind === 'no_key'}
            <span class="flex-1 min-w-0 text-(--text-primary)">{m.portal_home_todo_no_key_title()}</span>
            <a href={pthref(slug, '/portal/keys')} class={linkClass}>{m.portal_home_todo_create_key()}</a>
          {:else if t.kind === 'key'}
            <span class="flex-1 min-w-0 text-(--text-primary)">
              {(t.expired ? m.portal_home_todo_key_expired : m.portal_home_todo_key_expiring)({
                name: formatKeyLabel(t.name, t.prefix),
                date: formatDate(t.expiresAt),
              })}
            </span>
            <a href={pthref(slug, '/portal/keys')} class={linkClass}>{m.portal_home_action_keys()}</a>
          {:else if t.kind === 'mcp'}
            <span class="flex-1 min-w-0 text-(--text-primary)">
              {m.portal_home_todo_mcp({ count: t.count, names: t.names.join(', ') })}
            </span>
            <a href={pthref(slug, '/portal/mcp/connections')} class={linkClass} data-testid="home-todo-mcp-link">{m.portal_home_todo_mcp_action()}</a>
          {:else}
            <span class="flex-1 min-w-0 text-(--text-primary)" data-host={t.host}>
              {m.portal_home_todo_cli({ host: t.host, version: t.version, latest: t.latest })}
            </span>
            <CopyTextButton value="ssai update" label={m.portal_home_todo_cli_copy()} copiedLabel={m.portal_home_todo_cli_copied()} size="sm" />
          {/if}
        </li>
      {/each}
    </ul>
  </section>
{/if}

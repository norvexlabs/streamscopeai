<script lang="ts">
  /** What one upstream Test returned: a one-line verdict, who acts next and
   *  where (with the editor, when the fix is the upstream's own settings),
   *  then the tools, prompts and resources the upstream lists. */
  import Icon from '#lib/components/Icon.svelte';
  import { upstreamTestSummary, type UpstreamTestResult } from '#lib/mcp/upstreamTest.js';

  let { result, onedit }: { result: UpstreamTestResult; onedit?: () => void } = $props();

  const summary = $derived(upstreamTestSummary(result));
  const TINT = {
    ok: { box: 'border-(--success-border) bg-(--success-bg) text-(--success-text)', icon: 'checkCircle', tone: 'success' },
    pending: { box: 'border-(--info-border) bg-(--info-bg) text-(--info-text)', icon: 'info', tone: 'info' },
    error: { box: 'border-(--error-border) bg-(--error-bg) text-(--error-text)', icon: 'blocked', tone: 'error' },
  } as const;
  const tint = $derived(TINT[summary.tone]);
</script>

<div class="space-y-2" data-testid="upstream-test-result" data-status={result.status}>
  <div class="flex items-start gap-2 rounded-lg border px-3 py-2 text-xs {tint.box}">
    <div class="shrink-0 mt-px"><Icon name={tint.icon} tone={tint.tone} size="xs" /></div>
    <div class="flex-1 min-w-0 space-y-1">
      <p data-testid="upstream-test-summary">{summary.text}</p>
      {#if summary.next}
        <p data-testid="upstream-test-next" class="font-medium">{summary.next}</p>
      {/if}
    </div>
    {#if summary.fix === 'edit' && onedit}
      <button
        type="button"
        data-testid="upstream-test-fix"
        class="shrink-0 self-center rounded-sm border border-current px-2 py-0.5 font-medium hover:opacity-80"
        onclick={onedit}>Open settings</button>
    {/if}
  </div>
  {#if result.builtin_status}
    <p class="text-xs text-(--text-secondary)">
      Search backend: {result.builtin_status.has_backend ? 'configured' : 'none (web_fetch only)'} ·
      credential: {result.builtin_status.has_credential ? 'stored' : 'none'}
    </p>
  {/if}
  {#if result.tools.length > 0}
    <div>
      <div class="text-[10px] text-(--text-secondary) uppercase tracking-wider mb-1">Tools ({result.tools.length})</div>
      <div class="flex flex-wrap gap-1">
        {#each result.tools as t, i (i)}
          <code title={t.description ?? ''} class="text-xs font-mono px-1.5 py-0.5 rounded-sm bg-(--bg-primary) text-(--text-primary) border border-(--border)">{t.name}</code>
        {/each}
      </div>
    </div>
  {/if}
  {#if result.prompts.length > 0}
    <div>
      <div class="text-[10px] text-(--text-secondary) uppercase tracking-wider mb-1">Prompts ({result.prompts.length})</div>
      <div class="flex flex-wrap gap-1">
        {#each result.prompts as p, i (i)}
          <code title={p.description ?? ''} class="text-xs font-mono px-1.5 py-0.5 rounded-sm bg-(--bg-primary) text-(--text-primary) border border-(--border)">{p.name}</code>
        {/each}
      </div>
    </div>
  {/if}
  {#if result.resources.length > 0}
    <div>
      <div class="text-[10px] text-(--text-secondary) uppercase tracking-wider mb-1">Resources ({result.resources.length})</div>
      <ul class="text-xs space-y-0.5">
        {#each result.resources as res, i (i)}
          <li class="text-(--text-secondary)">
            <code class="font-mono text-(--text-primary)">{res.uri}</code>{#if res.name} — {res.name}{/if}
          </li>
        {/each}
      </ul>
    </div>
  {/if}
</div>

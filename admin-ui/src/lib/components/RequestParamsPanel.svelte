<script lang="ts">
  // Collapsible side panel showing the canonical `DomainRequestMeta` —
  // sampling params, response format, tool catalog — for a single turn.
  // Driven by the `turn_params` field returned from
  // `/sessions/{id}/conversation` and `/traces/{id}`.
  // Starts collapsed; matches the System Prompt block's visual grammar.

  import type { DomainRequestMeta, DomainToolSummary } from '#lib/api-types.js';
  import RawJsonBlock from './RawJsonBlock.svelte';

  let { params }: { params: DomainRequestMeta | null | undefined } = $props();

  let expanded = $state(false);
  let expandedTools = $state<Record<number, boolean>>({});

  const hasAny = $derived(!!params && (
    params.temperature != null ||
    params.top_p != null ||
    params.max_output_tokens != null ||
    params.stop_sequences?.length ||
    params.reasoning_effort != null ||
    params.reasoning_budget_tokens != null ||
    params.response_format != null ||
    params.tool_choice != null ||
    params.store != null ||
    params.metadata != null ||
    (params.tools && params.tools.length > 0) ||
    (params.extra && Object.keys(params.extra).length > 0)
  ));

  const summary = $derived.by(() => {
    if (!params) return '';
    const bits: string[] = [];
    if (params.temperature != null) bits.push(`temp ${params.temperature}`);
    if (params.top_p != null) bits.push(`top_p ${params.top_p}`);
    if (params.max_output_tokens != null) bits.push(`max ${params.max_output_tokens}`);
    if (params.tools && params.tools.length > 0) bits.push(`${params.tools.length} tool${params.tools.length === 1 ? '' : 's'}`);
    return bits.join(' · ');
  });

  function hasParams(tool: DomainToolSummary): boolean {
    const p = tool.parameters as Record<string, unknown> | undefined | null;
    if (!p) return false;
    const props = p.properties as Record<string, unknown> | undefined;
    return !!props && Object.keys(props).length > 0;
  }

  function paramList(tool: DomainToolSummary): { name: string; type: string; required: boolean; description: string }[] {
    const p = tool.parameters as Record<string, unknown> | undefined | null;
    if (!p) return [];
    const props = (p.properties ?? {}) as Record<string, Record<string, unknown>>;
    const required = new Set((p.required as string[] | undefined) ?? []);
    return Object.entries(props).map(([name, schema]) => ({
      name,
      type: String(schema.type ?? 'any'),
      required: required.has(name),
      description: String(schema.description ?? ''),
    }));
  }
</script>

{#if params && hasAny}
  <div class="rounded-xl border border-dashed border-(--text-secondary) bg-(--bg-secondary)/30 overflow-hidden">
    <button
      type="button"
      onclick={() => (expanded = !expanded)}
      class="w-full flex items-center gap-2 px-4 py-2.5 text-left hover:bg-(--bg-elevated) transition-colors"
    >
      <span class="inline-block text-[10px] transition-transform text-(--text-secondary) {expanded ? 'rotate-90' : ''}">&#9654;</span>
      <span class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary)">Request Params</span>
      {#if params.model}
        <span class="text-[10px] font-mono text-(--text-primary)">{params.model}</span>
      {/if}
      {#if summary}
        <span class="text-[10px] text-(--text-secondary)">· {summary}</span>
      {/if}
    </button>

    {#if expanded}
      <div class="px-4 pb-3 text-sm text-(--text-primary) space-y-3">
        <!-- Sampling / generation params -->
        <dl class="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1 text-xs">
          {#if params.model}<dt class="font-mono text-(--text-secondary)">model</dt><dd class="font-mono break-all">{params.model}</dd>{/if}
          {#if params.stream != null}<dt class="font-mono text-(--text-secondary)">stream</dt><dd class="font-mono">{params.stream}</dd>{/if}
          {#if params.temperature != null}<dt class="font-mono text-(--text-secondary)">temperature</dt><dd class="font-mono">{params.temperature}</dd>{/if}
          {#if params.top_p != null}<dt class="font-mono text-(--text-secondary)">top_p</dt><dd class="font-mono">{params.top_p}</dd>{/if}
          {#if params.max_output_tokens != null}<dt class="font-mono text-(--text-secondary)">max_output_tokens</dt><dd class="font-mono">{params.max_output_tokens}</dd>{/if}
          {#if params.reasoning_effort != null}<dt class="font-mono text-(--text-secondary)">reasoning_effort</dt><dd class="font-mono">{params.reasoning_effort}</dd>{/if}
          {#if params.reasoning_budget_tokens != null}<dt class="font-mono text-(--text-secondary)">reasoning_budget_tokens</dt><dd class="font-mono">{params.reasoning_budget_tokens}</dd>{/if}
          {#if params.store != null}<dt class="font-mono text-(--text-secondary)">store</dt><dd class="font-mono">{params.store}</dd>{/if}
          {#if params.stop_sequences && params.stop_sequences.length > 0}
            <dt class="font-mono text-(--text-secondary)">stop_sequences</dt><dd class="font-mono break-all">{params.stop_sequences.join(', ')}</dd>
          {/if}
        </dl>

        {#if params.response_format}
          <RawJsonBlock label="response_format" value={params.response_format} />
        {/if}
        {#if params.tool_choice}
          <RawJsonBlock label="tool_choice" value={params.tool_choice} />
        {/if}
        {#if params.metadata}
          <RawJsonBlock label="metadata" value={params.metadata} />
        {/if}
        {#if params.extra && Object.keys(params.extra).length > 0}
          <RawJsonBlock label="extra" value={params.extra} />
        {/if}

        {#if params.tools && params.tools.length > 0}
          <div>
            <div class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary) mb-1.5">Tools available ({params.tools.length})</div>
            <ul class="divide-y divide-(--border) rounded-lg border border-(--border) bg-(--bg-card)">
              {#each params.tools as tool, i}
                <li class="px-3 py-2">
                  <div class="flex items-center gap-2">
                    <span class="font-mono text-xs font-semibold text-(--text-primary)">{tool.name}</span>
                    {#if tool.server_type}
                      <span class="px-1.5 py-0.5 text-[9px] uppercase tracking-wider rounded-sm bg-(--bg-primary) text-(--text-secondary) border border-(--border)">{tool.server_type}</span>
                    {/if}
                    {#if hasParams(tool)}
                      <button
                        type="button"
                        onclick={() => (expandedTools = { ...expandedTools, [i]: !(expandedTools[i] ?? false) })}
                        class="ml-auto text-[10px] text-(--accent) hover:underline inline-flex items-center gap-1"
                      >
                        <span class="inline-block text-[9px] transition-transform {expandedTools[i] ? 'rotate-90' : ''}">&#9654;</span>
                        {paramList(tool).length} param{paramList(tool).length === 1 ? '' : 's'}
                      </button>
                    {/if}
                  </div>
                  {#if tool.description}
                    <div class="text-[11px] text-(--text-secondary) mt-0.5">{tool.description}</div>
                  {/if}
                  {#if expandedTools[i] && hasParams(tool)}
                    <ul class="mt-1.5 divide-y divide-(--border) border-t border-(--border)">
                      {#each paramList(tool) as p}
                        <li class="py-1 flex items-start gap-2 text-[11px]">
                          <span class="font-mono text-(--text-primary) font-medium">{p.name}</span>
                          <span class="font-mono text-(--text-secondary)">{p.type}</span>
                          {#if p.required}
                            <span class="text-[9px] px-1 py-0.5 rounded-sm bg-(--error-bg) text-(--error) border border-(--error-border)">required</span>
                          {/if}
                          {#if p.description}
                            <span class="text-(--text-secondary) flex-1 wrap-break-word">— {p.description}</span>
                          {/if}
                        </li>
                      {/each}
                    </ul>
                  {/if}
                </li>
              {/each}
            </ul>
          </div>
        {/if}
      </div>
    {/if}
  </div>
{/if}

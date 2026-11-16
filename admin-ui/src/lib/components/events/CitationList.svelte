<script lang="ts">
  /**
   * The sources a message's text cites (an Anthropic text's `citations`, an
   * OpenAI text's `annotations`), the one renderer for them, shared by the
   * session view and the audit detail: collapsed to a count, opened to each
   * source — its title (a link where it names a web page), the file it names,
   * where in it the quote is, and the quote.
   */
  import type { Citation } from '#lib/api-types.js';
  import { m } from '#lib/paraglide/messages.js';
  import { citationLocation, citationLink } from '#lib/citations.js';

  interface Props {
    citations: Citation[];
  }

  let { citations }: Props = $props();
  let open = $state(false);
</script>

{#if citations.length > 0}
  <div class="mt-2 rounded-lg border border-(--border) bg-(--bg-primary) overflow-hidden">
    <button
      type="button"
      onclick={() => (open = !open)}
      class="w-full flex items-center gap-2 px-3 py-1.5 text-left hover:bg-(--bg-elevated) transition-colors"
      aria-expanded={open}
    >
      <span class="inline-block text-[10px] transition-transform text-(--text-secondary) {open ? 'rotate-90' : ''}">&#9654;</span>
      <span class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary)">{m.conv_citations({ count: citations.length })}</span>
    </button>
    {#if open}
      <ol class="px-3 pb-2 space-y-2 list-decimal list-inside">
        {#each citations as c, i (i)}
          {@const link = citationLink(c)}
          {@const where = citationLocation(c)}
          <li class="text-xs text-(--text-primary)">
            {#if link}
              <a href={link} target="_blank" rel="noopener noreferrer" class="text-(--tag-blue-text) hover:underline break-all">{c.title || link}</a>
            {:else}
              <span class="font-medium">{c.title || m.conv_citation_untitled()}</span>
            {/if}
            {#if c.file_id}
              <span class="text-(--text-secondary) break-all">· {m.conv_citation_file({ id: c.file_id })}</span>
            {/if}
            {#if where}
              <span class="text-(--text-secondary)">
                · {where.unit === 'chars'
                  ? m.conv_citation_chars({ start: where.start, end: where.end })
                  : where.unit === 'pages'
                    ? where.start === where.end
                      ? m.conv_citation_page({ page: where.start })
                      : m.conv_citation_pages({ start: where.start, end: where.end })
                    : where.start === where.end
                      ? m.conv_citation_block({ block: where.start })
                      : m.conv_citation_blocks({ start: where.start, end: where.end })}
              </span>
            {/if}
            {#if c.cited_text}
              <blockquote class="mt-1 ml-4 pl-2 border-l-2 border-(--border) text-(--text-secondary) whitespace-pre-wrap">{c.cited_text}</blockquote>
            {/if}
          </li>
        {/each}
      </ol>
    {/if}
  </div>
{/if}

<script lang="ts">
  // Renders a list of canonical content blocks — the protocol-agnostic block
  // vocabulary the backend normalizes every wire format into. One renderer, so a
  // text part, an image an agent returned, and a payload nobody recognized all
  // look the same wherever they appear.
  //
  // Nothing is ever dropped: an unrecognized block renders its raw JSON, and a
  // block the gateway declined to inline renders a visible "stripped" marker.
  import RawJsonBlock from '#lib/components/RawJsonBlock.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import { formatBytes } from '#lib/formatters.js';
  import { m } from '#lib/paraglide/messages.js';
  import type { ContentBlock } from '#lib/components/events/blocks.js';

  interface Props {
    blocks: ContentBlock[];
  }

  let { blocks }: Props = $props();

  // The union is discriminated by `type`, but each arm below reads only the
  // fields its own variant carries; going through a record view keeps the
  // markup free of per-variant narrowing without ever inventing a field.
  function str(b: ContentBlock, key: string): string | null {
    const v = (b as Record<string, unknown>)[key];
    return typeof v === 'string' ? v : null;
  }
  function num(b: ContentBlock, key: string): number | null {
    const v = (b as Record<string, unknown>)[key];
    return typeof v === 'number' ? v : null;
  }
</script>

<div class="space-y-2">
  {#each blocks as block, i (i)}
    {#if block.type === 'text'}
      <p class="text-sm text-(--text-primary) whitespace-pre-wrap wrap-break-word">{str(block, 'text') ?? ''}</p>

    {:else if block.type === 'image'}
      <img
        src="data:{str(block, 'media_type') ?? 'image/png'};base64,{str(block, 'data') ?? ''}"
        alt={m.event_blocks_image()}
        class="block max-w-full h-auto rounded-sm"
        loading="lazy"
      />

    {:else if block.type === 'audio'}
      <audio controls src="data:audio/{str(block, 'format') ?? 'wav'};base64,{str(block, 'data') ?? ''}" class="w-full"></audio>

    {:else if block.type === 'document'}
      <div class="flex items-center gap-2 text-xs text-(--text-secondary)">
        <Icon name="document" size="sm" color="currentColor" />
        <span class="font-mono text-(--text-primary)">{str(block, 'title') ?? str(block, 'media_type') ?? m.event_blocks_document()}</span>
      </div>

    {:else if block.type === 'file'}
      <div class="flex items-center gap-2 text-xs text-(--text-secondary)">
        <Icon name="externalLink" size="sm" color="currentColor" />
        {#if str(block, 'url')}
          <span class="font-mono text-(--text-primary) truncate" title={str(block, 'url') ?? ''}>{str(block, 'url')}</span>
        {:else}
          <span class="font-mono text-(--text-primary)">{str(block, 'filename') ?? str(block, 'file_id') ?? m.event_blocks_file()}</span>
        {/if}
      </div>

    {:else if block.type === 'stripped'}
      <div class="flex items-center gap-2 text-xs text-(--warning)">
        <Icon name="triangleAlert" size="sm" color="currentColor" />
        <span>
          {m.event_blocks_stripped({
            type: str(block, 'media_type') ?? '?',
            size: formatBytes(num(block, 'size_bytes') ?? 0),
          })}
        </span>
      </div>

    {:else}
      <RawJsonBlock value={block.type === 'unknown' ? block.value : block} />
    {/if}
  {/each}
</div>

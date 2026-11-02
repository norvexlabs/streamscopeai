<script lang="ts">
  /**
   * One stored media blob — an image, an audio or video clip, or a file to download —
   * shown in the console or the portal from its NAME: content hash, blob kind
   * and the request that references it. The address is built here, once, for
   * the plane the page is on (`mediaUrl`), with the portal workspace the page
   * is viewing (`portalWorkspace`). A blob this plane cannot address (the
   * portal without its owning request), or one the server will not serve,
   * reads as unavailable, never as a broken image or a dead player.
   */
  import { page } from '$app/state';
  import { mediaUrl } from '#lib/media.js';
  import { portalWorkspace } from '#lib/selfScoped.js';
  import { m } from '#lib/paraglide/messages.js';
  import Icon from '#lib/components/Icon.svelte';

  interface Props {
    hash: string;
    blobType: string;
    requestId?: string | null;
    /** How to show it: `image`, `audio` and `video` show inline, anything else is a download. */
    kind: string;
    alt?: string;
    /** File name offered for the download link; no link when absent (a document is its own link). */
    download?: string;
    /** The audit detail's smaller frame. */
    compact?: boolean;
  }

  let { hash, blobType, requestId = null, kind, alt, download, compact = false }: Props = $props();

  const viewedWorkspace = portalWorkspace();
  const url = $derived(
    mediaUrl(page.params.slug ?? '', page.url.pathname, hash, blobType, requestId ?? undefined, viewedWorkspace()),
  );
  // The address that failed to load, so a new address is tried afresh.
  let failed = $state<string | null>(null);
</script>

{#if !url || failed === url}
  <p class="text-xs text-(--text-secondary) italic">{m.audit_detail_media_not_available()}</p>
{:else}
  {#if kind === 'image'}
    <img
      src={url}
      onerror={() => (failed = url)}
      alt={alt ?? m.conv_image_attachment()}
      loading="lazy"
      class={compact
        ? 'max-w-xs max-h-48 rounded-sm border border-(--border) mt-1'
        : 'block max-w-full h-auto rounded-sm'} />
  {:else if kind === 'audio'}
    <audio controls src={url} onerror={() => (failed = url)} class={compact ? 'w-full mt-1' : 'w-full'}></audio>
  {:else if kind === 'video'}
    <!-- svelte-ignore a11y_media_has_caption -->
    <video controls src={url} onerror={() => (failed = url)} class="max-w-md rounded-sm border border-(--border)"></video>
  {:else if !download}
    <a href={url} download class="text-sm text-(--tag-blue-text) hover:underline">{m.conv_download_document()}</a>
  {/if}
  {#if download}
    <a
      href={url}
      {download}
      class="inline-flex items-center gap-1 mt-1 text-[10px] text-(--accent) hover:underline">
      <Icon name="download" size="sm" color="currentColor" />
      {m.conv_download()}
    </a>
  {/if}
{/if}

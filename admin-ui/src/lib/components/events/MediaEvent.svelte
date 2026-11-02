<script lang="ts">
  /**
   * The body of a `media` conversation event — the one renderer for it, shared
   * by the session view and the audit detail (each draws its own frame and
   * header around it). In order: inline data of a type safe to play, the
   * stored blob the event names (`StoredMedia`, which addresses it for this
   * plane), the client's external URL, the client's provider file id, and
   * otherwise why nothing can be shown. A stored blob is never described as
   * "not stored".
   */
  import type { ConversationEvent } from '#lib/api-types.js';
  import { m } from '#lib/paraglide/messages.js';
  import { formatBytes } from '#lib/formatters.js';
  import StoredMedia from './StoredMedia.svelte';

  type MediaEventShape = Extract<ConversationEvent, { type: 'media' }>;

  interface Props {
    event: MediaEventShape;
    /** The audit detail's smaller frame. */
    compact?: boolean;
  }

  let { event, compact = false }: Props = $props();

  // Inline data is played only for types a browser renders without a script
  // surface (never SVG); anything else is named, not played. The lists carry
  // the spellings clients and the parsers really use (`audio/mp3` is Chat's
  // `input_audio` and Gemini's, `image/jpg` a common client spelling).
  const SAFE_IMAGE_TYPES = new Set(['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp', 'image/avif', 'image/bmp', 'image/tiff']);
  const SAFE_AUDIO_TYPES = new Set(['audio/mpeg', 'audio/mp3', 'audio/wav', 'audio/x-wav', 'audio/ogg', 'audio/opus', 'audio/webm', 'audio/mp4', 'audio/flac', 'audio/aac']);

  const external = $derived(event.url && /^https?:\/\//i.test(event.url) ? event.url : null);

  const media = $derived(compact ? 'block max-w-full h-auto rounded-sm border border-(--border) mt-1' : 'block max-w-full h-auto rounded-sm');
</script>

{#if event.content_type === 'image' && event.data && SAFE_IMAGE_TYPES.has(event.media_type)}
  <img src="data:{event.media_type};base64,{event.data}" alt={event.title ?? m.conv_image_attachment()} class={media} />
{:else if event.content_type === 'audio' && event.data && SAFE_AUDIO_TYPES.has(event.media_type)}
  <audio controls src="data:{event.media_type};base64,{event.data}" class="w-full"></audio>
{:else if event.content_type === 'document' && event.data && event.media_type === 'application/pdf'}
  <iframe sandbox="allow-same-origin" src="data:application/pdf;base64,{event.data}" class="w-full h-96 rounded-sm border-0" title={event.title ?? m.conv_pdf_document()}></iframe>
{:else if event.content_type === 'document' && event.data && event.media_type.startsWith('text/')}
  <!-- A text document's data is its prose, decoded at the parser. -->
  <pre class="text-xs font-mono text-(--text-secondary) whitespace-pre-wrap max-h-64 overflow-y-auto">{event.data}</pre>
{:else if event.content_type === 'image' && event.data}
  <p class="text-sm text-(--text-secondary) italic">{m.conv_unsupported_image_type({ type: event.media_type })}</p>
{:else if event.content_type === 'audio' && event.data}
  <p class="text-sm text-(--text-secondary) italic">{m.conv_unsupported_audio_type({ type: event.media_type })}</p>
{:else if event.content_hash && event.blob_type}
  {#if !event.request_id}
    <!-- The turn's request did not carry the blob itself (a part the client
         wrote, or history it did not resend): shown where it can be, and said so. -->
    <p class="text-xs text-(--warning) italic mb-1">{m.conv_media_not_carried()}</p>
  {/if}
  <StoredMedia
    hash={event.content_hash}
    blobType={event.blob_type}
    requestId={event.request_id}
    kind={event.content_type}
    alt={event.title ?? undefined}
    {compact} />
{:else if external && event.content_type === 'image'}
  <img src={external} alt={event.title ?? m.conv_image_attachment()} class={media} />
{:else if external}
  <a href={external} target="_blank" rel="noopener noreferrer" class="text-sm text-(--tag-blue-text) hover:underline break-all">{event.title ?? external}</a>
{:else if event.url}
  <!-- A provider file id: the client's own reference, nothing to load. -->
  <p class="text-xs font-mono text-(--text-secondary) break-all">{event.url}</p>
{:else if !event.data && event.size_bytes}
  <p class="text-sm text-(--text-secondary) italic">{m.conv_media_not_stored({ size: formatBytes(event.size_bytes) })}</p>
{:else if event.content_type === 'image'}
  <p class="text-sm text-(--text-secondary) italic">{m.conv_image_not_available()}</p>
{:else if event.content_type === 'document'}
  <p class="text-sm text-(--text-secondary) italic">{m.conv_document_not_available()}</p>
{:else if event.content_type === 'audio'}
  <p class="text-sm text-(--text-secondary) italic">{m.conv_audio_not_available()}</p>
{:else}
  <p class="text-sm text-(--text-secondary) italic">{m.audit_detail_media_not_available()}</p>
{/if}

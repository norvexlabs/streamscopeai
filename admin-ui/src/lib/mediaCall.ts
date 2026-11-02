/**
 * UI display primitives over a `DomainMediaCall`.
 *
 * The proxy stores media RPC turns under `event.media_call` (or
 * `audit_row.media_call`) as a `DomainMediaCall`. Session and audit
 * pages both project that shape into the same set of UI primitives
 * (category, title, first text/blob block) — the helpers used to live
 * inline in both pages and drifted.
 *
 * Keep the helpers pure — render decisions
 * (compact-row layout vs chat-bubble layout) belong on the call site.
 */

import type { DomainMediaCall } from './api-types';

export type BlobRef = {
  content_hash: string;
  media_type: string;
  size_bytes?: number;
};

/**
 * High-level bucket (image / audio / video / embedding) used for badge
 * colors and rendering branches. Returns `'media'` for anything not yet
 * categorised.
 */
export function mediaCallCategory(call: DomainMediaCall | null | undefined): string {
  if (!call) return 'media';
  switch (call.endpoint) {
    case 'embeddings':
      return 'embedding';
    case 'audio_speech':
    case 'audio_transcription':
    case 'audio_translation':
      return 'audio';
    case 'image_generation':
    case 'image_edit':
    case 'image_variation':
      return 'image';
    case 'video_generation':
      return 'video';
    default:
      return 'media';
  }
}

/**
 * Human-readable label derived from the endpoint. Falls back to a generic
 * "Media Request" for endpoints we don't recognise.
 */
export function mediaCallTitle(call: DomainMediaCall | null | undefined): string {
  if (!call) return 'Media Request';
  switch (call.endpoint) {
    case 'embeddings':
      return 'Embedding';
    case 'audio_speech':
      return 'Text to Speech';
    case 'audio_transcription':
      return 'Audio Transcription';
    case 'audio_translation':
      return 'Audio Translation';
    case 'image_generation':
      return 'Image Generation';
    case 'image_edit':
      return 'Image Edit';
    case 'image_variation':
      return 'Image Variation';
    case 'video_generation':
      return 'Video Generation';
    default:
      return 'Media Request';
  }
}

/** First Text block in a content array, or null. */
export function firstTextBlock(blocks: Array<Record<string, unknown>> | undefined): string | null {
  for (const b of blocks ?? []) {
    if (b['type'] === 'text' && typeof b['text'] === 'string') return b['text'] as string;
  }
  return null;
}

/** First BlobRef block in a content array, or null. `size_bytes` is preserved when present. */
export function firstBlobRef(blocks: Array<Record<string, unknown>> | undefined): BlobRef | null {
  for (const b of blocks ?? []) {
    if (b['type'] === 'blob_ref' && typeof b['content_hash'] === 'string') {
      return {
        content_hash: b['content_hash'] as string,
        media_type: String(b['media_type'] ?? 'application/octet-stream'),
        size_bytes: typeof b['size_bytes'] === 'number' ? (b['size_bytes'] as number) : undefined,
      };
    }
  }
  return null;
}

/** True when the endpoint uploads a file the audit list / session view should render back. */
export function isMultipartEndpoint(endpoint: string | undefined): boolean {
  return (
    endpoint === 'audio_transcription' ||
    endpoint === 'audio_translation' ||
    endpoint === 'image_edit' ||
    endpoint === 'image_variation'
  );
}

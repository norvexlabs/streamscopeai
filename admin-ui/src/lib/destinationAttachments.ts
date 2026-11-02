/**
 * The destination lists a consumer (the sandbox of a client-access profile,
 * the Web tool) attaches, each once, as `allow` or `block` — what the
 * attachments editor shows and sends back whole.
 */
import type { components } from '#lib/generated/api-types.js';

export type DestinationMode = components['schemas']['DestinationMode'];
export type Attachment = components['schemas']['DestinationAttachment'];

/** Attach `listId` in `mode`; a list already attached takes the new mode. */
export function attach(current: readonly Attachment[], listId: string, mode: DestinationMode): Attachment[] {
  const others = current.filter((a) => a.list_id !== listId);
  return [...others, { list_id: listId, mode }];
}

/** Detach `listId`; the others keep their order and mode. */
export function detach(current: readonly Attachment[], listId: string): Attachment[] {
  return current.filter((a) => a.list_id !== listId);
}

/** The lists not attached yet, in the order given. */
export function unattached<T extends { id: string }>(lists: readonly T[], current: readonly Attachment[]): T[] {
  const taken = new Set(current.map((a) => a.list_id));
  return lists.filter((l) => !taken.has(l.id));
}

/** Whether two attachment sets differ, whatever their order. */
export function attachmentsChanged(a: readonly Attachment[], b: readonly Attachment[]): boolean {
  if (a.length !== b.length) return true;
  const modes = new Map(a.map((x) => [x.list_id, x.mode]));
  return b.some((x) => modes.get(x.list_id) !== x.mode);
}

/** Entries typed one per line (blank lines and surrounding spaces dropped). */
export function entriesFromText(text: string): string[] {
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
}

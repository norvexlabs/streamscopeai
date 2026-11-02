// What the last model-discovery run on an upstream server did.
//
// Read from the stored row rather than re-derived per surface: the LLM gateway
// list and the server's own page both report it, and a failure that only one of
// them can see is a failure nobody acts on.
import { formatAge, formatTimeAgo } from '#lib/formatters.js';

/** The stored fields a run leaves behind. */
export interface SyncedServer {
  last_auto_sync_at?: string | null;
  last_auto_sync_status?: unknown;
}

export interface SyncStatus {
  ok: boolean;
  /** Short enough for a card or a chip. */
  label: string;
  /** The same thing with the provider's own reason, for a tooltip or a line of
   *  body text. Equal to `label` when there is nothing more to say. */
  detail: string;
  /** How long ago it happened, or null when nothing recorded a time. The one
   *  place that resolves it, so a tile and the panel beside it cannot show
   *  different instants for the same run. */
  ago: string | null;
  /** The same instant as a compact figure (`13h`) for a stat card's value
   *  slot, where the `ago` phrase would not fit; null exactly when `ago` is. */
  age: string | null;
}

function count(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

/**
 * `null` when nothing has been recorded.
 *
 * Two fields carry two different facts. `last_auto_sync_at` is what the
 * background worker's due window is measured from, so a path that must leave a
 * server due cannot touch it — an operator's sync, a replica being added, a
 * server being created. Those record the reason with its OWN `at` instead, and
 * a status that carries one is authoritative: reading the column would stamp a
 * fresh failure with the previous successful run's time.
 *
 * The recorded `ok` flag is the only thing separating a failure from a success,
 * because a failed run from the worker stamps the timestamp exactly as a
 * successful one does. A surface reading only the time reports a failure as a
 * success — which is how a server whose credential the provider refuses looks
 * healthy while serving no models. A status object that is present but says
 * anything other than `ok: true` is therefore read as a FAILURE: a run that
 * recorded something we cannot understand is not evidence that it worked. A row
 * carrying no status object at all records nothing either way, and is not
 * reported as a failure.
 */
export function syncStatus(server: SyncedServer | null | undefined): SyncStatus | null {
  const raw = server?.last_auto_sync_status;
  const status = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : null;
  const recordedAt = typeof status?.at === 'string' ? status.at : null;
  const stamped = recordedAt ?? server?.last_auto_sync_at ?? null;
  // A time that does not parse records no time: the run is reported without
  // one ("Synced"), never as "Synced --".
  const at = stamped && Number.isFinite(Date.parse(stamped)) ? stamped : null;
  const ago = at ? formatTimeAgo(at) : null;
  const age = at ? formatAge(at) : null;
  if (!status) {
    if (!ago) return null;
    const ran = `Ran ${ago}`;
    return { ok: true, label: ran, detail: `${ran} — nothing was recorded about the result`, ago, age };
  }
  const when = ago ? ` ${ago}` : '';
  if (status.ok !== true) {
    const reason = typeof status.reason === 'string' ? status.reason : '';
    const label = `Failed${when}`;
    return { ok: false, label, detail: reason ? `${label} — ${reason}` : label, ago, age };
  }
  const parts: string[] = [];
  const added = count(status.added);
  const removed = count(status.models_removed);
  if (added) parts.push(`+${added}`);
  if (removed) parts.push(`-${removed}`);
  const delta = parts.length ? ` (${parts.join(' ')})` : '';
  const label = `Synced${when}${delta}`;
  return { ok: true, label, detail: label, ago, age };
}

/**
 * A suggestion list's reload never changes what a pending row on screen says.
 *
 * Approving sends the `content_hash` of the row as shown, and the server
 * installs exactly that content or answers 409 `suggestion_changed`. What is
 * left is the reader: an agent re-proposal landing on screen moments before a
 * click would have the admin approve text they did not read. So a reload keeps
 * a shown pending row as it is when the server's copy of it changed, and
 * records the newer copy beside it; only the admin swaps it in
 * (`acceptNewer`). Every other row — a new suggestion, one reviewed elsewhere,
 * one whose content did not change — takes the server's copy.
 */
export interface Revisable {
  id: string;
  content_hash: string;
  status: string;
}

export interface MergedSuggestions<T extends Revisable> {
  rows: T[];
  /** Newer server copies of rows still shown as they were, by id. */
  newer: Record<string, T>;
}

export function mergeSuggestions<T extends Revisable>(shown: readonly T[], fetched: readonly T[]): MergedSuggestions<T> {
  const byId = new Map(shown.map((s) => [s.id, s]));
  const newer: Record<string, T> = {};
  const rows = fetched.map((f) => {
    const s = byId.get(f.id);
    if (s && s.status === 'pending' && f.status === 'pending' && s.content_hash !== f.content_hash) {
      newer[f.id] = f;
      return s;
    }
    return f;
  });
  return { rows, newer };
}

/** The admin chose to read the newer copy of row `id`: it replaces the shown one. */
export function acceptNewer<T extends Revisable>(merged: MergedSuggestions<T>, id: string): MergedSuggestions<T> {
  const next = merged.newer[id];
  if (!next) return merged;
  const newer = { ...merged.newer };
  delete newer[id];
  return { rows: merged.rows.map((r) => (r.id === id ? next : r)), newer };
}

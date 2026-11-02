/**
 * Reading the open-object fields of an audit row (`change_diff`, `request_body`),
 * whose shape the server documents rather than types.
 */

function field(value: unknown, key: string): unknown {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)[key]
    : undefined;
}

/** Whether `value` is the marker of a record too large to keep, not its content. */
export function isTruncated(value: unknown): boolean {
  return field(value, '_truncated') === true;
}

/** The size a record too large to keep was stored as, or `null` when the marker does not say. */
export function truncatedBytes(value: unknown): number | null {
  if (!isTruncated(value)) return null;
  const bytes = field(value, '_bytes');
  return typeof bytes === 'number' ? bytes : null;
}

/** A change diff's two sides, each `null` where the diff does not carry it. */
export function diffSides(value: unknown): { before: unknown; after: unknown } {
  return { before: field(value, 'before') ?? null, after: field(value, 'after') ?? null };
}

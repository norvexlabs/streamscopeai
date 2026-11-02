// Column count for a row of dashboard stat cards (<MetricGrid>).
//
// Every card is at least `minPx` wide. When the whole set fits on one row it
// takes one row; otherwise it takes the fewest rows that fit, balanced so the
// rows are equal whenever the count allows (8 cards → 2 × 4, 6 → 2 × 3) and
// never leave a lone straggler (7 → 4 + 3, never 6 + 1). A set smaller than
// `minTracks` still gets `minTracks` columns when they fit, so one or two
// cards stay tile-sized instead of stretching into a banner. Returns 0 while
// the container is unmeasured, so the caller can fall back to a CSS track.
// `maxCols` caps the columns however wide the container is.
export function metricGridColumns(
  count: number,
  widthPx: number,
  minPx: number,
  gapPx: number,
  minTracks = 1,
  maxCols = Infinity,
): number {
  if (count <= 0 || widthPx <= 0) return 0;
  const fit = Math.max(1, Math.min(maxCols, Math.floor((widthPx + gapPx) / (minPx + gapPx))));
  if (count <= fit) return Math.max(count, Math.min(fit, minTracks));
  const rows = Math.ceil(count / fit);
  return Math.ceil(count / rows);
}

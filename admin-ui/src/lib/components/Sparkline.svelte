<script lang="ts">
  // Inline sparkline rendered as area fill + line + optional partial-trailing
  // segment. The trailing segment is rendered dashed and translucent when the
  // caller flags the last bucket as still in-progress, so a half-elapsed hour
  // or day isn't mistaken for a real spike. All-zero series flatten to the
  // baseline (the Math.max(..., 1) divisor).
  let {
    values,
    partialLast,
    width = 80,
    height = 24,
    color = 'var(--chart-2)',
    strokeWidth = 1.5,
    title,
  }: {
    values: number[];
    /** Whether `values[n-1]` is a still-in-progress bucket. Required so callers
        explicitly opt the trailing segment into the dashed-partial treatment. */
    partialLast: boolean;
    width?: number;
    height?: number;
    color?: string;
    strokeWidth?: number;
    title?: string;
  } = $props();

  type Geom = {
    pts: Array<{ x: number; y: number }>;
    settled: string; // path for the leading (settled) segment
    partial: string; // path for the trailing partial segment (or '')
    area: string; // closed area under the full line
    last: { x: number; y: number } | null;
  };

  const geom = $derived.by<Geom>(() => {
    const empty: Geom = { pts: [], settled: '', partial: '', area: '', last: null };
    if (!values || values.length === 0) return empty;
    const n = values.length;
    const max = Math.max(...values, 1);
    const pad = strokeWidth / 2;
    const w = width - pad * 2;
    const h = height - pad * 2;
    const baseline = pad + h;
    const pts = values.map((v, i) => ({
      x: n === 1 ? pad + w / 2 : pad + (i / (n - 1)) * w,
      y: pad + h - (v / max) * h,
    }));
    // Settled segment covers indices 0..(partialLast ? n-2 : n-1).
    const splitIdx = partialLast && n >= 2 ? n - 1 : n;
    const settledPts = pts.slice(0, splitIdx);
    const settled = settledPts.length === 1
      ? `M${pts[0].x},${pts[0].y} L${pts[0].x},${pts[0].y}`
      : settledPts
          .map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(2)},${p.y.toFixed(2)}`)
          .join(' ');
    const partial = partialLast && n >= 2
      ? `M${pts[n - 2].x.toFixed(2)},${pts[n - 2].y.toFixed(2)} L${pts[n - 1].x.toFixed(2)},${pts[n - 1].y.toFixed(2)}`
      : '';
    const lineLs = pts
      .map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(2)},${p.y.toFixed(2)}`)
      .join(' ');
    const area = `${lineLs} L${pts[n - 1].x.toFixed(2)},${baseline.toFixed(2)} L${pts[0].x.toFixed(2)},${baseline.toFixed(2)} Z`;
    return { pts, settled, partial, area, last: pts[n - 1] };
  });
</script>

<svg
  {width}
  {height}
  viewBox={`0 0 ${width} ${height}`}
  class="block shrink-0"
  aria-label={title ?? 'Sparkline'}
  role="img"
>
  {#if title}
    <title>{title}</title>
  {/if}
  {#if geom.area}
    <path d={geom.area} fill={color} fill-opacity="0.12" stroke="none" />
  {/if}
  {#if geom.settled}
    <path
      d={geom.settled}
      fill="none"
      stroke={color}
      stroke-width={strokeWidth}
      stroke-linejoin="round"
      stroke-linecap="round"
    />
  {/if}
  {#if geom.partial}
    <path
      d={geom.partial}
      fill="none"
      stroke={color}
      stroke-width={strokeWidth}
      stroke-dasharray="2 2"
      stroke-opacity="0.6"
      stroke-linecap="round"
    />
  {/if}
  {#if partialLast && geom.last}
    <circle cx={geom.last.x} cy={geom.last.y} r={strokeWidth + 0.5} fill={color} fill-opacity="0.7" />
  {/if}
</svg>

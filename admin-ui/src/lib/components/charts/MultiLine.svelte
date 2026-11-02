<script lang="ts">
  import { getLayerCakeContext } from 'layercake';
  import { area, line, curveMonotoneX } from 'd3-shape';

  /** One line per series, keyed by the row field it plots. A row whose value
   *  is `null` (no reading for that bucket) is a GAP in the line, never a
   *  drop to zero — zero is a reading, and a line through it would claim one.
   *  A reading alone between two gaps is a dot.
   *  `fill` shades the area under the line. */
  let {
    series,
  }: {
    series: Array<{ key: string; color: string; width?: number; dashArray?: string; fill?: boolean }>;
  } = $props();

  const k = getLayerCakeContext();

  const present = (key: string) => (d: any) => d[key] != null && Number.isFinite(d[key]);

  function linePath(key: string): string {
    const gen = line()
      .defined(present(key))
      .x((d: any) => k.xScale(d.timestamp))
      .y((d: any) => k.yScale(d[key]))
      .curve(curveMonotoneX);
    return gen(k.data as any) || '';
  }

  /** Readings with no reading on either side: a line through one point is
   *  empty, so these are drawn as dots — a lone reading is still a reading. */
  function lonePoints(key: string): Array<{ timestamp: Date } & Record<string, unknown>> {
    const rows = k.data as Array<{ timestamp: Date } & Record<string, unknown>>;
    const has = present(key);
    return rows.filter((d, i) => has(d) && !(i > 0 && has(rows[i - 1])) && !(i < rows.length - 1 && has(rows[i + 1])));
  }

  function areaPath(key: string): string {
    const gen = area()
      .defined(present(key))
      .x((d: any) => k.xScale(d.timestamp))
      .y0(k.yScale.range()[0])
      .y1((d: any) => k.yScale(d[key]))
      .curve(curveMonotoneX);
    return gen(k.data as any) || '';
  }
</script>

{#each series as s (s.key)}
  {#if s.fill}
    <path d={areaPath(s.key)} fill={s.color} fill-opacity={0.15} stroke="none" />
  {/if}
  <path
    d={linePath(s.key)}
    fill="none"
    stroke={s.color}
    stroke-width={s.width ?? 2}
    stroke-dasharray={s.dashArray ?? ''}
  />
  {#each lonePoints(s.key) as d (d.timestamp)}
    <circle cx={k.xScale(d.timestamp)} cy={k.yScale(d[s.key] as number)} r={(s.width ?? 2) + 0.5} fill={s.color} />
  {/each}
{/each}

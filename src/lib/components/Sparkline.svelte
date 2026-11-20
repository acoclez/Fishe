<script lang="ts">
  /** Tiny rate trend for a table row: total (in + out) over the last points. */
  import type { TrafficPoint } from "#lib/api/types.ts";

  let { points, width = 96, height = 22 }: { points: TrafficPoint[]; width?: number; height?: number } = $props();

  const path = $derived.by(() => {
    const pts = points.slice(-120);
    if (pts.length < 2) return "";
    let max = 1;
    for (const p of pts) max = Math.max(max, p.inBps + p.outBps);
    const step = width / (pts.length - 1);
    return pts
      .map((p, i) => `${i ? "L" : "M"}${(i * step).toFixed(1)} ${(height - 1 - ((p.inBps + p.outBps) / max) * (height - 3)).toFixed(1)}`)
      .join("");
  });
</script>

<svg {width} {height} viewBox="0 0 {width} {height}" aria-hidden="true">
  {#if path}
    <path d="{path}L{width} {height}L0 {height}Z" class="area" />
    <path d={path} class="line" />
  {:else}
    <line x1="0" x2={width} y1={height - 1} y2={height - 1} class="flat" />
  {/if}
</svg>

<style>
  svg {
    display: block;
  }
  .area {
    fill: var(--accent);
    opacity: 0.18;
  }
  .line {
    fill: none;
    stroke: var(--accent-strong);
    stroke-width: 1.5;
    stroke-linejoin: round;
  }
  .flat {
    stroke: var(--border-strong);
    stroke-width: 1;
  }
</style>

<script lang="ts">
  /**
   * Rolling throughput chart.
   *
   * Stacked areas (inbound at the bottom, outbound on top) so the total
   * height equals the gauge's throughput; a dashed line shows the learned
   * baseline, and a strip under the axis records the busyness level over
   * time, which is the "when did it get busier" view. Hover for exact values.
   */
  import type { TrafficPoint, Units } from "$lib/api/types";
  import { formatRatio, niceCeil, rateText, shortSi, toUnits } from "$lib/utils/format";
  import LevelBadge from "./LevelBadge.svelte";

  interface Props {
    points: TrafficPoint[];
    /** Live mode: show the last N seconds, ending at the newest point. */
    windowSecs?: number;
    units: Units;
    /** Replay mode: show exactly this [start, end] time range (ms). */
    range?: [number, number] | null;
    /** "ago": -30s … now (live). "elapsed": 0:00 … 12:30 (recordings). */
    axis?: "ago" | "elapsed";
  }
  let { points, windowSecs = 60, units, range = null, axis = "ago" }: Props = $props();

  function clock(ms: number): string {
    const t = Math.max(0, Math.round(ms / 1000));
    const h = Math.floor(t / 3600);
    const m = Math.floor((t % 3600) / 60);
    const sec = String(t % 60).padStart(2, "0");
    return h ? `${h}:${String(m).padStart(2, "0")}:${sec}` : `${m}:${sec}`;
  }

  let width = $state(800);
  const H = 250;
  const M = { top: 14, right: 16, bottom: 46, left: 52 };
  const STRIP_H = 8;
  const GAP = 2;

  const plotW = $derived(Math.max(100, width - M.left - M.right));
  const plotH = H - M.top - M.bottom;

  const endMs = $derived(range ? range[1] : points.length ? points[points.length - 1].tMs : windowSecs * 1000);
  const startMs = $derived(range ? range[0] : endMs - windowSecs * 1000);
  const visible = $derived.by(() => {
    let i = points.length;
    while (i > 0 && points[i - 1].tMs >= startMs) i--;
    let j = i;
    while (j < points.length && points[j].tMs <= endMs) j++;
    // keep one point either side so lines run to the edges
    return points.slice(Math.max(0, i - 1), Math.min(points.length, j + 1));
  });

  const yMax = $derived.by(() => {
    let m = 0;
    for (const p of visible) m = Math.max(m, p.inBps + p.outBps, p.baselineBps);
    return niceCeil(Math.max(toUnits(m, units) * 1.08, units === "bits" ? 8000 : 1000));
  });

  const x = (t: number) => M.left + ((t - startMs) / (endMs - startMs || 1)) * plotW;
  const y = (bytesPerSec: number) => M.top + plotH - (toUnits(bytesPerSec, units) / yMax) * plotH;
  const baseY = $derived(M.top + plotH);

  const paths = $derived.by(() => {
    if (visible.length < 2) return null;
    let inTop = "";
    let outTop = "";
    let outBottom = "";
    let baseline = "";
    for (const [i, p] of visible.entries()) {
      const px = x(p.tMs).toFixed(1);
      const yi = y(p.inBps);
      // 2px surface gap between the stacked fills, never inverted.
      const yo = Math.min(y(p.inBps + p.outBps), yi - GAP);
      const cmd = i === 0 ? "M" : "L";
      inTop += `${cmd}${px} ${yi.toFixed(1)}`;
      outTop += `${cmd}${px} ${yo.toFixed(1)}`;
      outBottom = `L${px} ${(yi - GAP).toFixed(1)}` + outBottom;
      baseline += `${cmd}${px} ${y(p.baselineBps).toFixed(1)}`;
    }
    const x0 = x(visible[0].tMs).toFixed(1);
    const x1 = x(visible[visible.length - 1].tMs).toFixed(1);
    return {
      inArea: `${inTop}L${x1} ${baseY}L${x0} ${baseY}Z`,
      inLine: inTop,
      outArea: `${outTop}${outBottom}Z`,
      outLine: outTop,
      baseline,
    };
  });

  /** Level strip as runs of equal level: a few rects instead of one per tick. */
  const runs = $derived.by(() => {
    const out: { level: TrafficPoint["level"]; x1: number; x2: number }[] = [];
    for (let i = 0; i < visible.length; i++) {
      const p = visible[i];
      const nx = i + 1 < visible.length ? x(visible[i + 1].tMs) : x(p.tMs) + 1;
      const last = out[out.length - 1];
      if (last && last.level === p.level) last.x2 = nx;
      else out.push({ level: p.level, x1: Math.max(M.left, x(p.tMs)), x2: nx });
    }
    return out;
  });

  const yTicks = $derived([0, 0.25, 0.5, 0.75, 1].map((f) => f * yMax));
  const STEPS = [1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 14400];
  const xTicks = $derived.by(() => {
    const span = Math.max(1, (endMs - startMs) / 1000);
    const step = STEPS.find((st) => span / st <= 6) ?? 14400;
    const out: { t: number; label: string }[] = [];
    if (axis === "ago") {
      for (let sec = Math.floor(span / step) * step; sec >= 0; sec -= step) {
        const label = sec === 0 ? "now" : sec >= 60 && sec % 60 === 0 ? `-${sec / 60}m` : `-${sec}s`;
        out.push({ t: endMs - sec * 1000, label });
      }
    } else {
      for (let t = Math.ceil(startMs / 1000 / step) * step * 1000; t <= endMs; t += step * 1000) {
        out.push({ t, label: clock(t) });
      }
    }
    return out;
  });

  // ---- hover ----
  let hoverIdx = $state<number | null>(null);
  function onMove(e: PointerEvent) {
    const rect = (e.currentTarget as SVGElement).getBoundingClientRect();
    const px = e.clientX - rect.left;
    if (px < M.left || px > M.left + plotW || visible.length === 0) {
      hoverIdx = null;
      return;
    }
    const t = startMs + ((px - M.left) / plotW) * (endMs - startMs);
    let lo = 0;
    let hi = visible.length - 1;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (visible[mid].tMs < t) lo = mid + 1;
      else hi = mid;
    }
    if (lo > 0 && t - visible[lo - 1].tMs < visible[lo].tMs - t) lo--;
    hoverIdx = lo;
  }
  const hovered = $derived(hoverIdx !== null ? visible[hoverIdx] : null);
  const tipLeft = $derived(hovered ? x(hovered.tMs) : 0);
</script>

<div class="chart" bind:clientWidth={width}>
  <svg
    {width}
    height={H}
    role="img"
    aria-label="Throughput over the last {windowSecs} seconds"
    onpointermove={onMove}
    onpointerleave={() => (hoverIdx = null)}
  >
    <!-- grid + y axis -->
    {#each yTicks as v (v)}
      {@const gy = M.top + plotH - (v / yMax) * plotH}
      <line x1={M.left} x2={M.left + plotW} y1={gy} y2={gy} class="grid" class:zero={v === 0} />
      <text x={M.left - 8} y={gy} class="axis" text-anchor="end" dominant-baseline="middle">{shortSi(v)}</text>
    {/each}
    <text x={12} y={M.top + plotH / 2} class="axis unit" transform="rotate(-90 12 {M.top + plotH / 2})" text-anchor="middle">
      {units === "bits" ? "bits/s" : "bytes/s"}
    </text>

    {#if paths}
      <path d={paths.inArea} class="area" style:fill="var(--series-in)" />
      <path d={paths.outArea} class="area" style:fill="var(--series-out)" />
      <path d={paths.inLine} class="line" style:stroke="var(--series-in)" />
      <path d={paths.outLine} class="line" style:stroke="var(--series-out)" />
      <path d={paths.baseline} class="baseline" />
    {:else}
      <text x={M.left + plotW / 2} y={M.top + plotH / 2} class="empty" text-anchor="middle">
        Waiting for samples…
      </text>
    {/if}

    <!-- x axis -->
    {#each xTicks as tk (tk.label)}
      <text x={x(tk.t)} y={baseY + 16} class="axis" text-anchor="middle">{tk.label}</text>
    {/each}

    <!-- busyness strip -->
    <text x={M.left - 8} y={H - 10} class="axis" text-anchor="end" dominant-baseline="middle">level</text>
    {#each runs as run, i (i)}
      <rect
        x={run.x1}
        y={H - 10 - STRIP_H / 2}
        width={Math.max(1, run.x2 - run.x1)}
        height={STRIP_H}
        class="strip"
        style:fill="var(--level-{run.level})"
        style:opacity={run.level === "idle" ? 0.25 : run.level === "calm" ? 0.55 : 1}
      />
    {/each}

    <!-- hover crosshair -->
    {#if hovered}
      <line x1={tipLeft} x2={tipLeft} y1={M.top} y2={baseY} class="crosshair" />
      <circle cx={tipLeft} cy={y(hovered.inBps)} r="4" class="dot" style:fill="var(--series-in)" />
      <circle cx={tipLeft} cy={y(hovered.inBps + hovered.outBps)} r="4" class="dot" style:fill="var(--series-out)" />
    {/if}
  </svg>

  {#if hovered}
    <div class="tip" style:left="{tipLeft}px" class:flip={tipLeft > width - 220}>
      <div class="tip-head">
        <span>{axis === "ago" ? `${((hovered.tMs - endMs) / 1000).toFixed(1)}s` : clock(hovered.tMs)}</span>
        <LevelBadge level={hovered.level} size="sm" />
      </div>
      <div class="row"><i style:background="var(--series-in)"></i>Inbound<b class="num">{rateText(hovered.inBps, units)}</b></div>
      <div class="row"><i style:background="var(--series-out)"></i>Outbound<b class="num">{rateText(hovered.outBps, units)}</b></div>
      <div class="row"><i class="none"></i>Total<b class="num">{rateText(hovered.inBps + hovered.outBps, units)}</b></div>
      <div class="row"><i class="dash"></i>Normal<b class="num">{rateText(hovered.baselineBps, units)}</b></div>
      <div class="row"><i class="none"></i>vs normal<b class="num">{formatRatio(hovered.ratio)}</b></div>
    </div>
  {/if}
</div>

<style>
  .chart {
    position: relative;
    width: 100%;
  }
  svg {
    display: block;
    touch-action: none;
  }
  .grid {
    stroke: var(--border);
    stroke-width: 1;
  }
  .grid.zero {
    stroke: var(--border-strong);
  }
  .axis {
    fill: var(--text-muted);
    font-size: 11px;
  }
  .axis.unit {
    font-size: 10px;
    letter-spacing: 0.04em;
  }
  .area {
    opacity: 0.28;
  }
  .line {
    fill: none;
    stroke-width: 2;
    stroke-linejoin: round;
  }
  .baseline {
    fill: none;
    stroke: var(--text-secondary);
    stroke-width: 1.5;
    stroke-dasharray: 5 4;
  }
  .empty {
    fill: var(--text-muted);
    font-size: 13px;
  }
  .strip {
    shape-rendering: crispEdges;
  }
  .crosshair {
    stroke: var(--text-secondary);
    stroke-width: 1;
    stroke-dasharray: 3 3;
  }
  .dot {
    stroke: var(--surface-1);
    stroke-width: 2;
  }
  .tip {
    position: absolute;
    top: 10px;
    transform: translateX(12px);
    min-width: 200px;
    padding: 10px 12px;
    background: var(--surface-2);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius);
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.45);
    pointer-events: none;
    font-size: 12px;
    color: var(--text-secondary);
  }
  .tip.flip {
    transform: translateX(calc(-100% - 12px));
  }
  .tip-head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 6px;
    color: var(--text-muted);
  }
  .row {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 2px 0;
  }
  .row b {
    margin-left: auto;
    color: var(--text-primary);
    font-weight: 600;
  }
  .row i {
    width: 10px;
    height: 10px;
    border-radius: 3px;
  }
  .row i.none {
    background: transparent;
  }
  .row i.dash {
    height: 0;
    border-top: 2px dashed var(--text-secondary);
    border-radius: 0;
  }
</style>

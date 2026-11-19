<script lang="ts">
  /**
   * Speedometer-style dial for total throughput.
   *
   * - Log scale over 7 decades (bits: 1 k → 10 G b/s, bytes: 100 → 1 G B/s).
   * - The value arc and needle take the busyness level colour.
   * - An outer ring marks where "busy" and "spike" start *relative to the
   *   learned baseline*, so you can watch the needle approach the red zone.
   * - A notch marks the baseline ("normal") itself.
   */
  import { Spring } from "svelte/motion";
  import type { GaugeConfig, Level, Units } from "$lib/api/types";
  import { formatRate, formatRatio, shortSi, toUnits } from "$lib/utils/format";
  import LevelBadge from "../../components/LevelBadge.svelte";

  interface Props {
    /** Smoothed total throughput, bytes/s. */
    valueBps: number;
    baselineBps: number;
    ratio: number;
    level: Level;
    units: Units;
    gauge: GaugeConfig | null;
    active: boolean;
  }
  let { valueBps, baselineBps, ratio, level, units, gauge, active }: Props = $props();

  const CX = 160;
  const CY = 150;
  const R = 116;
  const START = 150; // degrees, screen coords (y down)
  const SWEEP = 240;

  const lo = $derived(units === "bits" ? 3 : 2);
  const hi = $derived(lo + 7);

  function toT(bytesPerSec: number): number {
    const v = toUnits(bytesPerSec, units);
    if (!(v > 0)) return 0;
    return Math.min(1, Math.max(0, (Math.log10(v) - lo) / (hi - lo)));
  }

  function polar(t: number, r: number): [number, number] {
    const a = ((START + SWEEP * t) * Math.PI) / 180;
    return [CX + r * Math.cos(a), CY + r * Math.sin(a)];
  }

  function arc(t0: number, t1: number, r: number): string {
    if (t1 - t0 < 1e-4) return "";
    const [x0, y0] = polar(t0, r);
    const [x1, y1] = polar(t1, r);
    const large = (t1 - t0) * SWEEP > 180 ? 1 : 0;
    return `M${x0.toFixed(2)} ${y0.toFixed(2)} A${r} ${r} 0 ${large} 1 ${x1.toFixed(2)} ${y1.toFixed(2)}`;
  }

  const needle = new Spring(0, { stiffness: 0.12, damping: 0.55 });
  $effect(() => {
    needle.target = active ? toT(valueBps) : 0;
  });

  const decades = $derived(Array.from({ length: hi - lo + 1 }, (_, i) => lo + i));
  const minor = $derived(
    decades.slice(0, -1).flatMap((d) => [2, 3, 4, 5, 6, 7, 8, 9].map((m) => (Math.log10(m * 10 ** d) - lo) / (hi - lo))),
  );

  const effectiveBase = $derived(Math.max(baselineBps, gauge?.baselineFloorBps ?? 0));
  const tBase = $derived(toT(effectiveBase));
  const tBusy = $derived(toT(effectiveBase * (gauge?.busyRatio ?? 2)));
  const tSpike = $derived(toT(effectiveBase * (gauge?.spikeRatio ?? 5)));
  const showZones = $derived(active && gauge !== null && baselineBps > 0);

  const reading = $derived(formatRate(active ? valueBps : 0, units));
  const needleAngle = $derived(START + SWEEP * needle.current);
  const levelColor = $derived(`var(--level-${level})`);
</script>

<div class="gauge" class:inactive={!active}>
  <svg viewBox="0 0 320 236" role="img" aria-label="Throughput {reading.value} {reading.unit}, {level}">
    <defs>
      <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
        <feGaussianBlur stdDeviation="4" result="b" />
        <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
      </filter>
    </defs>

    <!-- track -->
    <path d={arc(0, 1, R)} class="track" />

    <!-- busy / spike zones relative to the baseline -->
    {#if showZones}
      <path d={arc(tBusy, tSpike, R + 11)} class="zone" style:stroke="var(--level-busy)" />
      <path d={arc(tSpike, 1, R + 11)} class="zone" style:stroke="var(--level-spike)" />
      {@const [bx, by] = polar(tBase, R + 11)}
      {@const [bx2, by2] = polar(tBase, R + 19)}
      <line x1={bx} y1={by} x2={bx2} y2={by2} class="base-notch" />
    {/if}

    <!-- value -->
    <path d={arc(0, needle.current, R)} class="value" style:stroke={levelColor} filter="url(#glow)" />

    <!-- ticks -->
    {#each minor as t (t)}
      {@const [x0, y0] = polar(t, R - 12)}
      {@const [x1, y1] = polar(t, R - 8)}
      <line x1={x0} y1={y0} x2={x1} y2={y1} class="tick minor" />
    {/each}
    {#each decades as d, i (d)}
      {@const t = i / (hi - lo)}
      {@const [x0, y0] = polar(t, R - 14)}
      {@const [x1, y1] = polar(t, R - 6)}
      {@const [lx, ly] = polar(t, R - 28)}
      <line x1={x0} y1={y0} x2={x1} y2={y1} class="tick major" />
      <text x={lx} y={ly} class="tick-label" text-anchor="middle" dominant-baseline="middle">{shortSi(10 ** d)}</text>
    {/each}

    <!-- needle -->
    <g transform="rotate({needleAngle} {CX} {CY})" class="needle" style:--c={levelColor}>
      <path d="M{CX - 14} {CY - 3} L{CX + R - 20} {CY - 1} L{CX + R - 20} {CY + 1} L{CX - 14} {CY + 3} Z" />
    </g>
    <circle cx={CX} cy={CY} r="9" class="hub" />
    <circle cx={CX} cy={CY} r="3.5" class="hub-dot" style:fill={levelColor} />

    <!-- readout -->
    <text x={CX} y={CY + 52} class="value-text num" text-anchor="middle">{reading.value}</text>
    <text x={CX} y={CY + 72} class="unit-text" text-anchor="middle">{reading.unit}</text>
  </svg>

  <div class="footer">
    {#if active}
      <LevelBadge {level} />
      <span class="ratio num" title="Current rate divided by the learned normal level">
        {formatRatio(ratio)} <span class="muted">normal</span>
      </span>
    {:else}
      <span class="muted">Not monitoring</span>
    {/if}
  </div>
  {#if showZones}
    <div class="legend">
      <span><i class="notch"></i>normal</span>
      <span><i style:background="var(--level-busy)"></i>busy zone</span>
      <span><i style:background="var(--level-spike)"></i>spike zone</span>
    </div>
  {/if}
</div>

<style>
  .gauge {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 6px;
  }
  svg {
    width: 100%;
    max-width: 380px;
    overflow: visible;
  }
  .track {
    fill: none;
    stroke: var(--surface-3);
    stroke-width: 12;
    stroke-linecap: round;
  }
  .value {
    fill: none;
    stroke-width: 12;
    stroke-linecap: round;
    transition: stroke 300ms;
  }
  .zone {
    fill: none;
    stroke-width: 4;
    stroke-linecap: round;
    opacity: 0.85;
  }
  .base-notch {
    stroke: var(--text-primary);
    stroke-width: 2.5;
    stroke-linecap: round;
  }
  .tick.major {
    stroke: var(--text-secondary);
    stroke-width: 1.5;
  }
  .tick.minor {
    stroke: var(--text-muted);
    stroke-width: 1;
    opacity: 0.6;
  }
  .tick-label {
    fill: var(--text-muted);
    font-size: 10px;
  }
  .needle path {
    fill: var(--c);
    transition: fill 300ms;
  }
  .hub {
    fill: var(--surface-3);
    stroke: var(--border-strong);
  }
  .value-text {
    fill: var(--text-primary);
    font-size: 38px;
    font-weight: 600;
    letter-spacing: -0.02em;
  }
  .unit-text {
    fill: var(--text-secondary);
    font-size: 13px;
  }
  .inactive .value-text {
    fill: var(--text-muted);
  }
  .footer {
    display: flex;
    align-items: center;
    gap: 12px;
    min-height: 28px;
  }
  .ratio {
    font-size: 15px;
    font-weight: 600;
  }
  .muted {
    font-weight: 400;
  }
  .legend {
    display: flex;
    gap: 14px;
    font-size: 11px;
    color: var(--text-muted);
  }
  .legend i {
    display: inline-block;
    width: 12px;
    height: 4px;
    border-radius: 2px;
    margin-right: 5px;
    vertical-align: middle;
  }
  .legend i.notch {
    width: 2.5px;
    height: 10px;
    background: var(--text-primary);
  }
</style>

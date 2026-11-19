<script lang="ts">
  /**
   * Round-trip time over time, in milliseconds: the passive TCP RTT as a
   * line and, when a ping runs, the ping replies as dots with lost probes
   * marked on the axis. Shares the time window of the traffic chart.
   */
  interface Pt {
    tMs: number;
    v: number | null;
  }
  interface Props {
    /** TCP RTT per tick (null = no sample that tick). */
    rtt: Pt[];
    /** Ping replies (null = lost). */
    ping?: Pt[];
    /** Live: last N seconds ending at the newest point. */
    windowSecs?: number;
    /** Replay: exactly this range (ms). */
    range?: [number, number] | null;
    axis?: "ago" | "elapsed";
    height?: number;
  }
  let { rtt, ping = [], windowSecs = 60, range = null, axis = "ago", height = 130 }: Props = $props();

  let width = $state(600);
  const M = { top: 10, right: 16, bottom: 22, left: 52 };
  const plotW = $derived(Math.max(100, width - M.left - M.right));
  const plotH = $derived(height - M.top - M.bottom);

  const last = (a: Pt[]) => (a.length ? a[a.length - 1].tMs : 0);
  const endMs = $derived(range ? range[1] : rtt.length || ping.length ? Math.max(last(rtt), last(ping)) : windowSecs * 1000);
  const startMs = $derived(range ? range[0] : endMs - windowSecs * 1000);
  const inRange = (p: Pt) => p.tMs >= startMs && p.tMs <= endMs;
  const vis = $derived(rtt.filter(inRange));
  const visPing = $derived(ping.filter(inRange));

  const NICE = [5, 10, 20, 25, 50, 100, 150, 200, 250, 300, 400, 500, 750, 1000, 1500, 2000, 3000, 5000, 10000];
  const yMax = $derived.by(() => {
    let m = 0;
    for (const p of vis) if (p.v !== null) m = Math.max(m, p.v);
    for (const p of visPing) if (p.v !== null) m = Math.max(m, p.v);
    return NICE.find((n) => n >= m * 1.1) ?? Math.ceil(m * 1.1);
  });
  const x = (t: number) => M.left + ((t - startMs) / (endMs - startMs || 1)) * plotW;
  const y = (v: number) => M.top + plotH - (v / yMax) * plotH;

  /** Line through the samples; gaps longer than 3 s break it. */
  const path = $derived.by(() => {
    let d = "";
    let prev: number | null = null;
    for (const p of vis) {
      if (p.v === null) continue;
      const cmd = prev === null || p.tMs - prev > 3000 ? "M" : "L";
      d += `${cmd}${x(p.tMs).toFixed(1)} ${y(p.v).toFixed(1)}`;
      prev = p.tMs;
    }
    return d;
  });

  const yTicks = $derived([0, 0.5, 1].map((f) => f * yMax));
  function clock(ms: number): string {
    const t = Math.max(0, Math.round(ms / 1000));
    const m = Math.floor(t / 60);
    return `${m}:${String(t % 60).padStart(2, "0")}`;
  }
  const xTicks = $derived.by(() => {
    const span = Math.max(1, (endMs - startMs) / 1000);
    const step = [5, 10, 15, 30, 60, 120, 300, 600, 1800, 3600].find((st) => span / st <= 6) ?? 3600;
    const out: { t: number; label: string }[] = [];
    if (axis === "ago") {
      for (let sec = Math.floor(span / step) * step; sec >= 0; sec -= step) {
        out.push({ t: endMs - sec * 1000, label: sec === 0 ? "now" : sec >= 60 && sec % 60 === 0 ? `-${sec / 60}m` : `-${sec}s` });
      }
    } else {
      for (let t = Math.ceil(startMs / 1000 / step) * step * 1000; t <= endMs; t += step * 1000) out.push({ t, label: clock(t) });
    }
    return out;
  });

  let hoverT = $state<number | null>(null);
  function onMove(e: PointerEvent) {
    const rect = (e.currentTarget as SVGElement).getBoundingClientRect();
    const px = e.clientX - rect.left;
    hoverT = px < M.left || px > M.left + plotW ? null : startMs + ((px - M.left) / plotW) * (endMs - startMs);
  }
  function nearest(a: Pt[], t: number): Pt | null {
    let best: Pt | null = null;
    for (const p of a) if (!best || Math.abs(p.tMs - t) < Math.abs(best.tMs - t)) best = p;
    return best && Math.abs(best.tMs - t) < 2000 ? best : null;
  }
  const hRtt = $derived(hoverT === null ? null : nearest(vis.filter((p) => p.v !== null), hoverT));
  const hPing = $derived(hoverT === null ? null : nearest(visPing, hoverT));
  const empty = $derived(!vis.some((p) => p.v !== null) && visPing.length === 0);
</script>

<div class="qchart" bind:clientWidth={width}>
  <svg {width} {height} role="img" aria-label="Round-trip time" onpointermove={onMove} onpointerleave={() => (hoverT = null)}>
    {#each yTicks as v (v)}
      <line x1={M.left} x2={M.left + plotW} y1={y(v)} y2={y(v)} class="grid" />
      <text x={M.left - 8} y={y(v)} class="axis" text-anchor="end" dominant-baseline="middle">{v} ms</text>
    {/each}
    {#each xTicks as tk (tk.label)}
      <text x={x(tk.t)} y={height - 6} class="axis" text-anchor="middle">{tk.label}</text>
    {/each}
    {#if empty}
      <text x={M.left + plotW / 2} y={M.top + plotH / 2} class="empty" text-anchor="middle">No round-trip samples yet</text>
    {/if}
    <path d={path} class="rtt" />
    {#each visPing as p (p.tMs)}
      {#if p.v === null}
        <line x1={x(p.tMs)} x2={x(p.tMs)} y1={M.top + plotH - 8} y2={M.top + plotH} class="lost" />
      {:else}
        <circle cx={x(p.tMs)} cy={y(p.v)} r="2.2" class="ping" />
      {/if}
    {/each}
    {#if hoverT !== null && (hRtt || hPing)}
      <line x1={x(hoverT)} x2={x(hoverT)} y1={M.top} y2={M.top + plotH} class="cross" />
    {/if}
  </svg>
  {#if hoverT !== null && (hRtt || hPing)}
    <div class="tip" style:left="{x(hoverT)}px" class:flip={x(hoverT) > width - 160}>
      {#if hRtt?.v != null}<div><i class="sw rtt"></i>TCP {hRtt.v.toFixed(1)} ms</div>{/if}
      {#if hPing}<div><i class="sw ping"></i>Ping {hPing.v === null ? "lost" : `${hPing.v} ms`}</div>{/if}
    </div>
  {/if}
</div>

<style>
  .qchart {
    position: relative;
    width: 100%;
  }
  svg {
    display: block;
  }
  .grid {
    stroke: var(--border);
    stroke-width: 1;
  }
  .axis {
    fill: var(--text-muted);
    font-size: 11px;
    font-variant-numeric: tabular-nums;
  }
  .empty {
    fill: var(--text-muted);
    font-size: 12px;
  }
  .rtt {
    fill: none;
    stroke: var(--series-rtt);
    stroke-width: 1.8;
    stroke-linejoin: round;
  }
  .ping {
    fill: var(--accent-strong);
  }
  .lost {
    stroke: var(--level-spike);
    stroke-width: 2;
  }
  .cross {
    stroke: var(--text-muted);
    stroke-dasharray: 3 3;
  }
  .tip {
    position: absolute;
    top: 4px;
    transform: translateX(10px);
    padding: 5px 9px;
    border-radius: 7px;
    background: var(--surface-3);
    border: 1px solid var(--border-strong);
    font-size: 12px;
    white-space: nowrap;
    pointer-events: none;
  }
  .tip.flip {
    transform: translateX(calc(-100% - 10px));
  }
  .sw {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    margin-right: 6px;
  }
  .sw.rtt {
    background: var(--series-rtt);
  }
  .sw.ping {
    background: var(--accent-strong);
  }
</style>

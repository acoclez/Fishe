<script lang="ts">
  /** Replay of one recording: summary, full-length chart, notable moments, endpoints. */
  import { api, errorMessage } from "$lib/api";
  import { formatBytes, formatCount, formatDuration, formatRatio, rateText } from "$lib/utils/format";
  import type { Episode, RecordingDetail, SeriesPoint, Units } from "$lib/api/types";
  import TrafficChart from "../../components/TrafficChart.svelte";
  import LevelBadge from "../../components/LevelBadge.svelte";
  import StatTile from "../../components/StatTile.svelte";
  import ArchiveEndpoints from "./ArchiveEndpoints.svelte";
  import QualityChart from "../../components/QualityChart.svelte";
  import { GRADE_COLOR, jitterGrade, lossGrade, msText, pctText, rttGrade } from "$lib/utils/quality";

  let { id, units, onback }: { id: number; units: Units; onback: () => void } = $props();

  // `raw`: up to 3000 samples plus endpoints; replaced whole, never mutated.
  let detail = $state.raw<RecordingDetail | null>(null);
  let error = $state<string | null>(null);
  let focus = $state<string | null>(null);
  let focusSeries = $state<SeriesPoint[] | null>(null);
  let zoom = $state<[number, number] | null>(null);

  $effect(() => {
    const rid = id;
    detail = null;
    focus = null;
    zoom = null;
    api.getRecording(rid).then(
      (d) => (detail = d),
      (err) => (error = errorMessage(err)),
    );
  });

  $effect(() => {
    const ip = focus;
    focusSeries = null;
    if (!ip) return;
    api.getEndpointSeries(id, ip).then(
      (s) => focus === ip && (focusSeries = fillGaps(s)),
      (err) => (error = errorMessage(err)),
    );
  });

  /** Endpoint series only has active ticks: insert zeros so idle gaps read as idle. */
  function fillGaps(s: SeriesPoint[]): SeriesPoint[] {
    const tick = detail?.session?.tickMs ?? 250;
    const out: SeriesPoint[] = [];
    for (const p of s) {
      const prev = out[out.length - 1];
      if (prev && p.tMs - prev.tMs > tick * 1.5) {
        out.push({ ...prev, tMs: prev.tMs + tick, inBps: 0, outBps: 0, smoothedBps: 0, ratio: 0, level: "idle" });
        out.push({ ...prev, tMs: p.tMs - tick, inBps: 0, outBps: 0, smoothedBps: 0, ratio: 0, level: "idle" });
      }
      out.push(p);
    }
    return out;
  }

  const duration = $derived(detail?.summary.durationMs ?? 0);
  const fullRange = $derived<[number, number]>([0, Math.max(duration, (detail?.samples.at(-1)?.tMs ?? 0))]);
  const points = $derived(focus ? (focusSeries ?? []) : (detail?.samples ?? []));
  const focusRec = $derived(detail?.endpoints.find((e) => e.ip === focus) ?? null);
  const dateFmt = new Intl.DateTimeFormat(undefined, { dateStyle: "full", timeStyle: "medium" });

  function zoomTo(e: Episode) {
    const pad = Math.max(10_000, (e.endMs - e.startMs) * 0.5);
    zoom = [Math.max(0, e.startMs - pad), Math.min(fullRange[1], e.endMs + pad)];
  }
  function clock(ms: number) {
    return formatDuration(ms);
  }
</script>

<div class="view">
  <div class="bar">
    <button type="button" class="back" onclick={onback}>← Archive</button>
    {#if detail}
      <div class="title">
        <h2>{detail.summary.name}</h2>
        <span class="muted">
          {#if detail.summary.mode === "all"}All traffic{:else}{detail.summary.mode === "process" ? "Process" : "Host"} <span class="mono">{detail.summary.label}</span>{/if}
          · {dateFmt.format(new Date(detail.summary.startedAt))}
          {#if detail.summary.status === "interrupted"}<span class="tag">interrupted</span>{/if}
        </span>
      </div>
    {/if}
  </div>

  {#if error}<p class="msg error" role="alert">{error}</p>{/if}

  {#if !detail}
    {#if !error}<p class="muted">Loading recording…</p>{/if}
  {:else}
    {@const s = detail.summary}
    <div class="tiles">
      <StatTile label="Duration" value={formatDuration(s.durationMs)} sub={`${s.sampleCount.toLocaleString()} samples`} />
      <StatTile label="Transferred" value={formatBytes(s.totals.bytesIn + s.totals.bytesOut)} sub={`↓ ${formatBytes(s.totals.bytesIn)} · ↑ ${formatBytes(s.totals.bytesOut)}`} />
      <StatTile label="Packets" value={formatCount(s.totals.packetsIn + s.totals.packetsOut)} sub={`↓ ${formatCount(s.totals.packetsIn)} · ↑ ${formatCount(s.totals.packetsOut)}`} />
      <StatTile label="Peak" value={rateText(s.peakBps, units)} sub="highest tick" />
      <div class="tile-like">
        <span class="k">Busiest</span>
        <LevelBadge level={s.maxLevel} />
        <span class="sub">{detail.episodes.length} busy/spike {detail.episodes.length === 1 ? "moment" : "moments"}</span>
      </div>
      <StatTile label="Endpoints" value={String(s.endpointCount)} sub={s.pcapPath ? `${s.pcapPackets.toLocaleString()} packets saved` : "no packets file"} />
    </div>

    <section class="card chart-card">
      <div class="chart-head">
        <h2 class="card-title">
          {#if focusRec}{focusRec.name ?? focusRec.ip}{:else}Whole recording{/if}{#if zoom} · {clock(zoom[0])}–{clock(zoom[1])}{/if}
        </h2>
        <div class="chart-tools">
          {#if focus}<button type="button" onclick={() => (focus = null)}>Show whole recording</button>{/if}
          {#if zoom}<button type="button" onclick={() => (zoom = null)}>Zoom out</button>{/if}
          {#if detail.downsampled && !zoom}<span class="muted small" title="Long recordings are averaged for display; exports keep every sample">averaged for display</span>{/if}
        </div>
      </div>
      {#if focus && !focusSeries}
        <p class="muted">Loading endpoint history…</p>
      {:else}
        <TrafficChart {points} {units} range={zoom ?? fullRange} axis="elapsed" />
      {/if}
    </section>

    {@const rttPts = detail.samples.filter((p) => p.rttMs != null).map((p) => ({ tMs: p.tMs, v: p.rttMs ?? null }))}
    {@const q = focusRec ? focusRec.quality : (detail.extra?.quality ?? null)}
    {#if rttPts.length || q}
      {@const c = (v: number | null, g: (n: number) => "good" | "fair" | "poor") => (v === null ? "var(--text-muted)" : GRADE_COLOR[g(v)])}
      <section class="card qrec">
        <div class="chart-head">
          <h2 class="card-title">Connection quality · {focusRec ? (focusRec.name ?? focusRec.ip) : "whole recording"}</h2>
          <div class="qstats">
            <span>round trip <b class="num" style:color={c(q?.srttMs ?? null, rttGrade)}>{msText(q?.srttMs)}</b></span>
            <span>min <b class="num">{msText(q?.minRttMs)}</b></span>
            <span>jitter <b class="num" style:color={c(q?.jitterMs ?? null, jitterGrade)}>{msText(q?.jitterMs)}</b></span>
            <span>retransmitted ↑ <b class="num" style:color={c(q?.retransOutPct ?? null, lossGrade)}>{pctText(q?.retransOutPct)}</b></span>
            <span>↓ <b class="num" style:color={c(q?.retransInPct ?? null, lossGrade)}>{pctText(q?.retransInPct)}</b></span>
          </div>
        </div>
        {#if rttPts.length}
          <QualityChart rtt={rttPts} range={zoom ?? fullRange} axis="elapsed" height={120} />
          {#if focusRec}<p class="muted small">The chart shows every connection of the recording; the figures above are {focusRec.name ?? focusRec.ip}'s.</p>{/if}
        {:else}
          <p class="muted small">No round-trip samples were stored for this recording (recorded before Fishe 0.8, or no TCP traffic).</p>
        {/if}
      </section>
    {/if}

    <div class="lower">
      <section class="card moments">
        <h2 class="card-title">Notable moments</h2>
        {#if detail.episodes.length === 0}
          <p class="muted">Traffic stayed calm for the whole recording.</p>
        {:else}
          <ul>
            {#each detail.episodes as e (e.startMs)}
              <li>
                <button type="button" onclick={() => zoomTo(e)} title="Zoom the chart to this moment">
                  <LevelBadge level={e.maxLevel} size="sm" />
                  <span class="num when">{clock(e.startMs)}–{clock(e.endMs)}</span>
                  <span class="num">{rateText(e.peakBps, units)}</span>
                  <span class="muted num">{formatRatio(e.peakRatio)} normal</span>
                </button>
              </li>
            {/each}
          </ul>
        {/if}
      </section>

      {#if detail.endpoints.length}
        <ArchiveEndpoints endpoints={detail.endpoints} {units} {focus} onfocus={(ip) => (focus = focus === ip ? null : ip)} />
      {/if}
    </div>

    {#if detail.extra?.programs?.length}
      {@const progs = detail.extra.programs}
      {@const sum = progs.reduce((n, p) => n + p.bytesIn + p.bytesOut, 0)}
      <section class="card programs">
        <h2 class="card-title">Programs</h2>
        <table>
          <thead>
            <tr><th>Program</th><th class="r">Share</th><th class="r">Received</th><th class="r">Sent</th><th class="r">Peak</th><th class="r">Endpoints</th></tr>
          </thead>
          <tbody>
            {#each progs as p (p.key)}
              {@const b = p.bytesIn + p.bytesOut}
              <tr>
                <td class:none={p.key === ""}>{p.name}</td>
                <td class="r"><div class="share" title="{sum ? ((b / sum) * 100).toFixed(1) : 0}%"><i style:width="{sum ? Math.max(2, (b / sum) * 100) : 0}%"></i></div></td>
                <td class="r num">{formatBytes(p.bytesIn)}</td>
                <td class="r num">{formatBytes(p.bytesOut)}</td>
                <td class="r num">{rateText(p.peakBps, units)}</td>
                <td class="r num">{p.endpoints}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </section>
    {/if}
  {/if}
</div>

<style>
  .qrec {
    padding: 16px 18px 8px;
  }
  .qstats {
    display: flex;
    flex-wrap: wrap;
    gap: 4px 16px;
    font-size: 12.5px;
    color: var(--text-secondary);
  }
  .qstats b {
    color: var(--text-primary);
  }
  .programs {
    padding: 16px 18px 10px;
  }
  .programs table {
    width: 100%;
    margin-top: 8px;
    border-collapse: collapse;
    font-size: 13px;
  }
  .programs th {
    text-align: left;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    color: var(--text-muted);
    padding: 6px 10px;
    border-bottom: 1px solid var(--border);
  }
  .programs td {
    padding: 6px 10px;
    border-bottom: 1px solid var(--border);
  }
  .programs .r {
    text-align: right;
  }
  .programs td.none {
    font-style: italic;
    color: var(--text-secondary);
  }
  .share {
    width: 80px;
    height: 6px;
    margin-left: auto;
    border-radius: 3px;
    background: var(--surface-3);
    overflow: hidden;
  }
  .share i {
    display: block;
    height: 100%;
    background: var(--accent);
  }
  .view {
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .bar {
    display: flex;
    align-items: center;
    gap: 16px;
  }
  .back {
    height: 32px;
    padding: 0 12px;
    border-radius: 8px;
    border: 1px solid var(--border-strong);
    background: var(--surface-2);
    cursor: pointer;
    flex: none;
  }
  .back:hover {
    border-color: var(--accent);
  }
  .title h2 {
    margin: 0;
    font-size: 17px;
  }
  .small {
    font-size: 11px;
  }
  .tag {
    margin-left: 6px;
    padding: 0 6px;
    border-radius: 4px;
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    border: 1px solid var(--level-busy);
    color: var(--level-busy);
  }
  .msg.error {
    padding: 8px 12px;
    border-radius: 8px;
    background: var(--danger-wash);
  }
  .tiles {
    display: grid;
    grid-template-columns: repeat(6, minmax(0, 1fr));
    gap: 14px;
  }
  .tile-like {
    display: flex;
    flex-direction: column;
    justify-content: center;
    gap: 6px;
    padding: 14px 16px;
    background: var(--surface-1);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    align-items: flex-start;
  }
  .tile-like .k {
    font-size: 12px;
    color: var(--text-secondary);
  }
  .tile-like .sub {
    font-size: 12px;
    color: var(--text-muted);
  }
  .chart-card {
    padding: 16px 18px 8px;
  }
  .chart-head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    margin-bottom: 6px;
  }
  .chart-tools {
    display: flex;
    gap: 8px;
    align-items: center;
  }
  .chart-tools button {
    height: 28px;
    padding: 0 10px;
    border-radius: 6px;
    border: 1px solid var(--accent);
    background: none;
    color: var(--accent-strong);
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
  }
  .lower {
    display: grid;
    grid-template-columns: minmax(280px, 1fr) 2.4fr;
    gap: 14px;
    align-items: start;
  }
  .moments {
    padding: 16px 18px;
  }
  .moments ul {
    list-style: none;
    margin: 10px 0 0;
    padding: 0;
    max-height: 420px;
    overflow-y: auto;
  }
  .moments button {
    display: flex;
    align-items: center;
    gap: 10px;
    width: 100%;
    padding: 7px 6px;
    border: 0;
    border-top: 1px solid var(--border);
    background: none;
    text-align: left;
    font-size: 13px;
    cursor: pointer;
  }
  .moments button:hover {
    background: var(--surface-2);
  }
  .when {
    font-weight: 600;
  }
  @media (max-width: 1180px) {
    .tiles {
      grid-template-columns: repeat(3, minmax(0, 1fr));
    }
  }
  /* The endpoints table needs ~1100 px; below that, moments go above it. */
  @media (max-width: 1600px) {
    .lower {
      grid-template-columns: minmax(0, 1fr);
    }
  }
</style>

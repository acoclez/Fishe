<script lang="ts">
  /** Live: the target bar, the gauge and tiles, the chart, quality, the busiest few, protocols and ports. */
  import FocusBar from "$lib/components/FocusBar.svelte";
  import Gauge from "$lib/pages/live/Gauge.svelte";
  import LevelBadge from "$lib/components/LevelBadge.svelte";
  import NpcapMissing from "$lib/pages/live/NpcapMissing.svelte";
  import ProcessInfo from "$lib/pages/live/ProcessInfo.svelte";
  import ProtocolBreakdown from "$lib/pages/live/ProtocolBreakdown.svelte";
  import QualityCard from "$lib/pages/live/QualityCard.svelte";
  import StatTile from "$lib/components/StatTile.svelte";
  import TargetForm from "$lib/pages/live/TargetForm.svelte";
  import TopList from "$lib/pages/live/TopList.svelte";
  import TopPorts from "$lib/pages/live/TopPorts.svelte";
  import TrafficChart from "$lib/components/TrafficChart.svelte";
  import { formatBytes, formatCount } from "$lib/utils/format";
  import { monitor } from "$lib/stores/monitor.svelte";
  import { nav } from "$lib/stores/nav.svelte";
  import { session } from "$lib/stores/session.svelte";
  import { settings } from "$lib/stores/settings.svelte";

  const s = $derived(monitor.latest);
  const view = $derived(session.view);
</script>

{#if session.npcap && !session.npcap.available}<NpcapMissing />{/if}

<TargetForm
  interfaces={session.interfaces}
  phase={monitor.phase}
  disabled={!session.npcap?.available}
  processModeAvailable={session.caps?.processMode ?? false}
  onstart={(target, iface) => session.start(target, iface)}
  onstop={() => monitor.stop()}
  onsettings={() => nav.go("settings")}
  settingsOpen={false}
  recording={monitor.recording !== null}
  recordingTick={s?.recording ?? null}
  recordingBusy={monitor.recordingBusy}
  onrecord={() => session.toggleRecording()}
  bind:selection={session.formSelection}
/>

{#if session.info && session.processMode && monitor.active}
  <ProcessInfo session={session.info} tick={s?.process ?? null} unattributed={s?.unattributed ?? 0} programCount={s?.programs?.total ?? 0} />
{/if}

{#if session.processMode && monitor.active}<FocusBar />{/if}

<div class="top">
  <section class="card gauge-card">
    <h2 class="card-title">Throughput{#if session.focus}<span class="scope-tag">· {session.focusName}</span>{/if}</h2>
    <Gauge
      valueBps={view.smoothed}
      baselineBps={view.baseline}
      ratio={view.ratio}
      level={view.level}
      units={session.units}
      gauge={session.gauge}
      active={session.active}
    />
  </section>

  <div class="tiles">
    <StatTile label="Inbound" swatch="var(--series-in)" value={session.inRate.value} unit={session.inRate.unit} sub={session.inSub} />
    <StatTile label="Outbound" swatch="var(--series-out)" value={session.outRate.value} unit={session.outRate.unit} sub={session.outSub} />
    <StatTile label="Peak" value={session.peak.value} unit={session.peak.unit} sub="highest tick this session" />
    <StatTile
      label="Transferred"
      value={formatBytes(session.viewBytes)}
      sub={`↓ ${formatBytes(view.totals.bytesIn)} · ↑ ${formatBytes(view.totals.bytesOut)}`}
    />
    <StatTile
      label="Packets"
      value={formatCount(view.totals.packetsIn + view.totals.packetsOut)}
      sub={`↓ ${formatCount(view.totals.packetsIn)} · ↑ ${formatCount(view.totals.packetsOut)}`}
    />
    <StatTile
      label="Dropped"
      value={formatCount(session.drops)}
      sub={session.drops ? "capture buffer overflowed" : "no packets lost"}
      warn={session.drops > 0}
    />
  </div>
</div>

<section class="card chart-card">
  <div class="chart-head">
    <h2 class="card-title">
      {session.focus ? `${session.focusName}, last` : "Traffic, last"}
      {settings.windowSecs < 60 ? `${settings.windowSecs}s` : `${settings.windowSecs / 60} min`}
    </h2>
    <div class="legend">
      <span><i style:background="var(--series-in)"></i>Inbound</span>
      <span><i style:background="var(--series-out)"></i>Outbound</span>
      <span><i class="dash"></i>Normal</span>
      {#if s}<LevelBadge level={view.level} size="sm" />{/if}
    </div>
  </div>
  <TrafficChart points={session.chartPoints} windowSecs={settings.windowSecs} units={session.units} />
</section>

{#if session.info && monitor.active}
  <QualityCard {...session.quality} windowSecs={settings.windowSecs} />
{/if}

{#if session.processMode && monitor.active}
  <TopList
    title={session.allMode ? "Busiest programs" : "Busiest endpoints"}
    items={session.topItems}
    total={session.allMode ? (s?.programs?.total ?? 0) : Math.max(s?.endpoints?.total ?? 0, monitor.endpointRows.length)}
    nowMs={s?.tMs ?? 0}
    units={session.units}
    focused={session.allMode ? (session.focusProg?.key ?? null) : (session.focusEp?.ip ?? null)}
    onpick={(k) =>
      session.allMode
        ? monitor.setProgramFocus(session.focusProg?.key === k ? null : k)
        : monitor.setFocus(session.focusEp?.ip === k ? null : k)}
    onall={() => nav.go("connections")}
  />
{/if}

{#if session.processMode}
  <p class="note" class:hidden={!session.focus}>Protocols and top services below cover the {session.allMode ? "whole machine" : "whole process"}.</p>
{/if}
<div class="bottom">
  <ProtocolBreakdown transports={s?.transports ?? null} />
  <TopPorts ports={s?.topPorts ?? []} totalBytes={session.totalBytes} />
</div>

<style>
  .top {
    display: grid;
    grid-template-columns: minmax(320px, 400px) 1fr;
    gap: 14px;
  }
  .gauge-card {
    padding: 16px 18px 14px;
    display: flex;
    flex-direction: column;
    gap: 4px;
    background: radial-gradient(120% 90% at 50% 0%, #15232c 0%, var(--surface-1) 60%);
  }
  .tiles {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    grid-auto-rows: 1fr;
    gap: 14px;
  }
  .tiles :global(.tile) {
    display: flex;
    flex-direction: column;
    justify-content: center;
  }
  @media (max-width: 1180px) {
    .tiles {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
  }
  .chart-card {
    padding: 16px 18px 8px;
  }
  .chart-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 6px;
    flex-wrap: wrap;
  }
  .legend {
    display: flex;
    align-items: center;
    gap: 14px;
    font-size: 12px;
    color: var(--text-secondary);
  }
  .legend i {
    display: inline-block;
    width: 10px;
    height: 10px;
    border-radius: 3px;
    margin-right: 6px;
    vertical-align: -1px;
  }
  .legend i.dash {
    height: 0;
    width: 14px;
    border-top: 2px dashed var(--text-secondary);
    border-radius: 0;
    vertical-align: 3px;
  }
  .scope-tag {
    margin-left: 6px;
    color: var(--accent-strong);
    text-transform: none;
    letter-spacing: 0;
  }
  .note {
    margin: -6px 4px -4px;
    font-size: 12px;
    color: var(--text-muted);
  }
  .note.hidden {
    visibility: hidden;
  }
  .bottom {
    display: grid;
    grid-template-columns: minmax(300px, 1fr) 1.6fr;
    gap: 14px;
  }
  @media (max-width: 980px) {
    .top,
    .bottom {
      grid-template-columns: 1fr;
    }
  }
</style>

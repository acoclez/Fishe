<script lang="ts">
  /**
   * Connection quality of the session, or of one endpoint: TCP round-trip
   * time, jitter and retransmissions measured passively, plus an optional
   * continuous ping (ICMP, started by the user) for traffic TCP can't time.
   */
  import type { TrafficPoint } from "$lib/api/types";
  import { pings } from "$lib/stores/pings.svelte";
  import { GRADE_COLOR, jitterGrade, lossGrade, msText, pctText, rttGrade } from "$lib/utils/quality";
  import QualityChart from "../../components/QualityChart.svelte";

  interface Props {
    /** What the figures describe ("1.1.1.1", "all connections", an endpoint name). */
    subject: string;
    /** Address to ping, when the subject is one endpoint. */
    pingIp: string | null;
    rttMs: number | null;
    /** How `rttMs` is computed, shown under it. */
    rttHint: string;
    minRttMs: number | null;
    /** `null` hides jitter (mixed endpoints). */
    jitterMs: number | null;
    jitterHint: string;
    retransOutPct: number | null;
    retransInPct: number | null;
    retransHint: string;
    /** History with `rttMs` (session ticks or the endpoint's track). */
    points: TrafficPoint[];
    windowSecs: number;
  }
  let {
    subject, pingIp, rttMs, rttHint, minRttMs, jitterMs, jitterHint, retransOutPct, retransInPct, retransHint, points, windowSecs,
  }: Props = $props();

  const ping = $derived(pings.get(pingIp));
  const rttPts = $derived(points.map((p) => ({ tMs: p.tMs, v: p.rttMs ?? null })));
  // Ping history is per second ending now; align its end with the newest sample.
  const pingPts = $derived.by(() => {
    if (!ping || !points.length) return [];
    const end = points[points.length - 1].tMs;
    const n = ping.history.length;
    return ping.history.map((v, i) => ({ tMs: end - (n - 1 - i) * 1000, v }));
  });
  const color = (v: number | null, grade: (n: number) => "good" | "fair" | "poor") => (v === null ? "var(--text-muted)" : GRADE_COLOR[grade(v)]);
</script>

<section class="card qcard">
  <header>
    <h2 class="card-title">Connection quality <span class="scope-tag">· {subject}</span></h2>
    <div class="legend">
      <span><i class="sw rtt"></i>TCP round trip</span>
      {#if ping}<span><i class="sw ping"></i>Ping</span>{/if}
      {#if pingIp}
        <button
          type="button"
          class="ping-btn"
          class:on={ping?.running}
          onclick={() => pings.toggle(pingIp)}
          title={ping?.running ? "Stop pinging" : `Ping ${pingIp} once per second (sends ICMP echo requests)`}
        >
          <i class="dot"></i>{ping?.running ? "Stop ping" : "Ping"}
        </button>
      {/if}
    </div>
  </header>

  <div class="body">
    <div class="stats">
      <div class="stat">
        <span class="k">Round trip</span>
        <span class="v num" style:color={color(rttMs, rttGrade)}>{msText(rttMs)}</span>
        <span class="sub">
          {rttMs === null
            ? pingIp ? "no TCP round trips yet (UDP? use Ping)" : "no TCP traffic timed yet"
            : `${rttHint}${minRttMs !== null ? ` · min ${msText(minRttMs)}` : ""}`}
        </span>
      </div>
      <div class="stat">
        <span class="k">Jitter</span>
        <span class="v num" style:color={color(jitterMs, jitterGrade)}>{msText(jitterMs)}</span>
        <span class="sub">{jitterHint}</span>
      </div>
      <div class="stat">
        <span class="k">Retransmitted ↑</span>
        <span class="v num" style:color={color(retransOutPct, lossGrade)}>{pctText(retransOutPct)}</span>
        <span class="sub">of data sent · {retransHint}</span>
      </div>
      <div class="stat">
        <span class="k">Retransmitted ↓</span>
        <span class="v num" style:color={color(retransInPct, lossGrade)}>{pctText(retransInPct)}</span>
        <span class="sub">of data received · {retransHint}</span>
      </div>
    </div>

    {#if ping}
      <div class="ping-row" class:stopped={!ping.running}>
        <span class="k">Ping {ping.ip}{ping.running ? "" : " (stopped)"}</span>
        <span>last <b class="num">{ping.lastMs === null ? (ping.sent ? "lost" : "–") : `${ping.lastMs} ms`}</b></span>
        <span>avg <b class="num" style:color={color(ping.avgMs, rttGrade)}>{msText(ping.avgMs)}</b></span>
        <span>min/max <b class="num">{msText(ping.minMs)} / {msText(ping.maxMs)}</b></span>
        <span>jitter <b class="num" style:color={color(ping.jitterMs, jitterGrade)}>{msText(ping.jitterMs)}</b></span>
        <span>loss <b class="num" style:color={color(ping.lossPct, lossGrade)}>{pctText(ping.lossPct)}</b></span>
        <span class="muted num">{ping.received}/{ping.sent}</span>
        {#if ping.error}<span class="err">{ping.error}</span>{/if}
        {#if ping.received === 0 && ping.sent >= 3}
          <span class="hint" title="No replies: this host probably ignores ping (common for game and voice servers); its traffic can still be fine.">
            no replies: the host may ignore ping
          </span>
        {/if}
        {#if !ping.running}<button type="button" class="link" onclick={() => pings.remove(ping.ip)}>Clear</button>{/if}
      </div>
    {:else if pingIp}
      <!-- Same height as the live row, so starting a ping moves nothing. -->
      <div class="ping-row stopped">
        <span class="k">Ping</span>
        <span class="muted">off · one ICMP echo per second, also measures hosts that only use UDP (games, calls)</span>
      </div>
    {/if}
    {#if pings.error}<p class="err small">{pings.error}</p>{/if}

    <QualityChart rtt={rttPts} ping={pingPts} {windowSecs} />
  </div>
</section>

<style>
  .qcard {
    padding: 16px 18px 8px;
  }
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    flex-wrap: wrap;
  }
  .scope-tag {
    margin-left: 6px;
    color: var(--accent-strong);
    text-transform: none;
    letter-spacing: 0;
  }
  .legend {
    display: flex;
    align-items: center;
    gap: 14px;
    font-size: 12px;
    color: var(--text-secondary);
  }
  .sw {
    display: inline-block;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    margin-right: 6px;
    vertical-align: -1px;
  }
  .sw.rtt {
    background: var(--series-rtt);
  }
  .sw.ping {
    background: var(--accent-strong);
  }
  .ping-btn {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    height: 28px;
    padding: 0 12px;
    border-radius: 8px;
    border: 1px solid var(--border-strong);
    background: var(--surface-2);
    color: var(--text-secondary);
    font-weight: 600;
    font-size: 12px;
    cursor: pointer;
  }
  .ping-btn:hover {
    border-color: var(--accent);
    color: var(--text-primary);
  }
  .ping-btn .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    border: 2px solid currentColor;
  }
  .ping-btn.on {
    border-color: var(--accent);
    background: var(--accent-wash);
    color: var(--accent-strong);
  }
  .ping-btn.on .dot {
    background: var(--accent-strong);
    border-color: var(--accent-strong);
    animation: blink 1s ease-in-out infinite;
    will-change: opacity;
  }
  @keyframes blink {
    50% {
      opacity: 0.3;
    }
  }
  .body {
    display: flex;
    flex-direction: column;
    gap: 10px;
    margin-top: 10px;
  }
  .stats {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 14px;
  }
  .stat {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }
  .k {
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    color: var(--text-muted);
  }
  .v {
    font-size: 22px;
    font-weight: 600;
  }
  .sub {
    font-size: 11.5px;
    color: var(--text-muted);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .ping-row {
    display: flex;
    flex-wrap: nowrap;
    height: 34px;
    overflow: hidden;
    white-space: nowrap;
    align-items: center;
    gap: 6px 16px;
    padding: 8px 12px;
    border-radius: 8px;
    background: var(--accent-wash);
    font-size: 12.5px;
    color: var(--text-secondary);
  }
  .ping-row.stopped {
    background: var(--surface-2);
  }
  .ping-row b {
    color: var(--text-primary);
    font-weight: 600;
  }
  .hint {
    font-size: 12px;
    color: var(--text-muted);
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .small {
    margin: 0;
    font-size: 12px;
  }
  .link {
    margin-left: auto;
    border: 0;
    background: none;
    color: var(--accent-strong);
    font-size: 12px;
    cursor: pointer;
  }
  @media (max-width: 980px) {
    .stats {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
  }
</style>

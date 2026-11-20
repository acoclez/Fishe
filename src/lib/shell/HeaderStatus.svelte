<script lang="ts">
  /**
   * The header: the page's title and, on the right, what is going on: a
   * recording, connected agents, running pings, the live session (target,
   * owner, interface, clock) or, with nothing running, Npcap's state.
   */
  import { agents } from "#lib/stores/agents.svelte.ts";
  import { formatCount, formatDuration } from "#lib/utils/format.ts";
  import { monitor } from "#lib/stores/monitor.svelte.ts";
  import { PAGES, nav } from "#lib/stores/nav.svelte.ts";
  import { pings } from "#lib/stores/pings.svelte.ts";
  import { session } from "#lib/stores/session.svelte.ts";
  import OwnerCell from "../components/OwnerCell.svelte";

  const s = $derived(monitor.latest);
  const pageInfo = $derived(PAGES.find((p) => p.id === nav.page) ?? PAGES[0]);
  const runningPings = $derived(pings.list.filter((p) => p.running));
</script>

<header>
  <h1 class="page-title">{pageInfo.label}</h1>

  <div class="status">
    {#if monitor.recording}
      <button type="button" class="rec-chip" onclick={() => session.toggleRecording()} title="Stop recording">
        <i></i>REC <span class="num">{formatDuration(s?.recording?.elapsedMs ?? 0)}</span>
        {#if s?.recording && s.recording.pcapPackets > 0}<span class="num muted">· {formatCount(s.recording.pcapPackets)} pkts</span>{/if}
      </button>
    {/if}
    {#if agents.status?.running}
      {#key agents.pulse}
        <button
          type="button"
          class="agent-chip"
          class:flash={agents.pulse > 0}
          onclick={() => nav.go("settings", "agents")}
          title="Agents can connect over MCP ({agents.status.access} access, {agents.status.calls} calls). Click for settings and the activity log."
        >
          <svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="6" r="3" /><path d="M2.5 14c.8-2.8 3-4 5.5-4s4.7 1.2 5.5 4" /></svg>
          Agents
        </button>
      {/key}
    {/if}
    {#if runningPings.length}
      <button
        type="button"
        class="ping-chip"
        onclick={() => pings.stopAll()}
        title="Pinging {runningPings.map((p) => p.ip).join(', ')}: click to stop {runningPings.length === 1 ? 'it' : 'all'}"
      >
        <i></i>Ping ×{runningPings.length} <span class="muted">· Stop</span>
      </button>
    {/if}
    {#if monitor.session && monitor.phase === "running"}
      <span class="live"><i></i>Live</span>
      <span class="target" class:mono={monitor.session.mode !== "all"} title={monitor.session.filter}>
        {monitor.session.resolvedFrom ? `${monitor.session.resolvedFrom} → ` : ""}{monitor.session.label}
      </span>
      {#if session.hostOwner}<span class="host-owner"><OwnerCell owner={session.hostOwner} /></span>{/if}
      <span class="muted iface" title={monitor.session.interfaces.map((i) => i.description).join(", ")}>
        {monitor.session.interfaces.length === 1
          ? `via ${monitor.session.interfaces[0].description}`
          : `on ${monitor.session.interfaces.length} interfaces`}
      </span>
      {#if s}<span class="num muted clock">{formatDuration(s.tMs)}</span>{/if}
    {:else if session.npcap?.available}
      <span class="chip" title={session.npcap.dllDir ?? ""}>{session.npcap.version ?? "Npcap ready"}</span>
    {:else if session.npcap}
      <!-- Not an error: Npcap is installed by the user. The Live page says how. -->
      <button type="button" class="chip todo" onclick={() => nav.go("live")} title="Fishe needs Npcap to capture. Click to see how to install it.">
        Npcap not installed
      </button>
    {/if}
  </div>
</header>

<style>
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    height: 56px;
    padding: 0 20px;
    border-bottom: 1px solid var(--border);
    background: linear-gradient(180deg, #0f1317, var(--bg));
  }
  .page-title {
    margin: 0;
    font-size: 17px;
    font-weight: 700;
    letter-spacing: 0.01em;
  }
  .status {
    display: flex;
    align-items: center;
    gap: 12px;
    min-width: 0;
    font-size: 13px;
  }
  .clock {
    min-width: 5ch;
    text-align: right;
    font-variant-numeric: tabular-nums;
  }
  .status .iface {
    max-width: 260px;
    overflow: hidden;
    white-space: nowrap;
    text-overflow: ellipsis;
  }
  .live {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-weight: 600;
    color: var(--accent-strong);
  }
  .live i {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--accent-strong);
    animation: blink 1.6s ease-in-out infinite;
    will-change: opacity;
  }
  @keyframes blink {
    50% {
      opacity: 0.3;
    }
  }
  .target {
    color: var(--text-primary);
  }
  .chip {
    padding: 3px 10px;
    border-radius: 999px;
    font-size: 12px;
    background: var(--accent-wash);
    color: var(--accent-strong);
  }
  .chip.todo {
    border: 1px solid color-mix(in srgb, var(--level-busy) 55%, transparent);
    background: color-mix(in srgb, var(--level-busy) 12%, transparent);
    color: var(--level-busy);
    font-weight: 600;
    cursor: pointer;
  }
  .agent-chip {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 3px 10px;
    border-radius: 999px;
    border: 1px solid var(--border-strong);
    background: var(--surface-2);
    color: var(--text-secondary);
    font-weight: 600;
    font-size: 12px;
    cursor: pointer;
  }
  .agent-chip svg {
    width: 13px;
    height: 13px;
    fill: none;
    stroke: currentColor;
    stroke-width: 1.5;
  }
  /* One short flash per agent call, never a lasting animation. */
  .agent-chip.flash {
    animation: agentflash 900ms ease-out;
  }
  @keyframes agentflash {
    from {
      border-color: var(--accent-strong);
      color: var(--accent-strong);
      background: var(--accent-wash);
    }
  }
  .ping-chip {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 3px 10px;
    border-radius: 999px;
    border: 1px solid var(--accent);
    background: var(--accent-wash);
    color: var(--text-primary);
    font-weight: 600;
    font-size: 12px;
    cursor: pointer;
  }
  .ping-chip i {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--accent-strong);
  }
  .ping-chip:hover {
    border-color: var(--danger);
  }
  .rec-chip {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 3px 10px;
    border-radius: 999px;
    border: 1px solid var(--danger);
    background: var(--danger-wash);
    color: var(--text-primary);
    font-weight: 700;
    font-size: 12px;
    cursor: pointer;
  }
  .rec-chip i {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--danger);
    animation: blink 1.2s ease-in-out infinite;
    will-change: opacity;
  }
  @media (max-width: 980px) {
    .status .iface {
      display: none;
    }
  }
</style>

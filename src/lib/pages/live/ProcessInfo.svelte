<script lang="ts">
  /** Process / all-traffic status strip: what is bound, how it's attributed. */
  import type { ProcessTick, SessionInfo } from "#lib/api/types.ts";
  import { formatCount } from "#lib/utils/format.ts";

  let {
    session,
    tick,
    unattributed,
    programCount = 0,
  }: { session: SessionInfo; tick: ProcessTick | null; unattributed: number; programCount?: number } = $props();

  const all = $derived(session.mode === "all");

  const pids = $derived(tick?.pids ?? session.process?.pids ?? []);
  const pidCount = $derived(tick?.pidCount ?? pids.length);
  const byName = $derived(session.process?.selector.by === "name");
  const exact = $derived(session.attribution?.method === "etw");
</script>

<section class="card strip" aria-label="Process binding">
  <div class="who">
    {#if all}
      <svg viewBox="0 0 16 16" aria-hidden="true"><rect x="5.5" y="1.5" width="5" height="4" rx="1" /><rect x="1.5" y="10.5" width="5" height="4" rx="1" /><rect x="9.5" y="10.5" width="5" height="4" rx="1" /><path d="M8 5.5v2.5M4 10.5V8h8v2.5" /></svg>
      <div class="col">
        <b>{session.label}</b>
        <small class="path">Every packet of this machine, labelled with the program that owns it</small>
      </div>
    {:else}
      <svg viewBox="0 0 16 16" aria-hidden="true"><rect x="2" y="3" width="12" height="10" rx="1.5" /><path d="M2 6h12M5 9h3" /></svg>
      <div class="col">
        <b class="mono">{session.label}</b>
        {#if session.process?.exePath}<small class="path" title={session.process.exePath}>{session.process.exePath}</small>{/if}
      </div>
    {/if}
  </div>

  {#if all}
    <div class="stat">
      <span class="k">Programs</span>
      <span class="v num" title="Programs that sent or received traffic this session">{programCount}</span>
    </div>
    <div class="stat">
      <span class="k">With sockets</span>
      <span class="v num" title="Processes owning a TCP/UDP socket right now">{tick?.pidCount ?? "–"}</span>
    </div>
  {:else}
  <div class="stat">
    <span class="k">{byName ? "Instances" : "Process"}</span>
    {#if pidCount === 0}
      <span class="v waiting">{byName ? "none running, waiting for one to start…" : "process has exited"}</span>
    {:else}
      <span class="v num" title={pids.join(", ")}>
        {pidCount}
        <small class="mono">PID {pids.slice(0, 4).join(", ")}{pidCount > 4 ? ", …" : ""}</small>
      </span>
    {/if}
  </div>
  {/if}

  <div class="stat">
    <span class="k">Sockets</span>
    <span class="v num">{tick?.sockets ?? "–"}</span>
  </div>

  <div class="stat">
    <span class="k">Interfaces</span>
    <span class="v num" title={session.interfaces.map((i) => i.description).join("\n")}>{session.interfaces.length}</span>
  </div>

  <div class="stat">
    <span class="k">Attribution</span>
    <span class="v">
      <span class="badge" class:exact title={session.attribution?.note ?? "Kernel ETW events + socket table"}>
        {exact ? "Exact · ETW" : "Socket table"}
      </span>
    </span>
  </div>

  <div class="stat">
    <span class="k">Unattributed</span>
    <span
      class="v num"
      title={all
        ? "Packets counted without a program: ICMP and other non-TCP/UDP traffic, and TCP/UDP whose socket owner could not be found in time"
        : "Packets on this machine whose owning process could not be determined in time"}
    >{formatCount(unattributed)}</span>
  </div>
</section>
{#if session.attribution?.note && !exact}
  <p class="note">{session.attribution.note}</p>
{/if}

<style>
  .strip {
    display: flex;
    align-items: center;
    gap: 28px;
    padding: 12px 18px;
    flex-wrap: wrap;
  }
  .who {
    display: flex;
    align-items: center;
    gap: 10px;
    min-width: 0;
    flex: 1 1 260px;
  }
  .who svg {
    width: 22px;
    height: 22px;
    flex: none;
    fill: none;
    stroke: var(--accent);
    stroke-width: 1.4;
  }
  .col {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }
  .col b {
    font-size: 15px;
  }
  .path {
    color: var(--text-muted);
    font-size: 11px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .stat {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .k {
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    color: var(--text-muted);
  }
  .v {
    font-size: 15px;
    font-weight: 600;
    /* Counts change every tick: reserve their width so the strip stays put. */
    min-width: 5ch;
    font-variant-numeric: tabular-nums;
  }
  .v small {
    margin-left: 6px;
    font-size: 11px;
    font-weight: 400;
    color: var(--text-muted);
  }
  .waiting {
    font-weight: 400;
    color: var(--text-secondary);
    font-style: italic;
  }
  .badge {
    display: inline-block;
    padding: 1px 8px;
    border-radius: 999px;
    font-size: 12px;
    border: 1px solid var(--border-strong);
    color: var(--text-secondary);
  }
  .badge.exact {
    border-color: var(--accent);
    color: var(--accent-strong);
    background: var(--accent-wash);
  }
  .note {
    margin: -6px 4px 0;
    font-size: 12px;
    color: var(--text-muted);
  }
</style>

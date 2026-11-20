<script lang="ts">
  /**
   * All-traffic mode: which programs are using the network right now.
   * Click a row to focus the gauge on that program and filter the endpoints
   * to it; "Monitor" switches to process mode for it.
   *
   * Like the endpoints table, it stays readable while live: fixed height
   * (about 8 rows, scroll for more), fixed columns, values once a second,
   * order held while the pointer is over it.
   */
  import { untrack } from "svelte";
  import { flip } from "svelte/animate";
  import type { TrafficPoint, ProgramRow, Units } from "#lib/api/types.ts";
  import { StableList } from "#lib/stores/stable.svelte.ts";
  import { formatBytes, rateText } from "#lib/utils/format.ts";
  import { monitor } from "#lib/stores/monitor.svelte.ts";
  import LevelBadge from "../../components/LevelBadge.svelte";
  import Sparkline from "../../components/Sparkline.svelte";

  interface Props {
    rows: ProgramRow[];
    total: number;
    nowMs: number;
    units: Units;
    /** Switch to process mode bound to this executable name. */
    onmonitor: (name: string) => void;
  }
  let { rows, total, nowMs, units, onmonitor }: Props = $props();

  type SortKey = "live" | "total" | "name";
  let sort = $state<SortKey>("live");
  let query = $state("");
  const filtered = $derived.by(() => {
    const q = query.trim().toLowerCase();
    return q ? rows.filter((r) => r.name.toLowerCase().includes(q) || r.pids.some((p) => String(p).includes(q))) : rows;
  });
  const bytes = (r: ProgramRow) => r.totals.bytesIn + r.totals.bytesOut;
  const COMPARE: Record<SortKey, (a: ProgramRow, b: ProgramRow) => number> = {
    live: (a, b) => b.smoothedBps - a.smoothedBps || bytes(b) - bytes(a),
    total: (a, b) => bytes(b) - bytes(a),
    name: (a, b) => (a.key === "" ? 1 : b.key === "" ? -1 : a.name.localeCompare(b.name)),
  };

  const list = new StableList<ProgramRow>((r) => r.key);
  let hist = $state.raw(new Map<string, TrafficPoint[]>());
  let sig = "";
  $effect(() => {
    const items = filtered;
    const key = `${sort}|${query}`;
    const force = key !== sig;
    sig = key;
    if (list.update(items, COMPARE[sort], performance.now(), nowMs, force)) {
      hist = untrack(() => new Map(list.view.map((r) => [r.key, monitor.programHistory(r.key, 120)])));
    }
  });
  const visible = $derived(list.view);
  const viewNow = $derived(list.at);
  const sessionBytes = $derived(rows.reduce((n, r) => n + r.totals.bytesIn + r.totals.bytesOut, 0));

  function ago(ms: number): string {
    const s = Math.max(0, Math.round((viewNow - ms) / 1000));
    if (s < 2) return "now";
    if (s < 60) return `${s}s ago`;
    const m = Math.floor(s / 60);
    return m < 60 ? `${m}m ago` : `${Math.floor(m / 60)}h ago`;
  }

  function toggle(key: string) {
    monitor.setFocus(null);
    monitor.setProgramFocus(monitor.programFocus === key ? null : key);
  }

  /** Programs with a real executable name can be monitored on their own. */
  const monitorable = (r: ProgramRow) => r.key !== "" && !r.key.startsWith("pid:");
</script>

<section class="card panel">
  <header>
    <h2 class="card-title">Programs <span class="count num">{total}</span></h2>
    <div class="tools">
      <span class="held" class:on={list.frozen}>order held</span>
      <input class="search" bind:value={query} placeholder="Filter by name or PID" spellcheck="false" aria-label="Filter programs" />
      <div class="seg" role="radiogroup" aria-label="Sort programs">
        {#each [["live", "Live"], ["total", "Total"], ["name", "Name"]] as [k, label] (k)}
          <button type="button" role="radio" aria-checked={sort === k} class:on={sort === k} onclick={() => (sort = k as SortKey)}>{label}</button>
        {/each}
      </div>
    </div>
  </header>

  {#if rows.length === 0}
    <p class="empty">No traffic yet.</p>
  {:else}
    <div class="scroller" role="region" aria-label="Programs" onpointerenter={() => (list.frozen = true)} onpointerleave={() => (list.frozen = false)}>
    <table>
      <colgroup>
        <col />
        <col class="c-spark" />
        <col class="c-now" />
        <col class="c-level" />
        <col class="c-share" />
        <col class="c-total" />
        <col class="c-eps" />
        <col class="c-seen" />
        <col class="c-act" />
      </colgroup>
      <thead>
        <tr>
          <th>Program</th>
          <th>Activity</th>
          <th class="r">Now</th>
          <th>Level</th>
          <th class="r">Share</th>
          <th class="r">Total</th>
          <th class="r" title="Distinct remote addresses this session">Endpoints</th>
          <th class="r">Seen</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each visible as r (r.key)}
          {@const bytes = r.totals.bytesIn + r.totals.bytesOut}
          {@const share = sessionBytes ? bytes / sessionBytes : 0}
          <tr
            animate:flip={{ duration: 350 }}
            class:focused={monitor.programFocus === r.key}
            class:none={r.key === ""}
            onclick={() => toggle(r.key)}
            onkeydown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), toggle(r.key))}
            tabindex="0"
            aria-selected={monitor.programFocus === r.key}
            title="Focus the gauge on this program and show only its endpoints"
          >
            <td><div class="who">
              <span class="pname">{r.name}</span>
              {#if r.key === ""}
                <small class="muted" title="ICMP and other traffic without ports, and TCP/UDP whose socket owner could not be found in time">no owning program</small>
              {:else if r.pids.length}
                <small class="mono muted" title={r.pids.join(", ")}>
                  {r.pids.length === 1 ? `PID ${r.pids[0]}` : `${r.pids.length} processes`}
                </small>
              {/if}
            </div></td>
            <td><Sparkline points={hist.get(r.key) ?? []} /></td>
            <td class="r num">
              <div class="rate">
                <span>↓ {rateText(r.inBps, units)}</span>
                <span class="muted">↑ {rateText(r.outBps, units)}</span>
              </div>
            </td>
            <td><LevelBadge level={r.level} size="sm" /></td>
            <td class="r num">
              <div class="share" title="{(share * 100).toFixed(1)}% of this session's bytes">
                <i style:transform="scaleX({Math.max(0.02, share)})"></i>
              </div>
            </td>
            <td class="r num">{formatBytes(bytes)}</td>
            <td class="r num">{r.endpoints}</td>
            <td class="r num muted">{ago(r.lastSeenMs)}</td>
            <td class="act">
              {#if monitorable(r)}
                <button
                  type="button"
                  title="Monitor {r.name} on its own (process mode)"
                  onclick={(e) => {
                    e.stopPropagation();
                    onmonitor(r.name);
                  }}>Monitor ▸</button
                >
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    </div>
  {/if}
</section>

<style>
  .panel {
    padding: 16px 18px 10px;
  }
  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
  }
  .count {
    margin-left: 6px;
    color: var(--text-muted);
    font-weight: 500;
  }
  .tools {
    display: flex;
    gap: 10px;
    align-items: center;
  }
  .search {
    height: 30px;
    width: 180px;
    padding: 0 10px;
    background: var(--surface-2);
    border: 1px solid var(--border-strong);
    border-radius: 8px;
    outline: none;
    font-size: 12px;
  }
  .search:focus {
    border-color: var(--accent);
  }
  .seg {
    padding: 2px;
    border-radius: 8px;
  }
  .seg button {
    padding: 4px 10px;
    border-radius: 6px;
    font-size: 12px;
  }
  .empty {
    color: var(--text-muted);
    margin: 14px 0 6px;
    /* Same height as the table area, so the first rows don't push anything. */
    height: 414px;
  }
  .scroller {
    height: 414px;
    margin-top: 10px;
    overflow: auto;
  }
  table {
    width: 100%;
    min-width: 900px;
    table-layout: fixed;
    border-collapse: collapse;
    font-size: 13px;
  }
  th {
    position: sticky;
    top: 0;
    z-index: 1;
    background: var(--surface-1);
  }
  tbody tr {
    height: 47px;
  }
  td {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .c-spark {
    width: 128px;
  }
  .c-now {
    width: 104px;
  }
  .c-level {
    width: 92px;
  }
  .c-share {
    width: 84px;
  }
  .c-total {
    width: 84px;
  }
  .c-eps {
    width: 88px;
  }
  .c-seen {
    width: 72px;
  }
  .c-act {
    width: 104px;
  }
  .held {
    font-size: 11px;
    color: var(--accent-strong);
    visibility: hidden;
  }
  .held.on {
    visibility: visible;
  }
  th {
    text-align: left;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    color: var(--text-muted);
    padding: 6px 10px;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }
  td {
    padding: 7px 10px;
    border-bottom: 1px solid var(--border);
    vertical-align: middle;
  }
  .r {
    text-align: right;
  }
  tbody tr {
    cursor: pointer;
    transition: background 120ms;
  }
  tbody tr:hover {
    background: var(--surface-2);
  }
  tbody tr:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: -2px;
  }
  tbody tr.focused {
    background: var(--accent-wash);
    box-shadow: inset 3px 0 0 var(--accent);
  }
  tr.none .pname {
    font-style: italic;
    color: var(--text-secondary);
  }
  .who {
    display: flex;
    flex-direction: column;
    gap: 1px;
    min-width: 0;
  }
  .pname {
    font-weight: 600;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 260px;
  }
  .who small {
    font-size: 11px;
  }
  .rate {
    display: flex;
    flex-direction: column;
    line-height: 1.3;
    font-size: 12px;
    white-space: nowrap;
  }
  .share {
    width: 64px;
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
    transform-origin: left center;
  }
  .act {
    width: 1%;
    white-space: nowrap;
    text-align: right;
  }
  .act button {
    padding: 3px 10px;
    border-radius: 7px;
    border: 1px solid var(--border-strong);
    background: var(--surface-2);
    color: var(--text-secondary);
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    opacity: 0;
    transition: opacity 120ms, border-color 120ms;
  }
  tr:hover .act button,
  tr:focus-within .act button,
  tr.focused .act button {
    opacity: 1;
  }
  .act button:hover {
    border-color: var(--accent);
    color: var(--accent-strong);
  }
</style>

<script lang="ts">
  /**
   * Live list of the latest counted packets (headers only), Wireshark-style.
   * Turns the backend feed on while mounted and polls it twice a second.
   */
  import { onDestroy, onMount } from "svelte";
  import { api, errorMessage } from "#lib/api/index.ts";
  import type { CaptureInterface, PacketRow } from "#lib/api/types.ts";
  import { formatBytes } from "#lib/utils/format.ts";
  import { serviceName } from "#lib/utils/services.ts";

  interface Props {
    interfaces: CaptureInterface[];
    /** Show the Program column (all-traffic mode). */
    showPrograms: boolean;
  }
  let { interfaces, showPrograms }: Props = $props();

  /** Packets kept in the view (newest first). */
  const KEEP = 1000;
  /** Rows rendered at most. */
  const RENDER = 400;
  const POLL_MS = 500;

  let rows = $state.raw<PacketRow[]>([]);
  let paused = $state(false);
  /** Pointer over the list: hold it still (new packets are fetched on leave). */
  let hovering = $state(false);
  let query = $state("");
  let error = $state<string | null>(null);
  let missed = $state(0);
  let rate = $state(0);
  let lastSeq: number | null = null;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let alive = true;

  async function poll() {
    if (!alive) return;
    if (!paused && !hovering) {
      try {
        const batch = await api.recentPackets(lastSeq, 500);
        if (!batch.enabled) await api.setPacketFeed(true);
        if (batch.rows.length) {
          const first = batch.rows[0].seq;
          if (lastSeq !== null && first > lastSeq + 1) missed += first - lastSeq - 1;
          rate = batch.rows.length / (POLL_MS / 1000);
          lastSeq = batch.rows[batch.rows.length - 1].seq;
          rows = [...batch.rows.reverse(), ...rows].slice(0, KEEP);
        } else {
          rate = 0;
          if (lastSeq === null) lastSeq = batch.nextSeq - 1;
        }
        error = null;
      } catch (err) {
        error = errorMessage(err);
      }
    }
    if (alive) timer = setTimeout(poll, POLL_MS);
  }

  onMount(() => {
    api.setPacketFeed(true).catch(() => {});
    timer = setTimeout(poll, 150);
  });
  onDestroy(() => {
    alive = false;
    if (timer) clearTimeout(timer);
    api.setPacketFeed(false).catch(() => {});
  });

  const proto = (r: PacketRow) => r.transport.toUpperCase();
  function service(r: PacketRow): string | null {
    if (r.srcPort === null || r.dstPort === null) return null;
    const port = Math.min(r.srcPort, r.dstPort);
    return serviceName(r.transport, port) ?? null;
  }
  const endpoint = (ip: string, port: number | null) => (port === null ? ip : ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`);

  const shown = $derived.by(() => {
    const q = query.trim().toLowerCase();
    const list = q
      ? rows.filter(
          (r) =>
            r.src.includes(q) ||
            r.dst.includes(q) ||
            r.transport === q ||
            String(r.srcPort) === q ||
            String(r.dstPort) === q ||
            (r.program ?? "").toLowerCase().includes(q) ||
            (r.remoteName ?? "").toLowerCase().includes(q) ||
            (service(r) ?? "").toLowerCase().includes(q),
        )
      : rows;
    return list.slice(0, RENDER);
  });

  const time = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
  function stamp(us: number): string {
    const ms = Math.floor(us / 1000);
    return `${time.format(new Date(ms))}.${String(ms % 1000).padStart(3, "0")}`;
  }
  const ifaceName = (i: number) => interfaces[i]?.description ?? `#${i}`;

  function clear() {
    rows = [];
    missed = 0;
  }
</script>

<section class="card panel">
  <header>
    <h2 class="card-title">
      Packets
      <span class="count num">{paused ? "paused" : hovering ? "held while pointing" : `${Math.round(rate)}/s shown`}</span>
    </h2>
    <div class="tools">
      <input class="search" bind:value={query} placeholder="Filter: IP, port, tcp/udp, program, name" spellcheck="false" aria-label="Filter packets" />
      <button type="button" class="btn" class:on={paused} onclick={() => (paused = !paused)} aria-pressed={paused}>
        {paused ? "▶ Resume" : "❚❚ Pause"}
      </button>
      <button type="button" class="btn" onclick={clear}>Clear</button>
    </div>
  </header>
  {#if error}<p class="note err">{error}</p>{/if}
  {#if missed > 0}
    <p class="note">
      {missed.toLocaleString()} packets went by faster than the list refreshes and are not shown (all of them are counted).
    </p>
  {/if}

  {#if shown.length === 0}
    <p class="empty">{rows.length ? "No packet matches the filter." : paused ? "Paused." : "Waiting for packets…"}</p>
  {:else}
    <div class="scroller" role="region" aria-label="Packets" onpointerenter={() => (hovering = true)} onpointerleave={() => (hovering = false)}>
      <table>
        <colgroup>
          <col class="c-time" />
          <col class="c-dir" />
          <col class="c-addr" />
          <col class="c-addr" />
          <col class="c-proto" />
          <col class="c-len" />
          <col class="c-ttl" />
          {#if showPrograms}<col class="c-prog" />{/if}
          <col />
        </colgroup>
        <thead>
          <tr>
            <th>Time</th>
            <th></th>
            <th>Source</th>
            <th>Destination</th>
            <th>Protocol</th>
            <th class="r">Length</th>
            <th class="r" title="Time to live / hop limit">TTL</th>
            {#if showPrograms}<th>Program</th>{/if}
            <th>Remote name</th>
          </tr>
        </thead>
        <tbody>
          {#each shown as r (r.seq)}
            {@const svc = service(r)}
            <tr title={ifaceName(r.iface)}>
              <td class="num muted t">{stamp(r.tsUs)}</td>
              <td class="dir" class:in={r.dir === "in"} title={r.dir === "in" ? "Received" : "Sent"}>{r.dir === "in" ? "↓" : "↑"}</td>
              <td class="mono"><span class="clip addr" title={endpoint(r.src, r.srcPort)}>{endpoint(r.src, r.srcPort)}</span></td>
              <td class="mono"><span class="clip addr" title={endpoint(r.dst, r.dstPort)}>{endpoint(r.dst, r.dstPort)}</span></td>
              <td><span class="proto" data-t={r.transport}>{proto(r)}</span>{#if svc}<span class="svc">{svc}</span>{/if}</td>
              <td class="r num">{formatBytes(r.len)}</td>
              <td class="r num muted">{r.ttl}</td>
              {#if showPrograms}
                <td class:none={!r.program}><span class="clip prog">{r.program ?? "–"}</span></td>
              {/if}
              <td class="muted"><span class="clip name" title={r.remoteName ?? ""}>{r.remoteName ?? ""}</span></td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    <p class="foot muted">
      Newest first · {rows.length.toLocaleString()} kept{rows.length > RENDER && !query ? `, ${RENDER} shown` : ""} · headers only, nothing is saved unless you Record.
    </p>
  {/if}
</section>

<style>
  .panel {
    padding: 16px 18px 10px;
    /* Fills what is left of the page, like the endpoints table. */
    display: flex;
    flex-direction: column;
    flex: 1 1 auto;
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
    text-transform: none;
    letter-spacing: 0;
  }
  .tools {
    display: flex;
    gap: 8px;
    align-items: center;
  }
  .search {
    height: 30px;
    width: 250px;
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
  .btn {
    height: 30px;
    padding: 0 12px;
    border-radius: 8px;
    border: 1px solid var(--border-strong);
    background: var(--surface-2);
    color: var(--text-secondary);
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
  }
  .btn:hover {
    border-color: var(--accent);
    color: var(--text-primary);
  }
  .btn.on {
    border-color: var(--accent);
    color: var(--accent-strong);
    background: var(--accent-wash);
  }
  .note {
    margin: 8px 0 0;
    font-size: 12px;
    color: var(--text-muted);
  }
  .note.err {
    color: var(--danger);
  }
  .empty {
    color: var(--text-muted);
    margin: 10px 0 0;
    padding-top: 4px;
    /* Same box as the table area: the first rows don't push anything. */
    flex: 1 1 480px;
    min-height: 480px;
  }
  table {
    table-layout: fixed;
    min-width: 980px;
  }
  .c-time {
    width: 104px;
  }
  .c-dir {
    width: 28px;
  }
  .c-addr {
    width: 250px;
  }
  .c-proto {
    width: 120px;
  }
  .c-len {
    width: 76px;
  }
  .c-ttl {
    width: 48px;
  }
  .c-prog {
    width: 160px;
  }
  td {
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .scroller {
    flex: 1 1 480px;
    min-height: 480px;
    overflow-y: auto;
    overflow-x: hidden;
    margin-top: 10px;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }
  th {
    position: sticky;
    top: 0;
    background: var(--surface-1);
    text-align: left;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    color: var(--text-muted);
    padding: 6px 8px;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }
  td {
    padding: 3px 8px;
    border-bottom: 1px solid color-mix(in srgb, var(--border) 60%, transparent);
    white-space: nowrap;
  }
  tbody tr:hover {
    background: var(--surface-2);
  }
  .r {
    text-align: right;
  }
  .t {
    font-variant-numeric: tabular-nums;
  }
  .dir {
    color: var(--series-out);
    font-weight: 700;
    text-align: center;
    width: 1%;
  }
  .dir.in {
    color: var(--series-in);
  }
  .clip {
    display: inline-block;
    overflow: hidden;
    text-overflow: ellipsis;
    vertical-align: bottom;
  }
  .addr {
    max-width: 230px;
  }
  .proto {
    display: inline-block;
    min-width: 34px;
    padding: 0 5px;
    border-radius: 4px;
    font-size: 10.5px;
    font-weight: 700;
    text-align: center;
    background: var(--surface-3);
    color: var(--text-secondary);
  }
  .proto[data-t="tcp"] {
    color: var(--accent-strong);
  }
  .proto[data-t="udp"] {
    color: var(--series-out);
  }
  .svc {
    margin-left: 6px;
    color: var(--text-secondary);
  }
  .prog {
    max-width: 160px;
  }
  td.none {
    color: var(--text-muted);
  }
  .name {
    max-width: 220px;
  }
  .foot {
    margin: 8px 0 0;
    font-size: 11px;
  }
</style>

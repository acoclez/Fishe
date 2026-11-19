<script lang="ts">
  /**
   * Remote endpoints of the monitored process (or, in all-traffic mode, of
   * the machine): who it talks to, how much, and how busy each one is.
   * Click a row to focus the gauge and chart on it.
   *
   * Stays readable while live: values refresh once a second, the order at
   * most every 3 s and never while the pointer is over the table; columns
   * have fixed widths and rows a fixed height (see `stable.svelte.ts`).
   */
  import { untrack } from "svelte";
  import { flip } from "svelte/animate";
  import type { AddrScope, EndpointRow, TrafficPoint, NameSource, Units } from "$lib/api/types";
  import { StableList } from "$lib/stores/stable.svelte";
  import { formatBytes, rateText } from "$lib/utils/format";
  import { serviceName } from "$lib/utils/services";
  import { monitor } from "$lib/stores/monitor.svelte";
  import LevelBadge from "../../components/LevelBadge.svelte";
  import Sparkline from "../../components/Sparkline.svelte";
  import OwnerCell from "../../components/OwnerCell.svelte";
  import { ownerText } from "$lib/utils/geo";
  import { routes } from "$lib/stores/routes.svelte";
  import { pings } from "$lib/stores/pings.svelte";
  import { GRADE_COLOR, lossGrade, msText, pctText, rttGrade } from "$lib/utils/quality";

  const pingable = (r: EndpointRow) => !["multicast", "broadcast", "unspecified"].includes(r.scope);
  function rttTitle(r: EndpointRow): string {
    const q = r.quality;
    if (!q) return "No TCP traffic to time (UDP/QUIC): use Ping";
    const parts = [`TCP round trip ${msText(q.srttMs)} (min ${msText(q.minRttMs)}, jitter ${msText(q.jitterMs)}, ${q.rttSamples} samples)`];
    parts.push(`retransmitted: sent ${pctText(q.retransOutPct)}, received ${pctText(q.retransInPct)}`);
    return parts.join("\n");
  }

  interface Props {
    rows: EndpointRow[];
    total: number;
    nowMs: number;
    units: Units;
    /** All-traffic mode: show the Programs column. */
    showPrograms?: boolean;
    /** All-traffic mode: only endpoints this program talks to (by key). */
    program?: { key: string; name: string } | null;
    onclearprogram?: () => void;
  }
  let { rows, total, nowMs, units, showPrograms = false, program = null, onclearprogram }: Props = $props();

  type SortKey = "live" | "total" | "recent" | "name";
  let sort = $state<SortKey>("live");
  let query = $state("");

  const NEW_FOR_MS = 15_000;

  const SCOPE: Record<AddrScope, string> = {
    loopback: "Loopback",
    private: "LAN",
    linkLocal: "Link-local",
    cgnat: "CGNAT",
    multicast: "Multicast",
    broadcast: "Broadcast",
    unspecified: "Unspecified",
    documentation: "Test net",
    public: "Internet",
  };
  const SOURCE: Record<NameSource, { label: string; hint: string }> = {
    sni: { label: "TLS", hint: "Server name sent by the process when it opened a TLS connection (SNI)" },
    dns: { label: "DNS", hint: "Name from a DNS answer that returned this address" },
    echOuter: { label: "ECH", hint: "Encrypted Client Hello: only the shared front name is visible, not the real site" },
    reverseDns: { label: "PTR", hint: "Reverse DNS record of the address (often the hosting provider, not the site)" },
  };

  const filtered = $derived.by(() => {
    const q = query.trim().toLowerCase();
    const byProgram = program ? rows.filter((r) => r.programs?.some((p) => p.key === program.key)) : rows;
    const list = q
      ? byProgram.filter(
          (r) =>
            r.ip.includes(q) ||
            (r.name ?? "").toLowerCase().includes(q) ||
            ownerText(r.owner).includes(q) ||
            (r.programs ?? []).some((p) => p.name.toLowerCase().includes(q)),
        )
      : byProgram;
    return list;
  });

  const bytes = (r: EndpointRow) => r.totals.bytesIn + r.totals.bytesOut;
  const COMPARE: Record<SortKey, (a: EndpointRow, b: EndpointRow) => number> = {
    live: (a, b) => b.smoothedBps - a.smoothedBps || b.lastSeenMs - a.lastSeenMs || bytes(b) - bytes(a),
    total: (a, b) => bytes(b) - bytes(a),
    recent: (a, b) => b.firstSeenMs - a.firstSeenMs,
    name: (a, b) => (a.name ?? "~" + a.ip).localeCompare(b.name ?? "~" + b.ip),
  };

  const list = new StableList<EndpointRow>((r) => r.ip);
  /** Sparkline data, taken when the view refreshes (not every sample). */
  let hist = $state.raw(new Map<string, TrafficPoint[]>());
  let sig = "";
  $effect(() => {
    const items = filtered;
    const key = `${sort}|${query}|${program?.key ?? ""}`;
    const force = key !== sig;
    sig = key;
    if (list.update(items, COMPARE[sort], performance.now(), nowMs, force)) {
      hist = untrack(() => new Map(list.view.map((r) => [r.ip, monitor.endpointHistory(r.ip, 120)])));
    }
  });
  const shown = $derived(list.view);
  const viewNow = $derived(list.at);

  function ago(ms: number): string {
    const s = Math.max(0, Math.round((viewNow - ms) / 1000));
    if (s < 2) return "now";
    if (s < 60) return `${s}s ago`;
    const m = Math.floor(s / 60);
    return m < 60 ? `${m}m ago` : `${Math.floor(m / 60)}h ago`;
  }

  function toggle(ip: string) {
    monitor.setFocus(monitor.focus === ip ? null : ip);
  }
</script>

<section class="card panel">
  <header>
    <h2 class="card-title">
      Endpoints
      {#if program}
        <span class="count num">{shown.length}</span>
        <span class="chip-filter">of {program.name}<button type="button" onclick={() => onclearprogram?.()} aria-label="Show all endpoints" title="Show all endpoints">×</button></span>
      {:else}
        <span class="count num">{rows.length < total ? `${rows.length} of ${total}` : total}</span>
      {/if}
    </h2>
    <div class="tools">
      <span class="held" class:on={list.frozen} title="The order is held while the pointer is over the table">order held</span>
      <input class="search" bind:value={query} placeholder={showPrograms ? "Filter by name, IP, owner, program" : "Filter by name, IP, owner, country"} spellcheck="false" aria-label="Filter endpoints" />
      <div class="seg" role="radiogroup" aria-label="Sort endpoints">
        {#each [["live", "Live"], ["total", "Total"], ["recent", "Newest"], ["name", "Name"]] as [k, label] (k)}
          <button type="button" role="radio" aria-checked={sort === k} class:on={sort === k} onclick={() => (sort = k as SortKey)}>{label}</button>
        {/each}
      </div>
    </div>
  </header>

  {#if rows.length === 0}
    <p class="empty">{showPrograms ? "No traffic yet." : "No traffic from the process yet."}</p>
  {:else if shown.length === 0 && program}
    <p class="empty">{program.name} has no endpoint among the {rows.length} listed right now.</p>
  {:else}
    <div class="scroller" role="region" aria-label="Endpoints" onpointerenter={() => (list.frozen = true)} onpointerleave={() => (list.frozen = false)}>
      <table class:with-programs={showPrograms}>
        <colgroup>
          <col />
          <col class="c-owner" />
          {#if showPrograms}<col class="c-progs" />{/if}
          <col class="c-hops" />
          <col class="c-rtt" />
          <col class="c-ports" />
          <col class="c-spark" />
          <col class="c-now" />
          <col class="c-level" />
          <col class="c-total" />
          <col class="c-seen" />
        </colgroup>
        <thead>
          <tr>
            <th>Endpoint</th>
            <th>Owner</th>
            {#if showPrograms}<th title="Programs exchanging traffic with this endpoint (biggest first)">Programs</th>{/if}
            <th class="r" title="Routers between here and the endpoint: traced, or ~estimated from packet TTLs">Hops</th>
            <th class="r" title="TCP round-trip time (smoothed); a running ping replaces it">RTT</th>
            <th>Services</th>
            <th>Activity</th>
            <th class="r">Now</th>
            <th>Level</th>
            <th class="r">Total</th>
            <th class="r">Seen</th>
          </tr>
        </thead>
        <tbody>
          {#each shown as r (r.ip)}
            {@const isNew = viewNow - r.firstSeenMs < NEW_FOR_MS}
            <tr
              animate:flip={{ duration: 350 }}
              class:focused={monitor.focus === r.ip}
              onclick={() => toggle(r.ip)}
              onkeydown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), toggle(r.ip))}
              tabindex="0"
              aria-selected={monitor.focus === r.ip}
              title="Focus the gauge on this endpoint"
            >
              <td class="ep">
                <div class="name">
                  {#if r.name}<span class="host">{r.name}</span>{:else}<span class="host mono">{r.ip}</span>{/if}
                  {#if isNew}<span class="tag new">NEW</span>{/if}
                </div>
                <div class="meta">
                  {#if r.name}<span class="mono ip">{r.ip}</span>{/if}
                  <span class="tag scope" data-scope={r.scope}>{SCOPE[r.scope]}</span>
                  {#if r.nameSource}<span class="tag src" title={SOURCE[r.nameSource].hint}>{SOURCE[r.nameSource].label}</span>{/if}
                </div>
              </td>
              <td><OwnerCell owner={r.owner} /></td>
              {#if showPrograms}
                <td class="progs">
                  {#each r.programs ?? [] as p (p.key)}
                    <span class="prog" class:none={p.key === ""} class:hit={program?.key === p.key} title="{p.name}: {formatBytes(p.bytes)}">{p.name}</span>
                  {/each}
                </td>
              {/if}
              <td class="r num hops">
                {#if routes.traces[r.ip]}
                  {@const t = routes.traces[r.ip]}
                  <span title="Traced{t.reached ? '' : ' (destination did not reply)'}">{t.hops.length}{t.reached ? "" : "+"}</span>
                {:else if r.hops !== null}
                  <span class="muted" title="Estimated from the TTL of received packets">~{r.hops}</span>
                {/if}
                {#if r.scope === "public"}
                  <button
                    type="button"
                    class="trace"
                    class:busy={routes.isPending(r.ip)}
                    disabled={routes.isPending(r.ip)}
                    title={routes.traces[r.ip] ? "Trace the route again" : "Trace the route (sends ICMP probes)"}
                    aria-label="Trace route to {r.name ?? r.ip}"
                    onclick={(e) => {
                      e.stopPropagation();
                      routes.trace(r.ip, !!routes.traces[r.ip]);
                    }}>⤳</button
                  >
                {/if}
              </td>
              <td class="num rtt">
                <!-- Value shrinks (ellipsis), the button never does: it must stay clickable. -->
                <div class="rtt-line">
                <span class="rtt-val">
                {#if pings.get(r.ip)}
                  {@const p = pings.get(r.ip)!}
                  <span
                    title="Ping: avg {msText(p.avgMs)}, jitter {msText(p.jitterMs)}, loss {pctText(p.lossPct)} ({p.received}/{p.sent})"
                    style:color={p.lastMs === null ? "var(--level-spike)" : GRADE_COLOR[rttGrade(p.lastMs)]}
                  >{p.lastMs === null ? (p.sent ? "lost" : "…") : `${p.lastMs} ms`}</span>
                {:else if r.quality?.srttMs != null}
                  <span title={rttTitle(r)} style:color={GRADE_COLOR[rttGrade(r.quality.srttMs)]}>{msText(r.quality.srttMs)}</span>
                {:else}
                  <span class="muted" title={rttTitle(r)}>–</span>
                {/if}
                </span>
                {#if pingable(r)}
                  <button
                    type="button"
                    class="trace pingb"
                    class:on={pings.running(r.ip)}
                    title={pings.running(r.ip) ? "Stop pinging" : "Ping once per second (sends ICMP echo requests)"}
                    aria-label="{pings.running(r.ip) ? 'Stop pinging' : 'Ping'} {r.name ?? r.ip}"
                    onclick={(e) => {
                      e.stopPropagation();
                      pings.toggle(r.ip);
                    }}>◉</button
                  >
                {/if}
                </div>
                {#if pings.get(r.ip)}
                  <div class="sub-line"><i class="ptag" class:off={!pings.running(r.ip)}>{pings.running(r.ip) ? "ping" : "ping stopped"}</i></div>
                {:else if r.quality?.retransOutPct != null && r.quality.retransOutPct >= 1}
                  <div class="sub-line retx" title={rttTitle(r)} style:color={GRADE_COLOR[lossGrade(r.quality.retransOutPct)]}>⟳ {pctText(r.quality.retransOutPct)}</div>
                {/if}
              </td>
              <td class="ports">
                {#each r.topPorts.slice(0, 3) as p (`${p.transport}${p.port}`)}
                  <span class="port mono" title={serviceName(p.transport, p.port) ?? ""}>{p.port}<i>/{p.transport}</i></span>
                {/each}
              </td>
              <td><Sparkline points={hist.get(r.ip) ?? []} width={88} /></td>
              <td class="r num">
                <div class="rate">
                  <span>↓ {rateText(r.inBps, units)}</span>
                  <span class="muted">↑ {rateText(r.outBps, units)}</span>
                </div>
              </td>
              <td><LevelBadge level={r.level} size="sm" /></td>
              <td class="r num">{formatBytes(r.totals.bytesIn + r.totals.bytesOut)}</td>
              <td class="r num muted">{ago(r.lastSeenMs)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
  <!-- Always laid out (hidden when unused) so the panel never changes height for it. -->
  <p class="credit" class:hidden={!rows.some((r) => r.owner?.source === "dbip")}>
    Owner &amp; country: IP data by DB-IP.com (CC BY 4.0){#if rows.some((r) => r.owner?.source === "ipinfo")}{" and ipinfo.io (↗)"}{/if}.
  </p>
</section>

<style>
  /* Fixed layout: columns keep their width whatever the values. */
  /* Fixed columns sum to 902 px (1042 with Programs); the endpoint name
     keeps at least 240 px, below that the table scrolls sideways. */
  table {
    table-layout: fixed;
    min-width: 1142px;
  }
  table.with-programs {
    min-width: 1282px;
  }
  .c-owner {
    width: 150px;
  }
  .c-progs {
    width: 140px;
  }
  .c-hops {
    width: 70px;
  }
  .c-rtt {
    width: 104px;
  }
  .c-ports {
    width: 120px;
  }
  .c-spark {
    width: 110px;
  }
  .c-now {
    width: 104px;
  }
  .c-level {
    width: 92px;
  }
  .c-total {
    width: 80px;
  }
  .c-seen {
    width: 72px;
  }
  tbody tr {
    height: 54px;
  }
  td {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .held {
    font-size: 11px;
    color: var(--accent-strong);
    visibility: hidden;
  }
  .held.on {
    visibility: visible;
  }
  .credit.hidden {
    visibility: hidden;
  }
  .rtt {
    white-space: nowrap;
  }
  .rtt-line {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: 2px;
  }
  .rtt-val {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .rtt-line .trace {
    flex: none;
  }
  .sub-line {
    text-align: right;
    line-height: 1.2;
  }
  .ptag {
    margin-left: 4px;
    padding: 0 4px;
    border-radius: 4px;
    background: var(--accent-wash);
    color: var(--accent-strong);
    font-size: 10px;
    font-style: normal;
    font-weight: 700;
  }
  .ptag.off {
    background: var(--surface-3);
    color: var(--text-muted);
  }
  .retx {
    font-size: 11px;
  }
  .pingb.on {
    color: var(--accent-strong);
    border-color: var(--accent);
    background: var(--accent-wash);
  }
  td.num {
    white-space: nowrap;
  }
  .prog {
    display: inline-block;
    max-width: 150px;
    margin: 1px 4px 1px 0;
    padding: 0 6px;
    border-radius: 5px;
    background: var(--surface-3);
    color: var(--text-secondary);
    font-size: 11.5px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    vertical-align: middle;
  }
  .prog.none {
    font-style: italic;
    color: var(--text-muted);
  }
  .prog.hit {
    background: var(--accent-wash);
    color: var(--accent-strong);
  }
  .chip-filter {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    margin-left: 6px;
    padding: 1px 4px 1px 9px;
    border-radius: 999px;
    background: var(--accent-wash);
    color: var(--accent-strong);
    text-transform: none;
    letter-spacing: 0;
    font-weight: 600;
  }
  .chip-filter button {
    border: 0;
    background: none;
    color: inherit;
    font-size: 14px;
    line-height: 1;
    cursor: pointer;
    padding: 0 4px;
  }
  .credit {
    margin: 8px 0 0;
    font-size: 11px;
    color: var(--text-muted);
  }
  .panel {
    padding: 16px 18px 10px;
    /* Fills what is left of the page (see ConnectionsPage): its height follows
       the window, never the rows. */
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
  }
  .tools {
    display: flex;
    gap: 10px;
    align-items: center;
  }
  .search {
    height: 30px;
    width: 200px;
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
    margin: 10px 0 0;
    padding-top: 4px;
    /* Same box as the table area: the first rows don't push anything. */
    flex: 1 1 440px;
    min-height: 440px;
  }
  .scroller {
    /* Sized by the window (at least 440px), not by its rows: rows coming
       and going never move anything. */
    flex: 1 1 440px;
    min-height: 440px;
    overflow: auto;
    margin-top: 10px;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }
  th {
    position: sticky;
    top: 0;
    z-index: 1;
    background: var(--surface-1);
    text-align: left;
    font-weight: 500;
    font-size: 11px;
    color: var(--text-muted);
    padding: 4px 8px 6px;
  }
  td {
    padding: 7px 8px;
    border-top: 1px solid var(--border);
    vertical-align: middle;
  }
  tbody tr {
    cursor: pointer;
    transition: background 120ms;
  }
  tbody tr:hover {
    background: var(--surface-2);
  }
  tbody tr.focused {
    background: var(--accent-wash);
    box-shadow: inset 3px 0 0 var(--accent);
  }
  tbody tr:focus-visible {
    outline: 2px solid var(--accent-strong);
    outline-offset: -2px;
  }
  .r {
    text-align: right;
  }
  .ep {
    min-width: 0;
  }
  .name {
    display: flex;
    align-items: center;
    gap: 6px;
    min-width: 0;
  }
  .host {
    font-weight: 600;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .meta {
    display: flex;
    align-items: center;
    gap: 6px;
    margin-top: 2px;
    font-size: 11px;
    color: var(--text-muted);
    min-width: 0;
  }
  .ip {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .tag {
    flex: none;
    padding: 0 6px;
    border-radius: 4px;
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.03em;
    line-height: 16px;
    border: 1px solid var(--border-strong);
    color: var(--text-secondary);
  }
  .tag.new {
    border-color: var(--accent);
    color: var(--accent-strong);
    background: var(--accent-wash);
  }
  .tag.scope[data-scope="private"],
  .tag.scope[data-scope="loopback"],
  .tag.scope[data-scope="linkLocal"] {
    color: var(--text-primary);
    background: var(--surface-3);
  }
  .tag.src {
    border-style: dashed;
    cursor: help;
  }
  .ports {
    white-space: nowrap;
  }
  .hops {
    white-space: nowrap;
  }
  .trace {
    margin-left: 4px;
    width: 22px;
    height: 20px;
    border: 1px solid var(--border-strong);
    border-radius: 5px;
    background: var(--surface-2);
    color: var(--text-secondary);
    cursor: pointer;
    font-size: 12px;
    line-height: 1;
  }
  .trace:hover:not(:disabled) {
    border-color: var(--accent);
    color: var(--accent-strong);
  }
  .trace.busy {
    animation: pulse 1s ease-in-out infinite;
    will-change: opacity;
  }
  @keyframes pulse {
    50% {
      opacity: 0.35;
    }
  }
  .port {
    display: inline-block;
    margin-right: 4px;
    padding: 0 5px;
    border-radius: 4px;
    background: var(--surface-3);
    font-size: 11px;
  }
  .port i {
    font-style: normal;
    color: var(--text-muted);
  }
  .rate {
    display: flex;
    flex-direction: column;
    align-items: flex-end;
    font-size: 12px;
    white-space: nowrap;
  }
</style>

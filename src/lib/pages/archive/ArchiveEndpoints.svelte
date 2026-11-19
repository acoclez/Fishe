<script lang="ts">
  /** Endpoints of a recording (totals over the recording). Click to chart one. */
  import type { AddrScope, EndpointRecord, NameSource, Units } from "$lib/api/types";
  import { formatBytes, formatDuration, rateText } from "$lib/utils/format";
  import { serviceName } from "$lib/utils/services";
  import LevelBadge from "../../components/LevelBadge.svelte";
  import OwnerCell from "../../components/OwnerCell.svelte";
  import { ownerText } from "$lib/utils/geo";
  import { GRADE_COLOR, lossGrade, msText, pctText, rttGrade } from "$lib/utils/quality";

  interface Props {
    endpoints: EndpointRecord[];
    units: Units;
    focus: string | null;
    onfocus: (ip: string) => void;
  }
  let { endpoints, units, focus, onfocus }: Props = $props();
  let query = $state("");

  const SCOPE: Record<AddrScope, string> = {
    loopback: "Loopback", private: "LAN", linkLocal: "Link-local", cgnat: "CGNAT", multicast: "Multicast",
    broadcast: "Broadcast", unspecified: "Unspecified", documentation: "Test net", public: "Internet",
  };
  const SOURCE: Record<NameSource, string> = { sni: "TLS", dns: "DNS", echOuter: "ECH", reverseDns: "PTR" };

  const shown = $derived.by(() => {
    const q = query.trim().toLowerCase();
    return q
      ? endpoints.filter((e) => e.ip.includes(q) || (e.name ?? "").toLowerCase().includes(q) || ownerText(e.owner).includes(q))
      : endpoints;
  });
</script>

<section class="card panel">
  <header>
    <h2 class="card-title">Endpoints <span class="count num">{endpoints.length}</span></h2>
    <input bind:value={query} placeholder="Filter by name, IP, owner, country" spellcheck="false" aria-label="Filter endpoints" />
  </header>
  <div class="scroller">
    <table>
      <thead>
        <tr><th>Endpoint</th><th>Owner</th><th class="r" title="TCP round-trip time (smoothed) over the recording">RTT</th><th>Services</th><th class="r">Total</th><th class="r">Peak</th><th>Max</th><th class="r">Active</th></tr>
      </thead>
      <tbody>
        {#each shown as e (e.ip)}
          <tr
            class:focused={focus === e.ip}
            onclick={() => onfocus(e.ip)}
            onkeydown={(ev) => (ev.key === "Enter" || ev.key === " ") && (ev.preventDefault(), onfocus(e.ip))}
            tabindex="0"
            title="Chart this endpoint"
          >
            <td class="ep">
              <div class="host">{e.name ?? e.ip}</div>
              <div class="meta">
                {#if e.name}<span class="mono">{e.ip}</span>{/if}
                <span class="tag">{SCOPE[e.scope] ?? e.scope}</span>
                {#if e.nameSource}<span class="tag src">{SOURCE[e.nameSource] ?? e.nameSource}</span>{/if}
              </div>
            </td>
            <td><OwnerCell owner={e.owner} /></td>
            <td
              class="r num"
              title={e.quality
                ? `min ${msText(e.quality.minRttMs)}, jitter ${msText(e.quality.jitterMs)}, retransmitted sent ${pctText(e.quality.retransOutPct)}, received ${pctText(e.quality.retransInPct)}`
                : "No TCP round trips recorded"}
            >
              {#if e.quality?.srttMs != null}
                <span style:color={GRADE_COLOR[rttGrade(e.quality.srttMs)]}>{msText(e.quality.srttMs)}</span>
              {:else}<span class="muted">–</span>{/if}
              {#if e.quality?.retransOutPct != null && e.quality.retransOutPct >= 1}
                <div style:color={GRADE_COLOR[lossGrade(e.quality.retransOutPct)]} style:font-size="11px">⟳ {pctText(e.quality.retransOutPct)}</div>
              {/if}
            </td>
            <td class="ports">
              {#each e.topPorts.slice(0, 3) as p (`${p.transport}${p.port}`)}
                <span class="port mono" title={serviceName(p.transport, p.port) ?? ""}>{p.port}<i>/{p.transport}</i></span>
              {/each}
            </td>
            <td class="r num">{formatBytes(e.totals.bytesIn + e.totals.bytesOut)}</td>
            <td class="r num">{rateText(e.peakBps, units)}</td>
            <td><LevelBadge level={e.maxLevel} size="sm" /></td>
            <td class="r num muted">{formatDuration(e.firstSeenMs)}–{formatDuration(e.lastSeenMs)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
  {#if endpoints.some((e) => e.owner?.source === "dbip")}
    <p class="credit">Owner &amp; country: IP data by DB-IP.com (CC BY 4.0).</p>
  {/if}
</section>

<style>
  .credit {
    margin: 8px 0 0;
    font-size: 11px;
    color: var(--text-muted);
  }
  .panel {
    padding: 16px 18px 10px;
    min-width: 0;
  }
  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
  }
  .count {
    margin-left: 6px;
    color: var(--text-muted);
  }
  input {
    height: 30px;
    width: 200px;
    padding: 0 10px;
    background: var(--surface-2);
    border: 1px solid var(--border-strong);
    border-radius: 8px;
    outline: none;
    font-size: 12px;
  }
  input:focus {
    border-color: var(--accent);
  }
  .scroller {
    max-height: 420px;
    overflow-y: auto;
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
  }
  tbody tr {
    cursor: pointer;
  }
  tbody tr:hover {
    background: var(--surface-2);
  }
  tbody tr.focused {
    background: var(--accent-wash);
    box-shadow: inset 3px 0 0 var(--accent);
  }
  .r {
    text-align: right;
  }
  .host {
    font-weight: 600;
    max-width: 320px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .meta {
    display: flex;
    gap: 6px;
    align-items: center;
    margin-top: 2px;
    font-size: 11px;
    color: var(--text-muted);
  }
  .tag {
    padding: 0 6px;
    border-radius: 4px;
    font-size: 10px;
    font-weight: 600;
    line-height: 16px;
    border: 1px solid var(--border-strong);
    color: var(--text-secondary);
  }
  .tag.src {
    border-style: dashed;
  }
  .ports {
    white-space: nowrap;
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
</style>

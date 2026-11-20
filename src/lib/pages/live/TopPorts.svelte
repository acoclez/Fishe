<script lang="ts">
  /** Busiest service ports (lower port of each flow), cumulative. */
  import type { PortUsage } from "#lib/api/types.ts";
  import { formatBytes, formatCount } from "#lib/utils/format.ts";
  import { serviceName } from "#lib/utils/services.ts";

  let { ports, totalBytes }: { ports: PortUsage[]; totalBytes: number } = $props();
</script>

<section class="card panel">
  <h2 class="card-title">Top services</h2>
  {#if ports.length === 0}
    <p class="empty">No port traffic yet.</p>
  {:else}
    <table>
      <thead>
        <tr><th>Port</th><th>Service</th><th class="r">Share</th><th class="r">Bytes</th><th class="r">Packets</th></tr>
      </thead>
      <tbody>
        {#each ports as p (`${p.transport}:${p.port}`)}
          <tr>
            <td class="mono">{p.port}<span class="proto">/{p.transport}</span></td>
            <td class="svc">{serviceName(p.transport, p.port) ?? "-"}</td>
            <td class="r">
              <span class="bar"><span style:transform="scaleX({totalBytes ? p.bytes / totalBytes : 0})"></span></span>
            </td>
            <td class="r num">{formatBytes(p.bytes)}</td>
            <td class="r num muted">{formatCount(p.packets)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</section>

<style>
  .panel {
    padding: 16px 18px;
    min-width: 0;
  }
  .empty {
    color: var(--text-muted);
    margin: 14px 0 4px;
  }
  table {
    width: 100%;
    margin-top: 8px;
    border-collapse: collapse;
    font-size: 13px;
  }
  th {
    text-align: left;
    font-weight: 500;
    font-size: 11px;
    color: var(--text-muted);
    padding: 4px 6px;
  }
  td {
    padding: 5px 6px;
    border-top: 1px solid var(--border);
  }
  .r {
    text-align: right;
  }
  .proto {
    color: var(--text-muted);
  }
  .svc {
    color: var(--text-secondary);
  }
  .bar {
    display: inline-block;
    width: 70px;
    height: 6px;
    border-radius: 3px;
    background: var(--surface-3);
    overflow: hidden;
    vertical-align: middle;
  }
  /* scaleX, not width: compositor-only transition (see ProtocolBreakdown). */
  .bar span {
    display: block;
    height: 100%;
    background: var(--accent);
    transform-origin: left center;
    transition: transform 400ms ease;
  }
</style>

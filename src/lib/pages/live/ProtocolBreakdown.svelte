<script lang="ts">
  /** Cumulative bytes per transport protocol: one hue (magnitude), labelled rows. */
  import type { TransportBytes } from "$lib/api/types";
  import { formatBytes, formatPercent } from "$lib/utils/format";

  let { transports }: { transports: TransportBytes | null } = $props();

  const rows = $derived.by(() => {
    const t = transports ?? { tcp: 0, udp: 0, icmp: 0, other: 0 };
    const total = t.tcp + t.udp + t.icmp + t.other;
    return {
      total,
      items: [
        { name: "TCP", bytes: t.tcp },
        { name: "UDP", bytes: t.udp },
        { name: "ICMP", bytes: t.icmp },
        { name: "Other", bytes: t.other },
      ],
    };
  });
</script>

<section class="card panel">
  <h2 class="card-title">Protocols</h2>
  <ul>
    {#each rows.items as r (r.name)}
      <li>
        <span class="name">{r.name}</span>
        <span class="bar"><span style:transform="scaleX({rows.total ? r.bytes / rows.total : 0})"></span></span>
        <span class="pct num">{formatPercent(r.bytes, rows.total)}</span>
        <span class="bytes num">{formatBytes(r.bytes)}</span>
      </li>
    {/each}
  </ul>
</section>

<style>
  .panel {
    padding: 16px 18px;
  }
  ul {
    list-style: none;
    margin: 12px 0 0;
    padding: 0;
    display: grid;
    gap: 10px;
  }
  li {
    display: grid;
    grid-template-columns: 48px 1fr 44px 70px;
    align-items: center;
    gap: 10px;
    font-size: 13px;
  }
  .name {
    color: var(--text-secondary);
  }
  .bar {
    height: 8px;
    border-radius: 4px;
    background: var(--surface-3);
    overflow: hidden;
  }
  /* scaleX, not width: the transition stays on the compositor (a width
     transition re-triggered every tick meant a page layout every frame). */
  .bar span {
    display: block;
    height: 100%;
    background: var(--accent);
    transform-origin: left center;
    transition: transform 400ms ease;
  }
  .pct {
    text-align: right;
    font-weight: 600;
  }
  .bytes {
    text-align: right;
    color: var(--text-muted);
  }
</style>

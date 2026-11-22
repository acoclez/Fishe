<script lang="ts">
  /**
   * LAN map: scan the local network for devices and show what each one is.
   *
   * A scan is a one-shot action (it sends ARP requests and, optionally, probes
   * a few common ports), so results replace the previous set atomically — the
   * list and the map are drawn once per scan and never reflow on their own.
   * The result is kept in the `lan` store, so leaving the page does not lose it.
   */
  import { lan } from "#lib/stores/lan.svelte.ts";
  import { nav } from "#lib/stores/nav.svelte.ts";
  import { session } from "#lib/stores/session.svelte.ts";
  import { settings } from "#lib/stores/settings.svelte.ts";
  import type { LanDevice, LanNetwork } from "#lib/api/types.ts";

  const scanning = $derived(lan.scanning);
  const result = $derived(lan.result);
  const error = $derived(lan.error);
  const view = $derived(lan.view);
  let hover = $state<string | null>(null);
  const hoverDev = $derived.by(() => {
    if (!hover || !result) return null;
    for (const net of result.networks) {
      const d = net.devices.find((x) => x.ip === hover);
      if (d) return d;
    }
    return null;
  });

  /** The sweep sends ARP through the capture library: without it there is nothing to press. */
  const noCapture = $derived(session.npcap !== null && !session.npcap.available);

  const deviceCount = $derived(result ? result.networks.reduce((n, net) => n + net.devices.length, 0) : 0);

  const scan = () => lan.scan(settings.lanProbePorts);

  function label(d: LanDevice): string {
    if (d.hostname) return d.hostname;
    if (d.isGateway) return "Gateway";
    if (d.isSelf) return "This PC";
    return d.ip;
  }

  function kind(d: LanDevice): string {
    if (d.isSelf) return "self";
    if (d.isGateway) return "gateway";
    return "device";
  }
</script>

<div class="lan">
  <div class="toolbar">
    <button type="button" class="primary" onclick={scan} disabled={scanning || noCapture}>
      {#if scanning}<span class="spin"></span> Scanning…{:else}{result ? "Scan again" : "Scan network"}{/if}
    </button>
    <label class="opt" title="Open and close a connection to a few well-known ports to hint at what each device is">
      <input
        type="checkbox"
        checked={settings.lanProbePorts}
        disabled={scanning}
        onchange={(e) => (settings.lanProbePorts = (e.currentTarget as HTMLInputElement).checked)}
      />
      Probe common ports
    </label>
    <span class="spacer"></span>
    {#if result}
      <div class="viewtoggle" role="group" aria-label="View">
        <button type="button" class:on={view === "list"} onclick={() => (lan.view = "list")}>List</button>
        <button type="button" class:on={view === "map"} onclick={() => (lan.view = "map")}>Map</button>
      </div>
    {/if}
  </div>

  <p class="status">
    {#if noCapture}
      {#if session.linux}
        Scanning needs the permission to capture packets.
        <button type="button" class="link" onclick={() => nav.go("live")}>See how to grant it</button>
      {:else}
        Scanning needs Npcap, which isn't installed yet.
        <button type="button" class="link" onclick={() => nav.go("live")}>See how to install it</button>
      {/if}
    {:else if error}
      <span class="err">{error}</span>
    {:else if scanning}
      Sweeping the network with ARP{settings.lanProbePorts ? " and probing ports" : ""}… this takes a few seconds.
    {:else if result}
      {deviceCount} device{deviceCount === 1 ? "" : "s"} · scanned in {(result.durationMs / 1000).toFixed(1)}s
      {#if !result.probedPorts}· ports not probed{/if}
      {#if result.note}<span class="muted">· {result.note}</span>{/if}
    {:else}
      Find the devices on your local network — their address, maker and what they offer.
      <span class="muted">Sends ARP requests, like your router's device list does.</span>
    {/if}
  </p>

  {#if result}
    {#each result.networks as net (net.interface + net.ip)}
      {@render network(net)}
    {/each}
  {:else if !scanning && !error}
    <div class="empty">
      <svg class="icon" viewBox="0 0 48 40" aria-hidden="true">
        <rect x="18" y="3" width="12" height="9" rx="2" />
        <rect x="3" y="28" width="12" height="9" rx="2" />
        <rect x="18" y="28" width="12" height="9" rx="2" />
        <rect x="33" y="28" width="12" height="9" rx="2" />
        <path d="M24 12v8M9 28v-8h30v8M24 20v8" />
      </svg>
      <p>{#if noCapture}{session.linux ? "Allow Fishe to capture to scan your network." : "Install Npcap to scan your network."}{:else}No scan yet. Press <b>Scan network</b> to see what's connected.{/if}</p>
    </div>
  {/if}
</div>

{#snippet network(net: LanNetwork)}
  <section class="net">
    <h3>
      {net.interface}
      <span class="muted">· {net.ip}/{net.prefix}{net.wireless ? " · Wi-Fi" : ""}</span>
      {#if net.description && net.description !== net.interface}<span class="muted small">· {net.description}</span>{/if}
      {#if net.dhcp.length === 1}
        <span class="muted small" title="The DHCP server that answered: it hands out gateway {net.dhcp[0].router ?? '–'} and DNS {net.dhcp[0].dns.join(' ') || '–'}">· DHCP {net.dhcp[0].ip}</span>
      {:else if net.dhcp.length > 1}
        <span class="badge new" title={net.dhcp.map((d) => `${d.ip}${d.mac ? " (" + d.mac + ")" : ""}: gateway ${d.router ?? "–"}, DNS ${d.dns.join(" ") || "–"}`).join("\n")}>
          {net.dhcp.length} DHCP servers
        </span>
      {/if}
    </h3>

    {#if view === "list"}
      <table>
        <colgroup>
          <col />
          <col class="c-ip" />
          <col class="c-maker" />
          <col class="c-mac" />
          <col class="c-ports" />
        </colgroup>
        <thead>
          <tr><th>Device</th><th>Address</th><th>Maker</th><th>MAC</th><th>Open ports</th></tr>
        </thead>
        <tbody>
          {#each net.devices as d (d.ip)}
            <tr class={kind(d)}>
              <td>
                <div class="name">
                  <span class="dot {kind(d)}"></span>
                  <span class="who" title={label(d)}>{label(d)}</span>
                  {#if d.isGateway && d.hostname}<span class="badge">Gateway</span>{/if}
                  {#if d.isSelf && d.hostname}<span class="badge self">This PC</span>{/if}
                  {#if d.isNew}<span class="badge new" title="Not there at the previous scan of this network">New</span>{/if}
                </div>
              </td>
              <td class="mono">{d.ip}</td>
              <td class="vendor" title={d.vendor ?? undefined}>
                {#if d.vendor}{d.vendor}{:else if d.randomizedMac}<span class="muted" title="A privacy-randomised MAC carries no maker">Random MAC</span>{:else}<span class="muted">Unknown</span>{/if}
              </td>
              <td class="mono mac">{d.mac ?? "—"}</td>
              <td>
                <div class="chips">
                  {#if d.ports.length}
                    {#each d.ports as p (p.port)}
                      <span class="chip" title="Port {p.port}">{p.service ?? p.port}</span>
                    {/each}
                  {:else if d.isSelf}
                    <span class="muted small">not probed</span>
                  {:else}
                    <span class="muted small">none open</span>
                  {/if}
                </div>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {:else}
      {@render map(net)}
    {/if}
  </section>
{/snippet}

{#snippet map(net: LanNetwork)}
  {@const W = 760}
  {@const H = 420}
  {@const cx = W / 2}
  {@const cy = H / 2}
  {@const ring = net.devices.filter((d) => !d.isGateway)}
  {@const gw = net.devices.find((d) => d.isGateway)}
  {@const R = Math.min(cx, cy) - 70}
  {@const pos = new Map(ring.map((d, i) => {
    const a = -Math.PI / 2 + (i / Math.max(1, ring.length)) * Math.PI * 2;
    return [d.ip, { x: cx + Math.cos(a) * R, y: cy + Math.sin(a) * R, a }];
  }))}
  <div class="mapwrap">
    <svg viewBox="0 0 {W} {H}" role="img" aria-label="Devices on {net.interface}, arranged around the gateway">
      <!-- edges: every device links to the gateway (the LAN's hub) -->
      {#each ring as d (d.ip)}
        {@const p = pos.get(d.ip)!}
        <line x1={cx} y1={cy} x2={p.x} y2={p.y} class="edge" class:hl={hover === d.ip} />
      {/each}
      <!-- gateway at the centre -->
      <g class="node gateway" class:dim={hover !== null && hover !== (gw?.ip ?? "")} onpointerenter={() => (hover = gw?.ip ?? null)} onpointerleave={() => (hover = null)} role="presentation">
        <rect x={cx - 11} y={cy - 11} width="22" height="22" rx="4" transform="rotate(45 {cx} {cy})" />
        <text x={cx} y={cy + 26} text-anchor="middle" class="lbl strong">{gw ? label(gw) : "Gateway"}</text>
      </g>
      <!-- devices on the ring -->
      {#each ring as d (d.ip)}
        {@const p = pos.get(d.ip)!}
        {@const right = Math.cos(p.a) >= 0}
        <g
          class="node {kind(d)}"
          class:dim={hover !== null && hover !== d.ip}
          transform="translate({p.x} {p.y})"
          onpointerenter={() => (hover = d.ip)}
          onpointerleave={() => (hover = null)}
          role="presentation"
        >
          <circle r={d.isSelf ? 9 : 7} class:ports={d.ports.length > 0} />
          <text x={right ? 12 : -12} y="4" text-anchor={right ? "start" : "end"} class="lbl" class:strong={d.isSelf}>{trunc(label(d), 18)}</text>
        </g>
      {/each}
    </svg>

    {#if hoverDev}
      <div class="tip">
        <b>{label(hoverDev)}</b>
        <div class="mono">{hoverDev.ip}{#if hoverDev.mac} · {hoverDev.mac}{/if}</div>
        {#if hoverDev.vendor}<div>{hoverDev.vendor}</div>{:else if hoverDev.randomizedMac}<div class="muted">Randomised MAC (no maker)</div>{/if}
        {#if hoverDev.ports.length}<div class="muted small">{hoverDev.ports.map((p) => p.service ?? String(p.port)).join(" · ")}</div>{/if}
      </div>
    {/if}
  </div>
{/snippet}

<script lang="ts" module>
  const trunc = (s: string, n: number) => (s.length > n ? s.slice(0, n - 1) + "…" : s);
</script>

<style>
  .lan {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .toolbar {
    display: flex;
    gap: 12px;
    align-items: center;
    flex-wrap: wrap;
  }
  .spacer {
    flex: 1;
  }
  button {
    height: 30px;
    padding: 0 12px;
    border-radius: 7px;
    border: 1px solid var(--border-strong);
    background: var(--surface-2);
    color: var(--text-primary);
    font-size: 13px;
    cursor: pointer;
  }
  button.primary {
    background: var(--accent);
    border-color: var(--accent);
    color: #04121a;
    font-weight: 600;
  }
  button:disabled {
    opacity: 0.55;
    cursor: default;
  }
  .opt {
    display: inline-flex;
    gap: 6px;
    align-items: center;
    font-size: 12px;
    color: var(--text-secondary);
    cursor: pointer;
  }
  .opt input {
    accent-color: var(--accent);
  }
  .viewtoggle {
    display: inline-flex;
  }
  .viewtoggle button {
    border-radius: 0;
    min-width: 48px;
    font-size: 12px;
  }
  .viewtoggle button:first-child {
    border-radius: 7px 0 0 7px;
  }
  .viewtoggle button:last-child {
    border-radius: 0 7px 7px 0;
    border-left: 0;
  }
  .viewtoggle button.on {
    background: var(--accent-deep);
    border-color: var(--accent);
    color: var(--text-primary);
  }
  button.link {
    height: auto;
    padding: 0;
    border: 0;
    background: none;
    color: var(--accent-strong);
    font-size: inherit;
    text-decoration: underline;
  }
  .status {
    margin: 0;
    font-size: 12px;
    color: var(--text-secondary);
    min-height: 16px;
  }
  .small {
    font-size: 11px;
  }
  .spin {
    width: 10px;
    height: 10px;
  }
  .empty {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 6px;
    padding: 30px 20px;
    color: var(--text-muted);
    text-align: center;
  }
  .empty .icon {
    width: 44px;
    height: auto;
    fill: none;
    stroke: currentColor;
    stroke-width: 1.6;
    stroke-linejoin: round;
    opacity: 0.6;
  }
  .empty p {
    margin: 0;
    font-size: 13px;
  }
  .net {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .net h3 {
    margin: 4px 0 0;
    font-size: 13px;
    font-weight: 600;
    color: var(--text-primary);
  }
  .net h3 .muted {
    font-weight: 400;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    table-layout: fixed;
  }
  th {
    text-align: left;
    font-weight: 500;
    color: var(--text-muted);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    padding: 0 10px 6px;
    border-bottom: 1px solid var(--border);
  }
  col.c-ip {
    width: 125px;
  }
  col.c-maker {
    width: 18%;
  }
  col.c-mac {
    width: 145px;
  }
  col.c-ports {
    width: 32%;
  }
  td {
    padding: 7px 10px;
    border-bottom: 1px solid var(--border);
    vertical-align: middle;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  tr.gateway td,
  tr.self td {
    background: color-mix(in srgb, var(--accent) 7%, transparent);
  }
  .name {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
  }
  .who {
    color: var(--text-primary);
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .dot {
    flex: none;
    width: 9px;
    height: 9px;
    border-radius: 50%;
    background: var(--text-muted);
  }
  .dot.self {
    background: var(--accent);
  }
  .dot.gateway {
    background: var(--accent-deep);
    border: 1px solid var(--accent);
    border-radius: 2px;
    transform: rotate(45deg);
  }
  .dot.device {
    background: var(--level-calm, var(--accent));
    opacity: 0.8;
  }
  .badge {
    font-size: 10px;
    padding: 1px 6px;
    border-radius: 999px;
    background: var(--surface-3);
    border: 1px solid var(--border-strong);
    color: var(--text-secondary);
  }
  .badge.self {
    border-color: var(--accent);
    color: var(--accent);
  }
  .badge.new {
    border-color: var(--level-busy);
    color: var(--level-busy);
  }
  .mono {
    font-family: var(--mono, ui-monospace, monospace);
    font-size: 12px;
  }
  .mac {
    color: var(--text-muted);
  }
  .vendor {
    color: var(--text-secondary);
  }
  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    white-space: normal;
  }
  .chip {
    font-size: 11px;
    padding: 1px 7px;
    border-radius: 5px;
    background: var(--accent-deep);
    border: 1px solid var(--border-strong);
    color: var(--text-secondary);
    white-space: nowrap;
  }
  .mapwrap {
    position: relative;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background:
      radial-gradient(circle at 1px 1px, color-mix(in srgb, var(--border-strong) 55%, transparent) 1px, transparent 0) 0 0 / 22px 22px,
      var(--bg);
    overflow: hidden;
  }
  .mapwrap svg {
    display: block;
    width: 100%;
    height: auto;
  }
  .edge {
    stroke: color-mix(in srgb, var(--accent) 40%, var(--border-strong));
    stroke-width: 1.2;
    transition: opacity 150ms;
  }
  .edge.hl {
    stroke: var(--accent-strong);
    stroke-width: 2;
  }
  .node {
    cursor: default;
    transition: opacity 150ms;
  }
  .node.dim {
    opacity: 0.3;
  }
  .node circle,
  .node rect {
    stroke: var(--bg);
    stroke-width: 2;
  }
  .node.self circle {
    fill: var(--accent);
    stroke: var(--accent-strong);
  }
  .node.gateway rect {
    fill: var(--accent-deep);
    stroke: var(--accent);
  }
  .node.device circle {
    fill: var(--surface-3);
    stroke: var(--accent);
    stroke-width: 1.5;
  }
  .node circle.ports {
    fill: color-mix(in srgb, var(--accent) 45%, var(--surface-3));
  }
  .lbl {
    fill: var(--text-secondary);
    font-size: 11px;
    pointer-events: none;
  }
  .lbl.strong {
    fill: var(--text-primary);
    font-weight: 600;
  }
  .tip {
    position: absolute;
    left: 12px;
    bottom: 12px;
    max-width: 320px;
    padding: 8px 11px;
    background: var(--surface-2);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius);
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.5);
    font-size: 12px;
    color: var(--text-secondary);
    display: flex;
    flex-direction: column;
    gap: 2px;
    pointer-events: none;
  }
  .tip b {
    color: var(--text-primary);
  }
</style>

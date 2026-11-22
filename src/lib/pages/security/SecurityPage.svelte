<script lang="ts">
  /**
   * Security: what the measurements say about how exposed this machine is,
   * and what on it deserves a look. Findings first (a fact and why it
   * matters, never a verdict), then the facts behind them: what each
   * program talks to, who can connect to this machine and who tried, the
   * DNS servers, whether a VPN carries the traffic, and the local networks
   * scanned so far.
   *
   * The report is polled while the page is open. Every table has fixed
   * columns and a stable order (by name, address or port, never by a
   * figure that moves), so rows hold still between refreshes.
   */
  import { onMount } from "svelte";
  import { formatBytes, formatCount, formatDuration } from "#lib/utils/format.ts";
  import { monitor } from "#lib/stores/monitor.svelte.ts";
  import { nav } from "#lib/stores/nav.svelte.ts";
  import { security } from "#lib/stores/security.svelte.ts";
  import type { AddrScope, DhcpServer, DnsServer, Finding, InboundPeer, Listener, PlainUse, ProgramAudit, Route, Severity } from "#lib/api/types.ts";

  onMount(() => security.watch());

  const report = $derived(security.report);
  const session = $derived(security.session);
  const findings = $derived(security.findings);

  const SEVERITY: Record<Severity, string> = { warning: "Warning", notice: "Notice", info: "Note" };
  const counts = $derived({
    warning: findings.filter((f) => f.severity === "warning").length,
    notice: findings.filter((f) => f.severity === "notice").length,
    info: findings.filter((f) => f.severity === "info").length,
  });

  /** Findings whose explanation is open. */
  let open = $state<Record<string, boolean>>({});

  const byText = (a: string, b: string) => a.localeCompare(b, undefined, { sensitivity: "base", numeric: true });
  const flagged = (p: ProgramAudit) => p.plaintext.some((u) => u.certainty !== "maybe") || p.oldTls.length > 0;

  // Stable orders: what is flagged first, then by name or address.
  const programs = $derived(
    [...(session?.programs ?? [])].sort((a, b) => Number(flagged(b)) - Number(flagged(a)) || byText(a.name, b.name)),
  );
  const inbound = $derived(
    [...(session?.inbound ?? [])].sort(
      (a, b) => Number(b.scan) - Number(a.scan) || Number(b.accepted > 0) - Number(a.accepted > 0) || byText(a.ip, b.ip),
    ),
  );
  const dnsServers = $derived([...(session?.dns.servers ?? [])].sort((a, b) => byText(a.ip, b.ip)));
  const listeners = $derived(report?.listeners ?? []);
  const reachable = $derived(listeners.filter((l) => l.reach === "network").length);
  const vpn = $derived(report?.vpn ?? null);
  /** DHCP servers heard during the session, grouped for one line of text. */
  const dhcpHeard = $derived((session?.dhcp ?? []).map((d) => `${d.server} on ${d.interface}`));

  const dhcpTitle = (d: DhcpServer) =>
    [d.ip + (d.isGateway ? " (the gateway)" : ""), d.mac, d.vendor, `hands out gateway ${d.router ?? "–"}`, `DNS ${d.dns.join(" ") || "–"}`]
      .filter(Boolean)
      .join(" · ");
  /** A family that leaves directly while the VPN carries IPv4 is the thing to notice. */
  const routeChip = (r: Route) => (r.via === "tunnel" ? "net" : r.via === "direct" && vpn?.ipv4.via === "tunnel" ? "credentials" : "quiet");
  const routeText = (r: Route) => (r.via === "tunnel" ? "Through the VPN" : r.via === "direct" ? "Direct" : "No route");

  const where = (scope: AddrScope) => (scope === "public" ? "Internet" : scope === "loopback" ? "This PC" : "Local network");
  const whoOwns = (o: InboundPeer["owner"] | DnsServer["owner"]) => (o ? [o.org, o.country].filter(Boolean).join(" · ") : "");
  const names = (items: { name: string }[], n: number) => items.slice(0, n).map((i) => i.name);
  const plainTitle = (u: PlainUse) =>
    `${u.service} (port ${u.port}), ${formatBytes(u.bytes)} with ${u.endpointCount} endpoint${u.endpointCount === 1 ? "" : "s"}: ` +
    u.endpoints.map((e) => e.name ?? e.ip).join(", ") +
    (u.certainty === "maybe" ? ". Encrypted only if the program upgrades the connection." : "");
  const listenerTitle = (l: Listener) =>
    l.reach === "network"
      ? "Other machines can try to connect, unless a firewall stops them (Fishe does not see firewall rules)"
      : "Only programs on this PC can connect";
  const ms = (v: number | null) => (v === null ? "–" : v < 10 ? `${v.toFixed(1)} ms` : `${Math.round(v)} ms`);
  const dateFmt = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

  let confirmForget = $state(false);
  async function forget() {
    confirmForget = false;
    await security.forgetLan();
  }
</script>

<div class="sec">
  <!-- Summary: always the same three counters, so nothing moves when a finding appears. -->
  <section class="card summary" aria-label="Summary">
    <div class="tally warning" class:zero={counts.warning === 0}><b class="num">{counts.warning}</b><span>Warning{counts.warning === 1 ? "" : "s"}</span></div>
    <div class="tally notice" class:zero={counts.notice === 0}><b class="num">{counts.notice}</b><span>Notice{counts.notice === 1 ? "" : "s"}</span></div>
    <div class="tally info" class:zero={counts.info === 0}><b class="num">{counts.info}</b><span>Note{counts.info === 1 ? "" : "s"}</span></div>
    <p class="state">
      {#if !report}
        {security.error ?? "Reading…"}
      {:else if report.state === "auditing" && session}
        Auditing this PC's traffic for <span class="num">{formatDuration(session.tMs)}</span>. Fishe reads packet headers, not content: it
        reports what was seen and why it matters, not whether something is malicious.
      {:else if report.state === "notAllTraffic"}
        The running session watches one {monitor.session?.mode === "host" ? "host" : "program"}, not the whole PC. Programs, inbound
        connections and DNS are audited in an <b>All</b> traffic session.
        <button type="button" class="link" onclick={() => nav.go("live")}>Go to Live</button>
      {:else if security.ended}
        Showing what the last All traffic session found. Listening services and the local network are current.
      {:else}
        Programs, inbound connections and DNS are audited while an <b>All</b> traffic session runs. Listening services and the local
        network below don't need one.
        <button type="button" class="link" onclick={() => nav.go("live")}>Go to Live</button>
      {/if}
    </p>
  </section>

  {#if report && security.error}<p class="err small" role="alert">{security.error}</p>{/if}

  <section class="card block">
    <h2 class="card-title">Findings <span class="count num">{findings.length}</span></h2>
    {#if findings.length === 0}
      <p class="none">{report ? "Nothing to point out." : " "}</p>
    {:else}
      <ul class="findings">
        {#each findings as f (f.id)}
          {@render finding(f)}
        {/each}
      </ul>
    {/if}
  </section>

  <section class="card block">
    <h2 class="card-title">
      Programs <span class="count num">{session ? session.programCount : "–"}</span>
      <span class="sub">who each program talks to, and how</span>
    </h2>
    {#if !session}
      <p class="none">Needs an All traffic session.</p>
    {:else if programs.length === 0}
      <p class="none">No program has exchanged traffic yet.</p>
    {:else}
      <div class="scroll">
        <table class="t-programs">
          <colgroup>
            <col class="c-program" /><col class="c-num" /><col class="c-countries" /><col /><col class="c-plain" /><col class="c-tls" />
          </colgroup>
          <thead>
            <tr>
              <th>Program</th>
              <th class="r" title="Remote addresses it exchanged traffic with">Endpoints</th>
              <th title="Countries of its Internet endpoints, most traffic first">Countries</th>
              <th title="Organisations owning those addresses, most traffic first">Organisations</th>
              <th title="Traffic over services that are not encrypted">Unencrypted</th>
              <th title="The newest TLS version it offered, when that is an outdated one">TLS</th>
            </tr>
          </thead>
          <tbody>
            {#each programs as p (p.key)}
              <tr>
                <td>
                  <div class="two">
                    <span class="strong ell" class:unknown={p.key === ""} title={p.name}>{p.name}</span>
                    <span class="muted small num">{formatBytes(p.bytes)}</span>
                  </div>
                </td>
                <td class="r num">{formatCount(p.endpoints)}</td>
                <td class="ell" title={p.countries.map((c) => `${c.name}: ${formatBytes(c.bytes)}, ${c.endpoints} endpoint${c.endpoints === 1 ? "" : "s"}`).join("\n")}>
                  {#if p.countries.length}
                    <span class="mono">{names(p.countries, 4).join(" ")}</span>{#if p.countries.length > 4}<span class="muted">&nbsp;+{p.countries.length - 4}</span>{/if}
                  {:else if p.publicEndpoints === 0}
                    <span class="muted">local only</span>
                  {:else}
                    <span class="muted" title={report?.ownerData ? "Not in the owner database" : "Install the owner database in Settings to see countries and organisations"}>unknown</span>
                  {/if}
                </td>
                <td class="ell" title={p.owners.map((o) => `${o.name}: ${formatBytes(o.bytes)}`).join("\n")}>
                  {#if p.owners.length}
                    {names(p.owners, 2).join(", ")}{#if p.ownerCount > 2}<span class="muted">&nbsp;+{p.ownerCount - 2}</span>{/if}
                  {:else}
                    <span class="muted">–</span>
                  {/if}
                </td>
                <td>
                  <div class="chips">
                    {#each p.plaintext as u (u.transport + u.port)}
                      <span class="chip {u.certainty}" title={plainTitle(u)}>{u.service} <span class="num">{formatBytes(u.bytes)}</span></span>
                    {:else}
                      <span class="muted">–</span>
                    {/each}
                  </div>
                </td>
                <td>
                  {#if p.oldTls.length}
                    <span class="chip yes" title={p.oldTls.map((t) => `${t.server.name ?? t.server.ip}: ${t.version}`).join("\n")}>{p.oldTls[0].version} offered</span>
                  {:else if p.tlsHellos > 0}
                    <span class="muted" title="{p.tlsHellos} TLS connections seen, all offering TLS 1.2 or newer">current</span>
                  {:else}
                    <span class="muted">–</span>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>

  <section class="card block">
    <h2 class="card-title">
      Listening services <span class="count num">{report ? listeners.length : "–"}</span>
      <span class="sub">{report ? `${reachable} reachable from the network` : ""}</span>
    </h2>
    {#if report?.listenersError}
      <p class="none">Could not read the socket table: {report.listenersError}</p>
    {:else if listeners.length === 0}
      <p class="none">{report ? "No program is accepting connections." : " "}</p>
    {:else}
      <div class="scroll">
        <table class="t-listeners">
          <colgroup><col class="c-program" /><col class="c-port" /><col /><col class="c-reach" /><col class="c-bound" /></colgroup>
          <thead>
            <tr><th>Program</th><th class="r">Port</th><th>Usually</th><th>Reachable from</th><th>Bound to</th></tr>
          </thead>
          <tbody>
            {#each listeners as l (l.pid + ":" + l.port)}
              <tr>
                <td><span class="strong ell" title="{l.program} (PID {l.pid})">{l.program}</span></td>
                <td class="r num mono">{l.port}</td>
                <td class="ell">{#if l.service}{l.service}{:else}<span class="muted">–</span>{/if}</td>
                <td>
                  <span class="chip {l.reach === 'network' ? (l.sensitive ? 'yes' : 'net') : 'quiet'}" title={listenerTitle(l)}>
                    {l.reach === "network" ? "The network" : "This PC only"}
                  </span>
                </td>
                <td class="ell mono small" title={l.address}>{l.address}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>

  <section class="card block">
    <h2 class="card-title">
      Inbound connection attempts <span class="count num">{session ? session.inboundCount : "–"}</span>
      <span class="sub">who tried to connect to this PC</span>
    </h2>
    {#if !session}
      <p class="none">Needs an All traffic session.</p>
    {:else if inbound.length === 0}
      <p class="none">Nobody has tried to connect to this PC during the session.</p>
    {:else}
      <div class="scroll">
        <table class="t-inbound">
          <colgroup><col /><col class="c-where" /><col class="c-ports" /><col class="c-num" /><col class="c-num" /><col class="c-flag" /></colgroup>
          <thead>
            <tr>
              <th>From</th><th>Where</th><th>Ports tried</th>
              <th class="r" title="Connection requests received">Attempts</th>
              <th class="r" title="Requests a program on this PC accepted">Accepted</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {#each inbound as p (p.ip)}
              <tr>
                <td>
                  <div class="two">
                    <span class="strong ell" title={p.name ?? p.ip}>{p.name ?? p.ip}</span>
                    {#if p.name}<span class="muted small mono">{p.ip}</span>{/if}
                  </div>
                </td>
                <td class="ell" title={whoOwns(p.owner)}>{where(p.scope)}{#if p.owner}<span class="muted small">&nbsp;· {whoOwns(p.owner)}</span>{/if}</td>
                <td class="ell mono small" title={p.ports.join(", ")}>
                  {p.ports.slice(0, 6).join(", ")}{#if p.portCount > 6}<span class="muted">&nbsp;+{p.portCount - 6}</span>{/if}
                </td>
                <td class="r num">{formatCount(p.attempts)}</td>
                <td class="r num" title={p.acceptedPorts.length ? `Accepted on ${p.acceptedPorts.join(", ")}` : ""}>{formatCount(p.accepted)}</td>
                <td>{#if p.scan}<span class="chip credentials" title="{p.portCount} different ports tried: looks like a scan">Scan</span>{/if}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>

  <section class="card block">
    <h2 class="card-title">DNS <span class="sub">the servers asked for names</span></h2>
    {#if !session}
      <p class="none">Needs an All traffic session.</p>
    {:else}
      {#if dnsServers.length === 0}
        <p class="none">No unencrypted DNS question seen yet.</p>
      {:else}
        <div class="scroll">
          <table class="t-dns">
            <colgroup><col /><col class="c-where" /><col class="c-num" /><col class="c-num" /><col class="c-num" /><col class="c-num" /><col class="c-ms" /><col class="c-ms" /></colgroup>
            <thead>
              <tr>
                <th>Server</th><th>Where</th>
                <th class="r">Questions</th>
                <th class="r" title="Questions never answered">No answer</th>
                <th class="r" title="Answers saying the server could not or would not resolve">Errors</th>
                <th class="r" title="'No such name' answers: normal">No name</th>
                <th class="r">Average</th><th class="r">Slowest</th>
              </tr>
            </thead>
            <tbody>
              {#each dnsServers as d (d.ip)}
                <tr>
                  <td>
                    <div class="two">
                      <span class="strong ell" title={d.name ?? d.ip}>{d.name ?? d.ip}</span>
                      {#if d.name}<span class="muted small mono">{d.ip}</span>{/if}
                    </div>
                  </td>
                  <td class="ell" title={whoOwns(d.owner)}>{where(d.scope)}{#if d.owner}<span class="muted small">&nbsp;· {whoOwns(d.owner)}</span>{/if}</td>
                  <td class="r num">{formatCount(d.queries)}</td>
                  <td class="r num" class:bad={d.unanswered > 0}>{formatCount(d.unanswered)}</td>
                  <td class="r num" class:bad={d.failed > 0}>{formatCount(d.failed)}</td>
                  <td class="r num">{formatCount(d.nxdomain)}</td>
                  <td class="r num">{ms(d.avgMs)}</td>
                  <td class="r num">{ms(d.maxMs)}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
      <p class="foot">
        {#if dnsServers.length}Questions to these servers travel unencrypted (UDP port 53).{/if}
        {#if session.dns.overHttps.length}
          Encrypted DNS over HTTPS seen with {session.dns.overHttps.map((e) => e.name ?? e.ip).join(", ")}.
        {/if}
        {#if session.dns.overTls.length}
          Encrypted DNS over TLS seen with {session.dns.overTls.map((e) => e.name ?? e.ip).join(", ")}.
        {/if}
        {#if !session.dns.overHttps.length && !session.dns.overTls.length}No encrypted DNS seen.{/if}
      </p>
    {/if}
  </section>

  <section class="card block">
    <h2 class="card-title">VPN <span class="sub">tunnels, and what leaves outside them</span></h2>
    {#if !vpn}
      <p class="none">&nbsp;</p>
    {:else if vpn.error}
      <p class="none">Could not list the interfaces: {vpn.error}</p>
    {:else}
      <div class="routes">
        {@render route("IPv4 to the Internet", vpn.ipv4)}
        {@render route("IPv6 to the Internet", vpn.ipv6)}
      </div>
      {#if vpn.tunnels.length === 0}
        <p class="none">No VPN tunnel is up.</p>
      {:else}
        <div class="scroll">
          <table class="t-vpn">
            <colgroup><col class="c-tunnel" /><col class="c-kind" /><col /></colgroup>
            <thead>
              <tr><th>Tunnel</th><th>Kind</th><th>Addresses</th></tr>
            </thead>
            <tbody>
              {#each vpn.tunnels as t (t.name)}
                <tr>
                  <td><span class="strong ell" title={t.name}>{t.description}</span></td>
                  <td class="ell">{t.kind}</td>
                  <td class="ell mono small" title={t.addresses.join(", ")}>{t.addresses.join(", ")}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
        {#if vpn.measured}
          <div class="sides">
            <div class="side"><span class="k">Inside the tunnel</span><b class="num">{formatBytes(vpn.insideBytes)}</b></div>
            <div class="side"><span class="k">Outside it</span><b class="num">{formatBytes(vpn.outsideBytes)}</b></div>
            <div class="side wide" title="The busiest Internet address outside the tunnel: the tunnel's own encrypted packets travel to the VPN server">
              <span class="k">Of which to the VPN server (most likely)</span>
              <b class="ell">
                {#if vpn.carrier}<span class="mono">{vpn.carrier.name ?? vpn.carrier.ip}</span> <span class="muted num">{formatBytes(vpn.carrier.bytes)}</span>{:else}–{/if}
              </b>
            </div>
          </div>
          <p class="foot">
            {#if vpn.outsideCount > 0}
              {vpn.outsideCount} other Internet address{vpn.outsideCount === 1 ? " was" : "es were"} reached outside the tunnel:
              {vpn.outside.map((e) => `${e.name ?? e.ip} (${formatBytes(e.bytes)})`).join(", ")}{vpn.outsideCount > vpn.outside.length ? "…" : "."}
            {:else}
              Nothing but the VPN server was reached outside the tunnel.
            {/if}
            {#if vpn.dnsOutside > 0}{formatCount(vpn.dnsOutside)} unencrypted DNS question{vpn.dnsOutside === 1 ? "" : "s"} left outside it.{/if}
          </p>
        {:else}
          <p class="foot">What goes inside and outside the tunnel is measured by an All traffic session started while the tunnel is up.</p>
        {/if}
      {/if}
    {/if}
  </section>

  <section class="card block">
    <h2 class="card-title">
      Local network <span class="sub">devices remembered between scans</span>
      <span class="spacer"></span>
      {#if report?.lans.length}
        {#if confirmForget}
          <span class="confirm">Forget every device? <button type="button" class="link" onclick={forget}>Forget</button> <button type="button" class="link" onclick={() => (confirmForget = false)}>Keep</button></span>
        {:else}
          <button type="button" class="link" disabled={security.forgetting} onclick={() => (confirmForget = true)}>Forget devices</button>
        {/if}
      {/if}
    </h2>
    {#if !report?.lans.length}
      <p class="none">
        {#if report}
          No scan yet. A scan on the Map page lists the devices; the next one says who is new and whether the gateway is still the same.
          <button type="button" class="link" onclick={() => nav.go("map")}>Go to Map</button>
        {/if}
      </p>
    {:else}
      <div class="scroll">
        <table class="t-lan">
          <colgroup><col class="c-net" /><col class="c-gw" /><col class="c-dhcp" /><col class="c-count" /><col class="c-count" /><col class="c-date" /><col /></colgroup>
          <thead>
            <tr>
              <th>Network</th><th>Gateway</th>
              <th title="The DHCP servers that answered the latest scan's question">DHCP server</th>
              <th class="r">Devices</th><th class="r">Scans</th><th>Last scan</th><th title="Since the scan before">Changes</th>
            </tr>
          </thead>
          <tbody>
            {#each report.lans as lan (lan.network + lan.gatewayMac)}
              <tr>
                <td class="mono">{lan.network}</td>
                <td>
                  <div class="two">
                    <span class="mono ell">{lan.gateway ?? "–"}</span>
                    <span class="muted small mono">{lan.gatewayMac ?? "did not answer"}</span>
                  </div>
                </td>
                <td>
                  <div class="chips">
                    {#if lan.dhcp.length === 0}
                      <span class="muted" title="No DHCP server answered the scan's question">none answered</span>
                    {:else if lan.dhcp.length === 1}
                      <span class="mono small ell" title={dhcpTitle(lan.dhcp[0])}>{lan.dhcp[0].ip}</span>
                    {:else}
                      <span class="chip credentials" title={lan.dhcp.map(dhcpTitle).join("\n")}>{lan.dhcp.length} servers</span>
                    {/if}
                  </div>
                </td>
                <td class="r num">{lan.devices}</td>
                <td class="r num">{lan.scans}</td>
                <td class="num">{dateFmt.format(new Date(lan.lastScan))}</td>
                <td>
                  <div class="chips">
                    {#if lan.gatewayWas}
                      <span class="chip credentials" title="The gateway answered from {lan.gatewayWas} before">Gateway changed</span>
                    {/if}
                    {#if lan.newDevices.length}
                      <span class="chip net" title={lan.newDevices.map((d) => `${d.hostname ?? d.vendor ?? "Unknown"} · ${d.ip} · ${d.mac}`).join("\n")}>
                        {lan.newDevices.length} new device{lan.newDevices.length === 1 ? "" : "s"}
                      </span>
                    {/if}
                    {#if !lan.gatewayWas && !lan.newDevices.length}<span class="muted">{lan.scans > 1 ? "no change" : "first scan"}</span>{/if}
                  </div>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      <p class="foot">
        Kept in a file on this PC only. <button type="button" class="link" onclick={() => nav.go("map")}>Scan again on the Map page</button>
      </p>
    {/if}
    {#if dhcpHeard.length}
      <p class="foot">DHCP servers heard answering during the session: {dhcpHeard.join(", ")}.</p>
    {/if}
  </section>
</div>

{#snippet route(label: string, r: Route)}
  <div class="route">
    <span class="k">{label}</span>
    <span class="chip {routeChip(r)}">{routeText(r)}</span>
    <span class="ell muted small" title={r.interface ?? ""}>{r.interface ?? ""}</span>
  </div>
{/snippet}

{#snippet finding(f: Finding)}
  <li class="finding {f.severity}">
    <button type="button" class="head" aria-expanded={!!open[f.id]} onclick={() => (open[f.id] = !open[f.id])}>
      <span class="sev">{SEVERITY[f.severity]}</span>
      <span class="what">
        <span class="title ell">{f.title}</span>
        <span class="subjects ell muted">{f.subjects.join(" · ") || " "}</span>
      </span>
      <svg class="chev" viewBox="0 0 16 16" aria-hidden="true"><path d="M4 6l4 4 4-4" /></svg>
    </button>
    {#if open[f.id]}
      <p class="detail">{f.detail}</p>
    {/if}
  </li>
{/snippet}

<style>
  .sec {
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .small {
    font-size: 11px;
  }
  .ell {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    min-width: 0;
  }
  button.link {
    padding: 0;
    border: 0;
    background: none;
    color: var(--accent-strong);
    font: inherit;
    text-decoration: underline;
    cursor: pointer;
  }
  button.link:disabled {
    opacity: 0.5;
    cursor: default;
  }

  /* ── summary ── */
  .summary {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 12px 16px;
  }
  .tally {
    flex: none;
    width: 96px;
    height: 54px;
    display: flex;
    flex-direction: column;
    justify-content: center;
    padding: 0 12px;
    border: 1px solid var(--border);
    border-left-width: 3px;
    border-radius: var(--radius);
    background: var(--surface-2);
  }
  .tally b {
    font-size: 20px;
    line-height: 1.1;
  }
  .tally span {
    font-size: 11px;
    color: var(--text-secondary);
  }
  .tally.warning {
    border-left-color: var(--danger);
  }
  .tally.notice {
    border-left-color: var(--level-busy);
  }
  .tally.info {
    border-left-color: var(--accent);
  }
  .tally.zero {
    border-left-color: var(--border-strong);
  }
  .tally.zero b {
    color: var(--text-muted);
  }
  .state {
    flex: 1;
    min-width: 0;
    margin: 0 0 0 8px;
    font-size: 13px;
    line-height: 1.45;
    color: var(--text-secondary);
  }
  .state b {
    color: var(--text-primary);
  }

  /* ── cards ── */
  .block {
    padding: 14px 16px 12px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .card-title {
    display: flex;
    align-items: baseline;
    gap: 8px;
  }
  .count {
    color: var(--text-muted);
    font-weight: 500;
  }
  .sub {
    font-size: 12px;
    font-weight: 400;
    letter-spacing: 0;
    text-transform: none;
    color: var(--text-muted);
  }
  .spacer {
    flex: 1;
  }
  .card-title .link,
  .confirm {
    font-size: 12px;
    font-weight: 400;
    letter-spacing: 0;
    text-transform: none;
  }
  .confirm {
    color: var(--text-secondary);
  }
  .none {
    margin: 0;
    min-height: 20px;
    font-size: 13px;
    color: var(--text-muted);
  }
  .foot {
    margin: 0;
    font-size: 12px;
    color: var(--text-muted);
  }

  /* ── findings ── */
  .findings {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
  }
  .finding {
    border-top: 1px solid var(--border);
  }
  .finding:first-child {
    border-top: 0;
  }
  .head {
    width: 100%;
    height: 48px;
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 0 4px;
    border: 0;
    background: none;
    color: inherit;
    font: inherit;
    text-align: left;
    cursor: pointer;
  }
  .head:hover .title {
    color: var(--accent-strong);
  }
  .sev {
    flex: none;
    width: 72px;
    height: 22px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 600;
    border: 1px solid transparent;
  }
  .warning .sev {
    color: var(--danger);
    background: var(--danger-wash);
    border-color: color-mix(in srgb, var(--danger) 45%, transparent);
  }
  .notice .sev {
    color: var(--level-busy);
    background: color-mix(in srgb, var(--level-busy) 12%, transparent);
    border-color: color-mix(in srgb, var(--level-busy) 40%, transparent);
  }
  .info .sev {
    color: var(--accent-strong);
    background: var(--accent-wash);
    border-color: color-mix(in srgb, var(--accent) 40%, transparent);
  }
  .what {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 1px;
  }
  .title {
    font-size: 13px;
    font-weight: 600;
    color: var(--text-primary);
  }
  .subjects {
    font-size: 12px;
    min-height: 15px;
  }
  .chev {
    flex: none;
    width: 14px;
    height: 14px;
    fill: none;
    stroke: var(--text-muted);
    stroke-width: 1.6;
    stroke-linecap: round;
    stroke-linejoin: round;
    transition: transform 120ms ease;
  }
  .head[aria-expanded="true"] .chev {
    transform: rotate(180deg);
  }
  .detail {
    margin: 0 4px 12px 88px;
    max-width: 78ch;
    font-size: 12.5px;
    line-height: 1.5;
    color: var(--text-secondary);
  }

  /* ── tables ── */
  .scroll {
    max-height: 372px;
    overflow-y: auto;
    scrollbar-gutter: stable;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    table-layout: fixed;
    font-size: 13px;
  }
  th {
    position: sticky;
    top: 0;
    z-index: 1;
    background: var(--surface-1);
    text-align: left;
    font-size: 11px;
    font-weight: 500;
    letter-spacing: 0.03em;
    text-transform: uppercase;
    color: var(--text-muted);
    padding: 0 10px 6px;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }
  td {
    height: 40px;
    padding: 0 10px;
    border-bottom: 1px solid var(--border);
    vertical-align: middle;
    color: var(--text-secondary);
  }
  tbody tr:last-child td {
    border-bottom: 0;
  }
  .r {
    text-align: right;
  }
  .strong {
    display: block;
    color: var(--text-primary);
    font-weight: 600;
  }
  .strong.unknown {
    font-style: italic;
    font-weight: 500;
    color: var(--text-secondary);
  }
  .two {
    display: flex;
    flex-direction: column;
    min-width: 0;
    line-height: 1.25;
  }
  td.bad {
    color: var(--level-busy);
  }
  col.c-program {
    width: 170px;
  }
  col.c-num {
    width: 78px;
  }
  col.c-countries {
    width: 112px;
  }
  col.c-plain {
    width: 190px;
  }
  col.c-tls {
    width: 112px;
  }
  col.c-port {
    width: 72px;
  }
  col.c-reach {
    width: 130px;
  }
  col.c-bound {
    width: 200px;
  }
  col.c-where {
    width: 176px;
  }
  col.c-ports {
    width: 190px;
  }
  col.c-flag {
    width: 64px;
  }
  col.c-ms {
    width: 78px;
  }
  col.c-net {
    width: 128px;
  }
  col.c-dhcp {
    width: 116px;
  }
  col.c-tunnel {
    width: 260px;
  }
  col.c-kind {
    width: 180px;
  }

  /* ── VPN ── */
  .routes {
    display: flex;
    flex-direction: column;
  }
  .route {
    display: flex;
    align-items: center;
    gap: 10px;
    height: 30px;
    font-size: 13px;
    color: var(--text-secondary);
  }
  .route .k {
    flex: none;
    width: 150px;
  }
  .route .chip {
    width: 112px;
    justify-content: center;
  }
  .sides {
    display: flex;
    gap: 10px;
  }
  .side {
    flex: none;
    width: 150px;
    height: 54px;
    display: flex;
    flex-direction: column;
    justify-content: center;
    gap: 2px;
    padding: 0 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--surface-2);
    min-width: 0;
  }
  .side.wide {
    flex: 1;
    width: auto;
  }
  .side .k {
    font-size: 11px;
    color: var(--text-muted);
  }
  .side b {
    font-size: 14px;
    color: var(--text-primary);
  }
  col.c-date {
    width: 136px;
  }
  col.c-gw {
    width: 150px;
  }
  col.c-count {
    width: 60px;
  }

  /* ── chips ── */
  .chips {
    display: flex;
    gap: 5px;
    overflow: hidden;
    white-space: nowrap;
  }
  .chip {
    flex: none;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    height: 20px;
    padding: 0 7px;
    border-radius: 6px;
    border: 1px solid var(--border-strong);
    background: var(--surface-2);
    font-size: 11px;
    color: var(--text-secondary);
  }
  .chip.credentials {
    color: var(--danger);
    border-color: color-mix(in srgb, var(--danger) 45%, transparent);
    background: var(--danger-wash);
  }
  .chip.yes {
    color: var(--level-busy);
    border-color: color-mix(in srgb, var(--level-busy) 40%, transparent);
    background: color-mix(in srgb, var(--level-busy) 10%, transparent);
  }
  .chip.net {
    color: var(--accent-strong);
    border-color: color-mix(in srgb, var(--accent) 40%, transparent);
    background: var(--accent-wash);
  }
  .chip.quiet,
  .chip.maybe {
    color: var(--text-muted);
  }
</style>

<script lang="ts">
  /**
   * Network map: this PC → gateway → routers → endpoints, from traceroutes.
   * Node size = traffic, endpoint colour = busyness level, edge width = traffic
   * through it. Hover for details; click an endpoint to focus it, a router to
   * highlight every route through it. Drag to pan, Ctrl + wheel (or pinch)
   * to zoom, so the page still scrolls over the map.
   *
   * Readability: long edges bend around the nodes of the columns they
   * cross (the layout gives each one its bend points); labels sit on a halo
   * of the background colour, so an edge never strikes through a name;
   * router labels appear when zoomed in or on the highlighted route;
   * layout changes (new traces) glide instead of jumping; Fit, zoom
   * and Find animate the view; the highlighted route shows its traffic
   * flowing (only while pointing, and never with reduced motion).
   */
  import { onDestroy, onMount, untrack } from "svelte";
  import { routes } from "$lib/stores/routes.svelte";
  import { settings } from "$lib/stores/settings.svelte";
  import { buildGraph, curvePath, layout, type GEdge, type GNode, type Layout, type MapEndpoint } from "$lib/utils/netgraph";
  import { formatBytes, rateText } from "$lib/utils/format";
  import { countryName, ownerText } from "$lib/utils/geo";
  import type { Units } from "$lib/api/types";

  interface Props {
    endpoints: MapEndpoint[];
    units: Units;
    focus: string | null;
    onfocus: (ip: string) => void;
    /** Show at most this many endpoints (by total traffic); default: the setting. */
    limit?: number;
  }
  let { endpoints, units, focus, onfocus, limit }: Props = $props();
  const maxShown = $derived(limit ?? (settings.mapLimit || 150));
  const reduced = typeof matchMedia !== "undefined" && matchMedia("(prefers-reduced-motion: reduce)").matches;

  onMount(() => {
    routes.load();
  });

  const shown = $derived.by(() => {
    const sorted = [...endpoints].sort((a, b) => b.totalBytes - a.totalBytes);
    const top = sorted.slice(0, maxShown);
    const f = focus ? sorted.find((e) => e.ip === focus) : null;
    if (f && !top.includes(f)) top.push(f);
    return top;
  });

  const graph = $derived(buildGraph(shown, routes.traces, routes.context, { group: settings.mapGroup, neighbors: settings.mapNeighbors }));

  // Layout only changes with the graph's structure, so nodes stay put as numbers move.
  let cached: { key: string; lay: Layout } | null = null;
  // Long routes: narrow the columns to fit the width before scaling down.
  const colW = $derived.by(() => {
    const columns = new Set(graph.nodes.map((n) => n.depth)).size;
    return Math.round(Math.max(110, Math.min(170, (vw - 320) / Math.max(1, columns - 1))) / 10) * 10;
  });
  const lay = $derived.by(() => {
    const key = `${graph.structureKey}:${colW}`;
    if (cached?.key !== key) {
      const bytes = new Map(shown.map((e) => [e.ip, e.totalBytes]));
      const rank = (n: GNode) => (n.endpoint ? n.endpoint.totalBytes : n.via.reduce((s, ip) => s + (bytes.get(ip) ?? 0), 0));
      cached = { key, lay: layout(graph, rank, colW) };
    }
    return cached.lay;
  });

  const maxBytes = $derived(Math.max(1, ...shown.map((e) => e.totalBytes)));
  const bytesOf = $derived(new Map(shown.map((e) => [e.ip, e.totalBytes])));
  const viaBytes = (via: string[]) => via.reduce((s, ip) => s + (bytesOf.get(ip) ?? 0), 0);

  function radius(n: GNode): number {
    switch (n.kind) {
      case "self":
        return 11;
      case "gateway":
        return 8;
      case "endpoint":
        return 5 + 9 * Math.sqrt((n.endpoint?.totalBytes ?? 0) / maxBytes);
      case "network":
        return 7;
      case "untraced":
        return 6;
      default:
        return 5;
    }
  }

  // ── highlight ──
  let hover = $state<GNode | null>(null);
  let pinned = $state<string | null>(null);
  const highlight = $derived.by(() => {
    const n = hover ?? (pinned ? graph.nodes.find((x) => x.id === pinned) : null) ?? (focus ? graph.nodes.find((x) => x.id === `ep:${focus}`) : null);
    if (!n || n.kind === "self") return null;
    return new Set(n.endpoint ? [n.endpoint.ip] : n.via);
  });
  const lit = (via: string[]) => !highlight || via.some((ip) => highlight.has(ip));

  // ── node positions: glide to a new layout instead of jumping ──
  let drawn = $state.raw(new Map<string, { x: number; y: number }>());
  let posAnim: number | null = null;
  $effect(() => {
    const target = lay.pos;
    untrack(() => {
      const from = drawn;
      if (posAnim) cancelAnimationFrame(posAnim);
      if (from.size === 0 || reduced) {
        drawn = target;
        return;
      }
      const t0 = performance.now();
      const step = (now: number) => {
        const p = Math.min(1, (now - t0) / 450);
        const e = 1 - Math.pow(1 - p, 3);
        const m = new Map<string, { x: number; y: number }>();
        for (const [id, b] of target) {
          const a = from.get(id);
          m.set(id, a ? { x: a.x + (b.x - a.x) * e, y: a.y + (b.y - a.y) * e } : b);
        }
        drawn = m;
        posAnim = p < 1 ? requestAnimationFrame(step) : null;
      };
      posAnim = requestAnimationFrame(step);
    });
  });

  // ── pan / zoom ──
  let viewport: HTMLDivElement;
  let vw = $state(900);
  let vh = $state(520);
  let k = $state(1);
  let tx = $state(0);
  let ty = $state(0);
  let fitted = "";
  let viewAnim: number | null = null;
  /** Move the view to (nk, ntx, nty), eased over ~300 ms. */
  function animateView(nk: number, ntx: number, nty: number) {
    if (viewAnim) cancelAnimationFrame(viewAnim);
    if (reduced) {
      [k, tx, ty] = [nk, ntx, nty];
      return;
    }
    const [k0, x0, y0, t0] = [k, tx, ty, performance.now()];
    const step = (now: number) => {
      const p = Math.min(1, (now - t0) / 320);
      const e = 1 - Math.pow(1 - p, 3);
      k = k0 + (nk - k0) * e;
      tx = x0 + (ntx - x0) * e;
      ty = y0 + (nty - y0) * e;
      viewAnim = p < 1 ? requestAnimationFrame(step) : null;
    };
    viewAnim = requestAnimationFrame(step);
  }
  /** Smallest zoom Fit uses: below it labels can't be read; pan for the rest. */
  const READABLE = 0.75;
  function fit() {
    const sw = (vw - 20) / lay.width;
    const sh = (vh - 20) / lay.height;
    const nk = Math.min(1.2, sw, Math.max(sh, Math.min(sw, READABLE)));
    const ty0 = lay.height * nk > vh - 20 ? 10 : (vh - lay.height * nk) / 2;
    animateView(nk, (vw - lay.width * nk) / 2, ty0);
  }
  function zoomBy(f: number) {
    const nk = Math.min(3, Math.max(0.25, k * f));
    const [cx, cy] = [vw / 2, vh / 2];
    animateView(nk, cx - ((cx - tx) * nk) / k, cy - ((cy - ty) * nk) / k);
  }
  /** Frame an endpoint's whole route (or just the node when it has none). */
  function frameRoute(ip: string) {
    const pts = graph.nodes
      .filter((n) => n.kind === "self" || n.endpoint?.ip === ip || n.via.includes(ip))
      .map((n) => lay.pos.get(n.id))
      .filter((p): p is { x: number; y: number } => !!p);
    if (!pts.length) return;
    const [x0, x1] = [Math.min(...pts.map((p) => p.x)), Math.max(...pts.map((p) => p.x)) + 220];
    const [y0, y1] = [Math.min(...pts.map((p) => p.y)) - 30, Math.max(...pts.map((p) => p.y)) + 30];
    const nk = Math.max(0.6, Math.min(1.2, (vw - 40) / (x1 - x0), (vh - 40) / (y1 - y0)));
    animateView(nk, vw / 2 - ((x0 + x1) / 2) * nk, vh / 2 - ((y0 + y1) / 2) * nk);
  }
  onDestroy(() => {
    if (viewAnim) cancelAnimationFrame(viewAnim);
    if (posAnim) cancelAnimationFrame(posAnim);
    clearTimeout(hintTimer);
  });
  $effect(() => {
    // Re-fit when the column count changes (new hops discovered).
    const sig = `${lay.columns}:${Math.round(lay.height / 100)}:${lay.width}`;
    if (sig !== fitted && vw > 0) {
      fitted = sig;
      fit();
    }
  });
  // Plain wheel scrolls the page; Ctrl/⌘ + wheel (and trackpad pinch) zooms.
  let wheelHint = $state(false);
  let hintTimer: ReturnType<typeof setTimeout> | undefined;
  function onWheel(e: WheelEvent) {
    if (!(e.ctrlKey || e.metaKey)) {
      wheelHint = true;
      clearTimeout(hintTimer);
      hintTimer = setTimeout(() => (wheelHint = false), 1400);
      return;
    }
    e.preventDefault();
    if (viewAnim) cancelAnimationFrame(viewAnim);
    const rect = viewport.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    const nk = Math.min(3, Math.max(0.25, k * Math.exp(-e.deltaY * 0.0015)));
    tx = mx - ((mx - tx) * nk) / k;
    ty = my - ((my - ty) * nk) / k;
    k = nk;
  }
  let drag: { x: number; y: number; tx: number; ty: number } | null = null;
  function onDown(e: PointerEvent) {
    if ((e.target as Element).closest(".node")) return;
    drag = { x: e.clientX, y: e.clientY, tx, ty };
    (e.currentTarget as Element).setPointerCapture(e.pointerId);
    pinned = null;
  }
  function onMove(e: PointerEvent) {
    if (!drag) return;
    tx = drag.tx + e.clientX - drag.x;
    ty = drag.ty + e.clientY - drag.y;
  }

  function clickNode(n: GNode) {
    if (n.endpoint) onfocus(n.endpoint.ip);
    else pinned = pinned === n.id ? null : n.id;
  }

  // ── find ──
  let find = $state("");
  const matches = $derived.by(() => {
    const q = find.trim().toLowerCase();
    if (!q) return [];
    return shown.filter((e) => e.ip.includes(q) || (e.name ?? "").toLowerCase().includes(q) || ownerText(e.owner).includes(q));
  });
  let matchIdx = 0;
  function goFind() {
    if (!matches.length) return;
    const m = matches[matchIdx++ % matches.length];
    pinned = `ep:${m.ip}`;
    frameRoute(m.ip);
  }

  // ── what to label ──
  /** Routers / silent hops: when zoomed in, hovered, or on the highlighted route. */
  const showMinor = (n: GNode) => k >= 0.95 || hover?.id === n.id || (!!highlight && lit(n.via));
  const showNetwork = (n: GNode) => k >= 0.6 || hover?.id === n.id || (!!highlight && lit(n.via));
  /** Traffic flow on the highlighted route, only while pointing at something
      (it repaints the map every frame, so never as a lasting state). */
  const flowing = $derived(!reduced && hover !== null && highlight !== null);

  // ── tracing ──
  const untraced = $derived(shown.filter((e) => !routes.traces[e.ip] && e.scope === "public"));
  const busy = $derived(routes.pending.length);
  function traceTop() {
    routes.traceMany(untraced.slice(0, 10).map((e) => e.ip));
  }
  function retraceAll() {
    routes.traceMany(shown.filter((e) => routes.traces[e.ip]).map((e) => e.ip), true);
  }

  type Pt = { x: number; y: number };
  /** The points an edge is drawn through: its ends and, for a long edge, its
      bend points (just the ends while those glide into place). */
  function routePoints(e: GEdge): Pt[] | null {
    const a = drawn.get(e.from);
    const b = drawn.get(e.to);
    if (!a || !b) return null;
    const pts = (lay.routes.get(e.id) ?? []).map((id) => drawn.get(id));
    return pts.length >= 2 && pts.every((p) => p) ? (pts as Pt[]) : [a, b];
  }
  /** Where an edge's label goes: the middle of its middle stretch. */
  function midPoint(pts: Pt[]): Pt {
    const i = Math.floor((pts.length - 1) / 2);
    return { x: (pts[i].x + pts[i + 1].x) / 2, y: (pts[i].y + pts[i + 1].y) / 2 };
  }
  const trunc = (s: string, n: number) => (s.length > n ? s.slice(0, n - 1) + "…" : s);

  // Routers, networks and the gateway are named on one line above the node:
  // edges leave a node sideways, so the name never sits on its own edge, and
  // it is cut to the column width so two neighbours' names don't run together.
  const labelChars = $derived(Math.max(10, Math.floor((colW - 12) / 5.6)));
  function minorLabel(n: GNode): [string, string] {
    const extra = n.kind === "untraced" ? n.sub : n.rttMs !== null ? `${n.rttMs} ms` : "";
    const tail = extra ? ` · ${extra}` : "";
    return [trunc(n.label, Math.max(6, labelChars - tail.length)), tail];
  }
</script>

<div class="map">
  <div class="toolbar">
    <div class="actions">
      <button type="button" class="primary" onclick={traceTop} disabled={untraced.length === 0}>
        Trace top {Math.min(10, untraced.length) || ""}
      </button>
      <button type="button" onclick={() => routes.traceMany(untraced.map((e) => e.ip))} disabled={untraced.length === 0}>Trace all shown</button>
      <button type="button" onclick={retraceAll} disabled={graph.traced === 0 || busy > 0}>Re-trace</button>
    </div>
    <div class="nav">
      <input
        class="find"
        bind:value={find}
        placeholder="Find endpoint…"
        spellcheck="false"
        aria-label="Find an endpoint on the map"
        onkeydown={(e) => e.key === "Enter" && goFind()}
      />
      {#if find.trim()}<span class="muted small">{matches.length} found</span>{/if}
      <select bind:value={settings.mapLimit} aria-label="Endpoints shown" title="Endpoints shown (busiest by traffic)">
        <option value={10}>Top 10</option>
        <option value={20}>Top 20</option>
        <option value={40}>Top 40</option>
        <option value={0}>All</option>
      </select>
      <div class="zoom" role="group" aria-label="Zoom">
        <button type="button" onclick={() => zoomBy(1 / 1.3)} aria-label="Zoom out">−</button>
        <button type="button" onclick={fit}>Fit</button>
        <button type="button" onclick={() => zoomBy(1.3)} aria-label="Zoom in">+</button>
      </div>
    </div>
    <div class="toggles">
      <label><input type="checkbox" checked={settings.mapGroup} onchange={(e) => (settings.mapGroup = (e.currentTarget as HTMLInputElement).checked)} /> Group by network</label>
      <label><input type="checkbox" checked={settings.mapNeighbors} onchange={(e) => { settings.mapNeighbors = (e.currentTarget as HTMLInputElement).checked; routes.refreshContext(); }} /> LAN devices</label>
    </div>
  </div>
  <p class="status">
    {graph.traced} of {shown.length} endpoint{shown.length === 1 ? "" : "s"} traced{#if busy} · <span class="spin"></span> tracing {busy}…{/if}
    <span class="muted">· Traces send a few ICMP probes per hop (like tracert).</span>
    {#if routes.error}<span class="err">{routes.error}</span>{/if}
  </p>

  <div
    class="viewport"
    bind:this={viewport}
    bind:clientWidth={vw}
    bind:clientHeight={vh}
    style:height="{Math.round(Math.min(720, Math.max(260, lay.height * READABLE + 40)))}px"
    onwheel={onWheel}
    onpointerdown={onDown}
    onpointermove={onMove}
    onpointerup={() => (drag = null)}
    role="application"
    aria-label="Network map"
  >
    {#if shown.length === 0}
      <p class="empty">No traffic yet.</p>
    {:else}
      <svg width={vw} height={vh}>
        <g transform="translate({tx} {ty}) scale({k})">
          {#each graph.edges as e (e.id)}
            {@const pts = routePoints(e)}
            {#if pts}
              {@const w = 1 + 4 * Math.sqrt(viaBytes(e.via) / maxBytes)}
              {@const on = !!highlight && lit(e.via)}
              {@const d = curvePath(pts)}
              <path {d} class="edge" class:dashed={e.dashed} class:lit={on} class:dim={!lit(e.via)} stroke-width={w} />
              {#if on && flowing && !e.dashed}
                <path {d} class="flow" stroke-width={Math.max(1.5, w * 0.6)} />
              {/if}
              {#if e.label && on}
                {@const m = midPoint(pts)}
                <text x={m.x} y={m.y - 4} class="edge-label" text-anchor="middle">{e.label}</text>
              {/if}
            {/if}
          {/each}

          {#each graph.nodes as n (n.id)}
            {@const p = drawn.get(n.id)}
            {#if p}
              {@const r = radius(n)}
              {@const dim = n.kind !== "self" && !lit(n.endpoint ? [n.endpoint.ip] : n.via)}
              <g
                class="node {n.kind}"
                class:dim
                class:focused={n.endpoint?.ip === focus}
                transform="translate({p.x} {p.y})"
                onpointerenter={() => (hover = n)}
                onpointerleave={() => (hover = null)}
                onclick={() => clickNode(n)}
                ondblclick={() => n.endpoint && frameRoute(n.endpoint.ip)}
                onkeydown={(ev) => ev.key === "Enter" && clickNode(n)}
                role="button"
                tabindex="0"
                aria-label={n.label}
              >
                {#if n.kind === "gateway"}
                  <rect x={-r} y={-r} width={r * 2} height={r * 2} rx="3" transform="rotate(45)" />
                {:else if n.kind === "network"}
                  <rect x={-r - 3} y={-r} width={(r + 3) * 2} height={r * 2} rx={r} />
                {:else}
                  <circle {r} style:fill={n.endpoint ? `var(--level-${n.endpoint.level})` : null} />
                {/if}
                {#if n.kind === "self"}
                  <text y={r + 14} text-anchor="middle" class="label strong">This PC</text>
                {:else if n.kind === "endpoint"}
                  <text x={r + 6} y="4" class="label strong">{trunc(n.label, 32)}</text>
                  {#if n.endpoint && n.endpoint.rateBps > 0}<text x={r + 6} y="16" class="label tiny">{rateText(n.endpoint.rateBps, units)}</text>{/if}
                {:else if n.kind === "untraced" || (n.kind === "network" ? showNetwork(n) : n.kind === "gateway" || showMinor(n))}
                  {@const [name, tail] = minorLabel(n)}
                  <text y={-(n.kind === "gateway" ? r * 1.42 : r) - 5} text-anchor="middle" class="label">{name}<tspan class="tail">{tail}</tspan></text>
                {/if}
              </g>
            {/if}
          {/each}
        </g>
      </svg>

      {#if wheelHint}<div class="wheel-hint">Ctrl + wheel to zoom · drag to pan</div>{/if}
      {#if hover && drawn.get(hover.id)}
        {@const p = drawn.get(hover.id)!}
        <div class="tip" style:left="{tx + p.x * k + 16}px" style:top="{ty + p.y * k + 10}px" class:flip={tx + p.x * k > vw - 280}>
          <b>{hover.endpoint?.name ?? hover.label}</b>
          {#if hover.ip}<div class="mono">{hover.ip}</div>{/if}
          {#if hover.kind === "router" && hover.label.startsWith("…")}<div class="mono small">{routes.traces && Object.values(routes.traces).flatMap((t) => t.hops).find((h) => h.addr === hover?.ip)?.name}</div>{/if}
          {#if hover.kind === "gateway" && hover.members.length > 1}<div class="mono small">{hover.members.join(" · ")}</div>{/if}
          {#if hover.kind === "network"}<div>{hover.sub} · {hover.members.length} router{hover.members.length === 1 ? "" : "s"}</div>{/if}
          {#if hover.kind === "untraced"}<div>{hover.sub} with no route yet. <b>Trace top</b> or <b>Trace all shown</b> draws their routes; until then they share this stub.</div>{/if}
          {#if hover.kind === "silent"}<div>{hover.hops} hop{hover.hops === 1 ? "" : "s"} that didn't answer the probes ({hover.sub}): routers that drop ICMP, or rate-limit it</div>{/if}
          {#if hover.owner}<div>{hover.owner.org ?? ""}{hover.owner.asn ? ` (AS${hover.owner.asn})` : ""}{hover.owner.country ? ` · ${countryName(hover.owner.country)}` : ""}</div>{/if}
          {#if hover.ttl !== null && hover.kind !== "endpoint"}<div>Hop {hover.ttl}{hover.rttMs !== null ? ` · ${hover.rttMs} ms` : ""}{hover.answered ? ` · ${hover.answered} replies` : ""}</div>{/if}
          {#if hover.endpoint}
            {@const t = routes.traces[hover.endpoint.ip]}
            <div>{formatBytes(hover.endpoint.totalBytes)} total · {rateText(hover.endpoint.rateBps, units)} now</div>
            {@const looped = t ? new Set(t.hops.filter((h) => h.addr).map((h) => h.addr)).size < t.hops.filter((h) => h.addr).length : false}
            <div>{t ? `${t.hops.length} hop${t.hops.length === 1 ? "" : "s"} (traced${t.reached ? "" : ", not reached"}${looped ? ", routing loop" : ""})` : hover.endpoint.hops !== null ? `~${hover.endpoint.hops} hops (estimated)` : "not traced"}</div>
          {:else if hover.kind !== "self"}
            <div class="muted">{hover.via.length} endpoint{hover.via.length === 1 ? "" : "s"} through here · click to highlight</div>
          {/if}
        </div>
      {/if}
    {/if}
  </div>

  <div class="legend">
    <span><i class="sw self"></i>This PC</span>
    <span><i class="sw gw"></i>Gateway</span>
    <span><i class="sw router"></i>Router</span>
    {#if settings.mapGroup}<span><i class="sw net"></i>Network (ASN)</span>{/if}
    <span><i class="sw silent"></i>No reply</span>
    <span><i class="sw ep"></i>Endpoint (size = traffic, colour = level)</span>
    <span><i class="ln"></i>Traced</span>
    <span><i class="ln dash"></i>Not traced / estimated</span>
  </div>
</div>

<style>
  .map {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .toolbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
  }
  .actions,
  .toggles {
    display: flex;
    gap: 8px;
    align-items: center;
  }
  .toggles label {
    display: inline-flex;
    gap: 6px;
    align-items: center;
    font-size: 12px;
    color: var(--text-secondary);
    cursor: pointer;
  }
  .toggles input {
    accent-color: var(--accent);
  }
  button {
    height: 28px;
    padding: 0 10px;
    border-radius: 7px;
    border: 1px solid var(--border-strong);
    background: var(--surface-2);
    font-size: 12px;
    cursor: pointer;
  }
  button.primary {
    background: var(--accent);
    border-color: var(--accent);
    color: #04121a;
    font-weight: 600;
  }
  button:disabled {
    opacity: 0.45;
    cursor: default;
  }
  .status {
    margin: 0;
    font-size: 12px;
    color: var(--text-secondary);
  }
  .err {
    margin-left: 8px;
  }
  .spin {
    width: 9px;
    height: 9px;
    color: var(--accent);
  }
  .nav {
    display: flex;
    gap: 8px;
    align-items: center;
  }
  .find {
    height: 28px;
    width: 170px;
    padding: 0 9px;
    border-radius: 7px;
    border: 1px solid var(--border-strong);
    background: var(--surface-2);
    font-size: 12px;
    outline: none;
  }
  .find:focus {
    border-color: var(--accent);
  }
  select {
    height: 28px;
    padding: 0 6px;
    border-radius: 7px;
    border: 1px solid var(--border-strong);
    background: var(--surface-2);
    font-size: 12px;
  }
  .zoom {
    display: inline-flex;
  }
  .zoom button {
    border-radius: 0;
    min-width: 30px;
  }
  .zoom button:first-child {
    border-radius: 7px 0 0 7px;
  }
  .zoom button:last-child {
    border-radius: 0 7px 7px 0;
  }
  .zoom button + button {
    border-left: 0;
  }
  .small {
    font-size: 11px;
  }
  .wheel-hint {
    position: absolute;
    left: 50%;
    top: 12px;
    transform: translateX(-50%);
    padding: 5px 12px;
    border-radius: 999px;
    background: var(--surface-3);
    border: 1px solid var(--border-strong);
    font-size: 12px;
    color: var(--text-secondary);
    pointer-events: none;
  }
  .flow {
    fill: none;
    stroke: var(--accent-strong);
    stroke-linecap: round;
    stroke-dasharray: 2 10;
    animation: flow 0.9s linear infinite;
    pointer-events: none;
  }
  @keyframes flow {
    to {
      stroke-dashoffset: -12;
    }
  }
  .node {
    animation: appear 400ms ease-out;
  }
  @keyframes appear {
    from {
      opacity: 0;
    }
  }
  .viewport {
    position: relative;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background:
      radial-gradient(circle at 1px 1px, color-mix(in srgb, var(--border-strong) 60%, transparent) 1px, transparent 0) 0 0 / 22px 22px,
      var(--bg);
    overflow: hidden;
    cursor: grab;
    touch-action: none;
  }
  .viewport:active {
    cursor: grabbing;
  }
  .empty {
    padding: 20px;
    color: var(--text-muted);
  }
  svg {
    display: block;
  }
  .edge {
    fill: none;
    stroke: color-mix(in srgb, var(--accent) 45%, var(--border-strong));
    stroke-linecap: round;
    transition: opacity 150ms;
  }
  .edge.dashed {
    stroke-dasharray: 4 5;
    stroke: var(--border-strong);
    stroke-width: 1;
    opacity: 0.55;
  }
  .edge.dashed.lit {
    opacity: 1;
  }
  .edge.dashed.dim {
    opacity: 0.12;
  }
  .edge.lit {
    stroke: var(--accent-strong);
  }
  .dim {
    opacity: 0.18;
  }
  .edge-label {
    fill: var(--text-muted);
    font-size: 10px;
    paint-order: stroke;
    stroke: var(--bg);
    stroke-width: 3px;
    stroke-linejoin: round;
  }
  .node {
    cursor: pointer;
    transition: opacity 150ms;
  }
  .node circle,
  .node rect {
    stroke: var(--bg);
    stroke-width: 2;
  }
  .node.self circle {
    fill: var(--accent);
    stroke: var(--accent-strong);
    stroke-width: 3;
  }
  .node.gateway rect {
    fill: var(--accent-deep);
    stroke: var(--accent);
  }
  .node.router circle {
    fill: var(--surface-3);
    stroke: var(--accent);
    stroke-width: 1.5;
  }
  .node.network rect {
    fill: color-mix(in srgb, var(--accent) 30%, var(--surface-2));
    stroke: var(--accent);
    stroke-width: 1.5;
  }
  .node.silent circle {
    fill: var(--bg);
    stroke: var(--text-muted);
    stroke-dasharray: 2 2;
    stroke-width: 1.5;
  }
  .node.neighbor circle {
    fill: var(--surface-3);
    stroke: var(--text-muted);
  }
  .node.untraced circle {
    fill: var(--bg);
    stroke: var(--border-strong);
    stroke-dasharray: 3 3;
    stroke-width: 1.5;
  }
  .node.endpoint circle {
    stroke: var(--bg);
  }
  .node.focused circle {
    stroke: var(--text-primary);
    stroke-width: 2.5;
  }
  .node:focus-visible {
    outline: none;
  }
  .node:focus-visible circle,
  .node:focus-visible rect {
    stroke: var(--accent-strong);
    stroke-width: 3;
  }
  .label {
    fill: var(--text-secondary);
    font-size: 10.5px;
    pointer-events: none;
    /* A halo of the map's background: an edge passing behind a label is
       interrupted instead of striking through it. */
    paint-order: stroke;
    stroke: var(--bg);
    stroke-width: 3px;
    stroke-linejoin: round;
  }
  .label.strong {
    fill: var(--text-primary);
    font-size: 12px;
    font-weight: 600;
  }
  .label.tiny,
  .label .tail {
    fill: var(--text-muted);
    font-size: 10px;
  }
  .tip {
    position: absolute;
    z-index: 5;
    min-width: 200px;
    max-width: 300px;
    padding: 9px 11px;
    background: var(--surface-2);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius);
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.5);
    font-size: 12px;
    color: var(--text-secondary);
    pointer-events: none;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .tip .small {
    font-size: 10.5px;
    word-break: break-all;
  }
  .tip b {
    color: var(--text-primary);
    word-break: break-all;
  }
  .tip.flip {
    transform: translateX(calc(-100% - 32px));
  }
  .legend {
    display: flex;
    flex-wrap: wrap;
    gap: 14px;
    font-size: 11px;
    color: var(--text-muted);
  }
  .sw {
    display: inline-block;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    margin-right: 5px;
    vertical-align: -1px;
  }
  .sw.self {
    background: var(--accent);
  }
  .sw.gw {
    background: var(--accent-deep);
    border: 1px solid var(--accent);
    border-radius: 2px;
    transform: rotate(45deg);
  }
  .sw.router {
    background: var(--surface-3);
    border: 1.5px solid var(--accent);
  }
  .sw.net {
    width: 16px;
    border-radius: 6px;
    background: color-mix(in srgb, var(--accent) 30%, var(--surface-2));
    border: 1.5px solid var(--accent);
  }
  .sw.silent {
    border: 1.5px dashed var(--text-muted);
  }
  .sw.ep {
    background: var(--level-calm);
  }
  .ln {
    display: inline-block;
    width: 18px;
    height: 0;
    border-top: 2px solid var(--accent);
    margin-right: 5px;
    vertical-align: 3px;
  }
  .ln.dash {
    border-top: 2px dashed var(--border-strong);
  }
</style>

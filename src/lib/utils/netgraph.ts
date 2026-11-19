/**
 * Network map model: endpoints + traceroutes + LAN context → a layered graph.
 *
 * Columns are hop positions (this PC → gateway → routers → endpoints, which
 * all sit in the last column). Routers shared by several routes become one
 * node, so the tree shows where paths split. With `group`, consecutive hops
 * owned by the same network (ASN) collapse into one node.
 *
 * Runs of routers that didn't answer collapse into one "no reply" node
 * ("3 hops"), and silent hops at the end of a route into its last edge, so
 * long routes through firewalled networks stay readable.
 *
 * Untraced endpoints don't each get a line across the map: once some
 * route is traced they hang off one "not traced" stub next to the endpoint
 * column.
 *
 * Layout is a layered (Sugiyama-style) one, in four steps:
 * 1. columns: the longest way from this PC to each node, so edges point right;
 * 2. an edge that spans several columns gets a bend point in each column it
 *    crosses, so it takes a slot there instead of running through nodes;
 * 3. barycenter sweeps order each column to reduce crossings (the best
 *    ordering seen is kept);
 * 4. each node is pulled level with its neighbours, columns keeping their
 *    order and spacing, so chains run straight.
 * It depends only on the graph *structure*, so callers can cache it by
 * `structureKey` and keep nodes still while traffic numbers change.
 */
import type { AddrScope, Level, NetContext, Owner, TraceResult } from "../api/types";

export interface MapEndpoint {
  ip: string;
  name: string | null;
  owner: Owner | null;
  scope: AddrScope;
  level: Level;
  rateBps: number;
  totalBytes: number;
  /** Passive hop estimate (TTL). */
  hops: number | null;
}

export type NodeKind = "self" | "gateway" | "router" | "silent" | "network" | "endpoint" | "neighbor" | "untraced";

export interface GNode {
  id: string;
  kind: NodeKind;
  depth: number;
  label: string;
  sub: string;
  ip: string | null;
  owner: Owner | null;
  rttMs: number | null;
  /** Probes answered / sent (routers). */
  answered: string | null;
  ttl: number | null;
  /** Router addresses merged into a network node. */
  members: string[];
  /** Silent node: how many consecutive hops didn't answer. */
  hops: number;
  endpoint: MapEndpoint | null;
  /** Endpoints reached through this node. */
  via: string[];
}

export interface GEdge {
  id: string;
  from: string;
  to: string;
  /** Not traced (or the trace stopped before the endpoint). */
  dashed: boolean;
  label: string | null;
  /** Endpoint IPs whose path uses this edge. */
  via: string[];
  /** Silent hops folded into this edge (route ended without replies). */
  silent: number;
}

export interface Graph {
  nodes: GNode[];
  edges: GEdge[];
  structureKey: string;
  traced: number;
}

export interface GraphOptions {
  group: boolean;
  neighbors: boolean;
}

const LOCAL: AddrScope[] = ["private", "linkLocal", "loopback"];

export function shortName(name: string | null, ip: string | null): string {
  if (name) {
    const parts = name.split(".");
    // Machine-generated first labels (e.g. an IPv6 address spelled out in
    // hex) say nothing: show the operator's domain instead.
    if (parts[0].length > 16 && /^[0-9a-f-]+$/i.test(parts[0])) return "…" + parts.slice(-2).join(".");
    // Otherwise keep the most telling labels of long names.
    return parts.length > 4 ? parts.slice(0, 2).join(".") + "…" : name;
  }
  return ip ?? "?";
}

export function buildGraph(eps: MapEndpoint[], traces: Record<string, TraceResult>, ctx: NetContext | null, o: GraphOptions): Graph {
  const nodes = new Map<string, GNode>();
  const edges = new Map<string, GEdge>();
  const gateways = new Set((ctx?.gateways ?? []).map((g) => g.ip.toLowerCase()));
  // One box often has several addresses (IPv4, global IPv6, link-local):
  // the neighbour table's MAC tells us they're the same device.
  const macOf = new Map((ctx?.neighbors ?? []).map((n) => [n.ip.toLowerCase(), n.mac]));
  const gatewayMacs = new Set([...gateways].map((ip) => macOf.get(ip)).filter((m): m is string => !!m));
  const isGatewayAddr = (ip: string) => gateways.has(ip.toLowerCase()) || gatewayMacs.has(macOf.get(ip.toLowerCase()) ?? "");
  const gatewayNodeId = (ip: string) => {
    const mac = macOf.get(ip.toLowerCase());
    return mac && gatewayMacs.has(mac) ? `gw:${mac}` : `ip:${ip}`;
  };

  const node = (id: string, init: Omit<GNode, "id" | "via" | "hops"> & { hops?: number }): GNode => {
    let n = nodes.get(id);
    if (!n) nodes.set(id, (n = { id, via: [], hops: 1, ...init, members: [...init.members] }));
    else {
      n.depth = Math.min(n.depth, init.depth);
      for (const m of init.members) if (!n.members.includes(m)) n.members.push(m);
      if (n.kind === "gateway") n.sub = n.members.join(" · ");
      if (n.rttMs === null) n.rttMs = init.rttMs;
    }
    return n;
  };
  const edge = (from: string, to: string, dashed: boolean, label: string | null, ep: string, silent = 0) => {
    const id = `${from}>${to}`;
    let e = edges.get(id);
    if (!e) edges.set(id, (e = { id, from, to, dashed, label, via: [], silent }));
    if (!e.via.includes(ep)) e.via.push(ep);
    for (const nid of [from, to]) {
      const n = nodes.get(nid);
      if (n && !n.via.includes(ep)) n.via.push(ep);
    }
  };

  node("self", { kind: "self", depth: 0, label: "This PC", sub: "", ip: null, owner: null, rttMs: null, answered: null, ttl: null, members: [], endpoint: null });

  const gatewayId = () => {
    const gw = ctx?.gateways.find((g) => g.ip.includes(".")) ?? ctx?.gateways[0];
    if (!gw) return "self";
    return node(gatewayNodeId(gw.ip), {
      kind: "gateway", depth: 1, label: "Gateway", sub: gw.ip, ip: gw.ip, owner: null, rttMs: null, answered: null, ttl: 1, members: [gw.ip], endpoint: null,
    }).id;
  };

  let traced = 0;
  const epIds: string[] = [];
  /** Internet endpoints with no trace yet. */
  const untraced: MapEndpoint[] = [];

  for (const ep of eps) {
    const epId = `ep:${ep.ip}`;
    epIds.push(epId);
    node(epId, {
      kind: "endpoint", depth: 0, label: ep.name ?? ep.ip, sub: ep.name ? ep.ip : "", ip: ep.ip, owner: ep.owner,
      rttMs: null, answered: null, ttl: null, members: [], endpoint: ep,
    });

    const t = traces[ep.ip];
    if (!t || !t.hops.length) {
      // Not traced: dashed, no label (the hop estimate is in the tooltip).
      // Local ones are next to this PC; the others are wired below.
      if (LOCAL.includes(ep.scope)) edge("self", epId, true, null, ep.ip);
      else untraced.push(ep);
      continue;
    }
    traced++;

    // Hops before the endpoint itself, cut at the first repeated router: past
    // it the probes bounce in a routing loop (seen with anycast networks)
    // and would draw a long back-and-forth chain.
    const all = t.hops.filter((h) => !(h.status === "destination" && h.addr === ep.ip));
    const seenAddr = new Set<string>();
    let loop = false;
    const hops: typeof all = [];
    for (const h of all) {
      if (h.addr && seenAddr.has(h.addr)) {
        loop = true;
        break;
      }
      if (h.addr) seenAddr.add(h.addr);
      hops.push(h);
    }
    // Group consecutive hops of the same network.
    type Step = { id: string; init: Omit<GNode, "id" | "via" | "hops"> & { hops?: number } };
    const steps: Step[] = [];
    for (const h of hops) {
      // The first hop of any route is the gateway, whatever its address.
      const isGateway = h.addr ? h.ttl === 1 || isGatewayAddr(h.addr) : false;
      const asn = h.owner?.asn ?? null;
      const prev = steps[steps.length - 1];
      if (o.group && asn !== null && !isGateway) {
        const gid = `as:${asn}`;
        if (prev?.id === gid) {
          if (h.addr && !prev.init.members.includes(h.addr)) prev.init.members.push(h.addr);
          continue;
        }
        // Silent hops between two hops of the same network are absorbed.
        let k = steps.length;
        while (k > 0 && steps[k - 1].init.kind === "silent") k--;
        if (k < steps.length && k > 0 && steps[k - 1].id === gid) {
          steps.length = k;
          const g = steps[k - 1];
          if (h.addr && !g.init.members.includes(h.addr)) g.init.members.push(h.addr);
          continue;
        }
        steps.push({
          id: gid,
          init: {
            kind: "network", depth: 0, label: h.owner?.org ?? `AS${asn}`, sub: `AS${asn}${h.owner?.country ? " · " + h.owner.country : ""}`,
            ip: null, owner: h.owner, rttMs: h.rttMs, answered: null, ttl: h.ttl, members: h.addr ? [h.addr] : [], endpoint: null,
          },
        });
        continue;
      }
      if (h.addr) {
        steps.push({
          id: isGateway ? gatewayNodeId(h.addr) : `ip:${h.addr}`,
          init: {
            kind: isGateway ? "gateway" : "router", depth: 0,
            label: isGateway ? "Gateway" : shortName(h.name, h.addr), sub: isGateway ? h.addr : (h.owner?.org ?? (h.name ? h.addr : "")),
            ip: h.addr, owner: h.owner, rttMs: h.rttMs, answered: `${h.received}/${h.sent}`, ttl: h.ttl, members: [h.addr], endpoint: null,
          },
        });
      } else {
        steps.push({
          id: `silent:${prev?.id ?? "self"}:${h.ttl}`,
          init: { kind: "silent", depth: 0, label: "no reply", sub: `hop ${h.ttl}`, ip: null, owner: null, rttMs: null, answered: `0/${h.sent}`, ttl: h.ttl, members: [], endpoint: null },
        });
      }
    }

    // Fold runs of silent hops into one node, and trailing ones into the last edge.
    const folded: Step[] = [];
    for (const st of steps) {
      const last = folded[folded.length - 1];
      if (st.init.kind === "silent" && last?.init.kind === "silent") {
        const n = (last.init.hops ?? 1) + 1;
        const first = last.init.ttl ?? 0;
        last.init = { ...last.init, hops: n, label: `${n} hops, no reply`, sub: `hops ${first}–${st.init.ttl}` };
        last.id = `${last.id.split("#")[0]}#${n}`;
        continue;
      }
      folded.push({ id: st.id, init: { ...st.init } });
    }
    let trailing = 0;
    while (folded.length && folded[folded.length - 1].init.kind === "silent") {
      trailing += folded.pop()!.init.hops ?? 1;
    }

    let prev = "self";
    folded.forEach((st, i) => {
      node(st.id, { ...st.init, depth: i + 1 });
      edge(prev, st.id, false, null, ep.ip);
      prev = st.id;
    });
    const endLabel = loop
      ? "routing loop"
      : trailing
        ? `${trailing} silent hop${trailing === 1 ? "" : "s"}`
        : t.reached
          ? null
          : "no reply";
    edge(prev, epId, loop || !t.reached || trailing > 0, endLabel, ep.ip, trailing);
  }

  if (o.neighbors) {
    for (const nb of ctx?.neighbors ?? []) {
      if (gateways.has(nb.ip.toLowerCase()) || nodes.has(`ep:${nb.ip}`) || nb.ip.startsWith("fe80")) continue;
      const id = `nb:${nb.ip}`;
      node(id, { kind: "neighbor", depth: 1, label: nb.ip, sub: nb.mac, ip: nb.ip, owner: null, rttMs: null, answered: null, ttl: null, members: [], endpoint: null });
      const e = { id: `self>${id}`, from: "self", to: id, dashed: true, label: null, via: [], silent: 0 };
      edges.set(e.id, e);
    }
  }

  // Untraced Internet endpoints are behind the gateway.
  const gw = untraced.length ? gatewayId() : null;
  if (gw && gw !== "self") for (const ep of untraced) edge("self", gw, true, null, ep.ip);

  // Columns: the longest way from this PC to each node, so every edge points
  // right even when two routes reach a router after a different number of
  // hops. Edges that close a cycle (routes disagreeing on an order) are left
  // out of the count.
  const out = new Map<string, string[]>();
  for (const e of edges.values()) {
    if (nodes.get(e.to)?.kind === "endpoint") continue;
    (out.get(e.from) ?? out.set(e.from, []).get(e.from)!).push(e.to);
  }
  const state = new Map<string, 1 | 2>();
  const order: string[] = [];
  const back = new Set<string>();
  const visit = (id: string) => {
    state.set(id, 1);
    for (const to of out.get(id) ?? []) {
      const st = state.get(to);
      if (st === 1) back.add(`${id}>${to}`);
      else if (!st) visit(to);
    }
    state.set(id, 2);
    order.push(id);
  };
  visit("self");
  const depth = new Map<string, number>([["self", 0]]);
  for (const id of order.reverse()) {
    const d = depth.get(id) ?? 0;
    for (const to of out.get(id) ?? []) {
      if (!back.has(`${id}>${to}`)) depth.set(to, Math.max(depth.get(to) ?? 0, d + 1));
    }
  }
  for (const n of nodes.values()) if (depth.has(n.id)) n.depth = depth.get(n.id)!;

  let maxDepth = 1;
  for (const n of nodes.values()) if (n.kind !== "endpoint") maxDepth = Math.max(maxDepth, n.depth);

  // Once routes are drawn, a dashed line from the gateway to every untraced
  // endpoint would cross all of them: they share one stub in the last
  // column before the endpoints instead.
  if (gw) {
    if (untraced.length >= 2 && maxDepth >= 2) {
      const hub = node("untraced", {
        kind: "untraced", depth: maxDepth, label: "Not traced", sub: `${untraced.length} endpoints`,
        ip: null, owner: null, rttMs: null, answered: null, ttl: null, members: [], endpoint: null,
      }).id;
      for (const ep of untraced) {
        edge(gw, hub, true, null, ep.ip);
        edge(hub, `ep:${ep.ip}`, true, null, ep.ip);
      }
    } else {
      for (const ep of untraced) edge(gw, `ep:${ep.ip}`, true, null, ep.ip);
    }
  }

  // Endpoints all sit in the last column.
  for (const id of epIds) nodes.get(id)!.depth = maxDepth + 1;

  const list = [...nodes.values()];
  const edgeList = [...edges.values()];
  const structureKey = list.map((n) => `${n.id}@${n.depth}`).sort().join("|") + "#" + edgeList.map((e) => e.id + (e.dashed ? "~" : "")).sort().join("|");
  return { nodes: list, edges: edgeList, structureKey, traced };
}

/**
 * SVG path through `pts` (left to right). Two points: an S-curve, level at
 * both ends. More (a long edge and its bend points): one smooth curve
 * through all of them that never overshoots between two points (monotone
 * cubic interpolation), level where it meets its two nodes.
 */
export function curvePath(pts: { x: number; y: number }[]): string {
  const n = pts.length;
  const f = (v: number) => Math.round(v * 10) / 10;
  let d = `M${f(pts[0].x)} ${f(pts[0].y)}`;
  if (n === 2) {
    const [a, b] = pts;
    const mx = f((a.x + b.x) / 2);
    return `${d} C${mx} ${f(a.y)} ${mx} ${f(b.y)} ${f(b.x)} ${f(b.y)}`;
  }
  // Secant slopes, then tangents: zero at the ends and at local extremes,
  // otherwise the harmonic mean of the two neighbouring slopes.
  const s: number[] = [];
  for (let i = 0; i + 1 < n; i++) s.push((pts[i + 1].y - pts[i].y) / (pts[i + 1].x - pts[i].x || 1));
  const m = pts.map((_, i) => (i === 0 || i === n - 1 || s[i - 1] * s[i] <= 0 ? 0 : (2 * s[i - 1] * s[i]) / (s[i - 1] + s[i])));
  for (let i = 0; i + 1 < n; i++) {
    const [a, b] = [pts[i], pts[i + 1]];
    const dx = (b.x - a.x) / 3;
    d += ` C${f(a.x + dx)} ${f(a.y + m[i] * dx)} ${f(b.x - dx)} ${f(b.y - m[i + 1] * dx)} ${f(b.x)} ${f(b.y)}`;
  }
  return d;
}

export interface Layout {
  /** Where each node is, and each bend point of a long edge. */
  pos: Map<string, { x: number; y: number }>;
  /** Edge id → the ids in `pos` it runs through, from its source to its target. */
  routes: Map<string, string[]>;
  width: number;
  height: number;
  columns: number;
}

interface LNode {
  id: string;
  col: number;
  /** A bend point of a long edge, not a node of the graph. */
  bend: boolean;
  rank: number;
}

/**
 * Layered layout. `rank` orders each column initially (e.g. by traffic);
 * see the module comment for the steps.
 */
export function layout(g: Graph, rank: (n: GNode) => number, colW = 170, rowH = 30, pad = 30): Layout {
  const depths = [...new Set(g.nodes.map((n) => n.depth))].sort((a, b) => a - b);
  const colOf = new Map(depths.map((d, i) => [d, i]));
  const cols: LNode[][] = depths.map(() => []);
  const lnodes = new Map<string, LNode>();
  for (const n of g.nodes) {
    const ln: LNode = { id: n.id, col: colOf.get(n.depth)!, bend: false, rank: rank(n) };
    cols[ln.col].push(ln);
    lnodes.set(n.id, ln);
  }

  // Segments between adjacent columns; a long edge is a chain of them
  // through its bend points. Edges that don't point right are drawn direct.
  const preds = new Map<string, string[]>();
  const succs = new Map<string, string[]>();
  const link = (a: string, b: string) => {
    (succs.get(a) ?? succs.set(a, []).get(a)!).push(b);
    (preds.get(b) ?? preds.set(b, []).get(b)!).push(a);
  };
  const routes = new Map<string, string[]>();
  for (const e of g.edges) {
    const a = lnodes.get(e.from);
    const b = lnodes.get(e.to);
    if (!a || !b) continue;
    const path = [a.id];
    for (let c = a.col + 1; c < b.col; c++) {
      const ln: LNode = { id: `~${e.id}~${c}`, col: c, bend: true, rank: b.rank };
      cols[c].push(ln);
      lnodes.set(ln.id, ln);
      path.push(ln.id);
    }
    path.push(b.id);
    if (b.col > a.col) for (let i = 0; i + 1 < path.length; i++) link(path[i], path[i + 1]);
    routes.set(e.id, path);
  }
  for (const c of cols) c.sort((a, b) => b.rank - a.rank || a.id.localeCompare(b.id));

  // ── order: barycenter sweeps, keeping the ordering with the fewest crossings ──
  const norm = () => {
    const r = new Map<string, number>();
    for (const c of cols) c.forEach((n, i) => r.set(n.id, c.length > 1 ? i / (c.length - 1) : 0.5));
    return r;
  };
  const sweep = (order: number[], neigh: Map<string, string[]>) => {
    for (const ci of order) {
      const r = norm();
      const c = cols[ci];
      const bary = new Map(c.map((n) => {
        const ns = (neigh.get(n.id) ?? []).map((id) => r.get(id)!);
        return [n.id, ns.length ? ns.reduce((a, b) => a + b, 0) / ns.length : r.get(n.id)!];
      }));
      c.sort((a, b) => bary.get(a.id)! - bary.get(b.id)!);
    }
  };
  const crossings = () => {
    const at = new Map<string, number>();
    for (const c of cols) c.forEach((n, i) => at.set(n.id, i));
    let x = 0;
    for (const c of cols) {
      const segs: [number, number][] = [];
      for (const n of c) for (const to of succs.get(n.id) ?? []) segs.push([at.get(n.id)!, at.get(to)!]);
      for (let i = 0; i < segs.length; i++) {
        for (let j = i + 1; j < segs.length; j++) {
          if ((segs[i][0] - segs[j][0]) * (segs[i][1] - segs[j][1]) < 0) x++;
        }
      }
    }
    return x;
  };
  const right = cols.map((_, i) => i).slice(1);
  const left = cols.map((_, i) => i).slice(0, -1).reverse();
  let best = cols.map((c) => [...c]);
  let fewest = crossings();
  for (let i = 0; i < 8 && fewest > 0; i++) {
    sweep(right, preds);
    sweep(left, succs);
    const x = crossings();
    if (x < fewest) {
      fewest = x;
      best = cols.map((c) => [...c]);
    }
  }
  best.forEach((c, i) => (cols[i] = c));

  // ── place: each node level with its neighbours, columns keeping order and spacing ──
  const gap = (a: LNode, b: LNode) => (a.bend && b.bend ? rowH * 0.4 : a.bend || b.bend ? rowH * 0.6 : rowH);
  /** Distance of each node from the first of its column when packed tight. */
  const offs = cols.map((c) => {
    const o = [0];
    for (let i = 1; i < c.length; i++) o.push(o[i - 1] + gap(c[i - 1], c[i]));
    return o;
  });
  const span = Math.max(0, ...offs.map((o) => o[o.length - 1] ?? 0));
  const y = new Map<string, number>();
  cols.forEach((c, ci) => {
    const top = (span - (offs[ci][offs[ci].length - 1] ?? 0)) / 2;
    c.forEach((n, i) => y.set(n.id, top + offs[ci][i]));
  });
  const P = (id: string) => preds.get(id) ?? [];
  const S = (id: string) => succs.get(id) ?? [];
  const both = (id: string) => [...P(id), ...S(id)];
  /** Move one column toward its neighbours' mean: a weighted least-squares
      fit that keeps the order and the gaps (pool adjacent violators). */
  const place = (ci: number, neigh: (id: string) => string[]) => {
    const c = cols[ci];
    const o = offs[ci];
    const blocks: { sum: number; w: number; n: number }[] = [];
    c.forEach((n, i) => {
      const ns = neigh(n.id);
      const want = ns.length ? ns.reduce((a, id) => a + y.get(id)!, 0) / ns.length : y.get(n.id)!;
      // Bend points pull hardest, so long edges run straight.
      const w = ns.length ? (n.bend ? 8 : ns.length) : 0.5;
      blocks.push({ sum: (want - o[i]) * w, w, n: 1 });
      while (blocks.length > 1) {
        const b = blocks[blocks.length - 1];
        const a = blocks[blocks.length - 2];
        if (a.sum / a.w <= b.sum / b.w) break;
        blocks.splice(-2, 2, { sum: a.sum + b.sum, w: a.w + b.w, n: a.n + b.n });
      }
    });
    let i = 0;
    for (const b of blocks) for (let k = 0; k < b.n; k++, i++) y.set(c[i].id, b.sum / b.w + o[i]);
  };
  const all = cols.map((_, i) => i);
  for (let round = 0; round < 2; round++) {
    for (const ci of right) place(ci, P);
    for (const ci of left) place(ci, S);
  }
  for (let round = 0; round < 6; round++) {
    for (const ci of all) place(ci, both);
    for (const ci of [...all].reverse()) place(ci, both);
  }

  let top = Infinity;
  let bottom = -Infinity;
  for (const v of y.values()) {
    top = Math.min(top, v);
    bottom = Math.max(bottom, v);
  }
  if (!y.size) top = bottom = 0;
  const pos = new Map<string, { x: number; y: number }>();
  for (const ln of lnodes.values()) {
    pos.set(ln.id, { x: pad + ln.col * colW, y: Math.round((y.get(ln.id)! - top + pad + rowH / 2) * 10) / 10 });
  }
  return {
    pos,
    routes,
    width: pad * 2 + (depths.length - 1) * colW + 260,
    height: Math.round(bottom - top + pad * 2 + rowH),
    columns: depths.length,
  };
}

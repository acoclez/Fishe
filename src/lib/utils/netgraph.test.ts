import { describe, expect, it } from "vitest";
import { buildGraph, curvePath, layout, shortName, type MapEndpoint } from "./netgraph";
import type { Hop, NetContext, Owner, TraceResult } from "../api/types";

const cf: Owner = { asn: 13335, org: "Cloudflare, Inc.", country: "AU", source: "dbip" };
const isp: Owner = { asn: 64500, org: "Example ISP", country: "FR", source: "dbip" };

function ep(ip: string, scope: MapEndpoint["scope"] = "public", name: string | null = null): MapEndpoint {
  return { ip, name, owner: null, scope, level: "calm", rateBps: 1000, totalBytes: 1e6, hops: null };
}

function hop(ttl: number, addr: string | null, owner: Owner | null = null, status: Hop["status"] = addr ? "router" : "silent"): Hop {
  return { ttl, addr, alternates: [], rttMs: addr ? ttl * 5 : null, sent: 3, received: addr ? 3 : 0, status, name: null, owner, scope: null };
}

function trace(target: string, hops: Hop[], reached = true): TraceResult {
  return { target, startedAt: 0, durationMs: 100, reached, hops };
}

const ctx: NetContext = {
  gateways: [{ ip: "192.168.1.1", interfaceIndex: 7, metric: 10 }],
  neighbors: [
    { ip: "192.168.1.1", mac: "aa:bb:cc:00:00:01", state: "reachable", interfaceIndex: 7 },
    { ip: "192.168.1.20", mac: "aa:bb:cc:00:00:20", state: "stale", interfaceIndex: 7 },
    { ip: "fe80::1", mac: "aa:bb:cc:00:00:01", state: "reachable", interfaceIndex: 7 },
  ],
};

describe("shortName", () => {
  it("keeps short names, trims long ones, hides machine-generated labels", () => {
    expect(shortName(null, "1.1.1.1")).toBe("1.1.1.1");
    expect(shortName(null, null)).toBe("?");
    expect(shortName("one.one.one.one", "1.1.1.1")).toBe("one.one.one.one");
    expect(shortName("a.b.c.d.example.com", null)).toBe("a.b…");
    expect(shortName("2a01-4f8-0-0-0-0-0-1.rev.example.net", null)).toBe("…example.net");
  });
});

describe("buildGraph", () => {
  const opts = { group: false, neighbors: false };

  it("draws untraced endpoints behind the gateway, local ones next to this PC", () => {
    const g = buildGraph([ep("1.1.1.1"), ep("192.168.1.50", "private")], {}, ctx, opts);
    const ids = g.nodes.map((n) => n.id).sort();
    expect(ids).toEqual(["ep:1.1.1.1", "ep:192.168.1.50", "gw:aa:bb:cc:00:00:01", "self"]);
    expect(g.traced).toBe(0);
    const toPublic = g.edges.find((e) => e.to === "ep:1.1.1.1")!;
    expect([toPublic.from, toPublic.dashed, toPublic.label]).toEqual(["gw:aa:bb:cc:00:00:01", true, null]);
    expect(g.edges.find((e) => e.to === "ep:192.168.1.50")!.from).toBe("self");
    // Endpoints share the last column.
    const depths = new Map(g.nodes.map((n) => [n.id, n.depth]));
    expect(depths.get("ep:1.1.1.1")).toBe(depths.get("ep:192.168.1.50"));
    expect(depths.get("ep:1.1.1.1")).toBe(2);
  });

  it("merges shared routers, folds silent runs and labels trailing silence", () => {
    const traces = {
      "1.1.1.1": trace("1.1.1.1", [hop(1, "192.168.1.1"), hop(2, "10.0.0.1", isp), hop(3, null), hop(4, null), hop(5, "172.16.0.1", cf), hop(6, "1.1.1.1", cf, "destination")]),
      "8.8.8.8": trace("8.8.8.8", [hop(1, "192.168.1.1"), hop(2, "10.0.0.1", isp), hop(3, null), hop(4, null)], false),
    };
    const g = buildGraph([ep("1.1.1.1"), ep("8.8.8.8")], traces, ctx, opts);
    expect(g.traced).toBe(2);
    const byId = new Map(g.nodes.map((n) => [n.id, n]));
    // The first hop is the gateway whatever its address; one node for both routes.
    const gw = byId.get("gw:aa:bb:cc:00:00:01")!;
    expect(gw.kind).toBe("gateway");
    expect(gw.via.sort()).toEqual(["1.1.1.1", "8.8.8.8"]);
    expect(byId.get("ip:10.0.0.1")!.via.length).toBe(2);
    // Two silent hops in the middle of the first route become one node.
    const silent = g.nodes.filter((n) => n.kind === "silent");
    expect(silent.length).toBe(1);
    expect([silent[0].hops, silent[0].label, silent[0].sub]).toEqual([2, "2 hops, no reply", "hops 3–4"]);
    expect(silent[0].via).toEqual(["1.1.1.1"]);
    // The destination hop is not a router node.
    expect(byId.has("ip:1.1.1.1")).toBe(false);
    expect(g.edges.find((e) => e.to === "ep:1.1.1.1")!).toMatchObject({ from: "ip:172.16.0.1", dashed: false, label: null });
    // The second route ends in silence: folded into a dashed, labelled edge.
    const tail = g.edges.find((e) => e.to === "ep:8.8.8.8")!;
    expect(tail).toMatchObject({ from: "ip:10.0.0.1", dashed: true, label: "2 silent hops", silent: 2 });
    // Columns: self 0, gateway 1, isp 2, silent 3, cf 4, endpoints 5.
    expect(byId.get("ip:172.16.0.1")!.depth).toBe(4);
    expect(byId.get("ep:8.8.8.8")!.depth).toBe(5);
  });

  it("groups consecutive hops of one network and stops at routing loops", () => {
    const traces = {
      "1.1.1.1": trace("1.1.1.1", [hop(1, "192.168.1.1"), hop(2, "10.0.0.1", isp), hop(3, "10.0.0.2", isp), hop(4, null), hop(5, "10.0.0.3", isp), hop(6, "172.16.0.1", cf), hop(7, "172.16.0.2", cf), hop(8, "172.16.0.1", cf)]),
    };
    const g = buildGraph([ep("1.1.1.1")], traces, ctx, { group: true, neighbors: false });
    const byId = new Map(g.nodes.map((n) => [n.id, n]));
    const ispNode = byId.get("as:64500")!;
    expect(ispNode.kind).toBe("network");
    expect(ispNode.label).toBe("Example ISP");
    // The silent hop between two ISP routers is absorbed into the network.
    expect(ispNode.members).toEqual(["10.0.0.1", "10.0.0.2", "10.0.0.3"]);
    expect(g.nodes.some((n) => n.kind === "silent")).toBe(false);
    // 172.16.0.1 answering again at hop 8 is a loop: the route is cut there.
    expect(byId.get("as:13335")!.members).toEqual(["172.16.0.1", "172.16.0.2"]);
    expect(g.edges.find((e) => e.to === "ep:1.1.1.1")!).toMatchObject({ from: "as:13335", dashed: true, label: "routing loop" });
  });

  it("lists LAN neighbours on request, skipping the gateway and link-local addresses", () => {
    const g = buildGraph([], {}, ctx, { group: false, neighbors: true });
    const nbs = g.nodes.filter((n) => n.kind === "neighbor");
    expect(nbs.map((n) => n.ip)).toEqual(["192.168.1.20"]);
    expect(nbs[0].sub).toBe("aa:bb:cc:00:00:20");
    expect(g.edges).toHaveLength(1);
    expect(g.edges[0]).toMatchObject({ from: "self", to: "nb:192.168.1.20", dashed: true });
  });

  it("absorbs a run of silent hops inside one network when grouping", () => {
    const traces = {
      "1.1.1.1": trace("1.1.1.1", [hop(1, "192.168.1.1"), hop(2, "10.0.0.1", isp), hop(3, null), hop(4, null), hop(5, null), hop(6, "10.0.0.9", isp), hop(7, "172.16.0.1", cf)]),
    };
    const g = buildGraph([ep("1.1.1.1")], traces, ctx, { group: true, neighbors: false });
    expect(g.nodes.some((n) => n.kind === "silent")).toBe(false);
    expect(g.nodes.find((n) => n.id === "as:64500")!.members).toEqual(["10.0.0.1", "10.0.0.9"]);
    // One network node, so no edge leads back to it.
    expect(g.edges.map((e) => e.id)).toEqual(["self>gw:aa:bb:cc:00:00:01", "gw:aa:bb:cc:00:00:01>as:64500", "as:64500>as:13335", "as:13335>ep:1.1.1.1"]);
  });

  it("puts a router in the column of its longest route, so every edge points right", () => {
    // 10.0.0.9 is the third hop of one route and the fourth of the other.
    const traces = {
      "1.1.1.1": trace("1.1.1.1", [hop(1, "192.168.1.1"), hop(2, "10.0.0.1", isp), hop(3, "10.0.0.9", isp)]),
      "8.8.8.8": trace("8.8.8.8", [hop(1, "192.168.1.1"), hop(2, "10.0.0.1", isp), hop(3, "10.0.0.5", isp), hop(4, "10.0.0.9", isp)]),
    };
    const g = buildGraph([ep("1.1.1.1"), ep("8.8.8.8")], traces, ctx, opts);
    const depth = new Map(g.nodes.map((n) => [n.id, n.depth]));
    expect(depth.get("ip:10.0.0.9")).toBe(4);
    expect(depth.get("ep:1.1.1.1")).toBe(5);
    for (const e of g.edges) expect(depth.get(e.to)!, e.id).toBeGreaterThan(depth.get(e.from)!);
  });

  it("gathers untraced endpoints behind one stub once a route is drawn", () => {
    const traces = { "1.1.1.1": trace("1.1.1.1", [hop(1, "192.168.1.1"), hop(2, "10.0.0.1", isp), hop(3, "172.16.0.1", cf)]) };
    const gwId = "gw:aa:bb:cc:00:00:01";
    const g = buildGraph([ep("1.1.1.1"), ep("8.8.8.8"), ep("9.9.9.9")], traces, ctx, opts);
    const stub = g.nodes.find((n) => n.kind === "untraced")!;
    expect([stub.label, stub.sub, stub.depth]).toEqual(["Not traced", "2 endpoints", 3]); // the last column before the endpoints
    expect(stub.via.sort()).toEqual(["8.8.8.8", "9.9.9.9"]);
    expect(g.edges.find((e) => e.id === `${gwId}>untraced`)).toMatchObject({ dashed: true });
    for (const ip of ["8.8.8.8", "9.9.9.9"]) {
      expect(g.edges.filter((e) => e.to === `ep:${ip}`).map((e) => [e.from, e.dashed])).toEqual([["untraced", true]]);
    }
    // The traced route's first edge stays solid, and also carries the untraced ones to the gateway.
    expect(g.edges.find((e) => e.id === `self>${gwId}`)).toMatchObject({ dashed: false, via: ["1.1.1.1", "8.8.8.8", "9.9.9.9"] });

    // A single untraced endpoint needs no stub.
    const one = buildGraph([ep("1.1.1.1"), ep("8.8.8.8")], traces, ctx, opts);
    expect(one.nodes.some((n) => n.kind === "untraced")).toBe(false);
    expect(one.edges.find((e) => e.to === "ep:8.8.8.8")).toMatchObject({ from: gwId, dashed: true });
  });

  it("keys the structure by nodes, depths and edges only", () => {
    const a = buildGraph([ep("1.1.1.1")], {}, ctx, opts);
    const b = buildGraph([{ ...ep("1.1.1.1"), rateBps: 99_999, level: "spike" }], {}, ctx, opts);
    expect(a.structureKey).toBe(b.structureKey);
    const c = buildGraph([ep("1.1.1.1"), ep("8.8.8.8")], {}, ctx, opts);
    expect(c.structureKey).not.toBe(a.structureKey);
  });
});

describe("layout", () => {
  const rank = (n: { endpoint: MapEndpoint | null }) => n.endpoint?.rateBps ?? 0;

  it("puts one column per depth and packs the tallest one", () => {
    const traces = { "1.1.1.1": trace("1.1.1.1", [hop(1, "192.168.1.1"), hop(2, "10.0.0.1", isp)]) };
    const g = buildGraph([ep("1.1.1.1"), ep("8.8.8.8"), ep("9.9.9.9")], traces, ctx, { group: false, neighbors: false });
    const l = layout(g, rank, 100, 20, 10);
    expect(l.columns).toBe(4); // self, gateway, router + stub, endpoints
    expect(l.height).toBe(10 * 2 + 3 * 20);
    expect(l.width).toBe(10 * 2 + 3 * 100 + 260);
    const x = (id: string) => l.pos.get(id)!.x;
    expect([x("self"), x("gw:aa:bb:cc:00:00:01"), x("ip:10.0.0.1"), x("untraced"), x("ep:1.1.1.1")]).toEqual([10, 110, 210, 210, 310]);
    const ys = ["ep:1.1.1.1", "ep:8.8.8.8", "ep:9.9.9.9"].map((id) => l.pos.get(id)!.y).sort((a, b) => a - b);
    expect(ys).toEqual([20, 40, 60]);
    // Every node has a position, every edge a route between its two ends.
    for (const n of g.nodes) expect(l.pos.has(n.id), n.id).toBe(true);
    for (const e of g.edges) {
      const r = l.routes.get(e.id)!;
      expect([r[0], r[r.length - 1]]).toEqual([e.from, e.to]);
    }
  });

  it("draws a single route as a straight line", () => {
    const traces = { "1.1.1.1": trace("1.1.1.1", [hop(1, "192.168.1.1"), hop(2, "10.0.0.1", isp), hop(3, "172.16.0.1", cf)]) };
    const g = buildGraph([ep("1.1.1.1")], traces, ctx, { group: false, neighbors: false });
    const l = layout(g, rank);
    expect(new Set(g.nodes.map((n) => l.pos.get(n.id)!.y)).size).toBe(1);
  });

  it("gives a long edge a bend point in every column it crosses, clear of the nodes there", () => {
    const traces = {
      "1.1.1.1": trace("1.1.1.1", [hop(1, "192.168.1.1"), hop(2, "10.0.0.1", isp), hop(3, "10.0.0.9", isp)]),
      "8.8.8.8": trace("8.8.8.8", [hop(1, "192.168.1.1"), hop(2, "10.0.0.1", isp), hop(3, "10.0.0.5", isp), hop(4, "10.0.0.9", isp)]),
      "9.9.9.9": trace("9.9.9.9", [hop(1, "192.168.1.1"), hop(2, "172.16.0.1", cf)]),
    };
    const g = buildGraph([ep("1.1.1.1"), ep("8.8.8.8"), ep("9.9.9.9")], traces, ctx, { group: false, neighbors: false });
    const rowH = 30;
    const l = layout(g, rank, 170, rowH);
    // 10.0.0.1 → 10.0.0.9 jumps over the column of 10.0.0.5: one bend, in that column.
    const jump = l.routes.get("ip:10.0.0.1>ip:10.0.0.9")!;
    expect(jump).toHaveLength(3);
    expect(l.pos.get(jump[1])!.x).toBe(l.pos.get("ip:10.0.0.5")!.x);
    // 172.16.0.1 → its endpoint crosses two columns.
    expect(l.routes.get("ip:172.16.0.1>ep:9.9.9.9")!).toHaveLength(4);
    // In every column, what shares it keeps its distance: nodes a row apart, bends at least 0.4 of one.
    const cols = new Map<number, { y: number; bend: boolean }[]>();
    for (const [id, p] of l.pos) (cols.get(p.x) ?? cols.set(p.x, []).get(p.x)!).push({ y: p.y, bend: id.startsWith("~") });
    for (const c of cols.values()) {
      c.sort((a, b) => a.y - b.y);
      for (let i = 1; i < c.length; i++) {
        const min = c[i].bend && c[i - 1].bend ? rowH * 0.4 : c[i].bend || c[i - 1].bend ? rowH * 0.6 : rowH;
        expect(c[i].y - c[i - 1].y).toBeGreaterThanOrEqual(min - 0.11);
      }
    }
    // The same graph always gives the same layout.
    expect([...layout(g, rank, 170, rowH).pos]).toEqual([...l.pos]);
  });
});

describe("curvePath", () => {
  it("draws two points as an S-curve, level at both ends", () => {
    expect(curvePath([{ x: 0, y: 0 }, { x: 100, y: 40 }])).toBe("M0 0 C50 0 50 40 100 40");
  });

  it("goes through every bend point without overshooting", () => {
    const pts = [{ x: 0, y: 0 }, { x: 100, y: 30 }, { x: 200, y: 30 }, { x: 300, y: 90 }];
    const d = curvePath(pts);
    expect(d.match(/C/g)).toHaveLength(3);
    for (const p of pts.slice(1)) expect(d).toContain(` ${p.x} ${p.y}`);
    // Control points stay between the two points of their stretch (monotone).
    const nums = d.replace(/[MC]/g, " ").trim().split(/\s+/).map(Number);
    for (let i = 0; i + 1 < pts.length; i++) {
      const [c1y, c2y] = [nums[2 + i * 6 + 1], nums[2 + i * 6 + 3]];
      const [lo, hi] = [Math.min(pts[i].y, pts[i + 1].y), Math.max(pts[i].y, pts[i + 1].y)];
      for (const v of [c1y, c2y]) expect(v >= lo && v <= hi).toBe(true);
    }
  });
});

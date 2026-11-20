# Network map

The map shows how traffic gets from this PC to each endpoint: through the
gateway (your router), your ISP's routers and the backbone, to the
endpoints. Routes that share routers are drawn once, so you can see where
they split.

- **Process mode:** Endpoints → **Map** (next to **Table**), up to the 40
  biggest endpoints plus the focused one.
- **Host mode:** a **Route** card under the chart for the target.

This is the *traffic* map — the path out to the endpoints a live session is
talking to. For scanning your *local* network and listing the devices on it,
see [lan-mapping.md](lan-mapping.md); that sits above this on the **Map** page
and needs no session.

## Where routes come from

Packets only carry their two endpoints; the routers in between never appear
in captured traffic. Fishe uses two sources:

| | Hop estimate (passive) | Traceroute (active) |
|---|---|---|
| What | How many routers away an endpoint is | The routers themselves, with response time and owner |
| How | Remaining TTL / hop limit of received packets: senders start at 32, 64, 128 or 255, each router subtracts 1 | ICMP echo probes with TTL 1, 2, 3…: each router that drops a probe answers "time exceeded" |
| Network use | none | 2 small probes per hop (like `tracert`) |
| When | always (Hops column `~N`) | only when you click **Trace** |
| Admin | no | no (Windows ICMP API: `IcmpSendEcho`, `Icmp6SendEcho2`). On Linux: a raw ICMP socket, with the capture permission ([linux.md](linux.md)) |

### Traceroute details (`route/trace.rs`)

- Up to 30 hops, 2 probes per hop, 1 s timeout.
- TTLs are probed **in parallel** (10 at a time), so a route resolves in
  about one timeout (~2 s) instead of `tracert`'s sequential 10–30 s. Once
  a TTL reaches the destination, larger TTLs aren't started.
- Each hop records the answering address (plus alternates when probes come
  back from different routers, i.e. load-balanced paths), fastest round
  trip, replies/sent, and a status: router, destination, unreachable, or
  **no reply** (many routers don't answer probes).
- Hops are then named by reverse DNS (2.5 s budget) and get owner/country
  from [owners.md](owners.md) when available.
- At most 3 traces run at once; results are cached for 10 minutes
  (**Re-trace** forces a new one).
- A route that never reaches its endpoint ends with a dashed "no reply"
  edge: many servers ignore ICMP echo even though they serve traffic.

### Gateway and LAN (`route/lan.rs`)

- **Gateways**: default routes from the routing table (`GetIpForwardTable2`).
- **LAN devices**: the neighbour table (ARP / IPv6 neighbour discovery,
  `GetIpNetTable2`): addresses and MACs of devices this PC has recently
  talked to on the local network. Shown with the **LAN devices** toggle.
- Hop 1 of any route is the gateway, and gateway addresses sharing a MAC
  (e.g. the router's IPv4, global IPv6 and link-local addresses) are drawn as
  **one** gateway node.

## Reading the map

| Element | Meaning |
|---|---|
| ● large blue | This PC |
| ◆ | Gateway (router at hop 1) |
| ○ | Router; above it, its reverse-DNS name (or IP) and response time |
| dashed ○ | Hop(s) that didn't reply; consecutive ones fold into one node ("3 hops, no reply") |
| rounded box | A network (ASN) when **Group by network** is on: consecutive hops owned by the same operator merge into one node |
| ● on the right | Endpoints: size = traffic, colour = busyness level |
| solid edge | Traced; width = traffic flowing through it |
| dashed edge | Not traced yet (faint; the TTL hop estimate is in the tooltip), or the trace stopped before the endpoint: silent hops at the end fold into it ("2 silent hops"), a **routing loop** cuts it |
| dashed ○ "Not traced · N endpoints" | The stub untraced Internet endpoints share once at least one route is drawn: one dashed line from the gateway to the stub instead of one per endpoint across the whole map. Tracing an endpoint moves it from the stub onto its route |

- **Hover** any node for details (address, name, owner/ASN, country, hop
  number, response time, replies, endpoints through it).
- **Click a router or network** to highlight every route through it; click
  the background to clear. While you point at a route, its traffic is shown
  flowing along it.
- **Click an endpoint** to focus the dashboard on it (same as the table);
  **double-click** to frame its whole route.
- **Find endpoint…** (name, IP, owner): Enter highlights the next match and
  frames its route.
- **Top 10 / 20 / 40 / All**: how many endpoints (busiest by traffic) the
  map shows. Default 20.
- **Drag** to pan; **Ctrl + wheel** (or pinch) to zoom, so the plain wheel
  still scrolls the page; **− Fit +** buttons. Fit never zooms out below a
  readable size: taller maps align to the top and you pan for the rest.
- **Trace top N** traces the 10 biggest untraced Internet endpoints; **Trace
  all shown** traces every one on the map.

**Labels.** Endpoints, the gateway, the stub and This PC are always
labelled. Routers and silent hops are labelled when zoomed in (≥ 95%), when
pointed at, or on the highlighted route; networks from 60%. Edge labels show
on the highlighted route only. A router's name sits on one line **above**
it, with its response time, cut to the column width: edges leave a node
sideways, so a name never lies on its own edge, and two neighbours' names
don't run together. Every label has a halo of the background colour, so an
edge passing behind one is interrupted, not struck through it.

**Layout** (`netgraph.ts`), a layered layout in four steps:

| Step | What it does | Why |
|---|---|---|
| Columns | A node's column is the **longest** way to it from this PC; endpoints share the last column | A router that is the third hop of one route and the fourth of another used to take the smaller number, which drew edges sideways or backwards. Now every edge points right |
| Bend points | An edge that spans several columns gets a point in each column it crosses, placed like a node | It takes a slot there instead of being drawn straight through the nodes and labels in between |
| Order | Barycenter sweeps over nodes and bend points; the ordering with the fewest crossings seen is kept | Fewer crossings |
| Placement | Each node is pulled level with what it connects to, columns keeping their order and spacing (a least-squares fit; bend points pull hardest) | Routes run straight, and an endpoint sits level with the router that serves it |

A long edge is then drawn as one smooth curve through its bend points
(monotone, so it never overshoots between two of them).

The layout only changes when the routes change (new traces), so nodes don't
move while traffic numbers update; when it does change, nodes glide to
their new place (450 ms) and new ones fade in. Fit, zoom and Find animate
the view. All motion is skipped with the system's *reduce motion* setting.
The same graph always gives the same layout.

**Routing loops.** Some traces bounce between two routers until the hop
limit (seen with anycast networks: hops 10–30 alternating between two
Cloudflare routers). The map stops the route at the first repeated router
and labels its last edge *routing loop*; the endpoint's tooltip says so.

### In the endpoints table

The **Hops** column shows the traced hop count, or `~N` (estimated from
TTL) before tracing; **⤳** traces (or re-traces) that endpoint.

## Things to know

- **Your router may answer for some addresses.** Some ISP boxes answer
  ICMP for `1.1.1.1` themselves, so `tracert` and Fishe both show
  1.1.1.1 at hop 1.
- **Silent hops are normal**: routers often rate-limit or drop "time
  exceeded" replies.
- **Different connections can take different paths** through load-balanced
  networks; a trace shows one of them (alternates are listed per hop).
- **Host mode counts the probes**: the trace's ICMP packets are traffic to
  the target, so they appear in the gauge and the Protocols panel.
- Routers' IPv6 hop names are often machine-generated
  (`2001db8….ipv6.example-isp.net`); the map shows the operator domain
  (`…example-isp.net`) and the tooltip the full name.

## Code map

| File | Role |
|---|---|
| `net/parse.rs` | `PacketInfo.ttl`, `hops_from_ttl` |
| `monitor/stats.rs`, `monitor/endpoints.rs` | Last received TTL per endpoint → `EndpointRow.hops` |
| `route/icmp.rs` | One probe with a given TTL (IPv4 / IPv6) |
| `route/trace.rs` | Parallel traceroute, hop assembly, enrichment, `TraceBook` cache/limits |
| `route/lan.rs` | Gateways and neighbour table |
| `src/lib/stores/routes.svelte.ts` | Trace queue (3 at a time), results, LAN context |
| `src/lib/utils/netgraph.ts` | Graph building (shared hops, grouping, gateway merging, the untraced stub, columns) and the layered layout with bend points; `curvePath` |
| `src/lib/pages/map/NetworkMap.svelte` | Rendering and interaction |

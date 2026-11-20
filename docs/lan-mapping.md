# LAN mapping

The **Map** page can scan the local network(s) this PC is on and list the
devices it finds — their address, maker and what they offer. It answers
"what's connected to my network?" the way a router's device list or a tool
like Fing does, without leaving Fishe.

A scan is a deliberate, one-shot action (it sends packets), so it runs only
when you press **Scan network** — never on a timer. Results replace the
previous set all at once; nothing on the page updates on its own.

## What a scan does

For every local IPv4 network that has a default gateway (`lan::adapters`):

1. **ARP sweep** (`lan::arp`). Through Npcap (libpcap on Linux), Fishe broadcasts an ARP
   "who has `<ip>`?" for each address of the network and collects the
   replies. Devices that are switched on answer with their MAC; devices
   that are asleep or firewalled against ARP do not (nothing short of ARP
   reaches them, since ARP is how any host on the segment is addressed).
   Three rounds, re-asking only the silent addresses, then a short linger.
   A /24 takes about 2 seconds. Networks larger than a /22 (1022 hosts) are
   swept around this PC's own /24 only, so a /16 does not take minutes; the
   result is flagged `narrowed`.
2. **Vendor** (`lan::oui`). The first 24–36 bits of a MAC are a prefix the
   IEEE registers to a maker. Fishe ships the registry
   (`data/oui.tsv.gz`, ~50k prefixes) and matches the longest one. A
   privacy-randomised MAC (the locally-administered bit set) carries no
   maker, and is shown as such rather than guessed.
3. **Name**. A reverse-DNS (PTR) lookup through the OS resolver, when the
   device has a name. Resolved in parallel, since a device without a PTR
   record can take seconds to time out.
4. **Open ports** (`lan::ports`), when **Probe common ports** is ticked.
   Fishe opens and immediately closes a TCP connection to a short list of
   well-known ports (HTTP, HTTPS, SSH, SMB, printing, RTSP, …) — the same
   thing a browser does — to hint at what a device is: a web UI, a NAS, a
   printer, a camera. It only sees services the device already offers to
   the LAN. UDP-only services (mDNS, SSDP) are out of scope.

This PC and the gateway are always included, even if the gateway stays
silent to the sweep.

## Views

- **List** — a table: device (name or address), address, maker, MAC, and
  the open ports as chips. The gateway and this PC are marked. The table is
  drawn once per scan and sorted (gateway, this PC, then by address), so
  rows never move on their own.
- **Map** — a static star: the gateway at the centre, every device on a
  ring around it (the shape of a home network, where devices reach each
  other through the router or switch). Hover a node for its details. It is
  laid out once per scan; it does not animate or re-flow.

## Scope and safety

A scan only ever touches the local network segment this PC is already on
(the subnet of an adapter with a gateway), and only with ARP, reverse DNS
and short-lived TCP connections to well-known ports — the ordinary traffic
of being a device on that network. It sends nothing to the internet and
changes nothing on the devices it finds. Nothing is stored: the last result is
kept in memory until the next scan or until the app closes, so it is still
there after a visit to another page.

## Where it lives

- Backend: `crates/fishe-core/src/lan/` (`adapters`, `arp`, `oui`, `ports`, and the
  `scan` orchestrator in `mod.rs`). Command: `scan_lan` (see
  [ipc-api.md](ipc-api.md)).
- Bundled vendor list: regenerate with `node scripts/update-oui.mjs`, which
  fetches the three IEEE registries (MA-L / MA-M / MA-S) and writes
  `crates/fishe-core/data/oui.tsv.gz`.
- Frontend: `src/lib/pages/map/LanScan.svelte`, on the Map page.

This is separate from the **traffic map** below it ([network-map.md](network-map.md)),
which traces the internet path to the endpoints a live session is talking to.
The LAN scan does not need a session — it works any time.

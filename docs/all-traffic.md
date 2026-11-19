# All-traffic mode

The third target, next to **Host** and **Process**: every packet this
machine sends or receives, Wireshark-style, with each one labelled with the
**program** that owns its socket. The gauge, chart and tiles measure the
whole machine; the **Programs** panel shows who is using the network, the
**Endpoints** table and **Map** show where the traffic goes, and the
**Packets** view lists the packets themselves.

## Starting

**Target → All**, then **Start**. *Interface* defaults to *All network
adapters*: every adapter that is up, running and has an address. The
loopback adapter is left out on purpose (loopback traffic never leaves the
machine, and a local proxy or VPN client would be counted twice); pick the
*Npcap Loopback Adapter* explicitly to watch it alone.

| | |
|---|---|
| BPF filter | `ip or ip6` (every IP packet; ARP and other non-IP frames carry no endpoint) |
| Snap length | 192 bytes (headers only), like the other modes |
| Kernel buffer | 4 MiB per interface (8 MiB when only one is captured) |
| Direction | **In** = received by this machine (including broadcast/multicast from others), **Out** = sent by it |

## Attribution

Each packet's owner comes from the same `(transport, local port) → PID`
table as [process mode](process-mode.md), fed by the socket table every tick
and, when Fishe runs as administrator, by kernel ETW events in real time.
The difference: process mode *filters* by owner, all-traffic mode only
*labels*, so nothing is ever dropped.

| Packet | Labelled as | When |
|---|---|---|
| TCP/UDP, local port owned | that PID's program | immediately |
| TCP/UDP, owner not known yet | held, then its program | as soon as the socket table / ETW names it (≤ 2 s) |
| TCP/UDP, nobody claims the port within 2 s | **Unattributed** | after 2 s (still counted) |
| ICMP, IGMP, other protocols without ports | **Unattributed** | immediately |

The **Unattributed** tile in the status strip counts both kinds. Typical
unattributed traffic: pings and ICMP errors, multicast group management,
TCP resets to closed ports, broadcasts to ports nobody listens on, and
(without admin) connections that opened and closed between two socket-table
polls.

PIDs are named from the process list, refreshed whenever an unseen PID shows
up (at most every 0.5 s) and, with ETW, from process-start events, so even
a process that lives a few milliseconds gets its name. A PID whose process
exited before it could be named is shown as `PID 1234`.

## Programs panel

One row per **executable name**: all `chrome.exe` processes are one
program (the row says how many processes were seen; hover for their PIDs).

| Column | Meaning |
|---|---|
| **Program** | Executable name; *Unattributed* for traffic without an owner |
| **Activity** | Sparkline of the last 30 s |
| **Now** | Current receive ↓ / send ↑ rate |
| **Level** | Busyness against the program's own learned normal (same detector as the gauge) |
| **Share** | Part of this session's bytes |
| **Total** | Bytes exchanged this session |
| **Endpoints** | Distinct remote addresses it talked to |
| **Seen** | Time since its last packet |

The panel has a fixed height (about 8 rows) and scrolls for the rest (up to
100 rows per sample; 1024 programs are remembered per session). Like the
endpoints table it refreshes once a second, re-sorts at most every 3 s and
holds its order while the pointer is over it (see
[frontend.md](frontend.md#stable-live-tables)).

**Click a row** to focus on that program: the gauge, tiles and chart follow
it, and the Endpoints table and Map are filtered to the endpoints it talks to
(a focus bar says so; **Show all traffic** returns). Clicking an endpoint
then focuses that endpoint, and **Back to *program*** returns to the
program.

**Monitor ▸** stops the session and starts **process mode** bound to that
program by name, for its full process-mode detail.

## Endpoints, map and names

Same as process mode ([endpoints.md](endpoints.md), [network-map.md](network-map.md)),
for the whole machine, plus a **Programs** column: up to three programs
exchanging traffic with each endpoint, biggest first. The endpoint filter
also matches program names. When a program is focused, endpoints are kept if
that program is among their top three.

## Packets view

**Endpoints | Packets** on the Connections page: a live list of the
latest counted packets, newest first.

| Column | |
|---|---|
| Time | Capture timestamp (ms) |
| ↓ / ↑ | Received / sent |
| Source, Destination | Address and port |
| Protocol | TCP / UDP / ICMP / other, and the service name of the lower port |
| Length | Frame length on the wire |
| TTL | TTL / hop limit |
| Program | Owning program (all-traffic mode) |
| Remote name | Best known name of the remote side (TLS, DNS, PTR) |

**Pause** freezes the list, **Clear** empties it, the filter matches
addresses, ports, protocol, program, service and names. The view keeps the
last 1000 packets and draws 400.

How it works: the feed is **off unless the view is open**. Workers then
copy a small summary of each counted packet into a local batch and hand it
over at their 50 ms flush; the backend keeps the last 2000, and the view
polls `recent_packets` twice a second. At high packet rates more packets
arrive than the list can show: the view says how many went by unseen. Every
packet is counted regardless. Packets held while their owner is looked up
appear when they are attributed, so the list can be slightly out of time
order. The view also works in process mode (without the Program column).

## Recording

Record works as in the other modes ([archive.md](archive.md)). An
all-traffic recording is labelled **All** in the archive and its summary
holds the **25 programs that moved the most bytes during the recording**
(received, sent, peak; endpoints counted over the session), shown as a
Programs table in the replay. The optional `.pcapng` contains every
counted packet's headers, so it is close to a headers-only Wireshark capture
of the machine.

## Cost

Per packet, compared with process mode: one ownership lookup (shared read
lock) and one extra hash-map update per tally. With the Packets view open:
one small copy (≈ 80 bytes) into a local batch.

For scale: on a PC with five network adapters and the socket table only
(no ETW), a video call at about 7 Mb/s gives some 800 packets per second to
label, and about 1% of them stay unattributed. The per-program bytes of a
recording sum exactly to its total.

## Code map

| File | Role |
|---|---|
| `monitor/target.rs` | `TargetSpec::All`, `Matcher::All`, `Verdict::Owned(dir, pid)`, `Matcher::unowned` |
| `process/machine.rs` | `MachineScope`: direction, owner lookup, PID → name, ETW sink |
| `process/etw.rs` | `EtwSink` trait, shared by process and all-traffic mode |
| `monitor/stats.rs` | `Tally::record_owned`, per-PID counters, per-endpoint program bytes |
| `monitor/programs.rs` | `ProgramBook`: grouping by name, detector per program, endpoints per program |
| `monitor/packets.rs` | `PacketRing`: the live packet feed |
| `monitor/engine.rs` | worker counting/expiry, programs in each sample |
| `process/refresh.rs` | `refresh_machine`: socket table every tick, process names when an unnamed PID shows up (at most every 500 ms) |
| `monitor/mod.rs` | `prepare_all` and the helpers shared with process mode |
| `src/lib/pages/connections/ProgramsPanel.svelte` | Programs panel |
| `src/lib/pages/connections/PacketList.svelte` | Packets view |

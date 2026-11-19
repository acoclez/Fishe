# Capture engine

How a packet travels from the network card to a number on the gauge.

## 1. Loading Npcap (`npcap.rs`)

Npcap installs `wpcap.dll` and `Packet.dll` in `%SystemRoot%\System32\Npcap`.
Unless Npcap was installed in *WinPcap API-compatible mode*, that folder is
**not** on the DLL search path, so a normally-linked binary fails to start
with "wpcap.dll was not found".

Fishe solves this with delay-loading:

1. `build.rs` adds `/DELAYLOAD:wpcap.dll` and links `delayimp.lib`.
2. At startup, before any pcap call, `npcap::init()`:
   - gets the system directory (`GetSystemDirectoryW`),
   - checks `System32\Npcap\wpcap.dll` exists,
   - calls `SetDllDirectoryW(System32\Npcap)`,
   - calls `pcap_lib_version()`, the first pcap call, which triggers the load.
3. If the DLL is missing, `available = false` and every capture command
   returns `npcap_unavailable` instead of crashing.

**Npcap is the only capture source, and it is the user's install.** Fishe
does not ship it: Npcap's licence asks each user to install it themselves,
so a PC without it is an expected first run, not an error. The Live page
then shows an install prompt (`NpcapMissing.svelte`): what Npcap is, three
steps, **Open npcap.com** (`open_npcap_site`, a fixed address) and **Check
again** (`npcap_recheck`). A failed probe loaded nothing, so looking again
is safe and no restart is needed; a successful probe is final. The header
shows *Npcap not installed* on every page, and the LAN scan says why it is
disabled. Everything that doesn't capture (Archive, Settings, agents setup)
works without it.

**Reads never block for long.** Every loop that reads packets (the
workers, the naming sniffers, the ARP sweep) calls
`net::capture::next_packet`, which gives up after the read timeout (50 ms)
so the loop can look at its stop flag. Npcap honours the timeout by itself.
libpcap on Linux does not return from a read while no packet arrives,
whatever the timeout, so there the capture is non-blocking and the wait is
a `poll` on its file descriptor. Without this a session on a silent
interface could not be stopped on Linux.

Npcap is the only packet source. ETW is used for process attribution only
([process-mode.md](process-mode.md)), never to read packets.

Build time is separate: the `pcap` crate needs the **Npcap SDK** import
libraries. `.cargo/config.toml` (repo root) sets
`LIBPCAP_LIBDIR=vendor/npcap-sdk/Lib/x64`; `scripts/setup-npcap-sdk.ps1`
downloads the SDK there.

**Admin rights:** not needed when Npcap's *"Restrict Npcap driver's access to
Administrators only"* option is off (the default, registry `AdminOnly = 0`).
If it is on, run Fishe as administrator.

## 2. Choosing the interface (`net/interfaces.rs`)

**Process mode** captures on every *active* interface at once (up, running,
with an address, plus the loopback adapter), one worker thread each. See
[process-mode.md](process-mode.md). **All-traffic mode** does the same
without the loopback adapter; see [all-traffic.md](all-traffic.md).

**Host mode** with *Automatic* selected:

1. **Loopback target** (`127.0.0.1`, `::1`) → the Npcap Loopback Adapter.
2. Otherwise Fishe asks the OS which local address it would use to reach the
   target: bind a UDP socket and `connect()` it to `target:9`. That is a pure
   route lookup and **sends no packets**. The adapter that owns that address is
   chosen.
3. Fallback: the first adapter that is up, running, non-loopback and has an
   address.

The user can override this in the *Interface* dropdown (useful with VPNs,
where traffic to the target may leave via the tunnel adapter).

## 3. Opening the capture (`net/capture.rs`)

| Setting | Value | Reason |
|---|---|---|
| promiscuous | off | Only this host's traffic is wanted |
| snaplen | 192 bytes | Ethernet 14 + 2×VLAN 8 + IPv6 40 + ext headers + ports; payload is never copied |
| read timeout | 50 ms | `next_packet` returns regularly even with no traffic, so ticks and stop are prompt |
| immediate mode | on | Deliver packets as they arrive instead of batching |
| kernel buffer | 8 MiB (4 MiB per interface in multi-interface mode) | Absorbs bursts; overflow is reported as **Dropped** |
| BPF filter | host: `host <ip>`; process: `tcp or udp`; all: `ip or ip6` | Compiled and run in the Npcap driver; works for IPv4 and IPv6 |

## 4. Parsing (`net/parse.rs`)

Supported link types (from `pcap_datalink`):

| DLT | Framing |
|---|---|
| 1 (EN10MB) | Ethernet, with up to two 802.1Q/802.1ad VLAN tags |
| 0 (NULL), 108 (LOOP) | 4-byte address family + IP (Npcap loopback) |
| 12, 14, 101, 228, 229 | Raw IP |

From IP it extracts `src`, `dst`, the TTL / hop limit (used to estimate the
hop distance of endpoints, see [network-map.md](network-map.md)), the transport (`tcp`/`udp`/`icmp`/`other`)
and, for TCP/UDP, the ports. IPv6 extension headers (hop-by-hop, routing,
destination options, fragment, AH) are walked. Ports are omitted for
non-first fragments and truncated headers; the packet is still counted.

Non-IP frames matched by the filter (e.g. ARP for the target's IPv4 address)
are counted internally as "unparsed" and excluded from the totals.

## 5. Counting (`monitor/stats.rs`)

- **Matching** is done by `monitor::target::Matcher`:
  - host mode: `src == target` → **inbound**, `dst == target` → **outbound**;
  - process mode: by local-port ownership, see [process-mode.md](process-mode.md);
  - all-traffic mode: everything counts; source is this host → **outbound**,
    otherwise **inbound**; the local port's owner labels the packet, see
    [all-traffic.md](all-traffic.md).
- **Bytes** = original frame length on the wire (`pcap_pkthdr.len`), including
  link-layer headers. This matches what Wireshark shows as "Frame length", and
  will read slightly higher than application-level throughput.
- **Window** counters reset every tick and become the rates
  (`bytes / tick seconds`).
- **Totals**, **per-transport bytes** and the **service-port table** are
  cumulative for the session.
- **Service port** = `min(src_port, dst_port)`. Servers usually sit on the
  lower, well-known port, so this names the service (443, 53, …) regardless
  of who initiated the connection. At most 2048 distinct ports are tracked,
  which bounds memory during port scans.

## 6. Workers and ticking (`monitor/engine.rs`)

Each interface has a **worker** thread that reads, parses, classifies and
counts into a local `Tally`. Every 50 ms it hands the tally (plus its
`pcap_stats` drop counters) to the **aggregator** over an mpsc channel.

The aggregator wakes at least every 50 ms. When `tick` (default 250 ms,
configurable 50 to 2000 ms) has elapsed it:

1. (process / all-traffic mode) polls the socket table and, when needed, the process list (`process/refresh.rs`),
2. turns the merged window into rates,
3. feeds the total rate to the `BusyDetector`,
4. sends a `Sample` over the UI channel.

The real elapsed time is used for rates (`intervalMs`), so a late tick never
inflates a rate.

Both halves are plain structs with step methods: `WorkerCore::on_parsed`
takes a parsed packet and the clock, `WorkerCore::flush` hands over the
tally; `Aggregator::on_message` takes a worker message, `Aggregator::tick`
builds the sample. The pcap loop, the threads and the channel live only in
`run_worker` and `run`, so the hold/retry/expiry and tick logic is
unit-tested without Npcap (`cargo test engine`).

## Performance notes

- Per packet: a header parse (no allocation) and a handful of hash-map
  updates (port table, endpoint, and in process / all-traffic mode the
  owner lookup and the TCP flow).
- Per tick: a sort of ≤ 2048 port entries for the top 8, plus one IPC message.
- Packet rates far beyond what a single remote host usually produces are
  handled; any kernel-buffer overflow is visible in the **Dropped** tile.

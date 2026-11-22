# Endpoints

In process mode Fishe lists every remote address the process talks to (in
[all-traffic mode](all-traffic.md), every remote address of the machine, with
the programs talking to it), names it, and tracks how busy each one is. Click a row to point the gauge, tiles
and chart at that endpoint alone.

## The panel

| Column | Meaning |
|---|---|
| **Endpoint** | Best known name (or the IP), the IP, an address-type tag, the name's source tag, and **NEW** for 15 s after first contact |
| **Owner** | Network owner and country badge (public addresses), from DB-IP Lite or ipinfo.io (↗); see [owners.md](owners.md) |
| **Programs** | All-traffic mode only: up to 3 programs exchanging traffic with it, biggest first |
| **Hops** | Routers to the endpoint: traced count, or `~N` estimated from packet TTLs; **⤳** traces the route. See [network-map.md](network-map.md) |
| **RTT** | Smoothed TCP round-trip time (colour-graded), ⟳ *n*% when ≥ 1% of the data sent was retransmitted, **◉** starts / stops a ping (1/s); a running ping replaces the value (tagged *ping* underneath). The header's **Ping ×N · Stop** chip stops all pings. See [connection-quality.md](connection-quality.md) |
| **Services** | Up to 3 service ports used with this endpoint (`443/tcp`, `3478/udp`…); hover for the service name |
| **Activity** | Sparkline of the last 30 s (in + out) |
| **Now** | Current receive ↓ / send ↑ rate |
| **Level** | Busyness of *this* endpoint against *its own* learned normal (same detector as the gauge) |
| **Total** | Bytes exchanged this session |
| **Seen** | Time since the last packet |

Sort by **Live** (current rate), **Total**, **Newest** (first contact) or
**Name**; filter by name, IP, owner, ASN (`as13335`) or country.

The backend sends at most 150 rows per sample: the 100 busiest right now plus
the 50 largest overall. The table keeps endpoints that drop out of those
rows (they went quiet) for 5 minutes, shown idle, so rows don't vanish and
reappear (at most 400). The header shows `rows of total` when more exist.
Up to 4096 endpoints are remembered per session; the least recently seen are
dropped beyond that.

The table is built to be read while live: values refresh once a second, the
order changes at most every 3 s and **never while the pointer is over the
table** ("order held"), rows glide to their new place, columns have fixed
widths and rows a fixed height. See [frontend.md](frontend.md#stable-live-tables).

### Focus

Clicking a row (or Enter on a focused row) makes the gauge, the six tiles,
the chart and the Connection quality card follow that endpoint. A bar shows what is focused; **Show whole
process** (or clicking the row again) returns to the process view. Protocols
and *Top services* stay process-wide while focused, and a note says so.

The chart uses the endpoint's own history, kept in the UI from the moment
the endpoint first appeared (up to 5 min). If the endpoint drops out of the
150 rows sent (it went quiet), its line continues at zero.

### Map and packets

The table lives on the **Connections** page; **Endpoints | Packets** above
it switches to the live packet list ([all-traffic.md](all-traffic.md#packets-view)).
The **Map** page (key 3) shows the same endpoints laid out along their
routes ([network-map.md](network-map.md)). A focus set on either page also
applies to the Live page's gauge and chart.

## Address types

| Tag | Ranges |
|---|---|
| Internet | everything not below |
| LAN | 10/8, 172.16/12, 192.168/16, IPv6 ULA fc00::/7 |
| Link-local | 169.254/16, fe80::/10 |
| Loopback | 127/8, ::1 (shown as `localhost`) |
| CGNAT | 100.64/10 (carrier-grade NAT) |
| Multicast / Broadcast | 224/4, ff00::/8 / 255.255.255.255 |
| Test net | 192.0.2/24, 198.51.100/24, 203.0.113/24, 2001:db8::/32 |

IPv4-mapped IPv6 addresses are classified by their IPv4 part.

## Names

Best source first. The source is shown as a tag (hover for an explanation).

| Tag | Source | How | Notes |
|---|---|---|---|
| **TLS** | Server Name Indication | Read from the ClientHello the process sends when opening a TLS connection to port 443 | Exactly the site the process asked for. ClientHellos larger than one TCP segment (common with post-quantum key shares) are reassembled. |
| **DNS** | DNS / mDNS answers | A/AAAA answers on UDP 53 and 5353, mapped to the *question* name (CNAME chains collapse to what was asked) | Windows resolves names in a shared service, so answers are recorded machine-wide. mDNS names LAN devices (`living-room-tv.local`). |
| **ECH** | Encrypted Client Hello, outer name | The ClientHello carries an ECH extension; only the shared front name (e.g. `cloudflare-ech.com`) is visible | Ranked below DNS, because it doesn't name the real site. |
| **PTR** | Reverse DNS | Background lookup through the OS resolver for unnamed Internet/LAN/CGNAT addresses (≤ 16 new per tick, 3 threads, once per address) | Often names the hosting provider rather than the site. Toggle in Settings → *Endpoint names*. |

What is *not* visible: DNS over HTTPS/TLS (browsers' secure DNS), the inner
name of ECH connections, and QUIC (HTTP/3 over UDP 443), whose ClientHello is
encrypted with per-connection keys. Those endpoints fall back to DNS (if the
OS resolved them) or PTR.

### How names are captured

Naming needs a little payload, so it uses a second, separate capture per
interface (`naming/sniffer.rs`):

| Setting | Value |
|---|---|
| BPF filter | `udp port 53 or udp src port 5353 or tcp dst port 443 or (udp src port 67 and udp dst port 68)` (the last part is DHCP servers' answers, for the [security view](security.md#local-network), not for naming) |
| Snap length | 4096 bytes |
| Kernel buffer | 2 MiB |

Only DNS, mDNS **responses** and **client→server** TCP/443 are captured. Of
the TLS stream, only the ClientHello (the first handshake message, which is
not encrypted) is parsed; the reassembler gives up after 16 KiB or 3 s, and
encrypted application data is never examined. Nothing is written to disk.

Any host on the network can send a packet that looks like a DNS answer, so
what the sniffer believes is narrow:

| Source | Believed when |
|---|---|
| DNS answer | it matches a query this machine sent in the last 10 s: same server, client port and transaction id (outgoing queries are captured for that only) |
| mDNS answer | the address it names is not public: mDNS can name a LAN device, never a site |
| TLS server name | the connection was opened by this machine |
| Any name, PTR included | it reads as a host name: ASCII letters, digits, `-`, `.`, `_`, at most 253 bytes |

Anything else is dropped (the session log counts DNS answers nobody asked
for). Names are therefore safe to show, to hand to agents and to export.

Turn naming capture off with `StartRequest.naming.sniff = false` (API) and
reverse DNS with the Settings toggle.

## Example

A Node process fetching `example.com`, `www.google.com`, `proof.ovh.net` and
the bare IP `1.1.1.1`, all bound by PID:

| Endpoint | Named as | Source |
|---|---|---|
| 2606:4700:10::… | example.com | TLS |
| 2001:4860:4827:7700:: | www.google.com | TLS |
| 2001:41d0:242:d300:: | proof.ovh.net | TLS |
| 1.1.1.1 | one.one.one.one | PTR (no name sent for a bare IP) |

During a 10 MB download, focusing `proof.ovh.net` showed **Busy 3.5×** with a
52 Mb/s peak, and its total (14.4 MB received) matched 3 × 1 MB + 10 MB plus
overhead.

## Code map

| File | Role |
|---|---|
| `monitor/stats.rs` | `Tally.endpoints`: per-remote-IP counts and service ports per batch |
| `monitor/endpoints.rs` | `EndpointBook`: totals, per-endpoint `BusyDetector`, selection, rows, eviction |
| `naming/addr.rs` | Address types |
| `naming/dns.rs` | DNS response parser (compression, CNAME, mDNS) |
| `naming/tls.rs` | ClientHello SNI parser, ECH detection, segment reassembly |
| `naming/book.rs` | `NameBook`: IP → names, source priority |
| `naming/rdns.rs` | Background PTR resolver |
| `naming/sniffer.rs` | Per-interface naming capture |
| `src/lib/pages/connections/EndpointsPanel.svelte`, `src/lib/components/Sparkline.svelte` | The panel |
| `src/lib/stores/monitor.svelte.ts` | Per-endpoint history, focus state |

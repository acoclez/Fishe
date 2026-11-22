# Security view

The Security page turns what Fishe already measures into an answer to
"what on this machine deserves a look?". It lists **findings**, each a fact
with the reason it matters, and below them the facts themselves: what each
program talks to, who can connect to this machine and who tried, the DNS
servers, whether a VPN carries the traffic, and the local networks scanned
so far.

Fishe observes. It blocks nothing, and it does not decide that a program or
a device is malicious: it reads packet headers, not content, and headers
cannot show intent. A finding says what was seen and what that does and
does not prove.

## Where the facts come from

| Card | Source | Needs |
|---|---|---|
| Programs | The session's per-endpoint counts (programs, service ports), plus TLS hellos read by the naming capture | an **All** traffic session |
| Inbound connection attempts | TCP handshakes seen by the capture: a request arriving for a local port, and this machine accepting it | an **All** traffic session |
| DNS | DNS questions and answers read by the naming capture | an **All** traffic session, with endpoint naming on |
| Listening services | The socket table (the one process attribution uses), read when the page asks | nothing |
| VPN | The interfaces and two route lookups, read when the page asks; per-interface counts of the session | nothing for the tunnel and the routes; an **All** traffic session started while the tunnel is up for what left outside it |
| Local network | The devices and DHCP servers found by LAN scans, remembered between scans; DHCP answers read by the naming capture | at least one scan (the answers heard need an **All** traffic session) |

A session on one host or one program does not see the whole machine, so it
is not audited; the page says so. The session's facts live with the
session: a new session starts from nothing. When a session stops, the page
keeps showing what it found, marked as such, until another one runs.

Reading the report sends nothing and contacts no service. Organisations
and countries come from the owner database when it is installed, and from
lookups already made; the report never triggers one. The one thing in this
view that sends a packet is the DHCP question, and it is part of the LAN
scan, which only runs when asked for.

## The cards

### Programs

One row per program that exchanged traffic.

| Column | Meaning |
|---|---|
| Endpoints | Remote addresses it exchanged traffic with (not this machine, not broadcast or multicast groups) |
| Countries, Organisations | Of its Internet endpoints, most traffic first. *unknown* when the owner database is not installed or does not cover the address |
| Unencrypted | Traffic on ports whose protocol sends its content in clear text (below) |
| TLS | *TLS 1.0 offered* when a connection of the program offered nothing newer than TLS 1.0 or 1.1; *current* otherwise |

**Unencrypted** is decided by the port, because the content is not read:

| Certainty | Ports | Shown as |
|---|---|---|
| Unencrypted, carries logins | FTP 21, Telnet 23, rlogin 513, rsh 514 | red |
| Unencrypted | HTTP 80, TFTP 69/udp, SNMP 161/udp, syslog 514/udp | amber |
| May be unencrypted | SMTP 25 and 587, POP3 110, IMAP 143, LDAP 389: they can switch to TLS after connecting (STARTTLS), and the headers do not show whether they did | grey |

Only data counts as use. For the TCP services, what is added up is the
payload that passed on the port, so a connection request that was refused
or never answered (a closed port, a port scan) is not reported as "using
Telnet". The UDP services have no connection to refuse: a datagram counts.

DNS (port 53) has its own card. Within one tick an endpoint is nearly
always one program's; when two programs share an endpoint in the same tick,
the unencrypted bytes of that tick go to the one that moved the most.

**TLS** is what the program *offered* in its hello (the highest entry of
`supported_versions`, or the hello's own version field), not what the
server chose: the server's answer is not captured. Only connections to
port 443 are read.

### Listening services

Programs accepting TCP connections right now, from the socket table.

| Reachable from | Meaning |
|---|---|
| The network | Bound to a network address or to all of them: other machines can try to connect. Whether a firewall lets them is not visible to Fishe |
| This PC only | Bound to the loopback address |

Remote access, file sharing and database ports (SSH, Telnet, FTP, SMB,
Remote Desktop, VNC, WinRM, SQL Server, MySQL, PostgreSQL, Redis, MongoDB,
Elasticsearch, the Docker API) are marked when reachable from the network.

### Inbound connection attempts

Every remote address that sent a TCP connection request to this machine
during the session: the ports it tried, how many requests, and how many
this machine accepted (it answered the handshake). Ten or more different
ports from one address is shown as a **scan**. UDP has no handshake and is
not covered.

### DNS

The servers asked over plain DNS (UDP port 53), with questions, questions
never answered (10 s), error answers, "no such name" answers (normal) and
the answer time. Times come from the capture's timestamps.

Below the table: whether encrypted DNS was seen. DNS over TLS is traffic to
TCP port 853. DNS over HTTPS looks like any HTTPS; it is recognised when a
connection's server name is a known public resolver (`dns.google`,
`cloudflare-dns.com`, `dns.quad9.net`, NextDNS, AdGuard, OpenDNS, Mullvad
and a few more). A resolver that is not on that list is not recognised.

On Windows, programs ask the system's DNS client, which sends the
questions: they cannot be attributed to the program that wanted the name.

### VPN

Three questions, each answered from something observable.

| Question | How it is answered |
|---|---|
| Is a tunnel up? | An interface that is up, has an address, and is a VPN's by its driver or name: WireGuard, OpenVPN (TAP, Wintun, DCO), and the adapters of NordVPN, Proton VPN, Mullvad, ExpressVPN, Surfshark, Private Internet Access, Windscribe, Tailscale, ZeroTier, Cloudflare WARP, Cisco, Fortinet, GlobalProtect, SonicWall, Check Point, Juniper; on Linux `wg0`, `tun0`, `tap0`, `ppp0`, `tailscale0` and the like |
| Where does Internet traffic leave? | The interface the system would send from to reach a public address, asked for IPv4 and for IPv6 (a route lookup; no packet is sent) |
| What left outside the tunnel? | In an All traffic session that captures on the tunnel: the Internet addresses reached through any other interface, and the unencrypted DNS questions seen there |

The busiest address outside the tunnel is shown apart, as the VPN server:
the tunnel's own encrypted packets travel to it through the ordinary
connection, so it is always there and always the largest. It is an
assumption, stated as one; the others are what the VPN did not carry.

Traffic to the local network is not "outside the tunnel": only Internet
addresses count. A tunnel that is up without carrying Internet traffic (a
mesh VPN such as Tailscale, a split tunnel for one office network) is
listed, and nothing is reported about it: nothing was meant to go through.

The session's interfaces are fixed when it starts. A tunnel that comes up
later is listed, but what goes inside and outside it is only measured by a
session started while it is up.

### Local network

Each scan on the Map page is folded into an inventory. A network is
recognised by its address range, its gateway's address and its gateway's
hardware address together.

| Reported | When |
|---|---|
| New device | A hardware address not seen in earlier scans of that network; the scan list on the Map page marks it too. Never on a network's first scan, when everything is new |
| Gateway changed | The gateway's address answers from a hardware address not seen for it before |

A gateway answering from another hardware address is what an ARP spoofing
attack looks like, and also what a replaced router looks like, and what
another network with the same addresses looks like (two places that both
use `192.168.1.0/24`). The three cannot be told apart, so it is reported
once, when first seen; after that both networks are known, each with its
own devices.

The inventory is a file in the data folder (`lan.json`): hardware
addresses, names and makers of devices on networks the user scanned. It
never leaves the machine. **Forget devices** on the card deletes it.

**DHCP servers.** A DHCP server tells every device that joins which gateway
and DNS servers to use; a second one can hand out its own and so receive
those devices' traffic. Two ways of knowing who answers:

| | How | When |
|---|---|---|
| Asked | The scan broadcasts one DHCPDISCOVER and lists the servers that offer an address, with the gateway and DNS servers each hands out ([lan-mapping.md](lan-mapping.md)) | each LAN scan |
| Heard | The naming capture reads the offers and acknowledgements that go by (replies to other devices are usually broadcast) | during an All traffic session |

More than one server on a network is reported: as a warning when they hand
out different gateways or DNS servers, as a notice when they hand out the
same (two servers backing each other up do).

## Findings

Pure rules over the report (`security/findings.rs`): the same facts always
give the same list. Three levels: **Note** (worth knowing), **Notice**
(worth a look), **Warning** (worth acting on, or at least understanding).

| Finding | Note | Notice | Warning |
|---|---|---|---|
| A program used an unencrypted service | on the local network only; a protocol that may upgrade to TLS; less than 64 KiB of HTTP; HTTP to hosts that use it by design | 64 KiB or more of HTTP to the Internet; a login protocol on the local network | a login protocol (Telnet, FTP, rlogin, rsh) to the Internet |
| A program offered nothing newer than TLS 1.0 / 1.1 | | always | |
| One address tried 10 or more ports | | always | when this machine accepted one of the connections |
| A connection was accepted from the Internet | | always | on a remote-access, file-sharing or database port |
| A sensitive service is reachable from the network | remote access, file sharing, databases | those that often run without a password (Telnet, FTP, VNC, Redis, MongoDB, Elasticsearch, the Docker API) | |
| A DNS server fails | | 20 % or more of at least 20 questions unanswered or answered with an error | |
| DNS questions go unencrypted to the Internet | always (one line for all such servers) | | |
| The gateway's hardware address changed | | | always |
| New devices on the local network | always | | |
| Several DHCP servers answer on one network | | they hand out the same gateway and DNS servers | they hand out different ones |
| A VPN carries IPv4 while IPv6 leaves directly | | | always |
| DNS questions left outside the VPN | | always | |
| Internet addresses other than the VPN server were reached outside the VPN | | always | |

The three VPN findings exist only when a tunnel carries this machine's IPv4
Internet traffic; the last two also need a session that captures on it.

**HTTP by design.** Certificate status and revocation lists (`ocsp.…`,
`crl.…`, Let's Encrypt, DigiCert and others), connectivity checks
(`msftconnecttest.com`, `connectivitycheck.gstatic.com`, …) and operating
system updates (`windowsupdate.com`, `delivery.mp.microsoft.com`,
`deb.debian.org`, `archive.ubuntu.com`) are served over plain HTTP on
purpose: the content is public and verified by other means. HTTP to these
is noted, whatever the amount, and never raised to a notice.

A connection accepted from an address on the local network is ordinary
(file sharing, a printer) and gives no finding unless it is part of a scan.

## Limits

- **Headers only.** "Unencrypted" is a statement about the service on a
  port, never about what was sent. A program that speaks something else on
  port 80, or plain HTTP on another port, is not seen for what it is.
- **Attribution.** A finding names the program that owned the connection
  when Fishe could find it. Short-lived programs can end up under
  *a program Fishe could not identify* (see [process-mode.md](process-mode.md));
  running elevated on Windows makes attribution exact.
- **TLS** is the version offered, on port 443, for connections opened
  while the session runs. The negotiated version, certificates and ciphers
  are not examined.
- **Firewalls are invisible.** A listening service is reported as
  reachable from the network when its socket is; a firewall may still block it.
- **Inbound attempts** are those that reach this machine's interfaces. A
  router or firewall in front of it filters most of the Internet's noise
  before Fishe can see it.
- **VPN tunnels are recognised by name.** A VPN whose adapter has a name
  of its own is not seen as one; this includes connections made with
  Windows' built-in VPN client, which the capture driver does not list.
  "Outside the tunnel" cannot tell split tunnelling from a leak: both look
  the same on the wire.
- **DHCP servers** are those that answer a broadcast question, or whose
  answers pass this machine. A server that only answers some devices, or
  whose answers to others are sent directly to them on a switched network,
  is not seen.
- **No history.** The session's facts are not recorded; a recording keeps
  the traffic figures, not the security report.

## Bounds

Remote addresses and ports are chosen by whoever sends the packets, so
everything kept is capped.

| Kept | Limit | Beyond it |
|---|---|---|
| Programs | 512 | counted, not listed |
| Endpoints per program | 512 | counted in the program's bytes |
| Unencrypted (endpoint, service) pairs per program | 64 | not added |
| Remote addresses with connection attempts | 512 | the one quiet for longest is forgotten |
| Ports per such address | 128 | counted |
| Connection attempts per capture batch | 1,024 (address, port) pairs | not counted |
| DNS servers | 16 | not counted |
| Internet addresses reached outside a tunnel | 256 | counted in the bytes |
| DHCP servers heard, per session | 32 (interface, server) pairs | not kept |
| DHCP servers listed per scanned network | 8 | not listed |
| Networks in the inventory | 32 | the one scanned longest ago is forgotten |
| Devices per network | 2,048 | the one seen longest ago is forgotten |
| Rows per table in a report | 200 | the count is still exact |

## Agents

`get_security_report` (read access) returns the same report as the page:
`findings`, `session`, `listeners`, `vpn`, `lans`. See [mcp.md](mcp.md).

## What was verified

| Checked | How |
|---|---|
| The rules, the audit's bounds, the inventory, the TLS and DNS parsing | unit tests (`cargo test -p fishe-core security`, `inventory`, `sniffer`, `tls`) |
| A real session on Windows: `curl` offering TLS 1.0 is reported under `curl.exe`; plain HTTP is reported per program; three public DNS servers asked in clear text with real answer times; the listening services of the machine | the built app, and `ops::tests::live_security_report` |
| The same live test on Linux, with a second machine trying 27 ports, one of them open: reported as a scan with an accepted connection, and its refused requests to the FTP and Telnet ports not reported as use of them | two containers on one Docker network (see [development.md](development.md#linux)) |
| DHCP discovery on a real home network: the router answers, offering this PC the address it already has; its answers are also heard by a running session | `lan::dhcp::tests::live_discover` and the live test with `FISHE_LIVE_DHCP`, on Windows |
| Two DHCP servers on one network: both listed by the scan's question, both heard by a session, reported as a warning because they hand out different gateways | two `dnsmasq` containers and a third running the tests, on Linux |
| A tunnel carrying the default route, with two addresses routed around it: IPv4 reported as going through the tunnel, traffic counted on each side, the address routed around it and the DNS question listed as outside | a container with an interface named `tun0`, on Linux |
| No tunnel: none listed, both address families reported as leaving through the Ethernet adapter | the built app on Windows |
| The page: every card, the states without a session and after one, a scan that finds a new device, a VPN with an IPv6 bypass, a second DHCP server | browser preview with sample data (`?vpn`, `?dhcp2`), and the built app |

Not verified against the real thing: an actual ARP spoofing on a LAN, a
scan from the Internet, a DNS server that really fails, and a real VPN
client (the tunnel above was an interface with a tunnel's name, not
WireGuard or OpenVPN; recognising each product's adapter rests on its
published driver name). Those paths are covered by unit tests with
constructed inputs.

## Code map

| File | Role |
|---|---|
| `security/audit.rs` | The session's facts: programs, connection attempts, DNS servers, TLS offers; bounded |
| `security/mod.rs` | The report types and how a report is assembled from the facts, the socket table and the inventory |
| `security/findings.rs` | The rules |
| `security/services.rs` | What a port number means: unencrypted services, sensitive listeners, DNS-over-HTTPS hosts, HTTP by design |
| `security/vpn.rs` | Tunnel interfaces, the two route lookups, the card |
| `lan/inventory.rs` | Devices, gateways and DHCP servers remembered between scans; `lan.json` |
| `lan/dhcp.rs` | The DHCPDISCOVER the scan sends, and the reply parser the scan and the sniffer share |
| `monitor/quality.rs`, `monitor/stats.rs` | Connection attempts noted from TCP handshakes (`Tally::note_syn`); payload on the audited ports (`Tally::note_payload`) |
| `naming/sniffer.rs`, `naming/tls.rs`, `naming/dns.rs` | DNS questions and answers, TLS hellos, DHCP answers, and which side of a tunnel they were seen on (`AuditTap`) |
| `monitor/engine.rs` | Per-interface counts handed to the audit before the workers' tallies are merged (`Audit::note_worker`) |
| `ops.rs` | `security_report`, `scan_lan`, `lan_forget` |
| `src/lib/stores/security.svelte.ts` | Polls the report while the page is open; keeps the last session's part |
| `src/lib/pages/security/SecurityPage.svelte` | The page |

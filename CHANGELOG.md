# Changelog

## 0.17.0 (2026-11-20)

- **Security page** (key 4; Archive is now 5, Settings 6). During an All
  traffic session it lists what deserves a look, each with the reason:
  programs using unencrypted services (FTP, Telnet, HTTP, …) or offering
  nothing newer than TLS 1.0 / 1.1, addresses that tried many ports of this
  machine, connections accepted from the Internet, DNS servers that fail or
  are asked in clear text. Below the findings: who each program talks to
  (organisations, countries), the connection attempts received, and the
  DNS servers with their answer times.
- The page also lists, at any time, the programs accepting connections and
  whether other machines can reach them.
- **VPN** on the Security page: the tunnel interfaces that are up, whether
  IPv4 and IPv6 leave through one (a VPN that carries IPv4 while IPv6
  leaves directly is flagged), and, in a session started while the tunnel
  is up, the Internet addresses and DNS questions that left outside it.
- LAN scans are remembered between runs: a scan marks the devices that were
  not there before, and the Security page says when the gateway answers
  from another hardware address. **Forget devices** deletes that memory.
- A LAN scan now also asks which DHCP servers answer (one broadcast
  question; no lease is taken) and shows what each hands out. More than
  one on a network is flagged, as are DHCP answers from several servers
  heard during a session.
- Agents get the same report through a new read-only tool,
  `get_security_report`.
- Fishe reads packet headers, not content: findings state what was seen
  and what it does not prove. docs/security.md has the rules and limits.

## 0.16.0 (2026-11-20)

- **Linux.** Fishe runs on Linux, from a `.deb` or `.rpm` package: capture
  through libpcap, traffic per program, endpoint naming, connection quality,
  ping and traceroute, the LAN scan, the route map, recordings and the MCP
  server. Capturing takes a permission you grant once after installing; the
  Live page shows the command. What differs from Windows is in
  docs/linux.md.
- The selected target (Host, Process, All) is filled like the other
  selectors; it was only shown in bold.
- A LAN scan stays on the Map page after a visit to another page, until the
  next scan or until Fishe closes.

## 0.15.1 (2026-11-20)

The first version with installers. 0.15.0 was published as source only; the
features are listed under 0.15.0 in CHANGELOG.md.

- The interface is built with SvelteKit 3 instead of SvelteKit 2, which has
  open security advisories. They concern server features Fishe does not use
  (it ships as static files inside the app), so 0.15.0 was not exposed; the
  affected code is no longer part of the build.

## 0.15.0 (2026-11-19)

First public release.

- Monitoring of a remote host, of one program, or of all traffic labelled by
  program, with a gauge and chart that compare the traffic to its learned
  normal level.
- Per-program attribution from the socket table, exact with ETW when run as
  administrator.
- Endpoints named from TLS server names, DNS answers and reverse DNS, with
  owner and country from the DB-IP Lite database.
- Connection quality from passive TCP analysis (round-trip time, jitter,
  retransmissions) and a continuous ping.
- Traceroute and a map of the routes to the endpoints.
- A scan of the local network: devices, makers, common services.
- Recordings with replay, CSV and JSON export, and optional pcapng files.
- A local MCP server for AI agents with three access levels.
- An install prompt when Npcap is missing.

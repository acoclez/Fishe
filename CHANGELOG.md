# Changelog

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

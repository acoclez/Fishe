# Changelog

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

# Agents (MCP)

Fishe includes a local **Model Context Protocol** server so AI agents
(Claude Code, Claude Desktop, any MCP client) can read its measurements
and, if you allow it, drive it: "what is using my network right now?",
"record the next five minutes and tell me when it spiked", "is my game
server's ping stable?".

It is **off by default**, listens on **this PC only**, needs a **token**,
and every call is shown in the app.

## Turning it on

**Settings → Agents (MCP)**:

1. **Allow agents to connect.** The pill at the top right says
   **Listening · N calls** (or the error, e.g. port in use).
2. Pick the **access level**:

   | Level | Agents can |
   |---|---|
   | **Read only** (default) | read status, history, endpoints, programs, packets, recordings, traces, pings, processes, interfaces, owners |
   | **+ Control** | also start/stop monitoring and recording |
   | **+ Network probes** | also traceroute and ping, i.e. send packets |

   The level applies immediately, to connected agents too; tools above it
   are neither listed nor callable.
3. Under **Connect a client**: the port and URL, the **token** (hidden
   until **Show**, everywhere including the configuration preview; **Copy**
   always copies the real one; **New** revokes it), and a ready-to-paste
   configuration (tabs **Claude Code**, **Claude Desktop**, **Other clients**).

The header shows an **Agents** chip while the server runs; it flashes on
each call and opens Settings. The **Activity** list shows every call: time,
client, tool, arguments, duration, result or error (last 200).

## Connecting a client

**Claude Code** (desktop app Code tab or terminal), no CLI needed: save
this as **`.mcp.json`** in the folder you open in Claude Code, start a new
session there and approve *fishe* when asked. Keep the file out of git (it
holds the token; Fishe's own `.gitignore` lists it).

```json
{ "mcpServers": { "fishe": { "type": "http", "url": "http://127.0.0.1:47823/mcp",
  "headers": { "Authorization": "Bearer <token>" } } } }
```

With the `claude` command installed, this registers it for every folder
instead:

```bash
claude mcp add --transport http fishe http://127.0.0.1:47823/mcp --header "Authorization: Bearer <token>"
```

**Other clients with HTTP support**: the same JSON, or URL
`http://127.0.0.1:47823/mcp` with the header `Authorization: Bearer <token>`.

**Claude Desktop** (and other clients that only launch local commands):
Settings → Developer → Edit Config, merge into
`claude_desktop_config.json`, restart Claude Desktop:

```json
{ "mcpServers": { "fishe": { "command": "C:\\Program Files\\Fishe\\fishe.exe", "args": ["--mcp-stdio"] } } }
```

On Linux the command is `/usr/bin/fishe`; Settings shows the configuration
with the right path for the copy that is running.

`fishe.exe --mcp-stdio` opens no window: it forwards each JSON-RPC line
from stdin to the running Fishe and writes the answer to stdout, reading
the port and token from `%APPDATA%\com.fishe.app\mcp.json` on every
message. Fishe itself must be running with agents allowed; otherwise the
bridge answers with an error that says so.

## Tools

Rates are **bytes per second**. `bytesPerSec` is in + out smoothed over
about a second: the rate the level is computed from, and the one to read.
`inBytesPerSec` / `outBytesPerSec` are the last 250 ms tick, which jumps
between 0 and a burst. Session times are seconds since the session started.
Levels: idle < calm < busy (≥ 2× normal) < spike (≥ 5×), each measured
against its own learned normal.

| Tool | Level | What it returns |
|---|---|---|
| `get_status` | read | Monitoring or not, the session (mode, label, interfaces, attribution), now: `bytesPerSec`, in/out rates, packets/s, level, ratio, normal, peak, totals, bytes by transport, top services, dropped/unattributed packets, endpoint and program counts, TCP quality, recording, `learningNormal` (true during the first seconds, while the level isn't meaningful yet). In host mode while Fishe pings that host, a `note` says its echoes are part of the traffic |
| `wait_for_traffic` | read | Blocks until traffic reaches `level` (calm / busy / spike, default busy) and/or `minBytesPerSec` (smoothed; alone: the rate only), or `timeoutSeconds` (≤ 120, default 30). `program` (all-traffic mode) or `endpoint` (IP or name substring) watches only the busiest match against its own normal, e.g. a game, so other traffic (the agent's own API calls included) doesn't trigger it; `matched` reports it. Returns the moment: rates, level, ratio, the 3 busiest endpoints and programs. "Tell me when it spikes" without polling. Levels are ignored while a normal is being learned (the first 5 s of the session, or of a new program or endpoint; a `note` says so), the rate counts at once |
| `get_traffic_history` | read | `seconds` (5–600, default 60) as at most `maxPoints` (default 60) points: averaged rates and normal, the highest level and RTT of each point (`rttMs` only where TCP gave one); `secondsPerPoint` says the resolution |
| `get_endpoints` | read | `limit` (≤ 150), `sort` (live = `bytesPerSec` / total / recent / rtt), `filter`: name and source, owner, country, rates, level, totals, services, RTT, min RTT, jitter, retransmissions, hop estimate, programs |
| `get_programs` | read | All-traffic mode: programs with rates, level, totals, endpoints, PIDs |
| `get_recent_packets` | read | `limit` (≤ 500), `filter`: latest packets (headers; `iface` is the interface name, empty fields left out). Turns the packet feed on for ~1.2 s if it is off. Responds within ~1.2 s |
| `list_processes` | read | Programs with sockets (names to pass to `start_monitoring`); `hiddenWithoutSockets` counts the others, listed with `includeNoSockets` or a `filter` |
| `list_interfaces` | read | Npcap devices |
| `list_recordings` | read | The archive |
| `get_recording` | read | `id`, `maxPoints` (default 100), `endpointLimit` (default 25): summary, notable moments, breakdowns, quality, endpoints, downsampled series (same field names as the live tools) |
| `get_route_traces` | read | Traceroutes done this run |
| `get_pings` | read | Running/stopped pings with figures and the last 30 probes |
| `lookup_owner` | read | `ip`: ASN, organisation, country |
| `start_monitoring` | control | `mode` host / process / all, with `host`, `process` (exe name) or `pid`, optional `interface`. Returns once the first measurement is in; a `note` says when no process matches yet (Fishe waits for it to start) |
| `stop_monitoring` | control | Stops the session (a running recording is saved) |
| `start_recording` / `stop_recording` | control | `name`, `pcap` / returns the saved recording's id |
| `trace_route` | network | `ip`, `force`: hops with names, owners, RTT. A `note` flags a public address answered at the first hop (the router or a local device answers for it, e.g. some ISP boxes intercept 1.1.1.1) |
| `start_ping` / `stop_ping` | network | `ip`: 1 ICMP echo per second, ≤ 4 at once, 30 min max |

**Arguments are checked**: an unknown argument (a typo like `limt`), a wrong
type (`limit: "abc"`, `-5`) or a value outside an enum (`sort: "bogus"`) is
an error naming what the tool accepts, never silently the default. A read
right after `start_monitoring` waits up to 2 s for the first measurement.

Every tool carries MCP annotations (`readOnlyHint` for read tools,
`openWorldHint` for network probes). Results are returned both as
structured content and as compact JSON text (no pretty-printing: it would
cost the agent's context about 30% more).

**One path for the window and agents.** `start_monitoring` starts the
session itself, through the same service layer (`crates/fishe-core/src/ops.rs`) as
a click on Start, with the Settings the window last pushed (sensitivity,
reverse DNS), so a session an agent starts measures exactly like one you
start. It works with the window minimised or not yet shown. The window
follows through its monitor subscription: it switches to Live, shows the
mode and target, the REC chip and the "saved" toast; pings and traces an
agent starts refresh the ping chip and the map.

## Security

| Measure | |
|---|---|
| Off by default | nothing listens until you enable it |
| Loopback only | binds `127.0.0.1`; other machines can't connect |
| Token | `Authorization: Bearer <token>` (192 random bits) on every request; otherwise **403** with "missing or wrong bearer token". Not 401: clients answer any 401 by starting an OAuth sign-in, which Fishe doesn't offer |
| Host / Origin checks | `Host` must be `127.0.0.1:<port>` or `localhost:<port>`, and an `Origin`, if present, the same; otherwise **403** (enforced by `rmcp`). A web page in a browser can't use DNS rebinding to reach it, and no CORS headers are sent |
| Least privilege | three levels; tools above the level are hidden and refused |
| No deletion | no tool deletes recordings or changes settings |
| Visible | Agents chip, activity log, and the window shows what an agent started |
| Bounded | request body ≤ 1 MiB; pings ≤ 4 and ≤ 30 min; traceroute cache 10 min |
| Names are data | endpoint names come from packets other hosts send. Only host-name characters are kept, and DNS answers only when this machine asked (see [endpoints.md](endpoints.md)), so a name cannot carry text meant for the agent |

The token is stored in plain text in `mcp.json` next to the archive (your
user profile), like other local API tokens; anyone who can read your
profile can use it. Regenerate it if it leaked.

## Protocol details

- Built on the official Rust SDK, **`rmcp` 3.9** (`StreamableHttpService`
  behind axum on Tauri's tokio runtime). It negotiates the protocol version
  (2024-11-05 … 2026-07-28), manages sessions, validates Host/Origin and
  shuts down gracefully (the port is free again at once).
- **Streamable HTTP**, `POST /mcp`. With a session (`initialize` returns
  `Mcp-Session-Id`), each answer comes as a short server-sent-event stream
  (`text/event-stream`), as the spec allows; clients and the stdio bridge
  read it. Notifications get `202`.
- Each session knows its client (`clientInfo` from `initialize`), so the
  activity log names the right client when several are connected. The
  2026-07-28 revision has no `initialize`: such clients appear unnamed.
- Tools do blocking work (traceroute, `wait_for_traffic`) on blocking
  threads, so a long call never stalls the others.
- Unknown tool or a tool above the access level → JSON-RPC error `-32602`;
  a tool that fails (e.g. "not monitoring") → result with `isError: true`
  and the reason as text.
- Configuration file: `<data dir>\mcp.json` (`enabled`, `access`, `port`,
  `token`). The data dir is `%APPDATA%\com.fishe.app`, or `FISHE_DATA_DIR`.

## Code map

| File | Role |
|---|---|
| `crates/fishe-core/src/mcp/mod.rs` | `McpState`: config (`mcp.json`), access levels, token, start/stop, activity log, events |
| `crates/fishe-core/src/mcp/server.rs` | `rmcp` `ServerHandler` (info, `initialize`, `tools/list`, `tools/call`), the Streamable HTTP service, token check, axum listener with graceful shutdown |
| `crates/fishe-core/src/mcp/tools.rs` | Tool table (`TOOLS`): typed argument structs with `schemars` schemas, handlers; the tests check the docs table above against it |
| `crates/fishe-core/src/ops.rs` | Service layer shared with the IPC commands: start/stop sessions and recordings, probes, pings, traces (and the `fishe://…-changed` notices) |
| `crates/fishe-core/src/mcp/bridge.rs` | `--mcp-stdio` bridge (JSON or SSE answers) |
| `crates/fishe-core/src/monitor/live.rs` | Latest sample and 10-minute history for non-UI readers |
| `src/lib/stores/agents.svelte.ts` | Settings, activity log, and the pings / traces "changed" notices |
| `src/lib/pages/settings/AgentsSettings.svelte` | Settings → Agents (MCP) |

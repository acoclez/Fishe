# Architecture

Fishe is a Tauri 2 desktop app: a Rust process that owns packet capture, and a
WebView2 window running a Svelte 5 single-page app that renders the gauge.

The Rust side is a workspace of two crates:

| Crate | Folder | Holds |
|---|---|---|
| `fishe-core` | `crates/fishe-core` | Everything that measures, records and answers: capture, attribution, naming, the detector, recordings, probes, the MCP server. **No window in it**: it does not depend on Tauri |
| `fishe` (the app) | `src-tauri` | The window: Tauri setup, the IPC commands, the generated TypeScript bindings |

The core keeps all its state in one `Services` value. The app creates it at
startup and hands it to the commands; the MCP server inside the core works
on the same value. What a window needs to hear leaves the core through
plain callbacks (session events, and "changed" notices for pings, traces
and agent calls), which the app turns into a Tauri channel and Tauri
events. With nobody listening the core runs the same, which is what makes a
windowless run and other platforms possible: the core already builds and
passes its tests on Linux (see [development.md](development.md#linux)).

A session targets either a **host** (one remote IP) or a **process** (a
program or PID, see [process-mode.md](process-mode.md)).

## Components

```
┌──────────────────────────────── Rust process ────────────────────────────────┐
│ main thread (Tauri)                                                          │
│   commands.rs ─ spawn_blocking ─▶ MonitorState::start(TargetSpec)            │
│                                     │ resolve target, open captures,         │
│                                     │ build Matcher, start ETW (if admin)    │
│                                     ▼                                        │
│ session thread "fishe-session-N"  (aggregator)                               │
│   ├─ every tick: merge tallies ▶ BusyDetector ▶ Sample ▶ Channel             │
│   ├─ process/all mode: socket-table poll + PID refresh ─▶ Process/MachineScope│
│   ├─ EndpointBook, ProgramBook (all mode)                                    │
│   └─ owns workers ───────────────────────────────┐                           │
│                                                   ▼                          │
│ capture threads "fishe-capture-N-i"  (one per interface)                     │
│   Npcap (BPF) ─▶ net::parse ─▶ Matcher::classify ─▶ Tally ─ every 50 ms ─▶   │
│                                  │ (Packets view on) summary ─▶ PacketRing    │
│                                  │ Pending → hold ≤ 2 s, retry on change      │
│                                  ▼                                           │
│      Host(ip) | Process(ProcessScope) | All(MachineScope) ─▶ OwnershipTable  │
│                                                        ▲         ▲           │
│                                           socket poll ─┘         └─ ETW      │
└──────────────────────────────────────────────────────────────────────────────┘
                        EventSink (the window's subscription)
┌────────────────────────────── WebView2 (Svelte) ─────────────────────────────┐
│ monitor.svelte.ts ◀── started / sample / warning / recording… / stopped      │
│   ├─▶ Gauge, TrafficChart, StatTiles, ProtocolBreakdown, TopPorts            │
│   └─▶ ProcessInfo, ProgramsPanel, EndpointsPanel, NetworkMap, PacketList     │
│ TargetForm ─ Host | Process | All ─▶ ProcessPicker ◀── list_processes        │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Rust modules (`crates/fishe-core/src`, and `src-tauri/src` for `commands.rs` and the app's `lib.rs`)

| Module | Responsibility |
|---|---|
| `npcap.rs` | Finds `System32\Npcap`, checks `wpcap.dll`, calls `SetDllDirectoryW`, reads `pcap_lib_version()`. Gatekeeper for every pcap call. |
| `net/capture.rs` | Opens a pcap capture (`OpenCapture`): snaplen, read timeout, kernel buffer, BPF filter; used by the measuring workers, the naming sniffers and the LAN scan. |
| `net/parse.rs` | Zero-allocation header parser: Ethernet/VLAN, DLT_NULL loopback, raw IP → IPv4/IPv6 → TCP/UDP ports. |
| `net/interfaces.rs` | Device list; route-based pick for host mode; `active_devices` for process and all-traffic mode. |
| `net/resolve.rs` | IP literal or host name → `IpAddr`. |
| `process/*` | (Linux: the socket table and process list come from `/proc`, see `procfs.rs`.) Process list, socket table, ownership table, ETW tracker (`EtwSink`), PID scope, machine scope (all-traffic labelling), per-tick refresh (`refresh.rs`). See [process-mode.md](process-mode.md), [all-traffic.md](all-traffic.md). |
| `naming/*` | Endpoint names: DNS/mDNS answers, TLS SNI, reverse DNS, address types; per-interface naming capture. See [endpoints.md](endpoints.md). |
| `monitor/endpoints.rs` | `EndpointBook`: per-remote-IP totals, detectors and rows. |
| `monitor/programs.rs` | `ProgramBook`: per-program totals, detectors, endpoint counts (all-traffic mode). |
| `monitor/packets.rs` | `PacketRing`: live packet list for the Packets view, off unless open. |
| `monitor/quality.rs` | TCP flow tracking per worker (RTT, retransmissions) and the session / endpoint quality figures. See [connection-quality.md](connection-quality.md). |
| `archive/*` | Recordings: SQLite store, recorder (`Accumulator` → `Sink`) and pcapng writer threads, exports. See [archive.md](archive.md). |
| `route/*` | Traceroute and continuous ping through the Windows ICMP API, gateways, LAN neighbours. See [network-map.md](network-map.md), [connection-quality.md](connection-quality.md). |
| `lan/*` | LAN map: adapter list (`GetAdaptersAddresses`), active ARP sweep through Npcap, MAC→vendor from the bundled IEEE list, common-port probe. See [lan-mapping.md](lan-mapping.md). |
| `geo/*` | Endpoint owner & country: DB-IP Lite (offline, downloaded on request), ipinfo.io (opt-in). See [owners.md](owners.md). |
| `monitor/target.rs` | `TargetSpec` (host / process / all), `ProcessSelector` (name / pid), `Matcher`, `Verdict` (`Match`, `Owned`, `Skip`, `Pending`). |
| `monitor/engine.rs` | `WorkerCore` (parse, classify, hold/retry pending) and `Aggregator` (merge, tick, refresh, emit) as plain state machines, unit-tested with synthetic packets; `run` wraps them in the pcap loop, threads and UI channel. |
| `monitor/stats.rs` | `Tally` (mergeable counters, per-protocol bytes, port table). |
| `monitor/gauge.rs` | `BusyDetector`: fast EWMA vs. log-domain baseline → ratio → level. |
| `monitor/events.rs` | `MonitorEvent` (`started` / `sample` / `warning` / `recordingStarted` / `recordingStopped` / `stopped`) and `EventSink`, the window's one subscription every session reports through. |
| `monitor/mod.rs` | `MonitorState`: at most one session; prepares host, process or all-traffic sessions; the subscription and the Settings defaults agent-started sessions use; packet feed. |
| `services.rs` | `Services`: the monitor, archive, owner data, traces, pings, MCP state and paths in one value; `Notice`s for what a window re-reads; `shutdown()`. |
| `ops.rs` | Service layer: start/stop sessions and recordings, probes, traces, pings, owners. Both front doors call it: the IPC commands (`commands.rs`) and the MCP tools (`mcp/tools.rs`), so an agent and a click do the same thing. |
| `mcp/*` | Local MCP server for agents on the `rmcp` SDK: config and access levels, Streamable HTTP service with token check, tools, stdio bridge. See [mcp.md](mcp.md). |
| `monitor/live.rs` | Latest sample and 10-minute history of the running session, for the MCP server. |
| `commands.rs` | Tauri IPC handlers, thin over `ops.rs`; blocking work goes to `spawn_blocking`. |
| `error.rs` | `AppError`, serialized as `{ code, message }`; codes in [ipc-api.md](ipc-api.md#errors). |
| `paths.rs` | `Paths`: the data folder (`FISHE_DATA_DIR`, else `%APPDATA%\com.fishe.app`) and where the archive, owner data, MCP settings and logs live under it. Resolved once in `setup` (and kept in Tauri state) and by the stdio bridge. |
| `logging.rs` | The `log` backend: stderr plus `logs/fishe.log` (2 MB, one rotated copy); `FISHE_LOG` sets the level overall or per module. |
| `util.rs` | Small shared helpers: `now_ms`, `format_mac`, `ipv4_from_ne`, `par_for_each` (bounded thread pool for short blocking I/O). |

## Threads and lifecycles

| Thread | Lives | Does |
|---|---|---|
| Tauri main | app lifetime | window, IPC dispatch |
| Tokio blocking pool | per command | DNS, device/process listing, opening captures, joining the session |
| `fishe-mcp` (2 workers + blocking pool) | app lifetime, once the MCP server first starts | The MCP server's own async runtime: HTTP on the workers, tool calls on its blocking pool |
| `fishe-session-N` | one session | aggregator: ticks, detector, process refresh, emits samples |
| `fishe-capture-N-i` | one session | one per interface: `next_packet` loop, classification, tallies |
| ferrisetw processing thread | one process session, elevated only | ETW callbacks → ownership table, process starts |
| `fishe-naming-N-i` | one process session | one per interface: DNS/mDNS answers and TLS ClientHellos → name book |
| `fishe-rdns-0..2` | one process session | background PTR lookups |
| `fishe-recorder-N` | one recording | batches samples, endpoints and episodes into SQLite |
| `fishe-pcap-N` | one recording with packet headers | drains the packet tap into a `.pcapng` |
| probe threads (scoped) | one traceroute | up to 10 parallel TTL probes; then `fishe-hop-ptr` threads name the hops |
| `fishe-ipinfo` | app lifetime, after online lookup is first used | rate-limited ipinfo.io requests |

A session ends when:

1. **The user stops it.** The aggregator sees the stop flag within ≤ 50 ms,
   stops and joins the workers, drops the ETW trace, then sends
   `stopped { reason: userRequested }`.
2. **Every worker failed** (adapter removed, driver error): `stopped { reason: error }`.
   If only some fail (process mode, several interfaces), a `warning` is sent
   and capture continues on the rest.
3. **The app exits**: `RunEvent::Exit` calls `stop()`. A session does not
   depend on the window: if the webview's subscription fails, the sink drops
   it and the session (and an agent's recording) carries on; the window
   subscribes again when it is back.

## Design choices

| Decision | Why |
|---|---|
| **Aggregate in Rust, ~4 messages/s to the UI** | UI cost is independent of packet rate. |
| **Workers + aggregator** | One capture per interface in parallel, each counting into its own tally (the only shared state a packet touches is the read-locked ownership table); workers batch every 50 ms; one place owns time, detection and process refresh. |
| **Kernel BPF filter** | Host: `host X`. Process: `tcp or udp` (only port-based traffic can be attributed). |
| **Snaplen 192 bytes** | Headers only; byte counts use the original wire length. |
| **Port-based process attribution** | Works without admin and needs no driver beyond Npcap; ETW adds exactness when elevated. |
| **Hold-and-retry for unknown owners** | A connection's first packets often precede the next socket poll; holding them for ≤ 2 s avoids systematic loss. |
| **Delay-loaded `wpcap.dll`** | The app starts and explains itself even without Npcap. |
| **Relative busyness** | A learned baseline makes "busier" meaningful for any host or process. |
| **One session at a time** | Simple state model; multi-session is a contained extension. |

## Extension points

- **Multiple sessions:** `MonitorState` → `HashMap<SessionId, Running>`.

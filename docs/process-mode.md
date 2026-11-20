# Process mode

Bind the gauge to a **program** (all its instances) or a single **PID**
instead of a remote IP. Every byte the process sends or receives, to any
address, on any interface, drives the gauge.

To see *every* program at once instead of one, use
[all-traffic mode](all-traffic.md): same attribution, but packets are only
labelled, never filtered out.

## Using it

1. Switch the target to **Process**.
2. Open the picker: programs are grouped by executable name, busiest network
   users first, and the list refreshes every 3 s while open.
   - Click a program to follow **all its instances**, including ones started
     later (`chrome.exe` spawns many).
   - Expand it (›) and click a **PID** to follow just that one process.
   - Type a name that isn't running and press Enter (or click *Wait for "…"
     to start*) to arm the gauge before the program launches.
3. *Interface* defaults to **All active interfaces** (every adapter that is up
   with an address, plus loopback). Pick one to narrow it.
4. **Start**. The strip under the target bar shows the binding: matched PIDs,
   owned sockets, interfaces, attribution method, and unattributed packets.

In process mode, **Inbound** = received by the process and **Outbound** =
sent by it. The **Endpoints** panel below the chart lists every remote
address the process talks to, with names; see [endpoints.md](endpoints.md).

## How packets are attributed

Npcap packets carry no process id. Fishe attributes each packet by its **local
port**, using a shared `(transport, port) → PID` table
(`process/ownership.rs`) and a PID set (`process/scope.rs`: which processes
match the selector), fed by:

| Source | Mechanism | Admin | Latency | Catches |
|---|---|---|---|---|
| **Socket table** (`process/sockets.rs`) | `GetExtendedTcpTable` / `GetExtendedUdpTable` with owner PID, polled every tick (250 ms) | no | ≤ 1 tick | every socket alive at a poll |
| **Process list** (`process/processes.rs`) | Toolhelp snapshot every 4 ticks, and right away when a poll shows an unseen PID | no | ≤ 1 s | processes alive at a refresh |
| **ETW: Kernel-Network** (`process/etw.rs`) | TCP connect/accept, UDP send/recv (ids 12, 15, 28, 31, 42, 43, 58, 59), filtered in the kernel | **yes** | real time | sockets that open and close between two polls |
| **ETW: Kernel-Process** (`process/etw.rs`) | ProcessStart (id 1): PID + image name | **yes** | real time | processes that start and exit between two refreshes |

Both ETW providers share one trace session. The UI shows which mode is
active (**Socket table** or **Exact · ETW**). Fishe uses ETW automatically when
it runs elevated.

### Per packet (`process/scope.rs`)

```
TCP/UDP only (other protocols have no ports → skipped)
if src ∈ host addresses  and owner(src port) ∈ selected PIDs → Outbound
if dst ∈ host addresses  and owner(dst port) ∈ selected PIDs → Inbound
owner unknown, or owner PID not seen in the process list yet  → Pending
otherwise                                                     → not ours
```

*Host addresses* = every address of every adapter plus `127.0.0.1` / `::1`.

### Pending packets

A brand-new connection's first packets can arrive before the next poll has
seen its socket. Workers **hold** such packets (up to 2 s, 16k per interface)
and re-classify them whenever the ownership table or the PID set changes.
Packets still unresolved after 2 s are counted as **Unattributed**: they
belonged to *some* process Fishe could not identify in time.

### Keeping up with short-lived processes

- The PID set (which processes match the selector) refreshes every 4 ticks,
  **and immediately** whenever a socket poll shows a PID that didn't exist at
  the last refresh. A process living only a few hundred milliseconds is still
  identified while it's alive.
- **TIME_WAIT rows are ignored.** Windows lists closed connections in
  TIME_WAIT with PID 0, and several can share a local port with a new live
  connection. Before this rule, whichever row came last won, and traffic from
  rapid back-to-back connections was misattributed to "System Idle" (seen in
  testing as only 53–85% of a curl loop's traffic being counted).
- Mappings live 10 s after their socket disappears (`DEFAULT_TTL`), and a
  matched process stays selected for 10 s after it exits (`EXIT_GRACE`), so
  FIN/ACK packets and late UDP replies are still attributed. The UI's
  instance count shows only live processes.
- With ETW, a ProcessStart event selects a matching program the moment it is
  created, before its first packet. Without it, a process that lives less
  than one tick can exit before any refresh sees it.

### Measured accuracy

| Scenario | Mode | Payload | Counted by Fishe |
|---|---|---|---|
| Node process bound by PID: 5 small requests + one 25 MB download | no admin | 25.15 MB | 26.6 MB in + 0.3 MB out |
| `curl.exe` by name: 6 processes × 3 MB, each living ~650 ms | no admin | 18.0 MB | 19.1 MB in + 0.2 MB out |
| `curl.exe` by name: 12 processes × 200 KB, each living ~240 ms | no admin | 2.4 MB | 1.56–2.00 MB (varies run to run); rest *Unattributed* |
| same | **admin (ETW)** | 2.4 MB | **2.67 MB**, 0 unattributed |

Counts include TCP/IP/Ethernet header overhead (~5%, more for small TLS
transfers), so every row except the non-admin 240 ms case is complete.
Reproduce with `FISHE_LIVE_BYTES=200000 FISHE_LIVE_RUNS=12 cargo test -- --ignored live_short_lived --nocapture`
(elevated to include ETW).

## Limitations

- **Port-based attribution.** Two processes can't own the same local port at
  once for the same protocol, so this is exact for normal client/server
  sockets. Raw sockets and ICMP (`ping`) aren't attributable.
- **Without admin**, a process that starts, transfers and exits within
  about one tick (< 250 ms) can be missed; its traffic shows up as
  *Unattributed* (measured: 17–35% lost for 240 ms curl processes).
  ETW removes this gap (measured: 0 lost).
- **Traffic that never touches an adapter** Npcap sees (for example inside a
  VPN client's own driver before encryption) is visible only on the interface
  where it appears, often the VPN adapter.
- **Windows and Linux.** Elsewhere the Process switch is hidden
  (`system_capabilities().processMode = false`).

## ETW notes

- Session name: `Fishe-<app pid>-<session id>`, stopped when the session ends.
  If Fishe is killed, Windows keeps the trace until reboot or until you run
  `logman stop Fishe-… -ets`.
- Ports in Kernel-Network events are network byte order; Fishe converts them.
- ProcessStart `ImageName` is an NT path (`\Device\HarddiskVolume3\…\curl.exe`);
  only the file name is compared.
- WebView2 refuses `--remote-debugging-port` in an elevated app, so the
  elevated path is tested at the engine level rather than by driving the UI.
- To check it on your machine, from an **elevated** shell:
  `cargo test -p fishe-core -- --ignored etw_attributes_new_connection --nocapture`.

## On Linux

On Linux attribution follows the same model with `/proc` as the socket
table (`process/procfs.rs`).

| | Windows | Linux |
|---|---|---|
| Socket table | IP Helper tables, every tick | `/proc/net/{tcp,tcp6,udp,udp6}`, every tick |
| Owner of a socket | In the table (`dwOwningPid`) | Not in the table: the process whose `/proc/<pid>/fd` links to `socket:[inode]` |
| Program name | Image name (`chrome.exe`) | Executable's file name (`firefox`), or the 15-character command name when the executable is not readable |
| Exact, event-based source | ETW, as administrator | none |
| Rights | none | none for your own programs; **root** to see other users' |

- **Finding owners costs more than listing sockets**, so owners are
  remembered per inode. The descriptors are only walked when a socket
  appears that isn't known yet, starting with the processes that already
  own sockets and stopping once every new socket has an owner. Sockets
  whose owner can't be read are retried every 2 s.
- An owner is forgotten when its process exits, so a socket a child
  inherited is looked up again and goes to the child.
- A socket shared by a parent and its children counts for the lowest PID.
- Sockets without an owner (another user's, without root) are listed with
  PID 0, which never owns a port, exactly like Windows' TIME_WAIT rows.
- Without an event source, a connection opened and closed between two ticks
  is missed, as on Windows without administrator rights.

- Sockets in other network namespaces (containers) are not listed in
  `/proc/net`, so their traffic is not attributed.

The live tests cover this on Linux: the socket table finds the test's own
sockets, process mode counts its datagrams for its PID, and all-traffic
mode labels them with its program name (`scripts/linux-check.ps1 -Live`).

## Code map

| File | Role |
|---|---|
| `process/processes.rs` | Toolhelp process list, image paths, picker groups |
| `process/sockets.rs` | IP Helper TCP/UDP tables with owner PIDs |
| `process/procfs.rs` | Linux: `/proc/net` socket lists, owners through `/proc/<pid>/fd` (remembered per inode), process names; the parsers are tested on every platform |
| `process/ownership.rs` | Shared port → PID table (TTL, TIME_WAIT filtering, generation counter) |
| `process/etw.rs` | ETW tracker: Kernel-Network (socket owners) + Kernel-Process (process starts), feeding any `EtwSink` (process scope or machine scope) |
| `process/scope.rs` | Selector → PID set (with exit grace); per-packet classification |
| `process/elevation.rs` | Elevated-token check (Windows), root check (Unix) |
| `monitor/target.rs` | `TargetSpec`, `ProcessSelector`, `Matcher`, `Verdict` |
| `monitor/engine.rs` | Workers (hold/retry) and aggregator (refresh cadence) |
| `process/refresh.rs` | `refresh_process`: socket table every tick, process list every 4th tick or on an unknown PID |

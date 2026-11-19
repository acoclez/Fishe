# Development

## Prerequisites

| Tool | Version used | Notes |
|---|---|---|
| Windows | 10/11 x64 | |
| Npcap (runtime) | any recent | <https://npcap.com>, default install options |
| Npcap SDK (build) | 1.17 | `scripts/setup-npcap-sdk.ps1` → `vendor/npcap-sdk` |
| Rust | stable, `x86_64-pc-windows-msvc` | needs VS Build Tools (C++ workload) |
| Node.js | 20+ (26 used) | npm |
| WebView2 | evergreen | preinstalled on Windows 10/11 |
| Docker Desktop | optional | only for the Linux check of the core (`npm run check:linux`) |

## First-time setup

```powershell
powershell -ExecutionPolicy Bypass -File scripts/setup-npcap-sdk.ps1
npm install
```

## Scripts

| Command | What it does |
|---|---|
| `npm run tauri dev` | Run the desktop app with hot reload (Vite on :1420) |
| `npm run tauri build` | Release build + installers (`src-tauri/target/release/bundle/`) |
| `npm run dev` | Frontend only in a browser, served by the **demo backend** |
| `npm run check` | `svelte-check` type checking |
| `npm test` | Frontend unit tests (vitest, `src/lib/utils/*.test.ts`); `npm run test:watch` re-runs on change |
| `npm run test:rust` | Rust unit tests of both crates (`cargo test --workspace`) |
| `npm run check:linux` | The core crate on Linux, in a Docker container: rustfmt, clippy, unit tests. See [Linux](#linux) |
| `cargo test -p fishe-core -- --ignored live_ --nocapture` | Live Npcap tests: host-mode capture, process-mode attribution of the test's own UDP, all-traffic labelling (prints the top programs), and short-lived `curl.exe` processes bound by name (prints where every byte went) |
| same, from an **elevated** shell, filtered to `etw_attributes_new_connection` | Verifies ETW attribution of a brand-new TCP connection |
| `npx tauri icon src-tauri/icons/fishe.svg` | Regenerate app icons from the SVG source |

## Tests

| Area | Where | Covers |
|---|---|---|
| Header parser | `net/parse.rs` | Ethernet/IPv4/TCP, VLAN, IPv6 ext headers, loopback, fragments, truncation, garbage; TCP fields and payload length (IP length, padding, LSO, IPv6) |
| Connection quality | `monitor/quality.rs` | handshake RTT both ways, data/ACK RTT, retransmissions and Karn's rule, keep-alives, sequence wrap, deferred attribution, session/endpoint figures |
| Ping | `route/ping.rs` | statistics (loss, avg, min/max, RFC 3550 jitter); loopback pings, 4-target limit |
| MCP | `mcp/mod.rs`, `mcp/tools.rs`, `mcp/bridge.rs` | config defaults (off, read, random token), save/load, access ordering; tools per access level, unique names, schemas, descriptions; JSON-RPC messages out of an SSE answer |
| Resolution | `net/resolve.rs` | IPv4/IPv6 literals, brackets, localhost, invalid input |
| Counters | `monitor/stats.rs` | record + merge of tallies, service-port heuristic, bounded port table, per-program and per-endpoint program bytes |
| Detector | `monitor/gauge.rs` | idle/calm/busy/spike transitions, adaptation, floor, hysteresis, sanitising |
| Matching | `monitor/target.rs` | host directions, `TargetSpec` JSON shape (incl. `{"kind":"all"}`) |
| Machine scope | `process/machine.rs` | all-traffic labelling: owned, pending, port-less, broadcast direction; PID names from the list and ETW |
| Programs | `monitor/programs.rs` | grouping PIDs by name (case-insensitive), unattributed / unnamed PIDs, rates, endpoint counts, ordering |
| Packet feed | `monitor/packets.rs` | ring bound, paging by sequence, newest kept under a limit, off clears, bounded worker batch |
| Process scope | `process/scope.rs` | by-name (case-insensitive, all instances) vs by-PID, pending for unknown ports/new PIDs, unknown-PID detection, non-local and port-less skips |
| Ownership | `process/ownership.rs` | refresh/lookup, generation counter, TTL expiry, TIME_WAIT (PID 0) rows ignored |
| Socket table | `process/sockets.rs` | sees this process's TCP listener, TCP connection and IPv6 UDP socket with the right PID |
| Processes | `process/processes.rs` | grouping/sorting, lists itself with an image path |
| ETW | `process/etw.rs` | local-side port selection; live test `#[ignore]` (admin) |
| Engine | `monitor/engine.rs` | worker: host directions, pending packets held until the owner is known, dropped for another owner, expired as unattributed (process) or unowned (all-traffic), cap on held packets; aggregator: rates/totals/drops across workers, one failure warns / last failure stops, row lists once a second, wait slice |
| Live capture | `monitor/engine.rs` (`#[ignore]`) | host mode, process mode by PID, all-traffic mode (own UDP under own PID), TCP RTT vs ICMP to 1.1.1.1, short-lived processes by name |
| Endpoints | `monitor/endpoints.rs` | totals, rates, ports, names, busiest-first, eviction |
| Address types | `naming/addr.rs` | IPv4/IPv6 ranges, IPv4-mapped |
| DNS | `naming/dns.rs` | compression, CNAME chains, mDNS, errors, pointer loops |
| TLS SNI | `naming/tls.rs` | SNI, ECH flag, incomplete/non-TLS, split ClientHello reassembly |
| Names | `naming/book.rs` | source priority, reverse DNS requested once |
| Reverse DNS | `naming/rdns.rs` | loopback; `#[ignore]` live PTR for 8.8.8.8 |
| Archive DB | `archive/db.rs` | schema (v3 migration), crash recovery, rename, cascade delete, spike-preserving downsampling |
| pcapng | `archive/pcapng.rs` | block structure, alignment, timestamps, multi-interface |
| Recorder | `archive/recorder.rs` | accumulator alone: relative times, episodes, per-second endpoint history, program bytes integrated from rates; full round trip: samples (with RTT), episodes, exact endpoint totals and quality, names, packet tap → pcapng, all exports |
| Logging | `logging.rs`, `util.rs` | `FISHE_LOG` parsing (longest prefix, overrides), default levels, UTC timestamps, file append and rotation; civil dates |
| Frontend | `src/lib/utils/*.test.ts` (vitest) | number formatting (`format`), quality grades and text (`quality`), service names, owner text (`geo`), network-map graph: untraced/traced routes, shared routers, silent runs, network grouping, routing loops, neighbours, layered layout (`netgraph`) |
| Export | `archive/export.rs` | CSV quoting |
| Geo download | `geo/download.rs` | UTC month math, gzip / pass-through; `#[ignore]` live DB-IP install + lookup of 1.1.1.1 |
| Hop estimate | `net/parse.rs` | TTL / hop limit parsing, `hops_from_ttl` |
| ICMP probe | `route/icmp.rs` | loopback answers directly (IPv4 and IPv6) |
| Traceroute | `route/trace.rs` | hop assembly (alternates, silent, destination); loopback in one hop; `#[ignore]` live trace to 8.8.8.8 and an OVH IPv6 address |
| LAN | `route/lan.rs` | gateways and neighbour table read |
| Online lookup | `geo/online.rs` | ipinfo JSON parsing (ASN split, bogons); no worker and no queue without opt-in |

## IPC bindings

`src/lib/api/bindings.ts` is generated from the Rust command signatures and
types by [tauri-specta](https://github.com/specta-rs/tauri-specta) and is
checked in, so `npm run check` and CI never need a Rust build. Regenerate it
after changing a command or an IPC type:

```powershell
cargo test -p fishe bindings_are_current
```

The test rewrites the file and fails once when it was stale (so CI catches a
forgotten regeneration); run it again and it passes. `npm run tauri dev` also
rewrites it on every start (debug builds only). Never edit `bindings.ts` by
hand.

## Debugging

- **Rust logs** go to stderr of `npm run tauri dev` (`[fishe INFO  module] …`)
  and to `<data>\logs\fishe.log` (UTC timestamps; rotated to `fishe.1.log`
  at 2 MB). **Settings → Diagnostics** shows the folder and opens it; that
  file is what to attach to a bug report. The level is `info` by default
  (the MCP server's HTTP stack at `warn`); `FISHE_LOG` changes it like
  `RUST_LOG`: `FISHE_LOG=debug`, or per module
  `FISHE_LOG=info,fishe_core::lan=trace,fishe_core::monitor=debug` (engine
  modules are `fishe_core::…`, the Tauri commands `fishe_lib::…`).
- **Webview devtools:** right-click → Inspect in dev builds.
- **Remote-debug the webview** (automation, CDP):
  `set WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=9333`
  before `npm run tauri dev`, then attach to `http://127.0.0.1:9333`.
- **RustRover:** open the repo root; the Cargo project is `src-tauri/`.
  `LIBPCAP_LIBDIR` comes from `.cargo/config.toml`, so IDE builds link
  without extra setup.

> The isolated build shares the app identifier, so by default it uses the
> **same archive and geo folders** (`%APPDATA%\com.fishe.app\…`) as your
> normal Fishe. Set **`FISHE_DATA_DIR`** to give it its own (it then uses
> `<dir>\archive`, `<dir>\geo` and `<dir>\logs`; copy `geo` in for owner
> data).

### Testing the real app while `tauri dev` is running

Build a second, isolated debug binary (separate target dir, embedded
frontend) and give it its own WebView2 profile:

```powershell
$env:CARGO_TARGET_DIR = "$env:TEMP\fishe-target"; npx tauri build --debug --no-bundle
$env:WEBVIEW2_USER_DATA_FOLDER = "$env:TEMP\fishe-wv2"
$env:FISHE_DATA_DIR = "$env:TEMP\fishe-data"
$env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = "--remote-debugging-port=9334"
& "$env:TEMP\fishe-target\debug\fishe.exe"
```

### Testing the MCP server

Enable agents in the test build (Settings → Agents; if your own Fishe is
also running with agents on, give the test build another port), then check
it with the official MCP Inspector in CLI mode:

```bash
npx -y @modelcontextprotocol/inspector --cli http://127.0.0.1:47823/mcp --transport http --header "Authorization: Bearer <token>" --method tools/list --strict
```

`--method tools/call --tool-name get_status` calls a tool. You can also pipe
JSON-RPC lines into `fishe.exe --mcp-stdio` (with the same
`FISHE_DATA_DIR`).

Don't run two `tauri build`s at once: both rebuild the frontend into
`build/`, and a binary can embed a mix of the two (blank window).

### Measuring the UI

With the remote-debugging port open, the Chrome DevTools Protocol gives:

- `Performance.getMetrics`: `TaskDuration`, `LayoutCount`,
  `RecalcStyleCount`… sampled before and after a window gives the renderer's
  busy share and layouts per second;
- a `PerformanceObserver` for `layout-shift` entries, injected with
  `Runtime.evaluate`: the cumulative layout-shift score and which elements
  moved (rows jumping, columns sliding);
- `Profiler.start/stop`: JavaScript self time per function.

Rules the UI follows because of what these showed (see
[frontend.md](frontend.md#performance-rules)): animate only `transform` and
`opacity`, never re-trigger a transition every tick on a layout property,
keep live tables at a readable pace.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Build error `LNK1181: cannot open input file 'wpcap.lib'` | SDK missing: run `scripts/setup-npcap-sdk.ps1` |
| Banner "Packet capture is not available" | Npcap runtime not installed. Install from npcap.com |
| `capture` error "…access denied…" / no adapters listed | Npcap installed with *admin-only* access. Run Fishe as administrator or reinstall Npcap without that option |
| Gauge stays at 0 | Wrong interface (VPN?). Pick the adapter manually; or the target simply isn't talking to you |
| **Dropped** tile non-zero | Kernel buffer overflowed during an extreme burst; counts may be slightly low |
| Port 1420 in use | Another `vite`/`tauri dev` is running |
| Process mode: attribution says *Socket table* | Not elevated. Run Fishe as administrator for ETW |
| Process mode: high *Unattributed* | Very short-lived connections without ETW, or traffic of processes that exited before they could be identified |
| ETW: "could not start" | The system limit of 64 trace sessions is reached, or a stale `Fishe-*` session exists (`logman query -ets`, then `logman stop <name> -ets`) |

## Code conventions

- Rust: edition 2024, `cargo fmt`, no `unwrap()` outside tests; all fallible
  commands return `AppResult<T>`.
- IPC types and commands are defined once, in Rust: derive `specta::Type`
  on anything that crosses IPC, put `#[specta::specta]` on new commands and
  list them in `ipc_builder()` (`src-tauri/src/lib.rs`); then regenerate
  `src/lib/api/bindings.ts` (see [IPC bindings](#ipc-bindings)) and update the
  prose in [ipc-api.md](ipc-api.md).
- UI colours only via tokens in `app.css`.

## Workspace layout

```
Cargo.toml                workspace root: members, shared version, release profile
Cargo.lock
crates/fishe-core/        the core: no Tauri, platform code behind cfg
src-tauri/                the app: lib.rs (setup, IPC surface), commands.rs, main.rs
.cargo/config.toml        Npcap SDK path; build output kept in src-tauri/target
```

Cargo commands work from any folder. The build output stays in
`src-tauri/target` (set in `.cargo/config.toml`), where Tauri and the
ignore files expect it. A new backend feature goes in the core, with the
operation in `ops.rs` if both the window and agents use it; the app crate
only gets the command that exposes it.

## Linux

The desktop app is Windows-only. The core crate also builds on Linux, and
CI keeps it that way; this is how to run the same check from Windows.

```powershell
npm run check:linux                                   # rustfmt, clippy, unit tests
powershell -File scripts/linux-check.ps1 -Live        # plus four live tests
```

The script builds a small Debian image with Rust and libpcap
(`scripts/linux/Dockerfile`) and runs the checks in a container. The
repository is mounted read-only and the Linux build lives in Docker volumes,
so the Windows build in `src-tauri/target` is untouched. The container sees
only its own traffic: enough to prove that capture, parsing, counting and
TCP quality work on Linux, not to test the LAN scan or real adapters.

| The core on Linux | |
|---|---|
| Capture, parsing, counting, the detector, TCP quality | implemented; covered by the live tests (`-Live`) |
| Process attribution from `/proc` ([process-mode.md](process-mode.md#on-linux)) | implemented; covered by the live tests |
| ETW, ping and traceroute, routes and neighbours, LAN scan | Windows only; on Linux they report "not available" |

## Version control

| File | Purpose |
|---|---|
| `.gitignore`, `src-tauri/.gitignore` | Build output, `node_modules`, the vendored Npcap SDK, IDE files, captures |
| `.gitattributes` | LF in the repository, CRLF for PowerShell scripts, binaries marked |
| `.editorconfig` | Indentation and line endings for editors |
| `.github/workflows/release.yml` | On a version tag: the installers and a draft GitHub release. See [Releases](#releases) |
| `.github/workflows/ci.yml` | On push/PR (GitHub). On `windows-latest`: Npcap SDK, `npm run check`, `npm test`, `npm run build`, `cargo fmt --all --check`, `cargo clippy --workspace -D warnings`, `cargo test --workspace`, then `tauri build --debug --no-bundle` (the real binary, no installer). On `ubuntu-latest`: clippy and the unit tests of `fishe-core` with libpcap |

## Releases

A release is a version tag. Pushing one makes GitHub build the installers
and open a release for it (`.github/workflows/release.yml`).

```powershell
npm run version:set -- 0.16.0          # the version, everywhere it lives
# write the "## 0.16.0 (date)" entry in CHANGELOG.md
git commit -am "Fishe 0.16.0"
git tag v0.16.0
git push; git push --tags
```

| Step of the workflow | What it guards |
|---|---|
| The tag must equal `v` + the version in `package.json` and `Cargo.toml` | A tag that doesn't match the files it releases |
| `scripts/release-notes.mjs` extracts the version's `CHANGELOG.md` entry; no entry, no release | A release without notes |
| `npm run check`, `npm test`, `cargo test --workspace --locked` | Releasing what would not pass CI, or with dependencies other than the committed `Cargo.lock` |
| `tauri-action` builds in release mode and bundles the NSIS `.exe` and the `.msi` | |
| The release is created as a **draft** with both installers and the notes | You look it over and press Publish; `releaseDraft: false` in the workflow publishes directly |

The version lives in five files (`package.json`, `package-lock.json`,
`tauri.conf.json`, the workspace `Cargo.toml` that both crates inherit
it from, `Cargo.lock`); `version:set` writes them all and warns when the
changelog has no entry for the new version.

The release job can write to the repository's releases, so it takes
nothing on trust. Actions in both workflows are pinned to a commit, with
the version in a comment: to update one, replace the hash with the commit
behind the new tag (`git ls-remote https://github.com/<owner>/<action>`).
`scripts/setup-npcap-sdk.ps1` checks the SDK's import libraries, which end
up inside the binary, against SHA-256 hashes kept in the script; a new SDK
version needs its hashes added there. The release job restores no build
cache.

**Not in the installers:** Npcap (users install it, the app says how) and a
code signature. Unsigned installers work, but Windows SmartScreen warns on
first run. There is no in-app updater: a new version is a new download.

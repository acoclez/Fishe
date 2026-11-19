# Frontend

SvelteKit in SPA mode (`adapter-static`, `ssr = false`) with **Svelte 5 runes**,
TypeScript and no UI framework. Charts and the gauge are hand-written SVG.

## Structure

```
src/
├─ app.css                    theme tokens + base styles
├─ app.html
├─ routes/
│  ├─ +layout.svelte          imports app.css
│  ├─ +layout.ts              ssr = false
│  └─ +page.svelte            the shell: rail, header, the open page, toasts; startup, keys, scroll memory
└─ lib/
   ├─ api/                    the only door to the backend
   │  ├─ index.ts             invoke wrappers; demo backend outside Tauri
   │  ├─ bindings.ts          generated from Rust by tauri-specta: `commands.*` + IPC types
   │  ├─ types.ts             re-exports the generated types; UI-only types (Units, TrafficPoint, TopItem)
   │  └─ demo.ts              simulated backend for browser previews
   ├─ stores/                 shared state (runes)
   │  ├─ monitor.svelte.ts    session store (events, samples, histories, focus, recording)
   │  ├─ session.svelte.ts    session controller: start/restart/record, startup data, the derived "view" the pages share
   │  ├─ settings.svelte.ts   persisted preferences + sensitivity presets
   │  ├─ nav.svelte.ts        current page, number keys, scroll per page, settings sections
   │  ├─ routes.svelte.ts     traceroute queue/results, gateways & neighbours
   │  ├─ pings.svelte.ts      running pings
   │  ├─ agents.svelte.ts     MCP server status, activity log, backend notices
   │  └─ stable.svelte.ts     StableList: rows that hold still while you read them
   ├─ utils/                  pure functions, each with its tests (`*.test.ts`)
   │  ├─ format.ts            SI units, rates, durations, nice axis maxima
   │  ├─ services.ts          port → service name
   │  ├─ geo.ts               country names (Intl.DisplayNames), owner tooltip/search text
   │  ├─ quality.ts           RTT / jitter / loss grades and formatting
   │  └─ netgraph.ts          map graph model and layered layout
   ├─ shell/                  the frame around every page
   │  ├─ Rail.svelte          side rail: pages, active marker, live/REC dot
   │  ├─ HeaderStatus.svelte  header: page title, REC / Agents / Ping chips, live target, clock, Npcap chip
   │  ├─ Toasts.svelte        error, warnings, "recording saved" at the bottom right
   │  └─ Logo.svelte
   ├─ components/             used by more than one page
   │  ├─ TrafficChart.svelte  stacked areas, baseline, level strip, tooltip
   │  ├─ QualityChart.svelte  RTT (ms) over time, ping dots and lost ticks
   │  ├─ Sparkline.svelte     per-row activity trend
   │  ├─ StatTile.svelte
   │  ├─ LevelBadge.svelte    icon + label (never colour alone)
   │  ├─ OwnerCell.svelte     country badge + organisation
   │  ├─ FocusBar.svelte      what the gauge follows (whole session / endpoint / program), fixed height
   │  ├─ EmptyState.svelte    Connections / Map without a suitable session
   │  └─ ConfirmDialog.svelte modal confirmation (permanent delete)
   └─ pages/                  one folder per page: the page and the parts only it uses
      ├─ live/
      │  ├─ LivePage.svelte          target bar, gauge and tiles, chart, quality, busiest, protocols and ports
      │  ├─ TargetForm.svelte        Host | Process | All switch, target, interface, start/stop
      │  ├─ ProcessPicker.svelte     searchable program/PID combobox (process mode)
      │  ├─ ProcessInfo.svelte       process / all-traffic strip: PIDs or programs, sockets, attribution
      │  ├─ Gauge.svelte             log dial, spring needle, busy/spike zones
      │  ├─ QualityCard.svelte       connection quality: RTT, jitter, retransmissions, Ping
      │  ├─ TopList.svelte           five busiest programs or endpoints, "All N →"
      │  ├─ ProtocolBreakdown.svelte
      │  ├─ TopPorts.svelte
      │  └─ NpcapMissing.svelte      without Npcap: what it is, how to install it, Check again
      ├─ connections/
      │  ├─ ConnectionsPage.svelte   programs, endpoints or packets
      │  ├─ ProgramsPanel.svelte     programs using the network (all-traffic mode), click to focus, Monitor ▸
      │  ├─ EndpointsPanel.svelte    remote endpoints table (process / all mode), click to focus
      │  └─ PacketList.svelte        live packet list (Packets view), polls recent_packets
      ├─ map/
      │  ├─ MapPage.svelte           LAN scan, traffic map or route
      │  ├─ NetworkMap.svelte        network map (routes graph), pan/zoom, highlight, focus
      │  └─ LanScan.svelte           devices on the local network: list or star map
      ├─ archive/
      │  ├─ ArchivePage.svelte       recordings list: open, rename, export, reveal, delete
      │  ├─ RecordingView.svelte     replay: tiles, full-length chart, moments, endpoints
      │  └─ ArchiveEndpoints.svelte  recorded endpoints table
      └─ settings/
         ├─ SettingsPage.svelte      section index + sections (measurement, recording, owners, agents)
         ├─ GeoSettings.svelte       Owner & country (download, update, remove, online opt-in)
         ├─ AgentsSettings.svelte    Agents (MCP): access, token, client configs, activity
         └─ DiagnosticsSettings.svelte log file location, Open logs folder
```

A component lives in `pages/<page>/` while one page uses it and moves to
`components/` when a second one does. Stores never import from pages or
components; `utils/` imports nothing but types.

## State

### `monitor` (`stores/monitor.svelte.ts`)

| Field | Type | |
|---|---|---|
| `phase` | `idle \| starting \| running \| stopping` | lifecycle |
| `session` | `SessionInfo \| null` | from the `started` event (a click here or an agent) |
| `latest` | `Sample \| null` | `$state.raw`, replaced each tick |
| `history` | `TrafficPoint[]` | `$state.raw`, ≤ 1200 points (5 min @ 250 ms) |
| `error` | `string \| null` | shown as a toast; `dismissError()` |
| `warnings` | `string[]` | non-fatal `warning` events (last 5), e.g. an interface dropped out; `dismissWarning(i)` |
| `focus` | `string \| null` | endpoint IP the gauge/tiles/chart follow (process / all mode) |
| `programFocus` | `string \| null` | all mode: program key the gauge follows and endpoints are filtered to (`focus` wins while set); program histories via `programHistory(key, last)` |
| `recording` / `recordingBusy` | `RecordingInfo \| null` / `boolean` | active recording; start/stop via `startRecording()` / `stopRecording()` |
| `lastSaved` | `RecordingInfo \| null` | drives the "saved to the archive" toast; `dismissSaved()` |
| `endpointVersion` | `number` | bumped per sample; per-endpoint histories (≤ 1200 points, forgotten after 5 min unseen) are read through `endpointHistory(ip, last)`, which returns a fresh slice so components redraw |

`attach()` subscribes once (`subscribe_monitor`) and every session reports
through that subscription, whoever started it. A `started` event resets the
store for the new session; samples and the other events are matched on its
`sessionId`, so a late sample from a stopped session never pollutes the new
one. A `started` the window did not ask for (an agent did) calls
`onForeignStart`, and the controller shows it like a click: Live page, mode
switch, picker.

### `session` (`stores/session.svelte.ts`)

The controller the pages share. It loads what the window needs at startup
(Npcap, interfaces, capabilities, detector defaults), pushes the Settings an
agent-started session should use (`set_monitor_defaults`), and owns the
actions: `start(target, iface)`, `restart()` (Settings → Apply),
`monitorProgram(name)` (Programs panel ▸), `toggleRecording()`, `openSaved()`.
From `monitor` it derives, once for every page, the `view` the gauge, tiles
and chart show (the whole session, or the focused endpoint / program), the
formatted rates, the quality card's subject, the map's endpoints and the
Live page's busiest list.

`$state.raw` + array replacement keeps reactivity cheap: one assignment per
tick instead of deep proxies over 1200 objects.

### `settings` (`stores/settings.svelte.ts`)

Persisted in `localStorage` under `fishe.settings.v1`: target mode (process by default, or host /
process / all), endpoints view (table / map / packets), map options (group by network,
LAN devices), online owner lookup (re-applied to the backend at startup),
record packet headers, reverse DNS, units, chart window, sensitivity preset/ratios, the last 8 hosts
(input suggestions) and the last 6 programs (chips in the process picker). All access is wrapped in `try/catch`; the app works with
defaults when storage is unavailable.

## Theme and colour

Dark only, by design: **sea blue on black/gray**. All colours are CSS custom
properties in `app.css`; components reference roles (`--series-in`,
`--level-busy`…), never hex.

| Token | Value | Use |
|---|---|---|
| `--bg` | `#0b0d0f` | window background |
| `--surface-1/2/3` | `#14181c` / `#1b2026` / `#232a31` | cards, inputs, tracks |
| `--accent` | `#1f9bd1` | brand sea blue: buttons, bars, calm level |
| `--series-in` | `#1f9bd1` | inbound data |
| `--series-out` | `#d95926` | outbound data |
| `--level-busy` | `#fab219` | busy (with icon + label) |
| `--level-spike` | `#d03b3b` | spike (with icon + label) |

The in/out pair was validated with the data-viz palette checker against
`--surface-1` in dark mode. It passes the lightness band, the chroma floor,
CVD separation (ΔE 23.2 deutan), the normal-vision floor (ΔE 30.0) and ≥ 3:1
contrast. The level colours are status colours: they always appear with an
icon and a text label, and never stand in for a data series.

## Components

### `Gauge.svelte`

- 240° dial, log scale across 7 decades (bits: 1 k → 10 G; bytes: 100 → 1 G).
- Needle position uses Svelte's `Spring` (`svelte/motion`) for smooth motion
  between 250 ms ticks.
- Busy/spike zone ring and baseline notch are computed from the session's
  `GaugeConfig` and the live baseline. See
  [busyness-detection.md](busyness-detection.md).

### Pages and navigation

A slim **side rail** (`Rail.svelte`) switches between five pages; the
header shows the page name and the status chips (REC, Agents, Ping, Live).

| Page | Key | Content |
|---|---|---|
| **Live** | 1 | Target bar, process/all strip, focus bar, gauge and tiles, chart, connection quality, the **five busiest** programs (all traffic) or endpoints (process) with *All N →*, protocols and top services |
| **Connections** | 2 | Focus bar, the full Programs table (all traffic), then **Endpoints** or **Packets** |
| **Map** | 3 | LAN scan (device list / star map, no session needed), then the traffic map (process / all) or the route in host mode |
| **Archive** | 4 | Recordings (`ArchivePage`) |
| **Settings** | 5 | Section index on the left (Measurement, Recording and names, Owners database, Agents) and the sections; the index follows the scroll |

- The session keeps running (and recording) on every page. Focus (an
  endpoint or program) is shared: set it on Connections or Map, see the
  gauge follow on Live. Connections and Map show an empty state with a
  *Go to Live* button when there is no program or all-traffic session.
- Number keys **1–5** open the pages (ignored while typing in a field).
  The last page is remembered across launches; each page keeps its scroll
  position while the app runs.
- The rail is fixed-width and its active marker moves with a transform;
  the Live dot shows a running session (red while recording). The Agents
  chip opens Settings at the Agents section (`nav.go("settings", "agents")`).
- Pages unmount when hidden, so the packet feed and the map's layout only
  run while their page is open.
- The **● Record** button sits in the target bar; while recording, a
  pulsing timer replaces its label and a **REC** chip appears in the header.

### `TrafficChart.svelte`

- Width from `bind:clientWidth`; pure SVG paths rebuilt per tick.
- Inbound at the bottom, outbound stacked on top (2 px gap between fills),
  so total height = gauge throughput; y-axis is a nice-rounded max.
- Dashed baseline line; level strip under the x-axis.
- Pointer crosshair + tooltip (binary search to the nearest sample).
- Live: `windowSecs` ending at the newest point, axis `-30s … now`.
  Replay: `range=[start, end]` and `axis="elapsed"` (`0:00 … 12:30`), with
  tick spacing chosen to give ≤ 6 labels.

### `ProcessPicker.svelte`

- Combobox over `list_processes()`, refreshed every 3 s while open.
- Filter by name or PID prefix; ↑/↓, Enter, Esc, → (expand) keyboard support.
- Row click → `{ by: "name" }`; expanded PID chip → `{ by: "pid" }`.
- Enter on a name with no running match arms it anyway (waits for the program).

### `ProcessInfo.svelte`

Shown while a process session runs: label + image path, matched PIDs
("none running, waiting…" / "process has exited"), owned sockets, interface
count, attribution badge (**Socket table** or **Exact · ETW**, with a hint to
run elevated), and the unattributed packet count.

In all-traffic mode it shows the program count, processes owning sockets,
total sockets, interfaces, attribution, and unattributed packets.

### `ProgramsPanel.svelte`

See [all-traffic.md](all-traffic.md). Fixed height (≈ 8 rows, scrolls),
sort (Live / Total / Name), filter by name or PID, sparkline, level, share bar; a row toggles
`monitor.programFocus`; **Monitor ▸** asks `session` to restart in process
mode for that program (`TargetForm`'s `selection` is bound to the controller,
so the form shows it).

### `PacketList.svelte`

Turns the backend feed on when mounted (off when unmounted), polls
`recent_packets(after)` every 500 ms, keeps 1000 packets (renders 400),
newest first; pause, clear, filter; reports packets that went by unseen.
The list holds still while the pointer is over it (new packets are fetched
when it leaves).

### `QualityCard.svelte` / `pings.svelte.ts`

See [connection-quality.md](connection-quality.md). The page derives the
card's subject (host target, focused endpoint, or all connections). Session
history points carry `rttMs` (the tick's mean TCP RTT); endpoint tracks carry
the endpoint's smoothed RTT when it got new samples. The `pings` store polls
`ping_status` once a second while a ping runs. Grades and formatting live in
`utils/quality.ts` (`--series-rtt` colours the RTT line).

### `agents.svelte.ts` / `AgentsSettings.svelte`

See [mcp.md](mcp.md). The store holds the server status and the activity
log and subscribes (desktop app only) to the `fishe://…` events: the
activity log, and the "changed" notices for pings and traces, which have
their own stores. Sessions and recordings an agent starts need nothing
here: they arrive through the monitor subscription like the window's own,
and `session` shows them like a click (Live page, mode switch, picker). The
header shows an **Agents** chip (flashes once per call) and, while pings
run, a **Ping ×N · Stop** chip.

### `EndpointsPanel.svelte`

See [endpoints.md](endpoints.md). Sort (Live / Total / Newest / Name), filter,
name-source and address-type tags, NEW marker, sparkline, level badge; rows
are keyboard-focusable and toggle `monitor.focus`. `session` derives the
`view` (gauge, tiles, chart points) from either the whole session or the
focused endpoint.

## Stable live tables

The endpoints, programs and packets tables update while you read them, so
they follow a few rules (`stores/stable.svelte.ts`, `StableList`):

| Rule | Why |
|---|---|
| Values refresh **once a second** (the gauge and chart stay at 4/s) | numbers that change 4×/s can't be read; 4× less DOM work |
| The order changes at most **every 3 s**, never while the pointer is over the table ("order held"); new rows join at the bottom until then | rows used to jump under the pointer every tick |
| Rows that move **glide** (`animate:flip`, 350 ms) | a re-sort reads as motion, not a jump (transforms don't count as layout shift) |
| `table-layout: fixed` with a `<colgroup>`, ellipsis, fixed row height | columns no longer slide when a value gets wider |
| Scrollers are sized by the layout, never by their rows: a fixed height (Programs), or what is left of the page with a floor of 440 / 480 px (Endpoints, Packets); empty states take the same box | rows appearing don't move anything; the height only follows the window |
| Endpoints that drop out of the backend's 150 rows stay (idle) for 5 min (`monitor.endpointRows`) | rows no longer vanish and come back |
| A sort or filter change applies at once | user actions are never delayed |

The page follows the same idea: the focus bar is always present in process
/ all mode (a hint when nothing is focused), transient notices (errors,
warnings, "recording saved") are **toasts** at the bottom right instead of
banners above the content, notes and credits are hidden rather than removed,
and changing numbers use tabular figures with reserved widths.

Measured (all-traffic mode, endpoints table in view, 20 s): cumulative
layout-shift score **1.23 → 0.001** (0.003 while focusing a program, an
endpoint and clearing).

## Performance rules

What the renderer measurements showed, and the rules that came out of it:

- **Animate only `transform` and `opacity`.** The spike badge pulsed a
  `box-shadow` (repaint every frame); the protocol and top-service bars had
  a 400 ms `width` transition re-triggered every 250 ms tick, which meant a
  page **layout every frame, forever**. Bars now use `transform: scaleX`;
  the pulse is an opacity animation on its own layer, and table badges don't
  pulse. Blinking dots have `will-change: opacity`.
- **Fewer DOM nodes for the same picture**: the chart's level strip is drawn
  as runs of equal level, not one rectangle per tick.
- **Continuous animations only while the user points at something** (the
  map's traffic flow), never as a lasting state.
- `prefers-reduced-motion` turns the decorative motion off.

Result (all-traffic mode, endpoints in view): renderer main thread busy
**46% → 15–20%**, layouts **180/s → 11–20/s**, WebView2 CPU **79% → 40%**
of one core. The Rust side uses ~2% of a core (debug build) for the same
traffic.

## Demo mode (browser preview)

`npm run dev` and open <http://localhost:1420> in a normal browser: `api/index.ts`
detects there's no Tauri runtime and swaps in `api/demo.ts`, which streams
synthetic traffic with periodic bursts, using a JS mirror of the detector.
It also serves a fake process list and named endpoints (TLS, DNS, ECH, PTR,
LAN), so process mode and the endpoints panel can be previewed.
A banner indicates the data is simulated. This is for UI work and
screenshots; the desktop app always uses the real backend, and `demo.ts`
is imported lazily and only by the dev server, so a production build does
not contain it.

Open the preview with `?npcap-missing` to see the app as on a PC without
Npcap: the install prompt, the header chip, the disabled LAN scan. The first
**Check again** still finds nothing, the second one finds it.

## Accessibility

- Level = icon + label + colour.
- Series identity = legend + swatch + tooltip labels.
- `prefers-reduced-motion` disables transitions and pulsing.
- Focus rings use `--accent-strong`; the gauge SVG has an `aria-label` with
  the current reading.

# Recording and the archive

Press **● Record** while monitoring (host or process mode) to save the
session from that moment on. Press it again (or the red **REC** chip in the
header) to stop; the recording also stops automatically when monitoring
stops. A banner offers to open it right away.

Recordings appear in the **Archive** tab.

## What is saved

| Data | Detail |
|---|---|
| **Samples** | Every tick (250 ms by default): in/out rates and packet rates, smoothed rate, baseline, ratio, level |
| **Notable moments** | Each continuous busy/spike stretch: start, end, highest level, peak rate, peak ratio |
| **Endpoints** (process mode) | Per remote address: exact bytes/packets *during the recording*, first/last seen, peak rate, highest level, top service ports, the best name at the end (TLS/DNS/ECH/PTR), and owner/country when available |
| **Endpoint history** | Per tick and endpoint while it was active: rates, detector values, level |
| **End-of-recording extras** | Protocol bytes, top services, dropped and unattributed packet counts |
| **Packet headers** *(optional)* | Settings → *Recording* → **Save packet headers (.pcapng)**: the first 192 bytes of every *counted* packet |

Times in a recording are relative to its start (0:00).

### The packets file

- **pcapng**, one file per recording, with one interface block per capture
  interface, so Ethernet and loopback packets coexist with the right link
  types. Opens directly in Wireshark (`capinfos` reports "per-packet"
  encapsulation for multi-interface files).
- Only packets Fishe **counted** are written: the target's traffic in host
  mode, the process's traffic in process mode (including packets that were
  attributed late). Headers only (snap length 192), no payload.
- The writer has a 65,536-packet queue. If the disk can't keep up, packets
  are skipped from the *file* and the count is shown in the archive; the
  measurements themselves never lose data to this.

## Storage

```
%APPDATA%\com.fishe.app\archive\
├─ fishe.db                 SQLite (WAL): recordings, samples, endpoints,
│                           endpoint_samples, episodes
└─ captures\
   └─ fishe-<id>-<start>.pcapng
```

The folder path is shown at the top of the Archive tab. Writes happen on a
background thread in one transaction per second, so recording never slows
capture. Endpoints that saw traffic are also checkpointed every 10 s, and
all of them are written once more when the recording ends (names and owners
learned late land then).

If Fishe exits while recording (crash, power loss), the recording is kept:
the next time the archive opens, it is closed at its last saved sample and
marked **interrupted**.

If the archive cannot be written (disk full, database locked), the writer
keeps its rows and tries again; after five failed commits in a row it gives
up. The recording then ends on its own, is marked **interrupted** with what
reached the disk, and the window shows a warning saying why. The session
itself keeps running.

What a recording keeps is bounded, because remote addresses are not the
user's to choose and can be forged:

| Limit | Value | Beyond it |
|---|---|---|
| Endpoints with their own row and history | 20,000 | later addresses count in the totals and the session series only |
| Ports remembered per endpoint | 32 (the 4 busiest are stored) | further ports are not listed |
| Ticks waiting for the writer | 512 | the tick is left out of the recording (logged) |

Owners stored with a recording come from the offline database and from
online lookups the window already made: recording never sends an address
to the online service by itself.

The database schema is versioned (`PRAGMA user_version`); version 2 added
the endpoint owner columns, version 3 the connection quality (`samples.rtt_ms`,
`endpoints.quality_json`, see [connection-quality.md](connection-quality.md)).
Older archives are migrated on open. A Fishe older than the archive refuses
to modify it ("created by a newer Fishe").

Size guide: about 100 bytes per sample (≈ 1.4 MB per hour at 4 samples/s),
plus endpoint history (one row per active endpoint per **second**, averaged
over its ticks, since 0.9; the session series keeps every tick), plus about
200 bytes per packet in the optional pcapng.

## The Archive tab

| Column / action | |
|---|---|
| Name | Click to open; ✎ to rename (defaults to `<target> · <date time>`) |
| Target, Started, Duration, Data, Peak, Max | Summary of the recording |
| Packets file | Packet count and size; click to show it in Explorer |
| **Open** | Replay view (below) |
| **Export ▾** | *Samples (.csv)*, *Endpoints (.csv)*, *Everything (.json)*, always at full resolution, to a location you pick |
| **Delete** | Asks for confirmation, then permanently removes the recording and its packets file |

### Replay

- Summary tiles: duration, data, packets, peak, highest level and number of
  notable moments, endpoints and packets saved.
- The whole recording on one chart (elapsed time axis, level strip, hover
  tooltip). Recordings longer than 3000 samples are averaged for display,
  keeping each bucket's highest level and ratio so spikes stay visible;
  exports always contain every sample.
- **Notable moments**: click one to zoom the chart around it; *Zoom out*
  returns.
- **Endpoints** (process mode): click one to chart that endpoint's own
  history (idle gaps shown as zero); click again or *Show whole recording*.

## Exports

**Samples CSV**

```
t_s,in_bytes_per_s,out_bytes_per_s,in_packets_per_s,out_packets_per_s,smoothed_bytes_per_s,baseline_bytes_per_s,ratio,level,rtt_ms
0.264,3980.8,409.8,7.59,7.59,519814.1,755329.4,0.688,calm,24.31
```

`rtt_ms` is the mean TCP round-trip time measured in that tick; empty when
the tick had no sample.

**Endpoints CSV**

```
ip,name,name_source,scope,asn,org,country,bytes_in,bytes_out,packets_in,packets_out,first_seen_s,last_seen_s,peak_bytes_per_s,max_level,ports
2001:41d0:242:d300::,proof.ovh.net,sni,public,16276,OVH SAS,FR,13277426,192503,8837,2546,2.371,13.655,6114024.6,spike,443/tcp
```

Rates are **bytes per second** in exports, whatever unit the UI shows.

Text cells (names, organisations) that start with `=`, `+`, `-` or `@`
get a leading apostrophe, so a spreadsheet shows them as text instead of
running them as a formula.

The save dialog is opened by the backend: the window passes a suggested
file name, never a path, so an export can only land where the dialog was
pointed.

**JSON**: `{ summary, session, extra, samples, downsampled: false, endpoints, episodes }`
with the same shapes as the IPC types in [ipc-api.md](ipc-api.md).

## Code map

| File | Role |
|---|---|
| `archive/mod.rs` | `ArchiveState`: folder, lazily opened connection, crash recovery |
| `archive/db.rs` | Schema, queries, downsampling, rename, delete |
| `archive/recorder.rs` | `RecordingSlot` (per session); writer thread = `Accumulator` (ticks → series, episodes, endpoint/program totals; pure, unit-tested) + `Sink` (SQLite); `PacketTap`/`TapHandle`, pcapng thread |
| `archive/pcapng.rs` | pcapng writer (SHB, IDB, EPB) |
| `archive/export.rs` | CSV / JSON export |
| `src/lib/pages/archive/ArchivePage.svelte` | List, rename, export, reveal, delete |
| `src/lib/pages/archive/RecordingView.svelte`, `ArchiveEndpoints.svelte` | Replay |
| `src/lib/components/ConfirmDialog.svelte` | Destructive-action confirmation |

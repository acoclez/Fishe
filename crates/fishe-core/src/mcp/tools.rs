//! The tools agents can call, by access level. The list with every tool's
//! level and arguments is the table in `docs/mcp.md` (a test checks that
//! every tool here is in it).
//!
//! Each tool's arguments are a struct: serde parses them (unknown fields,
//! wrong types and values outside an enum are errors that name what the
//! tool accepts) and schemars derives the JSON Schema clients see from the
//! same struct, so the two can't drift. The work itself is shared with the
//! IPC commands through `crate::ops`.
//!
//! Results are JSON (also as text for clients without structured output).
//! Rates are bytes per second; times in the session are seconds since it
//! started.

use super::{Access, Activity};
use crate::archive::db;
use crate::archive::recorder::RecordOptions;
use crate::monitor::endpoints::EndpointRow;
use crate::monitor::events::Sample;
use crate::monitor::gauge::Level;
use crate::monitor::programs::ProgramRow;
use crate::monitor::target::{ProcessSelector, TargetSpec};
use crate::monitor::{SessionInfo, StartRequest};
use crate::ops;
use crate::process::processes;
use crate::services::Services;
use crate::util::now_ms;
use schemars::{JsonSchema, schema_for};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

type Handler = fn(&Services, Value) -> Result<Value, String>;

struct Tool {
    name: &'static str,
    title: &'static str,
    description: &'static str,
    access: Access,
    /// The JSON Schema of the arguments (from the handler's argument struct).
    schema: fn() -> Value,
    handler: Handler,
}

// ───────────────────────────── arguments ─────────────────────────────
//
// One struct per tool with arguments. `deny_unknown_fields` makes a typo an
// error; optional fields take `null` as "not given"; defaults and bounds are
// in the schema (and applied again in the handler, leniently).

/// `Some(N)`: a default visible in the schema and used when the field is missing.
fn d<const N: u64>() -> Option<u64> {
    Some(N)
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct NoArgs {}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[schemars(inline)]
enum WaitLevel {
    Calm,
    Busy,
    Spike,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WaitArgs {
    /// Busyness level to wait for (default busy; ignored when only minBytesPerSec is given)
    level: Option<WaitLevel>,
    /// Rate (bytes/s, in + out, smoothed) to wait for; alone, the level is ignored
    #[schemars(range(min = 0))]
    min_bytes_per_sec: Option<f64>,
    /// All-traffic mode: watch only the busiest program whose name contains this
    program: Option<String>,
    /// Watch only the busiest endpoint whose IP or name contains this
    endpoint: Option<String>,
    #[serde(default = "d::<30>")]
    #[schemars(range(min = 1, max = 120))]
    timeout_seconds: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HistoryArgs {
    #[serde(default = "d::<60>")]
    #[schemars(range(min = 5, max = 600))]
    seconds: Option<u64>,
    /// More points = finer detail and a longer answer
    #[serde(default = "d::<60>")]
    #[schemars(range(min = 1, max = 600))]
    max_points: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
#[schemars(inline)]
enum EndpointSort {
    #[default]
    Live,
    Total,
    Recent,
    Rtt,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EndpointsArgs {
    #[serde(default = "d::<25>")]
    #[schemars(range(min = 1, max = 150))]
    limit: Option<u64>,
    /// live = busiest now (bytesPerSec)
    #[serde(default = "endpoint_sort")]
    sort: Option<EndpointSort>,
    /// Substring of name, IP, owner, country or program
    filter: Option<String>,
}

fn endpoint_sort() -> Option<EndpointSort> {
    Some(EndpointSort::Live)
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
#[schemars(inline)]
enum ProgramSort {
    #[default]
    Live,
    Total,
    Name,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProgramsArgs {
    #[serde(default = "d::<25>")]
    #[schemars(range(min = 1, max = 100))]
    limit: Option<u64>,
    #[serde(default = "program_sort")]
    sort: Option<ProgramSort>,
}

fn program_sort() -> Option<ProgramSort> {
    Some(ProgramSort::Live)
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PacketsArgs {
    #[serde(default = "d::<100>")]
    #[schemars(range(min = 1, max = 500))]
    limit: Option<u64>,
    /// Substring of an address, port, protocol, program or name
    filter: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProcessesArgs {
    /// Substring of the executable name
    filter: Option<String>,
    #[serde(default = "d::<40>")]
    #[schemars(range(min = 1, max = 200))]
    limit: Option<u64>,
    /// Also list programs without any socket (always with a filter)
    #[serde(default)]
    include_no_sockets: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecordingArgs {
    /// From list_recordings
    id: i64,
    /// Rate points (0 = none)
    #[serde(default = "d::<100>")]
    #[schemars(range(min = 0, max = 2000))]
    max_points: Option<u64>,
    #[serde(default = "d::<25>")]
    #[schemars(range(min = 0, max = 500))]
    endpoint_limit: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct IpArgs {
    ip: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[schemars(inline)]
enum StartMode {
    Host,
    Process,
    All,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StartArgs {
    mode: StartMode,
    /// mode host: IP address or host name
    host: Option<String>,
    /// mode process: executable name
    process: Option<String>,
    /// mode process: a single PID instead of a name
    pid: Option<u32>,
    /// Capture device name (from list_interfaces); default automatic
    interface: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecordArgs {
    /// Display name; default the session label
    name: Option<String>,
    /// Also save the packet headers as .pcapng
    #[serde(default)]
    pcap: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TraceArgs {
    ip: String,
    /// Trace again even if a result from the last 10 minutes exists
    #[serde(default)]
    force: Option<bool>,
}

/// Parse a tool's arguments. serde's messages name the unknown field and
/// the accepted ones, the expected type, or the accepted enum values.
fn parse<A: DeserializeOwned>(args: Value) -> Result<A, String> {
    if !args.is_object() {
        return Err("arguments must be an object".into());
    }
    serde_json::from_value(args).map_err(|e| format!("invalid arguments: {e}"))
}

/// The JSON Schema of an argument struct, as MCP clients expect it: a plain
/// object schema (no `$schema` / `title`), each property with one type
/// (optional fields are simply not required, rather than `["x", "null"]`).
fn schema_of<A: JsonSchema>() -> Value {
    let mut v = serde_json::to_value(schema_for!(A)).unwrap_or_default();
    let Some(o) = v.as_object_mut() else {
        return v;
    };
    o.remove("$schema");
    o.remove("title");
    o.entry("properties").or_insert_with(|| json!({}));
    if let Some(props) = o.get_mut("properties").and_then(Value::as_object_mut) {
        for p in props.values_mut() {
            if let Some(types) = p.get("type").and_then(Value::as_array) {
                let non_null: Vec<Value> = types.iter().filter(|t| *t != "null").cloned().collect();
                if let [one] = non_null.as_slice() {
                    p["type"] = one.clone();
                }
            }
            if let Some(choices) = p.get_mut("enum").and_then(Value::as_array_mut) {
                choices.retain(|c| !c.is_null());
            }
        }
    }
    v
}

/// A string argument that is given and not blank.
fn given(s: Option<String>) -> Option<String> {
    s.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// An optional count with its default and bounds (lenient: out of range is
/// clamped, the schema having said what the bounds are).
fn count(v: Option<u64>, default: u64, min: u64, max: u64) -> usize {
    v.unwrap_or(default).clamp(min, max) as usize
}

// ───────────────────────────── the table ─────────────────────────────

const TOOLS: &[Tool] = &[
    Tool {
        name: "get_status",
        title: "Monitoring status",
        description: "Whether Fishe is monitoring, what (host / program / all traffic), and the latest measurement: \
            current rate (bytesPerSec, smoothed over ~1 s) and receive/send rates of the last tick (250 ms by default), \
            busyness level and ratio to the learned normal, peak, totals, \
            protocol and service breakdown, TCP quality (RTT, retransmissions), recording state, endpoint and program counts.",
        access: Access::Read,
        schema: schema_of::<NoArgs>,
        handler: |svc, v| get_status(svc, parse(v)?),
    },
    Tool {
        name: "wait_for_traffic",
        title: "Wait for traffic",
        description: "Block until traffic reaches a busyness level (default 'busy', i.e. at least twice its learned \
            normal) and/or a rate (minBytesPerSec alone waits for the rate only; with level, whichever comes first), \
            or until the timeout (default 30 s, max 120). Returns at once if it is already there. Watches the whole \
            session, or with program / endpoint only the busiest matching program (all-traffic mode) or endpoint, \
            each against its own normal: e.g. program 'game.exe' so other programs (including this agent's own API \
            traffic) don't trigger it. Rates are smoothed over about a second. Levels are ignored while a normal is \
            still being learned (the first seconds of the session, or of a new program or endpoint; default 5 s); a \
            rate can trigger at any time. Reports the moment: rates, level, ratio, the busiest endpoints and programs, \
            and the matched one. Use it to 'tell me when it spikes' instead of polling get_status.",
        access: Access::Read,
        schema: schema_of::<WaitArgs>,
        handler: |svc, v| wait_for_traffic(svc, parse(v)?),
    },
    Tool {
        name: "get_traffic_history",
        title: "Traffic history",
        description: "Rates over the last N seconds of the running session (up to 600 at the default 250 ms tick), as at most maxPoints points \
            (default 60; ticks averaged together): receive/send rate (bytes/s), learned normal, the highest \
            busyness level and TCP RTT of each point.",
        access: Access::Read,
        schema: schema_of::<HistoryArgs>,
        handler: |svc, v| get_traffic_history(svc, parse(v)?),
    },
    Tool {
        name: "get_endpoints",
        title: "Remote endpoints",
        description: "Remote addresses the monitored traffic goes to (process and all-traffic modes): name and its source \
            (TLS SNI, DNS, reverse DNS), network owner and country, current rate (bytesPerSec, smoothed over ~1 s; \
            in/out are the last 250 ms tick), busyness level, totals, services, TCP RTT / jitter / retransmissions, \
            estimated hops, and (all-traffic mode) the programs using it. Sort 'live' = busiest now.",
        access: Access::Read,
        schema: schema_of::<EndpointsArgs>,
        handler: |svc, v| get_endpoints(svc, parse(v)?),
    },
    Tool {
        name: "get_programs",
        title: "Programs using the network",
        description: "All-traffic mode only: every program (grouped by executable name) with current rate \
            (bytesPerSec, smoothed; in/out per tick), busyness level, totals, number of endpoints and PIDs. 'Unattributed' is traffic without an owning program (ICMP, \
            or sockets that closed before they could be identified).",
        access: Access::Read,
        schema: schema_of::<ProgramsArgs>,
        handler: |svc, v| get_programs(svc, parse(v)?),
    },
    Tool {
        name: "get_recent_packets",
        title: "Recent packets",
        description: "The latest packets of the running session (headers only: time, direction, addresses, ports, \
            protocol, length, TTL, program, remote name). Turns the live packet feed on for about a second if it is off.",
        access: Access::Read,
        schema: schema_of::<PacketsArgs>,
        handler: |svc, v| get_recent_packets(svc, parse(v)?),
    },
    Tool {
        name: "list_processes",
        title: "Processes with sockets",
        description: "Running programs grouped by executable name, busiest network users first: PIDs, sockets, \
            connections, listening sockets. Use a name from here with start_monitoring (mode 'process').",
        access: Access::Read,
        schema: schema_of::<ProcessesArgs>,
        handler: |svc, v| list_processes(svc, parse(v)?),
    },
    Tool {
        name: "list_interfaces",
        title: "Network interfaces",
        description: "Capture interfaces (device name, description, addresses, up/running, loopback, wireless).",
        access: Access::Read,
        schema: schema_of::<NoArgs>,
        handler: |svc, v| list_interfaces(svc, parse(v)?),
    },
    Tool {
        name: "list_recordings",
        title: "Recordings",
        description: "Saved recordings in Fishe's archive, newest first: id, name, mode, start, duration, totals, peak, \
            highest busyness level, endpoint count, packet file.",
        access: Access::Read,
        schema: schema_of::<NoArgs>,
        handler: |svc, v| list_recordings(svc, parse(v)?),
    },
    Tool {
        name: "get_recording",
        title: "One recording",
        description: "A saved recording: summary, busy/spike episodes (\"notable moments\"), protocol/service/program \
            breakdown, TCP quality, the biggest endpoints with owners and RTT, and the rate series downsampled.",
        access: Access::Read,
        schema: schema_of::<RecordingArgs>,
        handler: |svc, v| get_recording(svc, parse(v)?),
    },
    Tool {
        name: "get_route_traces",
        title: "Route traces",
        description: "Traceroutes already done in this app run (hops with address, name, owner, RTT, replies).",
        access: Access::Read,
        schema: schema_of::<NoArgs>,
        handler: |svc, v| get_route_traces(svc, parse(v)?),
    },
    Tool {
        name: "get_pings",
        title: "Pings",
        description: "Continuous pings started in Fishe: per address last/avg/min/max RTT, jitter, loss over the last \
            60 probes, and the last 30 probes.",
        access: Access::Read,
        schema: schema_of::<NoArgs>,
        handler: |svc, v| get_pings(svc, parse(v)?),
    },
    Tool {
        name: "lookup_owner",
        title: "Address owner",
        description: "Network owner (ASN, organisation) and country of a public IP, from the local DB-IP database \
            (or ipinfo.io if the user enabled online lookup).",
        access: Access::Read,
        schema: schema_of::<IpArgs>,
        handler: |svc, v| lookup_owner(svc, parse(v)?),
    },
    Tool {
        name: "start_monitoring",
        title: "Start monitoring",
        description: "Start a session (replacing the current one), shown in the Fishe window like one started there. \
            mode 'host': traffic with one IP or host name (host). mode 'process': one program by executable name \
            (process, e.g. 'chrome.exe', all its instances) or one PID (pid). mode 'all': every packet of the PC, \
            labelled by program.",
        access: Access::Control,
        schema: schema_of::<StartArgs>,
        handler: |svc, v| start_monitoring(svc, parse(v)?),
    },
    Tool {
        name: "stop_monitoring",
        title: "Stop monitoring",
        description: "Stop the running session (a running recording is saved).",
        access: Access::Control,
        schema: schema_of::<NoArgs>,
        handler: |svc, v| stop_monitoring(svc, parse(v)?),
    },
    Tool {
        name: "start_recording",
        title: "Start recording",
        description: "Record the running session into Fishe's archive (samples, notable moments, endpoints; \
            optionally the packet headers as .pcapng).",
        access: Access::Control,
        schema: schema_of::<RecordArgs>,
        handler: |svc, v| start_recording(svc, parse(v)?),
    },
    Tool {
        name: "stop_recording",
        title: "Stop recording",
        description: "Stop the recording; returns its id for get_recording.",
        access: Access::Control,
        schema: schema_of::<NoArgs>,
        handler: |svc, v| stop_recording(svc, parse(v)?),
    },
    Tool {
        name: "trace_route",
        title: "Traceroute",
        description: "Trace the route to an IP with ICMP probes (sends packets; ~2-10 s). Cached 10 minutes unless force.",
        access: Access::Network,
        schema: schema_of::<TraceArgs>,
        handler: |svc, v| trace_route(svc, parse(v)?),
    },
    Tool {
        name: "start_ping",
        title: "Start ping",
        description: "Ping an IP once per second (ICMP) for RTT, jitter and loss, e.g. a UDP game or voice server that \
            TCP analysis can't time. Stops by itself after 30 minutes; at most 4 at once. Read results with get_pings.",
        access: Access::Network,
        schema: schema_of::<IpArgs>,
        handler: |svc, v| start_ping(svc, parse(v)?),
    },
    Tool {
        name: "stop_ping",
        title: "Stop ping",
        description: "Stop pinging an IP (its figures stay readable with get_pings).",
        access: Access::Network,
        schema: schema_of::<IpArgs>,
        handler: |svc, v| stop_ping(svc, parse(v)?),
    },
];

/// Tool definitions visible at `access`.
pub fn list(access: Access) -> Vec<Value> {
    TOOLS
        .iter()
        .filter(|t| t.access <= access)
        .map(|t| {
            json!({
                "name": t.name,
                "title": t.title,
                "description": t.description,
                "inputSchema": (t.schema)(),
                "annotations": {
                    "title": t.title,
                    "readOnlyHint": t.access == Access::Read,
                    "destructiveHint": false,
                    "idempotentHint": t.access == Access::Read,
                    "openWorldHint": t.access == Access::Network,
                }
            })
        })
        .collect()
}

pub fn call(svc: &Services, params: &Value, client: &str) -> Result<Value, (i64, String)> {
    let state = &svc.mcp;
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or((-32602, "missing tool name".to_string()))?;
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let tool = TOOLS
        .iter()
        .find(|t| t.name == name)
        .ok_or_else(|| (-32602, format!("unknown tool: {name}")))?;
    if tool.access > state.access() {
        return Err((
            -32602,
            format!(
                "{name} is not enabled: the user allows '{}' access in Fishe (Settings → Agents)",
                serde_json::to_value(state.access())
                    .ok()
                    .and_then(|v| v.as_str().map(String::from))
                    .unwrap_or_default()
            ),
        ));
    }

    let mut compact = args.to_string();
    if compact.len() > 160 {
        // Arguments are whatever the client sent: any script, any length.
        crate::util::truncate_at_char(&mut compact, 157);
        compact.push('…');
    }
    let started = Instant::now();
    let outcome = (tool.handler)(svc, args);
    state.record(
        svc,
        Activity {
            at_ms: now_ms(),
            tool: name.to_string(),
            args: if compact == "{}" {
                String::new()
            } else {
                compact
            },
            ok: outcome.is_ok(),
            duration_ms: started.elapsed().as_millis() as u64,
            note: outcome.as_ref().err().cloned().unwrap_or_default(),
            client: client.to_string(),
        },
    );

    Ok(match outcome {
        Ok(v) => {
            // Compact: pretty-printing costs the agent's context ~30% more tokens.
            let text = serde_json::to_string(&v).unwrap_or_default();
            let structured = if v.is_object() {
                v
            } else {
                json!({ "result": v })
            };
            json!({ "content": [{ "type": "text", "text": text }], "structuredContent": structured, "isError": false })
        }
        Err(e) => json!({ "content": [{ "type": "text", "text": e }], "isError": true }),
    })
}

// ───────────────────────────── helpers ─────────────────────────────

fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

fn to_json<T: serde::Serialize>(v: &T) -> Value {
    serde_json::to_value(v).unwrap_or(Value::Null)
}

fn err_text(e: crate::error::AppError) -> String {
    e.to_string()
}

const NOT_MONITORING: &str =
    "Fishe is not monitoring; start_monitoring (control access) or start it in the app";

/// The running session and its latest sample. A session that just started
/// gets up to 2 s for its first measurement, so a read right after
/// `start_monitoring` doesn't fail.
fn running(svc: &Services) -> Result<(SessionInfo, Sample), String> {
    let state = &svc.monitor;
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match state.latest() {
            Some((info, Some(s))) => return Ok((info, s)),
            Some((_, None)) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Some((_, None)) => {
                return Err("the session has no measurement yet; try again in a second".into());
            }
            None => return Err(NOT_MONITORING.into()),
        }
    }
}

fn session_json(info: &SessionInfo) -> Value {
    json!({
        "id": info.session_id,
        "mode": info.mode,
        "label": info.label,
        "target": info.target,
        "resolvedFrom": info.resolved_from,
        "process": info.process,
        "attribution": info.attribution.as_ref().map(|a| a.method),
        "interfaces": info.interfaces.iter().map(|i| &i.description).collect::<Vec<_>>(),
        "filter": info.filter,
        "tickMs": info.tick_ms,
    })
}

fn endpoint_json(r: &EndpointRow, now_ms: u64) -> Value {
    json!({
        "ip": r.ip,
        "name": r.name,
        "nameSource": r.name_source,
        "scope": r.scope,
        "owner": r.owner.as_ref().map(|o| json!({ "asn": o.asn, "org": o.org, "country": o.country })),
        "bytesPerSec": round1(r.smoothed_bps),
        "inBytesPerSec": round1(r.in_bps),
        "outBytesPerSec": round1(r.out_bps),
        "level": r.level,
        "ratioToNormal": round1(r.ratio),
        "peakBytesPerSec": round1(r.peak_bps),
        "totals": r.totals,
        "services": r.top_ports.iter().map(|p| format!("{}/{}", p.port, to_json(&p.transport).as_str().unwrap_or(""))).collect::<Vec<_>>(),
        "hopsEstimate": r.hops,
        "rttMs": r.quality.as_ref().and_then(|q| q.srtt_ms).map(round1),
        "minRttMs": r.quality.as_ref().and_then(|q| q.min_rtt_ms).map(round1),
        "jitterMs": r.quality.as_ref().and_then(|q| q.jitter_ms).map(round1),
        "retransmittedSentPct": r.quality.as_ref().and_then(|q| q.retrans_out_pct).map(round1),
        "retransmittedReceivedPct": r.quality.as_ref().and_then(|q| q.retrans_in_pct).map(round1),
        "programs": r.programs.iter().map(|p| &p.name).collect::<Vec<_>>(),
        "firstSeenSecondsAgo": now_ms.saturating_sub(r.first_seen_ms) / 1000,
        "lastSeenSecondsAgo": now_ms.saturating_sub(r.last_seen_ms) / 1000,
    })
}

fn program_json(r: &ProgramRow, now_ms: u64) -> Value {
    json!({
        "name": r.name,
        "pids": r.pids,
        "bytesPerSec": round1(r.smoothed_bps),
        "inBytesPerSec": round1(r.in_bps),
        "outBytesPerSec": round1(r.out_bps),
        "level": r.level,
        "ratioToNormal": round1(r.ratio),
        "peakBytesPerSec": round1(r.peak_bps),
        "totals": r.totals,
        "endpoints": r.endpoints,
        "lastSeenSecondsAgo": now_ms.saturating_sub(r.last_seen_ms) / 1000,
    })
}

// ───────────────────────────── read ─────────────────────────────

fn get_status(svc: &Services, _: NoArgs) -> Result<Value, String> {
    let npcap = crate::npcap::init();
    let pings = svc.pings.status();
    let pings_running = pings.iter().filter(|p| p.running).count();
    let Some((info, sample)) = svc.monitor.latest() else {
        return Ok(json!({
            "monitoring": false,
            "npcapAvailable": npcap.available,
            "pingsRunning": pings_running,
            "hint": "Not monitoring. With control access, start_monitoring; list_processes shows candidates.",
        }));
    };
    let now = sample.as_ref().map(|s| {
        json!({
            "runningForSeconds": s.t_ms / 1000,
            "learningNormal": learning_normal(&info, s),
            "bytesPerSec": round1(s.smoothed_bps),
            "inBytesPerSec": round1(s.in_bps),
            "outBytesPerSec": round1(s.out_bps),
            "inPacketsPerSec": round1(s.in_pps),
            "outPacketsPerSec": round1(s.out_pps),
            "level": s.level,
            "ratioToNormal": round1(s.ratio),
            "normalBytesPerSec": round1(s.baseline_bps),
            "peakBytesPerSec": round1(s.peak_bps),
            "totals": s.totals,
            "bytesByTransport": s.transports,
            "topServices": s.top_ports.iter().map(|p| json!({ "port": p.port, "transport": p.transport, "bytes": p.bytes, "packets": p.packets })).collect::<Vec<_>>(),
            "droppedPackets": s.dropped + s.if_dropped,
            "unattributedPackets": s.unattributed,
            "endpointCount": s.endpoints.as_ref().map(|e| e.total),
            "programCount": s.programs.as_ref().map(|p| p.total),
            "quality": s.quality,
            "recording": s.recording,
        })
    });
    let mut out = json!({
        "monitoring": true,
        "npcapAvailable": npcap.available,
        "session": session_json(&info),
        "now": now,
        "pingsRunning": pings_running,
        "levels": "idle < calm < busy (≥ 2× normal by default) < spike (≥ 5×)",
        "rates": "bytesPerSec is in + out smoothed over about a second (what the level uses); in/out are the last tick (250 ms by default)",
    });
    if info
        .target
        .is_some_and(|t| pings.iter().any(|p| p.running && p.ip == t))
    {
        out["note"] =
            json!("Fishe is pinging this host: its ICMP echoes are part of the measured traffic");
    }
    Ok(out)
}

/// Whether the session is still in the detector's warm-up, when the
/// "normal" level is not learned yet and levels are unreliable.
fn learning_normal(info: &SessionInfo, s: &Sample) -> bool {
    (s.t_ms as f64) < info.gauge.warmup_secs * 1000.0
}

/// The busiest endpoints and programs of a sample, briefly.
fn moment(s: &Sample) -> Value {
    let mut eps: Vec<&EndpointRow> = s
        .endpoints
        .as_ref()
        .map(|e| e.rows.iter().collect())
        .unwrap_or_default();
    eps.sort_by(|a, b| b.smoothed_bps.total_cmp(&a.smoothed_bps));
    let mut progs: Vec<&ProgramRow> = s
        .programs
        .as_ref()
        .map(|p| p.rows.iter().collect())
        .unwrap_or_default();
    progs.sort_by(|a, b| b.smoothed_bps.total_cmp(&a.smoothed_bps));
    json!({
        "tSeconds": round1(s.t_ms as f64 / 1000.0),
        "bytesPerSec": round1(s.smoothed_bps),
        "inBytesPerSec": round1(s.in_bps),
        "outBytesPerSec": round1(s.out_bps),
        "level": s.level,
        "ratioToNormal": round1(s.ratio),
        "normalBytesPerSec": round1(s.baseline_bps),
        "busiestEndpoints": eps.iter().take(3).filter(|r| r.smoothed_bps > 0.0).map(|r| json!({
            "ip": r.ip, "name": r.name, "bytesPerSec": round1(r.smoothed_bps),
            "programs": r.programs.iter().map(|p| &p.name).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "busiestPrograms": progs.iter().take(3).filter(|r| r.smoothed_bps > 0.0).map(|r| json!({
            "name": r.name, "bytesPerSec": round1(r.smoothed_bps),
        })).collect::<Vec<_>>(),
    })
}

/// What `wait_for_traffic` watches.
enum Watch {
    Session,
    /// The busiest program whose name contains this (lowercase).
    Program(String),
    /// The busiest endpoint whose IP or name contains this (lowercase).
    Endpoint(String),
}

/// The watched traffic at one sample.
struct Watched {
    /// Smoothed in + out, bytes/s.
    rate: f64,
    level: Level,
    /// Its detector is still learning the normal (levels mean little).
    learning: bool,
    /// The matched program or endpoint, for the answer.
    matched: Option<Value>,
}

impl Watch {
    fn new(program: Option<String>, endpoint: Option<String>) -> Result<Watch, String> {
        match (given(program), given(endpoint)) {
            (Some(_), Some(_)) => Err("give program or endpoint, not both".into()),
            (Some(p), None) => Ok(Watch::Program(p.to_lowercase())),
            (None, Some(e)) => Ok(Watch::Endpoint(e.to_lowercase())),
            (None, None) => Ok(Watch::Session),
        }
    }

    fn read(&self, info: &SessionInfo, s: &Sample) -> Result<Watched, String> {
        let warm_up_ms = info.gauge.warmup_secs * 1000.0;
        let young = |first_seen_ms: u64| (s.t_ms.saturating_sub(first_seen_ms) as f64) < warm_up_ms;
        let session_learning = learning_normal(info, s);
        let nothing = Watched {
            rate: 0.0,
            level: Level::Idle,
            learning: session_learning,
            matched: None,
        };
        Ok(match self {
            Watch::Session => Watched {
                rate: s.smoothed_bps,
                level: s.level,
                learning: session_learning,
                matched: None,
            },
            Watch::Program(q) => {
                let rows = s.programs.as_ref().ok_or(
                    "the program filter needs all-traffic mode (start_monitoring with mode 'all')",
                )?;
                rows.rows
                    .iter()
                    .filter(|r| r.name.to_lowercase().contains(q.as_str()))
                    .max_by(|a, b| a.smoothed_bps.total_cmp(&b.smoothed_bps))
                    .map_or(nothing, |r| Watched {
                        rate: r.smoothed_bps,
                        level: r.level,
                        learning: session_learning || young(r.first_seen_ms),
                        matched: Some(json!({
                            "program": r.name, "bytesPerSec": round1(r.smoothed_bps),
                            "level": r.level, "ratioToNormal": round1(r.ratio),
                        })),
                    })
            }
            Watch::Endpoint(q) => {
                let rows = s.endpoints.as_ref().ok_or(
                    "the endpoint filter needs process or all-traffic mode (a host session is one endpoint: leave it out)",
                )?;
                rows.rows
                    .iter()
                    .filter(|r| {
                        r.ip.to_string().contains(q.as_str())
                            || r.name
                                .as_deref()
                                .is_some_and(|n| n.to_lowercase().contains(q.as_str()))
                    })
                    .max_by(|a, b| a.smoothed_bps.total_cmp(&b.smoothed_bps))
                    .map_or(nothing, |r| Watched {
                        rate: r.smoothed_bps,
                        level: r.level,
                        learning: session_learning || young(r.first_seen_ms),
                        matched: Some(json!({
                            "ip": r.ip, "name": r.name, "bytesPerSec": round1(r.smoothed_bps),
                            "level": r.level, "ratioToNormal": round1(r.ratio),
                            "programs": r.programs.iter().map(|p| &p.name).collect::<Vec<_>>(),
                        })),
                    })
            }
        })
    }
}

fn wait_for_traffic(svc: &Services, a: WaitArgs) -> Result<Value, String> {
    let min_rate = match a.min_bytes_per_sec {
        Some(r) if r < 0.0 => return Err("minBytesPerSec must be a number ≥ 0".into()),
        r => r,
    };
    // A rate alone waits for the rate; otherwise the level (default busy).
    let level = match (a.level, min_rate) {
        (None, Some(_)) => None,
        (None, None) | (Some(WaitLevel::Busy), _) => Some(Level::Busy),
        (Some(WaitLevel::Calm), _) => Some(Level::Calm),
        (Some(WaitLevel::Spike), _) => Some(Level::Spike),
    };
    let watch = Watch::new(a.program, a.endpoint)?;
    let timeout = Duration::from_secs(count(a.timeout_seconds, 30, 1, 120) as u64);
    let state = &svc.monitor;
    if state.latest().is_none() {
        return Err(NOT_MONITORING.into());
    }
    let started = Instant::now();
    let mut skipped_warm_up = false;
    loop {
        let Some((info, sample)) = state.latest() else {
            return Ok(
                json!({ "triggered": false, "reason": "monitoring stopped", "waitedSeconds": started.elapsed().as_secs() }),
            );
        };
        // A session that just started has no sample yet: waiting covers that.
        if let Some(s) = &sample {
            let w = watch.read(&info, s)?;
            // While a normal is still being learned (the detector's warm-up),
            // a level means little: only a rate can trigger then.
            let level_hit = level.is_some_and(|l| w.level >= l);
            if level_hit && w.learning {
                skipped_warm_up = true;
            }
            let hit = (level_hit && !w.learning) || min_rate.is_some_and(|r| w.rate >= r);
            if hit || started.elapsed() >= timeout {
                let mut out = if hit {
                    json!({
                        "triggered": true,
                        "waitedSeconds": round1(started.elapsed().as_secs_f64()),
                        "moment": moment(s),
                    })
                } else {
                    json!({
                        "triggered": false,
                        "reason": "timeout",
                        "waitedSeconds": timeout.as_secs(),
                        "now": moment(s),
                    })
                };
                if let Some(m) = w.matched {
                    out["matched"] = m;
                } else if !matches!(watch, Watch::Session) {
                    out["matched"] = json!(null);
                    out["matchNote"] = json!("nothing matching the filter had traffic");
                }
                if skipped_warm_up {
                    out["note"] = json!(format!(
                        "ignored levels during the first {} s (of the session, or of the matched program or endpoint) while Fishe learned the normal",
                        info.gauge.warmup_secs
                    ));
                }
                return Ok(out);
            }
        } else if started.elapsed() >= timeout {
            return Ok(
                json!({ "triggered": false, "reason": "no measurement yet", "waitedSeconds": timeout.as_secs() }),
            );
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn get_traffic_history(svc: &Services, a: HistoryArgs) -> Result<Value, String> {
    let secs = count(a.seconds, 60, 5, 600) as u64;
    let max_points = count(a.max_points, 60, 1, 600);
    let (info, _) = running(svc)?;
    let points = svc.monitor.history(secs);
    // Average consecutive ticks so the answer has at most max_points points;
    // level and RTT are the worst of each bucket, so a spike survives.
    let bucket = points.len().div_ceil(max_points).max(1);
    let out: Vec<Value> = points
        .chunks(bucket)
        .map(|c| {
            let n = c.len() as f64;
            let mean = |f: fn(&crate::monitor::live::HistoryPoint) -> f64| {
                round1(c.iter().map(f).sum::<f64>() / n)
            };
            let mut p = json!({
                "t": round1(c[c.len() - 1].t_ms as f64 / 1000.0),
                "inBytesPerSec": mean(|p| p.in_bps),
                "outBytesPerSec": mean(|p| p.out_bps),
                "normalBytesPerSec": mean(|p| p.baseline_bps),
                "level": c.iter().map(|p| p.level).max(),
            });
            if let Some(rtt) = c.iter().filter_map(|p| p.rtt_ms).reduce(f64::max) {
                p["rttMs"] = json!(round1(rtt));
            }
            p
        })
        .collect();
    let tick_ms = info.tick_ms as f64;
    Ok(json!({
        "session": info.label,
        "secondsPerPoint": round1(bucket as f64 * tick_ms / 1000.0),
        "points": out,
        "notes": "t: seconds since the session started (end of each point); rates averaged per point, level and rttMs the worst of the point (rttMs only where TCP gave one)",
    }))
}

fn get_endpoints(svc: &Services, a: EndpointsArgs) -> Result<Value, String> {
    let (info, s) = running(svc)?;
    let tick = s
        .endpoints
        .as_ref()
        .ok_or("no endpoint list in host mode: the session is one endpoint (see get_status)")?;
    let q = given(a.filter).map(|f| f.to_lowercase());
    let mut rows: Vec<&EndpointRow> = tick
        .rows
        .iter()
        .filter(|r| {
            q.as_ref().is_none_or(|q| {
                r.ip.to_string().contains(q.as_str())
                    || r.name
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(q.as_str())
                    || r.owner.as_ref().is_some_and(|o| {
                        o.org
                            .as_deref()
                            .unwrap_or("")
                            .to_lowercase()
                            .contains(q.as_str())
                            || o.country.as_deref().unwrap_or("").to_lowercase() == *q
                    })
                    || r.programs
                        .iter()
                        .any(|p| p.name.to_lowercase().contains(q.as_str()))
            })
        })
        .collect();
    let bytes = |r: &EndpointRow| r.totals.bytes_in + r.totals.bytes_out;
    match a.sort.unwrap_or_default() {
        EndpointSort::Total => rows.sort_by_key(|r| std::cmp::Reverse(bytes(r))),
        EndpointSort::Recent => rows.sort_by_key(|r| std::cmp::Reverse(r.first_seen_ms)),
        EndpointSort::Rtt => rows.sort_by(|a, b| {
            let rtt = |r: &EndpointRow| r.quality.as_ref().and_then(|q| q.srtt_ms).unwrap_or(-1.0);
            rtt(b).total_cmp(&rtt(a))
        }),
        EndpointSort::Live => rows.sort_by(|a, b| b.smoothed_bps.total_cmp(&a.smoothed_bps)),
    }
    let limit = count(a.limit, 25, 1, 150);
    Ok(json!({
        "session": info.label,
        "endpointsKnown": tick.total,
        "matching": rows.len(),
        "endpoints": rows.iter().take(limit).map(|r| endpoint_json(r, s.t_ms)).collect::<Vec<_>>(),
    }))
}

fn get_programs(svc: &Services, a: ProgramsArgs) -> Result<Value, String> {
    let (_, s) = running(svc)?;
    let tick = s.programs.as_ref().ok_or(
        "programs are only measured in all-traffic mode (start_monitoring with mode 'all')",
    )?;
    let mut rows: Vec<&ProgramRow> = tick.rows.iter().collect();
    match a.sort.unwrap_or_default() {
        ProgramSort::Total => {
            rows.sort_by_key(|r| std::cmp::Reverse(r.totals.bytes_in + r.totals.bytes_out))
        }
        ProgramSort::Name => rows.sort_by(|a, b| a.name.cmp(&b.name)),
        ProgramSort::Live => rows.sort_by(|a, b| b.smoothed_bps.total_cmp(&a.smoothed_bps)),
    }
    let limit = count(a.limit, 25, 1, 100);
    Ok(json!({
        "programsKnown": tick.total,
        "programs": rows.iter().take(limit).map(|r| program_json(r, s.t_ms)).collect::<Vec<_>>(),
    }))
}

fn get_recent_packets(svc: &Services, a: PacketsArgs) -> Result<Value, String> {
    let q = given(a.filter).map(|f| f.to_lowercase());
    let limit = count(a.limit, 100, 1, 500);
    let (info, _) = running(svc)?;
    let state = &svc.monitor;
    // Hold the feed on for the duration of this call rather than toggling
    // the UI's switch: the window may turn it on meanwhile and must keep it.
    let was_on = state.packet_feed_enabled();
    let _hold = state.hold_packet_feed();
    if !was_on {
        std::thread::sleep(Duration::from_millis(1200));
    }
    let batch = state.recent_packets(None, crate::monitor::packets::RING_CAP);
    let rows: Vec<Value> = batch
        .rows
        .iter()
        .rev()
        .map(|p| {
            let mut v = to_json(p);
            if let Some(o) = v.as_object_mut() {
                // Fishe's own packet counter, easily mistaken for a TCP sequence number.
                o.remove("seq");
                // The capture worker index means nothing to an agent: name it.
                if let Some(i) = info.interfaces.get(p.iface as usize) {
                    o.insert("iface".into(), json!(i.description));
                }
                o.retain(|_, v| !v.is_null());
            }
            v
        })
        .filter(|v| {
            q.as_ref()
                .is_none_or(|q| v.to_string().to_lowercase().contains(q.as_str()))
        })
        .take(limit)
        .collect();
    Ok(json!({
        "newestFirst": true,
        "note": if was_on { "from the live feed" } else { "captured over ~1.2 s (feed turned on briefly)" },
        "packets": rows,
    }))
}

fn list_processes(_: &Services, a: ProcessesArgs) -> Result<Value, String> {
    let q = given(a.filter).map(|f| f.to_lowercase());
    let limit = count(a.limit, 40, 1, 200);
    // Without a filter, programs with no socket at all are noise.
    let all = q.is_some() || a.include_no_sockets.unwrap_or(false);
    let groups = processes::groups().map_err(err_text)?;
    let hidden = if all {
        0
    } else {
        groups.iter().filter(|g| g.sockets == 0).count()
    };
    let rows: Vec<Value> = groups
        .iter()
        .filter(|g| all || g.sockets > 0)
        .filter(|g| q.as_ref().is_none_or(|q| g.name.to_lowercase().contains(q.as_str())))
        .take(limit)
        .map(|g| {
            json!({ "name": g.name, "pids": g.pids, "sockets": g.sockets, "connections": g.connections, "listening": g.listening })
        })
        .collect();
    let mut out = json!({ "processes": rows });
    if hidden > 0 {
        out["hiddenWithoutSockets"] = json!(hidden);
    }
    Ok(out)
}

fn list_interfaces(_: &Services, _: NoArgs) -> Result<Value, String> {
    Ok(json!({ "interfaces": ops::list_interfaces().map_err(err_text)? }))
}

fn with_archive<T>(
    svc: &Services,
    f: impl FnOnce(&rusqlite::Connection) -> crate::error::AppResult<T>,
) -> Result<T, String> {
    ops::with_archive(svc, f).map_err(err_text)
}

fn list_recordings(svc: &Services, _: NoArgs) -> Result<Value, String> {
    let list = with_archive(svc, db::list)?;
    Ok(json!({ "recordings": list }))
}

fn get_recording(svc: &Services, a: RecordingArgs) -> Result<Value, String> {
    let d = with_archive(svc, |c| db::detail(c, a.id))?;
    let max_points = count(a.max_points, 100, 0, 2000);
    let ep_limit = count(a.endpoint_limit, 25, 0, 500);
    let (samples, downsampled) = db::downsample(d.samples, max_points.max(1));
    // Same names as the live tools (and fewer fields: ratio = in+out / normal).
    let samples: Vec<Value> = samples
        .iter()
        .map(|p| {
            let mut v = json!({
                "t": round1(p.t_ms as f64 / 1000.0),
                "inBytesPerSec": round1(p.in_bps),
                "outBytesPerSec": round1(p.out_bps),
                "normalBytesPerSec": round1(p.baseline_bps),
                "level": p.level,
            });
            if let Some(rtt) = p.rtt_ms {
                v["rttMs"] = json!(round1(rtt));
            }
            v
        })
        .collect();
    Ok(json!({
        "summary": d.summary,
        "session": d.session,
        "extra": d.extra,
        "notableMoments": d.episodes,
        "endpoints": d.endpoints.iter().take(ep_limit).collect::<Vec<_>>(),
        "endpointCount": d.endpoints.len(),
        "samples": if max_points == 0 { Value::Null } else { json!(samples) },
        "samplesDownsampled": downsampled || d.downsampled,
        "units": "rates in bytes/s; samples' t in seconds from the recording start (level is the highest of each averaged point)",
    }))
}

fn get_route_traces(svc: &Services, _: NoArgs) -> Result<Value, String> {
    Ok(json!({ "traces": svc.traces.cached() }))
}

fn get_pings(svc: &Services, _: NoArgs) -> Result<Value, String> {
    let mut list = svc.pings.status();
    for p in &mut list {
        let n = p.history.len();
        p.history.drain(..n.saturating_sub(30));
    }
    Ok(
        json!({ "pings": list, "historyNote": "last 30 probes, one per second, oldest first; null = lost" }),
    )
}

fn probe_target(ip: &str) -> Result<std::net::IpAddr, String> {
    ops::probe_target(ip).map_err(err_text)
}

fn lookup_owner(svc: &Services, a: IpArgs) -> Result<Value, String> {
    let ip: std::net::IpAddr =
        a.ip.trim()
            .parse()
            .map_err(|_| "not an IP address".to_string())?;
    let owner = ops::owner(svc, ip);
    Ok(json!({ "ip": ip, "owner": owner, "scope": crate::naming::addr::classify(ip) }))
}

// ───────────────────────────── control ─────────────────────────────

fn start_monitoring(svc: &Services, a: StartArgs) -> Result<Value, String> {
    let target = match a.mode {
        StartMode::Host => TargetSpec::Host {
            address: given(a.host).ok_or("mode 'host' needs host")?,
        },
        StartMode::Process => TargetSpec::Process {
            selector: match (a.pid, given(a.process)) {
                (Some(pid), _) => ProcessSelector::Pid { pid },
                (None, Some(name)) => ProcessSelector::Name { name },
                (None, None) => {
                    return Err("mode 'process' needs process (executable name) or pid".into());
                }
            },
        },
        StartMode::All => TargetSpec::All,
    };
    // Resolve up front: a typo must not stop the running session.
    if let TargetSpec::Host { address } = &target {
        crate::net::resolve::resolve(address).map_err(err_text)?;
    }
    let state = &svc.monitor;
    // The window's Settings (sensitivity, reverse DNS) apply, as with a click.
    let defaults = state.defaults();
    let req = StartRequest {
        target,
        interface: given(a.interface),
        gauge: defaults.gauge,
        tick_ms: None,
        naming: defaults.naming,
    };
    // The same path as the Start button; the window follows through its
    // event subscription.
    let info = ops::start_monitor(svc, req).map_err(err_text)?;
    // Wait for the first measurement (one tick), so the agent's next read
    // has data.
    let first = Instant::now() + Duration::from_secs(2);
    while Instant::now() < first
        && state
            .latest()
            .is_some_and(|(i, s)| i.session_id == info.session_id && s.is_none())
    {
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut out = json!({ "started": true, "session": session_json(&info) });
    if let Some(p) = info.process.as_ref().filter(|p| p.pids.is_empty()) {
        let what = match &p.selector {
            ProcessSelector::Name { name } => format!("'{name}'"),
            ProcessSelector::Pid { pid } => format!("PID {pid}"),
        };
        out["note"] = json!(format!(
            "no running process matches {what} yet: Fishe measures it as soon as it starts. If that's a typo, check list_processes"
        ));
    }
    Ok(out)
}

fn stop_monitoring(svc: &Services, _: NoArgs) -> Result<Value, String> {
    Ok(json!({ "stopped": ops::stop_monitor(svc) }))
}

fn start_recording(svc: &Services, a: RecordArgs) -> Result<Value, String> {
    let opts = RecordOptions {
        name: given(a.name),
        pcap: a.pcap.unwrap_or(false),
    };
    let info = ops::start_recording(svc, opts).map_err(err_text)?;
    Ok(json!({ "recording": info }))
}

fn stop_recording(svc: &Services, _: NoArgs) -> Result<Value, String> {
    Ok(json!({ "saved": ops::stop_recording(svc) }))
}

// ───────────────────────────── network ─────────────────────────────

fn trace_route(svc: &Services, a: TraceArgs) -> Result<Value, String> {
    let ip = probe_target(&a.ip)?;
    let t = ops::trace_route(svc, ip, a.force.unwrap_or(false));
    let mut out = to_json(&t);
    // A public address "reached" at the first hop is answered by the router
    // or another local device (some ISP boxes intercept 1.1.1.1, say).
    let public = matches!(
        crate::naming::addr::classify(ip),
        crate::naming::addr::AddrScope::Public
    );
    if public && t.reached && t.hops.len() == 1 {
        out["note"] = json!(
            "the destination answered at the first hop: your router or a local device answers for this address, so this is not its real route"
        );
    }
    Ok(out)
}

fn start_ping(svc: &Services, a: IpArgs) -> Result<Value, String> {
    let st = ops::ping_start(svc, probe_target(&a.ip)?).map_err(err_text)?;
    Ok(json!({ "ping": st, "hint": "one probe per second; read with get_pings" }))
}

fn stop_ping(svc: &Services, a: IpArgs) -> Result<Value, String> {
    Ok(json!({ "stopped": ops::ping_stop(svc, probe_target(&a.ip)?) }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(name: &str) -> &'static Tool {
        TOOLS.iter().find(|t| t.name == name).unwrap()
    }

    fn by_access(a: Access) -> usize {
        TOOLS.iter().filter(|t| t.access == a).count()
    }

    #[test]
    fn tools_by_access_level() {
        let read = list(Access::Read);
        let control = list(Access::Control);
        let network = list(Access::Network);
        assert_eq!(read.len(), by_access(Access::Read));
        assert_eq!(
            control.len(),
            by_access(Access::Read) + by_access(Access::Control)
        );
        assert_eq!(network.len(), TOOLS.len());
        assert!(
            read.iter()
                .all(|t| t["annotations"]["readOnlyHint"] == true)
        );
        assert!(!control.iter().any(|t| t["name"] == "trace_route"));
        let names: std::collections::HashSet<&str> = TOOLS.iter().map(|t| t.name).collect();
        assert_eq!(names.len(), TOOLS.len(), "unique names");
        for t in TOOLS {
            let s = (t.schema)();
            assert_eq!(s["type"], "object", "{}", t.name);
            assert_eq!(s["additionalProperties"], false, "{}", t.name);
            assert!(s["properties"].is_object(), "{}", t.name);
            assert!(s.get("$schema").is_none() && s.get("title").is_none());
            assert!(
                t.description.len() > 30,
                "{} needs a real description",
                t.name
            );
        }
    }

    /// Every tool (name and level) is in the table in docs/mcp.md.
    #[test]
    fn docs_list_every_tool() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/mcp.md");
        let doc = std::fs::read_to_string(&path).expect("docs/mcp.md");
        for t in TOOLS {
            let level = serde_json::to_value(t.access).unwrap();
            let level = level.as_str().unwrap();
            let cell = format!("| {level} |");
            let name = format!("`{}`", t.name);
            assert!(
                doc.lines().any(|l| l.contains(&name) && l.contains(&cell)),
                "docs/mcp.md has no table row for {} at level {level}",
                t.name
            );
        }
    }

    #[test]
    fn schemas_carry_defaults_bounds_and_choices() {
        let s = (tool("get_endpoints").schema)();
        let limit = &s["properties"]["limit"];
        assert_eq!(limit["type"], "integer", "{limit}");
        assert_eq!(limit["default"], 25);
        assert_eq!(limit["minimum"], 1);
        assert_eq!(limit["maximum"], 150);
        let sort = &s["properties"]["sort"];
        assert_eq!(sort["default"], "live");
        assert_eq!(sort["enum"], json!(["live", "total", "recent", "rtt"]));
        assert_eq!(s["properties"]["filter"]["type"], "string");
        assert!(
            s.get("required")
                .is_none_or(|r| r.as_array().is_some_and(Vec::is_empty))
        );

        let s = (tool("get_recording").schema)();
        assert_eq!(s["required"], json!(["id"]));
        assert_eq!(s["properties"]["maxPoints"]["minimum"], 0);

        let s = (tool("wait_for_traffic").schema)();
        assert_eq!(
            s["properties"]["level"]["enum"],
            json!(["calm", "busy", "spike"])
        );
        assert_eq!(s["properties"]["minBytesPerSec"]["type"], "number");
        assert!(s["properties"]["program"]["description"].is_string());

        let s = (tool("start_monitoring").schema)();
        assert_eq!(s["required"], json!(["mode"]));
        assert_eq!(
            s["properties"]["mode"]["enum"],
            json!(["host", "process", "all"])
        );
        assert_eq!((tool("get_status").schema)()["properties"], json!({}));
    }

    #[test]
    fn arguments_are_checked() {
        let a: EndpointsArgs =
            parse(json!({ "limit": 7, "sort": "total", "filter": null })).unwrap();
        assert_eq!(a.limit, Some(7));
        assert_eq!(a.sort, Some(EndpointSort::Total));
        assert_eq!(a.filter, None);
        let a: EndpointsArgs = parse(json!({})).unwrap();
        assert_eq!(
            (a.limit, a.sort),
            (Some(25), Some(EndpointSort::Live)),
            "defaults"
        );
        let a: EndpointsArgs = parse(json!({ "limit": null })).unwrap();
        assert_eq!(a.limit, None, "null = not given");
        assert_eq!(count(a.limit, 25, 1, 150), 25);
        assert_eq!(count(Some(9999), 25, 1, 150), 150, "clamped");

        let e = parse::<EndpointsArgs>(json!({ "limt": 3 })).unwrap_err();
        assert!(e.contains("limt") && e.contains("limit"), "{e}");
        let e = parse::<EndpointsArgs>(json!({ "limit": "abc" })).unwrap_err();
        assert!(e.contains("string") && e.contains("abc"), "{e}");
        let e = parse::<EndpointsArgs>(json!({ "limit": -5 })).unwrap_err();
        assert!(e.contains("-5"), "{e}");
        let e = parse::<EndpointsArgs>(json!({ "sort": "bogus" })).unwrap_err();
        assert!(
            e.contains("bogus") && e.contains("live") && e.contains("rtt"),
            "{e}"
        );
        let e = parse::<RecordingArgs>(json!({})).unwrap_err();
        assert!(e.contains("id"), "{e}");
        assert!(parse::<NoArgs>(json!({})).is_ok());
        let e = parse::<NoArgs>(json!({ "x": 1 })).unwrap_err();
        assert!(e.contains("x"), "{e}");
        assert!(parse::<NoArgs>(json!([1])).is_err());
    }

    #[test]
    fn start_arguments() {
        let a: StartArgs = parse(json!({ "mode": "process", "process": " chrome.exe " })).unwrap();
        assert_eq!(a.mode, StartMode::Process);
        assert_eq!(given(a.process).as_deref(), Some("chrome.exe"));
        assert_eq!(given(Some("  ".into())), None);
        assert!(parse::<StartArgs>(json!({ "mode": "everything" })).is_err());
        assert!(
            parse::<StartArgs>(json!({ "host": "1.1.1.1" })).is_err(),
            "mode required"
        );
    }
}

//! Monitoring sessions: at most one at a time, owned by [`MonitorState`].
//!
//! A session targets a remote **host** (one interface, BPF `host X`), a
//! **process** (every active interface, BPF `tcp or udp`, packets attributed
//! by socket ownership), or **all traffic** of the machine (every active
//! network interface, BPF `ip or ip6`, every packet labelled with its
//! program). See `docs/process-mode.md` and `docs/all-traffic.md`.

pub mod endpoints;
pub mod engine;
pub mod events;
pub mod gauge;
pub mod live;
pub mod packets;
pub mod programs;
pub mod quality;
pub mod stats;
pub mod target;

use crate::archive::ArchiveState;
use crate::archive::recorder::{RecordOptions, RecordingInfo, RecordingSlot};
use crate::error::{AppError, AppResult};
use crate::geo::Geo;
use crate::naming::{book::NameBook, rdns::Resolver, sniffer};
use crate::net::capture::{self, OpenCapture};
use crate::net::{interfaces, resolve};
use crate::process::etw::{EtwSink, EtwTracker};
use crate::process::{
    elevation, etw, machine::MachineScope, ownership::OwnershipTable, processes, refresh,
    scope::ProcessScope,
};
use events::{EventSink, MonitorEvent};
use gauge::{GaugeConfig, GaugeOverrides};
use packets::{PacketBatch, PacketRing, PacketRow};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;
use target::{Matcher, ProcessSelector, TargetSpec};

/// Parameters for [`MonitorState::start`], sent by the UI (or built from an
/// agent's `start_monitoring` call plus the window's [`SessionDefaults`]).
#[derive(Debug, Clone, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct StartRequest {
    pub target: TargetSpec,
    /// Capture device name. `None`: host mode picks the route's interface,
    /// process mode captures on every active interface.
    #[serde(default)]
    pub interface: Option<String>,
    /// Detector tuning; missing fields use defaults.
    #[serde(default)]
    pub gauge: Option<GaugeOverrides>,
    /// Sample period in milliseconds (clamped to 50..=2000, default 250).
    #[serde(default)]
    pub tick_ms: Option<u64>,
    /// Endpoint naming (process mode); missing fields use defaults.
    #[serde(default)]
    pub naming: NamingOptions,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase", default)]
pub struct NamingOptions {
    /// Read DNS answers and TLS server names from the wire.
    pub sniff: bool,
    /// Look up PTR records for unnamed endpoints (queries your DNS server).
    pub reverse_dns: bool,
}

impl Default for NamingOptions {
    fn default() -> Self {
        NamingOptions {
            sniff: true,
            reverse_dns: true,
        }
    }
}

/// What the window would send with a start: its Settings (sensitivity,
/// reverse DNS). Kept here so a session an agent starts measures the same
/// way as one started with the button.
#[derive(Debug, Clone, Default, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase", default)]
pub struct SessionDefaults {
    pub gauge: Option<GaugeOverrides>,
    pub naming: NamingOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct NamingInfo {
    /// Interfaces with a naming capture running.
    pub sniffers: usize,
    pub reverse_dns: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub enum Mode {
    Host,
    Process,
    All,
}

impl Mode {
    /// The wire / database spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Host => "host",
            Mode::Process => "process",
            Mode::All => "all",
        }
    }

    pub fn parse(s: &str) -> Option<Mode> {
        match s {
            "host" => Some(Mode::Host),
            "process" => Some(Mode::Process),
            "all" => Some(Mode::All),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct CaptureInterface {
    pub name: String,
    pub description: String,
    /// pcap data-link type (1 = Ethernet, 0 = loopback, …).
    pub link_type: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub enum AttributionMethod {
    /// Socket-table polling only.
    SocketTable,
    /// Socket table + kernel ETW events.
    Etw,
}

#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Attribution {
    pub method: AttributionMethod,
    pub elevated: bool,
    /// Why ETW isn't active, if it isn't.
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct ProcessSessionInfo {
    pub selector: ProcessSelector,
    /// PIDs matched when the session started.
    pub pids: Vec<u32>,
    pub exe_path: Option<String>,
}

/// Describes the running session.
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    pub session_id: u64,
    pub mode: Mode,
    /// Short display name: an IP, `chrome.exe` or `PID 1234`.
    pub label: String,
    /// Host mode: the monitored address.
    pub target: Option<IpAddr>,
    /// Host mode: the host name it was resolved from, if any.
    pub resolved_from: Option<String>,
    pub process: Option<ProcessSessionInfo>,
    pub attribution: Option<Attribution>,
    /// Endpoint naming (process and all-traffic modes).
    pub naming: Option<NamingInfo>,
    pub interfaces: Vec<CaptureInterface>,
    pub filter: String,
    pub tick_ms: u64,
    pub gauge: GaugeConfig,
}

struct Running {
    info: SessionInfo,
    stop: Arc<AtomicBool>,
    handle: JoinHandle<()>,
    recording: Arc<RecordingSlot>,
    names: Option<Arc<NameBook>>,
    geo: Arc<Geo>,
    packets: Arc<PacketRing>,
    /// PID → program names (all-traffic mode), for the packet list.
    machine: Option<Arc<MachineScope>>,
    /// Latest sample and recent history, for readers other than the UI (MCP).
    live: Arc<live::Live>,
}

/// A temporary claim on the packet feed (see [`MonitorState::hold_packet_feed`]).
pub struct FeedHold(Arc<PacketRing>);

impl Drop for FeedHold {
    fn drop(&mut self) {
        self.0.release();
    }
}

/// Tauri-managed state holding the (at most one) active session.
#[derive(Default)]
pub struct MonitorState {
    running: Mutex<Option<Running>>,
    next_id: AtomicU64,
    /// The window's event subscription (see [`EventSink`]).
    sink: Arc<EventSink>,
    defaults: Mutex<SessionDefaults>,
}

pub const DEFAULT_TICK_MS: u64 = 250;

impl MonitorState {
    /// The window subscribes to monitor events once, when it mounts. If a
    /// session is running (started by an agent, or before a webview reload),
    /// it gets `started` at once so it can show it.
    pub fn subscribe(&self, deliver: impl Fn(MonitorEvent) -> bool + Send + Sync + 'static) {
        self.sink.set(deliver);
        if let Some(info) = self.status() {
            self.sink.send(MonitorEvent::Started {
                session: Box::new(info),
            });
        }
    }

    /// Remember the window's start settings for sessions agents start.
    pub fn set_defaults(&self, d: SessionDefaults) {
        *self.defaults.lock().unwrap_or_else(|e| e.into_inner()) = d;
    }

    pub fn defaults(&self) -> SessionDefaults {
        self.defaults
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Stop any running session, open the capture(s) and start streaming
    /// events to the subscribed window.
    ///
    /// Blocking (DNS, device enumeration): call from a worker thread.
    pub fn start(&self, req: StartRequest, geo: Arc<Geo>) -> AppResult<SessionInfo> {
        crate::npcap::ensure_available()?;
        self.stop();

        let session_id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let tick_ms = req.tick_ms.unwrap_or(DEFAULT_TICK_MS).clamp(50, 2000);
        let gauge = req
            .gauge
            .unwrap_or_default()
            .apply(GaugeConfig::default())
            .sanitized();
        let interface = req.interface.as_deref().filter(|s| !s.is_empty());

        let prepared = match &req.target {
            TargetSpec::Host { address } => prepare_host(address, interface)?,
            TargetSpec::Process { selector } => {
                prepare_process(selector, interface, session_id, req.naming)?
            }
            TargetSpec::All => prepare_all(interface, session_id, req.naming)?,
        };

        let info = SessionInfo {
            session_id,
            mode: prepared.mode,
            label: prepared.label,
            target: prepared.target,
            resolved_from: prepared.resolved_from,
            process: prepared.process_info,
            attribution: prepared.attribution,
            naming: prepared.naming.as_ref().map(|n| NamingInfo {
                sniffers: n.captures.len(),
                reverse_dns: n.resolver.is_some(),
            }),
            interfaces: prepared
                .captures
                .iter()
                .map(|c| CaptureInterface {
                    name: c.device_name.clone(),
                    description: c.device_description.clone(),
                    link_type: c.link_type,
                })
                .collect(),
            filter: prepared.filter,
            tick_ms,
            gauge,
        };
        self.sink.send(MonitorEvent::Started {
            session: Box::new(info.clone()),
        });

        let recording = Arc::new(RecordingSlot::default());

        let names = prepared.naming.as_ref().map(|n| n.book.clone());
        let packets = Arc::new(PacketRing::default());
        let live = Arc::new(live::Live::default());
        let machine = prepared.machine.as_ref().map(|m| m.scope.clone());

        let stop = Arc::new(AtomicBool::new(false));
        let plan = engine::SessionPlan {
            session_id,
            matcher: prepared.matcher,
            process: prepared.runtime,
            machine: prepared.machine,
            naming: prepared.naming,
            packets: packets.clone(),
            local: prepared.local,
            live: live.clone(),
            recording: recording.clone(),
            geo: geo.clone(),
            captures: prepared.captures,
            gauge,
            tick: Duration::from_millis(tick_ms),
            stop: stop.clone(),
            sink: self.sink.clone(),
        };
        let handle = std::thread::Builder::new()
            .name(format!("fishe-session-{session_id}"))
            .spawn(move || engine::run(plan))
            .map_err(|e| AppError::Internal(format!("failed to spawn session thread: {e}")))?;

        log::info!(
            "session {session_id}: monitoring {} on {} interface(s)",
            info.label,
            info.interfaces.len()
        );
        let previous = self.lock().replace(Running {
            info: info.clone(),
            stop,
            handle,
            recording,
            names,
            geo,
            packets,
            machine,
            live,
        });
        if let Some(prev) = previous {
            // Another start raced us between `stop()` above and here (a double
            // click, or the window and an agent together): end that session
            // properly instead of leaving its thread capturing unreachably.
            log::warn!(
                "session {}: replaced by session {session_id} while starting",
                prev.info.session_id
            );
            prev.stop.store(true, Ordering::Relaxed);
            let _ = prev.handle.join();
        }
        Ok(info)
    }

    /// Stop the running session, if any. Returns whether one was running.
    pub fn stop(&self) -> bool {
        let Some(running) = self.lock().take() else {
            return false;
        };
        running.stop.store(true, Ordering::Relaxed);
        // Returns within about one read timeout (~50 ms) plus worker joins.
        let _ = running.handle.join();
        log::info!("session {}: stopped", running.info.session_id);
        true
    }

    /// Start recording the running session into the archive.
    pub fn start_recording(
        &self,
        archive: &ArchiveState,
        opts: RecordOptions,
    ) -> AppResult<RecordingInfo> {
        // Make sure the archive opens (and old interrupted recordings are closed) first.
        drop(archive.conn()?);
        // Take what the recording needs and release the lock: opening the
        // database and files can take seconds, during which the UI and agents
        // still ask for status and packets.
        let (slot, info, names, geo) = {
            let guard = self.lock();
            let running = guard
                .as_ref()
                .filter(|r| !r.handle.is_finished())
                .ok_or_else(|| {
                    AppError::InvalidState("start monitoring before recording".into())
                })?;
            (
                running.recording.clone(),
                running.info.clone(),
                running.names.clone(),
                running.geo.clone(),
            )
        };
        let rec = slot.start(
            &archive.db_path(),
            &archive.captures_dir(),
            &info,
            names,
            Some(geo),
            opts,
        )?;
        self.sink.send(MonitorEvent::RecordingStarted {
            session_id: info.session_id,
            recording: rec.clone(),
        });
        Ok(rec)
    }

    /// Stop the active recording (the session keeps running). `None` when
    /// nothing was recording.
    pub fn stop_recording(&self) -> Option<RecordingInfo> {
        let (slot, session_id) = self
            .lock()
            .as_ref()
            .map(|r| (r.recording.clone(), r.info.session_id))?;
        let done = slot.finish()?;
        let rec = done.info.clone();
        self.sink.recording_ended(session_id, done);
        Some(rec)
    }

    /// Turn the live packet list on or off. Returns whether a session runs.
    pub fn set_packet_feed(&self, enabled: bool) -> bool {
        match self.lock().as_ref() {
            Some(r) => {
                r.packets.set_enabled(enabled);
                true
            }
            None => false,
        }
    }

    /// Packets newer than `after`, with program and endpoint names resolved.
    pub fn recent_packets(&self, after: Option<u64>, limit: usize) -> PacketBatch {
        let (packets, names, machine) = match self.lock().as_ref() {
            Some(r) => (r.packets.clone(), r.names.clone(), r.machine.clone()),
            None => {
                return PacketBatch {
                    rows: Vec::new(),
                    next_seq: 0,
                    enabled: false,
                };
            }
        };
        let (items, next_seq) = packets.since(after, limit.clamp(1, packets::RING_CAP));
        let rows = items
            .into_iter()
            .map(|(seq, p)| {
                let remote = match p.dir {
                    stats::Direction::In => p.info.src,
                    stats::Direction::Out => p.info.dst,
                };
                PacketRow {
                    seq,
                    ts_us: p.ts_us,
                    iface: p.iface,
                    dir: p.dir,
                    src: p.info.src,
                    dst: p.info.dst,
                    transport: p.info.transport,
                    src_port: p.info.src_port,
                    dst_port: p.info.dst_port,
                    len: p.wire_len,
                    ttl: p.info.ttl,
                    pid: p.pid,
                    program: match (&machine, p.pid) {
                        (Some(m), Some(pid)) => m.name(pid).or_else(|| Some(format!("PID {pid}"))),
                        _ => None,
                    },
                    remote_name: names.as_ref().and_then(|n| n.best(remote)).map(|(n, _)| n),
                }
            })
            .collect();
        PacketBatch {
            rows,
            next_seq,
            enabled: packets.enabled(),
        }
    }

    /// The running session with its latest sample.
    pub fn latest(&self) -> Option<(SessionInfo, Option<events::Sample>)> {
        let guard = self.lock();
        let r = guard.as_ref().filter(|r| !r.handle.is_finished())?;
        Some((r.info.clone(), r.live.latest()))
    }

    /// The last `secs` seconds of the running session (compact points).
    pub fn history(&self, secs: u64) -> Vec<live::HistoryPoint> {
        self.lock()
            .as_ref()
            .map(|r| r.live.history(secs))
            .unwrap_or_default()
    }

    /// Whether the packet feed is on (so a temporary reader knows to wait for it to fill).
    pub fn packet_feed_enabled(&self) -> bool {
        self.lock().as_ref().is_some_and(|r| r.packets.enabled())
    }

    /// Keep the packet feed on while the returned guard lives, without
    /// touching the window's own switch. `None` when no session runs.
    pub fn hold_packet_feed(&self) -> Option<FeedHold> {
        let ring = self.lock().as_ref().map(|r| r.packets.clone())?;
        ring.hold();
        Some(FeedHold(ring))
    }

    /// The active session, or `None` if idle or the thread has exited.
    pub fn status(&self) -> Option<SessionInfo> {
        let mut guard = self.lock();
        if guard.as_ref().is_some_and(|r| r.handle.is_finished()) {
            *guard = None;
        }
        guard.as_ref().map(|r| r.info.clone())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Running>> {
        // A poisoned lock only means a previous holder panicked; the data is still usable.
        self.running.lock().unwrap_or_else(|e| e.into_inner())
    }
}

struct Prepared {
    mode: Mode,
    label: String,
    target: Option<IpAddr>,
    resolved_from: Option<String>,
    process_info: Option<ProcessSessionInfo>,
    attribution: Option<Attribution>,
    filter: String,
    matcher: Matcher,
    runtime: Option<engine::ProcessRuntime>,
    machine: Option<engine::MachineRuntime>,
    naming: Option<engine::NamingRuntime>,
    captures: Vec<OpenCapture>,
    /// Every address of this host.
    local: Arc<HashSet<IpAddr>>,
}

fn prepare_host(address: &str, interface: Option<&str>) -> AppResult<Prepared> {
    let resolved = resolve::resolve(address)?;
    let target = resolved.ip;
    let devices = interfaces::list_devices()?;
    let device = match interface {
        Some(name) => interfaces::find_device(name)?,
        None => interfaces::pick_for(target, &devices)
            .ok_or_else(|| AppError::NoRoute(target.to_string()))?,
    };
    let filter = format!("host {target}");
    let capture = capture::open(device, &filter, false)?;
    Ok(Prepared {
        mode: Mode::Host,
        label: target.to_string(),
        target: Some(target),
        resolved_from: resolved.from_hostname.then(|| resolved.input.clone()),
        process_info: None,
        attribution: None,
        filter,
        matcher: Matcher::Host(target),
        runtime: None,
        machine: None,
        naming: None,
        captures: vec![capture],
        local: Arc::new(local_addresses(&devices)),
    })
}

/// BPF for process mode: only TCP/UDP can be attributed to a process.
const PROCESS_FILTER: &str = "tcp or udp";

fn prepare_process(
    selector: &ProcessSelector,
    interface: Option<&str>,
    session_id: u64,
    naming: NamingOptions,
) -> AppResult<Prepared> {
    // Validate the selector against the live process list.
    let list = processes::list()?;
    let (label, first_pid) = match selector {
        ProcessSelector::Name { name } => {
            let name = name.trim();
            if name.is_empty() {
                return Err(AppError::InvalidTarget(String::new()));
            }
            let first = list
                .iter()
                .find(|p| p.name.eq_ignore_ascii_case(name))
                .map(|p| p.pid);
            (name.to_string(), first)
        }
        ProcessSelector::Pid { pid } => {
            let p = list
                .iter()
                .find(|p| p.pid == *pid)
                .ok_or_else(|| AppError::ProcessNotFound(format!("PID {pid}")))?;
            (format!("{} (PID {pid})", p.name), Some(*pid))
        }
    };

    let devices = interfaces::list_devices()?;
    let local = Arc::new(local_addresses(&devices));
    // Interfaces: the chosen one, or every active adapter plus loopback.
    let chosen: Vec<pcap::Device> = match interface {
        Some(name) => vec![interfaces::find_device(name)?],
        None => interfaces::active_devices(&devices),
    };
    let (captures, naming_devices) = open_all(chosen, PROCESS_FILTER, naming)?;

    // Attribution: socket table always, ETW when elevated.
    let scope = Arc::new(ProcessScope::new(
        selector.clone(),
        Arc::new(OwnershipTable::new()),
        local.clone(),
    ));
    scope.update_pids(&list);
    refresh::refresh_process(&scope, false);
    let (etw, attribution) = start_etw(scope.clone(), session_id);
    let naming_runtime = naming_runtime(naming_devices, naming);

    Ok(Prepared {
        mode: Mode::Process,
        label,
        target: None,
        resolved_from: None,
        process_info: Some(ProcessSessionInfo {
            selector: selector.clone(),
            pids: scope.selected_pids(),
            exe_path: first_pid.and_then(processes::exe_path),
        }),
        attribution: Some(attribution),
        filter: PROCESS_FILTER.into(),
        matcher: Matcher::Process(scope.clone()),
        runtime: Some(engine::ProcessRuntime { scope, _etw: etw }),
        machine: None,
        naming: naming_runtime,
        captures,
        local,
    })
}

/// BPF for all-traffic mode: every IP packet (ARP and other non-IP frames
/// carry no endpoint and are left out).
const ALL_FILTER: &str = "ip or ip6";

fn prepare_all(
    interface: Option<&str>,
    session_id: u64,
    naming: NamingOptions,
) -> AppResult<Prepared> {
    let devices = interfaces::list_devices()?;
    let local = Arc::new(local_addresses(&devices));
    // Network adapters only: loopback traffic never leaves the machine and
    // would double-count local proxies. Pick the loopback adapter explicitly
    // to watch it.
    let chosen: Vec<pcap::Device> = match interface {
        Some(name) => vec![interfaces::find_device(name)?],
        None => interfaces::active_devices(&devices)
            .into_iter()
            .filter(|d| !interfaces::is_loopback(d))
            .collect(),
    };
    let (captures, naming_devices) = open_all(chosen, ALL_FILTER, naming)?;

    let scope = Arc::new(MachineScope::new(
        Arc::new(OwnershipTable::new()),
        local.clone(),
    ));
    let mut last_names = None;
    refresh::refresh_machine(&scope, &[], true, &mut last_names);
    let (etw, attribution) = start_etw(scope.clone(), session_id);
    let naming_runtime = naming_runtime(naming_devices, naming);

    Ok(Prepared {
        mode: Mode::All,
        label: "All traffic".into(),
        target: None,
        resolved_from: None,
        process_info: None,
        attribution: Some(attribution),
        filter: ALL_FILTER.into(),
        matcher: Matcher::All(scope.clone()),
        runtime: None,
        machine: Some(engine::MachineRuntime { scope, _etw: etw }),
        naming: naming_runtime,
        captures,
        local,
    })
}

/// Every address of this host: all adapters plus loopback.
fn local_addresses(devices: &[pcap::Device]) -> HashSet<IpAddr> {
    devices
        .iter()
        .flat_map(|d| d.addresses.iter().map(|a| a.addr))
        .chain([
            IpAddr::from([127, 0, 0, 1]),
            IpAddr::from(std::net::Ipv6Addr::LOCALHOST),
        ])
        .collect()
}

/// Open a measuring capture on each device (skipping the ones that fail, as
/// long as one opens). Also returns the devices to run naming captures on.
fn open_all(
    chosen: Vec<pcap::Device>,
    filter: &str,
    naming: NamingOptions,
) -> AppResult<(Vec<OpenCapture>, Vec<pcap::Device>)> {
    if chosen.is_empty() {
        return Err(AppError::NoRoute("any active interface".into()));
    }
    let naming_devices: Vec<pcap::Device> = if naming.sniff {
        chosen.clone()
    } else {
        Vec::new()
    };
    let multi = chosen.len() > 1;
    let mut captures = Vec::new();
    let mut last_err = None;
    for device in chosen {
        let desc = device.desc.clone().unwrap_or_else(|| device.name.clone());
        match capture::open(device, filter, multi) {
            Ok(c) => captures.push(c),
            Err(e) => {
                log::warn!("skipping interface {desc}: {e}");
                last_err = Some(e);
            }
        }
    }
    if captures.is_empty() {
        return Err(last_err.unwrap_or_else(|| AppError::NoRoute("any active interface".into())));
    }
    Ok((captures, naming_devices))
}

/// Start ETW when elevated, and describe the attribution method in use.
fn start_etw(sink: Arc<dyn EtwSink>, session_id: u64) -> (Option<EtwTracker>, Attribution) {
    let elevated = elevation::is_elevated();
    let (etw, note) = if !cfg!(windows) {
        // No event source like ETW here: the socket table is all there is,
        // and on Linux it only shows other users' programs to root.
        let note = if elevated {
            "Programs are matched to their sockets on every tick; a connection shorter than a tick can be missed."
        } else {
            "Without root, only programs running as your user can be matched to their traffic."
        };
        (None, Some(note.to_string()))
    } else if elevated {
        let name = format!("Fishe-{}-{session_id}", std::process::id());
        match etw::start(sink, name) {
            Ok(t) => (Some(t), None),
            Err(e) => {
                log::warn!("ETW unavailable: {e}");
                (None, Some(format!("ETW could not start: {e}")))
            }
        }
    } else {
        (
            None,
            Some(
                "Run Fishe as administrator to also catch very short-lived connections (ETW)."
                    .into(),
            ),
        )
    };
    let attribution = Attribution {
        method: if etw.is_some() {
            AttributionMethod::Etw
        } else {
            AttributionMethod::SocketTable
        },
        elevated,
        note,
    };
    (etw, attribution)
}

/// Naming captures (payload, small filter). Failures only lose names.
fn naming_runtime(
    devices: Vec<pcap::Device>,
    naming: NamingOptions,
) -> Option<engine::NamingRuntime> {
    (naming.sniff || naming.reverse_dns).then(|| {
        let book = Arc::new(NameBook::new());
        let local = Arc::new(local_addresses(&devices));
        let captures: Vec<OpenCapture> = devices
            .into_iter()
            .filter_map(|d| {
                let desc = d.desc.clone().unwrap_or_else(|| d.name.clone());
                capture::open_with(d, sniffer::FILTER, sniffer::SNAPLEN, sniffer::BUFFER_BYTES)
                    .map_err(|e| log::warn!("no naming capture on {desc}: {e}"))
                    .ok()
            })
            .collect();
        let resolver = naming.reverse_dns.then(|| Resolver::new(book.clone()));
        engine::NamingRuntime {
            book,
            captures,
            local,
            resolver,
        }
    })
}

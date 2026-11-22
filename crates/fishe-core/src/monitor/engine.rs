//! Capture workers and the aggregator.
//!
//! ```text
//!  interface 1 ─▶ worker ─┐  Tally every 50 ms
//!  interface 2 ─▶ worker ─┼──────────────────▶ aggregator ── every tick ──▶ EventSink ─▶ UI
//!  interface N ─▶ worker ─┘                     │  BusyDetector
//!                                               │  (process / all-traffic mode)
//!                                               │  socket-table poll, PID refresh,
//!                                               │  ETW tracker, endpoint/program books
//! ```
//!
//! - **Workers** (one OS thread per interface) read packets, parse, classify
//!   them with the shared [`Matcher`], and count into a local [`Tally`].
//!   Packets whose owner isn't known yet are held up to [`PENDING_MAX_AGE`]
//!   and re-classified whenever the ownership data changes. [`WorkerCore`]
//!   is that logic without the pcap loop around it.
//! - The **aggregator** merges tallies, refreshes process ownership, runs the
//!   busyness detector and emits one [`Sample`] per tick. [`Aggregator`] is
//!   that state machine without the event sink and threads around it.
//!
//! Both are unit-tested with synthetic packets and messages; [`run`] glues
//! them to Npcap, the worker threads and the window's event sink. Read timeouts
//! guarantee every loop wakes at least every
//! [`READ_TIMEOUT_MS`](crate::net::capture::READ_TIMEOUT_MS), so ticks and
//! stop requests are prompt.

use super::endpoints::{EndpointBook, EndpointsTick};
use super::events::{EventSink, MonitorEvent, ProcessTick, Sample, StopReason};
use super::gauge::{BusyDetector, GaugeConfig};
use super::live::Live;
use super::packets::{self, PacketRing, PacketSummary};
use super::programs::{self, ProgramBook, ProgramsTick};
use super::quality::{FlowTracker, SessionQuality};
use super::stats::Tally;
use super::target::{Matcher, Verdict};
use crate::archive::recorder::{Finished, RecordingSlot, TapHandle};
use crate::geo::Geo;
use crate::naming::addr::{self, AddrScope};
use crate::naming::book::NameBook;
use crate::naming::rdns::Resolver;
use crate::naming::sniffer;
use crate::net::capture::OpenCapture;
use crate::net::parse::{self, LinkLayer, PacketInfo, TcpInfo};
use crate::process::etw::EtwTracker;
use crate::process::machine::MachineScope;
use crate::process::refresh::{refresh_machine, refresh_process};
use crate::process::scope::ProcessScope;
use crate::security::audit::Audit;
use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// How often workers hand their tally to the aggregator.
const FLUSH_EVERY: Duration = Duration::from_millis(50);
/// How long an unattributed packet may wait for its owner to appear.
pub const PENDING_MAX_AGE: Duration = Duration::from_secs(2);
/// Bound on held packets per worker.
const PENDING_CAP: usize = 16_384;
/// Number of ports included in each sample.
const TOP_PORTS: usize = 8;
/// Process list refresh period, in ticks (ownership refreshes every tick).
const PID_REFRESH_TICKS: u32 = 4;
/// New reverse-DNS lookups started per tick at most.
const RDNS_PER_TICK: usize = 16;
/// Longest the aggregator sleeps between checks of the stop flag.
const WAIT_SLICE: Duration = Duration::from_millis(50);

// ───────────────────────────── workers ─────────────────────────────

/// What worker threads send the aggregator.
enum WorkerMsg {
    Tally {
        worker: usize,
        tally: Box<Tally>,
        dropped: u32,
        if_dropped: u32,
    },
    Failed {
        worker: usize,
        interface: String,
        error: String,
    },
}

struct Held {
    info: PacketInfo,
    wire_len: u32,
    at: Instant,
    /// Capture timestamp (µs since the Unix epoch).
    ts: u64,
    /// Header bytes + timestamp, kept only while a pcap recording runs.
    copy: Option<(u64, Box<[u8]>)>,
}

fn held_copy(h: &Held) -> (u64, Option<&[u8]>) {
    match &h.copy {
        Some((ts, data)) => (*ts, Some(data)),
        None => (h.ts, None),
    }
}

/// Capture timestamp in microseconds since the Unix epoch.
// `timeval`'s fields are 32-bit on Windows and 64-bit on Linux: the casts are
// needed on one and a no-op on the other.
#[allow(clippy::unnecessary_cast)]
pub(crate) fn ts_us(h: &pcap::PacketHeader) -> u64 {
    (h.ts.tv_sec as i64).max(0) as u64 * 1_000_000 + (h.ts.tv_usec as i64).max(0) as u64
}

/// One worker's packet handling: classify, count, hold and retry.
///
/// Time comes in as an argument so the hold/expiry logic is testable; the
/// pcap loop in [`run_worker`] passes the clock.
struct WorkerCore {
    iface: u32,
    matcher: Matcher,
    tally: Tally,
    tap: TapHandle,
    feed: Arc<PacketRing>,
    batch: VecDeque<PacketSummary>,
    flows: FlowTracker,
    /// Packets waiting for their owner, oldest first.
    held: VecDeque<Held>,
    /// Spare deque for `flush`, so retrying never reallocates.
    scratch: VecDeque<Held>,
    seen_generation: u64,
}

impl WorkerCore {
    fn new(
        iface: u32,
        matcher: Matcher,
        tap: TapHandle,
        feed: Arc<PacketRing>,
        local: Arc<HashSet<IpAddr>>,
    ) -> Self {
        WorkerCore {
            iface,
            seen_generation: matcher.generation(),
            matcher,
            tally: Tally::default(),
            tap,
            feed,
            batch: VecDeque::new(),
            flows: FlowTracker::new(local),
            held: VecDeque::new(),
            scratch: VecDeque::new(),
        }
    }

    /// A captured frame: parse, then [`Self::on_parsed`].
    fn on_packet(&mut self, link: LinkLayer, data: &[u8], wire_len: u32, ts: u64, now: Instant) {
        match parse::parse_tcp(link, data, wire_len) {
            Some((info, tcp)) => self.on_parsed(&info, tcp.as_ref(), wire_len, ts, data, now),
            None => self.tally.unparsed += 1,
        }
    }

    /// A parsed packet: classify it, then count, hold or drop it.
    /// `data` is the captured header bytes, copied only while recording.
    fn on_parsed(
        &mut self,
        info: &PacketInfo,
        tcp: Option<&TcpInfo>,
        wire_len: u32,
        ts: u64,
        data: &[u8],
        now: Instant,
    ) {
        let verdict = self.matcher.classify(info);
        // TCP flows are tracked whatever the verdict, so a handshake is
        // timed even while its owner is unknown.
        if let Some(tcp) = tcp {
            let counted = match verdict {
                Verdict::Skip => Some(false),
                Verdict::Pending => None,
                _ => Some(true),
            };
            self.flows.observe(ts, info, tcp, counted, &mut self.tally);
        }
        match verdict {
            Verdict::Skip => {}
            Verdict::Pending => {
                if self.held.len() >= PENDING_CAP
                    && let Some(old) = self.held.pop_front()
                {
                    self.expire(old);
                }
                self.held.push_back(Held {
                    info: *info,
                    wire_len,
                    at: now,
                    ts,
                    copy: self.tap.active().then(|| (ts, data.into())),
                });
            }
            verdict => {
                let data = self.tap.active().then_some(data);
                self.count(verdict, info, wire_len, ts, data);
            }
        }
    }

    /// Count a packet that matched (`Match` or `Owned`); other verdicts are
    /// ignored. `data` is the captured header bytes, for the pcap tap.
    fn count(
        &mut self,
        verdict: Verdict,
        info: &PacketInfo,
        wire_len: u32,
        ts: u64,
        data: Option<&[u8]>,
    ) {
        let (dir, pid) = match verdict {
            Verdict::Match(dir) => {
                self.tally.record(dir, info, wire_len);
                (dir, None)
            }
            Verdict::Owned(dir, pid) => {
                self.tally.record_owned(dir, info, wire_len, pid);
                (dir, pid)
            }
            Verdict::Skip | Verdict::Pending => return,
        };
        if let Some(data) = data {
            self.tap.send(self.iface, ts, wire_len, data);
        }
        if self.feed.enabled() {
            packets::collect(
                &mut self.batch,
                PacketSummary {
                    ts_us: ts,
                    iface: self.iface,
                    dir,
                    info: *info,
                    wire_len,
                    pid,
                },
            );
        }
    }

    /// A held packet's owner never appeared.
    fn expire(&mut self, h: Held) {
        match self.matcher.unowned(&h.info) {
            Some(verdict) => {
                let (ts, data) = held_copy(&h);
                self.flows.resolve(&h.info, true, &mut self.tally);
                self.count(verdict, &h.info, h.wire_len, ts, data);
            }
            None => self.tally.unattributed += 1,
        }
    }

    /// End of a flush period: re-classify held packets if the ownership
    /// data changed, expire the old ones, publish the packet feed and hand
    /// over this period's tally.
    fn flush(&mut self, now: Instant) -> Tally {
        self.tap.refresh();
        if !self.held.is_empty() {
            let generation = self.matcher.generation();
            let retry = generation != self.seen_generation;
            self.seen_generation = generation;
            std::mem::swap(&mut self.held, &mut self.scratch);
            while let Some(h) = self.scratch.pop_front() {
                if retry {
                    match self.matcher.classify(&h.info) {
                        Verdict::Skip => {
                            self.flows.resolve(&h.info, false, &mut self.tally);
                            continue;
                        }
                        Verdict::Pending => {}
                        verdict => {
                            let (ts, data) = held_copy(&h);
                            self.flows.resolve(&h.info, true, &mut self.tally);
                            self.count(verdict, &h.info, h.wire_len, ts, data);
                            continue;
                        }
                    }
                }
                if now.saturating_duration_since(h.at) > PENDING_MAX_AGE {
                    self.expire(h);
                    continue;
                }
                self.held.push_back(h);
            }
        }
        self.feed.push(&mut self.batch);
        std::mem::take(&mut self.tally)
    }

    /// Packets currently waiting for their owner.
    #[cfg(test)]
    fn pending(&self) -> usize {
        self.held.len()
    }
}

/// Everything a capture worker shares with the session.
struct WorkerEnv {
    matcher: Matcher,
    stop: Arc<AtomicBool>,
    tx: mpsc::Sender<WorkerMsg>,
    tap: TapHandle,
    feed: Arc<PacketRing>,
    local: Arc<HashSet<IpAddr>>,
}

/// The pcap loop around a [`WorkerCore`]: one per interface.
fn run_worker(worker: usize, open: OpenCapture, env: WorkerEnv) {
    let WorkerEnv {
        matcher,
        stop,
        tx,
        tap,
        feed,
        local,
    } = env;
    let OpenCapture {
        mut capture,
        link,
        device_description,
        ..
    } = open;
    let mut core = WorkerCore::new(worker as u32, matcher, tap, feed, local);
    let mut last_flush = Instant::now();

    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }

        let packet = match crate::net::capture::next_packet(&mut capture) {
            Ok(packet) => Some(packet),
            Err(pcap::Error::TimeoutExpired) => None,
            Err(e) => {
                let _ = tx.send(WorkerMsg::Failed {
                    worker,
                    interface: device_description,
                    error: e.to_string(),
                });
                return;
            }
        };
        let now = Instant::now();
        if let Some(p) = packet {
            core.on_packet(link, p.data, p.header.len, ts_us(p.header), now);
        }

        if now - last_flush < FLUSH_EVERY {
            continue;
        }
        last_flush = now;
        let tally = core.flush(now);
        let (dropped, if_dropped) = capture
            .stats()
            .map(|s| (s.dropped, s.if_dropped))
            .unwrap_or((0, 0));
        if tx
            .send(WorkerMsg::Tally {
                worker,
                tally: Box::new(tally),
                dropped,
                if_dropped,
            })
            .is_err()
        {
            return; // aggregator gone
        }
    }
}

// ──────────────────────────── aggregator ───────────────────────────

/// Process-mode runtime owned by the aggregator.
pub struct ProcessRuntime {
    pub scope: Arc<ProcessScope>,
    /// Held only for its lifetime: dropping it stops the ETW trace.
    pub _etw: Option<EtwTracker>,
}

/// All-traffic-mode runtime owned by the aggregator.
pub struct MachineRuntime {
    pub scope: Arc<MachineScope>,
    /// Held only for its lifetime: dropping it stops the ETW trace.
    pub _etw: Option<EtwTracker>,
}

/// Endpoint naming runtime (process and all-traffic modes).
pub struct NamingRuntime {
    pub book: Arc<NameBook>,
    /// One payload capture per interface, read by sniffer threads.
    pub captures: Vec<OpenCapture>,
    /// This machine's addresses on those interfaces.
    pub local: Arc<HashSet<IpAddr>>,
    /// Background PTR lookups; `None` when reverse DNS is disabled.
    pub resolver: Option<Resolver>,
}

/// The per-session state the aggregator owns (everything but the workers).
pub struct Session {
    pub session_id: u64,
    pub process: Option<ProcessRuntime>,
    pub machine: Option<MachineRuntime>,
    /// Names learnt by the sniffers, for endpoint rows.
    pub names: Option<Arc<NameBook>>,
    pub resolver: Option<Resolver>,
    /// Recording state shared with `MonitorState` (start/stop from commands).
    pub recording: Arc<RecordingSlot>,
    /// Latest sample and history for non-UI readers.
    pub live: Arc<Live>,
    /// Owner/country lookups for endpoint rows.
    pub geo: Arc<Geo>,
    /// The security view's facts (all-traffic mode).
    pub audit: Option<Arc<Audit>>,
    pub gauge: GaugeConfig,
    pub tick: Duration,
}

pub struct SessionPlan {
    pub session_id: u64,
    pub matcher: Matcher,
    pub process: Option<ProcessRuntime>,
    pub machine: Option<MachineRuntime>,
    pub naming: Option<NamingRuntime>,
    /// Live packet list, shared with `MonitorState`.
    pub packets: Arc<PacketRing>,
    /// Every address of this host (orients TCP flows for quality analysis).
    pub local: Arc<HashSet<IpAddr>>,
    /// Latest sample and history for non-UI readers.
    pub live: Arc<Live>,
    /// Recording state shared with `MonitorState` (start/stop from commands).
    pub recording: Arc<RecordingSlot>,
    /// Owner/country lookups for endpoint rows.
    pub geo: Arc<Geo>,
    /// The security view's facts, shared with `MonitorState` (all-traffic mode).
    pub audit: Option<Arc<Audit>>,
    pub captures: Vec<OpenCapture>,
    pub gauge: GaugeConfig,
    pub tick: Duration,
    pub stop: Arc<AtomicBool>,
    /// The window's subscription, shared with `MonitorState`.
    pub sink: Arc<EventSink>,
}

/// What the aggregator wants done after one worker message.
#[derive(Debug)]
enum Step {
    Continue,
    /// One interface stopped; the session goes on. Text for the UI.
    Warn(String),
    Stop(StopReason, Option<String>),
}

/// The session's measuring state between worker messages and ticks.
struct Aggregator {
    s: Session,
    endpoints: Option<EndpointBook>,
    program_book: Option<ProgramBook>,
    session_quality: SessionQuality,
    /// Counts since the last tick.
    window: Tally,
    /// Counts since the session started (books aside).
    totals: Tally,
    /// Latest `(dropped, if_dropped)` per worker.
    drops: Vec<(u32, u32)>,
    failed: Vec<bool>,
    detector: BusyDetector,
    started: Instant,
    last_tick: Instant,
    tick_no: u32,
    /// Ticks between row lists sent to the window: about one second's worth.
    rows_every: u32,
    peak_bps: f64,
    owned_sockets: u32,
    machine_sockets: (u32, usize),
    last_names: Option<Instant>,
    /// A recording that ended on its own during the last tick (its writer
    /// gave up), until `run` reports it.
    recording_ended: Option<Finished>,
}

impl Aggregator {
    fn new(s: Session, worker_count: usize, now: Instant) -> Self {
        let mut last_names = None;
        let machine_sockets = s
            .machine
            .as_ref()
            .map(|m| refresh_machine(&m.scope, &[], true, &mut last_names))
            .unwrap_or((0, 0));
        let owned_sockets = s
            .process
            .as_ref()
            .map(|p| refresh_process(&p.scope, true))
            .unwrap_or(0);
        let books = s.process.is_some() || s.machine.is_some();
        Aggregator {
            endpoints: books.then(|| EndpointBook::new(s.gauge)),
            program_book: s.machine.as_ref().map(|_| ProgramBook::new(s.gauge)),
            session_quality: SessionQuality::default(),
            window: Tally::default(),
            totals: Tally::default(),
            drops: vec![(0, 0); worker_count],
            failed: vec![false; worker_count],
            detector: BusyDetector::new(s.gauge),
            started: now,
            last_tick: now,
            tick_no: 0,
            rows_every: (1000 / s.tick.as_millis().max(1)).max(1) as u32,
            peak_bps: 0.0,
            owned_sockets,
            machine_sockets,
            last_names,
            recording_ended: None,
            s,
        }
    }

    fn on_message(&mut self, msg: WorkerMsg) -> Step {
        match msg {
            WorkerMsg::Tally {
                worker,
                tally,
                dropped,
                if_dropped,
            } => {
                // Per interface, before the workers' counts are merged: the
                // security view tells a VPN tunnel from the other interfaces.
                if let Some(audit) = &self.s.audit {
                    audit.note_worker(worker, &tally.endpoints);
                }
                self.window.merge(&tally);
                if let Some(d) = self.drops.get_mut(worker) {
                    *d = (dropped, if_dropped);
                }
                Step::Continue
            }
            WorkerMsg::Failed {
                worker,
                interface,
                error,
            } => {
                if let Some(f) = self.failed.get_mut(worker) {
                    *f = true;
                }
                log::warn!(
                    "session {}: capture on {interface} failed: {error}",
                    self.s.session_id
                );
                if self.failed.iter().all(|&f| f) {
                    Step::Stop(StopReason::Error, Some(error))
                } else {
                    Step::Warn(format!("Stopped capturing on {interface}: {error}"))
                }
            }
        }
    }

    /// How long to wait for the next worker message before checking the
    /// clock and the stop flag again.
    fn wait(&self, now: Instant) -> Duration {
        self.s
            .tick
            .saturating_sub(now.saturating_duration_since(self.last_tick))
            .min(WAIT_SLICE)
    }

    fn due(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_tick) >= self.s.tick
    }

    /// Close the window: refresh ownership, feed the books and the detector,
    /// and build the tick's sample. The recorder and `live` get it in full.
    fn tick(&mut self, now: Instant) -> Sample {
        let elapsed = now.saturating_duration_since(self.last_tick);
        self.last_tick = now;
        self.tick_no = self.tick_no.wrapping_add(1);
        let s = &self.s;

        if let Some(p) = &s.process {
            self.owned_sockets =
                refresh_process(&p.scope, self.tick_no.is_multiple_of(PID_REFRESH_TICKS));
        }

        let secs = elapsed.as_secs_f64();
        let mut w = std::mem::take(&mut self.window);
        // Per-endpoint and per-program counts go to their books, not the session totals.
        let window_endpoints = std::mem::take(&mut w.endpoints);
        let window_programs = std::mem::take(&mut w.programs);
        let window_quality = std::mem::take(&mut w.quality);
        let window_inbound = std::mem::take(&mut w.inbound);
        let window_payload = std::mem::take(&mut w.payload);
        self.totals.merge(&w);
        let t_ms = now.saturating_duration_since(self.started).as_millis() as u64;

        let labels = match &s.machine {
            Some(m) => {
                let seen: Vec<u32> = window_programs.keys().copied().collect();
                self.machine_sockets =
                    refresh_machine(&m.scope, &seen, false, &mut self.last_names);
                programs::labels(&m.scope, window_programs.keys())
            }
            None => Default::default(),
        };
        if let Some(audit) = &s.audit {
            audit.tick(
                t_ms,
                &window_endpoints,
                &window_payload,
                &window_inbound,
                &labels,
            );
        }
        let programs_tick = self.program_book.as_mut().map(|book| {
            book.tick(&window_programs, &window_endpoints, &labels, secs, t_ms);
            ProgramsTick {
                total: book.len(),
                rows: book.rows(),
            }
        });

        let endpoints_tick = match (&mut self.endpoints, &s.names) {
            (Some(book), Some(names)) => {
                book.tick(&window_endpoints, secs, t_ms);
                if s.machine.is_some() {
                    book.note_programs(&window_endpoints, &labels);
                }
                let ips = book.select();
                if let Some(resolver) = &s.resolver {
                    ips.iter()
                        .filter(|ip| {
                            matches!(
                                addr::classify(**ip),
                                AddrScope::Public | AddrScope::Private | AddrScope::Cgnat
                            )
                        })
                        .filter(|ip| resolver.request(**ip))
                        .take(RDNS_PER_TICK)
                        .for_each(drop);
                }
                Some(EndpointsTick {
                    total: book.len(),
                    rows: book.rows(&ips, names, Some(&s.geo), t_ms),
                })
            }
            _ => None,
        };
        let in_bps = w.counters.bytes_in as f64 / secs;
        let out_bps = w.counters.bytes_out as f64 / secs;
        let reading = self.detector.update(in_bps + out_bps, secs);
        self.peak_bps = self.peak_bps.max(in_bps + out_bps);

        let process_tick = match (&s.process, &s.machine) {
            (Some(p), _) => {
                let pids = p.scope.selected_pids();
                Some(ProcessTick {
                    pid_count: pids.len(),
                    pids: pids.into_iter().take(64).collect(),
                    sockets: self.owned_sockets,
                    known_ports: p.scope.ownership.len(),
                })
            }
            (None, Some(m)) => Some(ProcessTick {
                pid_count: self.machine_sockets.1,
                pids: Vec::new(),
                sockets: self.machine_sockets.0,
                known_ports: m.scope.ownership.len(),
            }),
            (None, None) => None,
        };

        let sample = Sample {
            session_id: s.session_id,
            t_ms,
            interval_ms: secs * 1000.0,
            in_bps,
            out_bps,
            in_pps: w.counters.packets_in as f64 / secs,
            out_pps: w.counters.packets_out as f64 / secs,
            smoothed_bps: reading.smoothed_bps,
            baseline_bps: reading.baseline_bps,
            ratio: reading.ratio,
            level: reading.level,
            peak_bps: self.peak_bps,
            totals: self.totals.counters,
            transports: self.totals.transports,
            top_ports: self.totals.top_ports(TOP_PORTS),
            dropped: self.drops.iter().map(|d| u64::from(d.0)).sum(),
            if_dropped: self.drops.iter().map(|d| u64::from(d.1)).sum(),
            unattributed: self.totals.unattributed,
            process: process_tick,
            endpoints: endpoints_tick,
            programs: programs_tick,
            quality: Some(self.session_quality.tick(&window_quality, t_ms)),
            recording: s.recording.status(),
        };
        if let Some(done) = s.recording.tick(&sample, &window_endpoints) {
            self.recording_ended = Some(done);
        }
        s.live.update(&sample);
        sample
    }

    /// The window redraws its tables and map about once a second, so the
    /// row lists (up to 200 rows) go to the window at that pace; the
    /// numbers go every tick.
    fn for_window(&self, mut sample: Sample) -> Sample {
        if !(self.tick_no.wrapping_sub(1)).is_multiple_of(self.rows_every) {
            sample.endpoints = None;
            sample.programs = None;
        }
        sample
    }

    /// End the session: close any recording, stop the ETW traces.
    fn finish(self) -> Option<Finished> {
        let info = self.s.recording.finish();
        drop(self.s.process);
        drop(self.s.machine);
        info
    }
}

/// Run a session until stopped, every worker failed, or the UI went away.
pub fn run(plan: SessionPlan) {
    let SessionPlan {
        session_id,
        matcher,
        process,
        machine,
        naming,
        packets: feed,
        local,
        live,
        recording,
        geo,
        audit,
        captures,
        gauge,
        tick,
        stop,
        sink,
    } = plan;

    let worker_stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<WorkerMsg>();
    let worker_count = captures.len();
    let mut handles: Vec<JoinHandle<()>> = Vec::with_capacity(worker_count);
    for (i, open) in captures.into_iter().enumerate() {
        let env = WorkerEnv {
            matcher: matcher.clone(),
            stop: worker_stop.clone(),
            tx: tx.clone(),
            tap: TapHandle::new(recording.tap()),
            feed: feed.clone(),
            local: local.clone(),
        };
        let spawned = std::thread::Builder::new()
            .name(format!("fishe-capture-{session_id}-{i}"))
            .spawn(move || run_worker(i, open, env));
        match spawned {
            Ok(h) => handles.push(h),
            Err(e) => log::error!("failed to spawn worker {i}: {e}"),
        }
    }
    drop(tx);

    // Naming sniffers (process mode): best-effort, one per interface.
    let (names, resolver) = match naming {
        Some(NamingRuntime {
            book,
            captures,
            local,
            resolver,
        }) => {
            for (i, open) in captures.into_iter().enumerate() {
                let (b, l, s) = (book.clone(), local.clone(), worker_stop.clone());
                let tap = audit
                    .as_ref()
                    .zip(machine.as_ref())
                    .map(|(a, m)| sniffer::AuditTap {
                        audit: a.clone(),
                        machine: m.scope.clone(),
                        interface: open.device_description.clone(),
                        tunnel: crate::security::vpn::tunnel_kind(
                            &open.device_name,
                            &open.device_description,
                        )
                        .is_some(),
                    });
                match std::thread::Builder::new()
                    .name(format!("fishe-naming-{session_id}-{i}"))
                    .spawn(move || sniffer::run(open, b, l, tap, s))
                {
                    Ok(h) => handles.push(h),
                    Err(e) => log::warn!("failed to spawn naming thread {i}: {e}"),
                }
            }
            (Some(book), resolver)
        }
        None => (None, None),
    };

    let mut agg = Aggregator::new(
        Session {
            session_id,
            process,
            machine,
            names,
            resolver,
            recording,
            live,
            geo,
            audit,
            gauge,
            tick,
        },
        worker_count,
        Instant::now(),
    );

    let outcome: (StopReason, Option<String>) = loop {
        if stop.load(Ordering::Relaxed) {
            break (StopReason::UserRequested, None);
        }

        match rx.recv_timeout(agg.wait(Instant::now())) {
            Ok(msg) => match agg.on_message(msg) {
                Step::Continue => {}
                Step::Warn(message) => sink.send(MonitorEvent::Warning {
                    session_id,
                    message,
                }),
                Step::Stop(reason, message) => break (reason, message),
            },
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                break (StopReason::Error, Some("all capture workers exited".into()));
            }
        }

        let now = Instant::now();
        if !agg.due(now) {
            continue;
        }
        let sample = agg.tick(now);
        if let Some(done) = agg.recording_ended.take() {
            sink.recording_ended(session_id, done);
        }
        sink.send(MonitorEvent::Sample(Box::new(agg.for_window(sample))));
    };

    worker_stop.store(true, Ordering::Relaxed);
    for h in handles {
        let _ = h.join();
    }
    if let Some(done) = agg.finish() {
        sink.recording_ended(session_id, done);
    }
    feed.set_enabled(false);
    let (reason, message) = outcome;
    sink.send(MonitorEvent::Stopped {
        session_id,
        reason,
        message,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::recorder::PacketTap;
    use crate::monitor::stats::{Direction, UNATTRIBUTED};
    use crate::monitor::target::ProcessSelector;
    use crate::net::parse::Transport;
    use crate::process::ownership::{DEFAULT_TTL, OwnershipTable};
    use crate::process::processes::ProcessEntry;
    use crate::process::sockets::SocketEntry;
    use std::path::PathBuf;

    const REMOTE: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1));
    const LOCAL: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2));

    fn udp(src: IpAddr, sport: u16, dst: IpAddr, dport: u16) -> PacketInfo {
        PacketInfo {
            src,
            dst,
            transport: Transport::Udp,
            src_port: Some(sport),
            dst_port: Some(dport),
            ttl: 64,
        }
    }

    fn local_set() -> Arc<HashSet<IpAddr>> {
        Arc::new(HashSet::from([LOCAL]))
    }

    fn core(matcher: Matcher) -> WorkerCore {
        WorkerCore::new(
            0,
            matcher,
            TapHandle::new(Arc::new(PacketTap::default())),
            Arc::new(PacketRing::default()),
            local_set(),
        )
    }

    fn feed(core: &mut WorkerCore, info: &PacketInfo, len: u32, now: Instant) {
        core.on_parsed(info, None, len, 0, &[], now);
    }

    fn socket(port: u16, pid: u32) -> SocketEntry {
        SocketEntry {
            transport: Transport::Udp,
            local: std::net::SocketAddr::new(LOCAL, port),
            remote: None,
            pid,
            listening: false,
        }
    }

    fn process(pid: u32, name: &str) -> ProcessEntry {
        ProcessEntry {
            pid,
            parent_pid: 4,
            name: name.into(),
        }
    }

    /// A process scope selecting `foo.exe` (PID 42) on a machine that also
    /// runs PID 7, with no socket ownership known yet.
    fn foo_scope() -> Arc<ProcessScope> {
        let scope = Arc::new(ProcessScope::new(
            ProcessSelector::Name {
                name: "foo.exe".into(),
            },
            Arc::new(OwnershipTable::new()),
            local_set(),
        ));
        scope.update_pids(&[process(42, "foo.exe"), process(7, "bar.exe")]);
        scope
    }

    #[test]
    fn worker_counts_host_traffic_by_direction() {
        let now = Instant::now();
        let mut c = core(Matcher::Host(REMOTE));
        feed(&mut c, &udp(REMOTE, 53, LOCAL, 5000), 100, now);
        feed(&mut c, &udp(LOCAL, 5000, REMOTE, 53), 60, now);
        feed(&mut c, &udp(LOCAL, 5000, [8, 8, 8, 8].into(), 53), 999, now);
        let t = c.flush(now);
        assert_eq!((t.counters.bytes_in, t.counters.packets_in), (100, 1));
        assert_eq!((t.counters.bytes_out, t.counters.packets_out), (60, 1));
        assert_eq!(t.top_ports(1)[0].port, 53);
        assert_eq!(c.pending(), 0);
        // The tally is handed over, not accumulated.
        let t = c.flush(now);
        assert_eq!(t.counters.bytes(), 0);
    }

    #[test]
    fn worker_holds_pending_packets_until_owner_is_known() {
        let now = Instant::now();
        let scope = foo_scope();
        let mut c = core(Matcher::Process(scope.clone()));
        feed(&mut c, &udp(LOCAL, 5000, REMOTE, 443), 100, now);
        feed(&mut c, &udp(REMOTE, 443, LOCAL, 5000), 300, now);
        let t = c.flush(now);
        assert_eq!(t.counters.bytes(), 0, "nothing counted while unowned");
        assert_eq!(c.pending(), 2);

        // The socket table now says port 5000 belongs to foo.exe.
        scope.ownership.refresh(&[socket(5000, 42)], DEFAULT_TTL);
        let t = c.flush(now + Duration::from_millis(50));
        assert_eq!((t.counters.bytes_out, t.counters.bytes_in), (100, 300));
        assert_eq!(c.pending(), 0);
    }

    #[test]
    fn worker_drops_held_packets_owned_by_another_process() {
        let now = Instant::now();
        let scope = foo_scope();
        let mut c = core(Matcher::Process(scope.clone()));
        feed(&mut c, &udp(LOCAL, 6000, REMOTE, 443), 100, now);
        c.flush(now);
        scope.ownership.refresh(&[socket(6000, 7)], DEFAULT_TTL);
        let t = c.flush(now);
        assert_eq!(t.counters.bytes(), 0);
        assert_eq!(
            t.unattributed, 0,
            "a known other owner is not 'unattributed'"
        );
        assert_eq!(c.pending(), 0);
    }

    #[test]
    fn worker_expires_pending_packets_in_process_mode_as_unattributed() {
        let now = Instant::now();
        let mut c = core(Matcher::Process(foo_scope()));
        feed(&mut c, &udp(LOCAL, 6000, REMOTE, 443), 100, now);
        let t = c.flush(now + PENDING_MAX_AGE);
        assert_eq!(c.pending(), 1, "kept until strictly older than the max age");
        assert_eq!(t.unattributed, 0);
        let t = c.flush(now + PENDING_MAX_AGE + Duration::from_millis(1));
        assert_eq!(c.pending(), 0);
        assert_eq!(t.unattributed, 1);
        assert_eq!(t.counters.bytes(), 0);
    }

    #[test]
    fn worker_expires_pending_packets_in_all_traffic_mode_as_unowned() {
        let now = Instant::now();
        let scope = Arc::new(MachineScope::new(
            Arc::new(OwnershipTable::new()),
            local_set(),
        ));
        let mut c = core(Matcher::All(scope));
        feed(&mut c, &udp(LOCAL, 6000, REMOTE, 443), 100, now);
        assert_eq!(c.pending(), 1);
        let t = c.flush(now + PENDING_MAX_AGE + Duration::from_millis(1));
        // Counted (it is this machine's traffic), but under no program.
        assert_eq!((t.counters.bytes_out, t.counters.packets_out), (100, 1));
        assert_eq!(t.unattributed, 1);
        assert_eq!(
            t.programs.get(&UNATTRIBUTED).map(|c| c.bytes_out),
            Some(100)
        );
    }

    #[test]
    fn worker_caps_held_packets_by_expiring_the_oldest() {
        let now = Instant::now();
        let mut c = core(Matcher::Process(foo_scope()));
        for i in 0..=PENDING_CAP {
            feed(
                &mut c,
                &udp(LOCAL, 6000, REMOTE, 443),
                10,
                now + Duration::from_micros(i as u64),
            );
        }
        assert_eq!(c.pending(), PENDING_CAP);
        let t = c.flush(now);
        assert_eq!(t.unattributed, 1);
    }

    // ───────────── aggregator ─────────────

    fn host_session(tick: Duration) -> Session {
        Session {
            session_id: 7,
            process: None,
            machine: None,
            names: None,
            resolver: None,
            recording: Arc::new(RecordingSlot::default()),
            live: Arc::new(Live::default()),
            geo: Arc::new(Geo::new(PathBuf::from("fishe-test-no-geo-db"))),
            audit: None,
            gauge: GaugeConfig::default(),
            tick,
        }
    }

    fn tally_msg(worker: usize, bytes_in: u64, bytes_out: u64, dropped: u32) -> WorkerMsg {
        let mut tally = Tally::default();
        if bytes_in > 0 {
            tally.record(
                Direction::In,
                &udp(REMOTE, 443, LOCAL, 5000),
                bytes_in as u32,
            );
        }
        if bytes_out > 0 {
            tally.record(
                Direction::Out,
                &udp(LOCAL, 5000, REMOTE, 443),
                bytes_out as u32,
            );
        }
        WorkerMsg::Tally {
            worker,
            tally: Box::new(tally),
            dropped,
            if_dropped: 0,
        }
    }

    #[test]
    fn aggregator_rates_totals_and_drops_across_workers() {
        let t0 = Instant::now();
        let tick = Duration::from_millis(500);
        let mut a = Aggregator::new(host_session(tick), 2, t0);
        assert!(!a.due(t0 + Duration::from_millis(499)));
        assert!(a.due(t0 + tick));
        assert!(matches!(
            a.on_message(tally_msg(0, 1000, 0, 3)),
            Step::Continue
        ));
        assert!(matches!(
            a.on_message(tally_msg(1, 0, 500, 2)),
            Step::Continue
        ));

        let s = a.tick(t0 + tick);
        assert_eq!(s.session_id, 7);
        assert_eq!(s.t_ms, 500);
        assert!((s.in_bps - 2000.0).abs() < 1e-6, "{}", s.in_bps);
        assert!((s.out_bps - 1000.0).abs() < 1e-6, "{}", s.out_bps);
        assert_eq!(s.totals.bytes(), 1500);
        assert_eq!(s.dropped, 5);
        assert!(s.process.is_none() && s.endpoints.is_none() && s.programs.is_none());
        assert!(a.s.live.latest().is_some(), "live got the sample");

        // Quiet second tick: rates fall to zero, totals and peak stay.
        let s = a.tick(t0 + 2 * tick);
        assert_eq!(s.in_bps, 0.0);
        assert_eq!(s.totals.bytes(), 1500);
        assert!((s.peak_bps - 3000.0).abs() < 1e-6);
    }

    #[test]
    fn aggregator_warns_on_one_failure_and_stops_on_the_last() {
        let mut a = Aggregator::new(host_session(Duration::from_secs(1)), 2, Instant::now());
        let failed = |worker| WorkerMsg::Failed {
            worker,
            interface: format!("eth{worker}"),
            error: "gone".into(),
        };
        match a.on_message(failed(0)) {
            Step::Warn(m) => assert_eq!(m, "Stopped capturing on eth0: gone"),
            other => panic!("expected a warning, got {other:?}"),
        }
        match a.on_message(failed(1)) {
            Step::Stop(StopReason::Error, Some(m)) => assert_eq!(m, "gone"),
            other => panic!("expected a stop, got {other:?}"),
        }
    }

    #[test]
    fn aggregator_sends_row_lists_about_once_a_second() {
        let t0 = Instant::now();
        let tick = Duration::from_millis(250);
        let mut a = Aggregator::new(host_session(tick), 1, t0);
        // Host mode has no rows of its own; plant some to see them thinned.
        let got: Vec<bool> = (1..=8)
            .map(|n| {
                let mut s = a.tick(t0 + n * tick);
                s.endpoints = Some(EndpointsTick {
                    total: 0,
                    rows: Vec::new(),
                });
                a.for_window(s).endpoints.is_some()
            })
            .collect();
        assert_eq!(
            got,
            [true, false, false, false, true, false, false, false],
            "rows on ticks 1 and 5 at 250 ms"
        );
    }

    #[test]
    fn aggregator_wait_never_exceeds_the_slice_or_the_tick() {
        let t0 = Instant::now();
        let a = Aggregator::new(host_session(Duration::from_millis(20)), 1, t0);
        assert_eq!(a.wait(t0), Duration::from_millis(20));
        assert_eq!(
            a.wait(t0 + Duration::from_millis(15)),
            Duration::from_millis(5)
        );
        assert_eq!(a.wait(t0 + Duration::from_secs(1)), Duration::ZERO);
        let a = Aggregator::new(host_session(Duration::from_secs(1)), 1, t0);
        assert_eq!(a.wait(t0), WAIT_SLICE);
    }
}

/// Live test against the real Npcap driver. Needs network access, so it is
/// ignored by default: `cargo test -- --ignored live_ --nocapture`.
#[cfg(test)]
mod live_tests {
    use super::*;
    use crate::net::capture::open;
    use crate::net::interfaces;
    #[cfg(any(windows, target_os = "linux"))]
    use crate::process::ownership::OwnershipTable;
    use std::collections::HashSet;
    use std::net::{IpAddr, UdpSocket};

    fn drain(open: &mut OpenCapture, matcher: &Matcher, secs: u64) -> Tally {
        let mut tally = Tally::default();
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
            match crate::net::capture::next_packet(&mut open.capture) {
                Ok(p) => {
                    if let Some(info) = parse::parse(open.link, p.data)
                        && let Verdict::Match(d) = matcher.classify(&info)
                    {
                        tally.record(d, &info, p.header.len);
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {}
                Err(e) => panic!("capture error: {e}"),
            }
        }
        tally
    }

    #[test]
    #[ignore = "requires Npcap and a network connection"]
    fn live_capture_sees_outgoing_udp() {
        crate::npcap::ensure_available().expect("Npcap available");
        let target: IpAddr = [1, 1, 1, 1].into();
        let devices = interfaces::list_devices().unwrap();
        let device =
            interfaces::pick_for(target, &devices).expect("an interface routes to 1.1.1.1");
        println!("capturing on {} ({:?})", device.name, device.desc);
        let mut open = open(device, &format!("host {target}"), false).unwrap();

        let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
        for _ in 0..5 {
            sock.send_to(b"fishe", (target, 9)).unwrap();
        }
        let t = drain(&mut open, &Matcher::Host(target), 2);
        println!("totals: {:?}", t.counters);
        assert!(
            t.counters.packets_out >= 5,
            "expected our 5 datagrams, got {:?}",
            t.counters
        );
        assert_eq!(t.top_ports(1)[0].port, 9);
    }

    /// Process mode end-to-end at the engine level: bind to *this* test
    /// process by PID and check its own UDP datagrams are attributed.
    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    #[ignore = "requires Npcap and a network connection"]
    fn live_process_mode_attributes_own_traffic() {
        use crate::monitor::target::ProcessSelector;
        crate::npcap::ensure_available().expect("Npcap available");
        let target: IpAddr = [1, 1, 1, 1].into();
        let devices = interfaces::list_devices().unwrap();
        let device = interfaces::pick_for(target, &devices).expect("route to 1.1.1.1");
        let local: HashSet<IpAddr> = devices
            .iter()
            .flat_map(|d| d.addresses.iter().map(|a| a.addr))
            .collect();

        let sock = UdpSocket::bind("0.0.0.0:0").unwrap(); // opened before the scope refresh
        let scope = Arc::new(ProcessScope::new(
            ProcessSelector::Pid {
                pid: std::process::id(),
            },
            Arc::new(OwnershipTable::new()),
            Arc::new(local),
        ));
        let owned = refresh_process(&scope, true);
        println!("sockets owned by this test: {owned}");
        let matcher = Matcher::Process(scope);

        let mut open = open(device, "tcp or udp", false).unwrap();
        for _ in 0..5 {
            sock.send_to(b"fishe-process", (target, 9)).unwrap();
        }
        let t = drain(&mut open, &matcher, 2);
        println!("totals: {:?}", t.counters);
        assert!(
            t.counters.packets_out >= 5,
            "expected our 5 datagrams, got {:?}",
            t.counters
        );
    }

    /// All-traffic mode at the engine level: every packet is counted, and
    /// this test's own UDP datagrams are labelled with its PID.
    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    #[ignore = "requires Npcap and a network connection"]
    fn live_all_traffic_labels_programs() {
        use crate::process::machine::MachineScope;
        crate::npcap::ensure_available().expect("Npcap available");
        let target: IpAddr = [1, 1, 1, 1].into();
        let devices = interfaces::list_devices().unwrap();
        let device = interfaces::pick_for(target, &devices).expect("route to 1.1.1.1");
        let local: HashSet<IpAddr> = devices
            .iter()
            .flat_map(|d| d.addresses.iter().map(|a| a.addr))
            .collect();
        let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
        let scope = Arc::new(MachineScope::new(
            Arc::new(OwnershipTable::new()),
            Arc::new(local),
        ));
        let mut last = None;
        let (sockets, pids) = refresh_machine(&scope, &[], true, &mut last);
        println!("socket table: {sockets} sockets, {pids} PIDs");
        let matcher = Matcher::All(scope.clone());

        let mut open = open(device, "ip or ip6", false).unwrap();
        for _ in 0..5 {
            sock.send_to(b"fishe-all", (target, 9)).unwrap();
        }
        let mut tally = Tally::default();
        let (mut pending, mut total) = (0u64, 0u64);
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            match crate::net::capture::next_packet(&mut open.capture) {
                Ok(p) => {
                    let Some(info) = parse::parse(open.link, p.data) else {
                        continue;
                    };
                    total += 1;
                    match matcher.classify(&info) {
                        Verdict::Owned(d, pid) => tally.record_owned(d, &info, p.header.len, pid),
                        Verdict::Pending => pending += 1,
                        v => panic!("all-traffic mode never skips: {v:?}"),
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {}
                Err(e) => panic!("capture error: {e}"),
            }
        }
        let me = std::process::id();
        println!("packets: {total}, pending: {pending}");
        let mut by_pid: Vec<(u32, u64)> = tally
            .programs
            .iter()
            .map(|(pid, c)| (*pid, c.bytes_in + c.bytes_out))
            .collect();
        by_pid.sort_by_key(|p| std::cmp::Reverse(p.1));
        for (pid, bytes) in by_pid.iter().take(10) {
            println!(
                "  {:>6} {:<24} {bytes} B",
                pid,
                scope.name(*pid).unwrap_or_default()
            );
        }
        let mine = tally.programs.get(&me).copied().unwrap_or_default();
        assert!(
            mine.packets_out >= 5,
            "expected our 5 datagrams under PID {me}, got {mine:?}"
        );
        assert_eq!(
            scope
                .name(me)
                .map(|n| n.to_ascii_lowercase().contains("fishe")),
            Some(true)
        );
    }

    /// Connection quality: the TCP handshake and request/response RTTs to
    /// 1.1.1.1:443 measured passively, next to ICMP pings of the same host.
    #[test]
    #[ignore = "requires Npcap and a network connection"]
    fn live_tcp_quality_matches_ping() {
        use crate::monitor::quality::FlowTracker;
        use std::io::{Read, Write};
        use std::net::TcpStream;
        crate::npcap::ensure_available().expect("Npcap available");
        let target: IpAddr = [1, 1, 1, 1].into();
        let devices = interfaces::list_devices().unwrap();
        let device = interfaces::pick_for(target, &devices).expect("route to 1.1.1.1");
        let local: HashSet<IpAddr> = devices
            .iter()
            .flat_map(|d| d.addresses.iter().map(|a| a.addr))
            .collect();
        let mut open = open(device, &format!("host {target} and tcp"), false).unwrap();
        let mut flows = FlowTracker::new(Arc::new(local));

        let client = std::thread::spawn(move || {
            for _ in 0..3 {
                let mut s = TcpStream::connect((target, 443)).unwrap();
                // Not TLS: the server answers with an alert / closes, which
                // still ACKs our bytes.
                let _ = s.write_all(&[0x16, 3, 1, 0, 4, 1, 0, 0, 0]);
                let mut buf = [0u8; 64];
                s.set_read_timeout(Some(Duration::from_millis(800)))
                    .unwrap();
                let _ = s.read(&mut buf);
                std::thread::sleep(Duration::from_millis(200));
            }
        });
        let mut tally = Tally::default();
        let deadline = Instant::now() + Duration::from_secs(4);
        while Instant::now() < deadline {
            match crate::net::capture::next_packet(&mut open.capture) {
                Ok(p) => {
                    if let Some((info, Some(tcp))) =
                        parse::parse_tcp(open.link, p.data, p.header.len)
                    {
                        flows.observe(ts_us(p.header), &info, &tcp, Some(true), &mut tally);
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {}
                Err(e) => panic!("capture error: {e}"),
            }
        }
        client.join().unwrap();
        let pings: Vec<u32> = (0..5)
            .filter_map(|_| crate::route::icmp::probe(target, 128, 1000).ok()?.rtt_ms)
            .collect();
        let rtts: Vec<f64> = tally
            .quality
            .rtt_us
            .iter()
            .map(|&u| f64::from(u) / 1000.0)
            .collect();
        println!("TCP RTT samples (ms): {rtts:?}");
        println!("ICMP RTTs (ms):       {pings:?}");
        println!(
            "data out/in: {} / {} B, retrans out/in: {} / {} B",
            tally.quality.data_out,
            tally.quality.data_in,
            tally.quality.retrans_out,
            tally.quality.retrans_in
        );
        assert!(
            rtts.len() >= 3,
            "a handshake sample per connection at least"
        );
        let min_tcp = rtts.iter().copied().fold(f64::MAX, f64::min);
        if let Some(&min_ping) = pings.iter().min() {
            assert!(
                (min_tcp - f64::from(min_ping)).abs() < 15.0,
                "passive RTT {min_tcp:.1} ms vs ping {min_ping} ms"
            );
        }
    }

    /// Diagnostic: short-lived `curl.exe` processes bound by name, with the
    /// real worker hold/retry logic and the aggregator's refresh cadence.
    /// Prints where every byte to/from the server went.
    #[cfg(windows)]
    #[test]
    #[ignore = "requires Npcap, network and curl.exe"]
    fn live_short_lived_processes_by_name() {
        use crate::monitor::target::ProcessSelector;
        use crate::net::parse::Transport;
        crate::npcap::ensure_available().expect("Npcap available");
        let devices = interfaces::list_devices().unwrap();
        let local: HashSet<IpAddr> = devices
            .iter()
            .flat_map(|d| d.addresses.iter().map(|a| a.addr))
            .collect();
        let scope = Arc::new(ProcessScope::new(
            ProcessSelector::Name {
                name: "curl.exe".into(),
            },
            Arc::new(OwnershipTable::new()),
            Arc::new(local),
        ));
        refresh_process(&scope, true);
        let matcher = Matcher::Process(scope.clone());

        // Same as the app: ETW joins in when elevated.
        let etw = if crate::process::elevation::is_elevated() {
            let name = format!("Fishe-test-{}", std::process::id());
            Some(crate::process::etw::start(scope.clone(), name).expect("ETW session"))
        } else {
            None
        };
        println!(
            "attribution: {}",
            if etw.is_some() {
                "socket table + ETW"
            } else {
                "socket table only"
            }
        );
        std::thread::sleep(Duration::from_millis(300));

        // FISHE_LIVE_BYTES / FISHE_LIVE_RUNS tune how short-lived each curl is.
        let env_num = |k: &str, d: u64| {
            std::env::var(k)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(d)
        };
        let (bytes, runs) = (
            env_num("FISHE_LIVE_BYTES", 2_000_000),
            env_num("FISHE_LIVE_RUNS", 4),
        );

        // Aggregator-like refresher.
        let stop = Arc::new(AtomicBool::new(false));
        let refresher = {
            let (scope, stop) = (scope.clone(), stop.clone());
            std::thread::spawn(move || {
                let mut n = 0u32;
                while !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(250));
                    n += 1;
                    refresh_process(&scope, n.is_multiple_of(PID_REFRESH_TICKS));
                }
            })
        };
        // Traffic: short curl runs.
        let curls = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(500));
            let mut payload = 0u64;
            let url = format!("https://speed.cloudflare.com/__down?bytes={bytes}");
            for _ in 0..runs {
                let out = std::process::Command::new("curl")
                    .args(["-s", "-o", "NUL", "-w", "%{size_download}", &url])
                    .output()
                    .unwrap();
                payload += String::from_utf8_lossy(&out.stdout)
                    .trim()
                    .parse::<u64>()
                    .unwrap_or(0);
                std::thread::sleep(Duration::from_millis(400));
            }
            payload
        });

        let route = devices
            .iter()
            .find(|d| {
                d.addresses
                    .iter()
                    .any(|a| a.addr.is_ipv6() && !a.addr.to_string().starts_with("fe80"))
            })
            .cloned();
        let device = route
            .or_else(|| interfaces::pick_for([1, 1, 1, 1].into(), &devices))
            .unwrap();
        let mut open = open(device, "tcp port 443", false).unwrap();

        let mut tally = Tally::default();
        let mut held: Vec<(PacketInfo, u32, Instant)> = Vec::new();
        let (mut skipped, mut expired) = (0u64, 0u64);
        let mut skip_examples: Vec<String> = Vec::new();
        let mut seen = matcher.generation();
        let deadline = Instant::now() + Duration::from_millis(1500 + runs * 1200);
        while Instant::now() < deadline {
            if let Ok(p) = crate::net::capture::next_packet(&mut open.capture)
                && let Some(info) = parse::parse(open.link, p.data)
            {
                match matcher.classify(&info) {
                    Verdict::Match(d) | Verdict::Owned(d, _) => {
                        tally.record(d, &info, p.header.len)
                    }
                    Verdict::Pending => held.push((info, p.header.len, Instant::now())),
                    Verdict::Skip => {
                        skipped += u64::from(p.header.len);
                        if skip_examples.len() < 6 {
                            let lp = if scope.local.contains(&info.src) {
                                info.src_port
                            } else {
                                info.dst_port
                            };
                            let owner =
                                lp.and_then(|port| scope.ownership.owner(Transport::Tcp, port));
                            skip_examples
                                .push(format!("{info:?} local_port={lp:?} owner={owner:?}"));
                        }
                    }
                }
            }
            let g = matcher.generation();
            let retry = g != seen;
            seen = g;
            let now = Instant::now();
            held.retain(|(info, len, at)| {
                if retry {
                    match matcher.classify(info) {
                        Verdict::Match(d) | Verdict::Owned(d, _) => {
                            tally.record(d, info, *len);
                            return false;
                        }
                        Verdict::Skip => {
                            skipped += u64::from(*len);
                            return false;
                        }
                        Verdict::Pending => {}
                    }
                }
                if now - *at > PENDING_MAX_AGE {
                    expired += u64::from(*len);
                    return false;
                }
                true
            });
        }
        stop.store(true, Ordering::Relaxed);
        refresher.join().unwrap();
        let payload = curls.join().unwrap();
        println!("curl payload: {payload} B");
        println!(
            "attributed:   {} B ({:?})",
            tally.counters.bytes_in + tally.counters.bytes_out,
            tally.counters
        );
        println!(
            "skipped:      {skipped} B, expired pending: {expired} B, still held: {}",
            held.len()
        );
        for e in skip_examples {
            println!("  skip: {e}");
        }
    }
}

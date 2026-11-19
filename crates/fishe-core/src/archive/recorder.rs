//! Recording a running session.
//!
//! [`RecordingSlot`] belongs to a session. While a recording is active the
//! aggregator hands it every sample plus the tick's per-endpoint counts, and
//! a writer thread batches them into SQLite (one transaction per second), so
//! disk I/O never slows the capture. With "packet headers" enabled, capture
//! workers also copy each *counted* packet into a [`PacketTap`], drained by a
//! pcapng writer thread. Both channels are bounded/non-blocking for workers:
//! if the disk can't keep up, packets are dropped from the file (and counted),
//! never from the measurement.
//!
//! What a recording keeps is bounded whatever the traffic looks like: the
//! tick queue, the endpoints (and the ports per endpoint) and the programs
//! all have a cap, because remote addresses are not ours to choose. A write
//! that fails is retried with its rows kept; when the archive stays
//! unwritable the recording ends, is marked interrupted, and the session is
//! told ([`Finished::error`]).

use super::db::{self, RecordingExtra, RecordingProgram};
use super::pcapng::{InterfaceDesc, PcapngWriter};
use crate::error::{AppError, AppResult};
use crate::geo::Geo;
use crate::monitor::SessionInfo;
use crate::monitor::endpoints::EndpointPort;
use crate::monitor::events::Sample;
use crate::monitor::gauge::Level;
use crate::monitor::quality::EndpointQualityAcc;
use crate::monitor::stats::{Counters, EndpointDelta};
use crate::naming::addr;
use crate::naming::book::NameBook;
use crate::net::parse::Transport;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::BufWriter;
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

// ─────────────────────────── packet tap ───────────────────────────

pub struct TapPacket {
    pub iface: u32,
    pub ts_us: u64,
    pub orig_len: u32,
    pub data: Box<[u8]>,
}

pub enum TapMsg {
    Packet(TapPacket),
    Close,
}

/// Where workers copy counted packets while a pcap recording runs.
#[derive(Default)]
pub struct PacketTap {
    generation: AtomicU64,
    sender: Mutex<Option<SyncSender<TapMsg>>>,
    dropped: AtomicU64,
}

impl PacketTap {
    fn set(&self, s: Option<SyncSender<TapMsg>>) {
        *self.sender.lock().unwrap_or_else(|e| e.into_inner()) = s;
        self.generation.fetch_add(1, Ordering::AcqRel);
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// A worker's cached view of the tap (one atomic load per check).
pub struct TapHandle {
    tap: Arc<PacketTap>,
    generation: u64,
    sender: Option<SyncSender<TapMsg>>,
}

impl TapHandle {
    pub fn new(tap: Arc<PacketTap>) -> Self {
        let mut h = TapHandle {
            tap,
            generation: u64::MAX,
            sender: None,
        };
        h.refresh();
        h
    }

    /// Pick up a started/stopped recording. Cheap; call often.
    pub fn refresh(&mut self) {
        let g = self.tap.generation.load(Ordering::Acquire);
        if g != self.generation {
            self.generation = g;
            self.sender = self
                .tap
                .sender
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
        }
    }

    pub fn active(&self) -> bool {
        self.sender.is_some()
    }

    pub fn send(&self, iface: u32, ts_us: u64, orig_len: u32, data: &[u8]) {
        if let Some(s) = &self.sender {
            let p = TapPacket {
                iface,
                ts_us,
                orig_len,
                data: data.into(),
            };
            if s.try_send(TapMsg::Packet(p)).is_err() {
                self.tap.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

// ─────────────────────────── public types ───────────────────────────

#[derive(Debug, Clone, Default, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase", default)]
pub struct RecordOptions {
    /// Display name; defaults to the session label.
    pub name: Option<String>,
    /// Also save the counted packets' headers to a .pcapng file.
    pub pcap: bool,
}

#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct RecordingInfo {
    pub id: i64,
    pub name: String,
    /// Unix ms.
    pub started_at: i64,
    pub pcap_path: Option<String>,
}

/// A recording that ended, by request or on its own.
#[derive(Debug, Clone)]
pub struct Finished {
    pub info: RecordingInfo,
    /// Why the archive holds less than the whole recording, when writing it
    /// failed (the recording is then marked interrupted).
    pub error: Option<String>,
}

/// Live recording status, included in every sample while recording.
#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct RecordingTick {
    pub id: i64,
    pub elapsed_ms: u64,
    pub samples: u64,
    pub pcap_packets: u64,
    pub pcap_dropped: u64,
}

// ─────────────────────────── the slot ───────────────────────────

enum RecMsg {
    Tick {
        sample: Box<Sample>,
        endpoints: HashMap<IpAddr, EndpointDelta>,
    },
    Finish {
        pcap_packets: u64,
        pcap_dropped: u64,
    },
}

#[derive(Default)]
struct RecCounters {
    samples: AtomicU64,
    pcap_packets: AtomicU64,
    /// Ticks the writer had no room for (the disk is slower than the session).
    dropped_ticks: AtomicU64,
    /// Set by the writer thread when it gives up.
    failure: Mutex<Option<String>>,
}

impl RecCounters {
    fn take_failure(&self) -> Option<String> {
        self.failure
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }
}

struct Active {
    info: RecordingInfo,
    tx: SyncSender<RecMsg>,
    writer: JoinHandle<()>,
    pcap: Option<(SyncSender<TapMsg>, JoinHandle<()>)>,
    counters: Arc<RecCounters>,
    started: Instant,
}

/// Per-session recording state (at most one active recording).
#[derive(Default)]
pub struct RecordingSlot {
    inner: Mutex<Option<Active>>,
    tap: Arc<PacketTap>,
}

/// Snap length written into the pcapng interface blocks (matches capture).
const PCAP_SNAPLEN: u32 = 192;
const TAP_QUEUE: usize = 65_536;
/// Ticks that may wait for the writer (two minutes at the default tick).
/// Beyond that the tick is dropped from the recording, never queued.
const TICK_QUEUE: usize = 512;
/// Endpoints one recording keeps a row for. Later ones still count in the
/// totals and the session series. Remote addresses can be forged, so
/// without a cap a flood of them would grow the archive without limit.
const MAX_ENDPOINTS: usize = 20_000;
/// Distinct ports remembered per endpoint (the four busiest are stored).
const MAX_PORTS_PER_ENDPOINT: usize = 32;
const MAX_PROGRAMS: usize = 4096;
/// Failed commits in a row before the recording gives up (each one already
/// waited out SQLite's busy timeout).
const WRITE_ATTEMPTS: u32 = 5;

impl RecordingSlot {
    pub fn tap(&self) -> Arc<PacketTap> {
        self.tap.clone()
    }

    pub fn start(
        &self,
        db_path: &Path,
        captures_dir: &Path,
        session: &SessionInfo,
        names: Option<Arc<NameBook>>,
        geo: Option<Arc<Geo>>,
        opts: RecordOptions,
    ) -> AppResult<RecordingInfo> {
        const BUSY: &str = "a recording is already running";
        if self.lock().is_some() {
            return Err(AppError::Busy(BUSY.into()));
        }
        // Everything up to the install runs without the lock: the aggregator
        // reads this slot every tick, and opening the database can wait
        // seconds on a busy file.
        let conn = db::open(db_path)?;
        let started_at = db::chrono_now_ms();
        let name = opts
            .name
            .map(|n| n.trim().to_string())
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| session.label.clone());
        let mode = session.mode.as_str();
        let session_json = serde_json::to_string(session).unwrap_or_else(|_| "{}".into());
        conn.execute(
            "INSERT INTO recordings (name, mode, label, session_json, started_at, tick_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![name, mode, session.label, session_json, started_at, session.tick_ms as i64],
        )?;
        let id = conn.last_insert_rowid();
        let counters = Arc::new(RecCounters::default());

        // Optional pcapng writer.
        let mut pcap = None;
        let mut pcap_path = None;
        if opts.pcap {
            std::fs::create_dir_all(captures_dir)
                .map_err(|e| AppError::io("cannot create captures folder", e))?;
            let path = captures_dir.join(format!("fishe-{id}-{started_at}.pcapng"));
            let file = std::fs::File::create(&path)
                .map_err(|e| AppError::io(format_args!("cannot create {}", path.display()), e))?;
            let interfaces: Vec<InterfaceDesc> = session
                .interfaces
                .iter()
                .map(|i| InterfaceDesc {
                    link_type: i.link_type as u16,
                    snaplen: PCAP_SNAPLEN,
                    name: i.name.clone(),
                    description: i.description.clone(),
                })
                .collect();
            let writer = PcapngWriter::new(BufWriter::with_capacity(1 << 20, file), &interfaces)
                .map_err(|e| AppError::io("cannot write pcapng", e))?;
            let (tx, rx) = mpsc::sync_channel::<TapMsg>(TAP_QUEUE);
            let c = counters.clone();
            let handle = std::thread::Builder::new()
                .name(format!("fishe-pcap-{id}"))
                .spawn(move || pcap_loop(writer, rx, c))
                .map_err(|e| AppError::Internal(format!("cannot spawn pcap writer: {e}")))?;
            conn.execute(
                "UPDATE recordings SET pcap_path = ?1 WHERE id = ?2",
                params![path.display().to_string(), id],
            )?;
            pcap_path = Some(path.display().to_string());
            pcap = Some((tx, handle));
        }

        let (tx, rx) = mpsc::sync_channel::<RecMsg>(TICK_QUEUE);
        let c = counters.clone();
        let writer = std::thread::Builder::new()
            .name(format!("fishe-recorder-{id}"))
            .spawn(move || {
                if let Err(e) = writer_loop(conn, id, started_at, rx, names, geo, &c) {
                    log::error!("recording {id}: {e}");
                    *c.failure.lock().unwrap_or_else(|e| e.into_inner()) = Some(e.to_string());
                }
            })
            .map_err(|e| AppError::Internal(format!("cannot spawn recorder: {e}")))?;

        let info = RecordingInfo {
            id,
            name,
            started_at,
            pcap_path,
        };
        let active = Active {
            info: info.clone(),
            tx,
            writer,
            pcap,
            counters,
            started: Instant::now(),
        };

        let mut guard = self.lock();
        if guard.is_some() {
            // Lost a race with another start while we were opening files:
            // close what we built (its row stays, finalised and empty).
            drop(guard);
            let _ = Self::close(active, None);
            return Err(AppError::Busy(BUSY.into()));
        }
        if let Some((tap_tx, _)) = &active.pcap {
            self.tap.set(Some(tap_tx.clone()));
        }
        log::info!("recording {id} started ({})", info.name);
        *guard = Some(active);
        Ok(info)
    }

    /// Hand one tick to the writer (no-op when not recording). Returns the
    /// recording when it just ended on its own: the writer gave up on the
    /// archive, and the caller has to tell the session.
    pub fn tick(
        &self,
        sample: &Sample,
        endpoints: &HashMap<IpAddr, EndpointDelta>,
    ) -> Option<Finished> {
        let mut guard = self.lock();
        let a = guard.as_ref()?;
        match a.tx.try_send(RecMsg::Tick {
            sample: Box::new(sample.clone()),
            endpoints: endpoints.clone(),
        }) {
            Ok(()) => None,
            Err(TrySendError::Full(_)) => {
                let n = a.counters.dropped_ticks.fetch_add(1, Ordering::Relaxed) + 1;
                if n == 1 || n.is_multiple_of(240) {
                    log::warn!(
                        "recording {}: the disk is not keeping up, {n} tick(s) left out so far",
                        a.info.id
                    );
                }
                None
            }
            Err(TrySendError::Disconnected(_)) => {
                // The writer thread is gone: end the recording rather than
                // report it as running while nothing is saved.
                let active = guard.take()?;
                drop(guard);
                self.tap.set(None);
                let mut done = Self::close(active, Some(&self.tap));
                done.error
                    .get_or_insert_with(|| "the recording's writer stopped".into());
                Some(done)
            }
        }
    }

    pub fn status(&self) -> Option<RecordingTick> {
        self.lock().as_ref().map(|a| RecordingTick {
            id: a.info.id,
            elapsed_ms: a.started.elapsed().as_millis() as u64,
            samples: a.counters.samples.load(Ordering::Relaxed),
            pcap_packets: a.counters.pcap_packets.load(Ordering::Relaxed),
            pcap_dropped: self.tap.dropped(),
        })
    }

    /// Stop recording and wait until everything is on disk.
    pub fn finish(&self) -> Option<Finished> {
        let active = self.lock().take()?;
        self.tap.set(None);
        Some(Self::close(active, Some(&self.tap)))
    }

    /// Stop the writer threads and wait until everything is on disk. `tap`
    /// is the tap this recording was fed from, for its drop count.
    fn close(active: Active, tap: Option<&PacketTap>) -> Finished {
        if let Some((tx, handle)) = active.pcap {
            let _ = tx.send(TapMsg::Close);
            let _ = handle.join();
        }
        let _ = active.tx.send(RecMsg::Finish {
            pcap_packets: active.counters.pcap_packets.load(Ordering::Relaxed),
            pcap_dropped: tap.map_or(0, PacketTap::dropped),
        });
        let _ = active.writer.join();
        let error = active.counters.take_failure();
        match &error {
            None => log::info!("recording {} finished", active.info.id),
            Some(e) => log::error!("recording {} ended incomplete: {e}", active.info.id),
        }
        Finished {
            info: active.info,
            error,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Active>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn pcap_loop(
    mut w: PcapngWriter<BufWriter<std::fs::File>>,
    rx: Receiver<TapMsg>,
    counters: Arc<RecCounters>,
) {
    while let Ok(TapMsg::Packet(p)) = rx.recv() {
        if let Err(e) = w.write_packet(p.iface, p.ts_us, p.orig_len, &p.data) {
            log::error!("pcapng write failed: {e}");
            break;
        }
        counters.pcap_packets.fetch_add(1, Ordering::Relaxed);
    }
    if let Err(e) = w.finish() {
        log::error!("pcapng flush failed: {e}");
    }
}

// ─────────────────────────── writer thread ───────────────────────────

#[derive(Default)]
struct EndpointAcc {
    totals: Counters,
    first_ms: i64,
    last_ms: i64,
    peak_bps: f64,
    max_level: u8,
    ports: HashMap<(Transport, u16), u64>,
    quality: EndpointQualityAcc,
}

struct OpenEpisode {
    start_ms: i64,
    max_level: Level,
    peak_bps: f64,
    peak_ratio: f64,
}

/// (Short under test, so the give-up path runs in a fraction of a second.)
const COMMIT_EVERY: Duration = Duration::from_millis(if cfg!(test) { 20 } else { 1000 });
const ENDPOINTS_EVERY: Duration = Duration::from_secs(10);
/// Endpoint history resolution: per-endpoint rows are averaged over this
/// long (the session series keeps every tick). Busy all-traffic sessions
/// would otherwise write tens of rows per tick.
const EP_SAMPLE_MS: i64 = 1000;

/// One endpoint's ticks within the current history window.
#[derive(Default)]
struct EpWindow {
    bytes_in: u64,
    bytes_out: u64,
    smoothed: f64,
    baseline: f64,
    ratio: f64,
    level: u8,
}

type SampleRow = (i64, f64, f64, f64, f64, f64, f64, f64, u8, Option<f64>);

/// Per-program totals of a recording, integrated from each tick's rates
/// (rates are exactly bytes / tick length, so the sum is exact).
#[derive(Default)]
struct ProgramAcc {
    name: String,
    bytes_in: f64,
    bytes_out: f64,
    peak_bps: f64,
    endpoints: usize,
}
type EpSampleRow = (String, i64, f64, f64, f64, f64, f64, u8);
/// `(start_ms, end_ms, max_level, peak_bps, peak_ratio)`.
type EpisodeRow = (i64, i64, u8, f64, f64);

/// Rows the accumulator produced since the last flush.
#[derive(Default)]
struct Rows {
    samples: Vec<SampleRow>,
    ep_samples: Vec<EpSampleRow>,
    episodes: Vec<EpisodeRow>,
}

impl Rows {
    fn is_empty(&self) -> bool {
        self.samples.is_empty() && self.ep_samples.is_empty() && self.episodes.is_empty()
    }
}

/// Which endpoint rows a write includes.
#[derive(Clone, Copy, PartialEq)]
enum Endpoints {
    None,
    /// Those that saw traffic since they were last written.
    Touched,
    /// Every one: the last write, so names and owners learned late land too.
    All,
}

/// What a recording accumulates from the ticks: the session series,
/// episodes, per-endpoint and per-program totals, and the endpoint history
/// windows. Pure state, no I/O: [`Sink`] writes what it hands out.
struct Accumulator {
    offset_ms: Option<i64>,
    last_t: i64,
    count: u64,
    totals: Counters,
    peak_bps: f64,
    max_level: Level,
    episode: Option<OpenEpisode>,
    endpoints: HashMap<IpAddr, EndpointAcc>,
    /// Endpoints with traffic since their row was last written.
    touched: HashSet<IpAddr>,
    /// Addresses that arrived after [`MAX_ENDPOINTS`] was reached.
    over_cap: u64,
    /// All-traffic mode: per-program bytes within the recording.
    programs: HashMap<String, ProgramAcc>,
    /// TCP quality over the recording (all counted flows).
    quality: EndpointQualityAcc,
    last_sample: Option<Box<Sample>>,
    /// Rows not yet handed to the sink.
    rows: Rows,
    /// Endpoint ticks not yet rolled up: window start (ms) and per-endpoint sums.
    ep_window: (i64, HashMap<IpAddr, EpWindow>),
}

impl Default for Accumulator {
    fn default() -> Self {
        Accumulator {
            offset_ms: None,
            last_t: 0,
            count: 0,
            totals: Counters::default(),
            peak_bps: 0.0,
            max_level: Level::Idle,
            episode: None,
            endpoints: HashMap::new(),
            touched: HashSet::new(),
            over_cap: 0,
            programs: HashMap::new(),
            quality: EndpointQualityAcc::default(),
            last_sample: None,
            rows: Rows::default(),
            ep_window: (0, HashMap::new()),
        }
    }
}

/// The SQLite side of one recording.
struct Sink {
    conn: Connection,
    id: i64,
    started_at: i64,
}

fn writer_loop(
    conn: Connection,
    id: i64,
    started_at: i64,
    rx: Receiver<RecMsg>,
    names: Option<Arc<NameBook>>,
    geo: Option<Arc<Geo>>,
    counters: &RecCounters,
) -> AppResult<()> {
    let mut sink = Sink {
        conn,
        id,
        started_at,
    };
    let result = write_recording(&mut sink, rx, names.as_deref(), geo.as_deref(), counters);
    if result.is_err() {
        // Leave a row the Archive can show and delete, not one that looks
        // like it is still recording until the next launch.
        if let Err(e) = sink.mark_interrupted() {
            log::error!("recording {id}: cannot mark it interrupted: {e}");
        }
    }
    result
}

fn write_recording(
    sink: &mut Sink,
    rx: Receiver<RecMsg>,
    names: Option<&NameBook>,
    geo: Option<&Geo>,
    counters: &RecCounters,
) -> AppResult<()> {
    let id = sink.id;
    let mut acc = Accumulator::default();
    let mut last_commit = Instant::now();
    let mut last_endpoints = Instant::now();
    let mut pcap_stats = (0u64, 0u64);
    let mut failures = 0u32;

    loop {
        match rx.recv_timeout(COMMIT_EVERY) {
            Ok(RecMsg::Tick { sample, endpoints }) => {
                acc.add(sample, &endpoints);
                counters.samples.store(acc.count, Ordering::Relaxed);
            }
            Ok(RecMsg::Finish {
                pcap_packets,
                pcap_dropped,
            }) => {
                pcap_stats = (pcap_packets, pcap_dropped);
                break;
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if last_commit.elapsed() < COMMIT_EVERY {
            continue;
        }
        let which = if last_endpoints.elapsed() >= ENDPOINTS_EVERY {
            Endpoints::Touched
        } else {
            Endpoints::None
        };
        // A failed write keeps its rows: the next attempt writes them again.
        match sink.write(&mut acc, which, names, geo) {
            Ok(()) => {
                failures = 0;
                if which == Endpoints::Touched {
                    last_endpoints = Instant::now();
                }
            }
            Err(e) => {
                failures += 1;
                if failures >= WRITE_ATTEMPTS {
                    return Err(e);
                }
                log::warn!("recording {id}: write failed ({failures}/{WRITE_ATTEMPTS}): {e}");
            }
        }
        last_commit = Instant::now();
    }

    acc.close_episode();
    acc.close_ep_window();
    let mut attempt = 1;
    while let Err(e) = sink.write(&mut acc, Endpoints::All, names, geo) {
        if attempt >= 3 {
            return Err(e);
        }
        log::warn!("recording {id}: final write failed ({attempt}/3): {e}");
        attempt += 1;
    }
    sink.finalize(&acc, pcap_stats)?;
    Ok(())
}

impl Accumulator {
    fn add(&mut self, sample: Box<Sample>, endpoints: &HashMap<IpAddr, EndpointDelta>) {
        let offset = *self
            .offset_ms
            .get_or_insert(sample.t_ms as i64 - sample.interval_ms.round() as i64);
        let t = (sample.t_ms as i64 - offset).max(0);
        self.last_t = t;
        self.count += 1;
        if let Some(p) = &sample.programs {
            let secs = sample.interval_ms / 1000.0;
            for r in &p.rows {
                if self.programs.len() >= MAX_PROGRAMS && !self.programs.contains_key(&r.key) {
                    continue;
                }
                let acc = self.programs.entry(r.key.clone()).or_default();
                acc.name.clone_from(&r.name);
                acc.bytes_in += r.in_bps * secs;
                acc.bytes_out += r.out_bps * secs;
                acc.peak_bps = acc.peak_bps.max(r.in_bps + r.out_bps);
                acc.endpoints = r.endpoints;
            }
        }
        let total_bps = sample.in_bps + sample.out_bps;
        self.peak_bps = self.peak_bps.max(total_bps);
        self.max_level = self.max_level.max(sample.level);
        self.rows.samples.push((
            t,
            sample.in_bps,
            sample.out_bps,
            sample.in_pps,
            sample.out_pps,
            sample.smoothed_bps,
            sample.baseline_bps,
            sample.ratio,
            sample.level.as_u8(),
            sample.quality.as_ref().and_then(|q| q.rtt_tick_ms),
        ));

        // Busy/spike episodes.
        if sample.level >= Level::Busy {
            let e = self.episode.get_or_insert(OpenEpisode {
                start_ms: t,
                max_level: sample.level,
                peak_bps: 0.0,
                peak_ratio: 0.0,
            });
            e.max_level = e.max_level.max(sample.level);
            e.peak_bps = e.peak_bps.max(total_bps);
            e.peak_ratio = e.peak_ratio.max(sample.ratio);
        } else {
            self.close_episode();
        }

        // Endpoints: exact per-recording totals from the tick's deltas;
        // detector values from the rows the sample carries.
        let secs = (sample.interval_ms / 1000.0).max(1e-3);
        let rows: HashMap<IpAddr, (f64, f64, f64, Level)> = sample
            .endpoints
            .as_ref()
            .map(|e| {
                e.rows
                    .iter()
                    .map(|r| (r.ip, (r.smoothed_bps, r.baseline_bps, r.ratio, r.level)))
                    .collect()
            })
            .unwrap_or_default();
        for (ip, d) in endpoints {
            self.totals.merge(&d.counters);
            if !d.quality.is_empty() {
                self.quality.add(&d.quality);
            }
            if self.endpoints.len() >= MAX_ENDPOINTS && !self.endpoints.contains_key(ip) {
                if self.over_cap == 0 {
                    log::warn!(
                        "recording: more than {MAX_ENDPOINTS} endpoints; further ones count in the totals only"
                    );
                }
                self.over_cap += 1;
                continue;
            }
            let acc = self.endpoints.entry(*ip).or_insert_with(|| EndpointAcc {
                first_ms: t,
                ..Default::default()
            });
            self.touched.insert(*ip);
            acc.totals.merge(&d.counters);
            acc.last_ms = t;
            if !d.quality.is_empty() {
                acc.quality.add(&d.quality);
            }
            for (&k, &b) in &d.ports {
                if let Some(bytes) = acc.ports.get_mut(&k) {
                    *bytes += b;
                } else if acc.ports.len() < MAX_PORTS_PER_ENDPOINT {
                    acc.ports.insert(k, b);
                }
            }
            let (inb, outb) = (
                d.counters.bytes_in as f64 / secs,
                d.counters.bytes_out as f64 / secs,
            );
            acc.peak_bps = acc.peak_bps.max(inb + outb);
            let (smoothed, baseline, ratio, level) =
                rows.get(ip)
                    .copied()
                    .unwrap_or((inb + outb, 0.0, 0.0, Level::Calm));
            acc.max_level = acc.max_level.max(level.as_u8());
            let win = self.ep_window.1.entry(*ip).or_default();
            win.bytes_in += d.counters.bytes_in;
            win.bytes_out += d.counters.bytes_out;
            win.smoothed = smoothed;
            win.baseline = baseline;
            win.ratio = win.ratio.max(ratio);
            win.level = win.level.max(level.as_u8());
        }
        if t - self.ep_window.0 >= EP_SAMPLE_MS {
            self.close_ep_window();
        }
        self.last_sample = Some(sample);
    }

    /// Write one averaged history row per endpoint active in the window.
    fn close_ep_window(&mut self) {
        let t = self.last_t;
        let secs = ((t - self.ep_window.0) as f64 / 1000.0).max(1e-3);
        for (ip, w) in self.ep_window.1.drain() {
            self.rows.ep_samples.push((
                ip.to_string(),
                t,
                w.bytes_in as f64 / secs,
                w.bytes_out as f64 / secs,
                w.smoothed,
                w.baseline,
                w.ratio,
                w.level,
            ));
        }
        self.ep_window.0 = t;
    }

    fn close_episode(&mut self) {
        if let Some(e) = self.episode.take() {
            self.rows.episodes.push((
                e.start_ms,
                self.last_t,
                e.max_level.as_u8(),
                e.peak_bps,
                e.peak_ratio,
            ));
        }
    }

    /// Hand out the rows produced since the last call.
    #[cfg(test)]
    fn take_rows(&mut self) -> Rows {
        std::mem::take(&mut self.rows)
    }

    /// The `n` programs that moved the most bytes during the recording.
    fn program_summary(&self, n: usize) -> Vec<RecordingProgram> {
        let mut v: Vec<(&String, &ProgramAcc)> = self
            .programs
            .iter()
            .filter(|(_, a)| a.bytes_in + a.bytes_out >= 0.5)
            .collect();
        v.sort_by(|a, b| (b.1.bytes_in + b.1.bytes_out).total_cmp(&(a.1.bytes_in + a.1.bytes_out)));
        v.into_iter()
            .take(n)
            .map(|(key, a)| RecordingProgram {
                key: key.clone(),
                name: a.name.clone(),
                bytes_in: a.bytes_in.round() as u64,
                bytes_out: a.bytes_out.round() as u64,
                endpoints: a.endpoints as u64,
                peak_bps: a.peak_bps,
            })
            .collect()
    }

    /// The summary stored with the recording: what the last sample knew
    /// about the whole session, plus the recording's own quality and programs.
    fn extra(&self) -> Option<RecordingExtra> {
        self.last_sample.as_ref().map(|s| RecordingExtra {
            transports: s.transports,
            top_ports: s.top_ports.clone(),
            dropped: s.dropped,
            if_dropped: s.if_dropped,
            unattributed: s.unattributed,
            quality: self.quality.row(),
            programs: s.programs.as_ref().map(|_| self.program_summary(25)),
        })
    }
}

impl Sink {
    /// Write what the accumulator holds and forget it only once it is on
    /// disk, so a failed write can simply be tried again.
    fn write(
        &mut self,
        acc: &mut Accumulator,
        which: Endpoints,
        names: Option<&NameBook>,
        geo: Option<&Geo>,
    ) -> AppResult<()> {
        self.flush(&acc.rows)?;
        acc.rows = Rows::default();
        match which {
            Endpoints::None => {}
            Endpoints::Touched => {
                let rows = acc
                    .touched
                    .iter()
                    .filter_map(|ip| acc.endpoints.get(ip).map(|a| (ip, a)));
                self.write_endpoints(rows, names, geo)?;
                acc.touched.clear();
            }
            Endpoints::All => {
                self.write_endpoints(acc.endpoints.iter(), names, geo)?;
                acc.touched.clear();
            }
        }
        Ok(())
    }

    /// The writer gave up: close the row with what reached the disk.
    fn mark_interrupted(&self) -> AppResult<()> {
        self.conn.execute(
            "UPDATE recordings SET interrupted = 1,
                ended_at = started_at + COALESCE((SELECT MAX(t_ms) FROM samples s WHERE s.recording_id = recordings.id), 0),
                sample_count = (SELECT COUNT(*) FROM samples s WHERE s.recording_id = recordings.id),
                endpoint_count = (SELECT COUNT(*) FROM endpoints e WHERE e.recording_id = recordings.id)
             WHERE id = ?1 AND ended_at IS NULL",
            params![self.id],
        )?;
        Ok(())
    }

    fn flush(&mut self, rows: &Rows) -> AppResult<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let tx = self.conn.transaction()?;
        {
            let mut s = tx.prepare_cached(
                "INSERT OR REPLACE INTO samples (recording_id, t_ms, in_bps, out_bps, in_pps, out_pps,
                    smoothed_bps, baseline_bps, ratio, level, rtt_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            )?;
            for r in &rows.samples {
                s.execute(params![
                    self.id, r.0, r.1, r.2, r.3, r.4, r.5, r.6, r.7, r.8, r.9
                ])?;
            }
            let mut s = tx.prepare_cached(
                "INSERT OR REPLACE INTO endpoint_samples VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            )?;
            for r in &rows.ep_samples {
                s.execute(params![self.id, r.0, r.1, r.2, r.3, r.4, r.5, r.6, r.7])?;
            }
            let mut s = tx.prepare_cached(
                "INSERT OR REPLACE INTO episodes VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            for e in &rows.episodes {
                s.execute(params![self.id, e.0, e.1, e.2, e.3, e.4])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn write_endpoints<'a>(
        &mut self,
        endpoints: impl Iterator<Item = (&'a IpAddr, &'a EndpointAcc)>,
        names: Option<&NameBook>,
        geo: Option<&Geo>,
    ) -> AppResult<()> {
        let mut endpoints = endpoints.peekable();
        if endpoints.peek().is_none() {
            return Ok(());
        }
        let tx = self.conn.transaction()?;
        {
            let mut s = tx.prepare_cached(
                "INSERT OR REPLACE INTO endpoints (recording_id, ip, name, name_source, scope, bytes_in, bytes_out,
                    packets_in, packets_out, first_seen_ms, last_seen_ms, peak_bps, max_level, ports_json,
                    asn, org, country, owner_source, quality_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
            )?;
            for (ip, a) in endpoints {
                let (name, source) = match names.and_then(|n| n.best(*ip)) {
                    Some((n, src)) => (
                        Some(n),
                        serde_json::to_value(src)
                            .ok()
                            .and_then(|v| v.as_str().map(String::from)),
                    ),
                    None => (None, None),
                };
                // What is already known: a recording never sends an address
                // to the online lookup that the window did not ask about.
                let owner = geo.and_then(|g| g.known_owner(*ip));
                let scope = serde_json::to_value(addr::classify(*ip))
                    .ok()
                    .and_then(|v| v.as_str().map(String::from))
                    .unwrap_or_default();
                let mut ports: Vec<EndpointPort> = a
                    .ports
                    .iter()
                    .map(|(&(transport, port), &bytes)| EndpointPort {
                        transport,
                        port,
                        bytes,
                    })
                    .collect();
                ports.sort_unstable_by_key(|p| (std::cmp::Reverse(p.bytes), p.port));
                ports.truncate(4);
                s.execute(params![
                    self.id,
                    ip.to_string(),
                    name,
                    source,
                    scope,
                    a.totals.bytes_in as i64,
                    a.totals.bytes_out as i64,
                    a.totals.packets_in as i64,
                    a.totals.packets_out as i64,
                    a.first_ms,
                    a.last_ms,
                    a.peak_bps,
                    a.max_level,
                    serde_json::to_string(&ports).unwrap_or_else(|_| "[]".into()),
                    owner.as_ref().and_then(|o| o.asn),
                    owner.as_ref().and_then(|o| o.org.clone()),
                    owner.as_ref().and_then(|o| o.country.clone()),
                    owner.as_ref().map(|o| match o.source {
                        crate::geo::OwnerSource::Dbip => "dbip",
                        crate::geo::OwnerSource::Ipinfo => "ipinfo",
                    }),
                    a.quality.row().and_then(|q| serde_json::to_string(&q).ok()),
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Mark the recording complete with its totals and summary.
    fn finalize(
        &self,
        acc: &Accumulator,
        (pcap_packets, pcap_dropped): (u64, u64),
    ) -> AppResult<()> {
        let extra = acc
            .extra()
            .map(|e| serde_json::to_string(&e).unwrap_or_else(|_| "{}".into()));
        self.conn.execute(
            "UPDATE recordings SET ended_at = ?2, sample_count = ?3, bytes_in = ?4, bytes_out = ?5,
                packets_in = ?6, packets_out = ?7, peak_bps = ?8, max_level = ?9, endpoint_count = ?10,
                summary_json = ?11, pcap_packets = ?12, pcap_dropped = ?13
             WHERE id = ?1",
            params![
                self.id,
                db::chrono_now_ms().max(self.started_at + acc.last_t),
                acc.count as i64,
                acc.totals.bytes_in as i64,
                acc.totals.bytes_out as i64,
                acc.totals.packets_in as i64,
                acc.totals.packets_out as i64,
                acc.peak_bps,
                acc.max_level.as_u8(),
                acc.endpoints.len() as i64,
                extra,
                pcap_packets as i64,
                pcap_dropped as i64,
            ],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::endpoints::{EndpointRow, EndpointsTick};
    use crate::monitor::gauge::GaugeConfig;
    use crate::monitor::stats::{Counters, TransportBytes};
    use crate::monitor::target::ProcessSelector;
    use crate::monitor::{CaptureInterface, Mode, ProcessSessionInfo};
    use crate::naming::addr::AddrScope;
    use crate::naming::book::NameSource;

    fn session() -> SessionInfo {
        SessionInfo {
            session_id: 1,
            mode: Mode::Process,
            label: "app.exe".into(),
            target: None,
            resolved_from: None,
            process: Some(ProcessSessionInfo {
                selector: ProcessSelector::Name {
                    name: "app.exe".into(),
                },
                pids: vec![7],
                exe_path: None,
            }),
            attribution: None,
            naming: None,
            interfaces: vec![
                CaptureInterface {
                    name: "eth".into(),
                    description: "Ethernet".into(),
                    link_type: 1,
                },
                CaptureInterface {
                    name: "lo".into(),
                    description: "Loopback".into(),
                    link_type: 0,
                },
            ],
            filter: "tcp or udp".into(),
            tick_ms: 250,
            gauge: GaugeConfig::default(),
        }
    }

    fn sample(t_ms: u64, bps: f64, level: Level, ratio: f64) -> Sample {
        Sample {
            session_id: 1,
            t_ms,
            interval_ms: 250.0,
            in_bps: bps,
            out_bps: 0.0,
            in_pps: 1.0,
            out_pps: 0.0,
            smoothed_bps: bps,
            baseline_bps: 1000.0,
            ratio,
            level,
            peak_bps: bps,
            totals: Counters::default(),
            transports: TransportBytes::default(),
            top_ports: vec![],
            dropped: 0,
            if_dropped: 0,
            unattributed: 0,
            process: None,
            endpoints: Some(EndpointsTick {
                total: 1,
                rows: vec![EndpointRow {
                    ip: [1, 1, 1, 1].into(),
                    name: None,
                    name_source: None,
                    scope: AddrScope::Public,
                    owner: None,
                    hops: None,
                    in_bps: bps,
                    out_bps: 0.0,
                    smoothed_bps: bps,
                    baseline_bps: 1000.0,
                    ratio,
                    level,
                    peak_bps: bps,
                    totals: Counters::default(),
                    top_ports: vec![],
                    first_seen_ms: 0,
                    last_seen_ms: t_ms,
                    programs: vec![],
                    quality: None,
                }],
            }),
            programs: None,
            quality: Some(crate::monitor::quality::QualityTick {
                rtt_tick_ms: Some(20.0),
                ..Default::default()
            }),
            recording: None,
        }
    }

    fn delta(bytes: u64, port: u16) -> EndpointDelta {
        let mut d = EndpointDelta::default();
        d.counters.bytes_in = bytes;
        d.counters.packets_in = 1;
        d.ports.insert((Transport::Tcp, port), bytes);
        if port == 443 {
            d.quality = crate::monitor::quality::QualityDelta {
                rtt_us: vec![20_000],
                data_out: 1000,
                retrans_out: 10,
                data_in: bytes,
                retrans_in: 0,
            };
        }
        d
    }

    /// Four 250 ms ticks (calm, busy, spike, calm) with one public endpoint
    /// throughout and a LAN endpoint on the third tick.
    fn four_ticks(acc: &mut Accumulator) {
        let levels = [
            (Level::Calm, 1.0),
            (Level::Busy, 2.5),
            (Level::Spike, 6.0),
            (Level::Calm, 1.1),
        ];
        for (i, (lvl, ratio)) in levels.iter().enumerate() {
            let t = 10_000 + (i as u64 + 1) * 250;
            let mut eps = HashMap::new();
            eps.insert(
                IpAddr::from([1, 1, 1, 1]),
                delta(1000 * (i as u64 + 1), 443),
            );
            if i == 2 {
                eps.insert(IpAddr::from([192, 168, 1, 5]), delta(10, 53));
            }
            acc.add(
                Box::new(sample(t, 4000.0 * (i as f64 + 1.0), *lvl, *ratio)),
                &eps,
            );
        }
    }

    #[test]
    fn accumulator_series_episodes_and_endpoint_history() {
        let mut acc = Accumulator::default();
        four_ticks(&mut acc);
        acc.close_episode();
        acc.close_ep_window();

        assert_eq!(acc.count, 4);
        assert_eq!(acc.totals.bytes_in, 1000 + 2000 + 3000 + 4000 + 10);
        assert_eq!(acc.max_level, Level::Spike);
        assert_eq!(acc.peak_bps, 16_000.0);

        let rows = acc.take_rows();
        assert!(acc.take_rows().is_empty(), "rows are handed out once");
        let times: Vec<i64> = rows.samples.iter().map(|r| r.0).collect();
        assert_eq!(
            times,
            [250, 500, 750, 1000],
            "relative to the recording start"
        );
        assert_eq!(rows.samples[2].8, Level::Spike.as_u8());
        assert_eq!(rows.samples[0].9, Some(20.0), "per-sample RTT");

        // Busy at 500 ms, spike at 750 ms, closed by the calm tick at 1000 ms.
        assert_eq!(
            rows.episodes,
            [(500, 1000, Level::Spike.as_u8(), 12_000.0, 6.0)]
        );

        // Endpoint history is averaged per second: four ticks → one row each.
        let mut eps = rows.ep_samples.clone();
        eps.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(eps.len(), 2);
        assert_eq!(
            (eps[0].0.as_str(), eps[0].1, eps[0].2),
            ("1.1.1.1", 1000, 10_000.0)
        );
        assert_eq!(eps[0].7, Level::Spike.as_u8());
        assert_eq!((eps[1].0.as_str(), eps[1].2), ("192.168.1.5", 10.0));

        let one = &acc.endpoints[&IpAddr::from([1, 1, 1, 1])];
        assert_eq!((one.first_ms, one.last_ms), (250, 1000));
        assert_eq!(one.totals.bytes_in, 10_000);
        assert_eq!(one.ports[&(Transport::Tcp, 443)], 10_000);
        assert_eq!(one.quality.row().map(|q| q.rtt_samples), Some(4));
        let lan = &acc.endpoints[&IpAddr::from([192, 168, 1, 5])];
        assert_eq!((lan.first_ms, lan.last_ms), (750, 750));
        assert!(lan.quality.row().is_none());

        let extra = acc.extra().unwrap();
        assert_eq!(extra.quality.and_then(|q| q.min_rtt_ms), Some(20.0));
        assert!(extra.programs.is_none(), "not an all-traffic recording");
    }

    #[test]
    fn accumulator_integrates_program_rates_into_bytes() {
        use crate::monitor::programs::{ProgramRow, ProgramsTick};
        let row = |key: &str, in_bps: f64| ProgramRow {
            key: key.into(),
            name: key.to_uppercase(),
            pids: vec![1],
            in_bps,
            out_bps: 0.0,
            smoothed_bps: in_bps,
            baseline_bps: 0.0,
            ratio: 1.0,
            level: Level::Calm,
            peak_bps: in_bps,
            totals: Counters::default(),
            endpoints: 3,
            first_seen_ms: 0,
            last_seen_ms: 0,
        };
        let mut acc = Accumulator::default();
        for i in 1..=4u64 {
            let mut s = sample(i * 250, 0.0, Level::Calm, 1.0);
            s.programs = Some(ProgramsTick {
                total: 2,
                rows: vec![row("a", 4000.0), row("b", 400.0 * i as f64)],
            });
            acc.add(Box::new(s), &HashMap::new());
        }
        let programs = acc.extra().unwrap().programs.unwrap();
        let summary: Vec<(&str, u64)> = programs
            .iter()
            .map(|p| (p.key.as_str(), p.bytes_in))
            .collect();
        // 4 ticks × 250 ms × 4000 B/s = 4000 B; b: (400+800+1200+1600)/4 = 1000 B.
        assert_eq!(summary, [("a", 4000), ("b", 1000)]);
        assert_eq!(programs[0].name, "A");
        assert_eq!((programs[0].endpoints, programs[1].peak_bps), (3, 1600.0));
        assert_eq!(acc.program_summary(1).len(), 1);
    }

    #[test]
    fn accumulator_bounds_endpoints_and_ports() {
        let mut acc = Accumulator::default();
        // One tick with more remote addresses than a recording keeps.
        let extra = 50;
        let eps: HashMap<IpAddr, EndpointDelta> = (0..(MAX_ENDPOINTS + extra) as u32)
            .map(|i| (IpAddr::from((0x0B00_0000 + i).to_be_bytes()), delta(10, 80)))
            .collect();
        acc.add(Box::new(sample(10_250, 4000.0, Level::Calm, 1.0)), &eps);
        assert_eq!(acc.endpoints.len(), MAX_ENDPOINTS);
        assert_eq!(acc.over_cap, extra as u64);
        assert_eq!(acc.touched.len(), MAX_ENDPOINTS);
        assert_eq!(
            acc.totals.bytes_in,
            10 * (MAX_ENDPOINTS + extra) as u64,
            "the totals still count every address"
        );
        acc.close_ep_window();
        assert_eq!(acc.rows.ep_samples.len(), MAX_ENDPOINTS);

        // One endpoint talking on more ports than are remembered.
        let mut acc = Accumulator::default();
        let ip = IpAddr::from([1, 1, 1, 1]);
        let mut d = EndpointDelta::default();
        for port in 1..=100u16 {
            d.ports.insert((Transport::Udp, port), 5);
        }
        for t in [10_250, 10_500] {
            acc.add(
                Box::new(sample(t, 4000.0, Level::Calm, 1.0)),
                &HashMap::from([(ip, d.clone())]),
            );
        }
        let ports = &acc.endpoints[&ip].ports;
        assert_eq!(ports.len(), MAX_PORTS_PER_ENDPOINT);
        assert!(
            ports.values().all(|&b| b == 10),
            "known ports keep counting"
        );
    }

    #[test]
    fn a_recording_that_cannot_be_written_ends_interrupted_and_says_so() {
        let dir = std::env::temp_dir().join(format!("fishe-rec-fail-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("fishe.db");

        let slot = RecordingSlot::default();
        let info = slot
            .start(
                &db_path,
                &dir.join("captures"),
                &session(),
                None,
                None,
                RecordOptions::default(),
            )
            .unwrap();
        // Every commit now fails, the way it would on a full or broken disk.
        let conn = db::open(&db_path).unwrap();
        conn.execute("DROP TABLE episodes", []).unwrap();

        let eps = HashMap::from([(IpAddr::from([1, 1, 1, 1]), delta(1000, 443))]);
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut t = 10_000;
        let done = loop {
            t += 250;
            if let Some(done) = slot.tick(&sample(t, 4000.0, Level::Calm, 1.0), &eps) {
                break done;
            }
            assert!(Instant::now() < deadline, "the writer never gave up");
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(done.info.id, info.id);
        assert!(done.error.is_some(), "the session is told why");
        assert!(slot.status().is_none(), "no longer reported as recording");
        assert!(slot.finish().is_none());

        // The row is closed: the Archive shows it as interrupted and can delete it.
        let (interrupted, ended): (i64, bool) = conn
            .query_row(
                "SELECT interrupted, ended_at IS NOT NULL FROM recordings WHERE id = ?1",
                params![info.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((interrupted, ended), (1, true));
        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn records_samples_endpoints_episodes_and_pcap() {
        let dir = std::env::temp_dir().join(format!("fishe-rec-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("fishe.db");
        let names = Arc::new(NameBook::new());
        names.set_sni([1, 1, 1, 1].into(), "one.example".into(), false);

        let slot = RecordingSlot::default();
        let info = slot
            .start(
                &db_path,
                &dir.join("captures"),
                &session(),
                Some(names),
                None,
                RecordOptions {
                    name: Some(" test ".into()),
                    pcap: true,
                },
            )
            .unwrap();
        assert_eq!(info.name, "test");

        // A worker copies two packets into the tap.
        let mut tap = TapHandle::new(slot.tap());
        tap.refresh();
        assert!(tap.active());
        tap.send(0, 1_700_000_000_000_000, 1514, &[0u8; 60]);
        tap.send(1, 1_700_000_000_000_500, 64, &[1u8; 44]);

        // calm, busy, spike, calm: one episode.
        let levels = [
            (Level::Calm, 1.0),
            (Level::Busy, 2.5),
            (Level::Spike, 6.0),
            (Level::Calm, 1.1),
        ];
        for (i, (lvl, ratio)) in levels.iter().enumerate() {
            let t = 10_000 + (i as u64 + 1) * 250;
            let mut eps = HashMap::new();
            eps.insert(
                IpAddr::from([1, 1, 1, 1]),
                delta(1000 * (i as u64 + 1), 443),
            );
            if i == 2 {
                eps.insert(IpAddr::from([192, 168, 1, 5]), delta(10, 53));
            }
            slot.tick(&sample(t, 4000.0 * (i as f64 + 1.0), *lvl, *ratio), &eps);
        }
        let done = slot.finish().unwrap();
        assert!(done.error.is_none());
        let done = done.info;
        assert_eq!(done.id, info.id);
        assert!(slot.status().is_none());

        let conn = db::open(&db_path).unwrap();
        let d = db::detail(&conn, info.id).unwrap();
        assert_eq!(d.summary.status, db::RecordingStatus::Complete);
        assert_eq!(d.summary.sample_count, 4);
        assert_eq!(
            d.samples[0].t_ms, 250,
            "times are relative to the recording start"
        );
        assert_eq!(d.summary.totals.bytes_in, 1000 + 2000 + 3000 + 4000 + 10);
        assert_eq!(d.summary.max_level, Level::Spike);
        assert_eq!(d.summary.endpoint_count, 2);
        assert_eq!(d.summary.pcap_packets, 2);
        assert!(d.summary.pcap_bytes.unwrap() > 100);

        assert_eq!(d.episodes.len(), 1);
        let ep = &d.episodes[0];
        assert_eq!(
            (ep.start_ms, ep.end_ms, ep.max_level),
            (500, 1000, Level::Spike)
        );
        assert_eq!(ep.peak_ratio, 6.0);

        let one = d.endpoints.iter().find(|e| e.ip == "1.1.1.1").unwrap();
        assert_eq!(one.totals.bytes_in, 10_000);
        let q = one.quality.as_ref().expect("endpoint quality stored");
        assert_eq!((q.min_rtt_ms, q.rtt_samples), (Some(20.0), 4));
        assert_eq!(q.retrans_out_pct, Some(1.0));
        assert!(
            d.endpoints
                .iter()
                .any(|e| e.ip == "192.168.1.5" && e.quality.is_none())
        );
        assert_eq!(d.samples[0].rtt_ms, Some(20.0), "per-sample RTT stored");
        let extra = d.extra.as_ref().unwrap();
        assert_eq!(
            extra.quality.as_ref().and_then(|q| q.min_rtt_ms),
            Some(20.0)
        );
        assert_eq!(one.name.as_deref(), Some("one.example"));
        assert_eq!(one.name_source, Some(NameSource::Sni));
        assert_eq!(one.top_ports[0].port, 443);
        assert_eq!(one.max_level, Level::Spike);
        let lan = d.endpoints.iter().find(|e| e.ip == "192.168.1.5").unwrap();
        assert_eq!(lan.scope, AddrScope::Private);
        assert_eq!((lan.first_seen_ms, lan.last_seen_ms), (750, 750));

        let series = db::endpoint_series(&conn, info.id, "1.1.1.1").unwrap();
        // History is averaged per second: four 250 ms ticks → one row.
        assert_eq!(series.len(), 1);
        assert_eq!(series[0].in_bps, 10_000.0);

        // Exports
        for (fmt, file) in [
            (super::super::export::ExportFormat::SamplesCsv, "s.csv"),
            (super::super::export::ExportFormat::EndpointsCsv, "e.csv"),
            (super::super::export::ExportFormat::Json, "r.json"),
        ] {
            super::super::export::export(&conn, info.id, fmt, &dir.join(file)).unwrap();
        }
        let csv = std::fs::read_to_string(dir.join("s.csv")).unwrap();
        assert_eq!(csv.lines().count(), 5);
        assert!(
            csv.lines().nth(3).unwrap().ends_with(",spike,20.00"),
            "level, then RTT"
        );
        assert!(
            std::fs::read_to_string(dir.join("e.csv"))
                .unwrap()
                .contains("one.example")
        );
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("r.json")).unwrap()).unwrap();
        assert_eq!(json["samples"].as_array().unwrap().len(), 4);

        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

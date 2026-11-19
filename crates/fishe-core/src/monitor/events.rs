//! Messages from the monitor to the window: the session lifecycle, one
//! [`Sample`] per tick, recording starts and stops. They go through the
//! [`EventSink`] to whoever subscribed (the window does once, with
//! `subscribe_monitor`), so a session started by an agent reaches the window
//! exactly like one started with the Start button. The sink holds a plain
//! callback: this module knows nothing about windows. Field names are
//! camelCase on the wire; the TypeScript types are generated.

use super::SessionInfo;
use super::endpoints::EndpointsTick;
use super::gauge::Level;
use super::programs::ProgramsTick;
use super::quality::QualityTick;
use super::stats::{Counters, PortUsage, TransportBytes};
use crate::archive::recorder::{RecordingInfo, RecordingTick};
use serde::Serialize;
use std::sync::Mutex;

/// A subscriber: takes one event, answers `false` once it is gone.
type Subscriber = Box<dyn Fn(MonitorEvent) -> bool + Send + Sync>;

/// Where monitor events go: the subscriber, once there is one. Events sent
/// before that (or while the webview reloads) are dropped; the window asks
/// for the running session when it subscribes.
#[derive(Default)]
pub struct EventSink(Mutex<Option<Subscriber>>);

impl EventSink {
    /// Replace the subscriber (a webview reload subscribes again).
    pub fn set(&self, deliver: impl Fn(MonitorEvent) -> bool + Send + Sync + 'static) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Some(Box::new(deliver));
    }

    /// Deliver to the current subscriber, if any. `false` from it means it
    /// is gone (the webview closed); it is dropped and the session goes on.
    pub fn send(&self, event: MonitorEvent) {
        let mut guard = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(deliver) = guard.as_ref()
            && !deliver(event)
        {
            log::info!("monitor events: the subscriber is gone");
            *guard = None;
        }
    }
}

#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum MonitorEvent {
    /// Capture is open and packets are being counted. Also sent to a new
    /// subscriber while a session runs, so a reloaded window catches up.
    Started { session: Box<SessionInfo> },
    /// One measurement tick.
    Sample(Box<Sample>),
    /// Capture ended (user or agent request, or an error).
    #[serde(rename_all = "camelCase")]
    Stopped {
        session_id: u64,
        reason: StopReason,
        message: Option<String>,
    },
    /// A recording started (from the window or an agent).
    #[serde(rename_all = "camelCase")]
    RecordingStarted {
        session_id: u64,
        recording: RecordingInfo,
    },
    /// The recording ended (stopped, or the session ended); it is complete on disk.
    #[serde(rename_all = "camelCase")]
    RecordingStopped {
        session_id: u64,
        recording: RecordingInfo,
    },
    /// A non-fatal problem (e.g. one of several interfaces failed).
    #[serde(rename_all = "camelCase")]
    Warning { session_id: u64, message: String },
}

impl EventSink {
    /// A recording ended: say so, with a warning first when the archive
    /// could not be written and holds only part of it.
    pub fn recording_ended(&self, session_id: u64, done: crate::archive::recorder::Finished) {
        if let Some(error) = &done.error {
            self.send(MonitorEvent::Warning {
                session_id,
                message: format!(
                    "Recording \"{}\" stopped early: {error}. What was saved is in the Archive, marked interrupted.",
                    done.info.name
                ),
            });
        }
        self.send(MonitorEvent::RecordingStopped {
            session_id,
            recording: done.info,
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub enum StopReason {
    UserRequested,
    Error,
}

/// A measurement over the last tick. Rates are bytes (or packets) per second.
#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Sample {
    pub session_id: u64,
    /// Milliseconds since the capture started.
    pub t_ms: u64,
    /// Real duration of this tick in milliseconds.
    pub interval_ms: f64,

    pub in_bps: f64,
    pub out_bps: f64,
    pub in_pps: f64,
    pub out_pps: f64,

    /// Busyness detector output (see `gauge.rs`).
    pub smoothed_bps: f64,
    pub baseline_bps: f64,
    pub ratio: f64,
    pub level: Level,
    /// Highest `in_bps + out_bps` seen so far.
    pub peak_bps: f64,

    pub totals: Counters,
    pub transports: TransportBytes,
    pub top_ports: Vec<PortUsage>,

    /// Packets the OS buffers dropped (we were too slow) since start, all interfaces.
    pub dropped: u64,
    /// Packets the interfaces/drivers dropped since start.
    pub if_dropped: u64,
    /// Packets that could not be attributed to any process (process mode:
    /// dropped from the counts; all-traffic mode: counted as *Unattributed*).
    pub unattributed: u64,
    /// Live process information (process mode), or socket-table figures for
    /// the whole machine (all-traffic mode: `pids` empty, `pid_count` = PIDs
    /// owning sockets).
    pub process: Option<ProcessTick>,
    /// Remote endpoints (process and all-traffic modes).
    pub endpoints: Option<EndpointsTick>,
    /// Programs using the network (all-traffic mode only).
    pub programs: Option<ProgramsTick>,
    /// TCP connection quality of the counted traffic (RTT, retransmissions).
    pub quality: Option<QualityTick>,
    /// Live recording status, while recording.
    pub recording: Option<RecordingTick>,
}

#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct ProcessTick {
    /// Currently matched PIDs (at most 64 listed).
    pub pids: Vec<u32>,
    pub pid_count: usize,
    /// Sockets owned by the matched PIDs at the last socket-table poll.
    pub sockets: u32,
    /// Port→PID mappings currently known (all processes).
    pub known_ports: usize,
}

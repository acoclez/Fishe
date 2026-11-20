//! On-demand continuous ping: one ICMP echo per second to an address, for
//! RTT, jitter and loss of traffic that passive TCP analysis can't time
//! (UDP games, voice, QUIC).
//!
//! Active: it sends packets, so it only runs when the user starts it, at
//! most [`MAX_TARGETS`] at once, and stops by itself after [`MAX_DURATION`].

use super::icmp::{self, ProbeKind};
use crate::error::{AppError, AppResult};
use crate::monitor::quality::RttStats;
use crate::util::now_ms;
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const MAX_TARGETS: usize = 4;
pub const INTERVAL: Duration = Duration::from_secs(1);
/// A reply later than this counts as lost.
pub const TIMEOUT_MS: u32 = 1000;
pub const MAX_DURATION: Duration = Duration::from_secs(30 * 60);
/// Probes kept for the history and the rolling figures.
const HISTORY: usize = 300;
/// Rolling window of loss / average, in probes.
const RECENT: usize = 60;
/// Probes listed in each status.
const HISTORY_SENT: usize = 120;

#[derive(Debug, Default)]
struct PingState {
    /// RTT in ms per probe, `None` = lost; oldest first.
    history: VecDeque<Option<u32>>,
    sent: u64,
    received: u64,
    rtt: RttStats,
    max_us: u32,
    error: Option<String>,
}

impl PingState {
    fn record(&mut self, rtt_ms: Option<u32>) {
        self.sent += 1;
        if self.history.len() >= HISTORY {
            self.history.pop_front();
        }
        self.history.push_back(rtt_ms);
        if let Some(ms) = rtt_ms {
            self.received += 1;
            let us = ms.saturating_mul(1000);
            self.rtt.add(us);
            self.max_us = self.max_us.max(us);
        }
    }

    fn status(&self, ip: IpAddr, running: bool, started_at_ms: u64) -> PingStatus {
        let recent: Vec<Option<u32>> = self.history.iter().rev().take(RECENT).copied().collect();
        let got: Vec<u32> = recent.iter().flatten().copied().collect();
        let has = self.rtt.count > 0;
        PingStatus {
            ip,
            running,
            started_at_ms,
            sent: self.sent,
            received: self.received,
            loss_pct: (!recent.is_empty())
                .then(|| (recent.len() - got.len()) as f64 * 100.0 / recent.len() as f64),
            last_ms: self.history.back().copied().flatten(),
            avg_ms: (!got.is_empty())
                .then(|| got.iter().map(|&v| f64::from(v)).sum::<f64>() / got.len() as f64),
            min_ms: has.then(|| f64::from(self.rtt.min_us) / 1000.0),
            max_ms: has.then(|| f64::from(self.max_us) / 1000.0),
            jitter_ms: (self.rtt.count > 1).then(|| self.rtt.jitter_us / 1000.0),
            history: self
                .history
                .iter()
                .skip(self.history.len().saturating_sub(HISTORY_SENT))
                .copied()
                .collect(),
            error: self.error.clone(),
        }
    }
}

/// One ping target as sent to the UI.
#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct PingStatus {
    pub ip: IpAddr,
    pub running: bool,
    pub started_at_ms: u64,
    pub sent: u64,
    pub received: u64,
    /// Lost share of the last 60 probes.
    pub loss_pct: Option<f64>,
    pub last_ms: Option<u32>,
    /// Mean of the replies among the last 60 probes.
    pub avg_ms: Option<f64>,
    pub min_ms: Option<f64>,
    pub max_ms: Option<f64>,
    /// RFC 3550-style jitter: smoothed difference between consecutive replies.
    pub jitter_ms: Option<f64>,
    /// Last 120 probes, oldest first; `null` = lost.
    pub history: Vec<Option<u32>>,
    /// Why probing stopped early (ICMP API failure).
    pub error: Option<String>,
}

struct Target {
    stop: Arc<AtomicBool>,
    state: Arc<Mutex<PingState>>,
    started: Instant,
    started_at_ms: u64,
}

impl Target {
    fn running(&self) -> bool {
        !self.stop.load(Ordering::Relaxed)
    }
}

/// Tauri-managed: the ping targets of this app run.
#[derive(Default)]
pub struct PingBook {
    targets: Mutex<HashMap<IpAddr, Target>>,
}

impl PingBook {
    /// Start pinging `ip` (or keep the running ping). Stopped targets are
    /// restarted with fresh statistics.
    pub fn start(&self, ip: IpAddr) -> AppResult<PingStatus> {
        let mut targets = self.lock();
        if let Some(t) = targets.get(&ip)
            && t.running()
        {
            return Ok(t.state.lock().unwrap_or_else(|e| e.into_inner()).status(
                ip,
                true,
                t.started_at_ms,
            ));
        }
        targets.retain(|_, t| t.running());
        if targets.len() >= MAX_TARGETS {
            return Err(AppError::Busy(format!(
                "at most {MAX_TARGETS} pings can run at once; stop one first"
            )));
        }
        let stop = Arc::new(AtomicBool::new(false));
        let state = Arc::new(Mutex::new(PingState::default()));
        let (s, st) = (stop.clone(), state.clone());
        std::thread::Builder::new()
            .name(format!("fishe-ping-{ip}"))
            .spawn(move || run(ip, s, st))
            .map_err(|e| AppError::Internal(format!("failed to start ping: {e}")))?;
        let t = Target {
            stop,
            state,
            started: Instant::now(),
            started_at_ms: now_ms(),
        };
        let status = PingState::default().status(ip, true, t.started_at_ms);
        targets.insert(ip, t);
        Ok(status)
    }

    /// Stop pinging `ip` (its figures stay readable). Returns whether it ran.
    pub fn stop(&self, ip: IpAddr) -> bool {
        match self.lock().get(&ip) {
            Some(t) if t.running() => {
                t.stop.store(true, Ordering::Relaxed);
                true
            }
            _ => false,
        }
    }

    /// Every target of this run, running ones first.
    pub fn status(&self) -> Vec<PingStatus> {
        let targets = self.lock();
        let mut v: Vec<PingStatus> = targets
            .iter()
            .map(|(ip, t)| {
                let running = t.running() && t.started.elapsed() < MAX_DURATION;
                t.state.lock().unwrap_or_else(|e| e.into_inner()).status(
                    *ip,
                    running,
                    t.started_at_ms,
                )
            })
            .collect();
        v.sort_by(|a, b| {
            b.running
                .cmp(&a.running)
                .then(a.started_at_ms.cmp(&b.started_at_ms))
        });
        v
    }

    /// Stop every running target (app exit). The threads notice within 50 ms.
    pub fn stop_all(&self) {
        for t in self.lock().values() {
            t.stop.store(true, Ordering::Relaxed);
        }
    }

    /// Forget a stopped target.
    pub fn remove(&self, ip: IpAddr) {
        let mut targets = self.lock();
        if let Some(t) = targets.remove(&ip) {
            t.stop.store(true, Ordering::Relaxed);
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<IpAddr, Target>> {
        self.targets.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn run(ip: IpAddr, stop: Arc<AtomicBool>, state: Arc<Mutex<PingState>>) {
    let started = Instant::now();
    while !stop.load(Ordering::Relaxed) && started.elapsed() < MAX_DURATION {
        let at = Instant::now();
        let reply = icmp::probe(ip, 128, TIMEOUT_MS);
        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
        match reply {
            Ok(r) => s.record(match r.kind {
                ProbeKind::Reached => Some(r.rtt_ms.unwrap_or(0)),
                _ => None,
            }),
            Err(e) => {
                s.error = Some(e.to_string());
                break;
            }
        }
        drop(s);
        let wait = INTERVAL.saturating_sub(at.elapsed());
        // Sleep in slices so a stop is prompt.
        let until = Instant::now() + wait;
        while Instant::now() < until && !stop.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(50).min(until - Instant::now()));
        }
    }
    stop.store(true, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statistics_over_probes() {
        let mut s = PingState::default();
        for v in [Some(20), Some(30), None, Some(25)] {
            s.record(v);
        }
        let st = s.status([1, 1, 1, 1].into(), true, 0);
        assert_eq!((st.sent, st.received), (4, 3));
        assert_eq!(st.loss_pct, Some(25.0));
        assert_eq!(st.avg_ms, Some(25.0));
        assert_eq!((st.min_ms, st.max_ms), (Some(20.0), Some(30.0)));
        assert_eq!(st.last_ms, Some(25));
        assert_eq!(st.history, vec![Some(20), Some(30), None, Some(25)]);
        // |30-20| = 10 → 10/16; then |25-30| = 5 → 0.625 + (5 - 0.625)/16
        let j = 0.625 + (5.0 - 0.625) / 16.0;
        assert!((st.jitter_ms.unwrap() - j).abs() < 1e-9);
    }

    #[test]
    #[cfg_attr(not(windows), ignore = "needs CAP_NET_RAW on Linux; no ICMP elsewhere")]
    fn loopback_ping_and_limits() {
        let book = PingBook::default();
        let lo: IpAddr = [127, 0, 0, 1].into();
        book.start(lo).unwrap();
        std::thread::sleep(Duration::from_millis(2300));
        let st = book.status();
        assert_eq!(st.len(), 1);
        assert!(st[0].running);
        assert!(st[0].received >= 2, "{st:?}");
        assert_eq!(st[0].loss_pct, Some(0.0));
        assert!(book.stop(lo));
        std::thread::sleep(Duration::from_millis(150));
        assert!(!book.status()[0].running);
        for i in 2..=5u8 {
            book.start([127, 0, 0, i].into()).unwrap();
        }
        assert!(
            book.start([127, 0, 0, 9].into()).is_err(),
            "at most 4 at once"
        );
        for i in 2..=5u8 {
            book.remove([127, 0, 0, i].into());
        }
    }
}

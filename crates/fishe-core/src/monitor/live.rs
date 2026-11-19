//! The running session as seen by readers other than the UI (the MCP
//! server): the latest sample and a compact rolling history.
//!
//! The UI gets every sample over its channel and keeps its own history; this
//! keeps a copy on the backend side so an agent can ask "what happened in
//! the last minute" without the window.

use super::events::Sample;
use super::gauge::Level;
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::Mutex;

/// 10 minutes at the default 250 ms tick (less at a shorter tick, more at a longer one).
const HISTORY_CAP: usize = 2400;

/// One tick, compact.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryPoint {
    /// Milliseconds since the session started.
    pub t_ms: u64,
    pub in_bps: f64,
    pub out_bps: f64,
    pub baseline_bps: f64,
    pub ratio: f64,
    pub level: Level,
    /// Mean TCP RTT measured in the tick.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
}

#[derive(Default)]
pub struct Live {
    latest: Mutex<Option<Sample>>,
    history: Mutex<VecDeque<HistoryPoint>>,
}

impl Live {
    pub fn update(&self, s: &Sample) {
        let point = HistoryPoint {
            t_ms: s.t_ms,
            in_bps: s.in_bps,
            out_bps: s.out_bps,
            baseline_bps: s.baseline_bps,
            ratio: s.ratio,
            level: s.level,
            rtt_ms: s.quality.as_ref().and_then(|q| q.rtt_tick_ms),
        };
        {
            let mut h = self.history.lock().unwrap_or_else(|e| e.into_inner());
            if h.len() >= HISTORY_CAP {
                h.pop_front();
            }
            h.push_back(point);
        }
        *self.latest.lock().unwrap_or_else(|e| e.into_inner()) = Some(s.clone());
    }

    pub fn latest(&self) -> Option<Sample> {
        self.latest
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Points of the last `secs` seconds, oldest first.
    pub fn history(&self, secs: u64) -> Vec<HistoryPoint> {
        let h = self.history.lock().unwrap_or_else(|e| e.into_inner());
        let Some(last) = h.back() else {
            return Vec::new();
        };
        let from = last.t_ms.saturating_sub(secs * 1000);
        h.iter().filter(|p| p.t_ms > from).copied().collect()
    }
}

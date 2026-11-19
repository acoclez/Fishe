//! Live packet list ("Packets" view): the latest counted packets, headers only.
//!
//! Off unless the UI has the view open: workers check one atomic flag per
//! packet, collect summaries locally and hand them over in batches at their
//! 50 ms flush, so the shared lock is taken ~20 times per second per
//! interface, not per packet. The UI polls with the last sequence number it
//! has seen.

use super::stats::Direction;
use crate::net::parse::{PacketInfo, Transport};
use serde::Serialize;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

/// Packets kept for the UI.
pub const RING_CAP: usize = 2000;
/// Packets a worker keeps between flushes (newest win).
pub const BATCH_CAP: usize = 2000;

/// One counted packet, as captured.
#[derive(Debug, Clone, Copy)]
pub struct PacketSummary {
    /// Capture timestamp, µs since the Unix epoch.
    pub ts_us: u64,
    /// Index of the capture interface in `SessionInfo.interfaces`.
    pub iface: u32,
    pub dir: Direction,
    pub info: PacketInfo,
    pub wire_len: u32,
    /// Owning PID (all-traffic mode), when known.
    pub pid: Option<u32>,
}

#[derive(Default)]
struct Ring {
    next_seq: u64,
    items: VecDeque<(u64, PacketSummary)>,
}

#[derive(Default)]
pub struct PacketRing {
    /// The window's own switch.
    enabled: AtomicBool,
    /// Temporary readers (agents) that need the feed on right now.
    holds: std::sync::atomic::AtomicUsize,
    ring: Mutex<Ring>,
}

impl PacketRing {
    /// On while the window's switch is on or any temporary hold is active.
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed) || self.holds.load(Ordering::Relaxed) > 0
    }

    /// The window's switch. Turning it off clears the list, unless a hold
    /// still needs it.
    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
        if !self.enabled() {
            self.lock().items.clear();
        }
    }

    /// Keep the feed on until the matching [`release`](Self::release).
    pub fn hold(&self) {
        self.holds.fetch_add(1, Ordering::Relaxed);
    }

    pub fn release(&self) {
        if self.holds.fetch_sub(1, Ordering::Relaxed) == 1 && !self.enabled.load(Ordering::Relaxed)
        {
            self.lock().items.clear();
        }
    }

    /// Append a worker's batch.
    pub fn push(&self, batch: &mut VecDeque<PacketSummary>) {
        if batch.is_empty() {
            return;
        }
        let mut ring = self.lock();
        for p in batch.drain(..) {
            let seq = ring.next_seq;
            ring.next_seq += 1;
            if ring.items.len() >= RING_CAP {
                ring.items.pop_front();
            }
            ring.items.push_back((seq, p));
        }
    }

    /// Packets with a sequence number greater than `after` (or all kept, for
    /// `None`), oldest first, at most `limit` of the newest. Also returns the
    /// next sequence number, so the caller can tell how many it missed.
    pub fn since(&self, after: Option<u64>, limit: usize) -> (Vec<(u64, PacketSummary)>, u64) {
        let ring = self.lock();
        let newer = ring
            .items
            .iter()
            .filter(|(seq, _)| after.is_none_or(|a| *seq > a))
            .copied();
        let mut v: Vec<(u64, PacketSummary)> = newer.collect();
        if v.len() > limit {
            v.drain(..v.len() - limit);
        }
        (v, ring.next_seq)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Ring> {
        self.ring.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// A worker's local batch, bounded.
pub fn collect(batch: &mut VecDeque<PacketSummary>, p: PacketSummary) {
    if batch.len() >= BATCH_CAP {
        batch.pop_front();
    }
    batch.push_back(p);
}

/// A packet as sent to the UI.
#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct PacketRow {
    pub seq: u64,
    pub ts_us: u64,
    pub iface: u32,
    /// `"in"` (received by the monitored side) or `"out"`.
    pub dir: Direction,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub transport: Transport,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub len: u32,
    pub ttl: u8,
    pub pid: Option<u32>,
    /// Program name (all-traffic mode).
    pub program: Option<String>,
    /// Best known name of the remote side.
    pub remote_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct PacketBatch {
    pub rows: Vec<PacketRow>,
    /// Sequence number the next packet will get.
    pub next_seq: u64,
    pub enabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(n: u32) -> PacketSummary {
        PacketSummary {
            ts_us: u64::from(n),
            iface: 0,
            dir: Direction::Out,
            info: PacketInfo {
                src: [10, 0, 0, 2].into(),
                dst: [1, 1, 1, 1].into(),
                transport: Transport::Udp,
                src_port: Some(5000),
                dst_port: Some(53),
                ttl: 64,
            },
            wire_len: n,
            pid: None,
        }
    }

    #[test]
    fn ring_keeps_the_newest_and_pages_by_sequence() {
        let ring = PacketRing::default();
        ring.set_enabled(true);
        let mut batch: VecDeque<PacketSummary> = (0..(RING_CAP as u32 + 10)).map(summary).collect();
        ring.push(&mut batch);
        assert!(batch.is_empty());
        let (all, next) = ring.since(None, usize::MAX);
        assert_eq!(all.len(), RING_CAP);
        assert_eq!(next, RING_CAP as u64 + 10);
        assert_eq!(all[0].0, 10, "oldest dropped");

        let (tail, _) = ring.since(Some(next - 4), 100);
        assert_eq!(
            tail.iter().map(|t| t.0).collect::<Vec<_>>(),
            vec![next - 3, next - 2, next - 1]
        );
        let (limited, _) = ring.since(None, 5);
        assert_eq!(limited.len(), 5);
        assert_eq!(limited[4].0, next - 1, "the newest are kept when limited");

        ring.set_enabled(false);
        assert!(ring.since(None, 10).0.is_empty());
    }

    #[test]
    fn worker_batch_is_bounded() {
        let mut b = VecDeque::new();
        for n in 0..(BATCH_CAP as u32 + 5) {
            collect(&mut b, summary(n));
        }
        assert_eq!(b.len(), BATCH_CAP);
        assert_eq!(b[0].wire_len, 5);
    }
}

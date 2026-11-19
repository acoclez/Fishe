//! Per-program statistics for all-traffic mode ("who is using the network?").
//!
//! Packets are attributed per PID; the book groups PIDs by executable name
//! (`chrome.exe` with 20 processes is one program), and keeps for each:
//! totals, current rates, a [`BusyDetector`] of its own, and the set of
//! endpoints it talked to.

use super::gauge::{BusyDetector, GaugeConfig, Level};
use super::stats::{Counters, EndpointDelta, UNATTRIBUTED};
use crate::process::machine::MachineScope;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// Rows sent per sample (busiest now first, then biggest overall).
pub const MAX_ROWS: usize = 100;
/// Programs remembered per session; least recently seen are evicted beyond it.
pub const MAX_PROGRAMS: usize = 1024;
/// Distinct endpoints counted per program.
const MAX_ENDPOINTS_PER_PROGRAM: usize = 4096;
/// PIDs listed per program.
const MAX_PIDS: usize = 16;

/// How a PID is shown and grouped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    /// Grouping key: lower-case executable name, `pid:N` while the name is
    /// unknown, or `""` for unattributed traffic.
    pub key: String,
    /// Display name: `chrome.exe`, `PID 1234`, `Unattributed`.
    pub name: String,
}

impl Label {
    pub fn of(scope: &MachineScope, pid: u32) -> Label {
        if pid == UNATTRIBUTED {
            return Label {
                key: String::new(),
                name: "Unattributed".into(),
            };
        }
        match scope.name(pid) {
            Some(name) => Label {
                key: name.to_ascii_lowercase(),
                name,
            },
            None => Label {
                key: format!("pid:{pid}"),
                name: format!("PID {pid}"),
            },
        }
    }
}

/// Labels for every PID in this window.
pub fn labels<'a>(
    scope: &MachineScope,
    pids: impl IntoIterator<Item = &'a u32>,
) -> HashMap<u32, Label> {
    pids.into_iter()
        .map(|&pid| (pid, Label::of(scope, pid)))
        .collect()
}

/// One program as sent to the UI.
#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct ProgramRow {
    pub key: String,
    pub name: String,
    /// PIDs seen sending/receiving (at most 16 listed).
    pub pids: Vec<u32>,
    pub in_bps: f64,
    pub out_bps: f64,
    pub smoothed_bps: f64,
    pub baseline_bps: f64,
    pub ratio: f64,
    pub level: Level,
    pub peak_bps: f64,
    pub totals: Counters,
    /// Distinct remote addresses this session.
    pub endpoints: usize,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct ProgramsTick {
    /// Programs seen this session (rows may hold a subset).
    pub total: usize,
    pub rows: Vec<ProgramRow>,
}

struct Program {
    name: String,
    pids: Vec<u32>,
    totals: Counters,
    endpoints: HashSet<IpAddr>,
    detector: BusyDetector,
    in_bps: f64,
    out_bps: f64,
    smoothed_bps: f64,
    baseline_bps: f64,
    ratio: f64,
    level: Level,
    peak_bps: f64,
    first_seen_ms: u64,
    last_seen_ms: u64,
}

pub struct ProgramBook {
    gauge: GaugeConfig,
    map: HashMap<String, Program>,
}

impl ProgramBook {
    pub fn new(gauge: GaugeConfig) -> Self {
        ProgramBook {
            gauge,
            map: HashMap::new(),
        }
    }

    /// How many programs are known.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Advance one tick of `secs` with this tick's per-PID and per-endpoint counts.
    pub fn tick(
        &mut self,
        programs: &HashMap<u32, Counters>,
        endpoints: &HashMap<IpAddr, EndpointDelta>,
        labels: &HashMap<u32, Label>,
        secs: f64,
        t_ms: u64,
    ) {
        let mut window: HashMap<&str, Counters> = HashMap::new();
        for (pid, c) in programs {
            let Some(label) = labels.get(pid) else {
                continue;
            };
            window.entry(&label.key).or_default().merge(c);
            let gauge = self.gauge;
            let p = self
                .map
                .entry(label.key.clone())
                .or_insert_with(|| Program {
                    name: label.name.clone(),
                    pids: Vec::new(),
                    totals: Counters::default(),
                    endpoints: HashSet::new(),
                    detector: BusyDetector::new(gauge),
                    in_bps: 0.0,
                    out_bps: 0.0,
                    smoothed_bps: 0.0,
                    baseline_bps: 0.0,
                    ratio: 0.0,
                    level: Level::Idle,
                    peak_bps: 0.0,
                    first_seen_ms: t_ms,
                    last_seen_ms: t_ms,
                });
            p.last_seen_ms = t_ms;
            p.totals.merge(c);
            if *pid != UNATTRIBUTED && !p.pids.contains(pid) {
                if p.pids.len() >= MAX_PIDS {
                    p.pids.remove(0);
                }
                p.pids.push(*pid);
            }
        }
        for (ip, d) in endpoints {
            for pid in d.programs.keys() {
                if let Some(p) = labels.get(pid).and_then(|l| self.map.get_mut(&l.key))
                    && p.endpoints.len() < MAX_ENDPOINTS_PER_PROGRAM
                {
                    p.endpoints.insert(*ip);
                }
            }
        }

        for (key, p) in &mut self.map {
            let (bin, bout) = window
                .get(key.as_str())
                .map_or((0, 0), |c| (c.bytes_in, c.bytes_out));
            p.in_bps = bin as f64 / secs;
            p.out_bps = bout as f64 / secs;
            let r = p.detector.update(p.in_bps + p.out_bps, secs);
            p.smoothed_bps = r.smoothed_bps;
            p.baseline_bps = r.baseline_bps;
            p.ratio = r.ratio;
            p.level = r.level;
            p.peak_bps = p.peak_bps.max(p.in_bps + p.out_bps);
        }

        if self.map.len() > MAX_PROGRAMS {
            let mut by_age: Vec<(u64, String)> = self
                .map
                .iter()
                .map(|(k, p)| (p.last_seen_ms, k.clone()))
                .collect();
            by_age.sort_unstable();
            let excess = self.map.len() - MAX_PROGRAMS * 7 / 8;
            for (_, k) in by_age.into_iter().take(excess) {
                self.map.remove(&k);
            }
        }
    }

    /// Busiest now first, then biggest overall; at most [`MAX_ROWS`].
    pub fn rows(&self) -> Vec<ProgramRow> {
        let mut v: Vec<(&String, &Program)> = self.map.iter().collect();
        v.sort_unstable_by(|a, b| {
            b.1.smoothed_bps
                .total_cmp(&a.1.smoothed_bps)
                .then_with(|| {
                    (b.1.totals.bytes_in + b.1.totals.bytes_out)
                        .cmp(&(a.1.totals.bytes_in + a.1.totals.bytes_out))
                })
                .then_with(|| a.0.cmp(b.0))
        });
        v.into_iter()
            .take(MAX_ROWS)
            .map(|(key, p)| ProgramRow {
                key: key.clone(),
                name: p.name.clone(),
                pids: p.pids.clone(),
                in_bps: p.in_bps,
                out_bps: p.out_bps,
                smoothed_bps: p.smoothed_bps,
                baseline_bps: p.baseline_bps,
                ratio: p.ratio,
                level: p.level,
                peak_bps: p.peak_bps,
                totals: p.totals,
                endpoints: p.endpoints.len(),
                first_seen_ms: p.first_seen_ms,
                last_seen_ms: p.last_seen_ms,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::stats::{Direction, Tally};
    use crate::net::parse::{PacketInfo, Transport};
    use crate::process::ownership::OwnershipTable;
    use crate::process::processes::ProcessEntry;
    use std::sync::Arc;

    const ME: [u8; 4] = [10, 0, 0, 2];

    fn scope() -> MachineScope {
        let s = MachineScope::new(
            Arc::new(OwnershipTable::new()),
            Arc::new([IpAddr::from(ME)].into()),
        );
        s.update_names(&[
            ProcessEntry {
                pid: 10,
                parent_pid: 1,
                name: "Chrome.exe".into(),
            },
            ProcessEntry {
                pid: 11,
                parent_pid: 10,
                name: "chrome.exe".into(),
            },
            ProcessEntry {
                pid: 20,
                parent_pid: 1,
                name: "svchost.exe".into(),
            },
        ]);
        s
    }

    fn recv(t: &mut Tally, remote: [u8; 4], bytes: u32, pid: Option<u32>) {
        let p = PacketInfo {
            src: remote.into(),
            dst: ME.into(),
            transport: Transport::Tcp,
            src_port: Some(443),
            dst_port: Some(50000),
            ttl: 60,
        };
        t.record_owned(Direction::In, &p, bytes, pid);
    }

    #[test]
    fn groups_pids_by_name_and_counts_endpoints() {
        let s = scope();
        let mut book = ProgramBook::new(GaugeConfig::default());
        let mut t = Tally::default();
        recv(&mut t, [1, 1, 1, 1], 1000, Some(10));
        recv(&mut t, [8, 8, 8, 8], 500, Some(11));
        recv(&mut t, [8, 8, 8, 8], 100, Some(20));
        recv(&mut t, [9, 9, 9, 9], 40, None);
        recv(&mut t, [9, 9, 9, 9], 60, Some(77)); // never named
        let l = labels(&s, t.programs.keys());
        book.tick(&t.programs, &t.endpoints, &l, 0.25, 250);

        let rows = book.rows();
        assert_eq!(rows.len(), 4);
        let chrome = &rows[0];
        assert_eq!(
            chrome.key, "chrome.exe",
            "busiest first, grouped case-insensitively"
        );
        assert_eq!(chrome.totals.bytes_in, 1500);
        assert_eq!(chrome.in_bps, 6000.0);
        assert_eq!(chrome.endpoints, 2);
        let mut pids = chrome.pids.clone();
        pids.sort_unstable();
        assert_eq!(pids, vec![10, 11]);
        assert!(
            rows.iter()
                .any(|r| r.key.is_empty() && r.name == "Unattributed")
        );
        assert!(rows.iter().any(|r| r.key == "pid:77" && r.name == "PID 77"));

        // Next tick: chrome idle, svchost busy.
        let mut t = Tally::default();
        recv(&mut t, [8, 8, 8, 8], 9000, Some(20));
        let l = labels(&s, t.programs.keys());
        book.tick(&t.programs, &t.endpoints, &l, 0.25, 500);
        let rows = book.rows();
        assert_eq!(rows[0].key, "svchost.exe");
        let chrome = rows.iter().find(|r| r.key == "chrome.exe").unwrap();
        assert_eq!(chrome.in_bps, 0.0);
        assert_eq!(chrome.last_seen_ms, 250);
    }
}

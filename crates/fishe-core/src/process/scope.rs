//! The set of PIDs being monitored and per-packet attribution.

use super::ownership::OwnershipTable;
use super::processes::ProcessEntry;
use crate::monitor::stats::Direction;
use crate::monitor::target::{ProcessSelector, Verdict};
use crate::net::parse::{PacketInfo, Transport};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// How long a matched process stays selected after it exits, so its last
/// packets (TCP FIN/ACK, late UDP) still count.
pub const EXIT_GRACE: Duration = Duration::from_secs(10);

#[derive(Debug, Default)]
struct PidState {
    /// PIDs matching the selector: alive, or exited less than [`EXIT_GRACE`] ago.
    selected: HashSet<u32>,
    /// Every PID that existed at the last refresh (or was announced by ETW).
    /// An owner PID outside this set is *new*: we can't tell yet whether it
    /// matches, so its packets wait.
    known: HashSet<u32>,
    /// Selected PIDs that disappeared, and when.
    exited: HashMap<u32, Instant>,
}

/// Shared between the aggregator (writes) and capture workers (read per packet).
#[derive(Debug)]
pub struct ProcessScope {
    pub selector: ProcessSelector,
    pub ownership: Arc<OwnershipTable>,
    /// Every address of this host (all adapters + loopback).
    pub local: Arc<HashSet<IpAddr>>,
    pids: RwLock<PidState>,
    generation: AtomicU64,
}

impl ProcessScope {
    pub fn new(
        selector: ProcessSelector,
        ownership: Arc<OwnershipTable>,
        local: Arc<HashSet<IpAddr>>,
    ) -> Self {
        ProcessScope {
            selector,
            ownership,
            local,
            pids: RwLock::default(),
            generation: AtomicU64::new(0),
        }
    }

    fn matches(&self, pid: u32, file_name: &str) -> bool {
        match &self.selector {
            ProcessSelector::Name { name } => file_name.eq_ignore_ascii_case(name),
            ProcessSelector::Pid { pid: wanted } => *wanted == pid,
        }
    }

    /// Recompute the selected PIDs from a process list.
    pub fn update_pids(&self, processes: &[ProcessEntry]) {
        let now = Instant::now();
        let alive: HashSet<u32> = processes
            .iter()
            .filter(|p| self.matches(p.pid, &p.name))
            .map(|p| p.pid)
            .collect();

        let mut state = self.pids.write().unwrap_or_else(|e| e.into_inner());
        // Selected PIDs that just vanished start their grace period.
        let vanished: Vec<u32> = state
            .selected
            .iter()
            .copied()
            .filter(|p| !alive.contains(p))
            .collect();
        for pid in vanished {
            state.exited.entry(pid).or_insert(now);
        }
        state
            .exited
            .retain(|pid, at| !alive.contains(pid) && now.duration_since(*at) < EXIT_GRACE);

        let selected: HashSet<u32> = alive.iter().chain(state.exited.keys()).copied().collect();
        let known: HashSet<u32> = processes
            .iter()
            .map(|p| p.pid)
            .chain(state.exited.keys().copied())
            .collect();
        if state.selected != selected || state.known != known {
            state.selected = selected;
            state.known = known;
            self.generation.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// A process just started (ETW). Lets even a process that lives only a
    /// few milliseconds be recognised before its first packet.
    pub fn note_process_start(&self, pid: u32, image: &str) {
        let file_name = image.rsplit(['\\', '/']).next().unwrap_or(image);
        let matched = self.matches(pid, file_name);
        let mut state = self.pids.write().unwrap_or_else(|e| e.into_inner());
        let mut changed = state.known.insert(pid);
        if matched {
            changed |= state.selected.insert(pid);
            state.exited.remove(&pid);
        }
        if changed {
            self.generation.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// Changes whenever attribution could give a different answer.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire) + self.ownership.generation()
    }

    /// Matched PIDs that are still running (excludes the exit grace period).
    pub fn selected_pids(&self) -> Vec<u32> {
        let state = self.pids.read().unwrap_or_else(|e| e.into_inner());
        let mut v: Vec<u32> = state
            .selected
            .iter()
            .copied()
            .filter(|p| !state.exited.contains_key(p))
            .collect();
        v.sort_unstable();
        v
    }

    /// Does any of these PIDs postdate the last process-list refresh?
    pub fn has_unknown(&self, pids: impl IntoIterator<Item = u32>) -> bool {
        let state = self.pids.read().unwrap_or_else(|e| e.into_inner());
        pids.into_iter()
            .any(|p| p != 0 && !state.known.contains(&p))
    }

    pub fn is_selected(&self, pid: u32) -> bool {
        self.pids
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .selected
            .contains(&pid)
    }

    /// Does this packet belong to the monitored process(es)?
    ///
    /// Only TCP/UDP can be attributed (ownership is per port). The local end
    /// is identified by address; sent = local source port owned by a selected
    /// PID, received = local destination port owned by one.
    pub fn classify(&self, info: &PacketInfo) -> Verdict {
        let (Some(sport), Some(dport)) = (info.src_port, info.dst_port) else {
            return Verdict::Skip;
        };
        if !matches!(info.transport, Transport::Tcp | Transport::Udp) {
            return Verdict::Skip;
        }

        let mut undecided = false;
        if self.local.contains(&info.src) {
            match self.owned(info.transport, sport) {
                Some(true) => return Verdict::Match(Direction::Out),
                Some(false) => {}
                None => undecided = true,
            }
        }
        if self.local.contains(&info.dst) {
            match self.owned(info.transport, dport) {
                Some(true) => return Verdict::Match(Direction::In),
                Some(false) => {}
                None => undecided = true,
            }
        }
        if undecided {
            Verdict::Pending
        } else {
            Verdict::Skip
        }
    }

    /// `Some(true)` selected owner, `Some(false)` other known owner, `None` unknown yet.
    fn owned(&self, transport: Transport, port: u16) -> Option<bool> {
        let pid = self.ownership.owner(transport, port)?;
        let state = self.pids.read().unwrap_or_else(|e| e.into_inner());
        if state.selected.contains(&pid) {
            Some(true)
        } else if state.known.contains(&pid) {
            Some(false)
        } else {
            None
        }
    }
}

impl super::etw::EtwSink for ProcessScope {
    fn ownership(&self) -> &OwnershipTable {
        &self.ownership
    }
    fn local(&self) -> &HashSet<IpAddr> {
        &self.local
    }
    fn process_started(&self, pid: u32, image: &str) {
        self.note_process_start(pid, image);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ownership::DEFAULT_TTL;
    use crate::process::sockets::SocketEntry;

    const ME: [u8; 4] = [10, 0, 0, 2];
    const REMOTE: [u8; 4] = [93, 184, 216, 34];

    fn procs() -> Vec<ProcessEntry> {
        vec![
            ProcessEntry {
                pid: 100,
                parent_pid: 1,
                name: "app.exe".into(),
            },
            ProcessEntry {
                pid: 101,
                parent_pid: 100,
                name: "App.exe".into(),
            },
            ProcessEntry {
                pid: 200,
                parent_pid: 1,
                name: "other.exe".into(),
            },
        ]
    }

    fn sock(port: u16, pid: u32) -> SocketEntry {
        SocketEntry {
            transport: Transport::Tcp,
            local: std::net::SocketAddr::new(ME.into(), port),
            remote: None,
            pid,
            listening: false,
        }
    }

    fn pkt(src: [u8; 4], sp: u16, dst: [u8; 4], dp: u16) -> PacketInfo {
        PacketInfo {
            src: src.into(),
            dst: dst.into(),
            transport: Transport::Tcp,
            src_port: Some(sp),
            dst_port: Some(dp),
            ttl: 64,
        }
    }

    fn scope(sel: ProcessSelector) -> ProcessScope {
        let own = Arc::new(OwnershipTable::new());
        own.refresh(
            &[
                sock(5000, 100),
                sock(5001, 101),
                sock(6000, 200),
                sock(7000, 999),
            ],
            DEFAULT_TTL,
        );
        let s = ProcessScope::new(sel, own, Arc::new([IpAddr::from(ME)].into()));
        s.update_pids(&procs());
        s
    }

    #[test]
    fn by_name_matches_all_instances_case_insensitively() {
        let s = scope(ProcessSelector::Name {
            name: "APP.EXE".into(),
        });
        assert_eq!(s.selected_pids(), vec![100, 101]);
        assert_eq!(
            s.classify(&pkt(ME, 5000, REMOTE, 443)),
            Verdict::Match(Direction::Out)
        );
        assert_eq!(
            s.classify(&pkt(REMOTE, 443, ME, 5001)),
            Verdict::Match(Direction::In)
        );
        assert_eq!(s.classify(&pkt(ME, 6000, REMOTE, 443)), Verdict::Skip);
    }

    #[test]
    fn by_pid_matches_only_that_pid() {
        let s = scope(ProcessSelector::Pid { pid: 101 });
        assert_eq!(s.classify(&pkt(ME, 5000, REMOTE, 443)), Verdict::Skip);
        assert_eq!(
            s.classify(&pkt(ME, 5001, REMOTE, 443)),
            Verdict::Match(Direction::Out)
        );
    }

    #[test]
    fn unknown_port_or_new_pid_is_pending() {
        let s = scope(ProcessSelector::Name {
            name: "app.exe".into(),
        });
        assert_eq!(s.classify(&pkt(ME, 5999, REMOTE, 443)), Verdict::Pending); // no owner yet
        assert_eq!(s.classify(&pkt(ME, 7000, REMOTE, 443)), Verdict::Pending); // pid 999 not in process list yet
        let g = s.generation();
        s.update_pids(
            &[
                procs(),
                vec![ProcessEntry {
                    pid: 999,
                    parent_pid: 1,
                    name: "app.exe".into(),
                }],
            ]
            .concat(),
        );
        assert!(s.generation() > g);
        assert_eq!(
            s.classify(&pkt(ME, 7000, REMOTE, 443)),
            Verdict::Match(Direction::Out)
        );
    }

    #[test]
    fn exited_process_keeps_its_ports_for_a_grace_period() {
        let s = scope(ProcessSelector::Name {
            name: "app.exe".into(),
        });
        // pid 100 exits: it leaves the process list.
        let remaining: Vec<ProcessEntry> = procs().into_iter().filter(|p| p.pid != 100).collect();
        s.update_pids(&remaining);
        assert_eq!(s.selected_pids(), vec![101], "UI shows live instances only");
        assert_eq!(
            s.classify(&pkt(REMOTE, 443, ME, 5000)),
            Verdict::Match(Direction::In),
            "trailing packet of the exited instance still counts"
        );
    }

    #[test]
    fn process_start_event_selects_before_any_list_refresh() {
        let s = scope(ProcessSelector::Name {
            name: "app.exe".into(),
        });
        s.ownership.note(Transport::Tcp, 7100, 555); // ETW connect: port 7100 -> pid 555
        assert_eq!(s.classify(&pkt(ME, 7100, REMOTE, 443)), Verdict::Pending);
        let g = s.generation();
        s.note_process_start(555, r"\Device\HarddiskVolume3\Tools\APP.EXE");
        assert!(s.generation() > g);
        assert_eq!(
            s.classify(&pkt(ME, 7100, REMOTE, 443)),
            Verdict::Match(Direction::Out)
        );
        // A non-matching new process becomes known (skipped, not held).
        s.ownership.note(Transport::Tcp, 7200, 556);
        s.note_process_start(556, r"C:\Windows\notepad.exe");
        assert_eq!(s.classify(&pkt(ME, 7200, REMOTE, 443)), Verdict::Skip);
    }

    #[test]
    fn detects_unknown_pids() {
        let s = scope(ProcessSelector::Name {
            name: "app.exe".into(),
        });
        assert!(!s.has_unknown([100, 200, 0]));
        assert!(s.has_unknown([100, 4242]));
    }

    #[test]
    fn non_local_and_portless_packets_skip() {
        let s = scope(ProcessSelector::Name {
            name: "app.exe".into(),
        });
        assert_eq!(s.classify(&pkt(REMOTE, 1, [8, 8, 8, 8], 2)), Verdict::Skip);
        let mut icmp = pkt(ME, 5000, REMOTE, 443);
        icmp.transport = Transport::Icmp;
        assert_eq!(s.classify(&icmp), Verdict::Skip);
    }
}

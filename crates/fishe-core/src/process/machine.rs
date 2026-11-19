//! All-traffic mode: every packet of this machine, labelled with the program
//! that owns its socket.
//!
//! Unlike [`ProcessScope`](super::scope::ProcessScope), nothing is filtered
//! out: a packet is always counted. The only question is *who*:
//!
//! - TCP/UDP with a known local-port owner → that PID, immediately;
//! - TCP/UDP whose port has no owner yet → [`Verdict::Pending`]: held (up to
//!   2 s) until the socket table or ETW names the owner, then counted as
//!   *unattributed* if nobody claims it;
//! - everything else (ICMP, IGMP, …) → counted, unattributed (no port, no owner).

use super::etw::EtwSink;
use super::ownership::OwnershipTable;
use super::processes::ProcessEntry;
use crate::monitor::stats::Direction;
use crate::monitor::target::Verdict;
use crate::net::parse::{PacketInfo, Transport};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

/// Names remembered per session (PIDs are never forgotten during a session,
/// so programs that exited keep their name in the Programs panel).
const MAX_NAMES: usize = 65_536;

#[derive(Debug)]
pub struct MachineScope {
    pub ownership: Arc<OwnershipTable>,
    /// Every address of this host (all adapters + loopback).
    pub local: Arc<HashSet<IpAddr>>,
    /// PID → executable file name (`chrome.exe`).
    names: RwLock<HashMap<u32, String>>,
}

impl MachineScope {
    pub fn new(ownership: Arc<OwnershipTable>, local: Arc<HashSet<IpAddr>>) -> Self {
        MachineScope {
            ownership,
            local,
            names: RwLock::default(),
        }
    }

    /// Sent when the source is this host, received otherwise (including
    /// broadcast/multicast from other hosts).
    pub fn direction(&self, info: &PacketInfo) -> Direction {
        if self.local.contains(&info.src) {
            Direction::Out
        } else {
            Direction::In
        }
    }

    /// Count the packet, with its owner when known.
    pub fn classify(&self, info: &PacketInfo) -> Verdict {
        let dir = self.direction(info);
        let port = match dir {
            Direction::Out => info.src_port,
            Direction::In => info.dst_port,
        };
        let (Some(port), Transport::Tcp | Transport::Udp) = (port, info.transport) else {
            return Verdict::Owned(dir, None);
        };
        match self.ownership.owner(info.transport, port) {
            Some(pid) => Verdict::Owned(dir, Some(pid)),
            None => Verdict::Pending,
        }
    }

    /// Changes when a pending packet might now have an owner.
    pub fn generation(&self) -> u64 {
        self.ownership.generation()
    }

    /// Learn names from a process list.
    pub fn update_names(&self, processes: &[ProcessEntry]) {
        let mut names = self.names.write().unwrap_or_else(|e| e.into_inner());
        if names.len() > MAX_NAMES {
            names.clear();
        }
        for p in processes {
            if names.get(&p.pid) != Some(&p.name) {
                names.insert(p.pid, p.name.clone());
            }
        }
    }

    /// Executable name of `pid`, if it was ever seen this session.
    pub fn name(&self, pid: u32) -> Option<String> {
        self.read().get(&pid).cloned()
    }

    /// Does any of these PIDs lack a name?
    pub fn has_unknown(&self, pids: impl IntoIterator<Item = u32>) -> bool {
        let names = self.read();
        pids.into_iter().any(|p| p != 0 && !names.contains_key(&p))
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<u32, String>> {
        self.names.read().unwrap_or_else(|e| e.into_inner())
    }
}

impl EtwSink for MachineScope {
    fn ownership(&self) -> &OwnershipTable {
        &self.ownership
    }
    fn local(&self) -> &HashSet<IpAddr> {
        &self.local
    }
    fn process_started(&self, pid: u32, image: &str) {
        let file = image.rsplit(['\\', '/']).next().unwrap_or(image);
        let mut names = self.names.write().unwrap_or_else(|e| e.into_inner());
        names.insert(pid, file.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ownership::DEFAULT_TTL;
    use crate::process::sockets::SocketEntry;

    const ME: [u8; 4] = [10, 0, 0, 2];
    const REMOTE: [u8; 4] = [93, 184, 216, 34];

    fn pkt(src: [u8; 4], sp: u16, dst: [u8; 4], dp: u16, t: Transport) -> PacketInfo {
        PacketInfo {
            src: src.into(),
            dst: dst.into(),
            transport: t,
            src_port: Some(sp),
            dst_port: Some(dp),
            ttl: 64,
        }
    }

    fn scope() -> MachineScope {
        let own = Arc::new(OwnershipTable::new());
        own.refresh(
            &[SocketEntry {
                transport: Transport::Tcp,
                local: std::net::SocketAddr::new(ME.into(), 5000),
                remote: None,
                pid: 100,
                listening: false,
            }],
            DEFAULT_TTL,
        );
        MachineScope::new(own, Arc::new([IpAddr::from(ME)].into()))
    }

    #[test]
    fn labels_every_packet() {
        let s = scope();
        assert_eq!(
            s.classify(&pkt(ME, 5000, REMOTE, 443, Transport::Tcp)),
            Verdict::Owned(Direction::Out, Some(100))
        );
        assert_eq!(
            s.classify(&pkt(REMOTE, 443, ME, 5000, Transport::Tcp)),
            Verdict::Owned(Direction::In, Some(100))
        );
        // No owner yet: wait for the socket table / ETW.
        assert_eq!(
            s.classify(&pkt(ME, 5999, REMOTE, 443, Transport::Tcp)),
            Verdict::Pending
        );
        // Not attributable at all: counted right away, without an owner.
        let mut icmp = pkt(REMOTE, 0, ME, 0, Transport::Icmp);
        icmp.src_port = None;
        icmp.dst_port = None;
        assert_eq!(s.classify(&icmp), Verdict::Owned(Direction::In, None));
        // Broadcast from another host is received.
        assert_eq!(
            s.direction(&pkt(REMOTE, 68, [255, 255, 255, 255], 67, Transport::Udp)),
            Direction::In
        );
    }

    #[test]
    fn names_from_list_and_process_start() {
        let s = scope();
        assert!(s.has_unknown([100]));
        s.update_names(&[ProcessEntry {
            pid: 100,
            parent_pid: 1,
            name: "app.exe".into(),
        }]);
        assert_eq!(s.name(100).as_deref(), Some("app.exe"));
        assert!(!s.has_unknown([100, 0]));
        s.process_started(200, r"\Device\HarddiskVolume3\Tools\curl.exe");
        assert_eq!(s.name(200).as_deref(), Some("curl.exe"));
    }
}

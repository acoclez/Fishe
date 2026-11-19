//! Shared `(transport, local port) → PID` table.
//!
//! Written by the socket-table poller (every tick) and, when elevated, by the
//! ETW tracker (instantly, on connect/accept/UDP I/O). Read by every capture
//! worker for every packet, so reads take a shared lock only.

use super::sockets::SocketEntry;
use crate::net::parse::Transport;
use std::collections::HashMap;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub type PortKey = (Transport, u16);

/// How long a mapping survives after its socket disappears. Covers trailing
/// packets (FIN/ACK, late UDP replies) that arrive after the socket closed.
pub const DEFAULT_TTL: Duration = Duration::from_secs(10);

/// PID Windows reports for sockets with no owning process (TIME_WAIT rows).
pub const NO_OWNER: u32 = 0;

#[derive(Debug, Clone, Copy)]
struct Owner {
    pid: u32,
    seen: Instant,
}

#[derive(Debug, Default)]
pub struct OwnershipTable {
    map: RwLock<HashMap<PortKey, Owner>>,
    generation: AtomicU64,
}

impl OwnershipTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// PID owning `port`, if known.
    pub fn owner(&self, transport: Transport, port: u16) -> Option<u32> {
        self.read().get(&(transport, port)).map(|o| o.pid)
    }

    /// Increments whenever a mapping is added or changes owner.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// How many ports are known.
    pub fn len(&self) -> usize {
        self.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.read().is_empty()
    }

    /// Record a single observation (used by ETW). Cheap when already known.
    pub fn note(&self, transport: Transport, port: u16, pid: u32) {
        if pid == NO_OWNER {
            return;
        }
        let key = (transport, port);
        if self.read().get(&key).is_some_and(|o| o.pid == pid) {
            return;
        }
        let mut map = self.write();
        let prev = map.insert(
            key,
            Owner {
                pid,
                seen: Instant::now(),
            },
        );
        if prev.is_none_or(|o| o.pid != pid) {
            self.generation.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// Merge a full socket-table snapshot and expire mappings unseen for `ttl`.
    ///
    /// Rows owned by PID 0 are ignored: those are TIME_WAIT leftovers of
    /// closed connections. Several can share a local port with a live
    /// connection, and letting them win would hand the port to "System Idle".
    pub fn refresh(&self, sockets: &[SocketEntry], ttl: Duration) {
        let now = Instant::now();
        let mut changed = false;
        let mut map = self.write();
        for s in sockets.iter().filter(|s| s.pid != NO_OWNER) {
            let owner = Owner {
                pid: s.pid,
                seen: now,
            };
            match map.insert((s.transport, s.local.port()), owner) {
                Some(prev) if prev.pid == s.pid => {}
                _ => changed = true,
            }
        }
        map.retain(|_, o| now.duration_since(o.seen) < ttl);
        if changed {
            self.generation.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<PortKey, Owner>> {
        self.map.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<PortKey, Owner>> {
        self.map.write().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(t: Transport, port: u16, pid: u32) -> SocketEntry {
        SocketEntry {
            transport: t,
            local: format!("10.0.0.2:{port}").parse().unwrap(),
            remote: None,
            pid,
            listening: false,
        }
    }

    #[test]
    fn refresh_and_lookup() {
        let t = OwnershipTable::new();
        t.refresh(
            &[
                entry(Transport::Tcp, 5000, 7),
                entry(Transport::Udp, 5000, 8),
            ],
            DEFAULT_TTL,
        );
        assert_eq!(t.owner(Transport::Tcp, 5000), Some(7));
        assert_eq!(t.owner(Transport::Udp, 5000), Some(8));
        assert_eq!(t.owner(Transport::Tcp, 5001), None);
    }

    #[test]
    fn generation_tracks_changes_only() {
        let t = OwnershipTable::new();
        let g0 = t.generation();
        t.refresh(&[entry(Transport::Tcp, 1, 1)], DEFAULT_TTL);
        let g1 = t.generation();
        assert!(g1 > g0);
        t.refresh(&[entry(Transport::Tcp, 1, 1)], DEFAULT_TTL);
        assert_eq!(t.generation(), g1, "unchanged snapshot must not bump");
        t.note(Transport::Tcp, 1, 1);
        assert_eq!(t.generation(), g1);
        t.note(Transport::Tcp, 1, 2); // port reused by another process
        assert!(t.generation() > g1);
        assert_eq!(t.owner(Transport::Tcp, 1), Some(2));
    }

    /// Regression from a live test: TIME_WAIT rows (PID 0) sharing a port with
    /// a live connection stole the port depending on row order.
    #[test]
    fn time_wait_rows_never_own_a_port() {
        for rows in [
            [
                entry(Transport::Tcp, 5000, 0),
                entry(Transport::Tcp, 5000, 42),
            ],
            [
                entry(Transport::Tcp, 5000, 42),
                entry(Transport::Tcp, 5000, 0),
            ],
        ] {
            let t = OwnershipTable::new();
            t.refresh(&rows, DEFAULT_TTL);
            assert_eq!(t.owner(Transport::Tcp, 5000), Some(42));
        }
        let t = OwnershipTable::new();
        t.note(Transport::Udp, 1, 0);
        assert_eq!(t.owner(Transport::Udp, 1), None);
    }

    #[test]
    fn expires_after_ttl() {
        let t = OwnershipTable::new();
        t.refresh(&[entry(Transport::Tcp, 1, 1)], DEFAULT_TTL);
        std::thread::sleep(Duration::from_millis(30));
        t.refresh(&[], Duration::from_millis(10));
        assert_eq!(t.owner(Transport::Tcp, 1), None);
        assert_eq!(t.len(), 0);
    }
}

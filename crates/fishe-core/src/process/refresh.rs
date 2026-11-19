//! Keeping the ownership data current while a session runs: the aggregator
//! calls one of these every tick (process mode / all-traffic mode). Both poll
//! the socket table and, when needed, the process list.

use super::machine::MachineScope;
use super::ownership::DEFAULT_TTL;
use super::scope::ProcessScope;
use super::{processes, sockets};
use std::collections::HashSet;
use std::time::{Duration, Instant};

/// All-traffic mode: minimum spacing of process-list refreshes triggered by
/// unnamed PIDs (an exited process stays unnamed; don't re-list every tick).
pub const NAME_REFRESH_MIN: Duration = Duration::from_millis(500);

/// Refresh socket ownership and (every few ticks) the PID set.
/// Returns the number of sockets owned by the selected PIDs.
///
/// The process list is also refreshed immediately whenever the socket table
/// shows a PID that didn't exist at the last refresh, so a short-lived
/// process is identified within one tick instead of waiting for the next
/// periodic refresh (it may be gone by then).
pub fn refresh_process(scope: &ProcessScope, refresh_pids: bool) -> u32 {
    let snap = match sockets::snapshot() {
        Ok(snap) => snap,
        Err(e) => {
            log::warn!("socket table failed: {e}");
            return 0;
        }
    };
    if refresh_pids || scope.has_unknown(snap.iter().map(|s| s.pid)) {
        match processes::list() {
            Ok(list) => scope.update_pids(&list),
            Err(e) => log::warn!("process list failed: {e}"),
        }
    }
    scope.ownership.refresh(&snap, DEFAULT_TTL);
    snap.iter().filter(|s| scope.is_selected(s.pid)).count() as u32
}

/// All-traffic mode: refresh socket ownership, and the process list when the
/// socket table (or `extra`, PIDs seen in packets) holds an unnamed PID.
/// Returns `(sockets, PIDs owning sockets)`.
pub fn refresh_machine(
    scope: &MachineScope,
    extra: &[u32],
    force_names: bool,
    last_names: &mut Option<Instant>,
) -> (u32, usize) {
    let snap = match sockets::snapshot() {
        Ok(snap) => snap,
        Err(e) => {
            log::warn!("socket table failed: {e}");
            return (0, 0);
        }
    };
    let unknown = scope.has_unknown(snap.iter().map(|s| s.pid).chain(extra.iter().copied()));
    let due = last_names.is_none_or(|t| t.elapsed() >= NAME_REFRESH_MIN);
    if force_names || (unknown && due) {
        *last_names = Some(Instant::now());
        match processes::list() {
            Ok(list) => scope.update_names(&list),
            Err(e) => log::warn!("process list failed: {e}"),
        }
    }
    scope.ownership.refresh(&snap, DEFAULT_TTL);
    let pids: HashSet<u32> = snap.iter().map(|s| s.pid).filter(|p| *p != 0).collect();
    (snap.len() as u32, pids.len())
}

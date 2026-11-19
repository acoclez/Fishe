//! Operations shared by the two front doors, the Tauri commands
//! (`commands.rs`) and the MCP tools (`mcp/tools.rs`): starting and stopping
//! sessions and recordings, probes, lookups. Both call these, so an agent's
//! `start_monitoring` and the Start button do exactly the same thing, and
//! the window learns about it the same way: session and recording changes go
//! out as [`MonitorEvent`](crate::monitor::events::MonitorEvent)s through the
//! window's subscription; pings and traces, which have their own stores,
//! send a "changed" [`Notice`] and the window reads them back.
//!
//! They work on a [`Services`] value, never on a window.
//!
//! Everything here may block (DNS, device enumeration, opening captures,
//! joining threads): callers run it on a blocking thread.

use crate::archive::recorder::{RecordOptions, RecordingInfo};
use crate::error::{AppError, AppResult};
use crate::geo::Owner;
use crate::monitor::{SessionInfo, StartRequest};
use crate::net::interfaces::{self, InterfaceInfo};
use crate::route::TraceResult;
use crate::route::ping::PingStatus;
use crate::services::{Notice, Services};
use std::net::IpAddr;

// ───────────────────────────── sessions ─────────────────────────────

/// Start a session (stopping the current one). The window gets `started`
/// through its subscription, whoever asked.
pub fn start_monitor(svc: &Services, req: StartRequest) -> AppResult<SessionInfo> {
    svc.monitor.start(req, svc.geo.clone())
}

/// Stop the running session. `true` if one was running.
pub fn stop_monitor(svc: &Services) -> bool {
    svc.monitor.stop()
}

/// Record the running session into the archive.
pub fn start_recording(svc: &Services, opts: RecordOptions) -> AppResult<RecordingInfo> {
    svc.monitor.start_recording(&svc.archive, opts)
}

/// Stop the recording; what was saved, or `None` if nothing was recording.
pub fn stop_recording(svc: &Services) -> Option<RecordingInfo> {
    svc.monitor.stop_recording()
}

// ───────────────────────────── archive ─────────────────────────────

/// Run `f` on the archive database.
pub fn with_archive<T>(
    svc: &Services,
    f: impl FnOnce(&rusqlite::Connection) -> AppResult<T>,
) -> AppResult<T> {
    let conn = svc.archive.conn()?;
    f(&conn)
}

// ───────────────────────────── network ─────────────────────────────

/// Every capture interface.
pub fn list_interfaces() -> AppResult<Vec<InterfaceInfo>> {
    Ok(interfaces::list_devices()?
        .iter()
        .map(InterfaceInfo::from)
        .collect())
}

/// Parse a probe target (trace / ping): an IP literal that can be sent to.
pub fn probe_target(ip: &str) -> AppResult<IpAddr> {
    let target: IpAddr = ip
        .trim()
        .parse()
        .map_err(|_| AppError::InvalidTarget(ip.to_string()))?;
    if target.is_unspecified()
        || target.is_multicast()
        || matches!(target, IpAddr::V4(v4) if v4.is_broadcast())
    {
        return Err(AppError::InvalidTarget(ip.to_string()));
    }
    Ok(target)
}

/// Traceroute (ICMP probes; ~2–10 s). Cached for 10 minutes unless `force`.
/// Only ever called from an explicit user or agent action.
pub fn trace_route(svc: &Services, target: IpAddr, force: bool) -> TraceResult {
    let t = svc.traces.trace(target, force, Some(&svc.geo));
    svc.notify(Notice::TracesChanged);
    t
}

/// Ping `target` once per second (ICMP), at most 4 at once, 30 min each.
pub fn ping_start(svc: &Services, target: IpAddr) -> AppResult<PingStatus> {
    let st = svc.pings.start(target)?;
    svc.notify(Notice::PingsChanged);
    Ok(st)
}

/// Stop pinging `target` (its figures stay). `true` if it was running.
pub fn ping_stop(svc: &Services, target: IpAddr) -> bool {
    let stopped = svc.pings.stop(target);
    svc.notify(Notice::PingsChanged);
    stopped
}

/// Forget a ping target (stopping it if needed).
pub fn ping_remove(svc: &Services, target: IpAddr) {
    svc.pings.remove(target);
    svc.notify(Notice::PingsChanged);
}

/// Network owner and country of one address. May queue an online lookup.
pub fn owner(svc: &Services, ip: IpAddr) -> Option<Owner> {
    svc.geo.owner(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_targets_are_sendable_addresses() {
        assert_eq!(
            probe_target(" 1.1.1.1 ").unwrap(),
            IpAddr::from([1, 1, 1, 1])
        );
        assert!(probe_target("2606:4700::1111").is_ok());
        for bad in [
            "",
            "example.com",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "::",
        ] {
            assert!(
                matches!(probe_target(bad), Err(AppError::InvalidTarget(_))),
                "{bad:?}"
            );
        }
    }
}

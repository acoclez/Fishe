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
use crate::lan::{self, ScanResult};
use crate::monitor::{SessionInfo, StartRequest};
use crate::net::interfaces::{self, InterfaceInfo};
use crate::process::{processes, sockets};
use crate::route::TraceResult;
use crate::route::ping::PingStatus;
use crate::security::{self, SecurityReport};
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

/// Scan the local networks (ARP requests, one DHCP discovery, optionally a
/// few TCP ports per device; a few seconds). Only ever called from an explicit user action.
/// The devices found are remembered, and marked when they were not there at
/// the previous scan.
pub fn scan_lan(svc: &Services, probe_ports: bool) -> AppResult<ScanResult> {
    let mut scan = lan::scan(probe_ports)?;
    svc.lan.record(&mut scan, crate::util::now_ms() as i64);
    Ok(scan)
}

/// Forget the devices remembered from LAN scans.
pub fn lan_forget(svc: &Services) -> AppResult<()> {
    svc.lan
        .forget()
        .map_err(|e| AppError::io("cannot delete the device inventory", e))
}

// ───────────────────────────── security ─────────────────────────────

/// The security view: what the running all-traffic session saw, the
/// programs accepting connections right now, the local networks scanned so
/// far, and what in all that deserves attention. Sends nothing: owners
/// come from the local database and from lookups already made.
pub fn security_report(svc: &Services) -> SecurityReport {
    let (state, facts, names) = svc.monitor.security();
    let sockets = sockets::snapshot()
        .map(|sockets| {
            // The names of the programs behind them; without them the
            // table still lists the PIDs.
            let names = processes::list()
                .map(|list| list.into_iter().map(|p| (p.pid, p.name)).collect())
                .unwrap_or_default();
            (sockets, names)
        })
        .map_err(|e| e.to_string());
    let (ifaces, source_v4, source_v6) = security::vpn::system();
    security::report(security::Sources {
        state,
        facts,
        names: names.as_deref(),
        geo: &svc.geo,
        sockets,
        inventory: &svc.lan.inventory(),
        ifaces,
        source_v4,
        source_v6,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real all-traffic session, from capture to the security report:
    /// this test opens an unencrypted HTTP connection, asks a public DNS
    /// server in clear text and listens on a port, then reads what the
    /// report says about it. `FISHE_LIVE_SECS` (default 6) is how long the
    /// session runs; while it does, another machine may try this one's
    /// ports to see them listed as inbound attempts (`FISHE_LIVE_PORT`
    /// fixes the port this test listens on, so that machine can connect).
    /// `FISHE_LIVE_DHCP` makes the test ask the network for its DHCP
    /// servers during the session, to see their answers heard; with
    /// `FISHE_LIVE_OUTSIDE` (addresses routed around a VPN tunnel) it sends
    /// a datagram to each, to see them reported as outside the tunnel.
    /// `cargo test -p fishe-core -- --ignored live_security_report --nocapture`
    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    #[ignore = "captures on every interface and sends a little traffic"]
    fn live_security_report() {
        use crate::monitor::target::TargetSpec;
        use crate::monitor::{NamingOptions, StartRequest};
        use crate::paths::Paths;
        use crate::security::SessionState;
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
        use std::time::Duration;

        crate::npcap::ensure_available().expect("capture available");
        let dir = std::env::temp_dir().join(format!("fishe-live-sec-{}", std::process::id()));
        let svc = Services::new(Paths::at(dir.clone()));
        let before = security_report(&svc);
        assert_eq!(before.state, SessionState::NoSession);
        assert!(before.session.is_none());

        let wanted: u16 = std::env::var("FISHE_LIVE_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(0);
        let listener = TcpListener::bind(("0.0.0.0", wanted)).unwrap();
        let port = listener.local_addr().unwrap().port();
        start_monitor(
            &svc,
            StartRequest {
                target: TargetSpec::All,
                interface: None,
                gauge: None,
                tick_ms: None,
                naming: NamingOptions {
                    sniff: true,
                    reverse_dns: false,
                },
            },
        )
        .expect("session starts");
        std::thread::sleep(Duration::from_millis(1200));

        // Unencrypted HTTP, kept open long enough to be attributed.
        let web = ("example.com", 80)
            .to_socket_addrs()
            .unwrap()
            .find(|a| a.is_ipv4());
        let mut http =
            web.and_then(|a| TcpStream::connect_timeout(&a, Duration::from_secs(4)).ok());
        if let Some(s) = &mut http {
            let _ = s.write_all(
                b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n",
            );
            let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
            let _ = s.read(&mut [0u8; 2048]);
        }
        // A DNS question in clear text to a public server: example.com, A.
        let dns = UdpSocket::bind("0.0.0.0:0").unwrap();
        let query = b"\x51\x7a\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
        let _ = dns.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = dns.send_to(query, "8.8.8.8:53");
        let _ = dns.recv(&mut [0u8; 512]);

        // A little traffic for the tunnel (if the route goes through one)…
        let _ = dns.send_to(b"fishe-live", "1.1.1.1:9");
        let _ = dns.send_to(b"fishe-live", "1.0.0.1:9");
        // …and for the addresses that are routed around it.
        for outside in std::env::var("FISHE_LIVE_OUTSIDE")
            .unwrap_or_default()
            .split(',')
            .filter(|a| !a.is_empty())
        {
            let _ = dns.send_to(b"fishe-live", (outside, 9));
        }
        if std::env::var_os("FISHE_LIVE_DHCP").is_some()
            && let Some(iface) = crate::lan::adapters::list()
                .into_iter()
                .find(|i| i.gateway.is_some())
        {
            let found = crate::lan::dhcp::discover(&iface).expect("DHCP discovery runs");
            println!(
                "asked on {}: {} DHCP server(s) answered",
                iface.name,
                found.len()
            );
        }

        let secs: u64 = std::env::var("FISHE_LIVE_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(6);
        std::thread::sleep(Duration::from_secs(secs));

        let report = security_report(&svc);
        stop_monitor(&svc);
        let http_done = http.is_some();
        drop((http, listener));
        std::fs::remove_dir_all(&dir).ok();

        let s = report
            .session
            .as_ref()
            .expect("an all-traffic session is audited");
        println!(
            "state {:?}, {} ms, {} programs",
            report.state, s.t_ms, s.program_count
        );
        for f in &report.findings {
            println!("  [{:?}] {}  {:?}", f.severity, f.title, f.subjects);
        }
        for p in s.programs.iter().filter(|p| !p.plaintext.is_empty()) {
            for u in &p.plaintext {
                println!(
                    "  plain: {} {} {} B, {} endpoint(s)",
                    p.name, u.service, u.bytes, u.endpoint_count
                );
            }
        }
        for d in &s.dns.servers {
            println!(
                "  dns: {} {} q, {} answered, {} unanswered, avg {:?} ms",
                d.ip, d.queries, d.answered, d.unanswered, d.avg_ms
            );
        }
        for p in &s.inbound {
            println!(
                "  inbound: {} ports {:?} (+{}), {} attempts, {} accepted on {:?}, scan {}",
                p.ip,
                p.ports,
                (p.port_count as usize).saturating_sub(p.ports.len()),
                p.attempts,
                p.accepted,
                p.accepted_ports,
                p.scan
            );
        }
        for d in &s.dhcp {
            println!(
                "  dhcp heard: {} on {} ({:?}), {} answer(s), gateway {:?}, dns {:?}",
                d.server, d.interface, d.mac, d.replies, d.router, d.dns
            );
        }
        let v = &report.vpn;
        println!(
            "  vpn: {} tunnel(s) {:?}; ipv4 {:?} via {:?}; ipv6 {:?} via {:?}; error {:?}",
            v.tunnels.len(),
            v.tunnels
                .iter()
                .map(|t| format!("{} ({})", t.description, t.kind))
                .collect::<Vec<_>>(),
            v.ipv4.via,
            v.ipv4.interface,
            v.ipv6.via,
            v.ipv6.interface,
            v.error
        );
        if v.measured {
            println!(
                "  vpn measured: inside {} B, outside {} B, carrier {:?}, {} other(s) {:?}, {} DNS outside",
                v.inside_bytes,
                v.outside_bytes,
                v.carrier.as_ref().map(|c| c.ip),
                v.outside_count,
                v.outside.iter().map(|e| e.ip).collect::<Vec<_>>(),
                v.dns_outside
            );
        }
        println!(
            "  listeners: {} ({} reachable) {:?}",
            report.listeners.len(),
            report
                .listeners
                .iter()
                .filter(|l| l.reach == crate::security::Reach::Network)
                .count(),
            report.listeners_error
        );

        assert_eq!(report.state, SessionState::Auditing);
        assert!(
            report
                .listeners
                .iter()
                .any(|l| l.port == port && l.reach == crate::security::Reach::Network),
            "our own listening port {port} is listed: {:?}",
            report.listeners
        );
        // (When the route to it is a tunnel with nobody at the other end, no connection.)
        if http_done {
            assert!(
                s.programs
                    .iter()
                    .any(|p| p.plaintext.iter().any(|u| u.port == 80 && u.bytes > 0)),
                "the HTTP exchange is reported as unencrypted"
            );
        }
        let google = s
            .dns
            .servers
            .iter()
            .find(|d| d.ip == IpAddr::from([8, 8, 8, 8]));
        assert!(
            google.is_some_and(|d| d.queries >= 1),
            "the DNS question was seen: {:?}",
            s.dns.servers
        );
    }

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

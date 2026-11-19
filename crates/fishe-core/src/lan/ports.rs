//! A light TCP "connect" probe of a handful of well-known ports, to hint at
//! what a device is (a printer, a NAS, a camera, a PC). It opens a normal
//! connection and closes it at once — the same thing a browser does — so it
//! finds only services the device already offers to the LAN. UDP-only
//! services (mDNS, SSDP) are out of scope.

use crate::util::par_for_each;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::Mutex;
use std::time::Duration;

/// How long to wait for a connection before giving up on a port.
const TIMEOUT: Duration = Duration::from_millis(400);
/// Parallel connections across the whole sweep (connects are I/O-bound).
const WORKERS: usize = 128;

/// Ports worth knowing about on a home or office network, with the service
/// they usually mean. Kept short on purpose: this is identification, not an
/// audit.
pub const COMMON: &[(u16, &str)] = &[
    (22, "SSH"),
    (53, "DNS"),
    (80, "HTTP"),
    (139, "NetBIOS"),
    (443, "HTTPS"),
    (445, "SMB"),
    (515, "Printer (LPD)"),
    (548, "Apple file sharing"),
    (554, "RTSP (camera)"),
    (631, "Printer (IPP)"),
    (1883, "MQTT"),
    (3389, "Remote Desktop"),
    (5000, "Web / UPnP"),
    (8080, "Web (alt)"),
    (8443, "HTTPS (alt)"),
    (9100, "Printer (raw)"),
    (32400, "Plex"),
    (62078, "iPhone sync"),
];

/// The service label for a port, if we name it.
pub fn service(port: u16) -> Option<&'static str> {
    COMMON.iter().find(|&&(p, _)| p == port).map(|&(_, s)| s)
}

/// Probe [`COMMON`] on every address in `ips`; returns the open ports of each
/// address that had any, sorted ascending.
pub fn probe(ips: &[Ipv4Addr]) -> HashMap<Ipv4Addr, Vec<u16>> {
    if ips.is_empty() {
        return HashMap::new();
    }
    let jobs: Vec<(Ipv4Addr, u16)> = ips
        .iter()
        .flat_map(|&ip| COMMON.iter().map(move |&(p, _)| (ip, p)))
        .collect();
    let open: Mutex<HashMap<Ipv4Addr, Vec<u16>>> = Mutex::new(HashMap::new());
    par_for_each(&jobs, WORKERS, |&(ip, port)| {
        if TcpStream::connect_timeout(&SocketAddr::from((ip, port)), TIMEOUT).is_ok() {
            open.lock()
                .unwrap_or_else(|e| e.into_inner())
                .entry(ip)
                .or_default()
                .push(port);
        }
    });
    let mut map = open.into_inner().unwrap_or_else(|e| e.into_inner());
    for v in map.values_mut() {
        v.sort_unstable();
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_probes_nothing() {
        assert!(probe(&[]).is_empty());
    }

    #[test]
    fn service_names_are_known_only_for_listed_ports() {
        assert_eq!(service(443), Some("HTTPS"));
        assert_eq!(service(9100), Some("Printer (raw)"));
        assert_eq!(service(12345), None);
    }
}

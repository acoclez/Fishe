//! LAN mapping: find the devices on the local network(s) this PC is on and
//! describe each one.
//!
//! A scan runs only when the UI asks for it (like a traceroute), because it
//! sends packets:
//!
//! - [`adapters`] lists the IPv4 networks this PC is on.
//! - [`arp`] broadcasts "who has <ip>?" for every address of a network and
//!   collects the replies — the devices that are switched on and answer.
//! - [`oui`] turns each device's MAC into the vendor that registered it.
//! - [`ports`] opens and closes a connection to a few well-known ports to
//!   hint at what the device is.
//!
//! - [`dhcp`] broadcasts one DHCPDISCOVER and lists the servers that offer
//!   an address (it never accepts one).
//! - [`inventory`] remembers the devices between scans, so a scan can say
//!   who is new and whether the gateway is the one seen before.
//!
//! Reverse-DNS names come from the OS resolver. See `docs/lan-mapping.md`.

pub mod adapters;
pub mod arp;
pub mod dhcp;
pub mod inventory;
pub mod oui;
pub mod ports;

use crate::error::{AppError, AppResult};
use crate::naming::rdns;
use crate::util::par_for_each;
use adapters::LanInterface;
use serde::Serialize;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;
use std::time::Instant;

/// One open port on a device, with the service it usually means.
#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct OpenPort {
    pub port: u16,
    pub service: Option<&'static str>,
}

/// A device discovered on the LAN.
#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(rename = "LanDevice", rename_all = "camelCase")]
pub struct Device {
    pub ip: Ipv4Addr,
    /// "aa:bb:cc:dd:ee:ff"; absent only when it could not be determined.
    pub mac: Option<String>,
    /// Vendor from the MAC's registered prefix, when known and not randomised.
    pub vendor: Option<String>,
    /// Reverse-DNS (PTR) name, when the device has one.
    pub hostname: Option<String>,
    /// The MAC is locally administered (a privacy-randomised address).
    pub randomized_mac: bool,
    pub is_gateway: bool,
    /// This PC itself.
    pub is_self: bool,
    /// Not seen in earlier scans of this network (never set on the first
    /// scan of a network, when everything is new).
    pub is_new: bool,
    /// When a scan first saw this device (Unix ms).
    pub first_seen: Option<i64>,
    pub ports: Vec<OpenPort>,
}

/// One local network and the devices found on it.
#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(rename = "LanNetwork", rename_all = "camelCase")]
pub struct Network {
    /// Friendly adapter name, e.g. "Wi-Fi".
    pub interface: String,
    pub description: String,
    /// This PC's address on this network.
    pub ip: Ipv4Addr,
    pub prefix: u8,
    pub gateway: Option<Ipv4Addr>,
    pub wireless: bool,
    /// A network larger than a /22 was swept around this PC's own /24.
    pub narrowed: bool,
    pub devices: Vec<Device>,
    /// The DHCP servers that answered on this network. More than one is
    /// worth a look.
    pub dhcp: Vec<dhcp::DhcpServer>,
}

#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(rename = "LanScan", rename_all = "camelCase")]
pub struct ScanResult {
    pub networks: Vec<Network>,
    pub duration_ms: u64,
    pub probed_ports: bool,
    /// A short human note when something was skipped or narrowed.
    pub note: Option<String>,
}

/// Scan every local network with a gateway. `probe_ports` adds the TCP port
/// probe; without it only addresses, MACs, vendors and names are collected.
pub fn scan(probe_ports: bool) -> AppResult<ScanResult> {
    crate::npcap::ensure_available()?;
    let started = Instant::now();

    let ifaces: Vec<LanInterface> = adapters::list()
        .into_iter()
        .filter(|i| i.gateway.is_some())
        .collect();
    if ifaces.is_empty() {
        return Err(AppError::NoRoute(
            "the local network (no network adapter with a gateway)".into(),
        ));
    }

    let mut networks = Vec::new();
    let mut narrowed_any = false;
    for iface in &ifaces {
        let (hosts, narrowed) = adapters::sweep_hosts(iface);
        narrowed_any |= narrowed;
        // The DHCP question waits for answers while the sweep runs.
        let (found, servers) = std::thread::scope(|s| {
            let asking = s.spawn(|| dhcp::discover(iface));
            let found = arp::sweep(iface, &hosts);
            (found, asking.join().unwrap_or_else(|_| Ok(Vec::new())))
        });
        let mut network = build_network(iface, found?, narrowed, probe_ports);
        // The scan is still good without it.
        network.dhcp = servers.unwrap_or_else(|e| {
            log::warn!("DHCP discovery on {} failed: {e}", iface.name);
            Vec::new()
        });
        networks.push(network);
    }

    let note = narrowed_any.then(|| {
        "A network larger than 1022 addresses was scanned around this PC only.".to_string()
    });
    Ok(ScanResult {
        networks,
        duration_ms: started.elapsed().as_millis() as u64,
        probed_ports: probe_ports,
        note,
    })
}

/// Assemble one network's device list from the ARP results, adding this PC
/// and the gateway, then enrich with vendor, name and (optionally) ports.
fn build_network(
    iface: &LanInterface,
    found: Vec<(Ipv4Addr, [u8; 6])>,
    narrowed: bool,
    probe_ports: bool,
) -> Network {
    // ip -> MAC, keeping the first seen. Start with the discovered devices.
    let mut macs: HashMap<Ipv4Addr, [u8; 6]> = HashMap::new();
    let mut order: Vec<Ipv4Addr> = Vec::new();
    for (ip, mac) in found {
        if macs.insert(ip, mac).is_none() {
            order.push(ip);
        }
    }
    // The gateway, even if it stayed silent to the sweep.
    if let Some(gw) = iface.gateway
        && !macs.contains_key(&gw)
    {
        order.push(gw);
    }

    // Addresses to look up names for and (optionally) probe: everything found
    // plus the gateway, but not this PC.
    let others: Vec<Ipv4Addr> = order.clone();
    let names = hostnames(&others);
    let open = if probe_ports {
        ports::probe(&others)
    } else {
        HashMap::new()
    };

    let mut devices: Vec<Device> = order
        .into_iter()
        .map(|ip| {
            let mac = macs.get(&ip).copied();
            Device {
                ip,
                mac: mac.map(|m| oui::format_mac(&m)),
                vendor: mac.and_then(|m| oui::vendor(&m).map(str::to_string)),
                hostname: names.get(&ip).cloned(),
                randomized_mac: mac.is_some_and(|m| oui::is_randomized(&m)),
                is_gateway: Some(ip) == iface.gateway,
                is_self: false,
                is_new: false,
                first_seen: None,
                ports: open
                    .get(&ip)
                    .map(|ps| {
                        ps.iter()
                            .map(|&p| OpenPort {
                                port: p,
                                service: ports::service(p),
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            }
        })
        .collect();

    // This PC, from its own adapter (never swept or probed).
    devices.push(Device {
        ip: iface.ip,
        mac: Some(oui::format_mac(&iface.mac)),
        vendor: oui::vendor(&iface.mac).map(str::to_string),
        hostname: None,
        randomized_mac: oui::is_randomized(&iface.mac),
        is_gateway: false,
        is_self: true,
        is_new: false,
        first_seen: None,
        ports: Vec::new(),
    });

    // Gateway first, then this PC, then the rest by address.
    devices.sort_by_key(|d| (!d.is_gateway, !d.is_self, u32::from(d.ip)));

    Network {
        interface: iface.name.clone(),
        description: iface.description.clone(),
        ip: iface.ip,
        prefix: iface.prefix,
        gateway: iface.gateway,
        wireless: iface.wireless,
        narrowed,
        devices,
        dhcp: Vec::new(),
    }
}

/// Reverse-DNS names for `ips`, resolved in parallel (each lookup can block
/// for seconds on a device with no PTR record).
fn hostnames(ips: &[Ipv4Addr]) -> HashMap<Ipv4Addr, String> {
    let out: Mutex<HashMap<Ipv4Addr, String>> = Mutex::new(HashMap::new());
    par_for_each(ips, 32, |&ip| {
        if let Some(name) = rdns::lookup(IpAddr::V4(ip)) {
            out.lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(ip, name);
        }
    });
    out.into_inner().unwrap_or_else(|e| e.into_inner())
}

//! Capture interface discovery and automatic selection.

use crate::error::{AppError, AppResult};
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};

/// A capture interface as shown in the UI.
#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct InterfaceInfo {
    /// Npcap device name, e.g. `\Device\NPF_{GUID}`. Used as the identifier.
    pub name: String,
    /// Adapter description, e.g. `Intel(R) Wi-Fi 6 AX201 160MHz`.
    pub description: String,
    pub addresses: Vec<String>,
    pub is_up: bool,
    pub is_running: bool,
    pub is_loopback: bool,
    pub is_wireless: bool,
}

impl From<&pcap::Device> for InterfaceInfo {
    fn from(d: &pcap::Device) -> Self {
        InterfaceInfo {
            name: d.name.clone(),
            description: d.desc.clone().unwrap_or_else(|| d.name.clone()),
            addresses: d.addresses.iter().map(|a| a.addr.to_string()).collect(),
            is_up: d.flags.is_up(),
            is_running: d.flags.is_running(),
            is_loopback: is_loopback(d),
            is_wireless: d.flags.is_wireless(),
        }
    }
}

/// All capture devices known to Npcap/libpcap.
pub fn list_devices() -> AppResult<Vec<pcap::Device>> {
    crate::npcap::ensure_available()?;
    Ok(pcap::Device::list()?)
}

/// Find a device by its exact name.
pub fn find_device(name: &str) -> AppResult<pcap::Device> {
    list_devices()?
        .into_iter()
        .find(|d| d.name == name)
        .ok_or_else(|| AppError::InterfaceNotFound(name.to_string()))
}

/// The local address the OS would use to reach `target`.
///
/// Uses the "connected UDP socket" trick: `connect` on a UDP socket only
/// performs a route lookup, no packet is sent.
pub fn route_source(target: IpAddr) -> Option<IpAddr> {
    let bind: IpAddr = match target {
        IpAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
        IpAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
    };
    let socket = UdpSocket::bind((bind, 0)).ok()?;
    socket.connect((target, 9)).ok()?;
    let local = socket.local_addr().ok()?.ip();
    (!local.is_unspecified()).then_some(local)
}

/// Choose the interface traffic to `target` will flow through.
///
/// 1. Loopback targets → the Npcap loopback adapter.
/// 2. The adapter owning the route's source address.
/// 3. Fallback: first up/running, non-loopback adapter that has an address.
pub fn pick_for(target: IpAddr, devices: &[pcap::Device]) -> Option<pcap::Device> {
    if target.is_loopback() {
        return devices.iter().find(|d| is_loopback(d)).cloned();
    }

    if let Some(source) = route_source(target)
        && let Some(d) = devices
            .iter()
            .find(|d| d.addresses.iter().any(|a| a.addr == source))
    {
        return Some(d.clone());
    }

    devices
        .iter()
        .find(|d| {
            d.flags.is_up() && d.flags.is_running() && !is_loopback(d) && !d.addresses.is_empty()
        })
        .cloned()
}

/// Every interface worth capturing on in process mode: adapters that are up,
/// running and have an address, plus the loopback adapter.
pub fn active_devices(devices: &[pcap::Device]) -> Vec<pcap::Device> {
    devices
        .iter()
        .filter(|d| {
            if is_loopback(d) {
                d.flags.is_up()
            } else {
                d.flags.is_up() && d.flags.is_running() && !d.addresses.is_empty()
            }
        })
        .cloned()
        .collect()
}

pub fn is_loopback(d: &pcap::Device) -> bool {
    d.flags.is_loopback() || d.name.to_ascii_lowercase().contains("loopback")
}

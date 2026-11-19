//! The local side of the map: default gateways and LAN neighbours.

use serde::Serialize;
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Gateway {
    pub ip: IpAddr,
    pub interface_index: u32,
    pub metric: u32,
}

#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Neighbor {
    pub ip: IpAddr,
    /// "aa:bb:cc:dd:ee:ff"
    pub mac: String,
    /// "reachable" | "stale" | "delay" | "probe" | "permanent"
    pub state: &'static str,
    pub interface_index: u32,
}

#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct NetContext {
    pub gateways: Vec<Gateway>,
    pub neighbors: Vec<Neighbor>,
}

#[cfg(windows)]
pub use win::context;

#[cfg(not(windows))]
pub fn context() -> NetContext {
    NetContext {
        gateways: vec![],
        neighbors: vec![],
    }
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::net::Ipv6Addr;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIpForwardTable2, GetIpNetTable2, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
        MIB_IPNET_ROW2, MIB_IPNET_TABLE2,
    };
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, NlnsDelay, NlnsPermanent, NlnsProbe, NlnsReachable,
        NlnsStale, SOCKADDR_INET,
    };

    fn ip_of(sa: &SOCKADDR_INET) -> Option<IpAddr> {
        // SAFETY: the family tag says which union member is valid.
        unsafe {
            match sa.si_family {
                AF_INET => Some(IpAddr::V4(crate::util::ipv4_from_ne(
                    sa.Ipv4.sin_addr.S_un.S_addr,
                ))),
                AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(sa.Ipv6.sin6_addr.u.Byte))),
                _ => None,
            }
        }
    }

    pub fn context() -> NetContext {
        NetContext {
            gateways: gateways(),
            neighbors: neighbors(),
        }
    }

    fn gateways() -> Vec<Gateway> {
        let mut out = Vec::new();
        // SAFETY: table allocated by the API and freed with FreeMibTable.
        unsafe {
            let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
            if GetIpForwardTable2(AF_UNSPEC, &mut table) != 0 || table.is_null() {
                return out;
            }
            let n = (*table).NumEntries as usize;
            let rows: &[MIB_IPFORWARD_ROW2] =
                std::slice::from_raw_parts(std::ptr::addr_of!((*table).Table).cast(), n);
            for r in rows {
                if r.DestinationPrefix.PrefixLength != 0 {
                    continue;
                }
                if let Some(ip) = ip_of(&r.NextHop).filter(|ip| !ip.is_unspecified()) {
                    out.push(Gateway {
                        ip,
                        interface_index: r.InterfaceIndex,
                        metric: r.Metric,
                    });
                }
            }
            FreeMibTable(table.cast());
        }
        out.sort_by_key(|g| g.metric);
        out.dedup_by_key(|g| g.ip);
        out
    }

    #[allow(non_upper_case_globals)] // Windows constant names used as patterns
    fn neighbors() -> Vec<Neighbor> {
        let mut out = Vec::new();
        // SAFETY: as above.
        unsafe {
            let mut table: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();
            if GetIpNetTable2(AF_UNSPEC, &mut table) != 0 || table.is_null() {
                return out;
            }
            let n = (*table).NumEntries as usize;
            let rows: &[MIB_IPNET_ROW2] =
                std::slice::from_raw_parts(std::ptr::addr_of!((*table).Table).cast(), n);
            for r in rows {
                let state = match r.State {
                    NlnsReachable => "reachable",
                    NlnsStale => "stale",
                    NlnsDelay => "delay",
                    NlnsProbe => "probe",
                    NlnsPermanent => "permanent",
                    _ => continue,
                };
                let Some(ip) = ip_of(&r.Address) else {
                    continue;
                };
                let len = (r.PhysicalAddressLength as usize).min(r.PhysicalAddress.len());
                let mac = &r.PhysicalAddress[..len];
                // Skip multicast/broadcast entries and incomplete ones.
                if ip.is_multicast()
                    || mac.is_empty()
                    || mac.iter().all(|&b| b == 0)
                    || mac.iter().all(|&b| b == 0xFF)
                {
                    continue;
                }
                if let IpAddr::V4(v4) = ip
                    && (v4.is_broadcast() || v4.octets()[3] == 255)
                {
                    continue;
                }
                let mac = crate::util::format_mac(mac);
                out.push(Neighbor {
                    ip,
                    mac,
                    state,
                    interface_index: r.InterfaceIndex,
                });
            }
            FreeMibTable(table.cast());
        }
        out
    }
}

#[cfg(all(test, windows))]
mod tests {
    #[test]
    fn reads_tables() {
        let c = super::context();
        println!("gateways: {:?}", c.gateways);
        println!("neighbours: {}", c.neighbors.len());
        // Every neighbour has a unicast address and a MAC.
        assert!(
            c.neighbors
                .iter()
                .all(|n| !n.ip.is_multicast() && n.mac.len() >= 11)
        );
    }
}

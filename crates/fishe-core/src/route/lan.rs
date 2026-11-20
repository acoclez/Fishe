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

#[cfg(not(any(windows, target_os = "linux")))]
pub fn context() -> NetContext {
    NetContext {
        gateways: vec![],
        neighbors: vec![],
    }
}

/// Is this neighbour entry a device (not a multicast or broadcast mapping,
/// not an unresolved one)?
#[cfg_attr(not(any(windows, target_os = "linux", test)), allow(dead_code))]
fn is_device(ip: IpAddr, mac: &[u8]) -> bool {
    if ip.is_multicast()
        || mac.is_empty()
        || mac.iter().all(|&b| b == 0)
        || mac.iter().all(|&b| b == 0xFF)
    {
        return false;
    }
    !matches!(ip, IpAddr::V4(v4) if v4.is_broadcast() || v4.octets()[3] == 255)
}

/// The same two tables from the kernel's routing socket.
#[cfg(target_os = "linux")]
pub fn context() -> NetContext {
    use super::netlink::{self, RTM_GETNEIGH, RTM_GETROUTE, RTM_NEWNEIGH, RTM_NEWROUTE};

    let mut gateways: Vec<Gateway> =
        netlink::table(RTM_GETROUTE, RTM_NEWROUTE, netlink::default_route)
            .into_iter()
            .map(|r| Gateway {
                ip: r.gateway,
                interface_index: r.index,
                metric: r.metric,
            })
            .collect();
    gateways.sort_by_key(|g| g.metric);
    gateways.dedup_by_key(|g| g.ip);

    let neighbors = netlink::table(RTM_GETNEIGH, RTM_NEWNEIGH, netlink::neigh)
        .into_iter()
        .filter(|n| is_device(n.ip, &n.mac))
        .map(|n| Neighbor {
            ip: n.ip,
            mac: crate::util::format_mac(&n.mac),
            state: n.state,
            interface_index: n.index,
        })
        .collect();
    NetContext {
        gateways,
        neighbors,
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
                if !is_device(ip, mac) {
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

#[cfg(test)]
mod filter_tests {
    use super::is_device;

    #[test]
    fn only_devices_are_neighbours() {
        let mac = [0xc8, 0x7f, 0x2b, 0x35, 0x1a, 0xc0];
        assert!(is_device("192.168.1.1".parse().unwrap(), &mac));
        assert!(is_device("fe80::1".parse().unwrap(), &mac));
        assert!(!is_device("224.0.0.251".parse().unwrap(), &mac));
        assert!(!is_device("ff02::fb".parse().unwrap(), &mac));
        assert!(!is_device("192.168.1.255".parse().unwrap(), &mac));
        assert!(!is_device("192.168.1.7".parse().unwrap(), &[]));
        assert!(!is_device("192.168.1.7".parse().unwrap(), &[0; 6]));
        assert!(!is_device("192.168.1.7".parse().unwrap(), &[0xff; 6]));
    }
}

#[cfg(all(test, any(windows, target_os = "linux")))]
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

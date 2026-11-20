//! The local networks this PC is on: IPv4 adapters that are up and have a
//! default gateway, with their MAC, address and prefix (IP Helper
//! `GetAdaptersAddresses` on Windows, the routing socket on Linux).

use serde::Serialize;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LanInterface {
    pub index: u32,
    /// The name to open a capture on: `\Device\NPF_{GUID}` with Npcap, the
    /// interface name (`eth0`) with libpcap.
    #[serde(skip)]
    pub device: String,
    /// "Ethernet", "Wi-Fi", …; on Linux the interface name.
    pub name: String,
    pub description: String,
    #[serde(skip)]
    pub mac: [u8; 6],
    pub ip: Ipv4Addr,
    pub prefix: u8,
    pub gateway: Option<Ipv4Addr>,
    pub wireless: bool,
}

impl LanInterface {
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let mask = mask(self.prefix);
        u32::from(ip) & mask == u32::from(self.ip) & mask
    }
}

fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix.min(32)))
    }
}

/// The largest network swept whole; bigger ones are swept around this PC's
/// own address (the /24 it sits in), as a /16 would take minutes.
pub const MAX_SWEEP_PREFIX: u8 = 22;

/// Addresses to probe on `iface`: every host of its network (without the
/// network, broadcast and own address), or of its /24 when the network is
/// larger than a /22. The flag says whether it was narrowed.
pub fn sweep_hosts(iface: &LanInterface) -> (Vec<Ipv4Addr>, bool) {
    let narrowed = iface.prefix < MAX_SWEEP_PREFIX;
    let prefix = if narrowed { 24 } else { iface.prefix };
    if prefix >= 31 {
        return (Vec::new(), narrowed);
    }
    let m = mask(prefix);
    let net = u32::from(iface.ip) & m;
    let bcast = net | !m;
    let hosts = (net + 1..bcast)
        .map(Ipv4Addr::from)
        .filter(|&ip| ip != iface.ip)
        .collect();
    (hosts, narrowed)
}

#[cfg(windows)]
pub use win::list;

#[cfg(target_os = "linux")]
pub use linux::list;

#[cfg(not(any(windows, target_os = "linux")))]
pub fn list() -> Vec<LanInterface> {
    Vec::new()
}

/// Put the kernel's links, addresses and default routes together: one
/// entry per Ethernet-like interface that is up and has an IPv4 address.
#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
fn assemble(
    links: &[crate::route::netlink::Link],
    addresses: &[crate::route::netlink::Address],
    routes: &[crate::route::netlink::DefaultRoute],
    wireless: impl Fn(&str) -> bool,
) -> Vec<LanInterface> {
    use std::net::IpAddr;
    let mut out: Vec<LanInterface> = links
        .iter()
        .filter(|l| l.up && l.ethernet && !l.loopback)
        .filter_map(|l| {
            let mac: [u8; 6] = l.mac.as_slice().try_into().ok()?;
            let (ip, prefix) = addresses.iter().find_map(|a| match a.ip {
                IpAddr::V4(ip) if a.index == l.index && !ip.is_link_local() => Some((ip, a.prefix)),
                _ => None,
            })?;
            let gateway = routes
                .iter()
                .filter(|r| r.index == l.index)
                .filter_map(|r| match r.gateway {
                    IpAddr::V4(gw) => Some((r.metric, gw)),
                    IpAddr::V6(_) => None,
                })
                .min()
                .map(|(_, gw)| gw);
            let wireless = wireless(&l.name);
            Some(LanInterface {
                index: l.index,
                device: l.name.clone(),
                name: l.name.clone(),
                description: if wireless { "Wi-Fi" } else { "Ethernet" }.to_string(),
                mac,
                ip,
                prefix,
                gateway,
                wireless,
            })
        })
        .collect();
    out.sort_by_key(|i| (i.gateway.is_none(), i.index));
    out
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::route::netlink::{
        self, RTM_GETADDR, RTM_GETLINK, RTM_GETROUTE, RTM_NEWADDR, RTM_NEWLINK, RTM_NEWROUTE,
    };

    pub fn list() -> Vec<LanInterface> {
        assemble(
            &netlink::table(RTM_GETLINK, RTM_NEWLINK, netlink::link),
            &netlink::table(RTM_GETADDR, RTM_NEWADDR, netlink::address),
            &netlink::table(RTM_GETROUTE, RTM_NEWROUTE, netlink::default_route),
            // The kernel gives every Wi-Fi interface this folder.
            |name| {
                std::path::Path::new("/sys/class/net")
                    .join(name)
                    .join("wireless")
                    .exists()
            },
        )
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn lists_this_machine() {
            for i in super::list() {
                println!(
                    "{} {} {}/{} gw {:?} wifi {} {}",
                    i.index, i.name, i.ip, i.prefix, i.gateway, i.wireless, i.device
                );
                assert!(i.prefix > 0 && i.prefix <= 32);
                assert_eq!(i.name, i.device);
            }
        }
    }
}

#[cfg(windows)]
mod win {
    use super::*;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR, SOCKADDR_IN};

    const ERROR_BUFFER_OVERFLOW: u32 = 111;
    const IF_TYPE_IEEE80211: u32 = 71;
    const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;

    /// IPv4 of a `SOCKADDR` if it is one.
    ///
    /// # Safety
    /// `sa` must be null or point to a socket address of at least its family's size.
    unsafe fn v4(sa: *const SOCKADDR) -> Option<Ipv4Addr> {
        // SAFETY: caller guarantees validity; the family says the layout.
        unsafe {
            if sa.is_null() || (*sa).sa_family != AF_INET {
                return None;
            }
            let sin = &*(sa as *const SOCKADDR_IN);
            Some(crate::util::ipv4_from_ne(sin.sin_addr.S_un.S_addr))
        }
    }

    /// # Safety
    /// `p` must be null or a NUL-terminated UTF-16 string.
    unsafe fn wide(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        // SAFETY: NUL-terminated per the API contract.
        unsafe {
            let mut n = 0;
            while *p.add(n) != 0 {
                n += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
        }
    }

    pub fn list() -> Vec<LanInterface> {
        let flags = GAA_FLAG_INCLUDE_GATEWAYS
            | GAA_FLAG_SKIP_ANYCAST
            | GAA_FLAG_SKIP_MULTICAST
            | GAA_FLAG_SKIP_DNS_SERVER;
        let mut size: u32 = 16 * 1024;
        let mut buf: Vec<u64> = Vec::new();
        for _ in 0..4 {
            buf = vec![0u64; (size as usize).div_ceil(8)];
            // SAFETY: the buffer is `size` bytes, 8-byte aligned.
            let rc = unsafe {
                GetAdaptersAddresses(
                    u32::from(AF_INET),
                    flags,
                    std::ptr::null(),
                    buf.as_mut_ptr().cast(),
                    &mut size,
                )
            };
            match rc {
                0 => break,
                ERROR_BUFFER_OVERFLOW => continue,
                _ => return Vec::new(),
            }
        }
        let mut out = Vec::new();
        let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        // SAFETY: a linked list the API filled in `buf`, alive until return.
        unsafe {
            while !cur.is_null() {
                let a = &*cur;
                cur = a.Next;
                if a.OperStatus != IfOperStatusUp
                    || a.IfType == IF_TYPE_SOFTWARE_LOOPBACK
                    || a.PhysicalAddressLength != 6
                {
                    continue;
                }
                let mut gateway = None;
                let mut g = a.FirstGatewayAddress;
                while !g.is_null() && gateway.is_none() {
                    gateway = v4((*g).Address.lpSockaddr).filter(|ip| !ip.is_unspecified());
                    g = (*g).Next;
                }
                let mut unicast = None;
                let mut u = a.FirstUnicastAddress;
                while !u.is_null() {
                    if let Some(ip) = v4((*u).Address.lpSockaddr).filter(|ip| !ip.is_link_local()) {
                        unicast = Some((ip, (*u).OnLinkPrefixLength));
                        break;
                    }
                    u = (*u).Next;
                }
                let Some((ip, prefix)) = unicast else {
                    continue;
                };
                // `{GUID}`, the tail of the Npcap device name.
                let guid = std::ffi::CStr::from_ptr(a.AdapterName.cast()).to_string_lossy();
                let mut mac = [0u8; 6];
                mac.copy_from_slice(&a.PhysicalAddress[..6]);
                out.push(LanInterface {
                    index: a.Anonymous1.Anonymous.IfIndex,
                    device: format!("\\Device\\NPF_{guid}"),
                    name: wide(a.FriendlyName),
                    description: wide(a.Description),
                    mac,
                    ip,
                    prefix,
                    gateway,
                    wireless: a.IfType == IF_TYPE_IEEE80211,
                });
            }
        }
        // Networks with a gateway first: those are "the LAN"; others are
        // host-only or virtual switches.
        out.sort_by_key(|i| (i.gateway.is_none(), i.index));
        out
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn lists_this_pc() {
            for i in super::list() {
                println!(
                    "{} {} {}/{} gw {:?} wifi {} {}",
                    i.index, i.name, i.ip, i.prefix, i.gateway, i.wireless, i.device
                );
                assert!(i.prefix > 0 && i.prefix <= 32);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(ip: [u8; 4], prefix: u8) -> LanInterface {
        LanInterface {
            index: 1,
            device: String::new(),
            name: String::new(),
            description: String::new(),
            mac: [0; 6],
            ip: ip.into(),
            prefix,
            gateway: None,
            wireless: false,
        }
    }

    #[test]
    fn hosts_of_a_slash_24() {
        let (h, narrowed) = sweep_hosts(&iface([192, 168, 1, 19], 24));
        assert!(!narrowed);
        assert_eq!(h.len(), 253, "254 hosts minus ourselves");
        assert_eq!(h[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(*h.last().unwrap(), Ipv4Addr::new(192, 168, 1, 254));
        assert!(!h.contains(&Ipv4Addr::new(192, 168, 1, 19)));
    }

    #[test]
    fn big_networks_are_narrowed() {
        let (h, narrowed) = sweep_hosts(&iface([10, 0, 7, 5], 16));
        assert!(narrowed);
        assert_eq!(h.len(), 253);
        assert_eq!(h[0], Ipv4Addr::new(10, 0, 7, 1));
        let (h, narrowed) = sweep_hosts(&iface([10, 0, 7, 5], 22));
        assert!(!narrowed);
        assert_eq!(h.len(), 1021);
        assert!(iface([192, 168, 1, 19], 24).contains(Ipv4Addr::new(192, 168, 1, 200)));
        assert!(!iface([192, 168, 1, 19], 24).contains(Ipv4Addr::new(192, 168, 2, 1)));
    }

    #[test]
    fn linux_tables_become_networks() {
        use crate::route::netlink::{Address, DefaultRoute, Link};
        let link = |index, name: &str, up, loopback| Link {
            index,
            name: name.into(),
            mac: vec![2, 0, 0, 0, 0, index as u8],
            up,
            loopback,
            ethernet: !loopback,
        };
        let addr = |index, ip: &str, prefix| Address {
            index,
            ip: ip.parse().unwrap(),
            prefix,
        };
        let links = [
            link(1, "lo", true, true),
            link(2, "enp3s0", true, false),
            link(3, "wlp4s0", true, false),
            link(4, "docker0", true, false),
            link(5, "enp5s0", false, false), // unplugged
            Link {
                mac: vec![], // a tunnel: no MAC
                ..link(6, "tun0", true, false)
            },
        ];
        let addresses = [
            addr(1, "127.0.0.1", 8),
            addr(2, "fe80::1", 64),
            addr(2, "169.254.3.4", 16), // link-local: not the network's address
            addr(2, "192.168.1.19", 24),
            addr(3, "192.168.1.20", 24),
            addr(4, "172.17.0.1", 16),
            addr(5, "10.0.0.5", 24),
            addr(6, "10.8.0.2", 24),
        ];
        let route = |index, gw: &str, metric| DefaultRoute {
            gateway: gw.parse().unwrap(),
            index,
            metric,
        };
        let routes = [
            route(3, "192.168.1.1", 600),
            route(2, "192.168.1.254", 200), // a second gateway, less preferred
            route(2, "192.168.1.1", 100),
            route(2, "fe80::1", 50),
        ];
        let found = assemble(&links, &addresses, &routes, |name| name.starts_with("wl"));
        let names: Vec<&str> = found.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, ["enp3s0", "wlp4s0", "docker0"], "gateways first");
        assert_eq!(found[0].ip, Ipv4Addr::new(192, 168, 1, 19));
        assert_eq!(found[0].gateway, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(found[0].device, "enp3s0");
        assert_eq!(found[0].mac, [2, 0, 0, 0, 0, 2]);
        assert!(found[1].wireless && !found[0].wireless);
        assert_eq!(found[2].gateway, None);
        assert_eq!(found[2].prefix, 16);
    }
}

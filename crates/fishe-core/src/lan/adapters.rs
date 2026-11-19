//! The local networks this PC is on: IPv4 adapters that are up and have a
//! default gateway, with their MAC, address and prefix (IP Helper
//! `GetAdaptersAddresses`).

use serde::Serialize;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LanInterface {
    pub index: u32,
    /// `{GUID}`, the tail of the Npcap device name `\Device\NPF_{GUID}`.
    #[serde(skip)]
    pub guid: String,
    /// "Ethernet", "Wi-Fi", …
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
    pub fn npcap_device(&self) -> String {
        format!("\\Device\\NPF_{}", self.guid)
    }

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

#[cfg(not(windows))]
pub fn list() -> Vec<LanInterface> {
    Vec::new()
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
                let guid = std::ffi::CStr::from_ptr(a.AdapterName.cast())
                    .to_string_lossy()
                    .into_owned();
                let mut mac = [0u8; 6];
                mac.copy_from_slice(&a.PhysicalAddress[..6]);
                out.push(LanInterface {
                    index: a.Anonymous1.Anonymous.IfIndex,
                    guid,
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
                    i.index,
                    i.name,
                    i.ip,
                    i.prefix,
                    i.gateway,
                    i.wireless,
                    i.npcap_device()
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
            guid: String::new(),
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
}

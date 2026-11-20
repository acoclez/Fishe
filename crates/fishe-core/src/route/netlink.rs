//! Linux's routing socket (rtnetlink): the kernel's own tables of links,
//! addresses, routes and neighbours, which is what `ip link`, `ip addr`,
//! `ip route` and `ip neigh` print.
//!
//! One request ("dump this table") is answered by a stream of messages, each
//! a fixed header followed by attributes. Reading that stream is pure byte
//! parsing, kept apart from the socket so it is tested on every platform;
//! only [`dump`] talks to the kernel, and only on Linux.
//!
//! All integers are in the machine's byte order.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Message types (`linux/rtnetlink.h`).
pub const RTM_NEWLINK: u16 = 16;
pub const RTM_GETLINK: u16 = 18;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_GETADDR: u16 = 22;
pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_GETROUTE: u16 = 26;
pub const RTM_NEWNEIGH: u16 = 28;
pub const RTM_GETNEIGH: u16 = 30;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
/// Size of `struct nlmsghdr`.
const HEADER: usize = 16;

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// Lengths in netlink are rounded up to 4 bytes.
fn align(n: usize) -> usize {
    (n + 3) & !3
}

/// The messages of `kind` in a reply: each one's payload, header removed.
/// Stops at the end-of-dump marker, an error message or malformed input.
pub fn payloads(reply: &[u8], kind: u16) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut rest = reply;
    while let (Some(len), Some(ty)) = (u32_at(rest, 0), u16_at(rest, 4)) {
        let len = len as usize;
        if len < HEADER || len > rest.len() || ty == NLMSG_DONE || ty == NLMSG_ERROR {
            break;
        }
        if ty == kind {
            out.push(&rest[HEADER..len]);
        }
        rest = rest.get(align(len)..).unwrap_or(&[]);
    }
    out
}

/// Did the reply end with the end-of-dump marker (or an error)?
#[cfg(any(target_os = "linux", test))]
fn finished(reply: &[u8]) -> bool {
    let mut rest = reply;
    while let (Some(len), Some(ty)) = (u32_at(rest, 0), u16_at(rest, 4)) {
        let len = len as usize;
        if ty == NLMSG_DONE || ty == NLMSG_ERROR || len < HEADER || len > rest.len() {
            return true;
        }
        rest = rest.get(align(len)..).unwrap_or(&[]);
    }
    false
}

/// The attributes after a message's fixed part: `(type, value)` pairs.
fn attrs(mut rest: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    while let (Some(len), Some(ty)) = (u16_at(rest, 0), u16_at(rest, 2)) {
        let len = usize::from(len);
        if len < 4 || len > rest.len() {
            break;
        }
        // The top bits of the type are flags (nested, byte order).
        out.push((ty & 0x3fff, &rest[4..len]));
        rest = rest.get(align(len)..).unwrap_or(&[]);
    }
    out
}

fn ip(family: u8, bytes: &[u8]) -> Option<IpAddr> {
    match family {
        AF_INET => Some(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).ok()?))),
        AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes).ok()?,
        ))),
        _ => None,
    }
}

/// A network interface (`RTM_NEWLINK`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub index: u32,
    pub name: String,
    pub mac: Vec<u8>,
    /// Administratively up and with a carrier.
    pub up: bool,
    pub loopback: bool,
    /// An Ethernet-like link (Ethernet, Wi-Fi, bridges, virtual pairs).
    pub ethernet: bool,
}

pub fn link(payload: &[u8]) -> Option<Link> {
    const IFLA_ADDRESS: u16 = 1;
    const IFLA_IFNAME: u16 = 3;
    const ARPHRD_ETHER: u16 = 1;
    const IFF_UP: u32 = 0x1;
    const IFF_LOOPBACK: u32 = 0x8;
    const IFF_RUNNING: u32 = 0x40;
    // struct ifinfomsg: family u8, pad u8, type u16, index i32, flags u32, change u32
    let kind = u16_at(payload, 2)?;
    let index = u32_at(payload, 4)?;
    let flags = u32_at(payload, 8)?;
    let mut name = String::new();
    let mut mac = Vec::new();
    for (ty, value) in attrs(payload.get(16..)?) {
        match ty {
            IFLA_IFNAME => {
                let end = value.iter().position(|&b| b == 0).unwrap_or(value.len());
                name = String::from_utf8_lossy(&value[..end]).into_owned();
            }
            IFLA_ADDRESS => mac = value.to_vec(),
            _ => {}
        }
    }
    Some(Link {
        index,
        name,
        mac,
        up: flags & IFF_UP != 0 && flags & IFF_RUNNING != 0,
        loopback: flags & IFF_LOOPBACK != 0,
        ethernet: kind == ARPHRD_ETHER,
    })
}

/// An address of an interface (`RTM_NEWADDR`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    pub index: u32,
    pub ip: IpAddr,
    pub prefix: u8,
}

pub fn address(payload: &[u8]) -> Option<Address> {
    const IFA_ADDRESS: u16 = 1;
    const IFA_LOCAL: u16 = 2;
    // struct ifaddrmsg: family u8, prefixlen u8, flags u8, scope u8, index u32
    let family = *payload.first()?;
    let prefix = *payload.get(1)?;
    let index = u32_at(payload, 4)?;
    let attrs = attrs(payload.get(8..)?);
    // On a point-to-point link IFA_ADDRESS is the peer; IFA_LOCAL is ours.
    let value = attrs
        .iter()
        .find(|(ty, _)| *ty == IFA_LOCAL)
        .or_else(|| attrs.iter().find(|(ty, _)| *ty == IFA_ADDRESS))?
        .1;
    Some(Address {
        index,
        ip: ip(family, value)?,
        prefix,
    })
}

/// A default route through a gateway (`RTM_NEWROUTE`); `None` for every
/// other route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultRoute {
    pub gateway: IpAddr,
    pub index: u32,
    pub metric: u32,
}

pub fn default_route(payload: &[u8]) -> Option<DefaultRoute> {
    const RTA_OIF: u16 = 4;
    const RTA_GATEWAY: u16 = 5;
    const RTA_PRIORITY: u16 = 6;
    const RTA_TABLE: u16 = 15;
    const RT_TABLE_MAIN: u32 = 254;
    const RTN_UNICAST: u8 = 1;
    // struct rtmsg: family, dst_len, src_len, tos, table, protocol, scope, type (u8 each), flags u32
    let family = *payload.first()?;
    let dst_len = *payload.get(1)?;
    let mut table = u32::from(*payload.get(4)?);
    let kind = *payload.get(7)?;
    if dst_len != 0 || kind != RTN_UNICAST {
        return None;
    }
    let (mut gateway, mut index, mut metric) = (None, 0, 0);
    for (ty, value) in attrs(payload.get(12..)?) {
        match ty {
            RTA_GATEWAY => gateway = ip(family, value),
            RTA_OIF => index = u32_at(value, 0)?,
            RTA_PRIORITY => metric = u32_at(value, 0)?,
            RTA_TABLE => table = u32_at(value, 0)?,
            _ => {}
        }
    }
    // Policy-routing tables (VPN clients fill their own) are not "the" route.
    if table != RT_TABLE_MAIN {
        return None;
    }
    Some(DefaultRoute {
        gateway: gateway.filter(|g| !g.is_unspecified())?,
        index,
        metric,
    })
}

/// A neighbour-table entry (`RTM_NEWNEIGH`) that has been resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neigh {
    pub ip: IpAddr,
    pub mac: Vec<u8>,
    pub state: &'static str,
    pub index: u32,
}

pub fn neigh(payload: &[u8]) -> Option<Neigh> {
    const NDA_DST: u16 = 1;
    const NDA_LLADDR: u16 = 2;
    // struct ndmsg: family u8, pad u8, pad u16, ifindex i32, state u16, flags u8, type u8
    let family = *payload.first()?;
    let index = u32_at(payload, 4)?;
    // Incomplete, failed and "no ARP" entries have no usable address.
    let state = match u16_at(payload, 8)? {
        s if s & 0x80 != 0 => "permanent",
        s if s & 0x02 != 0 => "reachable",
        s if s & 0x04 != 0 => "stale",
        s if s & 0x08 != 0 => "delay",
        s if s & 0x10 != 0 => "probe",
        _ => return None,
    };
    let (mut dst, mut mac) = (None, Vec::new());
    for (ty, value) in attrs(payload.get(12..)?) {
        match ty {
            NDA_DST => dst = ip(family, value),
            NDA_LLADDR => mac = value.to_vec(),
            _ => {}
        }
    }
    Some(Neigh {
        ip: dst?,
        mac,
        state,
        index,
    })
}

/// Ask the kernel for one whole table (`kind` is an `RTM_GET*` type) and
/// return the raw reply, to be read with [`payloads`].
#[cfg(target_os = "linux")]
pub fn dump(kind: u16) -> std::io::Result<Vec<u8>> {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    const NLM_F_REQUEST: u16 = 0x1;
    const NLM_F_DUMP: u16 = 0x300;

    // SAFETY: a plain socket call; the descriptor is owned (and closed) by
    // `OwnedFd` from the next line on.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a descriptor we just opened and nothing else owns.
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    let timeout = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    // SAFETY: the option value is a `timeval` of the stated size.
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const timeout).cast(),
            size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    // Header + the table's own request struct, all zero: family 0 means
    // every family. The exact size matters: the kernel reads anything after
    // it as attributes and logs a complaint about stray bytes.
    let body = match kind {
        RTM_GETLINK => 16, // struct ifinfomsg
        RTM_GETADDR => 8,  // struct ifaddrmsg
        _ => 12,           // struct rtmsg, struct ndmsg
    };
    let mut request = vec![0u8; HEADER + body];
    let len = request.len() as u32;
    request[0..4].copy_from_slice(&len.to_ne_bytes());
    request[4..6].copy_from_slice(&kind.to_ne_bytes());
    request[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    request[8..12].copy_from_slice(&1u32.to_ne_bytes()); // sequence number
    // SAFETY: the buffer is valid for its length; an unconnected netlink
    // socket sends to the kernel.
    let sent = unsafe {
        libc::send(
            socket.as_raw_fd(),
            request.as_ptr().cast(),
            request.len(),
            0,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut reply = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        // SAFETY: the buffer is valid and writable for its length.
        let n = unsafe { libc::recv(socket.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let chunk = &buf[..n as usize];
        let done = n == 0 || finished(chunk);
        // Keep the table size bounded whatever the kernel sends.
        if reply.len() + chunk.len() > 16 * 1024 * 1024 {
            return Err(io::Error::other("netlink reply too large"));
        }
        reply.extend_from_slice(chunk);
        if done {
            return Ok(reply);
        }
    }
}

/// A `Vec` of the messages of `reply_kind` obtained by dumping `get_kind`,
/// parsed with `parse`; empty when the kernel cannot be asked.
#[cfg(target_os = "linux")]
pub fn table<T>(get_kind: u16, reply_kind: u16, parse: fn(&[u8]) -> Option<T>) -> Vec<T> {
    match dump(get_kind) {
        Ok(reply) => payloads(&reply, reply_kind)
            .into_iter()
            .filter_map(parse)
            .collect(),
        Err(e) => {
            log::warn!("netlink dump {get_kind} failed: {e}");
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One attribute, padded.
    fn attr(ty: u16, value: &[u8]) -> Vec<u8> {
        let mut a = ((4 + value.len()) as u16).to_ne_bytes().to_vec();
        a.extend_from_slice(&ty.to_ne_bytes());
        a.extend_from_slice(value);
        a.resize(align(a.len()), 0);
        a
    }

    /// One message: header + payload, padded.
    fn message(kind: u16, payload: &[u8]) -> Vec<u8> {
        let mut m = ((HEADER + payload.len()) as u32).to_ne_bytes().to_vec();
        m.extend_from_slice(&kind.to_ne_bytes());
        m.extend_from_slice(&[0; 10]); // flags, sequence, port
        m.extend_from_slice(payload);
        m.resize(align(m.len()), 0);
        m
    }

    fn route(family: u8, dst_len: u8, table: u8, attrs: &[Vec<u8>]) -> Vec<u8> {
        let mut p = vec![family, dst_len, 0, 0, table, 3, 0, 1, 0, 0, 0, 0];
        p.extend(attrs.concat());
        p
    }

    #[test]
    fn a_reply_is_split_into_messages() {
        let mut reply = message(RTM_NEWROUTE, &[1, 2, 3]);
        reply.extend(message(RTM_NEWNEIGH, &[9]));
        reply.extend(message(RTM_NEWROUTE, &[4, 5, 6, 7]));
        assert!(!finished(&reply));
        reply.extend(message(NLMSG_DONE, &[0; 4]));
        reply.extend(message(RTM_NEWROUTE, &[8])); // after the end: ignored
        assert!(finished(&reply));
        assert_eq!(
            payloads(&reply, RTM_NEWROUTE),
            vec![&[1u8, 2, 3][..], &[4, 5, 6, 7]]
        );
        assert_eq!(payloads(&reply, RTM_NEWNEIGH), vec![&[9u8][..]]);
        // A length that runs past the buffer ends the walk instead of panicking.
        let mut cut = message(RTM_NEWROUTE, &[1, 2, 3, 4]);
        cut.truncate(18);
        assert!(payloads(&cut, RTM_NEWROUTE).is_empty());
        assert!(payloads(&[], RTM_NEWROUTE).is_empty());
        assert!(payloads(&[0xff; 7], RTM_NEWROUTE).is_empty());
    }

    #[test]
    fn default_routes_are_recognised() {
        let v4 = route(
            AF_INET,
            0,
            254,
            &[
                attr(5, &[192, 168, 1, 1]),
                attr(4, &7u32.to_ne_bytes()),
                attr(6, &600u32.to_ne_bytes()),
            ],
        );
        assert_eq!(
            default_route(&v4),
            Some(DefaultRoute {
                gateway: "192.168.1.1".parse().unwrap(),
                index: 7,
                metric: 600
            })
        );
        let gw6: Ipv6Addr = "fe80::1".parse().unwrap();
        let v6 = route(
            AF_INET6,
            0,
            254,
            &[attr(5, &gw6.octets()), attr(4, &2u32.to_ne_bytes())],
        );
        assert_eq!(default_route(&v6).unwrap().gateway, IpAddr::V6(gw6));

        // Not a default route; a default route in another table; one
        // without a gateway (a point-to-point link).
        let subnet = route(AF_INET, 24, 254, &[attr(5, &[192, 168, 1, 1])]);
        assert_eq!(default_route(&subnet), None);
        let vpn = route(AF_INET, 0, 51, &[attr(5, &[10, 8, 0, 1])]);
        assert_eq!(default_route(&vpn), None);
        let big_table = route(
            AF_INET,
            0,
            252,
            &[attr(5, &[10, 8, 0, 1]), attr(15, &51820u32.to_ne_bytes())],
        );
        assert_eq!(default_route(&big_table), None);
        let on_link = route(AF_INET, 0, 254, &[attr(4, &3u32.to_ne_bytes())]);
        assert_eq!(default_route(&on_link), None);
        assert_eq!(default_route(&[AF_INET, 0, 0]), None);
    }

    #[test]
    fn neighbours_with_an_address_are_kept() {
        let entry = |state: u16, attrs: &[Vec<u8>]| {
            let mut p = vec![AF_INET, 0, 0, 0];
            p.extend_from_slice(&4u32.to_ne_bytes());
            p.extend_from_slice(&state.to_ne_bytes());
            p.extend_from_slice(&[0, 1]);
            p.extend(attrs.concat());
            p
        };
        let mac = [0xc8, 0x7f, 0x2b, 0x35, 0x1a, 0xc0];
        let n = neigh(&entry(0x02, &[attr(1, &[192, 168, 1, 1]), attr(2, &mac)])).unwrap();
        assert_eq!(n.ip, "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(
            (n.mac.as_slice(), n.state, n.index),
            (&mac[..], "reachable", 4)
        );
        assert_eq!(
            neigh(&entry(0x04, &[attr(1, &[10, 0, 0, 2])]))
                .unwrap()
                .state,
            "stale"
        );
        assert_eq!(
            neigh(&entry(0x80, &[attr(1, &[10, 0, 0, 2])]))
                .unwrap()
                .state,
            "permanent"
        );
        // Incomplete, failed, no-ARP: nothing to show.
        for state in [0x01, 0x20, 0x40, 0x00] {
            assert_eq!(neigh(&entry(state, &[attr(1, &[10, 0, 0, 2])])), None);
        }
        assert_eq!(neigh(&entry(0x02, &[])), None, "no address");
    }

    #[test]
    fn links_and_addresses() {
        let mut l = vec![0, 0];
        l.extend_from_slice(&1u16.to_ne_bytes()); // ARPHRD_ETHER
        l.extend_from_slice(&3u32.to_ne_bytes());
        l.extend_from_slice(&0x1043u32.to_ne_bytes()); // UP | BROADCAST | RUNNING | MULTICAST
        l.extend_from_slice(&[0; 4]);
        l.extend(attr(3, b"wlp3s0\0"));
        l.extend(attr(1, &[2, 0, 0, 0, 0, 9]));
        let link = link(&l).unwrap();
        assert_eq!((link.index, link.name.as_str()), (3, "wlp3s0"));
        assert_eq!(link.mac, vec![2, 0, 0, 0, 0, 9]);
        assert!(link.up && link.ethernet && !link.loopback);

        let mut lo = vec![0, 0];
        lo.extend_from_slice(&772u16.to_ne_bytes()); // ARPHRD_LOOPBACK
        lo.extend_from_slice(&1u32.to_ne_bytes());
        lo.extend_from_slice(&0x49u32.to_ne_bytes()); // UP | LOOPBACK | RUNNING
        lo.extend_from_slice(&[0; 4]);
        let lo = super::link(&lo).unwrap();
        assert!(lo.loopback && !lo.ethernet);

        // A cable unplugged: up, not running.
        let mut down = l.clone();
        down[8..12].copy_from_slice(&0x1003u32.to_ne_bytes());
        assert!(!super::link(&down).unwrap().up);

        let mut a = vec![AF_INET, 24, 0, 0];
        a.extend_from_slice(&3u32.to_ne_bytes());
        a.extend(attr(1, &[192, 168, 1, 1])); // the peer, on a point-to-point link
        a.extend(attr(2, &[192, 168, 1, 19])); // ours
        assert_eq!(
            address(&a),
            Some(Address {
                index: 3,
                ip: "192.168.1.19".parse().unwrap(),
                prefix: 24
            })
        );
        // Without IFA_LOCAL (IPv6), IFA_ADDRESS is the address.
        let ip6: Ipv6Addr = "2001:db8::5".parse().unwrap();
        let mut a6 = vec![AF_INET6, 64, 0, 0];
        a6.extend_from_slice(&3u32.to_ne_bytes());
        a6.extend(attr(1, &ip6.octets()));
        assert_eq!(address(&a6).unwrap().ip, IpAddr::V6(ip6));
        assert_eq!(address(&[AF_INET, 24]), None);
    }
}

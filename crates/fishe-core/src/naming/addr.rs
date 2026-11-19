//! What kind of address is this?

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub enum AddrScope {
    /// 127.0.0.0/8, ::1
    Loopback,
    /// RFC 1918 (10/8, 172.16/12, 192.168/16) and IPv6 ULA (fc00::/7)
    Private,
    /// 169.254/16, fe80::/10
    LinkLocal,
    /// Carrier-grade NAT, 100.64/10
    Cgnat,
    Multicast,
    Broadcast,
    Unspecified,
    /// 192.0.2/24, 198.51.100/24, 203.0.113/24, 2001:db8::/32
    Documentation,
    Public,
}

pub fn classify(ip: IpAddr) -> AddrScope {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

fn classify_v4(ip: Ipv4Addr) -> AddrScope {
    let o = ip.octets();
    if ip.is_unspecified() {
        AddrScope::Unspecified
    } else if ip.is_loopback() {
        AddrScope::Loopback
    } else if ip.is_broadcast() {
        AddrScope::Broadcast
    } else if ip.is_multicast() {
        AddrScope::Multicast
    } else if ip.is_link_local() {
        AddrScope::LinkLocal
    } else if ip.is_private() {
        AddrScope::Private
    } else if o[0] == 100 && (o[1] & 0xC0) == 64 {
        AddrScope::Cgnat
    } else if ip.is_documentation() {
        AddrScope::Documentation
    } else {
        AddrScope::Public
    }
}

fn classify_v6(ip: Ipv6Addr) -> AddrScope {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return classify_v4(v4);
    }
    let s = ip.segments();
    if ip.is_unspecified() {
        AddrScope::Unspecified
    } else if ip.is_loopback() {
        AddrScope::Loopback
    } else if ip.is_multicast() {
        AddrScope::Multicast
    } else if (s[0] & 0xFFC0) == 0xFE80 {
        AddrScope::LinkLocal
    } else if (s[0] & 0xFE00) == 0xFC00 {
        AddrScope::Private
    } else if s[0] == 0x2001 && s[1] == 0x0DB8 {
        AddrScope::Documentation
    } else {
        AddrScope::Public
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> AddrScope {
        classify(s.parse().unwrap())
    }

    #[test]
    fn v4_scopes() {
        assert_eq!(c("127.0.0.1"), AddrScope::Loopback);
        assert_eq!(c("10.1.2.3"), AddrScope::Private);
        assert_eq!(c("172.20.0.1"), AddrScope::Private);
        assert_eq!(c("172.32.0.1"), AddrScope::Public);
        assert_eq!(c("192.168.1.19"), AddrScope::Private);
        assert_eq!(c("169.254.10.1"), AddrScope::LinkLocal);
        assert_eq!(c("100.64.0.1"), AddrScope::Cgnat);
        assert_eq!(c("100.128.0.1"), AddrScope::Public);
        assert_eq!(c("224.0.0.251"), AddrScope::Multicast);
        assert_eq!(c("255.255.255.255"), AddrScope::Broadcast);
        assert_eq!(c("203.0.113.7"), AddrScope::Documentation);
        assert_eq!(c("1.1.1.1"), AddrScope::Public);
    }

    #[test]
    fn v6_scopes() {
        assert_eq!(c("::1"), AddrScope::Loopback);
        assert_eq!(c("fe80::1"), AddrScope::LinkLocal);
        assert_eq!(c("fd12:3456::1"), AddrScope::Private);
        assert_eq!(c("ff02::fb"), AddrScope::Multicast);
        assert_eq!(c("2001:db8::1"), AddrScope::Documentation);
        assert_eq!(c("2606:4700::1111"), AddrScope::Public);
        assert_eq!(c("::ffff:192.168.1.1"), AddrScope::Private);
    }
}

//! Is a VPN up, and does this machine's traffic actually go through it?
//!
//! Three questions, each answered from something Fishe can observe:
//!
//! - **Is there a tunnel?** An interface that is up, has an address and is
//!   a VPN's by its name or description ([`tunnel_kind`]).
//! - **Where does Internet traffic leave?** The interface the system would
//!   use to reach a public address, asked separately for IPv4 and IPv6
//!   (a route lookup; no packet is sent). A VPN that carries IPv4 while
//!   IPv6 still leaves directly is the classic leak.
//! - **What left outside the tunnel?** During an all-traffic session that
//!   captures on the tunnel, the Internet addresses reached through any
//!   other interface. One of them is the VPN server itself (the tunnel's
//!   encrypted packets travel to it); any other is traffic the VPN did not
//!   carry, by design (split tunnelling) or not.
//!
//! Fishe does not configure, start or test the VPN; it reports what the
//! interfaces, the routing and the packets show.

use super::EndpointRef;
use crate::net::interfaces;
use serde::Serialize;
use std::net::IpAddr;

/// Public addresses used only to ask the system which interface it would
/// route through (nothing is sent to them).
const PROBE_V4: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1));
const PROBE_V6: IpAddr = IpAddr::V6(std::net::Ipv6Addr::new(
    0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111,
));

/// The VPN product or tunnel type an interface belongs to, by its name and
/// description; `None` for an ordinary adapter.
///
/// Windows describes adapters by their driver ("WireGuard Tunnel",
/// "TAP-Windows Adapter V9"); Linux only has the interface name (`wg0`,
/// `tun0`).
pub fn tunnel_kind(name: &str, description: &str) -> Option<&'static str> {
    let d = description.to_ascii_lowercase();
    // Order matters: products built on WireGuard or OpenVPN name themselves.
    const BY_DESCRIPTION: [(&str, &str); 24] = [
        ("nordlynx", "NordVPN"),
        ("nordvpn", "NordVPN"),
        ("protonvpn", "Proton VPN"),
        ("proton vpn", "Proton VPN"),
        ("mullvad", "Mullvad"),
        ("expressvpn", "ExpressVPN"),
        ("surfshark", "Surfshark"),
        ("private internet access", "Private Internet Access"),
        ("windscribe", "Windscribe"),
        ("tailscale", "Tailscale"),
        ("zerotier", "ZeroTier"),
        ("cloudflare warp", "Cloudflare WARP"),
        ("anyconnect", "Cisco AnyConnect"),
        ("cisco secure client", "Cisco Secure Client"),
        ("fortinet", "FortiClient"),
        ("pangp", "GlobalProtect"),
        ("globalprotect", "GlobalProtect"),
        ("sonicwall", "SonicWall"),
        ("check point", "Check Point"),
        ("juniper", "Juniper"),
        ("wireguard", "WireGuard"),
        ("wintun", "WireGuard / Wintun"),
        ("openvpn", "OpenVPN"),
        ("tap-windows", "OpenVPN (TAP)"),
    ];
    if let Some((_, kind)) = BY_DESCRIPTION.iter().find(|(needle, _)| d.contains(needle)) {
        return Some(*kind);
    }

    // Interface names (Linux, macOS): a known prefix followed by a number,
    // or a few fixed names.
    let n = name.to_ascii_lowercase();
    let numbered = |prefix: &str| {
        n.strip_prefix(prefix)
            .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
    };
    const BY_PREFIX: [(&str, &str); 7] = [
        ("wg", "WireGuard"),
        ("tun", "VPN tunnel"),
        ("tap", "VPN tunnel (TAP)"),
        ("ppp", "PPP / VPN"),
        ("utun", "VPN tunnel"),
        ("ipsec", "IPsec"),
        ("vti", "IPsec"),
    ];
    if let Some((_, kind)) = BY_PREFIX.iter().find(|(prefix, _)| numbered(prefix)) {
        return Some(*kind);
    }
    const BY_NAME: [(&str, &str); 6] = [
        ("tailscale0", "Tailscale"),
        ("nordlynx", "NordVPN"),
        ("proton0", "Proton VPN"),
        ("gpd0", "GlobalProtect"),
        ("cscotun0", "Cisco AnyConnect"),
        ("wgcf", "Cloudflare WARP"),
    ];
    BY_NAME
        .iter()
        .find(|(exact, _)| n == *exact)
        .map(|(_, kind)| *kind)
        .or_else(|| {
            n.starts_with("zt")
                .then_some("ZeroTier")
                .filter(|_| n.len() > 4)
        })
}

/// A tunnel interface that is up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Tunnel {
    /// Capture device name.
    pub name: String,
    pub description: String,
    /// "WireGuard", "OpenVPN", …
    pub kind: String,
    pub addresses: Vec<String>,
}

/// How Internet-bound traffic of one address family leaves this machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub enum RouteVia {
    /// Through a tunnel interface.
    Tunnel,
    /// Through an ordinary adapter.
    Direct,
    /// This machine has no route for that family.
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Route {
    pub via: RouteVia,
    /// Description of the interface used.
    pub interface: Option<String>,
}

impl Route {
    const NONE: Route = Route {
        via: RouteVia::None,
        interface: None,
    };
}

/// One interface as far as this module cares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Iface {
    pub name: String,
    pub description: String,
    pub addresses: Vec<IpAddr>,
    /// Up, running, and with an address.
    pub active: bool,
}

impl Iface {
    pub fn of(d: &pcap::Device) -> Self {
        Iface {
            name: d.name.clone(),
            description: d.desc.clone().unwrap_or_else(|| d.name.clone()),
            addresses: d.addresses.iter().map(|a| a.addr).collect(),
            active: d.flags.is_up() && d.flags.is_running() && !d.addresses.is_empty(),
        }
    }

    pub fn tunnel_kind(&self) -> Option<&'static str> {
        tunnel_kind(&self.name, &self.description)
    }
}

/// The tunnels among `ifaces` that are up.
pub fn tunnels(ifaces: &[Iface]) -> Vec<Tunnel> {
    ifaces
        .iter()
        .filter(|i| i.active)
        .filter_map(|i| {
            Some(Tunnel {
                kind: i.tunnel_kind()?.to_string(),
                name: i.name.clone(),
                description: i.description.clone(),
                addresses: i.addresses.iter().map(|a| a.to_string()).collect(),
            })
        })
        .collect()
}

/// Which interface owns `source`, the address the system would send from.
pub fn route_of(source: Option<IpAddr>, ifaces: &[Iface]) -> Route {
    let Some(source) = source else {
        return Route::NONE;
    };
    match ifaces.iter().find(|i| i.addresses.contains(&source)) {
        Some(i) => Route {
            via: if i.tunnel_kind().is_some() {
                RouteVia::Tunnel
            } else {
                RouteVia::Direct
            },
            interface: Some(i.description.clone()),
        },
        // An address no capture device carries: an adapter the capture
        // library does not list. Not a tunnel we know of.
        None => Route {
            via: RouteVia::Direct,
            interface: None,
        },
    }
}

/// What the session measured, for [`audit`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Measured {
    /// The session captures on at least one tunnel interface.
    pub on_tunnel: bool,
    /// Bytes exchanged with Internet addresses through tunnel interfaces.
    pub inside_bytes: u64,
    /// The same through every other interface.
    pub outside_bytes: u64,
    /// Internet addresses reached outside the tunnel, busiest first.
    pub outside: Vec<EndpointRef>,
    /// How many there were in all.
    pub outside_count: u32,
    /// Unencrypted DNS questions seen on interfaces that are not tunnels.
    pub dns_outside: u64,
}

/// The VPN card.
#[derive(Debug, Clone, PartialEq, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct VpnAudit {
    /// Tunnel interfaces that are up.
    pub tunnels: Vec<Tunnel>,
    pub ipv4: Route,
    pub ipv6: Route,
    /// Why the interfaces could not be listed, when they could not.
    pub error: Option<String>,
    /// The running all-traffic session captures on a tunnel, so the figures
    /// below mean something. Otherwise they are zero.
    pub measured: bool,
    /// Bytes exchanged with Internet addresses inside the tunnel.
    pub inside_bytes: u64,
    /// Bytes exchanged with Internet addresses outside it, the VPN server's
    /// own traffic included.
    pub outside_bytes: u64,
    /// The busiest address reached outside the tunnel: almost always the
    /// VPN server, which the tunnel's own packets travel to.
    pub carrier: Option<EndpointRef>,
    /// The other Internet addresses reached outside the tunnel (a few).
    pub outside: Vec<EndpointRef>,
    /// How many there are.
    pub outside_count: u32,
    /// Unencrypted DNS questions that left outside the tunnel.
    pub dns_outside: u64,
}

impl VpnAudit {
    /// The VPN carries this machine's IPv4 Internet traffic.
    pub fn routes_ipv4(&self) -> bool {
        self.ipv4.via == RouteVia::Tunnel
    }
}

/// Put the card together from the interfaces, the two route lookups and
/// what the session measured.
pub fn audit(
    ifaces: Result<Vec<Iface>, String>,
    source_v4: Option<IpAddr>,
    source_v6: Option<IpAddr>,
    measured: Option<Measured>,
) -> VpnAudit {
    let (ifaces, error) = match ifaces {
        Ok(i) => (i, None),
        Err(e) => (Vec::new(), Some(e)),
    };
    let m = measured.filter(|m| m.on_tunnel).unwrap_or_default();
    let mut outside = m.outside;
    let carrier = (!outside.is_empty()).then(|| outside.remove(0));
    let outside_count = m.outside_count.saturating_sub(u32::from(carrier.is_some()));
    VpnAudit {
        tunnels: tunnels(&ifaces),
        ipv4: route_of(source_v4, &ifaces),
        ipv6: route_of(source_v6, &ifaces),
        error,
        measured: m.on_tunnel,
        inside_bytes: m.inside_bytes,
        outside_bytes: m.outside_bytes,
        carrier,
        outside,
        outside_count,
        dns_outside: m.dns_outside,
    }
}

/// What this machine shows right now: its interfaces, and the address it
/// would send from to reach the Internet over IPv4 and over IPv6.
pub fn system() -> (Result<Vec<Iface>, String>, Option<IpAddr>, Option<IpAddr>) {
    let ifaces = interfaces::list_devices()
        .map(|devices| devices.iter().map(Iface::of).collect())
        .map_err(|e| e.to_string());
    (
        ifaces,
        interfaces::route_source(PROBE_V4),
        // A link-local or unique-local source is not a way to the Internet.
        interfaces::route_source(PROBE_V6).filter(|a| {
            matches!(
                crate::naming::addr::classify(*a),
                crate::naming::addr::AddrScope::Public
            )
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::naming::addr::AddrScope;

    fn iface(name: &str, description: &str, addresses: &[&str]) -> Iface {
        Iface {
            name: name.into(),
            description: description.into(),
            addresses: addresses.iter().map(|a| a.parse().unwrap()).collect(),
            active: !addresses.is_empty(),
        }
    }

    fn ep(ip: &str, bytes: u64) -> EndpointRef {
        EndpointRef {
            ip: ip.parse().unwrap(),
            name: None,
            scope: AddrScope::Public,
            bytes,
        }
    }

    #[test]
    fn tunnels_are_recognised_by_driver_or_interface_name() {
        let windows = [
            ("WireGuard Tunnel", "WireGuard"),
            ("ProtonVPN Tunnel", "Proton VPN"),
            ("NordLynx Tunnel", "NordVPN"),
            ("TAP-Windows Adapter V9", "OpenVPN (TAP)"),
            ("OpenVPN Data Channel Offload", "OpenVPN"),
            ("Wintun Userspace Tunnel", "WireGuard / Wintun"),
            (
                "Cisco AnyConnect Secure Mobility Client Virtual Miniport Adapter for Windows x64",
                "Cisco AnyConnect",
            ),
            (
                "Fortinet Virtual Ethernet Adapter (NDIS 6.30)",
                "FortiClient",
            ),
            ("PANGP Virtual Ethernet Adapter Secure", "GlobalProtect"),
            ("Tailscale Tunnel", "Tailscale"),
            ("ZeroTier Virtual Port", "ZeroTier"),
        ];
        for (description, kind) in windows {
            assert_eq!(
                tunnel_kind(r"\Device\NPF_{A1B2}", description),
                Some(kind),
                "{description}"
            );
        }
        for (name, kind) in [
            ("wg0", "WireGuard"),
            ("tun0", "VPN tunnel"),
            ("tap1", "VPN tunnel (TAP)"),
            ("ppp0", "PPP / VPN"),
            ("tailscale0", "Tailscale"),
            ("ztabcdef12", "ZeroTier"),
            ("proton0", "Proton VPN"),
        ] {
            assert_eq!(tunnel_kind(name, name), Some(kind), "{name}");
        }
        // Ordinary adapters, and names that only start like a tunnel's.
        for (name, description) in [
            (
                r"\Device\NPF_{C3D4}",
                "Intel(R) I211 Gigabit Network Connection",
            ),
            (r"\Device\NPF_{E5F6}", "Hyper-V Virtual Ethernet Adapter"),
            (
                r"\Device\NPF_Loopback",
                "Adapter for loopback traffic capture",
            ),
            ("eth0", "eth0"),
            ("wlp3s0", "wlp3s0"),
            ("docker0", "docker0"),
            ("tunnel", "tunnel"),
            ("wg", "wg"),
            ("tuna0", "tuna0"),
            ("zt", "zt"),
            ("lo", "lo"),
        ] {
            assert_eq!(
                tunnel_kind(name, description),
                None,
                "{name} / {description}"
            );
        }
    }

    #[test]
    fn a_full_tunnel_with_an_ipv6_bypass() {
        let ifaces = vec![
            iface("eth0", "Ethernet", &["192.168.1.19", "2a01:cb00:1::19"]),
            iface("wg0", "wg0", &["10.2.0.2"]),
            iface("tun7", "tun7", &[]), // configured, not up
        ];
        let v = audit(
            Ok(ifaces),
            Some("10.2.0.2".parse().unwrap()),
            Some("2a01:cb00:1::19".parse().unwrap()),
            None,
        );
        assert_eq!(v.tunnels.len(), 1, "only the tunnel that is up");
        assert_eq!(
            (v.tunnels[0].name.as_str(), v.tunnels[0].kind.as_str()),
            ("wg0", "WireGuard")
        );
        assert_eq!(v.ipv4.via, RouteVia::Tunnel);
        assert_eq!(v.ipv4.interface.as_deref(), Some("wg0"));
        assert_eq!(
            v.ipv6.via,
            RouteVia::Direct,
            "IPv6 leaves through the adapter"
        );
        assert!(v.routes_ipv4());
        assert!(!v.measured);
        assert_eq!((v.inside_bytes, v.outside_count), (0, 0));
    }

    #[test]
    fn no_tunnel_and_no_ipv6() {
        let ifaces = vec![iface("eth0", "Ethernet", &["192.168.1.19"])];
        let v = audit(
            Ok(ifaces),
            Some("192.168.1.19".parse().unwrap()),
            None,
            None,
        );
        assert!(v.tunnels.is_empty());
        assert_eq!(v.ipv4.via, RouteVia::Direct);
        assert_eq!(v.ipv6, Route::NONE);
        assert!(!v.routes_ipv4());

        let failed = audit(Err("no capture".into()), None, None, None);
        assert_eq!(failed.error.as_deref(), Some("no capture"));
        assert_eq!(failed.ipv4.via, RouteVia::None);
    }

    #[test]
    fn the_busiest_outside_address_is_the_carrier() {
        let ifaces = vec![
            iface("eth0", "Ethernet", &["192.168.1.19"]),
            iface("wg0", "wg0", &["10.2.0.2"]),
        ];
        let measured = Measured {
            on_tunnel: true,
            inside_bytes: 9_000_000,
            outside_bytes: 9_600_000,
            outside: vec![
                ep("185.159.157.1", 9_400_000),
                ep("8.8.8.8", 150_000),
                ep("17.253.1.1", 50_000),
            ],
            outside_count: 3,
            dns_outside: 12,
        };
        let v = audit(
            Ok(ifaces.clone()),
            Some("10.2.0.2".parse().unwrap()),
            None,
            Some(measured.clone()),
        );
        assert!(v.measured);
        assert_eq!(v.carrier.as_ref().unwrap().ip.to_string(), "185.159.157.1");
        assert_eq!(v.outside.len(), 2);
        assert_eq!(
            v.outside_count, 2,
            "the carrier is not counted as outside traffic"
        );
        assert_eq!(
            (v.inside_bytes, v.outside_bytes, v.dns_outside),
            (9_000_000, 9_600_000, 12)
        );

        // A session that does not capture on the tunnel measured nothing
        // that can be compared.
        let blind = audit(
            Ok(ifaces),
            Some("10.2.0.2".parse().unwrap()),
            None,
            Some(Measured {
                on_tunnel: false,
                ..measured
            }),
        );
        assert!(!blind.measured);
        assert_eq!(
            (blind.outside_bytes, blind.dns_outside, blind.outside_count),
            (0, 0, 0)
        );
        assert_eq!(blind.carrier, None);
    }
}

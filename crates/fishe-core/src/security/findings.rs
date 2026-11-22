//! What in a [`SecurityReport`] deserves attention, and why.
//!
//! Pure rules over the report: the same facts always give the same list.
//! Each finding states what was seen and what it does and does not prove.
//! Nothing here says a program or a device is malicious; packet headers
//! cannot show that.
//!
//! | Finding | Info | Notice | Warning |
//! |---|---|---|---|
//! | Unencrypted service | on the local network only; or a protocol that may upgrade to TLS; or little HTTP; or HTTP to hosts that use it by design (certificate status, connectivity checks, signed updates) | HTTP to the Internet; a login protocol on the local network | a login protocol (Telnet, FTP, …) to the Internet |
//! | Outdated TLS offered | | always | |
//! | Many ports tried by one address | | always | when a connection was accepted |
//! | Connection accepted from the Internet | | always | on a remote-access, file-sharing or database port |
//! | Sensitive service reachable from the network | remote access, file sharing, databases | services that often run without a password | |
//! | DNS server failing | | 20 % of at least 20 questions | |
//! | DNS unencrypted to the Internet | always | | |
//! | Gateway hardware address changed | | | always |
//! | New device on the local network | always | | |
//! | Several DHCP servers on one network | | they hand out the same gateway and DNS | they hand out different ones |
//! | A VPN carries IPv4 while IPv6 leaves directly | | | always |
//! | DNS questions, or other Internet traffic, outside the VPN | | always | |

use super::services;
use super::vpn::{RouteVia, VpnAudit};
use super::{
    Certainty, Finding, FindingKind, InboundPeer, Listener, PlainUse, ProgramAudit, Reach,
    SecurityReport, Severity,
};
use crate::naming::addr::AddrScope;
use crate::net::parse::Transport;
use std::collections::BTreeMap;

/// HTTP to the Internet below this much is noted, not flagged: connectivity
/// checks and certificate status requests use plain HTTP by design.
pub const HTTP_NOTICE_BYTES: u64 = 64 * 1024;
/// A DNS server is judged once it was asked this often…
pub const DNS_MIN_QUERIES: u64 = 20;
/// …and flagged when this share went wrong.
pub const DNS_FAILURE_SHARE: f64 = 0.2;
/// Subjects listed per finding.
const MAX_SUBJECTS: usize = 5;

/// Everything worth attention in `report`, most severe first.
pub fn derive(report: &SecurityReport) -> Vec<Finding> {
    let mut out = Vec::new();
    if let Some(s) = &report.session {
        for p in &s.programs {
            out.extend(p.plaintext.iter().filter_map(|u| plaintext(p, u)));
            out.extend(old_tls(p));
        }
        out.extend(s.inbound.iter().filter_map(port_scan));
        out.extend(accepted_from_internet(&s.inbound, &report.listeners));
        for d in &s.dns.servers {
            let wrong = d.failed + d.unanswered;
            if d.queries >= DNS_MIN_QUERIES && wrong as f64 >= d.queries as f64 * DNS_FAILURE_SHARE
            {
                out.push(Finding {
                    id: format!("dns-failures:{}", d.ip),
                    severity: Severity::Notice,
                    kind: FindingKind::DnsFailures,
                    title: format!(
                        "DNS server {} failed {wrong} of {} questions",
                        d.ip, d.queries
                    ),
                    detail: "Names that cannot be resolved make programs stall or fail. \
                             The server may be overloaded, unreachable, or refusing some names."
                        .into(),
                    program: None,
                    subjects: vec![format!(
                        "{} without an answer, {} answered with an error",
                        d.unanswered, d.failed
                    )],
                });
            }
        }
        // One line for every Internet server asked in clear text: a
        // resolver often has several addresses.
        let clear: Vec<_> = s
            .dns
            .servers
            .iter()
            .filter(|d| d.scope == AddrScope::Public && d.queries > 0)
            .collect();
        if !clear.is_empty() {
            let n = clear.len();
            let questions: u64 = clear.iter().map(|d| d.queries).sum();
            out.push(Finding {
                id: "dns-clear".into(),
                severity: Severity::Info,
                kind: FindingKind::DnsUnencrypted,
                title: format!(
                    "DNS questions go unencrypted to {n} server{} on the Internet: {questions} so far",
                    plural(n)
                ),
                detail: "Every network between this machine and those servers can read which \
                         names are looked up, and could alter the answers. Encrypted DNS (DNS \
                         over HTTPS or TLS) prevents both. A browser may already use it for its \
                         own lookups while the rest of the system does not."
                    .into(),
                program: None,
                subjects: clear
                    .iter()
                    .take(MAX_SUBJECTS)
                    .map(|d| match d.owner.as_ref().and_then(|o| o.org.as_deref()) {
                        Some(org) => format!("{} ({org})", d.ip),
                        None => d.ip.to_string(),
                    })
                    .collect(),
            });
        }
    }
    if let Some(s) = &report.session {
        // Servers heard during the session, per interface.
        let mut by_iface: BTreeMap<&str, Vec<Handout>> = BTreeMap::new();
        for d in &s.dhcp {
            by_iface
                .entry(d.interface.as_str())
                .or_default()
                .push(Handout {
                    server: d.server.clone(),
                    mac: d.mac.clone(),
                    router: d.router.clone(),
                    dns: d.dns.clone(),
                });
        }
        out.extend(by_iface.into_iter().filter_map(|(iface, servers)| {
            second_dhcp(format!("dhcp-seen:{iface}"), iface, &servers)
        }));
    }
    out.extend(vpn(&report.vpn));
    out.extend(report.listeners.iter().filter_map(sensitive_listener));
    for lan in &report.lans {
        let servers: Vec<Handout> = lan
            .dhcp
            .iter()
            .map(|d| Handout {
                server: d.ip.to_string(),
                mac: d.mac.clone(),
                router: d.router.map(|r| r.to_string()),
                dns: d.dns.iter().map(|a| a.to_string()).collect(),
            })
            .collect();
        out.extend(second_dhcp(
            format!("dhcp:{}", lan.network),
            &lan.network,
            &servers,
        ));
        if let (Some(was), Some(now)) = (&lan.gateway_was, &lan.gateway_mac) {
            out.push(Finding {
                id: format!("gateway:{}:{now}", lan.network),
                severity: Severity::Warning,
                kind: FindingKind::GatewayChanged,
                title: format!(
                    "The gateway of {} answers from another hardware address",
                    lan.network
                ),
                detail: "Normal if the router was replaced or this is another network with the \
                         same addresses. Otherwise another device may be answering in the \
                         gateway's place, which lets it see or alter this network's traffic."
                    .into(),
                program: None,
                subjects: vec![format!("was {was}"), format!("now {now}")],
            });
        }
        if !lan.new_devices.is_empty() {
            let n = lan.new_devices.len();
            out.push(Finding {
                id: format!("new-devices:{}:{}", lan.network, lan.last_scan),
                severity: Severity::Info,
                kind: FindingKind::NewDevice,
                title: format!(
                    "{n} new device{} on {} since the previous scan",
                    plural(n),
                    lan.network
                ),
                detail: "Devices that were not there before: a guest, a new appliance, a phone \
                         with a new private address, or something that should not be there."
                    .into(),
                program: None,
                subjects: lan
                    .new_devices
                    .iter()
                    .take(MAX_SUBJECTS)
                    .map(|d| {
                        let who = d.hostname.as_ref().or(d.vendor.as_ref());
                        match who {
                            Some(who) => format!("{who} ({}, {})", d.ip, d.mac),
                            None => format!("{} ({})", d.ip, d.mac),
                        }
                    })
                    .collect(),
            });
        }
    }
    out.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));
    out
}

/// What one DHCP server hands out.
struct Handout {
    server: String,
    mac: Option<String>,
    router: Option<String>,
    dns: Vec<String>,
}

/// More than one DHCP server answering on `place` (a network or an interface).
fn second_dhcp(id: String, place: &str, servers: &[Handout]) -> Option<Finding> {
    if servers.len() < 2 {
        return None;
    }
    // Do they tell devices the same thing? Redundant servers do.
    let same = servers.windows(2).all(|w| {
        let dns = |h: &Handout| {
            let mut d = h.dns.clone();
            d.sort();
            d
        };
        w[0].router == w[1].router && dns(&w[0]) == dns(&w[1])
    });
    Some(Finding {
        id,
        severity: if same {
            Severity::Notice
        } else {
            Severity::Warning
        },
        kind: FindingKind::SecondDhcpServer,
        title: format!("{} DHCP servers answer on {place}", servers.len()),
        detail: format!(
            "A DHCP server tells every device that joins which gateway and DNS servers to use. \
             {} Normal where two servers are set up to back each other up; on a home network a \
             second one is a misconfigured device, or one placing itself in the path of the \
             others' traffic.",
            if same {
                "These hand out the same gateway and DNS servers."
            } else {
                "These hand out different gateways or DNS servers, so devices end up sending \
                 their traffic or their DNS questions to different places."
            }
        ),
        program: None,
        subjects: servers
            .iter()
            .take(MAX_SUBJECTS)
            .map(|h| {
                let mut s = h.server.clone();
                if let Some(mac) = &h.mac {
                    s.push_str(&format!(" ({mac})"));
                }
                if let Some(router) = &h.router {
                    s.push_str(&format!(": gateway {router}"));
                }
                if !h.dns.is_empty() {
                    s.push_str(&format!(", DNS {}", h.dns.join(" ")));
                }
                s
            })
            .collect(),
    })
}

/// What leaves this machine outside a VPN that carries its IPv4 traffic.
/// Without such a VPN there is nothing to compare with, and no finding.
fn vpn(v: &VpnAudit) -> Vec<Finding> {
    let mut out = Vec::new();
    if !v.routes_ipv4() {
        return out;
    }
    let tunnel = v.ipv4.interface.as_deref().unwrap_or("the VPN");
    if v.ipv6.via == RouteVia::Direct {
        out.push(Finding {
            id: "vpn-ipv6".into(),
            severity: Severity::Warning,
            kind: FindingKind::VpnOutside,
            title: format!("IPv6 traffic does not go through {tunnel}"),
            detail: "IPv4 traffic to the Internet is routed through the VPN, but IPv6 still \
                     leaves through the ordinary connection. Sites reached over IPv6 see this \
                     machine's real address, and that traffic is not protected by the VPN."
                .into(),
            program: None,
            subjects: v
                .ipv6
                .interface
                .iter()
                .map(|i| format!("IPv6 leaves through {i}"))
                .collect(),
        });
    }
    if v.measured && v.dns_outside > 0 {
        out.push(Finding {
            id: "vpn-dns".into(),
            severity: Severity::Notice,
            kind: FindingKind::VpnOutside,
            title: format!(
                "{} DNS question{} left outside {tunnel}",
                v.dns_outside,
                plural(v.dns_outside as usize)
            ),
            detail: "The names this machine looks up were sent, unencrypted, through the \
                     ordinary connection instead of the VPN: the local network and the \
                     Internet provider can see them. VPN clients usually have a setting to \
                     send DNS through the tunnel."
                .into(),
            program: None,
            subjects: Vec::new(),
        });
    }
    if v.measured && v.outside_count > 0 {
        out.push(Finding {
            id: "vpn-outside".into(),
            severity: Severity::Notice,
            kind: FindingKind::VpnOutside,
            title: format!(
                "{} Internet address{} reached outside {tunnel}",
                v.outside_count,
                if v.outside_count == 1 {
                    " was"
                } else {
                    "es were"
                }
            ),
            detail: "Besides the VPN server itself, this machine exchanged traffic with these \
                     addresses through the ordinary connection. That is what split tunnelling \
                     does on purpose; if the VPN is meant to carry everything, it is a leak."
                .into(),
            program: None,
            subjects: v
                .outside
                .iter()
                .take(MAX_SUBJECTS)
                .map(|e| format!("{} ({})", e.label(), human(e.bytes)))
                .collect(),
        });
    }
    out
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

/// "1.2 MB", for sentences.
fn human(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["kB", "MB", "GB", "TB"];
    if bytes < 1000 {
        return format!("{bytes} B");
    }
    let mut v = bytes as f64 / 1000.0;
    let mut unit = 0;
    while v >= 1000.0 && unit < UNITS.len() - 1 {
        v /= 1000.0;
        unit += 1;
    }
    if v < 10.0 {
        format!("{v:.1} {}", UNITS[unit])
    } else {
        format!("{v:.0} {}", UNITS[unit])
    }
}

/// "legacy.exe", or a wording for traffic no program was found for.
fn who(p: &ProgramAudit) -> String {
    if p.key.is_empty() {
        "A program Fishe could not identify".into()
    } else {
        p.name.clone()
    }
}

fn plaintext(p: &ProgramAudit, u: &PlainUse) -> Option<Finding> {
    let public = u.public_bytes > 0;
    let (severity, title, detail) = match u.certainty {
        Certainty::Credentials => (
            if public {
                Severity::Warning
            } else {
                Severity::Notice
            },
            format!(
                "{} used {} (unencrypted, carries logins): {}",
                who(p),
                u.service,
                human(u.bytes)
            ),
            format!(
                "{} sends everything in clear text, passwords and commands included: anyone on \
                 the way can read them. {}",
                u.service,
                if public {
                    "Some of it crossed the Internet."
                } else {
                    "It stayed on the local network."
                }
            ),
        ),
        // HTTP to hosts that serve public, separately verified content
        // over it on purpose: worth a line, whatever the amount.
        Certainty::Yes if by_design(u) => (
            Severity::Info,
            format!(
                "{} used {} (unencrypted) for certificate checks, connectivity checks or updates: {}",
                who(p),
                u.service,
                human(u.bytes)
            ),
            "These hosts serve certificate status, connectivity checks or signed updates over \
             plain HTTP by design: the content is public and verified by other means. Anyone on \
             the way can still see that they were contacted."
                .to_string(),
        ),
        Certainty::Yes => (
            match (public, u.public_bytes >= HTTP_NOTICE_BYTES) {
                (true, true) => Severity::Notice,
                _ => Severity::Info,
            },
            format!(
                "{} used {} (unencrypted): {}",
                who(p),
                u.service,
                human(u.bytes)
            ),
            format!(
                "The content of {} can be read and altered on the way. Fishe sees the port, not \
                 the content: this says the service is unencrypted, not what was sent. Small \
                 amounts are usual.",
                u.service
            ),
        ),
        // A protocol that may have switched to TLS: only worth a line when
        // it crossed the Internet.
        Certainty::Maybe if public => (
            Severity::Info,
            format!(
                "{} used {}, which is only encrypted if the program upgrades it: {}",
                who(p),
                u.service,
                human(u.bytes)
            ),
            format!(
                "{} starts unencrypted and can switch to TLS (STARTTLS). Packet headers do not \
                 show whether it did; the program's own settings do.",
                u.service
            ),
        ),
        Certainty::Maybe => return None,
    };
    Some(Finding {
        id: format!("plain:{}:{:?}:{}", p.key, u.transport, u.port),
        severity,
        kind: FindingKind::Plaintext,
        title,
        detail,
        program: Some(p.name.clone()),
        subjects: u
            .endpoints
            .iter()
            .take(MAX_SUBJECTS)
            .map(|e| e.label())
            .collect(),
    })
}

/// Is every endpoint listed for this HTTP use a host that serves plain
/// HTTP by design? (An endpoint without a name is not.)
fn by_design(u: &PlainUse) -> bool {
    u.port == 80
        && !u.endpoints.is_empty()
        && u.endpoints.len() == u.endpoint_count as usize
        && u.endpoints
            .iter()
            .all(|e| e.name.as_deref().is_some_and(services::is_http_by_design))
}

fn old_tls(p: &ProgramAudit) -> Option<Finding> {
    let oldest = p.old_tls.iter().map(|t| t.version.as_str()).min()?;
    let n = p.old_tls.len();
    Some(Finding {
        id: format!("old-tls:{}", p.key),
        severity: Severity::Notice,
        kind: FindingKind::OldTls,
        title: format!(
            "{} offered nothing newer than {oldest} to {n} server{}",
            who(p),
            plural(n)
        ),
        detail: "TLS 1.0 and 1.1 are retired: their protection is weaker and current servers \
                 refuse them. A program that offers nothing newer is usually old or unmaintained. \
                 This is what the program offered, not what the server chose."
            .into(),
        program: Some(p.name.clone()),
        subjects: p
            .old_tls
            .iter()
            .take(MAX_SUBJECTS)
            .map(|t| format!("{} ({})", t.server.label(), t.version))
            .collect(),
    })
}

fn port_scan(peer: &InboundPeer) -> Option<Finding> {
    if !peer.scan {
        return None;
    }
    let from = match peer.scope {
        AddrScope::Public => "the Internet",
        _ => "the local network",
    };
    Some(Finding {
        id: format!("scan:{}", peer.ip),
        severity: if peer.accepted > 0 {
            Severity::Warning
        } else {
            Severity::Notice
        },
        kind: FindingKind::PortScan,
        title: format!(
            "{} on {from} tried {} ports of this machine",
            peer.name.as_deref().unwrap_or(&peer.ip.to_string()),
            peer.port_count
        ),
        detail: format!(
            "Trying many ports is how a device looks for services to connect to: a security \
             scanner, a network tool, or something probing for weaknesses. {}",
            if peer.accepted > 0 {
                "This machine accepted at least one of those connections."
            } else {
                "None of the attempts was accepted."
            }
        ),
        program: None,
        subjects: std::iter::once(peer.ip.to_string())
            .chain((!peer.accepted_ports.is_empty()).then(|| {
                format!(
                    "accepted on {}",
                    peer.accepted_ports
                        .iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }))
            .collect(),
    })
}

/// Connections accepted from Internet addresses, one finding per local port.
fn accepted_from_internet(peers: &[InboundPeer], listeners: &[Listener]) -> Vec<Finding> {
    let mut by_port: BTreeMap<u16, Vec<&InboundPeer>> = BTreeMap::new();
    for peer in peers
        .iter()
        .filter(|p| p.scope == AddrScope::Public && !p.scan)
    {
        for &port in &peer.accepted_ports {
            by_port.entry(port).or_default().push(peer);
        }
    }
    by_port
        .into_iter()
        .map(|(port, peers)| {
            let program = listeners
                .iter()
                .find(|l| l.port == port)
                .map(|l| l.program.clone());
            let service = services::sensitive_listener(Transport::Tcp, port);
            let n = peers.len();
            Finding {
                id: format!("accepted:{port}"),
                severity: if service.is_some() {
                    Severity::Warning
                } else {
                    Severity::Notice
                },
                kind: FindingKind::InboundAccepted,
                title: format!(
                    "{n} Internet address{} connected to this machine on port {port}{}",
                    if n == 1 { "" } else { "es" },
                    match (service, &program) {
                        (Some(s), _) => format!(" ({s})"),
                        (None, Some(p)) => format!(" ({p})"),
                        (None, None) => String::new(),
                    }
                ),
                detail: "This machine is reachable from the Internet on that port and a program \
                         accepted the connection. Expected for a server, a game host or a \
                         file-sharing program; otherwise check why the port is open."
                    .into(),
                program,
                subjects: peers
                    .iter()
                    .take(MAX_SUBJECTS)
                    .map(|p| match &p.name {
                        Some(name) => format!("{name} ({})", p.ip),
                        None => p.ip.to_string(),
                    })
                    .collect(),
            }
        })
        .collect()
}

fn sensitive_listener(l: &Listener) -> Option<Finding> {
    if !l.sensitive || l.reach != Reach::Network {
        return None;
    }
    let service = l.service.as_deref().unwrap_or("a sensitive service");
    // Services that are often installed without any password.
    let open_by_default = matches!(l.port, 23 | 21 | 5900..=5903 | 6379 | 27017 | 9200 | 2375);
    Some(Finding {
        id: format!("listener:{}:{}", l.program.to_ascii_lowercase(), l.port),
        severity: if open_by_default {
            Severity::Notice
        } else {
            Severity::Info
        },
        kind: FindingKind::SensitiveListener,
        title: format!(
            "{} accepts {service} connections from the network (port {})",
            l.program, l.port
        ),
        detail: format!(
            "Other machines on this network can try to connect to it, unless a firewall stops \
             them (Fishe does not see firewall rules). {}",
            if open_by_default {
                "This kind of service often runs without a password."
            } else {
                "Fine on a network you trust; worth turning off on public Wi-Fi if unused."
            }
        ),
        program: Some(l.program.clone()),
        subjects: vec![format!("bound to {}", l.address)],
    })
}

#[cfg(test)]
mod tests {
    use super::super::tests::sample_report;
    use super::*;
    use crate::lan::inventory::Inventory;

    fn find<'a>(f: &'a [Finding], id: &str) -> &'a Finding {
        f.iter().find(|f| f.id == id).unwrap_or_else(|| {
            panic!(
                "no finding {id} in {:#?}",
                f.iter().map(|f| &f.id).collect::<Vec<_>>()
            )
        })
    }

    #[test]
    fn sizes_read_naturally() {
        assert_eq!(human(999), "999 B");
        assert_eq!(human(1500), "1.5 kB");
        assert_eq!(human(64_000), "64 kB");
        assert_eq!(human(2_340_000), "2.3 MB");
        assert_eq!(human(u64::MAX), "18446744 TB");
    }

    #[test]
    fn the_sample_session_yields_the_expected_findings() {
        let report = sample_report(&Inventory::default());
        let f = &report.findings;

        // Telnet on the local network: a login protocol, but it stayed home.
        let telnet = find(f, "plain:legacy.exe:Tcp:23");
        assert_eq!(telnet.severity, Severity::Notice);
        assert!(telnet.title.contains("legacy.exe used Telnet"));
        assert_eq!(telnet.subjects, ["192.168.1.50"]);

        // A little HTTP to the Internet: noted, not flagged.
        let http = find(f, "plain:legacy.exe:Tcp:80");
        assert_eq!(http.severity, Severity::Info);
        assert_eq!(http.subjects, ["example.com (93.184.216.34)"]);
        assert_eq!(http.program.as_deref(), Some("legacy.exe"));

        // IMAP may have upgraded to TLS.
        assert_eq!(find(f, "plain:legacy.exe:Tcp:143").severity, Severity::Info);

        let tls = find(f, "old-tls:legacy.exe");
        assert_eq!(tls.severity, Severity::Notice);
        assert!(tls.title.contains("TLS 1.0"));

        let scan = find(f, "scan:45.33.32.156");
        assert_eq!(scan.severity, Severity::Notice, "nothing was accepted");
        assert!(scan.title.contains("the Internet tried 20 ports"));

        // Remote Desktop accepted a connection from the Internet.
        let rdp = find(f, "accepted:3389");
        assert_eq!(rdp.severity, Severity::Warning);
        assert_eq!(rdp.program.as_deref(), Some("svchost.exe"));
        assert!(rdp.title.contains("1 Internet address connected"));
        assert!(rdp.title.contains("Remote Desktop"));
        // File sharing used from the local network is ordinary.
        assert!(!f.iter().any(|f| f.id == "accepted:445"));

        // The router failed 4 of 10: too few questions to judge.
        assert!(!f.iter().any(|f| f.kind == FindingKind::DnsFailures));
        // One line for the Internet servers asked in clear; the router is
        // on the local network.
        let clear = find(f, "dns-clear");
        assert_eq!(clear.severity, Severity::Info);
        assert!(clear.title.contains("1 server on the Internet: 1 so far"));
        assert_eq!(clear.subjects, ["8.8.8.8"]);

        // Listening services: reachable ones only.
        assert_eq!(
            find(f, "listener:svchost.exe:3389").severity,
            Severity::Info
        );
        assert!(f.iter().any(|f| f.id == "listener:pid 4:445"));
        assert!(
            !f.iter().any(|f| f.id.ends_with(":5432")),
            "bound to loopback"
        );

        // Most severe first, then stable.
        let severities: Vec<Severity> = f.iter().map(|f| f.severity).collect();
        let mut sorted = severities.clone();
        sorted.sort_by(|a, b| b.cmp(a));
        assert_eq!(severities, sorted);
        assert_eq!(f[0].id, "accepted:3389");
        // The same report gives the same findings.
        assert_eq!(derive(&report), *f);
    }

    #[test]
    fn severity_follows_where_the_traffic_went_and_how_much() {
        let mut report = sample_report(&Inventory::default());
        let s = report.session.as_mut().unwrap();
        let legacy = s
            .programs
            .iter_mut()
            .find(|p| p.name == "legacy.exe")
            .unwrap();
        for u in &mut legacy.plaintext {
            match u.port {
                // Telnet across the Internet.
                23 => u.public_bytes = u.bytes,
                // Enough HTTP to matter.
                80 => {
                    u.bytes = 5_000_000;
                    u.public_bytes = 5_000_000;
                }
                // IMAP that never left the local network.
                _ => u.public_bytes = 0,
            }
        }
        // The scanner got in.
        let scan = s.inbound.iter_mut().find(|p| p.scan).unwrap();
        scan.accepted = 1;
        scan.accepted_ports = vec![22];
        // A DNS server asked often enough, failing a quarter of the time.
        let dns = &mut s.dns.servers[0];
        (dns.queries, dns.failed, dns.unanswered) = (40, 4, 6);

        let f = derive(&report);
        assert_eq!(
            find(&f, "plain:legacy.exe:Tcp:23").severity,
            Severity::Warning
        );
        let http = find(&f, "plain:legacy.exe:Tcp:80");
        assert_eq!(http.severity, Severity::Notice);
        assert!(http.title.ends_with("5.0 MB"));
        assert!(!f.iter().any(|f| f.id == "plain:legacy.exe:Tcp:143"));
        let scan = find(&f, "scan:45.33.32.156");
        assert_eq!(scan.severity, Severity::Warning);
        assert_eq!(scan.subjects, ["45.33.32.156", "accepted on 22"]);
        // A scan is reported as a scan, not also as an accepted connection.
        assert!(!f.iter().any(|f| f.id == "accepted:22"));
        let dns = find(&f, "dns-failures:192.168.1.1");
        assert!(dns.title.contains("failed 10 of 40"));
    }

    #[test]
    fn http_to_hosts_that_use_it_by_design_is_only_noted() {
        let mut report = sample_report(&Inventory::default());
        let s = report.session.as_mut().unwrap();
        let legacy = s
            .programs
            .iter_mut()
            .find(|p| p.name == "legacy.exe")
            .unwrap();
        let http = legacy.plaintext.iter_mut().find(|u| u.port == 80).unwrap();
        (http.bytes, http.public_bytes) = (9_000_000, 9_000_000);
        // A lot of HTTP to an ordinary site: flagged.
        assert_eq!(
            find(&derive(&report), "plain:legacy.exe:Tcp:80").severity,
            Severity::Notice
        );

        // The same amount, all of it certificate revocation lists.
        let s = report.session.as_mut().unwrap();
        let legacy = s
            .programs
            .iter_mut()
            .find(|p| p.name == "legacy.exe")
            .unwrap();
        let http = legacy.plaintext.iter_mut().find(|u| u.port == 80).unwrap();
        http.endpoints[0].name = Some("crls.ssl.com".into());
        let f = derive(&report);
        let noted = find(&f, "plain:legacy.exe:Tcp:80");
        assert_eq!(noted.severity, Severity::Info);
        assert!(noted.title.contains("certificate checks"));

        // One endpoint that is not on the list, or more endpoints than
        // are listed: no longer "by design".
        let s = report.session.as_mut().unwrap();
        let legacy = s
            .programs
            .iter_mut()
            .find(|p| p.name == "legacy.exe")
            .unwrap();
        let http = legacy.plaintext.iter_mut().find(|u| u.port == 80).unwrap();
        http.endpoint_count = 9;
        assert_eq!(
            find(&derive(&report), "plain:legacy.exe:Tcp:80").severity,
            Severity::Notice
        );
    }

    #[test]
    fn dhcp_servers_that_disagree_are_a_warning() {
        let h = |server: &str, router: &str, dns: &[&str]| Handout {
            server: server.into(),
            mac: Some("de:ad:be:ef:00:01".into()),
            router: Some(router.into()),
            dns: dns.iter().map(|d| d.to_string()).collect(),
        };
        let one = [h("192.168.1.1", "192.168.1.1", &["192.168.1.1"])];
        assert_eq!(second_dhcp("x".into(), "192.168.1.0/24", &one), None);

        // Two that back each other up (DNS listed in another order).
        let pair = [
            h("10.0.0.2", "10.0.0.1", &["10.0.0.53", "10.0.0.54"]),
            h("10.0.0.3", "10.0.0.1", &["10.0.0.54", "10.0.0.53"]),
        ];
        let f = second_dhcp("dhcp:10.0.0.0/24".into(), "10.0.0.0/24", &pair).unwrap();
        assert_eq!(f.severity, Severity::Notice);
        assert_eq!(f.title, "2 DHCP servers answer on 10.0.0.0/24");

        // One that hands out itself as gateway and DNS.
        let rogue = [
            h("192.168.1.1", "192.168.1.1", &["192.168.1.1"]),
            h("192.168.1.66", "192.168.1.66", &["192.168.1.66"]),
        ];
        let f = second_dhcp("dhcp:192.168.1.0/24".into(), "192.168.1.0/24", &rogue).unwrap();
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(
            f.subjects[1],
            "192.168.1.66 (de:ad:be:ef:00:01): gateway 192.168.1.66, DNS 192.168.1.66"
        );
    }

    #[test]
    fn nothing_is_said_about_a_vpn_that_does_not_carry_the_traffic() {
        use crate::security::vpn::{Iface, Measured, audit};
        let iface = |name: &str, addr: &str| Iface {
            name: name.into(),
            description: name.into(),
            addresses: vec![addr.parse().unwrap()],
            active: true,
        };
        let ifaces = vec![
            iface("eth0", "192.168.1.19"),
            iface("tailscale0", "100.90.1.2"),
        ];
        let measured = Measured {
            on_tunnel: true,
            outside_count: 5,
            dns_outside: 9,
            ..Default::default()
        };
        // A mesh VPN is up, but the Internet is reached directly: nothing
        // "leaks", because nothing was meant to go through it.
        let direct = audit(
            Ok(ifaces.clone()),
            Some("192.168.1.19".parse().unwrap()),
            None,
            Some(measured.clone()),
        );
        assert!(vpn(&direct).is_empty());
        // Routed through it, with no IPv6 at all and nothing measured outside.
        let clean = audit(
            Ok(ifaces.clone()),
            Some("100.90.1.2".parse().unwrap()),
            None,
            None,
        );
        assert!(vpn(&clean).is_empty());
        // Routed through it, and things left outside.
        let leaky = audit(
            Ok(ifaces),
            Some("100.90.1.2".parse().unwrap()),
            None,
            Some(measured),
        );
        let ids: Vec<String> = vpn(&leaky).into_iter().map(|f| f.id).collect();
        assert_eq!(ids, ["vpn-dns", "vpn-outside"]);
    }

    #[test]
    fn unidentified_programs_are_named_as_such() {
        let mut report = sample_report(&Inventory::default());
        let s = report.session.as_mut().unwrap();
        let p = s
            .programs
            .iter_mut()
            .find(|p| p.name == "legacy.exe")
            .unwrap();
        p.key = String::new();
        p.name = "Unattributed".into();
        let f = derive(&report);
        let http = find(&f, "plain::Tcp:80");
        assert!(
            http.title
                .starts_with("A program Fishe could not identify used HTTP")
        );
    }

    #[test]
    fn services_without_passwords_by_default_stand_out() {
        let l = |port: u16, reach: Reach| Listener {
            program: "db.exe".into(),
            pid: 1,
            port,
            reach,
            address: "all addresses".into(),
            service: services::listener_name(Transport::Tcp, port).map(str::to_string),
            sensitive: reach == Reach::Network
                && services::sensitive_listener(Transport::Tcp, port).is_some(),
        };
        assert_eq!(
            sensitive_listener(&l(6379, Reach::Network))
                .unwrap()
                .severity,
            Severity::Notice
        );
        assert_eq!(
            sensitive_listener(&l(22, Reach::Network)).unwrap().severity,
            Severity::Info
        );
        assert_eq!(sensitive_listener(&l(6379, Reach::Loopback)), None);
        assert_eq!(sensitive_listener(&l(8080, Reach::Network)), None);
    }
}

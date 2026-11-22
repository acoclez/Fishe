//! The security view: what the measurements say about how exposed this
//! machine is, and what on it deserves a look.
//!
//! Fishe observes; it blocks nothing and judges nobody's intentions. This
//! module turns facts it already has into a report:
//!
//! - **Programs**: who each program talks to (organisations, countries),
//!   how much of it over services that are not encrypted, and whether it
//!   still offers an outdated TLS version ([`audit`], during an
//!   all-traffic session).
//! - **Exposure**: the programs accepting connections from other machines
//!   (the socket table, at any time) and the connection attempts received
//!   during the session.
//! - **DNS**: the servers asked, their failures and latency, and whether
//!   the questions travel encrypted.
//! - **VPN**: whether a tunnel is up, whether Internet traffic leaves
//!   through it, and what left outside it ([`vpn`]).
//! - **Local network**: devices that appeared since the last scan, a
//!   gateway whose hardware address changed, and the DHCP servers that
//!   answer ([`crate::lan::inventory`], [`crate::lan::dhcp`]).
//!
//! [`findings`] reads that report and lists what is worth attention, with
//! the reason. A finding is a fact plus why it matters, never a verdict
//! that something is malicious. See `docs/security.md`.

pub mod audit;
pub mod findings;
pub mod services;
pub mod vpn;

use crate::geo::{Geo, Owner};
use crate::lan::dhcp::DhcpServer;
use crate::lan::inventory::Inventory;
use crate::naming::addr::{self, AddrScope};
use crate::naming::book::NameBook;
use crate::net::parse::Transport;
use crate::process::sockets::SocketEntry;
use audit::{Facts, PeerFacts, ProgramFacts, ResolverFacts};
use serde::Serialize;
use services::Clear;
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

/// Distinct local ports one address must try before it is called a scan.
pub const SCAN_PORTS: usize = 10;
/// Rows listed per table; the report says how many more there are.
const MAX_ROWS: usize = 200;
/// Examples carried per row (endpoints, organisations, ports).
const MAX_EXAMPLES: usize = 6;

/// How much attention a finding asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub enum Severity {
    /// Worth knowing; usually nothing to do.
    Info,
    /// Worth a look.
    Notice,
    /// Worth acting on, or at least understanding.
    Warning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub enum FindingKind {
    /// A program used a service that is not encrypted.
    Plaintext,
    /// A program offered nothing newer than an outdated TLS version.
    OldTls,
    /// One address tried many ports of this machine.
    PortScan,
    /// A program accepted a connection from the Internet.
    InboundAccepted,
    /// A remote-access, file-sharing or database service accepts
    /// connections from other machines.
    SensitiveListener,
    /// A DNS server fails or does not answer much of the time.
    DnsFailures,
    /// DNS questions travel unencrypted to a server on the Internet.
    DnsUnencrypted,
    /// The gateway's hardware address is not the one seen before.
    GatewayChanged,
    /// A device joined the local network since the previous scan.
    NewDevice,
    /// More than one DHCP server answers on a network.
    SecondDhcpServer,
    /// A VPN is up, and something leaves this machine outside it.
    VpnOutside,
}

/// Something worth attention, with the reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    /// Stable while the finding stands, so a list can keep its rows still.
    pub id: String,
    pub severity: Severity,
    pub kind: FindingKind,
    /// What was seen, in one line.
    pub title: String,
    /// Why it matters and what it does not prove.
    pub detail: String,
    pub program: Option<String>,
    /// The endpoints, ports or devices concerned (a few of them).
    pub subjects: Vec<String>,
}

/// A remote address with what is known about it.
#[derive(Debug, Clone, PartialEq, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct EndpointRef {
    pub ip: IpAddr,
    pub name: Option<String>,
    pub scope: AddrScope,
    pub bytes: u64,
}

impl EndpointRef {
    /// `name (address)` or the address alone.
    pub fn label(&self) -> String {
        match &self.name {
            Some(name) => format!("{name} ({})", self.ip),
            None => self.ip.to_string(),
        }
    }
}

/// How sure the port makes us that the content is unencrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub enum Certainty {
    /// The protocol can upgrade to TLS; the headers do not show whether it did.
    Maybe,
    Yes,
    /// Unencrypted, and the protocol carries logins or commands.
    Credentials,
}

/// A program's use of one unencrypted service.
#[derive(Debug, Clone, PartialEq, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct PlainUse {
    /// "HTTP", "Telnet", …
    pub service: String,
    pub transport: Transport,
    pub port: u16,
    pub certainty: Certainty,
    pub bytes: u64,
    /// Bytes exchanged with addresses on the Internet (the rest stayed on
    /// the local network).
    pub public_bytes: u64,
    pub endpoint_count: u32,
    /// The busiest few.
    pub endpoints: Vec<EndpointRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Share {
    /// A country code ("US") or an organisation's name.
    pub name: String,
    pub bytes: u64,
    pub endpoints: u32,
}

/// A server a program offered an outdated TLS version to.
#[derive(Debug, Clone, PartialEq, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct OldTls {
    pub server: EndpointRef,
    /// "TLS 1.0"
    pub version: String,
}

/// One program's side of the session.
#[derive(Debug, Clone, PartialEq, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct ProgramAudit {
    /// Grouping key (lower-case executable name; `""` = unattributed).
    pub key: String,
    pub name: String,
    pub bytes: u64,
    /// Remote addresses it exchanged traffic with.
    pub endpoints: u32,
    /// Those on the Internet.
    pub public_endpoints: u32,
    /// Countries of the public endpoints, most traffic first.
    pub countries: Vec<Share>,
    /// Organisations owning them, most traffic first (a few).
    pub owners: Vec<Share>,
    pub owner_count: u32,
    /// Public endpoints whose owner is not known (no owner database, or
    /// not in it).
    pub unknown_owner: u32,
    pub plaintext: Vec<PlainUse>,
    /// Bytes over services that are certainly unencrypted.
    pub plain_bytes: u64,
    pub tls_hellos: u32,
    pub old_tls: Vec<OldTls>,
}

/// Who can reach a listening socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub enum Reach {
    /// Bound to a network address: other machines can connect, unless a
    /// firewall stops them (which Fishe does not see).
    Network,
    /// Bound to the loopback address: this machine only.
    Loopback,
}

/// A program accepting TCP connections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Listener {
    pub program: String,
    pub pid: u32,
    pub port: u16,
    pub reach: Reach,
    /// "all addresses", or the addresses it is bound to.
    pub address: String,
    /// What usually runs on that port, when the number is well known.
    pub service: Option<String>,
    /// Remote access, file sharing or a database, reachable from the network.
    pub sensitive: bool,
}

/// What one remote address tried against this machine.
#[derive(Debug, Clone, PartialEq, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct InboundPeer {
    pub ip: IpAddr,
    pub name: Option<String>,
    pub scope: AddrScope,
    pub owner: Option<Owner>,
    /// Distinct local ports tried.
    pub port_count: u32,
    /// The first few, lowest first.
    pub ports: Vec<u16>,
    /// Connection requests received.
    pub attempts: u32,
    /// Requests this machine accepted.
    pub accepted: u32,
    /// Ports on which it was accepted.
    pub accepted_ports: Vec<u16>,
    /// Many ports tried: looks like a scan.
    pub scan: bool,
    /// Session time of the latest attempt.
    pub last_ms: u64,
}

/// One DNS server's figures.
#[derive(Debug, Clone, PartialEq, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct DnsServer {
    pub ip: IpAddr,
    pub name: Option<String>,
    pub scope: AddrScope,
    pub owner: Option<Owner>,
    pub queries: u64,
    pub answered: u64,
    pub unanswered: u64,
    /// "No such name" answers (normal).
    pub nxdomain: u64,
    /// Answers saying the server could not or would not resolve.
    pub failed: u64,
    pub avg_ms: Option<f64>,
    pub max_ms: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct DnsAudit {
    /// Servers asked in clear text (UDP port 53), busiest first.
    pub servers: Vec<DnsServer>,
    /// Servers reached on the DNS-over-TLS port.
    pub over_tls: Vec<EndpointRef>,
    /// Connections to known DNS-over-HTTPS hosts.
    pub over_https: Vec<EndpointRef>,
}

/// What an all-traffic session saw.
#[derive(Debug, Clone, PartialEq, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct SessionAudit {
    /// Session time covered.
    pub t_ms: u64,
    /// Busiest first.
    pub programs: Vec<ProgramAudit>,
    pub program_count: u32,
    /// Most ports tried first.
    pub inbound: Vec<InboundPeer>,
    pub inbound_count: u32,
    pub dns: DnsAudit,
    /// DHCP servers seen answering during the session, by interface.
    pub dhcp: Vec<DhcpSeen>,
}

/// A DHCP server whose answers went by during the session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct DhcpSeen {
    /// The interface it was heard on.
    pub interface: String,
    pub server: String,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    /// Offers and acknowledgements seen.
    pub replies: u32,
    /// The gateway and DNS servers it hands out.
    pub router: Option<String>,
    pub dns: Vec<String>,
}

/// Why the report has no session part.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub enum SessionState {
    /// An all-traffic session is running: `session` is filled.
    Auditing,
    /// Nothing is being monitored.
    NoSession,
    /// A session runs, but on one host or one program: it does not see
    /// the whole machine.
    NotAllTraffic,
}

/// A device first seen in the latest scan of a network already known.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct NewDevice {
    pub mac: String,
    pub ip: String,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
}

/// One local network Fishe has scanned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct KnownLan {
    /// "192.168.1.0/24"
    pub network: String,
    pub gateway: Option<String>,
    pub gateway_mac: Option<String>,
    /// Devices ever seen on it.
    pub devices: u32,
    pub scans: u32,
    /// Unix ms.
    pub first_scan: i64,
    pub last_scan: i64,
    /// First seen in the latest scan.
    pub new_devices: Vec<NewDevice>,
    /// The gateway answered with another hardware address in the latest
    /// scan than in the one before: the address it had.
    pub gateway_was: Option<String>,
    /// The DHCP servers that answered in the latest scan.
    pub dhcp: Vec<DhcpServer>,
}

/// Everything the Security page shows.
#[derive(Debug, Clone, PartialEq, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct SecurityReport {
    pub state: SessionState,
    pub session: Option<SessionAudit>,
    /// Programs accepting TCP connections right now; reachable ones first.
    pub listeners: Vec<Listener>,
    /// Why `listeners` is empty, when the socket table could not be read.
    pub listeners_error: Option<String>,
    /// Local networks scanned so far, latest first.
    pub lans: Vec<KnownLan>,
    /// Tunnel interfaces, where Internet traffic leaves, and what left
    /// outside the tunnel.
    pub vpn: vpn::VpnAudit,
    /// Is the owner database installed? Without it organisations and
    /// countries are unknown.
    pub owner_data: bool,
    /// Most severe first.
    pub findings: Vec<Finding>,
}

/// What a report is built from.
pub struct Sources<'a> {
    pub state: SessionState,
    pub facts: Option<Facts>,
    pub names: Option<&'a NameBook>,
    pub geo: &'a Geo,
    /// The socket table and the names of the processes in it.
    pub sockets: Result<(Vec<SocketEntry>, HashMap<u32, String>), String>,
    pub inventory: &'a Inventory,
    /// This machine's interfaces, and the addresses it would send from to
    /// reach the Internet over IPv4 and IPv6 (see [`vpn::system`]).
    pub ifaces: Result<Vec<vpn::Iface>, String>,
    pub source_v4: Option<IpAddr>,
    pub source_v6: Option<IpAddr>,
}

/// Assemble the report and derive its findings.
pub fn report(src: Sources<'_>) -> SecurityReport {
    let look = Lookup {
        names: src.names,
        geo: src.geo,
    };
    let (listeners, listeners_error) = match &src.sockets {
        Ok((sockets, names)) => (listeners(sockets, names), None),
        Err(e) => (Vec::new(), Some(e.clone())),
    };
    let session = src.facts.as_ref().map(|f| session_audit(f, &look));
    let lans = src.inventory.summary();
    let measured = src.facts.as_ref().map(|f| measured(f, &look));
    let mut report = SecurityReport {
        state: src.state,
        session,
        listeners,
        listeners_error,
        lans,
        vpn: vpn::audit(src.ifaces, src.source_v4, src.source_v6, measured),
        owner_data: src.geo.has_database(),
        findings: Vec::new(),
    };
    report.findings = findings::derive(&report);
    report
}

/// Names and owners of addresses, from what is already known locally.
struct Lookup<'a> {
    names: Option<&'a NameBook>,
    geo: &'a Geo,
}

impl Lookup<'_> {
    fn name(&self, ip: IpAddr) -> Option<String> {
        self.names.and_then(|n| n.best(ip)).map(|(name, _)| name)
    }

    /// Never asks the online service: a report must not send addresses out.
    fn owner(&self, ip: IpAddr) -> Option<Owner> {
        self.geo.known_owner(ip)
    }

    fn endpoint(&self, ip: IpAddr, bytes: u64) -> EndpointRef {
        EndpointRef {
            ip,
            name: self.name(ip),
            scope: addr::classify(ip),
            bytes,
        }
    }
}

/// Addresses a program "talks to": not this machine, not a broadcast.
fn is_remote(scope: AddrScope) -> bool {
    matches!(
        scope,
        AddrScope::Public | AddrScope::Private | AddrScope::Cgnat | AddrScope::LinkLocal
    )
}

fn session_audit(f: &Facts, look: &Lookup<'_>) -> SessionAudit {
    let mut programs: Vec<ProgramAudit> = f
        .programs
        .iter()
        .map(|(key, p)| program_audit(key, p, look))
        .filter(|p| p.endpoints > 0 || !p.old_tls.is_empty())
        .collect();
    programs.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.key.cmp(&b.key)));
    let program_count = programs.len() as u32 + f.more_programs;
    programs.truncate(MAX_ROWS);

    let mut inbound: Vec<InboundPeer> = f
        .peers
        .iter()
        .map(|(&ip, p)| inbound_peer(ip, p, look))
        .collect();
    inbound.sort_by(|a, b| {
        (b.scan, b.accepted > 0, b.port_count, b.attempts)
            .cmp(&(a.scan, a.accepted > 0, a.port_count, a.attempts))
            .then_with(|| a.ip.cmp(&b.ip))
    });
    let inbound_count = inbound.len() as u32;
    inbound.truncate(MAX_ROWS);

    SessionAudit {
        t_ms: f.t_ms,
        programs,
        program_count,
        inbound,
        inbound_count,
        dns: dns_audit(f, look),
        dhcp: dhcp_seen(f),
    }
}

/// The DHCP servers heard during the session, by interface then address.
fn dhcp_seen(f: &Facts) -> Vec<DhcpSeen> {
    let mut out: Vec<DhcpSeen> = f
        .dhcp
        .iter()
        .map(|((interface, server), d)| DhcpSeen {
            interface: interface.clone(),
            server: server.to_string(),
            mac: d.mac.map(|m| crate::lan::oui::format_mac(&m)),
            vendor: d
                .mac
                .and_then(|m| crate::lan::oui::vendor(&m).map(str::to_string)),
            replies: d.replies,
            router: d.router.map(|r| r.to_string()),
            dns: d.dns.iter().map(|a| a.to_string()).collect(),
        })
        .collect();
    out.sort_by(|a, b| (&a.interface, &a.server).cmp(&(&b.interface, &b.server)));
    out
}

/// What the session measured on each side of the tunnel.
fn measured(f: &Facts, look: &Lookup<'_>) -> vpn::Measured {
    let mut outside: Vec<EndpointRef> = f
        .outside
        .iter()
        .map(|(&ip, &bytes)| look.endpoint(ip, bytes))
        .collect();
    outside.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.ip.cmp(&b.ip)));
    let outside_count = outside.len() as u32;
    // The carrier and a few others.
    outside.truncate(MAX_EXAMPLES + 3);
    vpn::Measured {
        on_tunnel: f.tunnels.iter().any(|t| *t),
        inside_bytes: f.inside_bytes,
        outside_bytes: f.outside_bytes,
        outside,
        outside_count,
        dns_outside: f.dns_outside,
    }
}

fn program_audit(key: &str, p: &ProgramFacts, look: &Lookup<'_>) -> ProgramAudit {
    let mut countries: HashMap<String, (u64, u32)> = HashMap::new();
    let mut owners: HashMap<String, (u64, u32)> = HashMap::new();
    let (mut endpoints, mut public, mut unknown) = (0u32, 0u32, 0u32);
    for (&ip, &bytes) in &p.endpoints {
        let scope = addr::classify(ip);
        if !is_remote(scope) {
            continue;
        }
        endpoints += 1;
        if scope != AddrScope::Public {
            continue;
        }
        public += 1;
        match look.owner(ip) {
            Some(o) => {
                if let Some(c) = o.country {
                    let e = countries.entry(c).or_default();
                    e.0 += bytes;
                    e.1 += 1;
                }
                match o.org {
                    Some(org) => {
                        let e = owners.entry(org).or_default();
                        e.0 += bytes;
                        e.1 += 1;
                    }
                    None => unknown += 1,
                }
            }
            None => unknown += 1,
        }
    }
    let shares = |m: HashMap<String, (u64, u32)>| {
        let mut v: Vec<Share> = m
            .into_iter()
            .map(|(name, (bytes, endpoints))| Share {
                name,
                bytes,
                endpoints,
            })
            .collect();
        v.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.name.cmp(&b.name)));
        v
    };
    let mut owners = shares(owners);
    let owner_count = owners.len() as u32;
    owners.truncate(MAX_EXAMPLES);

    // Unencrypted use, one row per service.
    let mut by_service: BTreeMap<(Transport, u16), Vec<EndpointRef>> = BTreeMap::new();
    for (&(ip, transport, port), &bytes) in &p.plain {
        if is_remote(addr::classify(ip)) {
            by_service
                .entry((transport, port))
                .or_default()
                .push(look.endpoint(ip, bytes));
        }
    }
    let mut plaintext: Vec<PlainUse> = by_service
        .into_iter()
        .filter_map(|((transport, port), mut eps)| {
            let service = services::plaintext(transport, port)?;
            eps.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.ip.cmp(&b.ip)));
            let bytes = eps.iter().map(|e| e.bytes).sum();
            let public_bytes = eps
                .iter()
                .filter(|e| e.scope == AddrScope::Public)
                .map(|e| e.bytes)
                .sum();
            let endpoint_count = eps.len() as u32;
            eps.truncate(MAX_EXAMPLES);
            Some(PlainUse {
                service: service.name.to_string(),
                transport,
                port,
                certainty: match service.clear {
                    Clear::Maybe => Certainty::Maybe,
                    Clear::Yes => Certainty::Yes,
                    Clear::Credentials => Certainty::Credentials,
                },
                bytes,
                public_bytes,
                endpoint_count,
                endpoints: eps,
            })
        })
        .collect();
    plaintext.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.port.cmp(&b.port)));
    let plain_bytes = plaintext
        .iter()
        .filter(|u| u.certainty != Certainty::Maybe)
        .map(|u| u.bytes)
        .sum();

    let mut old_tls: Vec<OldTls> = p
        .old_tls
        .iter()
        .filter_map(|(&ip, &v)| {
            Some(OldTls {
                server: look.endpoint(ip, p.endpoints.get(&ip).copied().unwrap_or(0)),
                version: services::tls_version_name(v)?.to_string(),
            })
        })
        .collect();
    old_tls.sort_by_key(|t| t.server.ip);

    ProgramAudit {
        key: key.to_string(),
        name: p.name.clone(),
        bytes: p.bytes,
        endpoints: endpoints + p.more_endpoints,
        public_endpoints: public,
        countries: shares(countries),
        owners,
        owner_count,
        unknown_owner: unknown,
        plaintext,
        plain_bytes,
        tls_hellos: p.tls_hellos,
        old_tls,
    }
}

fn inbound_peer(ip: IpAddr, p: &PeerFacts, look: &Lookup<'_>) -> InboundPeer {
    let port_count = p.ports.len() + p.more_ports as usize;
    InboundPeer {
        ip,
        name: look.name(ip),
        scope: addr::classify(ip),
        owner: look.owner(ip),
        port_count: port_count as u32,
        ports: p.ports.keys().copied().take(12).collect(),
        attempts: p.ports.values().map(|h| h.syns).sum(),
        accepted: p.ports.values().map(|h| h.answered).sum(),
        accepted_ports: p
            .ports
            .iter()
            .filter(|(_, h)| h.answered > 0)
            .map(|(&port, _)| port)
            .take(12)
            .collect(),
        scan: port_count >= SCAN_PORTS,
        last_ms: p.last_ms,
    }
}

fn dns_server(ip: IpAddr, r: &ResolverFacts, look: &Lookup<'_>) -> DnsServer {
    let ms = |us: u64| us as f64 / 1000.0;
    DnsServer {
        ip,
        name: look.name(ip),
        scope: addr::classify(ip),
        owner: look.owner(ip),
        queries: r.queries,
        answered: r.answered,
        unanswered: r.unanswered,
        nxdomain: r.nxdomain,
        failed: r.failed,
        avg_ms: (r.answered > 0).then(|| ms(r.latency_sum_us) / r.answered as f64),
        max_ms: (r.answered > 0).then(|| ms(r.latency_max_us)),
    }
}

fn dns_audit(f: &Facts, look: &Lookup<'_>) -> DnsAudit {
    let mut servers: Vec<DnsServer> = f
        .resolvers
        .iter()
        .map(|(&ip, r)| dns_server(ip, r, look))
        .collect();
    servers.sort_by(|a, b| b.queries.cmp(&a.queries).then_with(|| a.ip.cmp(&b.ip)));

    let mut over_tls: Vec<EndpointRef> = f.dot.iter().map(|&ip| look.endpoint(ip, 0)).collect();
    over_tls.sort_by_key(|e| e.ip);

    // Known DNS-over-HTTPS hosts among everything any program reached,
    // one entry per host (it usually has several addresses).
    let mut doh: HashMap<String, (IpAddr, u64)> = HashMap::new();
    for p in f.programs.values() {
        for (&ip, &bytes) in &p.endpoints {
            if let Some(name) = look.name(ip).filter(|n| services::is_doh_host(n)) {
                let e = doh.entry(name).or_insert((ip, 0));
                e.0 = e.0.min(ip);
                e.1 += bytes;
            }
        }
    }
    let mut over_https: Vec<EndpointRef> = doh
        .into_values()
        .map(|(ip, bytes)| look.endpoint(ip, bytes))
        .collect();
    over_https.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.ip.cmp(&b.ip)));
    over_https.truncate(MAX_EXAMPLES);

    DnsAudit {
        servers,
        over_tls,
        over_https,
    }
}

/// The programs accepting TCP connections, one row per program and port.
pub fn listeners(sockets: &[SocketEntry], names: &HashMap<u32, String>) -> Vec<Listener> {
    // (pid, port) → addresses bound.
    let mut bound: BTreeMap<(u32, u16), Vec<IpAddr>> = BTreeMap::new();
    for s in sockets
        .iter()
        .filter(|s| s.listening && s.transport == Transport::Tcp)
    {
        let ips = bound.entry((s.pid, s.local.port())).or_default();
        if !ips.contains(&s.local.ip()) {
            ips.push(s.local.ip());
        }
    }
    let mut out: Vec<Listener> = bound
        .into_iter()
        .map(|((pid, port), mut ips)| {
            ips.sort();
            let reach = if ips.iter().all(|ip| ip.is_loopback()) {
                Reach::Loopback
            } else {
                Reach::Network
            };
            let address = if ips.iter().any(|ip| ip.is_unspecified()) {
                "all addresses".to_string()
            } else {
                ips.iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let sensitive = reach == Reach::Network
                && services::sensitive_listener(Transport::Tcp, port).is_some();
            Listener {
                program: names
                    .get(&pid)
                    .cloned()
                    .unwrap_or_else(|| format!("PID {pid}")),
                pid,
                port,
                reach,
                address,
                service: services::listener_name(Transport::Tcp, port).map(str::to_string),
                sensitive,
            }
        })
        .collect();
    out.sort_by(|a, b| {
        (a.reach, !a.sensitive, a.port, a.pid).cmp(&(b.reach, !b.sensitive, b.port, b.pid))
    });
    out.truncate(MAX_ROWS);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::programs::Label;
    use crate::monitor::stats::{EndpointDelta, InboundHit};
    use std::net::SocketAddr;
    use std::time::Duration;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn listen(addr: &str, pid: u32) -> SocketEntry {
        SocketEntry {
            transport: Transport::Tcp,
            local: addr.parse::<SocketAddr>().unwrap(),
            remote: None,
            pid,
            listening: true,
        }
    }

    #[test]
    fn listeners_are_grouped_and_classified() {
        let sockets = [
            listen("0.0.0.0:445", 4),
            listen("[::]:445", 4),
            listen("127.0.0.1:47823", 900),
            listen("[::1]:47823", 900),
            listen("192.168.1.19:8080", 901),
            listen("0.0.0.0:49664", 700),
            // Not listeners.
            SocketEntry {
                listening: false,
                remote: Some("1.1.1.1:443".parse().unwrap()),
                ..listen("192.168.1.19:50000", 901)
            },
            SocketEntry {
                transport: Transport::Udp,
                listening: false,
                ..listen("0.0.0.0:5353", 901)
            },
        ];
        let names: HashMap<u32, String> = [
            (4, "System".to_string()),
            (900, "fishe.exe".to_string()),
            (901, "node.exe".to_string()),
        ]
        .into();
        let l = listeners(&sockets, &names);
        let rows: Vec<(&str, u16, Reach, &str, bool)> = l
            .iter()
            .map(|l| {
                (
                    l.program.as_str(),
                    l.port,
                    l.reach,
                    l.address.as_str(),
                    l.sensitive,
                )
            })
            .collect();
        assert_eq!(
            rows,
            [
                // Reachable and sensitive first, then by port; loopback last.
                ("System", 445, Reach::Network, "all addresses", true),
                ("node.exe", 8080, Reach::Network, "192.168.1.19", false),
                ("PID 700", 49664, Reach::Network, "all addresses", false),
                ("fishe.exe", 47823, Reach::Loopback, "127.0.0.1, ::1", false),
            ]
        );
        assert_eq!(l[0].service.as_deref(), Some("Windows file sharing (SMB)"));
        assert_eq!(l[2].service, None);
    }

    /// A session with a bit of everything, through the audit and into a report.
    pub(super) fn sample_report(inventory: &Inventory) -> SecurityReport {
        let audit = audit::Audit::new();
        let label = |name: &str| Label {
            key: name.to_ascii_lowercase(),
            name: name.into(),
        };
        let labels: HashMap<u32, Label> =
            [(10, label("legacy.exe")), (20, label("Browser.exe"))].into();
        let delta = |programs: &[(u32, u64)], ports: &[(Transport, u16, u64)]| EndpointDelta {
            programs: programs.iter().copied().collect(),
            ports: ports.iter().map(|&(t, p, b)| ((t, p), b)).collect(),
            ..Default::default()
        };
        let endpoints: HashMap<IpAddr, EndpointDelta> = [
            (
                ip("93.184.216.34"),
                delta(&[(10, 5000)], &[(Transport::Tcp, 80, 5000)]),
            ),
            (
                ip("192.168.1.50"),
                delta(&[(10, 800)], &[(Transport::Tcp, 23, 800)]),
            ),
            (
                ip("185.199.109.153"),
                delta(&[(10, 300)], &[(Transport::Tcp, 143, 300)]),
            ),
            (
                ip("1.1.1.1"),
                delta(&[(20, 9000)], &[(Transport::Tcp, 443, 9000)]),
            ),
            (
                ip("9.9.9.9"),
                delta(&[(20, 100)], &[(Transport::Tcp, 853, 100)]),
            ),
            // Not "talking to" anybody.
            (
                ip("224.0.0.251"),
                delta(&[(20, 50)], &[(Transport::Udp, 5353, 50)]),
            ),
        ]
        .into();
        let scanner = ip("45.33.32.156");
        let mut inbound: HashMap<(IpAddr, u16), InboundHit> = (20..40u16)
            .map(|port| {
                (
                    (scanner, port),
                    InboundHit {
                        syns: 2,
                        answered: 0,
                    },
                )
            })
            .collect();
        inbound.insert(
            (ip("104.20.23.154"), 3389),
            InboundHit {
                syns: 1,
                answered: 1,
            },
        );
        inbound.insert(
            (ip("192.168.1.50"), 445),
            InboundHit {
                syns: 3,
                answered: 3,
            },
        );
        // The data that passed on the audited ports (the scanner's refused
        // requests carried none).
        let payload: HashMap<(IpAddr, u16), u64> = [
            ((ip("93.184.216.34"), 80), 5000),
            ((ip("192.168.1.50"), 23), 800),
            ((ip("185.199.109.153"), 143), 300),
            ((ip("9.9.9.9"), 853), 100),
        ]
        .into();
        audit.tick(60_000, &endpoints, &payload, &inbound, &labels);
        audit.tls_hello(&label("legacy.exe"), ip("93.184.216.34"), 0x0301);
        audit.tls_hello(&label("Browser.exe"), ip("1.1.1.1"), 0x0304);
        let router = ip("192.168.1.1");
        for _ in 0..10 {
            audit.dns_query(router);
        }
        for _ in 0..6 {
            audit.dns_answer(router, Duration::from_millis(20), 0);
        }
        audit.dns_answer(router, Duration::from_millis(40), 2);
        audit.dns_unanswered(router, 3);
        let public = ip("8.8.8.8");
        audit.dns_query(public);
        audit.dns_answer(public, Duration::from_millis(15), 3);

        let names = NameBook::new();
        names.set_dns(ip("93.184.216.34"), "example.com".into());
        names.set_dns(ip("1.1.1.1"), "one.one.one.one".into());
        names.set_dns(ip("9.9.9.9"), "one.one.one.one".into());
        let geo = Geo::new(std::env::temp_dir().join("fishe-no-geo-here"));
        let sockets = vec![
            listen("0.0.0.0:3389", 5),
            listen("0.0.0.0:445", 4),
            listen("127.0.0.1:5432", 6),
        ];
        let pnames: HashMap<u32, String> = [(5, "svchost.exe".to_string())].into();
        report(Sources {
            state: SessionState::Auditing,
            facts: Some(audit.facts()),
            names: Some(&names),
            geo: &geo,
            sockets: Ok((sockets, pnames)),
            inventory,
            ifaces: Ok(Vec::new()),
            source_v4: None,
            source_v6: None,
        })
    }

    #[test]
    fn a_report_describes_programs_inbound_and_dns() {
        let r = sample_report(&Inventory::default());
        assert_eq!(r.state, SessionState::Auditing);
        assert!(!r.owner_data);
        let s = r.session.as_ref().unwrap();
        assert_eq!(s.t_ms, 60_000);

        // Busiest first.
        assert_eq!(s.programs[0].name, "Browser.exe");
        let browser = &s.programs[0];
        assert_eq!(
            browser.endpoints, 2,
            "the multicast group is not an endpoint"
        );
        assert_eq!(browser.public_endpoints, 2);
        assert_eq!(browser.unknown_owner, 2, "no owner database here");
        assert!(browser.plaintext.is_empty() && browser.old_tls.is_empty());
        assert_eq!(browser.tls_hellos, 1);

        let legacy = &s.programs[1];
        assert_eq!((legacy.endpoints, legacy.public_endpoints), (3, 2));
        let services: Vec<(&str, Certainty, u64, u64)> = legacy
            .plaintext
            .iter()
            .map(|u| (u.service.as_str(), u.certainty, u.bytes, u.public_bytes))
            .collect();
        assert_eq!(
            services,
            [
                ("HTTP", Certainty::Yes, 5000, 5000),
                ("Telnet", Certainty::Credentials, 800, 0),
                ("IMAP", Certainty::Maybe, 300, 300),
            ]
        );
        assert_eq!(
            legacy.plain_bytes, 5800,
            "IMAP may be encrypted: not counted"
        );
        assert_eq!(
            legacy.plaintext[0].endpoints[0].label(),
            "example.com (93.184.216.34)"
        );
        assert_eq!(legacy.old_tls[0].version, "TLS 1.0");

        // The scan first, then the accepted connections.
        assert_eq!(s.inbound_count, 3);
        let scan = &s.inbound[0];
        assert!(scan.scan);
        assert_eq!((scan.port_count, scan.attempts, scan.accepted), (20, 40, 0));
        assert_eq!(scan.ports.len(), 12);
        assert!(s.inbound[1..].iter().all(|p| !p.scan && p.accepted > 0));
        let rdp = s
            .inbound
            .iter()
            .find(|p| p.ip == ip("104.20.23.154"))
            .unwrap();
        assert_eq!(rdp.accepted_ports, [3389]);

        let dns = &s.dns;
        assert_eq!(dns.servers[0].ip, ip("192.168.1.1"));
        assert_eq!(
            (
                dns.servers[0].queries,
                dns.servers[0].answered,
                dns.servers[0].unanswered,
                dns.servers[0].failed
            ),
            (10, 7, 3, 1)
        );
        assert!((dns.servers[0].avg_ms.unwrap() - 160.0 / 7.0).abs() < 1e-9);
        assert_eq!(dns.servers[0].max_ms, Some(40.0));
        assert_eq!(dns.servers[1].nxdomain, 1);
        assert_eq!(dns.over_tls.len(), 1);
        // Two addresses of the same DNS-over-HTTPS host: one entry.
        assert_eq!(dns.over_https.len(), 1);
        assert_eq!(dns.over_https[0].name.as_deref(), Some("one.one.one.one"));
        assert_eq!(dns.over_https[0].bytes, 9100);
    }

    #[test]
    fn a_session_on_a_tunnel_reports_both_sides_and_the_dhcp_servers() {
        use std::net::Ipv4Addr;
        // Worker 0 reads the adapter, worker 1 the tunnel.
        let audit = audit::Audit::with_tunnels(vec![false, true]);
        let bytes = |n: u64| EndpointDelta {
            counters: crate::monitor::stats::Counters {
                bytes_in: n,
                ..Default::default()
            },
            ..Default::default()
        };
        let adapter: HashMap<IpAddr, EndpointDelta> = [
            (ip("185.159.157.1"), bytes(9000)),
            (ip("8.8.8.8"), bytes(300)),
            (ip("17.253.1.1"), bytes(100)),
        ]
        .into();
        let tunnel: HashMap<IpAddr, EndpointDelta> = [(ip("1.1.1.1"), bytes(8000))].into();
        audit.note_worker(0, &adapter);
        audit.note_worker(1, &tunnel);
        audit.dns_outside();
        let router = Ipv4Addr::new(192, 168, 1, 1);
        let rogue = Ipv4Addr::new(192, 168, 1, 66);
        audit.dhcp_reply("Ethernet", router, None, Some(router), &[router]);
        audit.dhcp_reply(
            "Ethernet",
            rogue,
            Some([0xde, 0xad, 0xbe, 0xef, 0, 1]),
            Some(rogue),
            &[rogue],
        );

        let geo = Geo::new(std::env::temp_dir().join("fishe-no-geo-here"));
        let inventory = Inventory::default();
        let iface = |name: &str, addresses: &[&str]| vpn::Iface {
            name: name.into(),
            description: name.into(),
            addresses: addresses.iter().map(|a| ip(a)).collect(),
            active: true,
        };
        let r = report(Sources {
            state: SessionState::Auditing,
            facts: Some(audit.facts()),
            names: None,
            geo: &geo,
            sockets: Ok((Vec::new(), HashMap::new())),
            inventory: &inventory,
            ifaces: Ok(vec![
                iface("eth0", &["192.168.1.19", "2a01:cb00:1::19"]),
                iface("wg0", &["10.2.0.2"]),
            ]),
            source_v4: Some(ip("10.2.0.2")),
            source_v6: Some(ip("2a01:cb00:1::19")),
        });
        let v = &r.vpn;
        assert_eq!(v.tunnels.len(), 1);
        assert!(v.measured && v.routes_ipv4());
        assert_eq!(
            (v.inside_bytes, v.outside_bytes, v.dns_outside),
            (8000, 9400, 1)
        );
        assert_eq!(v.carrier.as_ref().unwrap().ip, ip("185.159.157.1"));
        assert_eq!(v.outside_count, 2);
        assert_eq!(v.outside[0].ip, ip("8.8.8.8"));

        let dhcp = &r.session.as_ref().unwrap().dhcp;
        assert_eq!(dhcp.len(), 2);
        assert_eq!(
            (dhcp[0].server.as_str(), dhcp[1].server.as_str()),
            ("192.168.1.1", "192.168.1.66")
        );
        assert_eq!(dhcp[1].mac.as_deref(), Some("de:ad:be:ef:00:01"));
        assert_eq!(dhcp[1].router.as_deref(), Some("192.168.1.66"));

        // The findings: IPv6 bypass, DNS and traffic outside, two DHCP servers.
        let ids: Vec<&str> = r.findings.iter().map(|f| f.id.as_str()).collect();
        for id in ["vpn-ipv6", "vpn-dns", "vpn-outside", "dhcp-seen:Ethernet"] {
            assert!(ids.contains(&id), "{id} in {ids:?}");
        }
    }

    #[test]
    fn without_a_session_the_report_still_lists_listeners() {
        let geo = Geo::new(std::env::temp_dir().join("fishe-no-geo-here"));
        let inventory = Inventory::default();
        let r = report(Sources {
            state: SessionState::NoSession,
            facts: None,
            names: None,
            geo: &geo,
            sockets: Ok((vec![listen("0.0.0.0:22", 1)], HashMap::new())),
            inventory: &inventory,
            ifaces: Ok(Vec::new()),
            source_v4: None,
            source_v6: None,
        });
        assert_eq!(r.session, None);
        assert_eq!(r.listeners.len(), 1);
        assert!(r.listeners[0].sensitive);

        let failed = report(Sources {
            state: SessionState::NoSession,
            facts: None,
            names: None,
            geo: &geo,
            sockets: Err("not supported here".into()),
            inventory: &inventory,
            ifaces: Err("no capture".into()),
            source_v4: None,
            source_v6: None,
        });
        assert_eq!(failed.vpn.error.as_deref(), Some("no capture"));
        assert!(failed.listeners.is_empty());
        assert_eq!(
            failed.listeners_error.as_deref(),
            Some("not supported here")
        );
    }
}

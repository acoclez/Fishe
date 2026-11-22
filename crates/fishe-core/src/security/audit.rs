//! What an all-traffic session learns for the security view.
//!
//! The session already counts every packet per endpoint and per program;
//! the [`Audit`] keeps the few extra facts the security view needs, for the
//! whole session:
//!
//! - which endpoints each program talked to, and how much data went over a
//!   service that is not encrypted (data, not packets: a connection that
//!   was refused did not use the service);
//! - who tried to open a connection *to* this machine, on which ports, and
//!   whether a program answered;
//! - which DNS servers were asked, how fast they answered and how often
//!   they failed;
//! - the oldest TLS version a program still settles for;
//! - which Internet addresses were reached outside a VPN tunnel, when the
//!   session captures on one;
//! - which DHCP servers answered on each interface.
//!
//! It is fed from two places: the aggregator once per tick (the window's
//! per-endpoint counts and connection attempts), and the naming sniffers as
//! DNS messages and TLS hellos go by. Everything is bounded: remote
//! addresses and ports are chosen by whoever sends the packets.

use super::services::{self, DNS_OVER_TLS};
use crate::monitor::programs::Label;
use crate::monitor::stats::{EndpointDelta, InboundHit, UNATTRIBUTED};
use crate::naming::addr::{self, AddrScope};
use crate::net::parse::Transport;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;
use std::time::Duration;

/// Programs with their own entry; later ones are counted, not remembered.
pub const MAX_PROGRAMS: usize = 512;
/// Endpoints remembered per program.
pub const MAX_ENDPOINTS_PER_PROGRAM: usize = 512;
/// Unencrypted (endpoint, service) pairs remembered per program.
pub const MAX_PLAIN_PER_PROGRAM: usize = 64;
/// Servers a program offered an outdated TLS version to.
pub const MAX_OLD_TLS_PER_PROGRAM: usize = 16;
/// Remote addresses remembered for their connection attempts.
pub const MAX_PEERS: usize = 512;
/// Local ports remembered per such address.
pub const MAX_PORTS_PER_PEER: usize = 128;
/// DNS servers with their own figures.
pub const MAX_RESOLVERS: usize = 16;
/// Servers remembered for DNS over TLS.
pub const MAX_DOT: usize = 32;
/// Internet addresses remembered as reached outside the tunnel.
pub const MAX_OUTSIDE: usize = 256;
/// (interface, DHCP server) pairs remembered.
pub const MAX_DHCP: usize = 32;

/// A DHCP server seen answering during the session.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DhcpFacts {
    pub mac: Option<[u8; 6]>,
    /// Offers and acknowledgements seen.
    pub replies: u32,
    /// The gateway and DNS servers of its latest answer.
    pub router: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
}

/// One program's side of the session.
#[derive(Debug, Default, Clone)]
pub struct ProgramFacts {
    pub name: String,
    pub bytes: u64,
    /// Remote address → bytes exchanged.
    pub endpoints: HashMap<IpAddr, u64>,
    /// Endpoints beyond the cap: counted in `bytes`, not listed.
    pub more_endpoints: u32,
    /// (endpoint, service) on an unencrypted port → bytes.
    pub plain: HashMap<(IpAddr, Transport, u16), u64>,
    /// TLS hellos seen from this program.
    pub tls_hellos: u32,
    /// Servers it offered nothing newer than an outdated version to, with
    /// that version.
    pub old_tls: HashMap<IpAddr, u16>,
}

/// What one remote address tried against this machine.
#[derive(Debug, Default, Clone)]
pub struct PeerFacts {
    /// Local port → attempts and how many this machine accepted.
    pub ports: BTreeMap<u16, InboundHit>,
    /// Ports beyond the cap.
    pub more_ports: u32,
    pub first_ms: u64,
    pub last_ms: u64,
}

/// One DNS server's answers.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ResolverFacts {
    pub queries: u64,
    pub answered: u64,
    /// No answer within the time a resolver waits.
    pub unanswered: u64,
    /// "No such name": an answer, and a normal one.
    pub nxdomain: u64,
    /// The server could not or would not answer (SERVFAIL, REFUSED, …).
    pub failed: u64,
    pub latency_sum_us: u64,
    pub latency_max_us: u64,
}

/// Everything the audit holds; cloned out for a report.
#[derive(Debug, Default, Clone)]
pub struct Facts {
    /// By program key (see [`Label::key`]).
    pub programs: HashMap<String, ProgramFacts>,
    /// Programs beyond the cap.
    pub more_programs: u32,
    pub peers: HashMap<IpAddr, PeerFacts>,
    pub resolvers: HashMap<IpAddr, ResolverFacts>,
    /// Servers reached on the DNS-over-TLS port.
    pub dot: HashSet<IpAddr>,
    /// Session time of the latest tick.
    pub t_ms: u64,
    /// Per capture worker: does it read a VPN tunnel interface?
    pub tunnels: Vec<bool>,
    /// Bytes exchanged with Internet addresses on tunnel interfaces…
    pub inside_bytes: u64,
    /// …and on every other interface.
    pub outside_bytes: u64,
    /// Internet addresses reached on interfaces that are not tunnels → bytes.
    pub outside: HashMap<IpAddr, u64>,
    /// Unencrypted DNS questions seen on interfaces that are not tunnels.
    pub dns_outside: u64,
    /// DHCP servers seen answering, by (interface, server address).
    pub dhcp: HashMap<(String, Ipv4Addr), DhcpFacts>,
}

/// The session's security facts, shared by the aggregator, the sniffers and
/// whoever asks for a report.
#[derive(Default)]
pub struct Audit {
    facts: Mutex<Facts>,
    /// Some capture worker reads a tunnel: only then is it worth telling
    /// the two sides apart.
    has_tunnel: bool,
}

impl Audit {
    pub fn new() -> Self {
        Self::default()
    }

    /// For a session whose capture workers read these interfaces, in
    /// order: `true` for a VPN tunnel.
    pub fn with_tunnels(tunnels: Vec<bool>) -> Self {
        Audit {
            has_tunnel: tunnels.iter().any(|t| *t),
            facts: Mutex::new(Facts {
                tunnels,
                ..Default::default()
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Facts> {
        self.facts.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// One capture worker's batch, before it is merged with the others:
    /// on which side of the tunnel its Internet traffic went. Does nothing
    /// in a session without a tunnel.
    pub fn note_worker(&self, worker: usize, endpoints: &HashMap<IpAddr, EndpointDelta>) {
        if !self.has_tunnel {
            return;
        }
        let mut f = self.lock();
        let inside = f.tunnels.get(worker).copied().unwrap_or(false);
        for (&ip, delta) in endpoints {
            if !matches!(addr::classify(ip), AddrScope::Public) {
                continue;
            }
            let bytes = delta.counters.bytes_in + delta.counters.bytes_out;
            if inside {
                f.inside_bytes += bytes;
            } else {
                f.outside_bytes += bytes;
                if f.outside.len() < MAX_OUTSIDE || f.outside.contains_key(&ip) {
                    *f.outside.entry(ip).or_default() += bytes;
                }
            }
        }
    }

    /// An unencrypted DNS question left on an interface that is not a tunnel.
    pub fn dns_outside(&self) {
        self.lock().dns_outside += 1;
    }

    /// A DHCP server answered on `interface` (an offer or an acknowledgement).
    pub fn dhcp_reply(
        &self,
        interface: &str,
        server: Ipv4Addr,
        mac: Option<[u8; 6]>,
        router: Option<Ipv4Addr>,
        dns: &[Ipv4Addr],
    ) {
        let mut f = self.lock();
        let key = (interface.to_string(), server);
        if f.dhcp.len() >= MAX_DHCP && !f.dhcp.contains_key(&key) {
            return;
        }
        let d = f.dhcp.entry(key).or_default();
        d.replies = d.replies.saturating_add(1);
        d.mac = mac.or(d.mac);
        d.router = router.or(d.router);
        if !dns.is_empty() {
            d.dns = dns.to_vec();
        }
    }

    /// A copy of the facts so far.
    pub fn facts(&self) -> Facts {
        self.lock().clone()
    }

    /// One tick's window: per-endpoint counts (with the programs and service
    /// ports behind them), the TCP payload on the audited service ports, and
    /// the connection attempts received.
    pub fn tick(
        &self,
        t_ms: u64,
        endpoints: &HashMap<IpAddr, EndpointDelta>,
        payload: &HashMap<(IpAddr, u16), u64>,
        inbound: &HashMap<(IpAddr, u16), InboundHit>,
        labels: &HashMap<u32, Label>,
    ) {
        let mut f = self.lock();
        f.t_ms = t_ms;
        for (&ip, delta) in endpoints {
            f.note_endpoint(ip, delta, labels);
        }
        for (&(ip, port), &bytes) in payload {
            f.note_payload(ip, port, bytes, endpoints.get(&ip), labels);
        }
        for (&(remote, port), hit) in inbound {
            f.note_inbound(t_ms, remote, port, *hit);
        }
    }

    /// This machine asked `resolver` something.
    pub fn dns_query(&self, resolver: IpAddr) {
        if let Some(r) = self.lock().resolver(resolver) {
            r.queries += 1;
        }
    }

    /// `resolver` answered after `latency` with response code `rcode`.
    pub fn dns_answer(&self, resolver: IpAddr, latency: Duration, rcode: u8) {
        if let Some(r) = self.lock().resolver(resolver) {
            let us = u64::try_from(latency.as_micros()).unwrap_or(u64::MAX);
            r.answered += 1;
            r.latency_sum_us = r.latency_sum_us.saturating_add(us);
            r.latency_max_us = r.latency_max_us.max(us);
            match rcode {
                0 => {}
                3 => r.nxdomain += 1,
                _ => r.failed += 1,
            }
        }
    }

    /// `count` queries to `resolver` were never answered.
    pub fn dns_unanswered(&self, resolver: IpAddr, count: u64) {
        if let Some(r) = self.lock().resolver(resolver) {
            r.unanswered += count;
        }
    }

    /// A program opened a TLS connection to `server`, offering `offered`
    /// as its newest version.
    pub fn tls_hello(&self, program: &Label, server: IpAddr, offered: u16) {
        let mut f = self.lock();
        let Some(p) = f.program(program) else {
            return;
        };
        p.tls_hellos = p.tls_hellos.saturating_add(1);
        if offered < services::TLS_1_2
            && (p.old_tls.len() < MAX_OLD_TLS_PER_PROGRAM || p.old_tls.contains_key(&server))
        {
            // Keep the oldest version seen towards this server.
            let v = p.old_tls.entry(server).or_insert(offered);
            *v = (*v).min(offered);
        }
    }
}

impl Facts {
    /// The program's entry, created if there is room.
    fn program(&mut self, label: &Label) -> Option<&mut ProgramFacts> {
        if !self.programs.contains_key(&label.key) {
            if self.programs.len() >= MAX_PROGRAMS {
                self.more_programs = self.more_programs.saturating_add(1);
                return None;
            }
            self.programs.insert(
                label.key.clone(),
                ProgramFacts {
                    name: label.name.clone(),
                    ..Default::default()
                },
            );
        }
        self.programs.get_mut(&label.key)
    }

    fn resolver(&mut self, ip: IpAddr) -> Option<&mut ResolverFacts> {
        if self.resolvers.len() >= MAX_RESOLVERS && !self.resolvers.contains_key(&ip) {
            return None;
        }
        Some(self.resolvers.entry(ip).or_default())
    }

    /// Add unencrypted bytes exchanged with `ip` on `(transport, port)` to
    /// the program that owns the endpoint in this window. Within one tick
    /// an endpoint is nearly always one program's; if several share it, the
    /// one that moved the most is held to have used the service.
    fn add_plain(
        &mut self,
        ip: IpAddr,
        service: (Transport, u16),
        bytes: u64,
        delta: Option<&EndpointDelta>,
        labels: &HashMap<u32, Label>,
    ) {
        let pid = delta
            .and_then(|d| {
                d.programs
                    .iter()
                    .max_by_key(|&(&pid, &bytes)| (bytes, std::cmp::Reverse(pid)))
            })
            .map_or(UNATTRIBUTED, |(&pid, _)| pid);
        if let Some(p) = self.program(&label_of(labels, pid)) {
            let key = (ip, service.0, service.1);
            if p.plain.len() < MAX_PLAIN_PER_PROGRAM || p.plain.contains_key(&key) {
                *p.plain.entry(key).or_default() += bytes;
            }
        }
    }

    /// TCP data exchanged with `ip` on an audited service port.
    fn note_payload(
        &mut self,
        ip: IpAddr,
        port: u16,
        bytes: u64,
        delta: Option<&EndpointDelta>,
        labels: &HashMap<u32, Label>,
    ) {
        if port == DNS_OVER_TLS {
            if self.dot.len() < MAX_DOT || self.dot.contains(&ip) {
                self.dot.insert(ip);
            }
        } else if services::plaintext(Transport::Tcp, port).is_some() {
            self.add_plain(ip, (Transport::Tcp, port), bytes, delta, labels);
        }
    }

    fn note_endpoint(&mut self, ip: IpAddr, delta: &EndpointDelta, labels: &HashMap<u32, Label>) {
        for (&pid, &bytes) in &delta.programs {
            let Some(p) = self.program(&label_of(labels, pid)) else {
                continue;
            };
            p.bytes += bytes;
            if p.endpoints.len() < MAX_ENDPOINTS_PER_PROGRAM || p.endpoints.contains_key(&ip) {
                *p.endpoints.entry(ip).or_default() += bytes;
            } else {
                p.more_endpoints = p.more_endpoints.saturating_add(1);
            }
        }

        // UDP has no connection to refuse: a datagram on an unencrypted
        // UDP service is use of it. (TCP comes through `note_payload`.)
        if delta.programs.is_empty() {
            return;
        }
        let udp: Vec<(u16, u64)> = delta
            .ports
            .iter()
            .filter(|((t, port), _)| {
                *t == Transport::Udp && services::plaintext(*t, *port).is_some()
            })
            .map(|(&(_, port), &bytes)| (port, bytes))
            .collect();
        for (port, bytes) in udp {
            self.add_plain(ip, (Transport::Udp, port), bytes, Some(delta), labels);
        }
    }

    fn note_inbound(&mut self, t_ms: u64, remote: IpAddr, port: u16, hit: InboundHit) {
        if !self.peers.contains_key(&remote) {
            if self.peers.len() >= MAX_PEERS {
                // Make room by forgetting whoever was quiet the longest.
                let Some(oldest) = self
                    .peers
                    .iter()
                    .min_by_key(|(ip, p)| (p.last_ms, **ip))
                    .map(|(ip, _)| *ip)
                else {
                    return;
                };
                self.peers.remove(&oldest);
            }
            self.peers.insert(
                remote,
                PeerFacts {
                    first_ms: t_ms,
                    ..Default::default()
                },
            );
        }
        let Some(peer) = self.peers.get_mut(&remote) else {
            return;
        };
        peer.last_ms = t_ms;
        if peer.ports.len() < MAX_PORTS_PER_PEER || peer.ports.contains_key(&port) {
            let p = peer.ports.entry(port).or_default();
            p.syns = p.syns.saturating_add(hit.syns);
            p.answered = p.answered.saturating_add(hit.answered);
        } else {
            peer.more_ports = peer.more_ports.saturating_add(1);
        }
    }
}

/// How a PID is shown: its label from this window, or a placeholder when
/// the window has none for it.
fn label_of(labels: &HashMap<u32, Label>, pid: u32) -> Label {
    labels.get(&pid).cloned().unwrap_or_else(|| {
        if pid == UNATTRIBUTED {
            Label {
                key: String::new(),
                name: "Unattributed".into(),
            }
        } else {
            Label {
                key: format!("pid:{pid}"),
                name: format!("PID {pid}"),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn label(name: &str) -> Label {
        Label {
            key: name.to_ascii_lowercase(),
            name: name.into(),
        }
    }

    /// An endpoint's window: (pid, bytes) and ((transport, port), bytes).
    fn delta(programs: &[(u32, u64)], ports: &[(Transport, u16, u64)]) -> EndpointDelta {
        EndpointDelta {
            programs: programs.iter().copied().collect(),
            ports: ports.iter().map(|&(t, p, b)| ((t, p), b)).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn programs_get_their_endpoints_and_unencrypted_bytes() {
        let audit = Audit::new();
        let labels: HashMap<u32, Label> =
            [(10, label("old.exe")), (20, label("Browser.exe"))].into();
        let endpoints: HashMap<IpAddr, EndpointDelta> = [
            (
                ip("93.184.216.34"),
                delta(&[(10, 500)], &[(Transport::Tcp, 80, 500)]),
            ),
            (
                ip("1.1.1.1"),
                delta(&[(20, 900)], &[(Transport::Tcp, 443, 900)]),
            ),
            // Two programs on one endpoint in the same tick: the bigger one
            // is held to have used the unencrypted port.
            (
                ip("10.0.0.9"),
                delta(&[(10, 100), (20, 30)], &[(Transport::Tcp, 23, 130)]),
            ),
        ]
        .into();
        // The data that actually passed on the unencrypted ports, plus an
        // SNMP datagram (UDP: counted from the endpoint's own ports).
        let payload: HashMap<(IpAddr, u16), u64> = [
            ((ip("93.184.216.34"), 80), 500),
            ((ip("10.0.0.9"), 23), 130),
        ]
        .into();
        let mut endpoints = endpoints;
        endpoints.insert(
            ip("10.0.0.7"),
            delta(
                &[(20, 90)],
                &[(Transport::Udp, 161, 90), (Transport::Tcp, 161, 5)],
            ),
        );
        audit.tick(250, &endpoints, &payload, &HashMap::new(), &labels);
        audit.tick(500, &endpoints, &payload, &HashMap::new(), &labels);
        let snmp = audit.facts().programs["browser.exe"].plain.clone();
        assert_eq!(snmp.len(), 1);
        assert_eq!(snmp[&(ip("10.0.0.7"), Transport::Udp, 161)], 180);
        // A port with packets but no data (a refused connection) is not use.
        let refused = Audit::new();
        refused.tick(1, &endpoints, &HashMap::new(), &HashMap::new(), &labels);
        assert!(refused.facts().programs["old.exe"].plain.is_empty());

        let f = audit.facts();
        assert_eq!(f.t_ms, 500);
        let old = &f.programs["old.exe"];
        assert_eq!(old.name, "old.exe");
        assert_eq!(old.bytes, 1200);
        assert_eq!(old.endpoints.len(), 2);
        assert_eq!(old.plain[&(ip("93.184.216.34"), Transport::Tcp, 80)], 1000);
        assert_eq!(old.plain[&(ip("10.0.0.9"), Transport::Tcp, 23)], 260);
        let browser = &f.programs["browser.exe"];
        assert_eq!(browser.bytes, 2040);
        assert_eq!(
            browser.plain.len(),
            1,
            "HTTPS is not unencrypted; the SNMP datagrams are"
        );
        assert_eq!(browser.endpoints[&ip("10.0.0.9")], 60);
    }

    #[test]
    fn unknown_owners_keep_a_name() {
        let audit = Audit::new();
        let endpoints: HashMap<IpAddr, EndpointDelta> = [(
            ip("8.8.8.8"),
            delta(&[(UNATTRIBUTED, 10), (77, 5)], &[(Transport::Tcp, 853, 15)]),
        )]
        .into();
        let payload: HashMap<(IpAddr, u16), u64> = [((ip("8.8.8.8"), 853), 15)].into();
        audit.tick(1, &endpoints, &payload, &HashMap::new(), &HashMap::new());
        let f = audit.facts();
        assert_eq!(f.programs[""].name, "Unattributed");
        assert_eq!(f.programs["pid:77"].name, "PID 77");
        assert!(f.dot.contains(&ip("8.8.8.8")), "port 853 is DNS over TLS");
    }

    #[test]
    fn connection_attempts_are_kept_per_remote_address() {
        let audit = Audit::new();
        let scanner = ip("203.0.113.7");
        let inbound: HashMap<(IpAddr, u16), InboundHit> = (1..=200u16)
            .map(|port| {
                (
                    (scanner, port),
                    InboundHit {
                        syns: 1,
                        answered: u32::from(port == 22),
                    },
                )
            })
            .collect();
        audit.tick(
            1000,
            &HashMap::new(),
            &HashMap::new(),
            &inbound,
            &HashMap::new(),
        );
        audit.tick(
            3000,
            &HashMap::new(),
            &HashMap::new(),
            &inbound,
            &HashMap::new(),
        );
        let f = audit.facts();
        let peer = &f.peers[&scanner];
        assert_eq!(peer.ports.len(), MAX_PORTS_PER_PEER);
        assert_eq!((peer.first_ms, peer.last_ms), (1000, 3000));
        assert!(peer.more_ports > 0, "ports past the cap are counted");
        // Whichever ports made it in were hit in both ticks.
        assert!(peer.ports.values().all(|h| h.syns == 2));
    }

    #[test]
    fn the_quietest_address_makes_room() {
        let audit = Audit::new();
        for i in 0..=MAX_PEERS as u32 {
            let remote = IpAddr::from(std::net::Ipv4Addr::from(0x0a00_0000 + i));
            let inbound: HashMap<(IpAddr, u16), InboundHit> = [(
                (remote, 445),
                InboundHit {
                    syns: 1,
                    answered: 0,
                },
            )]
            .into();
            audit.tick(
                u64::from(i),
                &HashMap::new(),
                &HashMap::new(),
                &inbound,
                &HashMap::new(),
            );
        }
        let f = audit.facts();
        assert_eq!(f.peers.len(), MAX_PEERS);
        assert!(!f.peers.contains_key(&ip("10.0.0.0")), "the oldest went");
        assert!(f.peers.contains_key(&ip("10.0.0.1")));
    }

    #[test]
    fn dns_servers_are_measured() {
        let audit = Audit::new();
        let r = ip("192.168.1.1");
        for _ in 0..4 {
            audit.dns_query(r);
        }
        audit.dns_answer(r, Duration::from_millis(12), 0);
        audit.dns_answer(r, Duration::from_millis(30), 3);
        audit.dns_answer(r, Duration::from_millis(18), 2);
        audit.dns_unanswered(r, 1);
        let f = audit.facts();
        assert_eq!(
            f.resolvers[&r],
            ResolverFacts {
                queries: 4,
                answered: 3,
                unanswered: 1,
                nxdomain: 1,
                failed: 1,
                latency_sum_us: 60_000,
                latency_max_us: 30_000,
            }
        );
        // Only so many servers get their own figures.
        for i in 0..40u8 {
            audit.dns_query(IpAddr::from([9, 9, 9, i]));
        }
        assert_eq!(audit.facts().resolvers.len(), MAX_RESOLVERS);
    }

    #[test]
    fn traffic_is_split_by_side_of_the_tunnel() {
        let bytes = |n: u64| EndpointDelta {
            counters: crate::monitor::stats::Counters {
                bytes_in: n,
                bytes_out: n,
                ..Default::default()
            },
            ..Default::default()
        };
        // Worker 0 reads the adapter, worker 1 the tunnel.
        let audit = Audit::with_tunnels(vec![false, true]);
        let server = ip("185.159.157.1");
        let adapter: HashMap<IpAddr, EndpointDelta> = [
            (server, bytes(5000)),
            (ip("8.8.8.8"), bytes(40)),
            (ip("192.168.1.1"), bytes(700)), // the local network is not "outside"
        ]
        .into();
        let tunnel: HashMap<IpAddr, EndpointDelta> =
            [(ip("1.1.1.1"), bytes(4000)), (ip("10.2.0.1"), bytes(10))].into();
        audit.note_worker(0, &adapter);
        audit.note_worker(1, &tunnel);
        audit.note_worker(0, &adapter);
        audit.dns_outside();
        let f = audit.facts();
        assert_eq!((f.inside_bytes, f.outside_bytes), (8000, 20_160));
        assert_eq!(f.outside.len(), 2);
        assert_eq!(f.outside[&server], 20_000);
        assert_eq!(f.dns_outside, 1);

        // A session without a tunnel does not keep any of it.
        let plain = Audit::with_tunnels(vec![false, false]);
        plain.note_worker(0, &adapter);
        assert!(plain.facts().outside.is_empty());
        assert_eq!(Audit::new().facts().tunnels, Vec::<bool>::new());
    }

    #[test]
    fn dhcp_servers_are_kept_per_interface() {
        let audit = Audit::new();
        let router = Ipv4Addr::new(192, 168, 1, 1);
        let rogue = Ipv4Addr::new(192, 168, 1, 66);
        let mac = [0xde, 0xad, 0xbe, 0xef, 0, 1];
        audit.dhcp_reply("Ethernet", router, None, Some(router), &[router]);
        audit.dhcp_reply("Ethernet", router, Some([1; 6]), None, &[]);
        audit.dhcp_reply("Ethernet", rogue, Some(mac), Some(rogue), &[rogue]);
        // The same address on another interface is another network's server.
        audit.dhcp_reply("vEthernet (WSL)", router, None, None, &[]);
        let f = audit.facts();
        assert_eq!(f.dhcp.len(), 3);
        let r = &f.dhcp[&("Ethernet".to_string(), router)];
        assert_eq!(
            (r.replies, r.mac, r.router),
            (2, Some([1; 6]), Some(router))
        );
        assert_eq!(
            r.dns,
            [router],
            "an answer without DNS servers keeps the earlier ones"
        );
        assert_eq!(f.dhcp[&("Ethernet".to_string(), rogue)].mac, Some(mac));
        for i in 0..100u8 {
            audit.dhcp_reply("Ethernet", Ipv4Addr::new(10, 0, 0, i), None, None, &[]);
        }
        assert_eq!(audit.facts().dhcp.len(), MAX_DHCP);
    }

    #[test]
    fn outdated_tls_offers_are_remembered_per_program() {
        let audit = Audit::new();
        let app = label("legacy.exe");
        audit.tls_hello(&app, ip("198.51.100.1"), 0x0304);
        audit.tls_hello(&app, ip("198.51.100.2"), 0x0302);
        audit.tls_hello(&app, ip("198.51.100.2"), 0x0301);
        audit.tls_hello(&app, ip("198.51.100.2"), 0x0302);
        let f = audit.facts();
        let p = &f.programs["legacy.exe"];
        assert_eq!(p.tls_hellos, 4);
        assert_eq!(p.old_tls.len(), 1, "a current offer is not remembered");
        assert_eq!(p.old_tls[&ip("198.51.100.2")], 0x0301, "the oldest offer");
    }
}

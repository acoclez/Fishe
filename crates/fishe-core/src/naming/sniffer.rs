//! Naming capture: one thread per interface reading DNS answers and TLS
//! ClientHellos into the [`NameBook`].
//!
//! This capture is separate from the measuring capture because it needs
//! payload bytes (snaplen 4096 instead of 192). Its BPF filter keeps the
//! volume small: DNS, mDNS responses and client→server TCP/443.
//!
//! DNS answers are recorded for the whole machine, not just the monitored
//! process: Windows resolves names in a shared service (`Dnscache`), so the
//! process never sends its own DNS packets.
//!
//! Any host on the network can send a packet that looks like a DNS answer,
//! so what is believed is narrow:
//!
//! - a DNS answer only when it matches a query this machine sent a moment
//!   ago (same server, port and transaction id), as a resolver would;
//! - mDNS, which is unsolicited by design, only for addresses that are not
//!   public: it can name a LAN device, never a site;
//! - a TLS server name only from a connection this machine opened;
//! - and every name has to read as a host name ([`super::is_host_name`]).
//!
//! In an all-traffic session the same packets also feed the security audit
//! ([`AuditTap`]): which DNS servers were asked, how long they took and how
//! they answered, the newest TLS version each program's hello offers, and
//! the DHCP servers heard answering (the filter lets their replies through).

use super::addr::{self, AddrScope};
use super::book::NameBook;
use super::dns;
use super::tls::{Reassembler, Sni};
use crate::monitor::programs::Label;
use crate::monitor::stats::UNATTRIBUTED;
use crate::net::capture::OpenCapture;
use crate::net::parse::{self, Transport};
use crate::process::machine::MachineScope;
use crate::security::audit::Audit;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub const FILTER: &str = "udp port 53 or udp src port 5353 or tcp dst port 443 \
     or (udp src port 67 and udp dst port 68)";
pub const SNAPLEN: i32 = 4096;
pub const BUFFER_BYTES: i32 = 2 * 1024 * 1024;

/// How long an answer may take, and how many queries are remembered.
const ASKED_TTL: Duration = Duration::from_secs(10);
const ASKED_MAX: usize = 4096;

/// A hello waits this long before its program is looked up: a new
/// connection's port shows in the socket table at the next refresh.
const HELLO_SETTLE: Duration = Duration::from_millis(400);
const HELLOS_MAX: usize = 512;

/// Where the sniffer reports what the security view needs.
pub struct AuditTap {
    pub audit: Arc<Audit>,
    /// Who owns a local port: names the program behind a TLS hello.
    pub machine: Arc<MachineScope>,
    /// The interface this sniffer reads, as shown to the user.
    pub interface: String,
    /// It is a VPN tunnel: what is seen here is inside the tunnel.
    pub tunnel: bool,
}

/// TLS hellos waiting for their program: (seen, local port, server, version).
#[derive(Default)]
struct Hellos(VecDeque<(Instant, u16, IpAddr, u16)>);

impl Hellos {
    fn seen(&mut self, now: Instant, port: u16, server: IpAddr, offered: u16) {
        if self.0.len() < HELLOS_MAX {
            self.0.push_back((now, port, server, offered));
        }
    }

    /// Report the hellos that have waited long enough (`all`: every one).
    fn settle(&mut self, tap: &AuditTap, now: Instant, all: bool) {
        while let Some(&(seen, port, server, offered)) = self.0.front() {
            if !all && now.saturating_duration_since(seen) < HELLO_SETTLE {
                break;
            }
            self.0.pop_front();
            let pid = tap
                .machine
                .ownership
                .owner(Transport::Tcp, port)
                .unwrap_or(UNATTRIBUTED);
            tap.audit
                .tls_hello(&Label::of(&tap.machine, pid), server, offered);
        }
    }
}

/// `(server, client, client port, transaction id)`.
type QueryKey = (IpAddr, IpAddr, u16, u16);

/// The DNS queries this machine sent in the last few seconds: when each
/// was read here (to forget it in time) and when the capture saw it (to
/// time the answer: packets arrive in batches, so the moment they are read
/// says little about the moment they passed).
#[derive(Default)]
struct Asked(HashMap<QueryKey, (Instant, u64)>);

impl Asked {
    /// A question left at capture time `ts_us` (µs).
    fn sent(&mut self, key: QueryKey, now: Instant, ts_us: u64) {
        if self.0.len() >= ASKED_MAX {
            self.expire(now);
            if self.0.len() >= ASKED_MAX {
                self.0.clear();
            }
        }
        self.0.insert(key, (now, ts_us));
    }

    /// An answer with this key arrived at capture time `ts_us`: how long
    /// it took, if it is one that was asked for. A question is answered
    /// once; a second answer to it is nobody's.
    fn answered(&mut self, key: &QueryKey, ts_us: u64) -> Option<Duration> {
        let (_, sent_us) = self.0.remove(key)?;
        let took = Duration::from_micros(ts_us.saturating_sub(sent_us));
        (took <= ASKED_TTL).then_some(took)
    }

    /// Forget the questions nobody answered in time; returns their servers.
    fn expire(&mut self, now: Instant) -> Vec<IpAddr> {
        let mut unanswered = Vec::new();
        self.0.retain(|key, (sent, _)| {
            let waiting = now.saturating_duration_since(*sent) <= ASKED_TTL;
            if !waiting {
                unanswered.push(key.0);
            }
            waiting
        });
        unanswered
    }
}

/// Run until `stop` is set or the capture fails (naming is best-effort).
/// `local` holds this machine's addresses on the captured interfaces;
/// `audit` is where an all-traffic session's security facts go.
pub fn run(
    mut open: OpenCapture,
    book: Arc<NameBook>,
    local: Arc<HashSet<IpAddr>>,
    audit: Option<AuditTap>,
    stop: Arc<AtomicBool>,
) {
    let mut tls = Reassembler::new();
    let mut asked = Asked::default();
    let mut hellos = Hellos::default();
    let mut last_expire = Instant::now();
    let (mut dns_answers, mut dns_unasked, mut snis) = (0u64, 0u64, 0u64);

    while !stop.load(Ordering::Relaxed) {
        match crate::net::capture::next_packet(&mut open.capture) {
            Ok(p) => {
                let Some((info, l4)) = parse::parse_l4(open.link, p.data) else {
                    continue;
                };
                let ts_us = crate::monitor::engine::ts_us(p.header);
                match info.transport {
                    // A query of ours: remember it, to recognise its answer.
                    Transport::Udp if info.dst_port == Some(53) => {
                        if let (true, Some(port), Some(id)) = (
                            local.contains(&info.src),
                            info.src_port,
                            parse::udp_payload(l4).and_then(dns::query_id),
                        ) {
                            asked.sent((info.dst, info.src, port, id), Instant::now(), ts_us);
                            // A resolver on this machine (127.0.0.53) asks
                            // the real server itself: that one is counted.
                            if let Some(tap) = &audit
                                && !info.dst.is_loopback()
                            {
                                tap.audit.dns_query(info.dst);
                                if !tap.tunnel {
                                    tap.audit.dns_outside();
                                }
                            }
                        }
                    }
                    Transport::Udp if info.src_port == Some(53) => {
                        let Some(payload) = parse::udp_payload(l4) else {
                            continue;
                        };
                        let took =
                            info.dst_port
                                .zip(dns::response_id(payload))
                                .and_then(|(port, id)| {
                                    asked.answered(&(info.src, info.dst, port, id), ts_us)
                                });
                        let Some(took) = took else {
                            dns_unasked += 1;
                            continue;
                        };
                        if let Some(tap) = &audit
                            && !info.src.is_loopback()
                        {
                            let code = dns::response_code(payload).unwrap_or(0);
                            tap.audit.dns_answer(info.src, took, code);
                        }
                        for (ip, name) in dns::parse_response(payload) {
                            book.set_dns(ip, name);
                            dns_answers += 1;
                        }
                    }
                    // A DHCP server answering somebody on this network.
                    Transport::Udp if info.src_port == Some(67) => {
                        if let Some(tap) = &audit
                            && let Some(seen) = crate::lan::dhcp::seen(open.link, p.data)
                            && matches!(
                                seen.reply.kind,
                                crate::lan::dhcp::OFFER | crate::lan::dhcp::ACK
                            )
                        {
                            tap.audit.dhcp_reply(
                                &tap.interface,
                                seen.reply.server_id.unwrap_or(seen.from),
                                seen.mac,
                                seen.reply.router,
                                &seen.reply.dns,
                            );
                        }
                    }
                    Transport::Udp if info.src_port == Some(5353) => {
                        let Some(payload) = parse::udp_payload(l4) else {
                            continue;
                        };
                        for (ip, name) in dns::parse_response(payload) {
                            if !matches!(addr::classify(ip), AddrScope::Public) {
                                book.set_dns(ip, name);
                                dns_answers += 1;
                            }
                        }
                    }
                    Transport::Tcp if info.dst_port == Some(443) && local.contains(&info.src) => {
                        let (Some(seg), Some(sport)) = (parse::tcp_segment(l4), info.src_port)
                        else {
                            continue;
                        };
                        let key = (info.src, sport, info.dst, 443);
                        if let Some(hello) = tls.push_hello(key, seg.seq, seg.payload) {
                            if let Sni::Found { name, ech } = hello.sni {
                                book.set_sni(info.dst, name, ech);
                                snis += 1;
                            }
                            if let (Some(_), Some(offered)) = (&audit, hello.offered) {
                                hellos.seen(Instant::now(), sport, info.dst, offered);
                            }
                        }
                    }
                    _ => {}
                }
            }
            Err(pcap::Error::TimeoutExpired) => {}
            Err(e) => {
                log::warn!("naming capture on {} stopped: {e}", open.device_description);
                return;
            }
        }
        if last_expire.elapsed() > Duration::from_secs(1) {
            tls.expire();
            last_expire = Instant::now();
            let unanswered = asked.expire(last_expire);
            if let Some(tap) = &audit {
                for server in unanswered.into_iter().filter(|s| !s.is_loopback()) {
                    tap.audit.dns_unanswered(server, 1);
                }
                hellos.settle(tap, last_expire, false);
            }
        }
    }
    if let Some(tap) = &audit {
        hellos.settle(tap, Instant::now(), true);
    }
    log::info!(
        "naming on {}: {dns_answers} DNS answers ({dns_unasked} not asked for, ignored), {snis} TLS server names",
        open.device_description
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_answers_to_recent_queries_are_expected() {
        let (server, client): (IpAddr, IpAddr) = ([9, 9, 9, 9].into(), [192, 168, 1, 20].into());
        let key = (server, client, 50_000, 0x1234);
        let t0 = Instant::now();
        // Capture times, in µs: the question left at 5 s.
        let sent_us = 5_000_000;
        let mut asked = Asked::default();
        assert_eq!(asked.answered(&key, sent_us), None, "nothing was asked");
        asked.sent(key, t0, sent_us);
        // Another server, port or id is somebody else's packet.
        let other: IpAddr = [8, 8, 8, 8].into();
        assert_eq!(
            asked.answered(&(other, client, 50_000, 0x1234), sent_us),
            None
        );
        assert_eq!(
            asked.answered(&(server, client, 50_001, 0x1234), sent_us),
            None
        );
        assert_eq!(
            asked.answered(&(server, client, 50_000, 0x1235), sent_us),
            None
        );
        // The answer: timed by the capture, however late both were read.
        // A second one is not expected.
        assert_eq!(
            asked.answered(&key, sent_us + 30_000),
            Some(Duration::from_millis(30))
        );
        assert_eq!(asked.answered(&key, sent_us + 30_000), None);
        // An answer captured too long after its question is not believed.
        asked.sent(key, t0, sent_us);
        let late_us = sent_us + ASKED_TTL.as_micros() as u64 + 1;
        assert_eq!(asked.answered(&key, late_us), None);
        // Questions nobody answered are forgotten, and counted for their server.
        asked.sent((other, client, 50_000, 0x1), t0, sent_us);
        let late = t0 + ASKED_TTL + Duration::from_secs(1);
        asked.sent(key, late, late_us);
        assert_eq!(asked.expire(late), [other], "the fresh question stays");
        assert_eq!(asked.0.len(), 1);
    }

    #[test]
    fn hellos_wait_for_their_program() {
        use crate::process::ownership::OwnershipTable;
        let ownership = Arc::new(OwnershipTable::new());
        let machine = Arc::new(MachineScope::new(
            ownership.clone(),
            Arc::new(HashSet::new()),
        ));
        let tap = AuditTap {
            audit: Arc::new(Audit::new()),
            machine: machine.clone(),
            interface: "Ethernet".into(),
            tunnel: false,
        };
        let server: IpAddr = [93, 184, 216, 34].into();
        let t0 = Instant::now();
        let mut hellos = Hellos::default();
        hellos.seen(t0, 50_000, server, 0x0301);
        hellos.seen(t0 + Duration::from_millis(300), 50_001, server, 0x0304);

        // Too early: the socket table has not seen the connection yet.
        hellos.settle(&tap, t0 + Duration::from_millis(100), false);
        assert!(tap.audit.facts().programs.is_empty());

        // The owner turns up, then the first hello is old enough.
        ownership.note(Transport::Tcp, 50_000, 4242);
        hellos.settle(&tap, t0 + HELLO_SETTLE, false);
        let facts = tap.audit.facts();
        let app = &facts.programs["pid:4242"];
        assert_eq!(app.old_tls[&server], 0x0301);
        assert_eq!(hellos.0.len(), 1);

        // At the end of the session the rest goes out, owner known or not.
        hellos.settle(&tap, t0, true);
        assert!(hellos.0.is_empty());
        assert_eq!(tap.audit.facts().programs[""].tls_hellos, 1);
    }

    /// A real lookup is still named: the query goes out, its answer is
    /// recognised. `cargo test -- --ignored live_dns --nocapture`.
    #[cfg(windows)]
    #[test]
    #[ignore = "requires Npcap and a network connection"]
    fn live_dns_answers_to_our_queries_are_named() {
        use crate::net::{capture, interfaces};
        use std::net::ToSocketAddrs;
        crate::npcap::ensure_available().expect("Npcap available");
        let devices = interfaces::list_devices().unwrap();
        let local: Arc<HashSet<IpAddr>> = Arc::new(
            devices
                .iter()
                .flat_map(|d| d.addresses.iter().map(|a| a.addr))
                .collect(),
        );
        let book = Arc::new(NameBook::new());
        let stop = Arc::new(AtomicBool::new(false));
        let threads: Vec<_> = devices
            .into_iter()
            .filter_map(|d| capture::open_with(d, FILTER, SNAPLEN, BUFFER_BYTES).ok())
            .map(|open| {
                let (b, l, s) = (book.clone(), local.clone(), stop.clone());
                std::thread::spawn(move || run(open, b, l, None, s))
            })
            .collect();
        assert!(!threads.is_empty(), "no interface could be opened");
        std::thread::sleep(Duration::from_millis(500));

        // nslookup asks the DNS server itself, so the OS cache can't hide it.
        let out = std::process::Command::new("nslookup")
            .arg("example.com")
            .output()
            .expect("nslookup runs");
        println!("{}", String::from_utf8_lossy(&out.stdout));
        std::thread::sleep(Duration::from_millis(1500));
        stop.store(true, Ordering::Relaxed);
        for t in threads {
            let _ = t.join();
        }

        let named: Vec<_> = ("example.com", 443)
            .to_socket_addrs()
            .unwrap()
            .filter_map(|a| book.best(a.ip()).map(|(n, _)| (a.ip(), n)))
            .collect();
        println!("named: {named:?}");
        assert!(
            named.iter().any(|(_, n)| n == "example.com"),
            "the answer to our own query was not recognised"
        );
    }

    #[test]
    fn remembered_queries_are_bounded() {
        let t0 = Instant::now();
        let mut asked = Asked::default();
        for i in 0..(ASKED_MAX as u32 + 10) {
            let key = (
                [9, 9, 9, 9].into(),
                [192, 168, 1, 20].into(),
                (i >> 16) as u16,
                i as u16,
            );
            asked.sent(key, t0, 0);
        }
        assert!(asked.0.len() <= ASKED_MAX);
    }
}

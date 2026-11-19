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

use super::addr::{self, AddrScope};
use super::book::NameBook;
use super::dns;
use super::tls::{Reassembler, Sni};
use crate::net::capture::OpenCapture;
use crate::net::parse::{self, Transport};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub const FILTER: &str = "udp port 53 or udp src port 5353 or tcp dst port 443";
pub const SNAPLEN: i32 = 4096;
pub const BUFFER_BYTES: i32 = 2 * 1024 * 1024;

/// How long an answer may take, and how many queries are remembered.
const ASKED_TTL: Duration = Duration::from_secs(10);
const ASKED_MAX: usize = 4096;

/// `(server, client, client port, transaction id)`.
type QueryKey = (IpAddr, IpAddr, u16, u16);

/// The DNS queries this machine sent in the last few seconds.
#[derive(Default)]
struct Asked(HashMap<QueryKey, Instant>);

impl Asked {
    fn sent(&mut self, key: QueryKey, now: Instant) {
        if self.0.len() >= ASKED_MAX {
            self.expire(now);
            if self.0.len() >= ASKED_MAX {
                self.0.clear();
            }
        }
        self.0.insert(key, now);
    }

    /// Whether an answer with this key is one that was asked for.
    fn expects(&self, key: &QueryKey, now: Instant) -> bool {
        self.0
            .get(key)
            .is_some_and(|sent| now.saturating_duration_since(*sent) <= ASKED_TTL)
    }

    fn expire(&mut self, now: Instant) {
        self.0
            .retain(|_, sent| now.saturating_duration_since(*sent) <= ASKED_TTL);
    }
}

/// Run until `stop` is set or the capture fails (naming is best-effort).
/// `local` holds this machine's addresses on the captured interfaces.
pub fn run(
    mut open: OpenCapture,
    book: Arc<NameBook>,
    local: Arc<HashSet<IpAddr>>,
    stop: Arc<AtomicBool>,
) {
    let mut tls = Reassembler::new();
    let mut asked = Asked::default();
    let mut last_expire = Instant::now();
    let (mut dns_answers, mut dns_unasked, mut snis) = (0u64, 0u64, 0u64);

    while !stop.load(Ordering::Relaxed) {
        match crate::net::capture::next_packet(&mut open.capture) {
            Ok(p) => {
                let Some((info, l4)) = parse::parse_l4(open.link, p.data) else {
                    continue;
                };
                match info.transport {
                    // A query of ours: remember it, to recognise its answer.
                    Transport::Udp if info.dst_port == Some(53) => {
                        if let (true, Some(port), Some(id)) = (
                            local.contains(&info.src),
                            info.src_port,
                            parse::udp_payload(l4).and_then(dns::query_id),
                        ) {
                            asked.sent((info.dst, info.src, port, id), Instant::now());
                        }
                    }
                    Transport::Udp if info.src_port == Some(53) => {
                        let Some(payload) = parse::udp_payload(l4) else {
                            continue;
                        };
                        let expected = info.dst_port.zip(dns::response_id(payload)).is_some_and(
                            |(port, id)| {
                                asked.expects(&(info.src, info.dst, port, id), Instant::now())
                            },
                        );
                        if !expected {
                            dns_unasked += 1;
                            continue;
                        }
                        for (ip, name) in dns::parse_response(payload) {
                            book.set_dns(ip, name);
                            dns_answers += 1;
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
                        if let Some(Sni::Found { name, ech }) = tls.push(key, seg.seq, seg.payload)
                        {
                            book.set_sni(info.dst, name, ech);
                            snis += 1;
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
            asked.expire(last_expire);
        }
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
        let mut asked = Asked::default();
        assert!(!asked.expects(&key, t0), "nothing was asked");
        asked.sent(key, t0);
        assert!(asked.expects(&key, t0 + Duration::from_secs(1)));
        // Another server, port or id is somebody else's packet.
        assert!(!asked.expects(&([8, 8, 8, 8].into(), client, 50_000, 0x1234), t0));
        assert!(!asked.expects(&(server, client, 50_001, 0x1234), t0));
        assert!(!asked.expects(&(server, client, 50_000, 0x1235), t0));
        // Too late.
        let late = t0 + ASKED_TTL + Duration::from_secs(1);
        assert!(!asked.expects(&key, late));
        asked.expire(late);
        assert!(asked.0.is_empty());
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
                std::thread::spawn(move || run(open, b, l, s))
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
            asked.sent(key, t0);
        }
        assert!(asked.0.len() <= ASKED_MAX);
    }
}

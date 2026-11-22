//! Which DHCP servers answer on a network.
//!
//! A DHCP server hands every joining device its address, its gateway and
//! its DNS servers. A second one on the same network, whether a
//! misconfigured router or a device set up to do it, can hand out its own
//! gateway and DNS and so place itself in the path of everything those
//! devices send. Finding out who answers is the check.
//!
//! [`discover`] asks the way a joining device does: it broadcasts one
//! DHCPDISCOVER and collects the DHCPOFFERs. It never sends the DHCPREQUEST
//! that would accept one, so no lease is taken and nothing changes on this
//! machine or on the server (a server may hold the offered address aside
//! for a moment, as for any device that asks and goes away). The request
//! carries this adapter's own hardware address: the server then offers the
//! address this PC already has, instead of setting a new one aside.
//!
//! [`parse_reply`] is also used by the naming sniffer for the replies that
//! go by during a session (see `naming/sniffer.rs`).

use super::adapters::LanInterface;
use super::oui;
use crate::error::AppResult;
use crate::net::parse::{self, LinkLayer};
use pcap::Capture;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// How long offers are waited for, and when the question is repeated.
/// A server that has never given this machine a lease often checks first
/// that the address it is about to offer is free (dnsmasq pings it for
/// three seconds): that server is exactly the one worth hearing, so the
/// wait covers it.
const LISTEN: Duration = Duration::from_millis(4500);
const REPEAT_AFTER: Duration = Duration::from_millis(1500);
/// Servers listed per network.
pub const MAX_SERVERS: usize = 8;

const BOOTREQUEST: u8 = 1;
const BOOTREPLY: u8 = 2;
const MAGIC: [u8; 4] = [0x63, 0x82, 0x53, 0x63];
/// Fixed part of a BOOTP message, before the magic cookie.
const FIXED: usize = 236;

pub const DISCOVER: u8 = 1;
pub const OFFER: u8 = 2;
pub const ACK: u8 = 5;
pub const NAK: u8 = 6;

/// A DHCP server that answered, with what it hands out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct DhcpServer {
    /// The server's own address (its "server identifier", or where the
    /// offer came from when it gave none).
    pub ip: Ipv4Addr,
    /// "aa:bb:cc:dd:ee:ff"
    pub mac: Option<String>,
    pub vendor: Option<String>,
    /// The address it offered this PC.
    pub offered: Option<Ipv4Addr>,
    /// The gateway it tells devices to use.
    pub router: Option<Ipv4Addr>,
    /// The DNS servers it tells devices to use.
    pub dns: Vec<Ipv4Addr>,
    pub lease_secs: Option<u32>,
    /// It is this network's gateway (the usual case at home).
    pub is_gateway: bool,
}

/// A server → client DHCP message, as far as Fishe reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub xid: u32,
    /// Message type (option 53): [`OFFER`], [`ACK`], [`NAK`], …
    pub kind: u8,
    /// "Your address": what the client is offered or given.
    pub your_ip: Option<Ipv4Addr>,
    /// Option 54.
    pub server_id: Option<Ipv4Addr>,
    /// Option 3 (the first router).
    pub router: Option<Ipv4Addr>,
    /// Option 6.
    pub dns: Vec<Ipv4Addr>,
    /// Option 51.
    pub lease_secs: Option<u32>,
    /// The client the message is for.
    pub client_mac: [u8; 6],
}

fn v4(b: &[u8]) -> Option<Ipv4Addr> {
    let a: [u8; 4] = b.get(..4)?.try_into().ok()?;
    let ip = Ipv4Addr::from(a);
    (!ip.is_unspecified()).then_some(ip)
}

/// Parse the UDP payload of a server → client DHCP message. `None` for a
/// request, a plain BOOTP reply without options, or anything malformed.
pub fn parse_reply(msg: &[u8]) -> Option<Reply> {
    if msg.len() < FIXED + 4 || msg[0] != BOOTREPLY || msg[FIXED..FIXED + 4] != MAGIC {
        return None;
    }
    let mut reply = Reply {
        xid: u32::from_be_bytes(msg[4..8].try_into().ok()?),
        kind: 0,
        your_ip: v4(&msg[16..20]),
        server_id: None,
        router: None,
        dns: Vec::new(),
        lease_secs: None,
        client_mac: msg[28..34].try_into().ok()?,
    };
    // Options: code, length, value; 0 pads, 255 ends.
    let mut p = FIXED + 4;
    while let Some(&code) = msg.get(p) {
        match code {
            0 => {
                p += 1;
                continue;
            }
            255 => break,
            _ => {}
        }
        let len = usize::from(*msg.get(p + 1)?);
        let value = msg.get(p + 2..p + 2 + len)?;
        match code {
            53 => reply.kind = *value.first()?,
            54 => reply.server_id = v4(value),
            3 => reply.router = v4(value),
            6 => {
                reply.dns = value
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .filter_map(|a| v4(a))
                    .take(4)
                    .collect();
            }
            51 => reply.lease_secs = Some(u32::from_be_bytes(value.get(..4)?.try_into().ok()?)),
            _ => {}
        }
        p += 2 + len;
    }
    (reply.kind != 0).then_some(reply)
}

fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in header.chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The Ethernet frame of a DHCPDISCOVER from `mac`, asking for the answer
/// to be broadcast.
pub fn discover_frame(mac: &[u8; 6], xid: u32) -> Vec<u8> {
    // BOOTP, padded to the 300 bytes some servers insist on.
    let mut bootp = vec![0u8; 300];
    bootp[0] = BOOTREQUEST;
    bootp[1] = 1; // Ethernet
    bootp[2] = 6;
    bootp[4..8].copy_from_slice(&xid.to_be_bytes());
    bootp[10] = 0x80; // flags: broadcast the reply
    bootp[28..34].copy_from_slice(mac);
    bootp[FIXED..FIXED + 4].copy_from_slice(&MAGIC);
    let options = [
        53, 1, DISCOVER, // message type
        55, 4, 1, 3, 6, 51,  // please include: mask, router, DNS, lease
        255, // end
    ];
    bootp[FIXED + 4..FIXED + 4 + options.len()].copy_from_slice(&options);

    let udp_len = (8 + bootp.len()) as u16;
    let ip_len = 20 + udp_len;
    let mut frame = Vec::with_capacity(14 + usize::from(ip_len));
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(mac);
    frame.extend_from_slice(&[0x08, 0x00]);
    let mut ip = [0u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&ip_len.to_be_bytes());
    ip[8] = 64; // TTL
    ip[9] = 17; // UDP
    // from 0.0.0.0 (already zero) to 255.255.255.255
    ip[16..20].copy_from_slice(&[255; 4]);
    let sum = ip_checksum(&ip);
    ip[10..12].copy_from_slice(&sum.to_be_bytes());
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&68u16.to_be_bytes());
    frame.extend_from_slice(&67u16.to_be_bytes());
    frame.extend_from_slice(&udp_len.to_be_bytes());
    frame.extend_from_slice(&[0, 0]); // UDP checksum: optional over IPv4
    frame.extend(bootp);
    frame
}

/// One answer as captured: who sent it (address and hardware address).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    pub from: Ipv4Addr,
    pub mac: Option<[u8; 6]>,
    pub reply: Reply,
}

/// Read a captured Ethernet frame as a DHCP reply.
pub fn seen(link: LinkLayer, frame: &[u8]) -> Option<Seen> {
    let (info, l4) = parse::parse_l4(link, frame)?;
    if info.src_port != Some(67) {
        return None;
    }
    let std::net::IpAddr::V4(from) = info.src else {
        return None;
    };
    let mac = (link == LinkLayer::Ethernet)
        .then(|| frame.get(6..12)?.try_into().ok())
        .flatten();
    Some(Seen {
        from,
        mac,
        reply: parse_reply(parse::udp_payload(l4)?)?,
    })
}

/// Fold answers into one entry per server, in order of first answer.
pub fn servers(answers: &[Seen], gateway: Option<Ipv4Addr>) -> Vec<DhcpServer> {
    let mut out: Vec<DhcpServer> = Vec::new();
    for a in answers {
        let ip = a.reply.server_id.unwrap_or(a.from);
        if out.iter().any(|s| s.ip == ip) || out.len() >= MAX_SERVERS {
            continue;
        }
        out.push(DhcpServer {
            ip,
            mac: a.mac.map(|m| oui::format_mac(&m)),
            vendor: a.mac.and_then(|m| oui::vendor(&m).map(str::to_string)),
            offered: a.reply.your_ip,
            router: a.reply.router,
            dns: a.reply.dns.clone(),
            lease_secs: a.reply.lease_secs,
            is_gateway: Some(ip) == gateway,
        });
    }
    out
}

/// Ask who serves DHCP on `iface` and wait a little for the offers.
pub fn discover(iface: &LanInterface) -> AppResult<Vec<DhcpServer>> {
    crate::npcap::ensure_available()?;
    let mut cap = crate::net::capture::bounded(
        Capture::from_device(iface.device.as_str())?
            .promisc(false)
            .snaplen(1500)
            .timeout(30)
            .immediate_mode(true)
            .open()?,
    )?;
    let Some(link) = LinkLayer::from_dlt(cap.get_datalink().0) else {
        return Ok(Vec::new());
    };
    if link != LinkLayer::Ethernet {
        return Ok(Vec::new()); // nothing to broadcast a frame on
    }
    cap.filter("udp src port 67 and udp dst port 68", true)?;

    let mut xid = [0u8; 4];
    if getrandom::fill(&mut xid).is_err() {
        xid = (std::process::id() ^ 0x5fd1_c0de).to_be_bytes();
    }
    let xid = u32::from_be_bytes(xid);
    let frame = discover_frame(&iface.mac, xid);

    let started = Instant::now();
    let mut repeated = false;
    let mut answers = Vec::new();
    let _ = cap.sendpacket(&frame[..]);
    while started.elapsed() < LISTEN {
        if !repeated && started.elapsed() >= REPEAT_AFTER {
            repeated = true;
            // Once more for a server that was slow or a frame that was lost.
            let _ = cap.sendpacket(&frame[..]);
        }
        match crate::net::capture::next_packet(&mut cap) {
            Ok(p) => {
                if let Some(s) = seen(link, p.data)
                    && s.reply.xid == xid
                    && s.reply.kind == OFFER
                {
                    answers.push(s);
                }
            }
            Err(pcap::Error::TimeoutExpired) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(servers(&answers, iface.gateway))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A server → client message with these options.
    pub(crate) fn reply(xid: u32, your_ip: [u8; 4], options: &[u8]) -> Vec<u8> {
        let mut m = vec![0u8; FIXED];
        m[0] = BOOTREPLY;
        m[1] = 1;
        m[2] = 6;
        m[4..8].copy_from_slice(&xid.to_be_bytes());
        m[16..20].copy_from_slice(&your_ip);
        m[28..34].copy_from_slice(&[2, 0, 0, 0, 0, 0x19]);
        m.extend_from_slice(&MAGIC);
        m.extend_from_slice(options);
        m.push(255);
        m
    }

    /// The options of an offer from `server` handing out `router` and `dns`.
    pub(crate) fn offer_options(server: [u8; 4], router: [u8; 4], dns: &[[u8; 4]]) -> Vec<u8> {
        let mut o = vec![53, 1, OFFER, 54, 4];
        o.extend_from_slice(&server);
        o.extend_from_slice(&[51, 4, 0, 1, 0x51, 0x80]); // one day
        o.extend_from_slice(&[1, 4, 255, 255, 255, 0]);
        o.extend_from_slice(&[3, 4]);
        o.extend_from_slice(&router);
        o.push(6);
        o.push((dns.len() * 4) as u8);
        for d in dns {
            o.extend_from_slice(d);
        }
        o
    }

    /// An Ethernet + IPv4 + UDP frame from `from`:67 carrying `payload`.
    pub(crate) fn frame(mac: [u8; 6], from: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0xff; 6];
        f.extend_from_slice(&mac);
        f.extend_from_slice(&[0x08, 0x00]);
        let udp_len = (8 + payload.len()) as u16;
        let mut ip = [0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(20 + udp_len).to_be_bytes());
        ip[8] = 64;
        ip[9] = 17;
        ip[12..16].copy_from_slice(&from);
        ip[16..20].copy_from_slice(&[255; 4]);
        f.extend_from_slice(&ip);
        f.extend_from_slice(&67u16.to_be_bytes());
        f.extend_from_slice(&68u16.to_be_bytes());
        f.extend_from_slice(&udp_len.to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(payload);
        f
    }

    #[test]
    fn an_offer_is_read() {
        let msg = reply(
            0xdead_beef,
            [192, 168, 1, 19],
            &offer_options(
                [192, 168, 1, 1],
                [192, 168, 1, 1],
                &[[192, 168, 1, 1], [1, 1, 1, 1]],
            ),
        );
        let r = parse_reply(&msg).unwrap();
        assert_eq!(r.xid, 0xdead_beef);
        assert_eq!(r.kind, OFFER);
        assert_eq!(r.your_ip, Some(Ipv4Addr::new(192, 168, 1, 19)));
        assert_eq!(r.server_id, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(r.router, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(
            r.dns,
            [Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(1, 1, 1, 1)]
        );
        assert_eq!(r.lease_secs, Some(86_400));
        assert_eq!(r.client_mac, [2, 0, 0, 0, 0, 0x19]);
    }

    #[test]
    fn what_is_not_a_dhcp_reply_is_refused() {
        let good = reply(1, [10, 0, 0, 5], &[0, 0, 53, 1, ACK]);
        assert_eq!(parse_reply(&good).unwrap().kind, ACK, "padding is skipped");
        // A request (what clients send).
        let mut request = good.clone();
        request[0] = BOOTREQUEST;
        assert_eq!(parse_reply(&request), None);
        // No magic cookie, no message type, cut short, an option that
        // runs past the end.
        let mut plain = good.clone();
        plain[FIXED] = 0;
        assert_eq!(parse_reply(&plain), None);
        assert_eq!(
            parse_reply(&reply(1, [10, 0, 0, 5], &[3, 4, 10, 0, 0, 1])),
            None
        );
        assert_eq!(parse_reply(&good[..100]), None);
        let mut cut = reply(1, [10, 0, 0, 5], &[53, 1, OFFER, 6, 200, 1, 1]);
        cut.pop();
        assert_eq!(parse_reply(&cut), None);
        assert_eq!(parse_reply(&[]), None);
    }

    #[test]
    fn the_discover_frame_is_a_broadcast_question() {
        let mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let f = discover_frame(&mac, 0x0102_0304);
        assert_eq!(f.len(), 14 + 20 + 8 + 300);
        assert_eq!(&f[0..6], &[0xff; 6], "to everyone");
        assert_eq!(&f[6..12], &mac);
        // IPv4, UDP 68 → 67, to 255.255.255.255, checksum valid.
        assert_eq!(f[14 + 9], 17);
        assert_eq!(ip_checksum(&f[14..34]), 0);
        assert_eq!(&f[30..34], &[255; 4]);
        assert_eq!(&f[34..38], &[0, 68, 0, 67]);
        let bootp = &f[42..];
        assert_eq!(bootp[0], BOOTREQUEST);
        assert_eq!(&bootp[4..8], &[1, 2, 3, 4]);
        assert_eq!(bootp[10] & 0x80, 0x80, "answer by broadcast");
        assert_eq!(&bootp[28..34], &mac);
        assert_eq!(
            &bootp[FIXED..FIXED + 7],
            &[0x63, 0x82, 0x53, 0x63, 53, 1, DISCOVER]
        );
        // It is a request: the reply parser does not take it for an answer.
        assert_eq!(parse_reply(bootp), None);
    }

    #[test]
    fn answers_become_one_entry_per_server() {
        let router = [192, 168, 1, 1];
        let rogue = [192, 168, 1, 66];
        let from_router = frame(
            [0xc8, 0x7f, 0x2b, 0x35, 0x1a, 0xc0],
            router,
            &reply(
                7,
                [192, 168, 1, 19],
                &offer_options(router, router, &[router]),
            ),
        );
        let from_rogue = frame(
            [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
            rogue,
            &reply(
                7,
                [192, 168, 1, 200],
                &offer_options(rogue, rogue, &[rogue]),
            ),
        );
        let answers: Vec<Seen> = [&from_router, &from_rogue, &from_router]
            .iter()
            .map(|f| seen(LinkLayer::Ethernet, f).unwrap())
            .collect();
        assert_eq!(answers[1].from, Ipv4Addr::from(rogue));
        assert_eq!(answers[1].mac, Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]));

        let s = servers(&answers, Some(Ipv4Addr::from(router)));
        assert_eq!(s.len(), 2, "the router answered twice: one entry");
        assert!(s[0].is_gateway && !s[1].is_gateway);
        assert_eq!(s[0].mac.as_deref(), Some("c8:7f:2b:35:1a:c0"));
        assert_eq!(s[1].ip, Ipv4Addr::from(rogue));
        assert_eq!(
            s[1].router,
            Some(Ipv4Addr::from(rogue)),
            "it offers itself as gateway"
        );
        assert_eq!(s[1].offered, Some(Ipv4Addr::new(192, 168, 1, 200)));

        // Not from the DHCP server port: not an answer.
        let mut other = from_router.clone();
        other[34..36].copy_from_slice(&1234u16.to_be_bytes());
        assert_eq!(seen(LinkLayer::Ethernet, &other), None);
        // Without a server identifier, the sender's address stands in.
        let anonymous = frame(
            [2, 0, 0, 0, 0, 9],
            [10, 0, 0, 9],
            &reply(7, [10, 0, 0, 50], &[53, 1, OFFER]),
        );
        let s = servers(&[seen(LinkLayer::Ethernet, &anonymous).unwrap()], None);
        assert_eq!(s[0].ip, Ipv4Addr::new(10, 0, 0, 9));
    }

    #[test]
    #[ignore = "broadcasts a DHCPDISCOVER on the LAN (needs capture rights)"]
    fn live_discover() {
        let iface = super::super::adapters::list()
            .into_iter()
            .find(|i| i.gateway.is_some())
            .expect("a LAN adapter");
        let found = discover(&iface).unwrap();
        println!("{} DHCP server(s) on {}", found.len(), iface.name);
        for s in &found {
            println!(
                "  {} {:?} offers {:?}, router {:?}, dns {:?}, lease {:?}s, gateway {}",
                s.ip, s.mac, s.offered, s.router, s.dns, s.lease_secs, s.is_gateway
            );
        }
    }
}

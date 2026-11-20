//! ARP sweep through the capture library: broadcast "who has <ip>?" for every address of
//! the network and collect the replies. A /24 takes about 2 s, far faster
//! than `SendARP` (which waits ~3 s per silent address), and every ARP
//! packet seen meanwhile, replies or other devices' own requests, counts.

use super::adapters::LanInterface;
use crate::error::AppResult;
use pcap::Capture;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// Rounds of requests; silent addresses get asked again.
const ROUNDS: u32 = 3;
const ROUND_GAP: Duration = Duration::from_millis(600);
/// How long to keep listening after the last round.
const LINGER: Duration = Duration::from_millis(900);

/// An Ethernet ARP request from `mac`/`ip` for `target`, padded to 60 bytes.
pub fn request(mac: &[u8; 6], ip: Ipv4Addr, target: Ipv4Addr) -> [u8; 60] {
    let mut f = [0u8; 60];
    f[0..6].copy_from_slice(&[0xff; 6]);
    f[6..12].copy_from_slice(mac);
    f[12..14].copy_from_slice(&[0x08, 0x06]);
    f[14..22].copy_from_slice(&[0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x01]);
    f[22..28].copy_from_slice(mac);
    f[28..32].copy_from_slice(&ip.octets());
    // target hardware address stays zero
    f[38..42].copy_from_slice(&target.octets());
    f
}

/// Sender (IP, MAC) of an Ethernet ARP packet (request or reply).
pub fn sender(frame: &[u8]) -> Option<(Ipv4Addr, [u8; 6])> {
    if frame.len() < 42
        || frame[12..14] != [0x08, 0x06]
        || frame[14..20] != [0x00, 0x01, 0x08, 0x00, 6, 4]
    {
        return None;
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&frame[22..28]);
    let ip = Ipv4Addr::new(frame[28], frame[29], frame[30], frame[31]);
    if ip.is_unspecified() || mac == [0; 6] || mac == [0xff; 6] {
        return None; // ARP probes (RFC 5227) and junk
    }
    Some((ip, mac))
}

/// Ask every address in `hosts` on `iface`; returns who answered (or spoke
/// ARP meanwhile) within the interface's network, in order of discovery.
pub fn sweep(iface: &LanInterface, hosts: &[Ipv4Addr]) -> AppResult<Vec<(Ipv4Addr, [u8; 6])>> {
    crate::npcap::ensure_available()?;
    let mut cap = crate::net::capture::bounded(
        Capture::from_device(iface.device.as_str())?
            .promisc(false)
            .snaplen(64)
            .timeout(30)
            .immediate_mode(true)
            .open()?,
    )?;
    cap.filter("arp", true)?;

    let mut found: HashMap<Ipv4Addr, [u8; 6]> = HashMap::new();
    let mut order = Vec::new();
    let started = Instant::now();
    let mut round = 0;
    let mut next_round = started;
    loop {
        let now = Instant::now();
        if round < ROUNDS && now >= next_round {
            for (i, &ip) in hosts
                .iter()
                .filter(|ip| !found.contains_key(ip))
                .enumerate()
            {
                // Pace a little: Wi-Fi drivers drop long bursts.
                if i % 16 == 15 {
                    std::thread::sleep(Duration::from_millis(2));
                }
                let _ = cap.sendpacket(&request(&iface.mac, iface.ip, ip)[..]);
            }
            round += 1;
            next_round = Instant::now() + ROUND_GAP;
        }
        if round >= ROUNDS && now >= next_round - ROUND_GAP + LINGER {
            break;
        }
        match crate::net::capture::next_packet(&mut cap) {
            Ok(p) => {
                if let Some((ip, mac)) = sender(p.data)
                    && iface.contains(ip)
                    && ip != iface.ip
                    && found.insert(ip, mac).is_none()
                {
                    order.push(ip);
                }
            }
            Err(pcap::Error::TimeoutExpired) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(order.into_iter().map(|ip| (ip, found[&ip])).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips_through_the_parser() {
        let mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let f = request(
            &mac,
            Ipv4Addr::new(192, 168, 1, 19),
            Ipv4Addr::new(192, 168, 1, 1),
        );
        assert_eq!(&f[38..42], &[192, 168, 1, 1]);
        assert_eq!(sender(&f), Some((Ipv4Addr::new(192, 168, 1, 19), mac)));
        let mut probe = f;
        probe[28..32].copy_from_slice(&[0, 0, 0, 0]);
        assert_eq!(
            sender(&probe),
            None,
            "RFC 5227 probes have no sender address"
        );
        assert_eq!(sender(&f[..30]), None);
    }

    #[test]
    #[ignore = "sends ARP requests on the LAN (needs Npcap)"]
    fn live_sweep() {
        let iface = super::super::adapters::list()
            .into_iter()
            .find(|i| i.gateway.is_some())
            .expect("a LAN adapter");
        let (hosts, _) = super::super::adapters::sweep_hosts(&iface);
        let t = Instant::now();
        let found = sweep(&iface, &hosts).unwrap();
        println!(
            "{} devices in {:?} on {}",
            found.len(),
            t.elapsed(),
            iface.name
        );
        for (ip, mac) in &found {
            println!("  {ip:<15} {}", super::super::oui::format_mac(mac));
        }
        assert!(
            found.iter().any(|(ip, _)| Some(*ip) == iface.gateway),
            "the gateway answers"
        );
    }
}

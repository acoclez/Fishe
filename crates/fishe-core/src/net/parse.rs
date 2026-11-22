//! Minimal, allocation-free packet header parser.
//!
//! Fishe only needs addresses, the transport protocol and ports, so instead of
//! a full dissector this module walks just enough of each header. It is
//! deliberately tolerant of truncated frames because captures use a small
//! snap length (only headers are copied out of the kernel).
//!
//! Supported link layers: Ethernet (with 802.1Q / QinQ VLAN tags),
//! BSD loopback (`DLT_NULL` / `DLT_LOOP`, used by the Npcap loopback adapter)
//! and raw IP.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Transport-layer protocol of a packet.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, specta::Type,
)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Tcp,
    Udp,
    /// ICMP (IPv4) or ICMPv6.
    Icmp,
    Other,
}

impl Transport {
    fn from_ip_proto(proto: u8) -> Self {
        match proto {
            6 => Transport::Tcp,
            17 => Transport::Udp,
            1 | 58 => Transport::Icmp,
            _ => Transport::Other,
        }
    }

    fn has_ports(self) -> bool {
        matches!(self, Transport::Tcp | Transport::Udp)
    }
}

/// The fields Fishe extracts from every packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketInfo {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub transport: Transport,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    /// IPv4 TTL / IPv6 hop limit as received.
    pub ttl: u8,
}

/// Routers a packet crossed, estimated from its remaining TTL: senders start
/// at 32, 64, 128 or 255 (by OS), so the distance is the gap to the nearest
/// of those at or above the received value.
pub fn hops_from_ttl(ttl: u8) -> u8 {
    let initial = [32u8, 64, 128, 255]
        .into_iter()
        .find(|&i| i >= ttl)
        .unwrap_or(255);
    initial - ttl
}

/// Link-layer framing of captured data, derived from the pcap DLT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkLayer {
    Ethernet,
    /// 4-byte address-family header followed by an IP packet.
    Null,
    /// IP packet with no link header.
    Raw,
}

impl LinkLayer {
    /// Map a pcap data-link type to a supported framing, if any.
    pub fn from_dlt(dlt: i32) -> Option<Self> {
        match dlt {
            1 => Some(LinkLayer::Ethernet),
            0 | 108 => Some(LinkLayer::Null),
            12 | 14 | 101 | 228 | 229 => Some(LinkLayer::Raw),
            _ => None,
        }
    }
}

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;
const ETHERTYPE_VLAN: [u16; 3] = [0x8100, 0x88A8, 0x9100];

/// Parse a captured frame. Returns `None` for non-IP or malformed frames.
/// (The engine uses [`parse_tcp`], which also reads TCP fields.)
#[cfg(test)]
pub fn parse(link: LinkLayer, data: &[u8]) -> Option<PacketInfo> {
    match link {
        LinkLayer::Ethernet => parse_ethernet(data),
        LinkLayer::Null => parse_ip(data.get(4..)?),
        LinkLayer::Raw => parse_ip(data),
    }
    .map(|(info, _, _)| info)
}

/// TCP header fields used for connection-quality analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpInfo {
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    /// Payload bytes of the segment as sent (from the IP length, not the
    /// captured length, which is cut at the snap length).
    pub payload_len: u32,
}

pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;

/// Like [`parse`], plus the TCP header fields for TCP packets.
///
/// `wire_len` (the frame's original length) is used for the payload length
/// only when the IP header doesn't state one: Windows reports IPv4 total
/// length 0 for large segments handed to the NIC for segmentation (LSO).
pub fn parse_tcp(
    link: LinkLayer,
    data: &[u8],
    wire_len: u32,
) -> Option<(PacketInfo, Option<TcpInfo>)> {
    let (info, l4, declared) = match link {
        LinkLayer::Ethernet => parse_ethernet(data),
        LinkLayer::Null => parse_ip(data.get(4..)?),
        LinkLayer::Raw => parse_ip(data),
    }?;
    let tcp = match (info.transport, l4) {
        (Transport::Tcp, Some(l4)) => tcp_info(data, l4, declared, wire_len),
        _ => None,
    };
    Some((info, tcp))
}

fn tcp_info(frame: &[u8], l4: &[u8], declared: Option<usize>, wire_len: u32) -> Option<TcpInfo> {
    let header = usize::from(l4.get(12)? >> 4) * 4;
    if header < 20 {
        return None;
    }
    let l4_len = match declared {
        Some(n) if n >= header => n,
        // l4 is a suffix of the frame: its offset is what precedes it.
        _ => (wire_len as usize).checked_sub(frame.len() - l4.len())?,
    };
    Some(TcpInfo {
        seq: u32::from_be_bytes(l4.get(4..8)?.try_into().ok()?),
        ack: u32::from_be_bytes(l4.get(8..12)?.try_into().ok()?),
        flags: *l4.get(13)?,
        payload_len: l4_len.saturating_sub(header) as u32,
    })
}

/// Like [`parse`], also returning the layer-4 bytes (transport header +
/// payload, as far as captured). `None` for fragments and truncated frames.
pub fn parse_l4(link: LinkLayer, data: &[u8]) -> Option<(PacketInfo, &[u8])> {
    let (info, l4, _) = match link {
        LinkLayer::Ethernet => parse_ethernet(data),
        LinkLayer::Null => parse_ip(data.get(4..)?),
        LinkLayer::Raw => parse_ip(data),
    }?;
    Some((info, l4?))
}

/// A TCP segment's sequence number, flags and payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSegment<'a> {
    pub seq: u32,
    pub flags: u8,
    pub payload: &'a [u8],
}

/// Split a TCP header from its payload.
pub fn tcp_segment(l4: &[u8]) -> Option<TcpSegment<'_>> {
    let seq = u32::from_be_bytes(l4.get(4..8)?.try_into().ok()?);
    let data_offset = usize::from(l4.get(12)? >> 4) * 4;
    if data_offset < 20 {
        return None;
    }
    Some(TcpSegment {
        seq,
        flags: *l4.get(13)?,
        payload: l4.get(data_offset..)?,
    })
}

/// The payload of a UDP datagram.
pub fn udp_payload(l4: &[u8]) -> Option<&[u8]> {
    l4.get(8..)
}

/// Packet info, layer-4 bytes (as captured), layer-4 length stated by the IP header.
type Parsed<'a> = (PacketInfo, Option<&'a [u8]>, Option<usize>);

fn parse_ethernet(data: &[u8]) -> Option<Parsed<'_>> {
    let mut ethertype = be16(data, 12)?;
    let mut offset = 14;
    // Skip up to two stacked VLAN tags.
    for _ in 0..2 {
        if !ETHERTYPE_VLAN.contains(&ethertype) {
            break;
        }
        ethertype = be16(data, offset + 2)?;
        offset += 4;
    }
    let payload = data.get(offset..)?;
    match ethertype {
        ETHERTYPE_IPV4 => parse_ipv4(payload),
        ETHERTYPE_IPV6 => parse_ipv6(payload),
        _ => None,
    }
}

fn parse_ip(data: &[u8]) -> Option<Parsed<'_>> {
    match data.first()? >> 4 {
        4 => parse_ipv4(data),
        6 => parse_ipv6(data),
        _ => None,
    }
}

fn parse_ipv4(data: &[u8]) -> Option<Parsed<'_>> {
    if data.len() < 20 || data[0] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(data[0] & 0x0F) * 4;
    if ihl < 20 {
        return None;
    }
    let transport = Transport::from_ip_proto(data[9]);
    let ttl = data[8];
    // 0 under large-send offload: unknown.
    let declared = match be16(data, 2)? as usize {
        0 => None,
        total => total.checked_sub(ihl),
    };
    let fragment_offset = be16(data, 6)? & 0x1FFF;
    let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    // Only the first fragment carries the transport header.
    let l4 = if fragment_offset == 0 {
        data.get(ihl..)
    } else {
        None
    };
    Some((
        with_ports(src.into(), dst.into(), transport, ttl, l4),
        l4,
        declared,
    ))
}

fn parse_ipv6(data: &[u8]) -> Option<Parsed<'_>> {
    if data.len() < 40 || data[0] >> 4 != 6 {
        return None;
    }
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).ok()?);

    let ttl = data[7];
    let mut next = data[6];
    let mut offset = 40;
    let mut l4_available = true;

    // Walk the common extension headers to reach the transport header.
    for _ in 0..8 {
        match next {
            // Hop-by-hop, routing, destination options: length in 8-octet units.
            0 | 43 | 60 => {
                let (Some(&n), Some(&len)) = (data.get(offset), data.get(offset + 1)) else {
                    l4_available = false;
                    break;
                };
                next = n;
                offset += (usize::from(len) + 1) * 8;
            }
            // Fragment header: fixed 8 bytes.
            44 => {
                let (Some(&n), Some(frag)) = (data.get(offset), be16(data, offset + 2)) else {
                    l4_available = false;
                    break;
                };
                next = n;
                offset += 8;
                if frag >> 3 != 0 {
                    l4_available = false;
                    break;
                }
            }
            // Authentication header: length in 4-octet units, minus 2.
            51 => {
                let (Some(&n), Some(&len)) = (data.get(offset), data.get(offset + 1)) else {
                    l4_available = false;
                    break;
                };
                next = n;
                offset += (usize::from(len) + 2) * 4;
            }
            _ => break,
        }
    }

    let transport = Transport::from_ip_proto(next);
    let l4 = if l4_available {
        data.get(offset..)
    } else {
        None
    };
    // Payload length 0 = jumbogram or LSO: unknown.
    let declared = match be16(data, 4)? as usize {
        0 => None,
        payload => (payload + 40).checked_sub(offset),
    };
    Some((
        with_ports(src.into(), dst.into(), transport, ttl, l4),
        l4,
        declared,
    ))
}

fn with_ports(
    src: IpAddr,
    dst: IpAddr,
    transport: Transport,
    ttl: u8,
    l4: Option<&[u8]>,
) -> PacketInfo {
    let (src_port, dst_port) = match l4 {
        Some(l4) if transport.has_ports() => (be16(l4, 0), be16(l4, 2)),
        _ => (None, None),
    };
    PacketInfo {
        src,
        dst,
        transport,
        src_port,
        dst_port,
        ttl,
    }
}

#[inline]
fn be16(data: &[u8], at: usize) -> Option<u16> {
    let b = data.get(at..at + 2)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_header(proto: u8, src: [u8; 4], dst: [u8; 4], frag: u16) -> Vec<u8> {
        let mut h = vec![0u8; 20];
        h[0] = 0x45;
        h[6..8].copy_from_slice(&frag.to_be_bytes());
        h[8] = 64;
        h[9] = proto;
        h[12..16].copy_from_slice(&src);
        h[16..20].copy_from_slice(&dst);
        h
    }

    fn ports(src: u16, dst: u16) -> Vec<u8> {
        let mut p = src.to_be_bytes().to_vec();
        p.extend_from_slice(&dst.to_be_bytes());
        p.extend_from_slice(&[0; 16]);
        p
    }

    fn ethernet(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&ethertype.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    #[test]
    fn ethernet_ipv4_tcp() {
        let mut ip = ipv4_header(6, [10, 0, 0, 2], [93, 184, 216, 34], 0);
        ip.extend(ports(51000, 443));
        let info = parse(LinkLayer::Ethernet, &ethernet(ETHERTYPE_IPV4, &ip)).unwrap();
        assert_eq!(info.src, IpAddr::from([10, 0, 0, 2]));
        assert_eq!(info.dst, IpAddr::from([93, 184, 216, 34]));
        assert_eq!(info.transport, Transport::Tcp);
        assert_eq!(info.src_port, Some(51000));
        assert_eq!(info.dst_port, Some(443));
    }

    #[test]
    fn vlan_tagged_udp() {
        let mut ip = ipv4_header(17, [1, 1, 1, 1], [10, 0, 0, 2], 0);
        ip.extend(ports(53, 60000));
        let mut tagged = vec![0x00, 0x0A]; // TCI
        tagged.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        tagged.extend(ip);
        let info = parse(LinkLayer::Ethernet, &ethernet(0x8100, &tagged)).unwrap();
        assert_eq!(info.transport, Transport::Udp);
        assert_eq!(info.src_port, Some(53));
    }

    fn tcp_header(sp: u16, dp: u16, seq: u32, ack: u32, flags: u8) -> Vec<u8> {
        let mut t = vec![0u8; 20];
        t[0..2].copy_from_slice(&sp.to_be_bytes());
        t[2..4].copy_from_slice(&dp.to_be_bytes());
        t[4..8].copy_from_slice(&seq.to_be_bytes());
        t[8..12].copy_from_slice(&ack.to_be_bytes());
        t[12] = 5 << 4;
        t[13] = flags;
        t
    }

    #[test]
    fn tcp_fields_and_payload_length_from_ip_header() {
        let mut ip = ipv4_header(6, [10, 0, 0, 2], [1, 1, 1, 1], 0);
        let tcp = tcp_header(50000, 443, 1000, 2000, TCP_ACK);
        ip[2..4].copy_from_slice(&(20u16 + 20 + 1400).to_be_bytes());
        ip.extend(&tcp);
        ip.extend([0u8; 40]); // only part of the payload is captured
        let frame = ethernet(ETHERTYPE_IPV4, &ip);
        let (info, t) = parse_tcp(LinkLayer::Ethernet, &frame, 14 + 1440).unwrap();
        assert_eq!(info.dst_port, Some(443));
        let t = t.unwrap();
        assert_eq!(
            (t.seq, t.ack, t.flags, t.payload_len),
            (1000, 2000, TCP_ACK, 1400)
        );

        // Ethernet padding of a pure ACK is not payload.
        let mut ip = ipv4_header(6, [1, 1, 1, 1], [10, 0, 0, 2], 0);
        ip[2..4].copy_from_slice(&40u16.to_be_bytes());
        ip.extend(tcp_header(443, 50000, 2000, 2400, TCP_ACK));
        ip.extend([0u8; 6]);
        let frame = ethernet(ETHERTYPE_IPV4, &ip);
        let (_, t) = parse_tcp(LinkLayer::Ethernet, &frame, 60).unwrap();
        assert_eq!(t.unwrap().payload_len, 0);

        // LSO: total length 0, fall back to the wire length.
        let mut ip = ipv4_header(6, [10, 0, 0, 2], [1, 1, 1, 1], 0);
        ip.extend(tcp_header(50000, 443, 5000, 1, TCP_ACK));
        let frame = ethernet(ETHERTYPE_IPV4, &ip);
        let (_, t) = parse_tcp(LinkLayer::Ethernet, &frame, 14 + 40 + 64_000).unwrap();
        assert_eq!(t.unwrap().payload_len, 64_000);

        // IPv6 payload length.
        let mut ip6 = vec![0u8; 40];
        ip6[0] = 0x60;
        ip6[4..6].copy_from_slice(&(20u16 + 100).to_be_bytes());
        ip6[6] = 6;
        ip6[7] = 64;
        ip6.extend(tcp_header(443, 50000, 7, 8, TCP_ACK | TCP_SYN));
        let (_, t) = parse_tcp(LinkLayer::Raw, &ip6, 160).unwrap();
        let t = t.unwrap();
        assert_eq!((t.payload_len, t.flags & TCP_SYN), (100, TCP_SYN));

        // UDP: no TCP info.
        let mut ip = ipv4_header(17, [1, 1, 1, 1], [10, 0, 0, 2], 0);
        ip.extend(ports(53, 6000));
        assert_eq!(parse_tcp(LinkLayer::Raw, &ip, 44).unwrap().1, None);
    }

    #[test]
    fn ipv4_non_first_fragment_has_no_ports() {
        let mut ip = ipv4_header(17, [1, 1, 1, 1], [10, 0, 0, 2], 185);
        ip.extend(ports(53, 60000));
        let info = parse(LinkLayer::Raw, &ip).unwrap();
        assert_eq!(info.transport, Transport::Udp);
        assert_eq!(info.src_port, None);
    }

    #[test]
    fn truncated_transport_header_still_counts() {
        let mut ip = ipv4_header(6, [1, 2, 3, 4], [5, 6, 7, 8], 0);
        ip.extend_from_slice(&[0x01]); // half a port
        let info = parse(LinkLayer::Raw, &ip).unwrap();
        assert_eq!(info.transport, Transport::Tcp);
        assert_eq!(info.src_port, None);
    }

    #[test]
    fn ipv6_with_hop_by_hop_then_udp() {
        let mut ip = vec![0u8; 40];
        ip[0] = 0x60;
        ip[6] = 0; // hop-by-hop
        ip[8..24].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        ip[24..40].copy_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        ip.extend_from_slice(&[17, 0, 0, 0, 0, 0, 0, 0]); // ext header -> UDP, len 0
        ip.extend(ports(5353, 5353));
        let info = parse(LinkLayer::Ethernet, &ethernet(ETHERTYPE_IPV6, &ip)).unwrap();
        assert_eq!(info.transport, Transport::Udp);
        assert_eq!(info.dst_port, Some(5353));
        assert_eq!(info.src, "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn null_loopback_frame() {
        let mut frame = 2u32.to_le_bytes().to_vec(); // AF_INET
        let mut ip = ipv4_header(1, [127, 0, 0, 1], [127, 0, 0, 1], 0);
        ip.extend_from_slice(&[8, 0, 0, 0]);
        frame.extend(ip);
        let info = parse(LinkLayer::Null, &frame).unwrap();
        assert_eq!(info.transport, Transport::Icmp);
        assert_eq!(info.src_port, None);
    }

    #[test]
    fn rejects_non_ip_and_garbage() {
        assert!(parse(LinkLayer::Ethernet, &ethernet(0x0806, &[0; 28])).is_none()); // ARP
        assert!(parse(LinkLayer::Ethernet, &[0; 5]).is_none());
        assert!(parse(LinkLayer::Raw, &[0x45, 0, 0]).is_none());
        assert!(parse(LinkLayer::Raw, &[]).is_none());
    }

    #[test]
    fn l4_payload_access() {
        let mut ip = ipv4_header(6, [10, 0, 0, 2], [1, 1, 1, 1], 0);
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&50000u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[4..8].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = 0x18; // PSH|ACK
        tcp.extend_from_slice(b"\x16\x03\x01hello");
        ip.extend(tcp);
        let (info, l4) = parse_l4(LinkLayer::Raw, &ip).unwrap();
        assert_eq!(info.dst_port, Some(443));
        let seg = tcp_segment(l4).unwrap();
        assert_eq!(seg.seq, 0xDEADBEEF);
        assert_eq!(seg.flags, 0x18);
        assert_eq!(seg.payload, b"\x16\x03\x01hello");

        let mut ip = ipv4_header(17, [8, 8, 8, 8], [10, 0, 0, 2], 0);
        ip.extend(ports(53, 5000));
        let (_, l4) = parse_l4(LinkLayer::Raw, &ip).unwrap();
        assert_eq!(udp_payload(l4).unwrap().len(), 12); // 20-byte test segment minus the 8-byte UDP header

        // fragments expose no layer 4
        let mut frag = ipv4_header(17, [8, 8, 8, 8], [10, 0, 0, 2], 185);
        frag.extend(ports(53, 5000));
        assert!(parse_l4(LinkLayer::Raw, &frag).is_none());
    }

    #[test]
    fn ttl_and_hop_estimate() {
        let ip = ipv4_header(6, [1, 1, 1, 1], [10, 0, 0, 2], 0); // TTL 64 in the helper
        assert_eq!(parse(LinkLayer::Raw, &ip).unwrap().ttl, 64);
        assert_eq!(hops_from_ttl(64), 0);
        assert_eq!(hops_from_ttl(54), 10);
        assert_eq!(hops_from_ttl(117), 11);
        assert_eq!(hops_from_ttl(243), 12);
        assert_eq!(hops_from_ttl(30), 2);
    }

    #[test]
    fn dlt_mapping() {
        assert_eq!(LinkLayer::from_dlt(1), Some(LinkLayer::Ethernet));
        assert_eq!(LinkLayer::from_dlt(0), Some(LinkLayer::Null));
        assert_eq!(LinkLayer::from_dlt(101), Some(LinkLayer::Raw));
        assert_eq!(LinkLayer::from_dlt(105), None); // 802.11
    }
}

//! Traffic counters.
//!
//! Capture workers fill a [`Tally`] and hand it to the aggregator every few
//! milliseconds; the aggregator merges tallies into the tick window and the
//! session totals.

use super::quality::QualityDelta;
use crate::net::parse::{PacketInfo, Transport};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// Direction relative to the monitored side.
///
/// - Host mode: `In` = remote host → this machine, `Out` = this machine → host.
/// - Process mode: `In` = received by the process, `Out` = sent by it.
/// - All-traffic mode: `In` = received by this machine, `Out` = sent by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, specta::Type)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    In,
    Out,
}

/// Byte/packet counters for both directions.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Counters {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
}

impl Counters {
    pub fn add(&mut self, dir: Direction, bytes: u64) {
        match dir {
            Direction::In => {
                self.bytes_in += bytes;
                self.packets_in += 1;
            }
            Direction::Out => {
                self.bytes_out += bytes;
                self.packets_out += 1;
            }
        }
    }

    pub fn merge(&mut self, o: &Counters) {
        self.bytes_in += o.bytes_in;
        self.bytes_out += o.bytes_out;
        self.packets_in += o.packets_in;
        self.packets_out += o.packets_out;
    }

    #[cfg(test)]
    pub fn bytes(&self) -> u64 {
        self.bytes_in + self.bytes_out
    }
}

/// Bytes per transport protocol.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
pub struct TransportBytes {
    pub tcp: u64,
    pub udp: u64,
    pub icmp: u64,
    pub other: u64,
}

impl TransportBytes {
    fn add(&mut self, t: Transport, bytes: u64) {
        match t {
            Transport::Tcp => self.tcp += bytes,
            Transport::Udp => self.udp += bytes,
            Transport::Icmp => self.icmp += bytes,
            Transport::Other => self.other += bytes,
        }
    }

    fn merge(&mut self, o: &TransportBytes) {
        self.tcp += o.tcp;
        self.udp += o.udp;
        self.icmp += o.icmp;
        self.other += o.other;
    }
}

/// Cumulative usage of one service port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct PortUsage {
    pub transport: Transport,
    pub port: u16,
    pub bytes: u64,
    pub packets: u64,
}

/// Upper bound on distinct ports tracked, to bound memory on port scans.
pub const MAX_TRACKED_PORTS: usize = 2048;

/// Connection requests one remote address sent to one local port.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct InboundHit {
    /// Requests received (TCP SYN).
    pub syns: u32,
    /// Requests this machine accepted (it answered SYN-ACK).
    pub answered: u32,
}

/// Upper bound on (remote address, local port) pairs per batch: a port
/// scan fills it, and the rest of the scan is not needed to call it one.
pub const MAX_INBOUND: usize = 1024;

/// Upper bound on (remote address, service port) pairs whose payload is
/// noted per batch.
pub const MAX_PAYLOAD_PORTS: usize = 1024;

/// A batch of counts.
#[derive(Debug, Default, Clone)]
pub struct Tally {
    pub counters: Counters,
    pub transports: TransportBytes,
    pub ports: HashMap<(Transport, u16), (u64, u64)>,
    /// Frames matching the BPF filter that couldn't be parsed as IP.
    pub unparsed: u64,
    /// Packets whose owner was never found (process mode).
    pub unattributed: u64,
    /// Per remote address (the side that isn't this machine).
    pub endpoints: HashMap<IpAddr, EndpointDelta>,
    /// Per owning PID (all-traffic mode); [`UNATTRIBUTED`] = no owner.
    pub programs: HashMap<u32, Counters>,
    /// TCP connection quality of the counted flows (see `quality.rs`).
    pub quality: QualityDelta,
    /// Connections other machines tried to open to this one, by
    /// (remote address, local port). For the security view.
    pub inbound: HashMap<(IpAddr, u16), InboundHit>,
    /// TCP payload bytes exchanged with a remote address on a service port
    /// the security view reports (unencrypted services, DNS over TLS).
    /// Payload, not packets: a refused connection request carries none.
    pub payload: HashMap<(IpAddr, u16), u64>,
}

/// Program key for packets without an owner (PID 0 never owns a socket in
/// the ownership table, so it can't collide).
pub const UNATTRIBUTED: u32 = 0;

/// Counts for one remote address within a tally.
#[derive(Debug, Default, Clone)]
pub struct EndpointDelta {
    pub counters: Counters,
    /// Service port → bytes.
    pub ports: HashMap<(Transport, u16), u64>,
    /// TTL of the latest packet received from this endpoint.
    pub last_ttl: Option<u8>,
    /// Owning PID → bytes (all-traffic mode).
    pub programs: HashMap<u32, u64>,
    /// TCP connection quality towards this endpoint.
    pub quality: QualityDelta,
}

/// Bound on programs remembered per endpoint.
pub const MAX_PROGRAMS_PER_ENDPOINT: usize = 8;

/// Bound on service ports remembered per endpoint.
pub const MAX_PORTS_PER_ENDPOINT: usize = 16;

impl EndpointDelta {
    pub fn merge(&mut self, o: &EndpointDelta) {
        self.counters.merge(&o.counters);
        if o.last_ttl.is_some() {
            self.last_ttl = o.last_ttl;
        }
        for (&k, &b) in &o.ports {
            if self.ports.len() < MAX_PORTS_PER_ENDPOINT || self.ports.contains_key(&k) {
                *self.ports.entry(k).or_default() += b;
            }
        }
        for (&pid, &b) in &o.programs {
            add_program(&mut self.programs, pid, b);
        }
        self.quality.merge(&o.quality);
    }
}

fn add_program(programs: &mut HashMap<u32, u64>, pid: u32, bytes: u64) {
    if programs.len() < MAX_PROGRAMS_PER_ENDPOINT || programs.contains_key(&pid) {
        *programs.entry(pid).or_default() += bytes;
    }
}

impl Tally {
    /// Record one matched packet of `wire_len` bytes (original length on the wire).
    pub fn record(&mut self, dir: Direction, info: &PacketInfo, wire_len: u32) {
        self.record_endpoint(dir, info, wire_len);
    }

    /// A TCP handshake packet between `remote` and local port `lport`:
    /// a request from the remote side (`dir` in, no ACK) or this machine
    /// accepting one (`dir` out, with ACK). Requests this machine sends
    /// are not attempts on it and are ignored.
    pub fn note_syn(&mut self, dir: Direction, ack: bool, remote: IpAddr, lport: u16) {
        let key = (remote, lport);
        if self.inbound.len() >= MAX_INBOUND && !self.inbound.contains_key(&key) {
            return;
        }
        match (dir, ack) {
            (Direction::In, false) => {
                let hit = self.inbound.entry(key).or_default();
                hit.syns = hit.syns.saturating_add(1);
            }
            (Direction::Out, true) => {
                let hit = self.inbound.entry(key).or_default();
                hit.answered = hit.answered.saturating_add(1);
            }
            _ => {}
        }
    }

    /// `bytes` of TCP payload passed between this machine and `remote` on
    /// service `port`.
    pub fn note_payload(&mut self, remote: IpAddr, port: u16, bytes: u64) {
        let key = (remote, port);
        if self.payload.len() < MAX_PAYLOAD_PORTS || self.payload.contains_key(&key) {
            *self.payload.entry(key).or_default() += bytes;
        }
    }

    /// Add TCP quality measurements of a counted flow to `remote`.
    pub fn add_quality(&mut self, remote: IpAddr, d: &QualityDelta) {
        self.quality.merge(d);
        self.endpoints.entry(remote).or_default().quality.merge(d);
    }

    /// Record one packet of all-traffic mode, with its owner (`None`: unattributed).
    pub fn record_owned(
        &mut self,
        dir: Direction,
        info: &PacketInfo,
        wire_len: u32,
        pid: Option<u32>,
    ) {
        let pid = pid.unwrap_or(UNATTRIBUTED);
        if pid == UNATTRIBUTED {
            self.unattributed += 1;
        }
        self.programs
            .entry(pid)
            .or_default()
            .add(dir, u64::from(wire_len));
        let e = self.record_endpoint(dir, info, wire_len);
        add_program(&mut e.programs, pid, u64::from(wire_len));
    }

    fn record_endpoint(
        &mut self,
        dir: Direction,
        info: &PacketInfo,
        wire_len: u32,
    ) -> &mut EndpointDelta {
        let bytes = u64::from(wire_len);
        self.counters.add(dir, bytes);
        self.transports.add(info.transport, bytes);
        let port = service_port(info);
        if let Some(port) = port {
            add_port(&mut self.ports, (info.transport, port), bytes, 1);
        }

        let remote = match dir {
            Direction::In => info.src,
            Direction::Out => info.dst,
        };
        let e = self.endpoints.entry(remote).or_default();
        e.counters.add(dir, bytes);
        if dir == Direction::In {
            e.last_ttl = Some(info.ttl);
        }
        if let Some(port) = port
            && (e.ports.len() < MAX_PORTS_PER_ENDPOINT
                || e.ports.contains_key(&(info.transport, port)))
        {
            *e.ports.entry((info.transport, port)).or_default() += bytes;
        }
        e
    }

    /// Fold `other` into `self`.
    pub fn merge(&mut self, other: &Tally) {
        self.counters.merge(&other.counters);
        self.transports.merge(&other.transports);
        for (&key, &(bytes, packets)) in &other.ports {
            add_port(&mut self.ports, key, bytes, packets);
        }
        self.unparsed += other.unparsed;
        self.unattributed += other.unattributed;
        for (ip, d) in &other.endpoints {
            self.endpoints.entry(*ip).or_default().merge(d);
        }
        for (pid, c) in &other.programs {
            self.programs.entry(*pid).or_default().merge(c);
        }
        self.quality.merge(&other.quality);
        for (key, hit) in &other.inbound {
            if self.inbound.len() < MAX_INBOUND || self.inbound.contains_key(key) {
                let h = self.inbound.entry(*key).or_default();
                h.syns = h.syns.saturating_add(hit.syns);
                h.answered = h.answered.saturating_add(hit.answered);
            }
        }
        for (&(remote, port), &bytes) in &other.payload {
            self.note_payload(remote, port, bytes);
        }
    }

    /// The `n` ports with the most bytes, descending.
    pub fn top_ports(&self, n: usize) -> Vec<PortUsage> {
        let mut v: Vec<PortUsage> = self
            .ports
            .iter()
            .map(|(&(transport, port), &(bytes, packets))| PortUsage {
                transport,
                port,
                bytes,
                packets,
            })
            .collect();
        v.sort_unstable_by(|a, b| b.bytes.cmp(&a.bytes).then(a.port.cmp(&b.port)));
        v.truncate(n);
        v
    }
}

fn add_port(
    ports: &mut HashMap<(Transport, u16), (u64, u64)>,
    key: (Transport, u16),
    bytes: u64,
    packets: u64,
) {
    if ports.len() < MAX_TRACKED_PORTS || ports.contains_key(&key) {
        let e = ports.entry(key).or_default();
        e.0 += bytes;
        e.1 += packets;
    }
}

/// Heuristic "service" port of a flow: the lower of the two ports.
///
/// Servers usually listen on well-known/registered ports, while clients use
/// high ephemeral ports, so `min(src, dst)` names the service (443, 53, …)
/// whichever side initiated the connection.
pub fn service_port(info: &PacketInfo) -> Option<u16> {
    match (info.src_port, info.dst_port) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(p), None) | (None, Some(p)) => Some(p),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: [u8; 4] = [10, 0, 0, 2];
    const THEM: [u8; 4] = [93, 184, 216, 34];

    fn pkt(src: [u8; 4], dst: [u8; 4], t: Transport, sp: u16, dp: u16) -> PacketInfo {
        PacketInfo {
            src: src.into(),
            dst: dst.into(),
            transport: t,
            src_port: Some(sp),
            dst_port: Some(dp),
            ttl: 64,
        }
    }

    #[test]
    fn record_and_merge() {
        let mut a = Tally::default();
        a.record(
            Direction::Out,
            &pkt(ME, THEM, Transport::Tcp, 50000, 443),
            100,
        );
        a.record(
            Direction::In,
            &pkt(THEM, ME, Transport::Tcp, 443, 50000),
            1500,
        );
        let mut b = Tally::default();
        b.record(
            Direction::In,
            &pkt(THEM, ME, Transport::Tcp, 443, 50000),
            1500,
        );
        b.unattributed = 3;

        let mut total = Tally::default();
        total.merge(&a);
        total.merge(&b);
        assert_eq!(
            (total.counters.bytes_out, total.counters.packets_out),
            (100, 1)
        );
        assert_eq!(
            (total.counters.bytes_in, total.counters.packets_in),
            (3000, 2)
        );
        assert_eq!(total.counters.bytes(), 3100);
        assert_eq!(total.transports.tcp, 3100);
        assert_eq!(total.unattributed, 3);
        assert_eq!(total.top_ports(1)[0].packets, 3);
    }

    #[test]
    fn top_ports_use_service_port() {
        let mut t = Tally::default();
        t.record(
            Direction::In,
            &pkt(THEM, ME, Transport::Tcp, 443, 50000),
            1000,
        );
        t.record(
            Direction::Out,
            &pkt(ME, THEM, Transport::Udp, 61000, 53),
            80,
        );
        t.record(
            Direction::Out,
            &pkt(ME, THEM, Transport::Tcp, 50001, 443),
            60,
        );
        let top = t.top_ports(5);
        assert_eq!(top[0].port, 443);
        assert_eq!(top[0].bytes, 1060);
        assert_eq!(top[0].packets, 2);
        assert_eq!(top[1].port, 53);
    }

    #[test]
    fn owned_packets_count_per_program_and_endpoint() {
        let mut t = Tally::default();
        let out = pkt(ME, THEM, Transport::Tcp, 50000, 443);
        t.record_owned(Direction::Out, &out, 100, Some(42));
        t.record_owned(
            Direction::In,
            &pkt(THEM, ME, Transport::Tcp, 443, 50000),
            1500,
            Some(42),
        );
        t.record_owned(
            Direction::In,
            &pkt(THEM, ME, Transport::Udp, 53, 50001),
            80,
            None,
        );
        let mut total = Tally::default();
        total.merge(&t);
        total.merge(&t);
        assert_eq!(total.programs[&42].bytes(), 3200);
        assert_eq!(total.programs[&UNATTRIBUTED].packets_in, 2);
        assert_eq!(total.unattributed, 2);
        let e = &total.endpoints[&IpAddr::from(THEM)];
        assert_eq!(e.programs[&42], 3200);
        assert_eq!(e.programs[&UNATTRIBUTED], 160);
        assert_eq!(total.counters.bytes(), 3360);
    }

    #[test]
    fn port_table_is_bounded() {
        let mut t = Tally::default();
        for p in 0..(MAX_TRACKED_PORTS as u16 + 50) {
            t.record(Direction::Out, &pkt(ME, THEM, Transport::Udp, p, p), 1);
        }
        assert_eq!(t.ports.len(), MAX_TRACKED_PORTS);
        assert_eq!(t.counters.packets_out, MAX_TRACKED_PORTS as u64 + 50);
    }
}

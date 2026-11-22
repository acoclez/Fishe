//! Connection quality, measured passively from TCP headers.
//!
//! Every capture worker runs a [`FlowTracker`] over the TCP packets it
//! sees, in capture order, and derives:
//!
//! - **RTT samples**: our SYN → their SYN-ACK; our SYN-ACK → their ACK
//!   (connections they opened); our data segment → their ACK covering it.
//!   Retransmitted segments, and anything outstanding when a retransmission
//!   happens, never give a sample (Karn's rule).
//! - **Retransmitted bytes** sent by us (data we had already sent: the path
//!   lost it, or the peer's ACK was lost) and received by us (data we had
//!   already received: our ACK was lost, or the segment before it was lost
//!   on the way to us). Keep-alive probes are not counted.
//!
//! Attribution can lag behind the packets (process mode holds packets
//! whose owner isn't known yet), so a flow's measurements are buffered
//! until a packet of it is counted, and dropped if it turns out to belong
//! to something else.
//!
//! The aggregator turns the per-tick [`QualityDelta`]s into rolling session
//! figures ([`SessionQuality`]) and per-endpoint ones ([`RttStats`] in the
//! endpoint book).

use super::stats::{Direction, Tally};
use crate::net::parse::{PacketInfo, TCP_ACK, TCP_RST, TCP_SYN, TcpInfo};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;

/// RTT samples above this are discarded (sleeping laptop, clock jump…).
const MAX_RTT_US: u64 = 10_000_000;
/// Unacknowledged segments remembered per flow.
const UNACKED_CAP: usize = 64;
/// Flows tracked per worker.
const MAX_FLOWS: usize = 16_384;
/// Flows without packets for this long are forgotten.
const FLOW_IDLE_US: u64 = 120_000_000;
const SWEEP_EVERY_US: u64 = 5_000_000;
/// RTT samples kept per delta (per batch, per endpoint).
pub const MAX_SAMPLES: usize = 64;
/// Rolling window of the session figures.
pub const RECENT_MS: u64 = 10_000;

/// Quality measurements of one batch.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct QualityDelta {
    /// RTT samples (µs), in capture order.
    pub rtt_us: Vec<u32>,
    /// TCP payload bytes sent / received, retransmissions included.
    pub data_out: u64,
    pub data_in: u64,
    /// Payload bytes that were retransmissions.
    pub retrans_out: u64,
    pub retrans_in: u64,
}

impl QualityDelta {
    pub fn is_empty(&self) -> bool {
        self.rtt_us.is_empty() && self.data_out == 0 && self.data_in == 0
    }

    pub fn merge(&mut self, o: &QualityDelta) {
        let room = MAX_SAMPLES.saturating_sub(self.rtt_us.len());
        self.rtt_us.extend(o.rtt_us.iter().take(room));
        self.data_out += o.data_out;
        self.data_in += o.data_in;
        self.retrans_out += o.retrans_out;
        self.retrans_in += o.retrans_in;
    }
}

// ─────────────────────────── per-worker tracking ───────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    local: IpAddr,
    lport: u16,
    remote: IpAddr,
    rport: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    /// No packet of the flow has been counted or skipped yet.
    Unknown,
    Counted,
    Skipped,
}

/// A handshake segment we sent: sequence number, time, retransmitted.
type Sent = (u32, u64, bool);

#[derive(Debug)]
struct Flow {
    scope: Scope,
    buffered: QualityDelta,
    /// Highest sequence end sent by us / by them.
    out_hi: Option<u32>,
    in_hi: Option<u32>,
    /// Our data segments waiting for an ACK: (sequence end, time).
    unacked: VecDeque<(u32, u64)>,
    syn: Option<Sent>,
    synack: Option<Sent>,
    last_us: u64,
}

impl Flow {
    fn new(ts: u64) -> Self {
        Flow {
            scope: Scope::Unknown,
            buffered: QualityDelta::default(),
            out_hi: None,
            in_hi: None,
            unacked: VecDeque::new(),
            syn: None,
            synack: None,
            last_us: ts,
        }
    }
}

/// `a < b` in TCP sequence space (wrap-around safe).
fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

fn seq_le(a: u32, b: u32) -> bool {
    a == b || seq_lt(a, b)
}

fn seq_max(a: u32, b: u32) -> u32 {
    if seq_lt(a, b) { b } else { a }
}

/// One capture worker's TCP flow state.
pub struct FlowTracker {
    local: std::sync::Arc<HashSet<IpAddr>>,
    flows: HashMap<FlowKey, Flow>,
    last_sweep: u64,
}

impl FlowTracker {
    pub fn new(local: std::sync::Arc<HashSet<IpAddr>>) -> Self {
        FlowTracker {
            local,
            flows: HashMap::new(),
            last_sweep: 0,
        }
    }

    /// The flow of a packet, oriented from this host. `None` when neither
    /// or both ends are local (loopback), or the packet has no ports.
    fn key(&self, info: &PacketInfo) -> Option<(FlowKey, Direction)> {
        let (sp, dp) = (info.src_port?, info.dst_port?);
        let (src_local, dst_local) = (
            self.local.contains(&info.src),
            self.local.contains(&info.dst),
        );
        match (src_local, dst_local) {
            (true, false) => Some((
                FlowKey {
                    local: info.src,
                    lport: sp,
                    remote: info.dst,
                    rport: dp,
                },
                Direction::Out,
            )),
            (false, true) => Some((
                FlowKey {
                    local: info.dst,
                    lport: dp,
                    remote: info.src,
                    rport: sp,
                },
                Direction::In,
            )),
            _ => None,
        }
    }

    /// Observe one TCP packet at capture time `ts` (µs). `counted`: the
    /// packet was counted (`Some(true)`), belongs to something else
    /// (`Some(false)`), or its owner isn't known yet (`None`).
    pub fn observe(
        &mut self,
        ts: u64,
        info: &PacketInfo,
        tcp: &TcpInfo,
        counted: Option<bool>,
        tally: &mut Tally,
    ) {
        let Some((key, dir)) = self.key(info) else {
            return;
        };
        if tcp.flags & TCP_SYN != 0 {
            tally.note_syn(dir, tcp.flags & TCP_ACK != 0, key.remote, key.lport);
        }
        if tcp.payload_len > 0 {
            let port = key.lport.min(key.rport);
            if crate::security::services::audited_tcp_port(port) {
                tally.note_payload(key.remote, port, u64::from(tcp.payload_len));
            }
        }
        self.sweep(ts);
        if !self.flows.contains_key(&key) && self.flows.len() >= MAX_FLOWS {
            return;
        }
        let flow = self.flows.entry(key).or_insert_with(|| Flow::new(ts));
        flow.last_us = ts;
        let mut ev = QualityDelta::default();
        analyse(flow, ts, dir, tcp, &mut ev);
        if let Some(c) = counted {
            set_scope(flow, c, key.remote, tally);
        }
        match flow.scope {
            Scope::Counted => {
                if !ev.is_empty() {
                    tally.add_quality(key.remote, &ev);
                }
            }
            Scope::Unknown => flow.buffered.merge(&ev),
            Scope::Skipped => {}
        }
    }

    /// A held packet was finally classified: settle its flow's scope.
    pub fn resolve(&mut self, info: &PacketInfo, counted: bool, tally: &mut Tally) {
        if let Some((key, _)) = self.key(info)
            && let Some(flow) = self.flows.get_mut(&key)
        {
            set_scope(flow, counted, key.remote, tally);
        }
    }

    fn sweep(&mut self, now: u64) {
        if now.saturating_sub(self.last_sweep) < SWEEP_EVERY_US {
            return;
        }
        self.last_sweep = now;
        self.flows
            .retain(|_, f| now.saturating_sub(f.last_us) < FLOW_IDLE_US);
    }
}

fn set_scope(flow: &mut Flow, counted: bool, remote: IpAddr, tally: &mut Tally) {
    if flow.scope != Scope::Unknown {
        // A port can be reused by another program later; first verdict wins
        // for the lifetime of the flow entry.
        if counted && flow.scope == Scope::Skipped {
            flow.scope = Scope::Counted;
        }
        return;
    }
    if counted {
        flow.scope = Scope::Counted;
        let buffered = std::mem::take(&mut flow.buffered);
        if !buffered.is_empty() {
            tally.add_quality(remote, &buffered);
        }
    } else {
        flow.scope = Scope::Skipped;
        flow.buffered = QualityDelta::default();
    }
}

fn sample(ev: &mut QualityDelta, from: u64, to: u64) {
    if to >= from && to - from <= MAX_RTT_US && ev.rtt_us.len() < MAX_SAMPLES {
        ev.rtt_us.push((to - from) as u32);
    }
}

/// Update one flow with one segment; measurements go to `ev`.
fn analyse(flow: &mut Flow, ts: u64, dir: Direction, tcp: &TcpInfo, ev: &mut QualityDelta) {
    let syn = tcp.flags & TCP_SYN != 0;
    let ack = tcp.flags & TCP_ACK != 0;
    if tcp.flags & TCP_RST != 0 {
        flow.unacked.clear();
        return;
    }
    let len = tcp.payload_len;
    let end = tcp.seq.wrapping_add(len);

    match dir {
        Direction::Out => {
            if syn {
                let slot = if ack { &mut flow.synack } else { &mut flow.syn };
                *slot = match *slot {
                    Some((s, t, _)) if s == tcp.seq => Some((s, t, true)), // retransmitted
                    _ => Some((tcp.seq, ts, false)),
                };
                flow.out_hi = Some(tcp.seq.wrapping_add(1));
            }
            if len > 0 {
                ev.data_out += u64::from(len);
                match flow.out_hi {
                    Some(hi) if seq_le(end, hi) => {
                        // Already sent: a retransmission, unless it is a
                        // keep-alive probe (≤ 1 byte just below the edge).
                        let keepalive = len <= 1 && tcp.seq == hi.wrapping_sub(1);
                        if !keepalive {
                            ev.retrans_out += u64::from(len);
                            // Karn: ACKs for anything still outstanding now
                            // also measure the loss recovery, not the path.
                            flow.unacked.clear();
                        }
                    }
                    Some(hi) if seq_lt(tcp.seq, hi) => {
                        ev.retrans_out += u64::from(hi.wrapping_sub(tcp.seq));
                        flow.unacked.clear();
                    }
                    _ => push_unacked(flow, end, ts),
                }
                flow.out_hi = Some(flow.out_hi.map_or(end, |hi| seq_max(hi, end)));
            }
        }
        Direction::In => {
            if syn && ack {
                if let Some((s, t, retx)) = flow.syn
                    && tcp.ack == s.wrapping_add(1)
                {
                    if !retx {
                        sample(ev, t, ts);
                    }
                    flow.syn = None;
                }
            } else if ack {
                if let Some((s, t, retx)) = flow.synack
                    && tcp.ack == s.wrapping_add(1)
                {
                    if !retx {
                        sample(ev, t, ts);
                    }
                    flow.synack = None;
                }
                // The newest of our segments this ACK covers gives the sample:
                // it is most likely the one that triggered the ACK.
                let mut newest = None;
                while let Some(&(e, t)) = flow.unacked.front() {
                    if !seq_le(e, tcp.ack) {
                        break;
                    }
                    newest = Some(t);
                    flow.unacked.pop_front();
                }
                if let Some(t) = newest {
                    sample(ev, t, ts);
                }
            }
            if syn {
                flow.in_hi = Some(tcp.seq.wrapping_add(1));
            }
            if len > 0 {
                ev.data_in += u64::from(len);
                if let Some(hi) = flow.in_hi
                    && seq_le(end, hi)
                    && !(len <= 1 && tcp.seq == hi.wrapping_sub(1))
                {
                    ev.retrans_in += u64::from(len);
                }
                flow.in_hi = Some(flow.in_hi.map_or(end, |hi| seq_max(hi, end)));
            }
        }
    }
}

fn push_unacked(flow: &mut Flow, end: u32, ts: u64) {
    if flow.unacked.len() >= UNACKED_CAP {
        flow.unacked.pop_front();
    }
    flow.unacked.push_back((end, ts));
}

// ───────────────────────────── aggregation ─────────────────────────────

/// Smoothed RTT statistics over a sequence of samples.
#[derive(Debug, Default, Clone, Copy)]
pub struct RttStats {
    /// TCP-style smoothed RTT (gain 1/8), µs.
    pub srtt_us: f64,
    /// RFC 3550-style jitter: smoothed |difference of consecutive samples| (gain 1/16), µs.
    pub jitter_us: f64,
    pub min_us: u32,
    pub last_us: u32,
    pub count: u64,
}

impl RttStats {
    pub fn add(&mut self, s: u32) {
        let x = f64::from(s);
        if self.count == 0 {
            self.srtt_us = x;
            self.min_us = s;
        } else {
            self.srtt_us += (x - self.srtt_us) / 8.0;
            self.jitter_us += ((x - f64::from(self.last_us)).abs() - self.jitter_us) / 16.0;
            self.min_us = self.min_us.min(s);
        }
        self.last_us = s;
        self.count += 1;
    }
}

fn ms(us: f64) -> f64 {
    us / 1000.0
}

/// Retransmitted share in percent, `None` without data.
fn pct(retrans: u64, data: u64) -> Option<f64> {
    (data > 0).then(|| retrans as f64 * 100.0 / data as f64)
}

/// Per-endpoint quality as sent to the UI (and stored with recordings).
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct EndpointQuality {
    pub srtt_ms: Option<f64>,
    pub min_rtt_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub rtt_samples: u64,
    /// Share of the TCP payload we sent that was retransmitted (session).
    pub retrans_out_pct: Option<f64>,
    /// Share of the TCP payload we received that was a retransmission (session).
    pub retrans_in_pct: Option<f64>,
}

/// Per-endpoint accumulator, kept in the endpoint book.
#[derive(Debug, Default, Clone)]
pub struct EndpointQualityAcc {
    pub rtt: RttStats,
    pub data_out: u64,
    pub data_in: u64,
    pub retrans_out: u64,
    pub retrans_in: u64,
}

impl EndpointQualityAcc {
    pub fn add(&mut self, d: &QualityDelta) {
        for &s in &d.rtt_us {
            self.rtt.add(s);
        }
        self.data_out += d.data_out;
        self.data_in += d.data_in;
        self.retrans_out += d.retrans_out;
        self.retrans_in += d.retrans_in;
    }

    pub fn row(&self) -> Option<EndpointQuality> {
        if self.rtt.count == 0 && self.data_out == 0 && self.data_in == 0 {
            return None;
        }
        let has = self.rtt.count > 0;
        Some(EndpointQuality {
            srtt_ms: has.then(|| ms(self.rtt.srtt_us)),
            min_rtt_ms: has.then(|| ms(f64::from(self.rtt.min_us))),
            jitter_ms: (self.rtt.count > 1).then(|| ms(self.rtt.jitter_us)),
            rtt_samples: self.rtt.count,
            retrans_out_pct: pct(self.retrans_out, self.data_out),
            retrans_in_pct: pct(self.retrans_in, self.data_in),
        })
    }
}

/// Session quality in each sample.
#[derive(Debug, Clone, Default, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct QualityTick {
    /// Mean RTT of the samples in the last 10 s.
    pub rtt_ms: Option<f64>,
    /// Mean RTT of this tick's samples (for the chart).
    pub rtt_tick_ms: Option<f64>,
    /// Lowest RTT this session.
    pub min_rtt_ms: Option<f64>,
    /// Smoothed RTT and jitter over all samples in order. Meaningful when
    /// they come from one endpoint (host mode, or one dominant peer).
    pub srtt_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    /// RTT samples in the last 10 s.
    pub recent_samples: u32,
    /// Retransmitted share of TCP payload in the last 10 s, sent / received.
    pub retrans_out_pct: Option<f64>,
    pub retrans_in_pct: Option<f64>,
    /// Session totals (TCP payload bytes).
    pub data_out: u64,
    pub data_in: u64,
    pub retrans_out: u64,
    pub retrans_in: u64,
    pub rtt_samples: u64,
}

/// The session-wide figures, owned by the aggregator.
#[derive(Default)]
pub struct SessionQuality {
    rtt: RttStats,
    recent_rtt: VecDeque<(u64, u32)>,
    /// (t_ms, data_out, retrans_out, data_in, retrans_in) per tick.
    recent_bytes: VecDeque<(u64, u64, u64, u64, u64)>,
    totals: QualityDelta,
}

impl SessionQuality {
    pub fn tick(&mut self, d: &QualityDelta, t_ms: u64) -> QualityTick {
        for &s in &d.rtt_us {
            self.rtt.add(s);
            if self.recent_rtt.len() >= 4096 {
                self.recent_rtt.pop_front();
            }
            self.recent_rtt.push_back((t_ms, s));
        }
        self.recent_bytes
            .push_back((t_ms, d.data_out, d.retrans_out, d.data_in, d.retrans_in));
        let cutoff = t_ms.saturating_sub(RECENT_MS);
        while self.recent_rtt.front().is_some_and(|(t, _)| *t <= cutoff) {
            self.recent_rtt.pop_front();
        }
        while self
            .recent_bytes
            .front()
            .is_some_and(|(t, ..)| *t <= cutoff)
        {
            self.recent_bytes.pop_front();
        }
        self.totals.data_out += d.data_out;
        self.totals.data_in += d.data_in;
        self.totals.retrans_out += d.retrans_out;
        self.totals.retrans_in += d.retrans_in;

        let mean = |it: &mut dyn Iterator<Item = u32>| {
            let (sum, n) = it.fold((0u64, 0u32), |(s, n), x| (s + u64::from(x), n + 1));
            (n > 0).then(|| ms(sum as f64 / f64::from(n)))
        };
        let (dout, rout, din, rin) = self.recent_bytes.iter().fold((0, 0, 0, 0), |a, b| {
            (a.0 + b.1, a.1 + b.2, a.2 + b.3, a.3 + b.4)
        });
        let has = self.rtt.count > 0;
        QualityTick {
            rtt_ms: mean(&mut self.recent_rtt.iter().map(|(_, s)| *s)),
            rtt_tick_ms: mean(&mut d.rtt_us.iter().copied()),
            min_rtt_ms: has.then(|| ms(f64::from(self.rtt.min_us))),
            srtt_ms: has.then(|| ms(self.rtt.srtt_us)),
            jitter_ms: (self.rtt.count > 1).then(|| ms(self.rtt.jitter_us)),
            recent_samples: self.recent_rtt.len() as u32,
            retrans_out_pct: pct(rout, dout),
            retrans_in_pct: pct(rin, din),
            data_out: self.totals.data_out,
            data_in: self.totals.data_in,
            retrans_out: self.totals.retrans_out,
            retrans_in: self.totals.retrans_in,
            rtt_samples: self.rtt.count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::parse::Transport;
    use std::sync::Arc;

    const ME: [u8; 4] = [10, 0, 0, 2];
    const THEM: [u8; 4] = [93, 184, 216, 34];

    fn pkt(out: bool) -> PacketInfo {
        let (src, dst, sp, dp) = if out {
            (ME, THEM, 50000, 443)
        } else {
            (THEM, ME, 443, 50000)
        };
        PacketInfo {
            src: src.into(),
            dst: dst.into(),
            transport: Transport::Tcp,
            src_port: Some(sp),
            dst_port: Some(dp),
            ttl: 60,
        }
    }

    fn seg(seq: u32, ack: u32, flags: u8, len: u32) -> TcpInfo {
        TcpInfo {
            seq,
            ack,
            flags,
            payload_len: len,
        }
    }

    fn tracker() -> FlowTracker {
        FlowTracker::new(Arc::new([IpAddr::from(ME)].into()))
    }

    fn q(t: &Tally) -> QualityDelta {
        t.endpoints
            .get(&IpAddr::from(THEM))
            .map(|e| e.quality.clone())
            .unwrap_or_default()
    }

    #[test]
    fn connection_attempts_on_this_machine_are_noted() {
        use crate::monitor::stats::InboundHit;
        let mut f = tracker();
        let mut t = Tally::default();
        let them = IpAddr::from(THEM);
        // They ask for local port 3389 twice (a retry), and we accept once.
        let request = PacketInfo {
            src_port: Some(61000),
            dst_port: Some(3389),
            ..pkt(false)
        };
        let reply = PacketInfo {
            src_port: Some(3389),
            dst_port: Some(61000),
            ..pkt(true)
        };
        f.observe(1, &request, &seg(100, 0, TCP_SYN, 0), Some(true), &mut t);
        f.observe(2, &request, &seg(100, 0, TCP_SYN, 0), Some(true), &mut t);
        f.observe(
            3,
            &reply,
            &seg(900, 101, TCP_SYN | TCP_ACK, 0),
            Some(true),
            &mut t,
        );
        // Port 8080 is asked for and never answered; counted whatever the
        // session's scope makes of the packet.
        let closed = PacketInfo {
            dst_port: Some(8080),
            ..request
        };
        f.observe(4, &closed, &seg(5, 0, TCP_SYN, 0), Some(false), &mut t);
        // A connection we open is not an attempt on us, nor is its answer.
        f.observe(5, &pkt(true), &seg(1, 0, TCP_SYN, 0), Some(true), &mut t);
        f.observe(
            6,
            &pkt(false),
            &seg(7, 2, TCP_SYN | TCP_ACK, 0),
            Some(true),
            &mut t,
        );
        // Ordinary data says nothing.
        f.observe(7, &request, &seg(101, 901, TCP_ACK, 10), Some(true), &mut t);

        assert_eq!(t.inbound.len(), 2);
        assert_eq!(
            t.inbound[&(them, 3389)],
            InboundHit {
                syns: 2,
                answered: 1
            }
        );
        assert_eq!(
            t.inbound[&(them, 8080)],
            InboundHit {
                syns: 1,
                answered: 0
            }
        );

        // Batches add up, and a scan cannot grow one without bound.
        let mut total = Tally::default();
        total.merge(&t);
        total.merge(&t);
        assert_eq!(
            total.inbound[&(them, 3389)],
            InboundHit {
                syns: 4,
                answered: 2
            }
        );
        for port in 0..=u16::MAX {
            total.note_syn(Direction::In, false, them, port);
        }
        assert_eq!(total.inbound.len(), crate::monitor::stats::MAX_INBOUND);
    }

    #[test]
    fn only_data_counts_as_using_an_unencrypted_service() {
        let mut f = tracker();
        let mut t = Tally::default();
        let them = IpAddr::from(THEM);
        let telnet = |out: bool| {
            let p = pkt(out);
            if out {
                PacketInfo {
                    dst_port: Some(23),
                    ..p
                }
            } else {
                PacketInfo {
                    src_port: Some(23),
                    ..p
                }
            }
        };
        // A connection to their Telnet port that is refused: no data, no use.
        f.observe(1, &telnet(true), &seg(1, 0, TCP_SYN, 0), Some(true), &mut t);
        f.observe(
            2,
            &telnet(false),
            &seg(0, 2, TCP_RST | TCP_ACK, 0),
            Some(true),
            &mut t,
        );
        assert!(t.payload.is_empty());
        // One that is accepted and carries data both ways.
        f.observe(
            3,
            &telnet(true),
            &seg(10, 0, TCP_SYN, 0),
            Some(true),
            &mut t,
        );
        f.observe(
            4,
            &telnet(false),
            &seg(50, 11, TCP_SYN | TCP_ACK, 0),
            Some(true),
            &mut t,
        );
        f.observe(
            5,
            &telnet(true),
            &seg(11, 51, TCP_ACK, 40),
            Some(true),
            &mut t,
        );
        f.observe(
            6,
            &telnet(false),
            &seg(51, 51, TCP_ACK, 200),
            Some(true),
            &mut t,
        );
        assert_eq!(t.payload[&(them, 23)], 240);
        // HTTPS is not an audited port.
        f.observe(7, &pkt(true), &seg(1, 0, TCP_ACK, 500), Some(true), &mut t);
        assert_eq!(t.payload.len(), 1);
        // Batches add up.
        let mut total = Tally::default();
        total.merge(&t);
        total.merge(&t);
        assert_eq!(total.payload[&(them, 23)], 480);
    }

    #[test]
    fn handshake_and_data_rtt() {
        let mut tr = tracker();
        let mut t = Tally::default();
        let c = Some(true);
        tr.observe(1_000, &pkt(true), &seg(100, 0, TCP_SYN, 0), c, &mut t);
        tr.observe(
            21_000,
            &pkt(false),
            &seg(900, 101, TCP_SYN | TCP_ACK, 0),
            c,
            &mut t,
        );
        tr.observe(21_100, &pkt(true), &seg(101, 901, TCP_ACK, 0), c, &mut t);
        // Two data segments, one ACK covering both: the newest gives the sample.
        tr.observe(30_000, &pkt(true), &seg(101, 901, TCP_ACK, 500), c, &mut t);
        tr.observe(31_000, &pkt(true), &seg(601, 901, TCP_ACK, 500), c, &mut t);
        tr.observe(56_000, &pkt(false), &seg(901, 1101, TCP_ACK, 0), c, &mut t);
        let d = q(&t);
        assert_eq!(d.rtt_us, vec![20_000, 25_000]);
        assert_eq!((d.data_out, d.retrans_out), (1000, 0));
        assert_eq!(t.quality.rtt_us, d.rtt_us, "session gets the same samples");
    }

    #[test]
    fn inbound_handshake_rtt() {
        let mut tr = tracker();
        let mut t = Tally::default();
        let c = Some(true);
        tr.observe(0, &pkt(false), &seg(900, 0, TCP_SYN, 0), c, &mut t);
        tr.observe(
            100,
            &pkt(true),
            &seg(100, 901, TCP_SYN | TCP_ACK, 0),
            c,
            &mut t,
        );
        tr.observe(30_100, &pkt(false), &seg(901, 101, TCP_ACK, 0), c, &mut t);
        assert_eq!(q(&t).rtt_us, vec![30_000]);
    }

    #[test]
    fn retransmissions_and_karn() {
        let mut tr = tracker();
        let mut t = Tally::default();
        let c = Some(true);
        tr.observe(0, &pkt(true), &seg(1000, 1, TCP_ACK, 1000), c, &mut t);
        tr.observe(1, &pkt(true), &seg(2000, 1, TCP_ACK, 1000), c, &mut t);
        // First segment lost: resent; its ACK must not give a sample.
        tr.observe(300_000, &pkt(true), &seg(1000, 1, TCP_ACK, 1000), c, &mut t);
        tr.observe(320_000, &pkt(false), &seg(1, 2000, TCP_ACK, 0), c, &mut t);
        // Keep-alive: 1 byte just below the edge, not a retransmission.
        tr.observe(400_000, &pkt(true), &seg(2999, 1, TCP_ACK, 1), c, &mut t);
        // Incoming: duplicate data.
        tr.observe(
            500_000,
            &pkt(false),
            &seg(1, 3000, TCP_ACK, 1400),
            c,
            &mut t,
        );
        tr.observe(
            500_100,
            &pkt(false),
            &seg(1, 3000, TCP_ACK, 1400),
            c,
            &mut t,
        );
        let d = q(&t);
        assert_eq!(d.rtt_us, Vec::<u32>::new());
        assert_eq!((d.data_out, d.retrans_out), (3001, 1000));
        assert_eq!((d.data_in, d.retrans_in), (2800, 1400));
    }

    #[test]
    fn sequence_wraps_around() {
        let mut tr = tracker();
        let mut t = Tally::default();
        let c = Some(true);
        let seq = u32::MAX - 99;
        tr.observe(0, &pkt(true), &seg(seq, 1, TCP_ACK, 200), c, &mut t);
        tr.observe(
            5_000,
            &pkt(false),
            &seg(1, seq.wrapping_add(200), TCP_ACK, 0),
            c,
            &mut t,
        );
        tr.observe(
            6_000,
            &pkt(true),
            &seg(seq.wrapping_add(200), 1, TCP_ACK, 100),
            c,
            &mut t,
        );
        let d = q(&t);
        assert_eq!(d.rtt_us, vec![5_000]);
        assert_eq!(d.retrans_out, 0);
    }

    #[test]
    fn measurements_wait_for_attribution() {
        let mut tr = tracker();
        let mut t = Tally::default();
        tr.observe(0, &pkt(true), &seg(100, 0, TCP_SYN, 0), None, &mut t);
        tr.observe(
            20_000,
            &pkt(false),
            &seg(9, 101, TCP_SYN | TCP_ACK, 0),
            None,
            &mut t,
        );
        assert!(t.quality.is_empty(), "held until the owner is known");
        tr.resolve(&pkt(true), true, &mut t);
        assert_eq!(t.quality.rtt_us, vec![20_000]);

        // Another program's flow: dropped.
        let mut other = pkt(true);
        other.src_port = Some(50001);
        let mut t = Tally::default();
        tr.observe(0, &other, &seg(100, 0, TCP_SYN, 0), None, &mut t);
        let mut other_in = pkt(false);
        other_in.dst_port = Some(50001);
        tr.observe(
            9_000,
            &other_in,
            &seg(9, 101, TCP_SYN | TCP_ACK, 0),
            Some(false),
            &mut t,
        );
        assert!(t.quality.is_empty());
    }

    #[test]
    fn session_and_endpoint_figures() {
        let mut s = SessionQuality::default();
        let d = QualityDelta {
            rtt_us: vec![20_000, 30_000],
            data_out: 1000,
            retrans_out: 10,
            data_in: 4000,
            retrans_in: 0,
        };
        let q1 = s.tick(&d, 250);
        assert_eq!(q1.rtt_ms, Some(25.0));
        assert_eq!(q1.min_rtt_ms, Some(20.0));
        assert_eq!(q1.retrans_out_pct, Some(1.0));
        assert_eq!(q1.retrans_in_pct, Some(0.0));
        assert_eq!(q1.jitter_ms, Some(10.0 / 16.0));
        // 10 s later the window has moved on; totals remain.
        let q2 = s.tick(&QualityDelta::default(), 10_500);
        assert_eq!((q2.rtt_ms, q2.retrans_out_pct), (None, None));
        assert_eq!((q2.data_out, q2.retrans_out, q2.rtt_samples), (1000, 10, 2));

        let mut e = EndpointQualityAcc::default();
        e.add(&d);
        let r = e.row().unwrap();
        assert_eq!(r.srtt_ms, Some(20.0 + 10.0 / 8.0));
        assert_eq!(r.retrans_out_pct, Some(1.0));
        assert!(EndpointQualityAcc::default().row().is_none());
    }
}

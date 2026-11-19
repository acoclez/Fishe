//! Per-remote-address statistics for process mode ("who is it talking to?").
//!
//! The aggregator feeds each tick's per-endpoint counts into an
//! [`EndpointBook`]: cumulative totals, the busiest service ports, a
//! [`BusyDetector`] per endpoint, and first/last-seen times. Each sample
//! carries a bounded selection of [`EndpointRow`]s.

use super::gauge::{BusyDetector, GaugeConfig, Level};
use super::programs::Label;
use super::quality::{EndpointQuality, EndpointQualityAcc};
use super::stats::{Counters, EndpointDelta, MAX_PORTS_PER_ENDPOINT, MAX_PROGRAMS_PER_ENDPOINT};
use crate::geo::{Geo, Owner};
use crate::naming::addr::{self, AddrScope};
use crate::naming::book::{NameBook, NameSource};
use crate::net::parse::{Transport, hops_from_ttl};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// Endpoints remembered per session; least recently seen are evicted beyond it.
pub const MAX_ENDPOINTS: usize = 4096;
/// Rows sent per sample: the busiest now plus the biggest overall.
pub const ROWS_BY_RATE: usize = 100;
pub const ROWS_BY_TOTAL: usize = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct EndpointPort {
    pub transport: Transport,
    pub port: u16,
    pub bytes: u64,
}

/// A program talking to an endpoint (all-traffic mode).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct EndpointProgram {
    /// Program key (see [`Label::key`]); `""` = unattributed.
    pub key: String,
    pub name: String,
    pub bytes: u64,
}

/// One endpoint as sent to the UI.
#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct EndpointRow {
    pub ip: IpAddr,
    pub name: Option<String>,
    pub name_source: Option<NameSource>,
    pub scope: AddrScope,
    /// Network owner and country (public addresses).
    pub owner: Option<Owner>,
    /// Routers between here and the endpoint, estimated from received TTLs.
    pub hops: Option<u8>,
    pub in_bps: f64,
    pub out_bps: f64,
    pub smoothed_bps: f64,
    pub baseline_bps: f64,
    pub ratio: f64,
    pub level: Level,
    pub peak_bps: f64,
    pub totals: Counters,
    pub top_ports: Vec<EndpointPort>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    /// Programs exchanging traffic with it, biggest first (all-traffic mode;
    /// empty otherwise).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub programs: Vec<EndpointProgram>,
    /// TCP connection quality (RTT, retransmissions); `None` without TCP data.
    pub quality: Option<EndpointQuality>,
}

#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct EndpointsTick {
    /// Endpoints known this session (rows hold a subset).
    pub total: usize,
    pub rows: Vec<EndpointRow>,
}

struct Endpoint {
    first_seen_ms: u64,
    last_seen_ms: u64,
    totals: Counters,
    ports: HashMap<(Transport, u16), u64>,
    detector: BusyDetector,
    in_bps: f64,
    out_bps: f64,
    smoothed_bps: f64,
    baseline_bps: f64,
    ratio: f64,
    level: Level,
    peak_bps: f64,
    hops: Option<u8>,
    /// Program key → (display name, bytes).
    programs: HashMap<String, (String, u64)>,
    quality: EndpointQualityAcc,
    /// Owner lookup and when it was made (ms); refreshed now and then, as
    /// an online answer or a database download can arrive later.
    owner: Option<(Option<Owner>, u64)>,
}

/// How long an owner lookup is reused: missing owners are retried sooner.
const OWNER_TTL_MS: u64 = 60_000;
const OWNER_RETRY_MS: u64 = 3_000;

pub struct EndpointBook {
    gauge: GaugeConfig,
    map: HashMap<IpAddr, Endpoint>,
}

impl EndpointBook {
    pub fn new(gauge: GaugeConfig) -> Self {
        EndpointBook {
            gauge,
            map: HashMap::new(),
        }
    }

    /// How many endpoints are known.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Advance one tick of `secs` with this tick's per-endpoint counts.
    pub fn tick(&mut self, window: &HashMap<IpAddr, EndpointDelta>, secs: f64, t_ms: u64) {
        for (ip, d) in window {
            let e = self.map.entry(*ip).or_insert_with(|| Endpoint {
                first_seen_ms: t_ms,
                last_seen_ms: t_ms,
                totals: Counters::default(),
                ports: HashMap::new(),
                detector: BusyDetector::new(self.gauge),
                in_bps: 0.0,
                out_bps: 0.0,
                smoothed_bps: 0.0,
                baseline_bps: 0.0,
                ratio: 0.0,
                level: Level::Idle,
                peak_bps: 0.0,
                hops: None,
                programs: HashMap::new(),
                quality: EndpointQualityAcc::default(),
                owner: None,
            });
            e.last_seen_ms = t_ms;
            e.totals.merge(&d.counters);
            if let Some(ttl) = d.last_ttl {
                e.hops = Some(hops_from_ttl(ttl));
            }
            if !d.quality.is_empty() {
                e.quality.add(&d.quality);
            }
            for (&k, &b) in &d.ports {
                if e.ports.len() < MAX_PORTS_PER_ENDPOINT || e.ports.contains_key(&k) {
                    *e.ports.entry(k).or_default() += b;
                }
            }
        }

        for (ip, e) in &mut self.map {
            let (bin, bout) = window
                .get(ip)
                .map_or((0, 0), |d| (d.counters.bytes_in, d.counters.bytes_out));
            e.in_bps = bin as f64 / secs;
            e.out_bps = bout as f64 / secs;
            let r = e.detector.update(e.in_bps + e.out_bps, secs);
            e.smoothed_bps = r.smoothed_bps;
            e.baseline_bps = r.baseline_bps;
            e.ratio = r.ratio;
            e.level = r.level;
            e.peak_bps = e.peak_bps.max(e.in_bps + e.out_bps);
        }

        if self.map.len() > MAX_ENDPOINTS {
            let mut by_age: Vec<(u64, IpAddr)> = self
                .map
                .iter()
                .map(|(ip, e)| (e.last_seen_ms, *ip))
                .collect();
            by_age.sort_unstable();
            let excess = self.map.len() - MAX_ENDPOINTS * 7 / 8;
            for (_, ip) in by_age.into_iter().take(excess) {
                self.map.remove(&ip);
            }
        }
    }

    /// Credit this tick's bytes to programs (all-traffic mode; after [`tick`](Self::tick)).
    pub fn note_programs(
        &mut self,
        window: &HashMap<IpAddr, EndpointDelta>,
        labels: &HashMap<u32, Label>,
    ) {
        for (ip, d) in window {
            let Some(e) = self.map.get_mut(ip) else {
                continue;
            };
            for (pid, &bytes) in &d.programs {
                let Some(label) = labels.get(pid) else {
                    continue;
                };
                if e.programs.len() < MAX_PROGRAMS_PER_ENDPOINT
                    || e.programs.contains_key(&label.key)
                {
                    e.programs
                        .entry(label.key.clone())
                        .or_insert_with(|| (label.name.clone(), 0))
                        .1 += bytes;
                }
            }
        }
    }

    /// The busiest endpoints right now plus the largest overall.
    ///
    /// Top-k partitioning (linear) instead of sorting every endpoint twice a
    /// tick; only the selected few are sorted.
    pub fn select(&self) -> Vec<IpAddr> {
        let by_rate = |a: &(&IpAddr, &Endpoint), b: &(&IpAddr, &Endpoint)| {
            b.1.smoothed_bps
                .total_cmp(&a.1.smoothed_bps)
                .then(b.1.last_seen_ms.cmp(&a.1.last_seen_ms))
                .then(a.0.cmp(b.0))
        };
        let mut all: Vec<(&IpAddr, &Endpoint)> = self.map.iter().collect();
        top_k(&mut all, ROWS_BY_RATE, by_rate);
        let mut chosen: Vec<IpAddr> = all.iter().take(ROWS_BY_RATE).map(|(ip, _)| **ip).collect();
        let mut seen: HashSet<IpAddr> = chosen.iter().copied().collect();

        let by_total = |a: &(&IpAddr, &Endpoint), b: &(&IpAddr, &Endpoint)| {
            (b.1.totals.bytes_in + b.1.totals.bytes_out)
                .cmp(&(a.1.totals.bytes_in + a.1.totals.bytes_out))
                .then(a.0.cmp(b.0))
        };
        let mut rest: Vec<(&IpAddr, &Endpoint)> = all
            .into_iter()
            .filter(|(ip, _)| !seen.contains(*ip))
            .collect();
        top_k(&mut rest, ROWS_BY_TOTAL, by_total);
        for (ip, _) in rest.into_iter().take(ROWS_BY_TOTAL) {
            if seen.insert(*ip) {
                chosen.push(*ip);
            }
        }
        chosen
    }

    /// Rows for `ips`. `now_ms` dates owner lookups, which are cached.
    pub fn rows(
        &mut self,
        ips: &[IpAddr],
        names: &NameBook,
        geo: Option<&Geo>,
        now_ms: u64,
    ) -> Vec<EndpointRow> {
        if let Some(geo) = geo {
            for ip in ips {
                if let Some(e) = self.map.get_mut(ip) {
                    let stale = match &e.owner {
                        None => true,
                        Some((Some(_), at)) => now_ms.saturating_sub(*at) >= OWNER_TTL_MS,
                        Some((None, at)) => now_ms.saturating_sub(*at) >= OWNER_RETRY_MS,
                    };
                    if stale {
                        e.owner = Some((geo.owner(*ip), now_ms));
                    }
                }
            }
        }
        ips.iter()
            .filter_map(|ip| self.map.get(ip).map(|e| (ip, e)))
            .map(|(ip, e)| {
                let scope = addr::classify(*ip);
                let (name, name_source) = match names.best(*ip) {
                    Some((n, s)) => (Some(n), Some(s)),
                    None if scope == AddrScope::Loopback => (Some("localhost".into()), None),
                    None => (None, None),
                };
                let mut ports: Vec<EndpointPort> = e
                    .ports
                    .iter()
                    .map(|(&(transport, port), &bytes)| EndpointPort {
                        transport,
                        port,
                        bytes,
                    })
                    .collect();
                ports.sort_unstable_by(|a, b| b.bytes.cmp(&a.bytes).then(a.port.cmp(&b.port)));
                ports.truncate(4);
                let mut programs: Vec<EndpointProgram> = e
                    .programs
                    .iter()
                    .map(|(key, (name, bytes))| EndpointProgram {
                        key: key.clone(),
                        name: name.clone(),
                        bytes: *bytes,
                    })
                    .collect();
                programs.sort_unstable_by(|a, b| b.bytes.cmp(&a.bytes).then(a.key.cmp(&b.key)));
                programs.truncate(3);
                EndpointRow {
                    ip: *ip,
                    name,
                    name_source,
                    scope,
                    owner: geo.and(e.owner.as_ref()).and_then(|(o, _)| o.clone()),
                    hops: e.hops,
                    in_bps: e.in_bps,
                    out_bps: e.out_bps,
                    smoothed_bps: e.smoothed_bps,
                    baseline_bps: e.baseline_bps,
                    ratio: e.ratio,
                    level: e.level,
                    peak_bps: e.peak_bps,
                    totals: e.totals,
                    top_ports: ports,
                    first_seen_ms: e.first_seen_ms,
                    last_seen_ms: e.last_seen_ms,
                    programs,
                    quality: e.quality.row(),
                }
            })
            .collect()
    }
}

/// Move the `k` smallest elements (by `cmp`) to the front, sorted.
fn top_k<T>(v: &mut [T], k: usize, cmp: impl Fn(&T, &T) -> std::cmp::Ordering) {
    if v.len() > k && k > 0 {
        v.select_nth_unstable_by(k - 1, &cmp);
    }
    let n = v.len().min(k);
    v[..n].sort_unstable_by(&cmp);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::stats::{Direction, Tally};
    use crate::net::parse::PacketInfo;

    const ME: [u8; 4] = [10, 0, 0, 2];

    fn tally(remote: [u8; 4], bytes_in: u32, port: u16) -> Tally {
        let mut t = Tally::default();
        let p = PacketInfo {
            src: remote.into(),
            dst: ME.into(),
            transport: Transport::Tcp,
            src_port: Some(port),
            dst_port: Some(50000),
            ttl: 64,
        };
        t.record(Direction::In, &p, bytes_in);
        t
    }

    #[test]
    fn tracks_totals_rates_ports_and_names() {
        let mut book = EndpointBook::new(GaugeConfig::default());
        let names = NameBook::new();
        names.set_dns([1, 1, 1, 1].into(), "one.one.one.one".into());
        let mut w = tally([1, 1, 1, 1], 1000, 443);
        w.merge(&tally([8, 8, 8, 8], 500, 53));
        book.tick(&w.endpoints, 0.25, 250);
        book.tick(&tally([1, 1, 1, 1], 1000, 443).endpoints, 0.25, 500);

        let ips = book.select();
        let rows = book.rows(&ips, &names, None, 0);
        assert_eq!(rows.len(), 2);
        let one = rows
            .iter()
            .find(|r| r.ip == IpAddr::from([1, 1, 1, 1]))
            .unwrap();
        assert_eq!(one.totals.bytes_in, 2000);
        assert_eq!(one.in_bps, 4000.0);
        assert_eq!((one.first_seen_ms, one.last_seen_ms), (250, 500));
        assert_eq!(one.name.as_deref(), Some("one.one.one.one"));
        assert_eq!(one.name_source, Some(NameSource::Dns));
        assert_eq!(one.top_ports[0].port, 443);
        assert_eq!(one.scope, AddrScope::Public);
        let dns = rows
            .iter()
            .find(|r| r.ip == IpAddr::from([8, 8, 8, 8]))
            .unwrap();
        assert_eq!(dns.in_bps, 0.0, "idle this tick");
        assert_eq!(dns.last_seen_ms, 250);
        assert_eq!(rows[0].ip, IpAddr::from([1, 1, 1, 1]), "busiest first");
    }

    #[test]
    fn evicts_least_recently_seen() {
        let mut book = EndpointBook::new(GaugeConfig::default());
        for i in 0..(MAX_ENDPOINTS as u32 + 10) {
            let ip = i.to_be_bytes();
            book.tick(
                &tally([11, ip[1], ip[2], ip[3]], 100, 443).endpoints,
                0.25,
                u64::from(i),
            );
        }
        assert!(book.len() <= MAX_ENDPOINTS);
        assert!(
            book.map.contains_key(&IpAddr::from([11, 0, 16, 9])),
            "newest kept"
        );
        assert!(
            !book.map.contains_key(&IpAddr::from([11, 0, 0, 0])),
            "oldest evicted"
        );
    }
}

//! Traceroute from ICMP probes, with TTLs probed in parallel.
//!
//! Classic traceroute probes TTL 1, 2, 3… one after another (30+ s when
//! hops are silent). Here a small pool of threads takes TTLs from a shared
//! counter, so a typical route resolves in one or two timeouts. Once a TTL
//! reaches the destination, larger TTLs are no longer started.

use super::icmp::{self, ProbeKind, ProbeReply};
use super::{Hop, HopStatus, TraceResult};
use crate::geo::Geo;
use crate::naming::{addr, rdns};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
pub struct TraceOptions {
    pub max_hops: u8,
    pub probes_per_hop: u8,
    pub timeout_ms: u32,
    pub parallel: usize,
}

impl Default for TraceOptions {
    fn default() -> Self {
        TraceOptions {
            max_hops: 30,
            probes_per_hop: 2,
            timeout_ms: 1000,
            parallel: 10,
        }
    }
}

/// Reverse-DNS lookups of a trace's hops run on this many threads at once.
const PTR_WORKERS: usize = 6;

/// Probe every TTL and assemble hops (no names/owners yet).
pub fn run(target: IpAddr, opts: TraceOptions) -> TraceResult {
    let started = Instant::now();
    let started_at = crate::util::now_ms() as i64;
    let next_ttl = Arc::new(AtomicU8::new(1));
    // Smallest TTL known to reach the target (u8::MAX = not yet).
    let reached_at = Arc::new(AtomicU8::new(u8::MAX));
    let replies: Arc<Mutex<HashMap<u8, Vec<ProbeReply>>>> = Arc::default();

    std::thread::scope(|s| {
        for _ in 0..opts.parallel.max(1) {
            let (next_ttl, reached_at, replies) =
                (next_ttl.clone(), reached_at.clone(), replies.clone());
            s.spawn(move || {
                loop {
                    let ttl = next_ttl.fetch_add(1, Ordering::Relaxed);
                    if ttl == 0 || ttl > opts.max_hops || ttl > reached_at.load(Ordering::Relaxed) {
                        return;
                    }
                    let mut got = Vec::with_capacity(opts.probes_per_hop as usize);
                    for _ in 0..opts.probes_per_hop {
                        let r = icmp::probe(target, ttl, opts.timeout_ms).unwrap_or(ProbeReply {
                            kind: ProbeKind::Timeout,
                            from: None,
                            rtt_ms: None,
                        });
                        if r.kind == ProbeKind::Reached {
                            reached_at.fetch_min(ttl, Ordering::Relaxed);
                        }
                        got.push(r);
                    }
                    replies
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(ttl, got);
                }
            });
        }
    });

    let replies = std::mem::take(&mut *replies.lock().unwrap_or_else(|e| e.into_inner()));
    let reached = reached_at.load(Ordering::Relaxed);
    let last = if reached != u8::MAX {
        reached
    } else {
        opts.max_hops
    };
    let mut hops: Vec<Hop> = (1..=last)
        .map(|ttl| assemble(ttl, replies.get(&ttl).map(Vec::as_slice).unwrap_or(&[])))
        .collect();

    if reached == u8::MAX {
        // Not reached: drop the run of silent hops at the end, keep one as "…".
        while hops.len() > 1
            && hops[hops.len() - 1].status == HopStatus::Silent
            && hops[hops.len() - 2].status == HopStatus::Silent
        {
            hops.pop();
        }
        if let Some(i) = hops.iter().position(|h| h.status == HopStatus::Unreachable) {
            hops.truncate(i + 1);
        }
    }

    TraceResult {
        target,
        started_at,
        duration_ms: started.elapsed().as_millis() as u64,
        reached: reached != u8::MAX,
        hops,
    }
}

/// Merge one TTL's probe replies into a hop.
pub fn assemble(ttl: u8, replies: &[ProbeReply]) -> Hop {
    let answered: Vec<&ProbeReply> = replies
        .iter()
        .filter(|r| r.kind != ProbeKind::Timeout)
        .collect();
    let mut addrs: Vec<IpAddr> = Vec::new();
    for r in &answered {
        if let Some(a) = r.from
            && !addrs.contains(&a)
        {
            addrs.push(a);
        }
    }
    let status = if answered.iter().any(|r| r.kind == ProbeKind::Reached) {
        HopStatus::Destination
    } else if answered.iter().any(|r| r.kind == ProbeKind::TtlExpired) {
        HopStatus::Router
    } else if !answered.is_empty() {
        HopStatus::Unreachable
    } else {
        HopStatus::Silent
    };
    let addr = addrs.first().copied();
    Hop {
        ttl,
        addr,
        alternates: addrs.into_iter().skip(1).collect(),
        rtt_ms: answered.iter().filter_map(|r| r.rtt_ms).min(),
        sent: replies.len() as u8,
        received: answered.len() as u8,
        status,
        name: None,
        owner: None,
        scope: addr.map(addr::classify),
    }
}

/// Add reverse-DNS names and owners to hops (names: at most `deadline`).
pub fn enrich(result: &mut TraceResult, geo: Option<&Geo>, deadline: Duration) {
    let (tx, rx) = mpsc::channel::<(usize, Option<String>)>();
    let mut jobs = Vec::new();
    for (i, h) in result.hops.iter_mut().enumerate() {
        let Some(a) = h.addr else { continue };
        h.owner = geo.and_then(|g| g.owner(a));
        jobs.push((i, a));
    }
    let mut pending = jobs.len();
    // Detached, on a small pool: a slow resolver can't hold up the trace
    // beyond `deadline`, and a 30-hop route doesn't open 30 threads.
    let _ = std::thread::Builder::new()
        .name("fishe-hop-ptr".into())
        .spawn(move || {
            crate::util::par_for_each(&jobs, PTR_WORKERS, |&(i, a)| {
                let _ = tx.send((i, rdns::lookup(a)));
            });
        });
    let until = Instant::now() + deadline;
    while pending > 0 {
        match rx.recv_timeout(until.saturating_duration_since(Instant::now())) {
            Ok((i, name)) => {
                result.hops[i].name = name;
                pending -= 1;
            }
            Err(_) => break,
        }
    }
}

// ───────────────────────────── cache & limits ─────────────────────────────

/// Tauri-managed: recent traces and a cap on concurrent ones.
pub struct TraceBook {
    cache: Mutex<HashMap<IpAddr, TraceResult>>,
    running: Mutex<usize>,
    freed: Condvar,
}

/// Traces running at once (each uses `parallel` probe threads).
const MAX_CONCURRENT: usize = 3;
/// A cached trace is reused for this long unless forced.
pub const CACHE_MS: i64 = 10 * 60 * 1000;

impl Default for TraceBook {
    fn default() -> Self {
        TraceBook {
            cache: Mutex::default(),
            running: Mutex::new(0),
            freed: Condvar::new(),
        }
    }
}

impl TraceBook {
    pub fn cached(&self) -> Vec<TraceResult> {
        let mut v: Vec<TraceResult> = self
            .cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect();
        v.sort_by_key(|t| t.started_at);
        v
    }

    /// Trace `target` (or return a fresh cached result).
    pub fn trace(&self, target: IpAddr, force: bool, geo: Option<&Geo>) -> TraceResult {
        if !force
            && let Some(t) = self
                .cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&target)
            && crate::util::now_ms() as i64 - t.started_at < CACHE_MS
        {
            return t.clone();
        }
        {
            let mut n = self.running.lock().unwrap_or_else(|e| e.into_inner());
            while *n >= MAX_CONCURRENT {
                n = self.freed.wait(n).unwrap_or_else(|e| e.into_inner());
            }
            *n += 1;
        }
        let mut result = run(target, TraceOptions::default());
        enrich(&mut result, geo, Duration::from_millis(2500));
        {
            let mut n = self.running.lock().unwrap_or_else(|e| e.into_inner());
            *n -= 1;
            self.freed.notify_one();
        }
        self.cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(target, result.clone());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(kind: ProbeKind, from: &str, rtt: u32) -> ProbeReply {
        ProbeReply {
            kind,
            from: Some(from.parse().unwrap()),
            rtt_ms: Some(rtt),
        }
    }
    const T: ProbeReply = ProbeReply {
        kind: ProbeKind::Timeout,
        from: None,
        rtt_ms: None,
    };

    #[test]
    fn assembles_hops() {
        let h = assemble(
            3,
            &[
                r(ProbeKind::TtlExpired, "10.0.0.1", 9),
                r(ProbeKind::TtlExpired, "10.0.0.2", 7),
            ],
        );
        assert_eq!(h.status, HopStatus::Router);
        assert_eq!(h.addr, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(h.alternates, vec!["10.0.0.2".parse::<IpAddr>().unwrap()]);
        assert_eq!(h.rtt_ms, Some(7));
        assert_eq!((h.sent, h.received), (2, 2));

        let h = assemble(4, &[T, r(ProbeKind::Reached, "1.1.1.1", 12)]);
        assert_eq!(h.status, HopStatus::Destination);
        assert_eq!(h.received, 1);

        let h = assemble(5, &[T, T]);
        assert_eq!(
            (h.status, h.addr, h.rtt_ms),
            (HopStatus::Silent, None, None)
        );
    }

    #[cfg(any(windows, target_os = "linux"))]
    #[cfg_attr(target_os = "linux", ignore = "needs CAP_NET_RAW")]
    #[test]
    fn traces_loopback_in_one_hop() {
        let t = run(
            "127.0.0.1".parse().unwrap(),
            TraceOptions {
                max_hops: 5,
                probes_per_hop: 1,
                timeout_ms: 500,
                parallel: 3,
            },
        );
        assert!(t.reached);
        assert_eq!(t.hops.len(), 1);
        assert_eq!(t.hops[0].status, HopStatus::Destination);
    }

    /// `cargo test -- --ignored live_trace --nocapture`
    #[test]
    #[ignore = "sends ICMP probes to 8.8.8.8 and an OVH IPv6 address"]
    fn live_trace_public() {
        // (1.1.1.1 is avoided: some home routers answer for it at hop 1.)
        for target in ["8.8.8.8", "2001:41d0:242:d300::"] {
            let mut t = run(target.parse().unwrap(), TraceOptions::default());
            enrich(&mut t, None, Duration::from_secs(3));
            println!("{target}: reached={} in {} ms", t.reached, t.duration_ms);
            for h in &t.hops {
                println!(
                    "  {:>2} {:<11} {:<40} {:<45} {:>4?} {}/{}",
                    h.ttl,
                    format!("{:?}", h.status),
                    h.addr.map(|a| a.to_string()).unwrap_or_default(),
                    h.name.clone().unwrap_or_default(),
                    h.rtt_ms,
                    h.received,
                    h.sent
                );
            }
            assert!(t.reached, "{target} answers ICMP echo");
            assert!(t.hops.len() >= 3, "{target} is several hops away");
            assert_eq!(t.hops.last().unwrap().addr, Some(target.parse().unwrap()));
            assert_eq!(
                t.hops[0].status,
                HopStatus::Router,
                "first hop is the gateway"
            );
        }
    }
}

//! Opt-in online owner lookup (ipinfo.io), for public addresses the offline
//! database doesn't cover (or when it isn't installed).
//!
//! Off by default. When on, the looked-up IP addresses are sent to
//! ipinfo.io over HTTPS. One worker thread, at most one request per second,
//! each address at most once per app run; HTTP 429 pauses lookups for a
//! minute.

use super::{Owner, OwnerSource};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
enum State {
    Pending,
    Done(Option<Owner>),
}

pub struct OnlineLookup {
    enabled: Arc<AtomicBool>,
    cache: Arc<RwLock<HashMap<IpAddr, State>>>,
    tx: Mutex<Option<Sender<IpAddr>>>,
}

const GAP: Duration = Duration::from_millis(1100);
const BACKOFF: Duration = Duration::from_secs(60);
const MAX_CACHE: usize = 20_000;

impl Default for OnlineLookup {
    fn default() -> Self {
        Self::new()
    }
}

impl OnlineLookup {
    pub fn new() -> Self {
        OnlineLookup {
            enabled: Arc::new(AtomicBool::new(false)),
            cache: Arc::new(RwLock::new(HashMap::new())),
            tx: Mutex::new(None),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
        if !on {
            // Forget queued (not yet sent) requests.
            self.cache
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .retain(|_, s| matches!(s, State::Done(_)));
            *self.tx.lock().unwrap_or_else(|e| e.into_inner()) = None;
        }
    }

    /// The cached result, if a lookup already finished.
    pub fn cached(&self, ip: IpAddr) -> Option<Owner> {
        match self
            .cache
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&ip)
        {
            Some(State::Done(o)) => o.clone(),
            _ => None,
        }
    }

    /// Cached result, or queue a lookup (when enabled) and return `None` for now.
    pub fn get_or_request(&self, ip: IpAddr) -> Option<Owner> {
        if let Some(state) = self
            .cache
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&ip)
        {
            return match state {
                State::Done(o) => o.clone(),
                State::Pending => None,
            };
        }
        if !self.enabled() {
            return None;
        }
        {
            let mut cache = self.cache.write().unwrap_or_else(|e| e.into_inner());
            if cache.len() >= MAX_CACHE {
                return None;
            }
            cache.insert(ip, State::Pending);
        }
        let mut tx = self.tx.lock().unwrap_or_else(|e| e.into_inner());
        if tx.is_none() {
            *tx = Some(self.spawn_worker());
        }
        let _ = tx.as_ref().map(|t| t.send(ip));
        None
    }

    fn spawn_worker(&self) -> Sender<IpAddr> {
        let (tx, rx) = mpsc::channel::<IpAddr>();
        let (cache, enabled) = (self.cache.clone(), self.enabled.clone());
        let _ = std::thread::Builder::new()
            .name("fishe-ipinfo".into())
            .spawn(move || {
                let agent = ureq::Agent::new_with_config(
                    ureq::Agent::config_builder()
                        .timeout_global(Some(Duration::from_secs(8)))
                        .http_status_as_error(false)
                        .user_agent(concat!("Fishe/", env!("CARGO_PKG_VERSION")))
                        .build(),
                );
                let mut next = Instant::now();
                while let Ok(ip) = rx.recv() {
                    if !enabled.load(Ordering::Relaxed) {
                        cache.write().unwrap_or_else(|e| e.into_inner()).remove(&ip);
                        continue;
                    }
                    std::thread::sleep(next.saturating_duration_since(Instant::now()));
                    let (result, wait) = fetch(&agent, ip);
                    next = Instant::now() + wait;
                    match result {
                        Some(owner) => {
                            cache
                                .write()
                                .unwrap_or_else(|e| e.into_inner())
                                .insert(ip, State::Done(owner));
                        }
                        // Transient failure: forget, so a later tick may retry.
                        None => {
                            cache.write().unwrap_or_else(|e| e.into_inner()).remove(&ip);
                        }
                    }
                }
            });
        tx
    }
}

#[derive(Deserialize)]
struct IpinfoJson {
    country: Option<String>,
    org: Option<String>,
    #[serde(default)]
    bogon: bool,
}

/// `Some(owner-or-none)` when the answer is final; `None` to retry later.
fn fetch(agent: &ureq::Agent, ip: IpAddr) -> (Option<Option<Owner>>, Duration) {
    let url = format!("https://ipinfo.io/{ip}/json");
    let mut res = match agent.get(&url).call() {
        Ok(r) => r,
        Err(e) => {
            log::warn!("ipinfo {ip}: {e}");
            return (None, GAP);
        }
    };
    match res.status().as_u16() {
        200 => {}
        429 => {
            log::warn!("ipinfo: rate limited, pausing");
            return (None, BACKOFF);
        }
        s => {
            log::warn!("ipinfo {ip}: HTTP {s}");
            return (Some(None), GAP);
        }
    }
    let body = res.body_mut().read_to_string().unwrap_or_default();
    (Some(parse(&body)), GAP)
}

/// Parse an ipinfo.io JSON answer (`org` is "AS13335 Cloudflare, Inc.").
pub fn parse(body: &str) -> Option<Owner> {
    let j: IpinfoJson = serde_json::from_str(body).ok()?;
    if j.bogon {
        return None;
    }
    let (asn, org) = match j.org.as_deref().map(str::trim) {
        Some(o) if o.starts_with("AS") => match o.split_once(' ') {
            Some((a, rest)) => (a[2..].parse().ok(), Some(rest.trim().to_string())),
            None => (o[2..].parse().ok(), None),
        },
        Some(o) if !o.is_empty() => (None, Some(o.to_string())),
        _ => (None, None),
    };
    let owner = Owner {
        asn,
        org,
        country: j.country.filter(|c| c.len() == 2),
        source: OwnerSource::Ipinfo,
    };
    (!owner.is_empty()).then_some(owner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipinfo() {
        let o = parse(r#"{"ip":"1.1.1.1","hostname":"one.one.one.one","country":"AU","org":"AS13335 Cloudflare, Inc."}"#).unwrap();
        assert_eq!(
            (o.asn, o.org.as_deref(), o.country.as_deref()),
            (Some(13335), Some("Cloudflare, Inc."), Some("AU"))
        );
        assert_eq!(o.source, OwnerSource::Ipinfo);
        assert!(parse(r#"{"ip":"10.0.0.1","bogon":true}"#).is_none());
        let o = parse(r#"{"ip":"x","org":"Some ISP"}"#).unwrap();
        assert_eq!((o.asn, o.org.as_deref()), (None, Some("Some ISP")));
        assert!(parse("not json").is_none());
    }

    #[test]
    fn disabled_never_queues() {
        let l = OnlineLookup::new();
        assert!(l.get_or_request("8.8.8.8".parse().unwrap()).is_none());
        assert!(l.cache.read().unwrap().is_empty());
        assert!(l.tx.lock().unwrap().is_none(), "no worker without consent");
    }
}

//! Shared IP → name knowledge for the session.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub enum NameSource {
    /// TLS server name of a connection to this address.
    Sni,
    /// A DNS (or mDNS) answer that returned this address.
    Dns,
    /// The outer server name of an Encrypted Client Hello: a shared front
    /// (e.g. `cloudflare-ech.com`), not the real site.
    EchOuter,
    /// PTR record.
    ReverseDns,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Rdns {
    #[default]
    NotRequested,
    Pending,
    Done(Option<String>),
}

#[derive(Debug, Clone, Default)]
struct Names {
    sni: Option<String>,
    ech_outer: Option<String>,
    dns: Option<String>,
    rdns: Rdns,
}

impl Names {
    fn best(&self) -> Option<(&str, NameSource)> {
        if let Some(n) = &self.sni {
            return Some((n, NameSource::Sni));
        }
        if let Some(n) = &self.dns {
            return Some((n, NameSource::Dns));
        }
        if let Some(n) = &self.ech_outer {
            return Some((n, NameSource::EchOuter));
        }
        match &self.rdns {
            Rdns::Done(Some(n)) => Some((n, NameSource::ReverseDns)),
            _ => None,
        }
    }
}

/// Bound on remembered addresses (DNS answers for the whole machine flow in).
const MAX_ENTRIES: usize = 50_000;

#[derive(Debug, Default)]
pub struct NameBook {
    map: RwLock<HashMap<IpAddr, Names>>,
}

impl NameBook {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_dns(&self, ip: IpAddr, name: String) {
        self.update(ip, |n| n.dns = Some(name));
    }

    pub fn set_sni(&self, ip: IpAddr, name: String, ech: bool) {
        self.update(ip, |n| {
            if ech {
                n.ech_outer = Some(name)
            } else {
                n.sni = Some(name)
            }
        });
    }

    pub fn set_rdns(&self, ip: IpAddr, state: Rdns) {
        self.update(ip, |n| n.rdns = state);
    }

    /// Best name for `ip` and where it came from.
    pub fn best(&self, ip: IpAddr) -> Option<(String, NameSource)> {
        let map = self.map.read().unwrap_or_else(|e| e.into_inner());
        map.get(&ip)
            .and_then(|n| n.best().map(|(s, src)| (s.to_string(), src)))
    }

    /// Should a reverse lookup be started? (No name yet and never requested.)
    pub fn wants_rdns(&self, ip: IpAddr) -> bool {
        let map = self.map.read().unwrap_or_else(|e| e.into_inner());
        map.get(&ip)
            .is_none_or(|n| n.rdns == Rdns::NotRequested && n.best().is_none())
    }

    fn update(&self, ip: IpAddr, f: impl FnOnce(&mut Names)) {
        let mut map = self.map.write().unwrap_or_else(|e| e.into_inner());
        if map.len() >= MAX_ENTRIES && !map.contains_key(&ip) {
            return;
        }
        f(map.entry(ip).or_default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_priority() {
        let b = NameBook::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(b.best(ip), None);
        b.set_rdns(ip, Rdns::Done(Some("host-1-2-3-4.isp.net".into())));
        assert_eq!(b.best(ip).unwrap().1, NameSource::ReverseDns);
        b.set_sni(ip, "cloudflare-ech.com".into(), true);
        assert_eq!(
            b.best(ip).unwrap(),
            ("cloudflare-ech.com".into(), NameSource::EchOuter)
        );
        b.set_dns(ip, "www.example.com".into());
        assert_eq!(
            b.best(ip).unwrap(),
            ("www.example.com".into(), NameSource::Dns)
        );
        b.set_sni(ip, "api.example.com".into(), false);
        assert_eq!(
            b.best(ip).unwrap(),
            ("api.example.com".into(), NameSource::Sni)
        );
    }

    #[test]
    fn rdns_requested_once_and_only_when_unnamed() {
        let b = NameBook::new();
        let a: IpAddr = "1.1.1.1".parse().unwrap();
        let named: IpAddr = "8.8.8.8".parse().unwrap();
        b.set_dns(named, "dns.google".into());
        assert!(b.wants_rdns(a));
        assert!(!b.wants_rdns(named));
        b.set_rdns(a, Rdns::Pending);
        assert!(!b.wants_rdns(a));
    }
}

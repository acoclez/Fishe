//! Who owns an address, and where is it registered?
//!
//! | source | what | network use | module |
//! |---|---|---|---|
//! | **DB-IP Lite** (offline) | ASN + organisation, country | one download when you click it in Settings (~9 MB, monthly) | [`db`], [`download`] |
//! | **ipinfo.io** (online, opt-in) | the same, for addresses the offline data doesn't cover | sends those IPs to ipinfo.io | [`online`] |
//!
//! DB-IP Lite is licensed CC BY 4.0: the UI shows the attribution wherever
//! its data appears. See `docs/owners.md`.

pub mod db;
pub mod download;
pub mod online;

use crate::naming::addr::{self, AddrScope};
use serde::Serialize;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub enum OwnerSource {
    /// DB-IP Lite database on this machine.
    Dbip,
    /// ipinfo.io online lookup.
    Ipinfo,
}

/// Owner and country of an address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Owner {
    pub asn: Option<u32>,
    /// Network owner, e.g. "Cloudflare, Inc.".
    pub org: Option<String>,
    /// ISO 3166-1 alpha-2, e.g. "US".
    pub country: Option<String>,
    pub source: OwnerSource,
}

impl Owner {
    fn is_empty(&self) -> bool {
        self.asn.is_none() && self.org.is_none() && self.country.is_none()
    }
}

pub const ATTRIBUTION: &str = "IP data by DB-IP.com, licensed CC BY 4.0";

/// Shared, Tauri-managed geo service.
pub struct Geo {
    dir: PathBuf,
    dbs: RwLock<Option<Arc<db::GeoDbs>>>,
    pub online: online::OnlineLookup,
}

impl Geo {
    /// Load an installed database from `dir`, if any.
    pub fn new(dir: PathBuf) -> Self {
        let dbs = db::GeoDbs::load(&dir)
            .map_err(|e| log::info!("no offline owner database: {e}"))
            .ok()
            .map(Arc::new);
        Geo {
            dir,
            dbs: RwLock::new(dbs),
            online: online::OnlineLookup::new(),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn dbs(&self) -> Option<Arc<db::GeoDbs>> {
        self.dbs.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Re-read the database files (after a download or removal).
    pub fn reload(&self) {
        let dbs = db::GeoDbs::load(&self.dir).ok().map(Arc::new);
        *self.dbs.write().unwrap_or_else(|e| e.into_inner()) = dbs;
    }

    /// Owner of a public address: offline first, then (if enabled) the online
    /// cache. Never blocks: an online miss queues a lookup for later ticks.
    pub fn owner(&self, ip: IpAddr) -> Option<Owner> {
        if !matches!(addr::classify(ip), AddrScope::Public) {
            return None;
        }
        if let Some(o) = self
            .dbs()
            .and_then(|d| d.lookup(ip))
            .filter(|o| !o.is_empty())
        {
            return Some(o);
        }
        self.online.get_or_request(ip)
    }

    /// Like [`Geo::owner`], but only what is known now: an online miss is
    /// not queued.
    /// Is an owner database installed?
    pub fn has_database(&self) -> bool {
        self.dbs().is_some()
    }

    pub fn known_owner(&self, ip: IpAddr) -> Option<Owner> {
        if !matches!(addr::classify(ip), AddrScope::Public) {
            return None;
        }
        self.dbs()
            .and_then(|d| d.lookup(ip))
            .filter(|o| !o.is_empty())
            .or_else(|| self.online.cached(ip))
    }
}

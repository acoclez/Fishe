//! Reading the DB-IP Lite MMDB files.

use super::{Owner, OwnerSource};
use crate::error::{AppError, AppResult};
use maxminddb::Reader;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;

pub const ASN_FILE: &str = "dbip-asn-lite.mmdb";
pub const COUNTRY_FILE: &str = "dbip-country-lite.mmdb";
pub const META_FILE: &str = "meta.json";

/// What was installed, written next to the files.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallMeta {
    /// Release month, "YYYY-MM".
    pub month: String,
    /// Unix ms.
    pub downloaded_at: i64,
}

pub struct GeoDbs {
    asn: Option<Reader<Vec<u8>>>,
    country: Option<Reader<Vec<u8>>>,
    pub meta: Option<InstallMeta>,
}

#[derive(Deserialize)]
struct AsnRec<'a> {
    autonomous_system_number: Option<u32>,
    #[serde(borrow)]
    autonomous_system_organization: Option<&'a str>,
}

#[derive(Deserialize)]
struct CountryRec<'a> {
    #[serde(borrow)]
    country: Option<CountryInner<'a>>,
}

#[derive(Deserialize)]
struct CountryInner<'a> {
    iso_code: Option<&'a str>,
}

impl GeoDbs {
    /// Load whichever of the two files exist in `dir`.
    pub fn load(dir: &Path) -> AppResult<Self> {
        let open = |f: &str| -> Option<Reader<Vec<u8>>> {
            let p = dir.join(f);
            if !p.is_file() {
                return None;
            }
            Reader::open_readfile(&p)
                .map_err(|e| log::warn!("cannot read {}: {e}", p.display()))
                .ok()
        };
        let asn = open(ASN_FILE);
        let country = open(COUNTRY_FILE);
        if asn.is_none() && country.is_none() {
            return Err(AppError::Unavailable("owner database not installed".into()));
        }
        let meta = std::fs::read_to_string(dir.join(META_FILE))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok());
        Ok(GeoDbs { asn, country, meta })
    }

    pub fn has_asn(&self) -> bool {
        self.asn.is_some()
    }

    pub fn has_country(&self) -> bool {
        self.country.is_some()
    }

    /// Database build time (unix seconds) of the ASN (or country) file.
    pub fn build_epoch(&self) -> Option<u64> {
        self.asn
            .as_ref()
            .or(self.country.as_ref())
            .map(|r| r.metadata().build_epoch)
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<Owner> {
        let (asn, org) = self
            .asn
            .as_ref()
            .and_then(|r| r.lookup(ip).ok()?.decode::<AsnRec>().ok().flatten())
            .map(|a| {
                (
                    a.autonomous_system_number,
                    a.autonomous_system_organization.map(String::from),
                )
            })
            .unwrap_or((None, None));
        let country = self
            .country
            .as_ref()
            .and_then(|r| r.lookup(ip).ok()?.decode::<CountryRec>().ok().flatten())
            .and_then(|c| c.country)
            .and_then(|c| c.iso_code.map(String::from));
        Some(Owner {
            asn,
            org,
            country,
            source: OwnerSource::Dbip,
        })
    }
}

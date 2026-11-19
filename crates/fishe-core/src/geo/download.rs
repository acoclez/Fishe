//! Downloading DB-IP Lite (only when the user asks).
//!
//! Files are published monthly at
//! `https://download.db-ip.com/free/dbip-{asn,country}-lite-YYYY-MM.mmdb.gz`.
//! The current month is tried first, then the previous one (early in a
//! month the new release may not be out yet). Each file is streamed through
//! gzip into a temporary file and moved into place only when complete, so a
//! failed download never breaks the installed copy.

use super::db::{ASN_FILE, COUNTRY_FILE, InstallMeta, META_FILE};
use crate::error::{AppError, AppResult};
use serde::Serialize;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::time::Duration;

const BASE: &str = "https://download.db-ip.com/free";
/// Safety cap per file (they are ~10–30 MB uncompressed).
const MAX_BYTES: u64 = 200 * 1024 * 1024;

/// Which database file a download progress report is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, specta::Type)]
#[serde(rename_all = "lowercase")]
pub enum GeoFile {
    Asn,
    Country,
}

#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(rename = "GeoProgress", rename_all = "camelCase")]
pub struct Progress {
    pub file: GeoFile,
    pub received: u64,
    pub total: Option<u64>,
}

/// UTC "YYYY-MM" for a unix timestamp in seconds.
pub fn month_of(unix_secs: i64) -> String {
    let (y, m, _) = crate::util::civil_from_days(unix_secs.div_euclid(86_400));
    format!("{y:04}-{m:02}")
}

/// The month before "YYYY-MM".
pub fn previous_month(month: &str) -> String {
    let (y, m) = month
        .split_once('-')
        .and_then(|(y, m)| Some((y.parse::<i32>().ok()?, m.parse::<u32>().ok()?)))
        .unwrap_or((1970, 1));
    if m <= 1 {
        format!("{:04}-12", y - 1)
    } else {
        format!("{y:04}-{:02}", m - 1)
    }
}

pub fn current_month() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    month_of(secs)
}

fn agent() -> ureq::Agent {
    ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(120)))
            .user_agent(concat!("Fishe/", env!("CARGO_PKG_VERSION")))
            .build(),
    )
}

/// Download both files for the newest available month into `dir`.
pub fn install(dir: &Path, mut progress: impl FnMut(Progress)) -> AppResult<InstallMeta> {
    std::fs::create_dir_all(dir)
        .map_err(|e| AppError::io(format_args!("cannot create {}", dir.display()), e))?;
    let agent = agent();
    let this = current_month();
    let mut last_err = None;
    for month in [this.clone(), previous_month(&this)] {
        match install_month(&agent, dir, &month, &mut progress) {
            Ok(()) => {
                let meta = InstallMeta {
                    month,
                    downloaded_at: crate::archive::db::chrono_now_ms(),
                };
                let json = serde_json::to_string_pretty(&meta).unwrap_or_default();
                std::fs::write(dir.join(META_FILE), json)
                    .map_err(|e| AppError::io("cannot write metadata", e))?;
                return Ok(meta);
            }
            Err(e) => {
                log::warn!("DB-IP {month}: {e}");
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| AppError::Internal("download failed".into())))
}

fn install_month(
    agent: &ureq::Agent,
    dir: &Path,
    month: &str,
    progress: &mut impl FnMut(Progress),
) -> AppResult<()> {
    // Fetch both before replacing either, so the pair always matches.
    let asn_tmp = dir.join(format!("{ASN_FILE}.part"));
    let country_tmp = dir.join(format!("{COUNTRY_FILE}.part"));
    let result = (|| {
        fetch(
            agent,
            &format!("{BASE}/dbip-asn-lite-{month}.mmdb.gz"),
            &asn_tmp,
            GeoFile::Asn,
            progress,
        )?;
        fetch(
            agent,
            &format!("{BASE}/dbip-country-lite-{month}.mmdb.gz"),
            &country_tmp,
            GeoFile::Country,
            progress,
        )?;
        // Validate before installing.
        for p in [&asn_tmp, &country_tmp] {
            maxminddb::Reader::open_readfile(p).map_err(|e| {
                AppError::Internal(format!("downloaded file is not a valid database: {e}"))
            })?;
        }
        replace(&asn_tmp, &dir.join(ASN_FILE))?;
        replace(&country_tmp, &dir.join(COUNTRY_FILE))?;
        Ok(())
    })();
    let _ = std::fs::remove_file(&asn_tmp);
    let _ = std::fs::remove_file(&country_tmp);
    result
}

fn replace(from: &Path, to: &Path) -> AppResult<()> {
    std::fs::rename(from, to)
        .map_err(|e| AppError::io(format_args!("cannot install {}", to.display()), e))
}

fn fetch(
    agent: &ureq::Agent,
    url: &str,
    to: &Path,
    file: GeoFile,
    progress: &mut impl FnMut(Progress),
) -> AppResult<()> {
    let res = agent.get(url).call().map_err(|e| AppError::io(url, e))?;
    let total = res
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    let body = res.into_body().into_with_config().limit(MAX_BYTES).reader();
    let counting = Counting {
        inner: body,
        received: 0,
        total,
        file,
        progress,
        last: 0,
    };
    decompress_to(counting, to)
}

/// gunzip `input` into `to` (passes through data that isn't gzip, e.g. if a
/// proxy already decoded it).
pub fn decompress_to(input: impl Read, to: &Path) -> AppResult<()> {
    let io = |e: std::io::Error| AppError::io("download failed", e);
    let mut buffered = BufReader::with_capacity(1 << 16, input);
    let is_gzip = buffered.fill_buf().map_err(io)?.starts_with(&[0x1F, 0x8B]);
    let mut out = std::io::BufWriter::new(std::fs::File::create(to).map_err(io)?);
    if is_gzip {
        let mut gz = flate2::bufread::GzDecoder::new(buffered);
        std::io::copy(&mut (&mut gz).take(MAX_BYTES), &mut out).map_err(io)?;
    } else {
        std::io::copy(&mut buffered.take(MAX_BYTES), &mut out).map_err(io)?;
    }
    out.flush().map_err(io)
}

struct Counting<'a, R, F: FnMut(Progress)> {
    inner: R,
    received: u64,
    total: Option<u64>,
    file: GeoFile,
    progress: &'a mut F,
    last: u64,
}

impl<R: Read, F: FnMut(Progress)> Read for Counting<'_, R, F> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.received += n as u64;
        if self.received - self.last >= 256 * 1024 || n == 0 {
            self.last = self.received;
            (self.progress)(Progress {
                file: self.file,
                received: self.received,
                total: self.total,
            });
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn months() {
        assert_eq!(month_of(0), "1970-01");
        assert_eq!(month_of(1_794_100_000), "2026-11"); // 2026-11-08
        assert_eq!(month_of(1_798_761_600), "2027-01"); // 2027-01-01T00:00Z
        assert_eq!(month_of(1_709_164_800), "2024-02"); // 2024-02-29
        assert_eq!(previous_month("2026-11"), "2026-10");
        assert_eq!(previous_month("2027-01"), "2026-12");
    }

    #[test]
    fn gunzips_and_passes_through() {
        let dir = std::env::temp_dir().join(format!("fishe-geo-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(b"hello mmdb").unwrap();
        let packed = gz.finish().unwrap();
        decompress_to(&packed[..], &dir.join("a")).unwrap();
        assert_eq!(std::fs::read(dir.join("a")).unwrap(), b"hello mmdb");
        decompress_to(&b"plain"[..], &dir.join("b")).unwrap();
        assert_eq!(std::fs::read(dir.join("b")).unwrap(), b"plain");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Downloads ~9 MB from db-ip.com:
    /// `cargo test -- --ignored live_dbip --nocapture`
    #[test]
    #[ignore = "downloads DB-IP Lite"]
    fn live_dbip_install_and_lookup() {
        let dir = std::env::temp_dir().join(format!("fishe-dbip-{}", std::process::id()));
        let meta = install(&dir, |p| {
            if p.received == p.total.unwrap_or(0) {
                println!("{:?}: {} bytes", p.file, p.received);
            }
        })
        .unwrap();
        println!("installed {}", meta.month);
        let dbs = super::super::db::GeoDbs::load(&dir).unwrap();
        let o = dbs.lookup("1.1.1.1".parse().unwrap()).unwrap();
        println!("1.1.1.1 -> {o:?}");
        assert_eq!(o.asn, Some(13335));
        assert!(o.org.unwrap().to_lowercase().contains("cloudflare"));
        assert!(o.country.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

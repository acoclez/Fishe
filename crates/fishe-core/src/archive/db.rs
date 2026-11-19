//! SQLite schema and queries.
//!
//! One database for all recordings. Tables are keyed by `recording_id` and
//! cascade on delete. Levels are stored as integers (0 idle … 3 spike).

use crate::error::{AppError, AppResult};
use crate::monitor::endpoints::EndpointPort;
use crate::monitor::gauge::Level;
use crate::monitor::quality::EndpointQuality;
use crate::monitor::stats::{Counters, PortUsage, TransportBytes};
use crate::monitor::{Mode, SessionInfo};
use crate::naming::addr::AddrScope;
use crate::naming::book::NameSource;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::path::Path;

const SCHEMA_VERSION: i64 = 3;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS recordings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT    NOT NULL,
    mode           TEXT    NOT NULL,
    label          TEXT    NOT NULL,
    session_json   TEXT    NOT NULL,
    started_at     INTEGER NOT NULL,          -- unix ms
    ended_at       INTEGER,                   -- NULL while recording
    interrupted    INTEGER NOT NULL DEFAULT 0,
    tick_ms        INTEGER NOT NULL,
    sample_count   INTEGER NOT NULL DEFAULT 0,
    bytes_in       INTEGER NOT NULL DEFAULT 0,
    bytes_out      INTEGER NOT NULL DEFAULT 0,
    packets_in     INTEGER NOT NULL DEFAULT 0,
    packets_out    INTEGER NOT NULL DEFAULT 0,
    peak_bps       REAL    NOT NULL DEFAULT 0,
    max_level      INTEGER NOT NULL DEFAULT 0,
    endpoint_count INTEGER NOT NULL DEFAULT 0,
    summary_json   TEXT,
    pcap_path      TEXT,
    pcap_packets   INTEGER NOT NULL DEFAULT 0,
    pcap_dropped   INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS samples (
    recording_id INTEGER NOT NULL REFERENCES recordings(id) ON DELETE CASCADE,
    t_ms INTEGER NOT NULL,
    in_bps REAL, out_bps REAL, in_pps REAL, out_pps REAL,
    smoothed_bps REAL, baseline_bps REAL, ratio REAL, level INTEGER,
    PRIMARY KEY (recording_id, t_ms)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS endpoints (
    recording_id INTEGER NOT NULL REFERENCES recordings(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    name TEXT, name_source TEXT, scope TEXT NOT NULL,
    bytes_in INTEGER, bytes_out INTEGER, packets_in INTEGER, packets_out INTEGER,
    first_seen_ms INTEGER, last_seen_ms INTEGER,
    peak_bps REAL, max_level INTEGER, ports_json TEXT,
    PRIMARY KEY (recording_id, ip)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS endpoint_samples (
    recording_id INTEGER NOT NULL REFERENCES recordings(id) ON DELETE CASCADE,
    ip TEXT NOT NULL, t_ms INTEGER NOT NULL,
    in_bps REAL, out_bps REAL, smoothed_bps REAL, baseline_bps REAL, ratio REAL, level INTEGER,
    PRIMARY KEY (recording_id, ip, t_ms)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS episodes (
    recording_id INTEGER NOT NULL REFERENCES recordings(id) ON DELETE CASCADE,
    start_ms INTEGER NOT NULL, end_ms INTEGER NOT NULL,
    max_level INTEGER NOT NULL, peak_bps REAL, peak_ratio REAL,
    PRIMARY KEY (recording_id, start_ms)
) WITHOUT ROWID;
"#;

/// Open (creating if needed) and migrate the database.
pub fn open(path: &Path) -> AppResult<Connection> {
    let conn = Connection::open(path)?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.execute_batch(
        "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON;",
    )?;
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version > SCHEMA_VERSION {
        return Err(AppError::Internal(format!(
            "archive was created by a newer Fishe (schema {version}); refusing to modify it"
        )));
    }
    conn.execute_batch(SCHEMA)?;
    // v2: endpoint owner (ASN / organisation / country).
    // v3: connection quality (per-sample RTT, per-endpoint quality).
    for (table, col, ty) in [
        ("endpoints", "asn", "INTEGER"),
        ("endpoints", "org", "TEXT"),
        ("endpoints", "country", "TEXT"),
        ("endpoints", "owner_source", "TEXT"),
        ("endpoints", "quality_json", "TEXT"),
        ("samples", "rtt_ms", "REAL"),
    ] {
        let exists: bool = conn
            .prepare(&format!(
                "SELECT 1 FROM pragma_table_info('{table}') WHERE name = ?1"
            ))?
            .exists([col])?;
        if !exists {
            conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {col} {ty}"))?;
        }
    }
    conn.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))?;
    Ok(conn)
}

/// Close out recordings left open by a crash: end time = last sample.
pub fn recover_interrupted(conn: &Connection) -> AppResult<usize> {
    let n = conn.execute(
        "UPDATE recordings SET interrupted = 1,
            ended_at = started_at + COALESCE((SELECT MAX(t_ms) FROM samples s WHERE s.recording_id = recordings.id), 0),
            sample_count = (SELECT COUNT(*) FROM samples s WHERE s.recording_id = recordings.id)
         WHERE ended_at IS NULL",
        [],
    )?;
    Ok(n)
}

// ───────────────────────────── read model ─────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub enum RecordingStatus {
    Recording,
    Complete,
    Interrupted,
}

#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct RecordingSummary {
    pub id: i64,
    pub name: String,
    pub mode: Mode,
    pub label: String,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub duration_ms: i64,
    pub status: RecordingStatus,
    pub sample_count: i64,
    pub totals: Counters,
    pub peak_bps: f64,
    pub max_level: Level,
    pub endpoint_count: i64,
    pub pcap_path: Option<String>,
    pub pcap_packets: i64,
    pub pcap_dropped: i64,
    pub pcap_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct SeriesPoint {
    pub t_ms: i64,
    pub in_bps: f64,
    pub out_bps: f64,
    pub smoothed_bps: f64,
    pub baseline_bps: f64,
    pub ratio: f64,
    pub level: Level,
    /// Mean TCP round-trip time of the tick (recordings since schema v3).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct EndpointRecord {
    pub ip: String,
    pub name: Option<String>,
    pub name_source: Option<NameSource>,
    pub scope: AddrScope,
    pub totals: Counters,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    pub peak_bps: f64,
    pub max_level: Level,
    pub top_ports: Vec<EndpointPort>,
    pub owner: Option<crate::geo::Owner>,
    /// TCP connection quality over the recording.
    pub quality: Option<crate::monitor::quality::EndpointQuality>,
}

#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Episode {
    pub start_ms: i64,
    pub end_ms: i64,
    pub max_level: Level,
    pub peak_bps: f64,
    pub peak_ratio: f64,
}

/// Whole-recording figures written when a recording ends (`summary_json`).
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct RecordingExtra {
    pub transports: TransportBytes,
    pub top_ports: Vec<PortUsage>,
    pub dropped: u64,
    pub if_dropped: u64,
    pub unattributed: u64,
    /// TCP quality over the recording (recordings since 0.8).
    #[serde(default)]
    pub quality: Option<EndpointQuality>,
    /// All-traffic recordings: the programs that moved the most bytes (≤ 25).
    #[serde(default)]
    pub programs: Option<Vec<RecordingProgram>>,
}

/// One program's share of an all-traffic recording.
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct RecordingProgram {
    pub key: String,
    pub name: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub endpoints: u64,
    pub peak_bps: f64,
}

#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct RecordingDetail {
    pub summary: RecordingSummary,
    /// The session the recording was made in; `None` if its stored JSON
    /// no longer parses (a recording from an incompatible version).
    pub session: Option<SessionInfo>,
    /// End-of-recording extras; `None` while recording or when interrupted.
    pub extra: Option<RecordingExtra>,
    pub samples: Vec<SeriesPoint>,
    /// Samples were averaged into fewer points for display.
    pub downsampled: bool,
    pub endpoints: Vec<EndpointRecord>,
    pub episodes: Vec<Episode>,
}

/// A serde-named enum value stored as its wire string (`"linkLocal"`, `"sni"`…).
fn enum_from_db<T: serde::de::DeserializeOwned>(s: &str) -> Option<T> {
    serde_json::from_value(serde_json::Value::String(s.to_string())).ok()
}

/// Points returned to the UI per series at most.
pub const MAX_POINTS: usize = 3000;

const SUMMARY_COLS: &str = "id, name, mode, label, started_at, ended_at, interrupted, sample_count,
    bytes_in, bytes_out, packets_in, packets_out, peak_bps, max_level, endpoint_count,
    pcap_path, pcap_packets, pcap_dropped";

fn summary_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<RecordingSummary> {
    let started_at: i64 = r.get(4)?;
    let ended_at: Option<i64> = r.get(5)?;
    let interrupted: bool = r.get::<_, i64>(6)? != 0;
    let pcap_path: Option<String> = r.get(15)?;
    let now = chrono_now_ms();
    Ok(RecordingSummary {
        id: r.get(0)?,
        name: r.get(1)?,
        mode: {
            let s: String = r.get(2)?;
            Mode::parse(&s).ok_or_else(|| {
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Text,
                    format!("unknown recording mode {s:?}").into(),
                )
            })?
        },
        label: r.get(3)?,
        started_at,
        ended_at,
        duration_ms: ended_at.unwrap_or(now) - started_at,
        status: match (ended_at, interrupted) {
            (None, _) => RecordingStatus::Recording,
            (Some(_), true) => RecordingStatus::Interrupted,
            (Some(_), false) => RecordingStatus::Complete,
        },
        sample_count: r.get(7)?,
        totals: Counters {
            bytes_in: r.get::<_, i64>(8)? as u64,
            bytes_out: r.get::<_, i64>(9)? as u64,
            packets_in: r.get::<_, i64>(10)? as u64,
            packets_out: r.get::<_, i64>(11)? as u64,
        },
        peak_bps: r.get(12)?,
        max_level: Level::from_u8(r.get::<_, i64>(13)? as u8),
        endpoint_count: r.get(14)?,
        pcap_bytes: pcap_path
            .as_ref()
            .and_then(|p| std::fs::metadata(p).ok())
            .map(|m| m.len()),
        pcap_path,
        pcap_packets: r.get(16)?,
        pcap_dropped: r.get(17)?,
    })
}

pub fn chrono_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn list(conn: &Connection) -> AppResult<Vec<RecordingSummary>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {SUMMARY_COLS} FROM recordings ORDER BY started_at DESC"
    ))?;
    let rows = stmt
        .query_map([], summary_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub fn summary(conn: &Connection, id: i64) -> AppResult<RecordingSummary> {
    conn.query_row(
        &format!("SELECT {SUMMARY_COLS} FROM recordings WHERE id = ?1"),
        [id],
        summary_row,
    )
    .optional()?
    .ok_or_else(|| AppError::NotFound(format!("recording {id} not found")))
}

fn series_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<SeriesPoint> {
    Ok(SeriesPoint {
        t_ms: r.get(0)?,
        in_bps: r.get(1)?,
        out_bps: r.get(2)?,
        smoothed_bps: r.get(3)?,
        baseline_bps: r.get(4)?,
        ratio: r.get(5)?,
        level: Level::from_u8(r.get::<_, i64>(6)? as u8),
        rtt_ms: None,
    })
}

/// A sample row with its RTT in column 7.
fn sample_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<SeriesPoint> {
    Ok(SeriesPoint {
        rtt_ms: r.get(7)?,
        ..series_row(r)?
    })
}

/// Average consecutive points into at most `max` points, keeping the
/// highest ratio and level of each bucket (so spikes survive).
pub fn downsample(points: Vec<SeriesPoint>, max: usize) -> (Vec<SeriesPoint>, bool) {
    if points.len() <= max || max == 0 {
        return (points, false);
    }
    let bucket = points.len().div_ceil(max);
    let out = points
        .chunks(bucket)
        .map(|c| {
            let n = c.len() as f64;
            SeriesPoint {
                t_ms: c[c.len() - 1].t_ms,
                in_bps: c.iter().map(|p| p.in_bps).sum::<f64>() / n,
                out_bps: c.iter().map(|p| p.out_bps).sum::<f64>() / n,
                smoothed_bps: c.iter().map(|p| p.smoothed_bps).sum::<f64>() / n,
                baseline_bps: c.iter().map(|p| p.baseline_bps).sum::<f64>() / n,
                ratio: c.iter().map(|p| p.ratio).fold(0.0, f64::max),
                level: c.iter().map(|p| p.level).max().unwrap_or(Level::Idle),
                // The worst RTT of the bucket, so lag spikes survive too.
                rtt_ms: c.iter().filter_map(|p| p.rtt_ms).reduce(f64::max),
            }
        })
        .collect();
    (out, true)
}

pub fn detail(conn: &Connection, id: i64) -> AppResult<RecordingDetail> {
    let summary = summary(conn, id)?;
    let (session_json, extra_json): (String, Option<String>) = conn.query_row(
        "SELECT session_json, summary_json FROM recordings WHERE id = ?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;

    let mut stmt = conn.prepare(
        "SELECT t_ms, in_bps, out_bps, smoothed_bps, baseline_bps, ratio, level, rtt_ms
         FROM samples WHERE recording_id = ?1 ORDER BY t_ms",
    )?;
    let raw = stmt
        .query_map([id], sample_row)?
        .collect::<Result<Vec<_>, _>>()?;
    let (samples, downsampled) = downsample(raw, MAX_POINTS);

    let mut stmt = conn.prepare(
        "SELECT ip, name, name_source, scope, bytes_in, bytes_out, packets_in, packets_out,
                first_seen_ms, last_seen_ms, peak_bps, max_level, ports_json,
                asn, org, country, owner_source, quality_json
         FROM endpoints WHERE recording_id = ?1 ORDER BY (bytes_in + bytes_out) DESC",
    )?;
    let endpoints = stmt
        .query_map([id], |r| {
            let ports: Option<String> = r.get(12)?;
            Ok(EndpointRecord {
                ip: r.get(0)?,
                name: r.get(1)?,
                name_source: r
                    .get::<_, Option<String>>(2)?
                    .and_then(|s| enum_from_db(&s)),
                scope: enum_from_db(&r.get::<_, String>(3)?).unwrap_or(AddrScope::Public),
                totals: Counters {
                    bytes_in: r.get::<_, i64>(4)? as u64,
                    bytes_out: r.get::<_, i64>(5)? as u64,
                    packets_in: r.get::<_, i64>(6)? as u64,
                    packets_out: r.get::<_, i64>(7)? as u64,
                },
                first_seen_ms: r.get(8)?,
                last_seen_ms: r.get(9)?,
                peak_bps: r.get(10)?,
                max_level: Level::from_u8(r.get::<_, i64>(11)? as u8),
                top_ports: ports
                    .and_then(|p| serde_json::from_str(&p).ok())
                    .unwrap_or_default(),
                owner: {
                    let source: Option<String> = r.get(16)?;
                    source
                        .map(|s| -> rusqlite::Result<crate::geo::Owner> {
                            Ok(crate::geo::Owner {
                                asn: r.get::<_, Option<i64>>(13)?.map(|a| a as u32),
                                org: r.get(14)?,
                                country: r.get(15)?,
                                source: if s == "ipinfo" {
                                    crate::geo::OwnerSource::Ipinfo
                                } else {
                                    crate::geo::OwnerSource::Dbip
                                },
                            })
                        })
                        .transpose()?
                },
                quality: r
                    .get::<_, Option<String>>(17)?
                    .and_then(|q| serde_json::from_str(&q).ok()),
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let mut stmt = conn.prepare(
        "SELECT start_ms, end_ms, max_level, peak_bps, peak_ratio FROM episodes
         WHERE recording_id = ?1 ORDER BY start_ms",
    )?;
    let episodes = stmt
        .query_map([id], |r| {
            Ok(Episode {
                start_ms: r.get(0)?,
                end_ms: r.get(1)?,
                max_level: Level::from_u8(r.get::<_, i64>(2)? as u8),
                peak_bps: r.get(3)?,
                peak_ratio: r.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(RecordingDetail {
        summary,
        session: serde_json::from_str(&session_json).ok(),
        extra: extra_json.and_then(|s| serde_json::from_str(&s).ok()),
        samples,
        downsampled,
        endpoints,
        episodes,
    })
}

/// One endpoint's series (zero-filled between its active ticks is left to the UI).
pub fn endpoint_series(conn: &Connection, id: i64, ip: &str) -> AppResult<Vec<SeriesPoint>> {
    let mut stmt = conn.prepare(
        "SELECT t_ms, in_bps, out_bps, smoothed_bps, baseline_bps, ratio, level
         FROM endpoint_samples WHERE recording_id = ?1 AND ip = ?2 ORDER BY t_ms",
    )?;
    let raw = stmt
        .query_map(params![id, ip], series_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(downsample(raw, MAX_POINTS).0)
}

/// Every sample at full resolution (exports).
pub fn all_samples(conn: &Connection, id: i64) -> AppResult<Vec<(SeriesPoint, f64, f64)>> {
    let mut stmt = conn.prepare(
        "SELECT t_ms, in_bps, out_bps, smoothed_bps, baseline_bps, ratio, level, rtt_ms, in_pps, out_pps
         FROM samples WHERE recording_id = ?1 ORDER BY t_ms",
    )?;
    let rows = stmt
        .query_map([id], |r| Ok((sample_row(r)?, r.get(8)?, r.get(9)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub fn rename(conn: &Connection, id: i64, name: &str) -> AppResult<()> {
    let name = name.trim();
    if name.is_empty() || name.len() > 200 {
        return Err(AppError::InvalidArgument(
            "name must be 1 to 200 characters".into(),
        ));
    }
    let n = conn.execute(
        "UPDATE recordings SET name = ?1 WHERE id = ?2",
        params![name, id],
    )?;
    if n == 0 {
        return Err(AppError::NotFound(format!("recording {id} not found")));
    }
    Ok(())
}

/// Delete a finished recording and its capture file. Returns the removed file, if any.
pub fn delete(conn: &Connection, id: i64) -> AppResult<Option<String>> {
    let s = summary(conn, id)?;
    if s.status == RecordingStatus::Recording {
        return Err(AppError::InvalidState(
            "stop the recording before deleting it".into(),
        ));
    }
    conn.execute("DELETE FROM recordings WHERE id = ?1", [id])?;
    if let Some(p) = &s.pcap_path {
        let _ = std::fs::remove_file(p);
    }
    Ok(s.pcap_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pt(t: i64, inb: f64, level: Level) -> SeriesPoint {
        SeriesPoint {
            t_ms: t,
            in_bps: inb,
            out_bps: 0.0,
            smoothed_bps: inb,
            baseline_bps: 1.0,
            ratio: inb,
            level,
            rtt_ms: None,
        }
    }

    #[test]
    fn downsample_keeps_spikes() {
        let mut v: Vec<SeriesPoint> = (0..1000).map(|i| pt(i, 1.0, Level::Calm)).collect();
        v[500] = pt(500, 1000.0, Level::Spike);
        let (d, did) = downsample(v, 100);
        assert!(did);
        assert_eq!(d.len(), 100);
        let spike = d
            .iter()
            .find(|p| p.level == Level::Spike)
            .expect("spike survives");
        assert_eq!(spike.ratio, 1000.0);
        assert!((spike.in_bps - (9.0 + 1000.0) / 10.0).abs() < 1e-9);
        let (same, did) = downsample(vec![pt(0, 1.0, Level::Idle)], 100);
        assert!(!did && same.len() == 1);
    }

    #[test]
    fn schema_and_recovery() {
        let dir = std::env::temp_dir().join(format!("fishe-db-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.db");
        let _ = std::fs::remove_file(&path);
        let c = open(&path).unwrap();
        c.execute(
            "INSERT INTO recordings (name, mode, label, session_json, started_at, tick_ms) VALUES ('r','host','1.1.1.1','{}',1000,250)",
            [],
        )
        .unwrap();
        let id = c.last_insert_rowid();
        c.execute(
            "INSERT INTO samples VALUES (?1, 250, 1,1,1,1,1,1,1,1, NULL), (?1, 500, 1,1,1,1,1,1,1,3, NULL)",
            [id],
        )
        .unwrap();
        assert_eq!(list(&c).unwrap()[0].status, RecordingStatus::Recording);
        assert_eq!(recover_interrupted(&c).unwrap(), 1);
        let s = summary(&c, id).unwrap();
        assert_eq!(
            (s.status, s.ended_at, s.sample_count),
            (RecordingStatus::Interrupted, Some(1500), 2)
        );
        rename(&c, id, "  morning  ").unwrap();
        assert_eq!(summary(&c, id).unwrap().name, "morning");
        delete(&c, id).unwrap();
        let left: i64 = c
            .query_row("SELECT COUNT(*) FROM samples", [], |r| r.get(0))
            .unwrap();
        assert_eq!(left, 0, "cascade");
        drop(c);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

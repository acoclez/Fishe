//! Exporting a recording to CSV or JSON (always full resolution).

use super::db;
use crate::error::{AppError, AppResult};
use rusqlite::Connection;
use serde::Deserialize;
use std::io::Write;
use std::path::Path;

#[derive(Debug, Clone, Copy, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub enum ExportFormat {
    /// One row per tick: time, rates, detector values, level.
    SamplesCsv,
    /// One row per endpoint: name, address, totals, ports.
    EndpointsCsv,
    /// Everything: summary, session, samples, endpoints, episodes.
    Json,
}

impl ExportFormat {
    /// File extension, without the dot.
    pub fn extension(self) -> &'static str {
        match self {
            ExportFormat::SamplesCsv | ExportFormat::EndpointsCsv => "csv",
            ExportFormat::Json => "json",
        }
    }
}

/// A file name to suggest for an export: `name` without anything that
/// could make it a path, plus the format's extension.
pub fn suggested_file_name(name: &str, format: ExportFormat) -> String {
    let stem: String = name
        .chars()
        .map(|c| match c {
            '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .take(80)
        .collect();
    let stem = stem.trim().trim_matches('.');
    let stem = if stem.is_empty() { "recording" } else { stem };
    format!("{stem}.{}", format.extension())
}

pub fn export(conn: &Connection, id: i64, format: ExportFormat, path: &Path) -> AppResult<()> {
    let io = |e: std::io::Error| AppError::io(format_args!("cannot write {}", path.display()), e);
    let file = std::fs::File::create(path).map_err(io)?;
    let mut out = std::io::BufWriter::new(file);
    match format {
        ExportFormat::SamplesCsv => {
            writeln!(out, "t_s,in_bytes_per_s,out_bytes_per_s,in_packets_per_s,out_packets_per_s,smoothed_bytes_per_s,baseline_bytes_per_s,ratio,level,rtt_ms").map_err(io)?;
            for (p, in_pps, out_pps) in db::all_samples(conn, id)? {
                writeln!(
                    out,
                    "{:.3},{:.1},{:.1},{:.2},{:.2},{:.1},{:.1},{:.3},{},{}",
                    p.t_ms as f64 / 1000.0,
                    p.in_bps,
                    p.out_bps,
                    in_pps,
                    out_pps,
                    p.smoothed_bps,
                    p.baseline_bps,
                    p.ratio,
                    level_name(p.level),
                    p.rtt_ms.map(|v| format!("{v:.2}")).unwrap_or_default()
                )
                .map_err(io)?;
            }
        }
        ExportFormat::EndpointsCsv => {
            let d = db::detail(conn, id)?;
            writeln!(out, "ip,name,name_source,scope,asn,org,country,bytes_in,bytes_out,packets_in,packets_out,first_seen_s,last_seen_s,peak_bytes_per_s,max_level,ports").map_err(io)?;
            for e in d.endpoints {
                let ports: Vec<String> = e
                    .top_ports
                    .iter()
                    .map(|p| format!("{}/{}", p.port, wire(&p.transport)))
                    .collect();
                writeln!(
                    out,
                    "{},{},{},{},{},{},{},{},{},{},{},{:.3},{:.3},{:.1},{},{}",
                    csv(&e.ip),
                    csv(e.name.as_deref().unwrap_or("")),
                    csv(&e.name_source.as_ref().map(wire).unwrap_or_default()),
                    csv(&wire(&e.scope)),
                    e.owner
                        .as_ref()
                        .and_then(|o| o.asn)
                        .map(|a| a.to_string())
                        .unwrap_or_default(),
                    csv(e
                        .owner
                        .as_ref()
                        .and_then(|o| o.org.as_deref())
                        .unwrap_or("")),
                    csv(e
                        .owner
                        .as_ref()
                        .and_then(|o| o.country.as_deref())
                        .unwrap_or("")),
                    e.totals.bytes_in,
                    e.totals.bytes_out,
                    e.totals.packets_in,
                    e.totals.packets_out,
                    e.first_seen_ms as f64 / 1000.0,
                    e.last_seen_ms as f64 / 1000.0,
                    e.peak_bps,
                    level_name(e.max_level),
                    csv(&ports.join(" "))
                )
                .map_err(io)?;
            }
        }
        ExportFormat::Json => {
            let mut d = db::detail(conn, id)?;
            d.samples = db::all_samples(conn, id)?
                .into_iter()
                .map(|(p, _, _)| p)
                .collect();
            d.downsampled = false;
            serde_json::to_writer_pretty(&mut out, &d)
                .map_err(|e| AppError::Internal(format!("JSON export failed: {e}")))?;
        }
    }
    out.flush().map_err(io)?;
    Ok(())
}

fn level_name(l: crate::monitor::gauge::Level) -> &'static str {
    use crate::monitor::gauge::Level::*;
    match l {
        Idle => "idle",
        Calm => "calm",
        Busy => "busy",
        Spike => "spike",
    }
}

/// A serde-named enum as its wire string (`"tcp"`, `"linkLocal"`, `"sni"`).
fn wire(v: &impl serde::Serialize) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default()
}

/// A text field for a CSV row: quoted when needed (RFC 4180), and never a
/// formula. Spreadsheets run a cell that starts with `=`, `+`, `-` or `@`,
/// and names and organisations are text other people chose, so such a cell
/// gets a leading apostrophe, which spreadsheets show as plain text.
fn csv(s: &str) -> String {
    let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        std::borrow::Cow::Owned(format!("'{s}"))
    } else {
        std::borrow::Cow::Borrowed(s)
    };
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::{ExportFormat, csv, suggested_file_name};

    #[test]
    fn suggested_names_are_file_names() {
        let f = ExportFormat::Json;
        assert_eq!(suggested_file_name("Evening run", f), "Evening run.json");
        assert_eq!(
            suggested_file_name("..\\..\\Startup\\x.cmd", f),
            "_.._Startup_x.cmd.json"
        );
        assert_eq!(
            suggested_file_name("a/b:c", ExportFormat::SamplesCsv),
            "a_b_c.csv"
        );
        assert_eq!(suggested_file_name(" .. ", f), "recording.json");
        assert_eq!(suggested_file_name("", f), "recording.json");
    }

    #[test]
    fn csv_quoting() {
        assert_eq!(csv("plain"), "plain");
        assert_eq!(csv("a,b"), "\"a,b\"");
        assert_eq!(csv("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn csv_cells_are_never_formulas() {
        assert_eq!(csv("=1+1"), "'=1+1");
        assert_eq!(csv("@SUM(A1)"), "'@SUM(A1)");
        assert_eq!(csv("-2+3"), "'-2+3");
        assert_eq!(
            csv("=HYPERLINK(\"http://x\",\"y\")"),
            "\"'=HYPERLINK(\"\"http://x\"\",\"\"y\"\")\""
        );
        assert_eq!(
            csv("a-b.example"),
            "a-b.example",
            "only a leading sign matters"
        );
    }
}

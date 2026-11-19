//! Logging. Every `log` line goes to stderr (what `tauri dev` shows) and,
//! once the data folder is known, to `<data>/logs/fishe.log` (kept at
//! [`MAX_BYTES`], one rotated copy `fishe.1.log`): the file a bug report
//! should come with. Settings → Diagnostics opens the folder.
//!
//! `FISHE_LOG` picks the level like `RUST_LOG`, overall or per module:
//!
//! ```text
//! FISHE_LOG=debug                        everything at debug
//! FISHE_LOG=info,fishe_core::lan=trace    one module louder
//! ```
//!
//! The default is `info`, with the HTTP stack behind the MCP server at
//! `warn`. The longest matching module prefix wins.

use log::{LevelFilter, Log, Metadata, Record};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

pub const FILE_NAME: &str = "fishe.log";
const ROTATED_NAME: &str = "fishe.1.log";
/// The file is rotated once a line would take it past this.
const MAX_BYTES: u64 = 2 * 1024 * 1024;
const DEFAULT_SPEC: &str = "info,rmcp=warn,axum=warn,hyper=warn,tower=warn,ureq=warn,rustls=warn";
/// Our own crates' prefixes (the engine, the app shell), dropped from targets
/// for readability.
const OWN_PREFIXES: [&str; 2] = ["fishe_core::", "fishe_lib::"];

/// A `RUST_LOG`-style filter.
#[derive(Debug, Clone, PartialEq)]
struct Filter {
    default: LevelFilter,
    /// `(target prefix, level)`, longest prefix first.
    modules: Vec<(String, LevelFilter)>,
}

impl Filter {
    /// `level` and `target=level` entries, comma separated. Later entries
    /// override earlier ones for the same target; unknown levels are ignored.
    fn parse(spec: &str) -> Self {
        let mut f = Filter {
            default: LevelFilter::Info,
            modules: Vec::new(),
        };
        for part in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            match part.split_once('=') {
                Some((target, level)) => {
                    let (target, Ok(level)) = (target.trim(), level.trim().parse()) else {
                        continue;
                    };
                    f.modules.retain(|(t, _)| t != target);
                    f.modules.push((target.to_string(), level));
                }
                None => {
                    if let Ok(level) = part.parse() {
                        f.default = level;
                    }
                }
            }
        }
        f.modules.sort_by_key(|(t, _)| std::cmp::Reverse(t.len()));
        f
    }

    fn level_for(&self, target: &str) -> LevelFilter {
        self.modules
            .iter()
            .find(|(t, _)| {
                target
                    .strip_prefix(t.as_str())
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with("::"))
            })
            .map_or(self.default, |(_, l)| *l)
    }

    /// The loudest level anything can log at (for `log::set_max_level`).
    fn max(&self) -> LevelFilter {
        self.modules
            .iter()
            .map(|(_, l)| *l)
            .fold(self.default, std::cmp::max)
    }
}

/// The open log file and how big it is.
struct LogFile {
    path: PathBuf,
    file: Option<File>,
    size: u64,
    limit: u64,
}

impl LogFile {
    fn open(path: PathBuf, limit: u64) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let size = file.metadata()?.len();
        Ok(LogFile {
            path,
            file: Some(file),
            size,
            limit,
        })
    }

    fn write(&mut self, line: &str) -> io::Result<()> {
        if self.size + line.len() as u64 > self.limit {
            self.rotate()?;
        }
        let file = self.file.as_mut().ok_or(io::ErrorKind::NotFound)?;
        file.write_all(line.as_bytes())?;
        self.size += line.len() as u64;
        Ok(())
    }

    /// `fishe.log` becomes `fishe.1.log` (replacing the previous one) and a
    /// fresh file starts; if the rename fails, the file is truncated instead.
    fn rotate(&mut self) -> io::Result<()> {
        self.file = None; // closed before the rename
        let rotated = self.path.with_file_name(ROTATED_NAME);
        let _ = std::fs::remove_file(&rotated);
        let mut open = OpenOptions::new();
        open.create(true);
        if std::fs::rename(&self.path, &rotated).is_ok() {
            open.append(true);
        } else {
            open.write(true).truncate(true);
        }
        self.file = Some(open.open(&self.path)?);
        self.size = 0;
        Ok(())
    }
}

struct Logger {
    filter: OnceLock<Filter>,
    file: Mutex<Option<LogFile>>,
}

static LOGGER: Logger = Logger {
    filter: OnceLock::new(),
    file: Mutex::new(None),
};

impl Log for Logger {
    fn enabled(&self, m: &Metadata) -> bool {
        let level = self
            .filter
            .get()
            .map_or(LevelFilter::Info, |f| f.level_for(m.target()));
        m.level() <= level
    }

    fn log(&self, r: &Record) {
        if !self.enabled(r.metadata()) {
            return;
        }
        let target = OWN_PREFIXES
            .iter()
            .find_map(|p| r.target().strip_prefix(p))
            .unwrap_or(r.target());
        eprintln!("[fishe {:<5} {target}] {}", r.level(), r.args());
        let mut guard = self.file.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(f) = guard.as_mut() {
            let line = format!("{} {:<5} {target}: {}\n", utc_now(), r.level(), r.args());
            if let Err(e) = f.write(&line) {
                // Not through `log`: we hold the lock.
                eprintln!("[fishe ERROR logging] log file closed: {e}");
                *guard = None;
            }
        }
    }

    fn flush(&self) {}
}

/// Install the logger (stderr only until [`attach_file`]). Safe to call
/// more than once; only the first call counts.
pub fn init() {
    let spec = match std::env::var("FISHE_LOG") {
        Ok(s) if !s.trim().is_empty() => format!("{DEFAULT_SPEC},{s}"),
        _ => DEFAULT_SPEC.to_string(),
    };
    let filter = Filter::parse(&spec);
    let max = filter.max();
    let _ = LOGGER.filter.set(filter);
    if log::set_logger(&LOGGER).is_ok() {
        log::set_max_level(max);
    }
}

/// Also write every line to `<dir>/fishe.log` from now on. Returns the file's path.
pub fn attach_file(dir: &Path) -> io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(FILE_NAME);
    let file = LogFile::open(path.clone(), MAX_BYTES)?;
    *LOGGER.file.lock().unwrap_or_else(|e| e.into_inner()) = Some(file);
    Ok(path)
}

fn utc_now() -> String {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    utc(ms)
}

/// `2026-11-08T21:14:03.123Z` for a unix time in milliseconds.
fn utc(ms: u64) -> String {
    let secs = ms / 1000;
    let (y, m, d) = crate::util::civil_from_days((secs / 86_400) as i64);
    let s = secs % 86_400;
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        s / 3600,
        s % 3600 / 60,
        s % 60,
        ms % 1000
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_longest_prefix_wins_and_later_entries_override() {
        let f = Filter::parse(
            "warn, fishe_core=info,fishe_core::lan=trace,hyper=warn,hyper=error,bogus=loud",
        );
        assert_eq!(f.default, LevelFilter::Warn);
        assert_eq!(f.level_for("fishe_core::lan::arp"), LevelFilter::Trace);
        assert_eq!(f.level_for("fishe_core::lan"), LevelFilter::Trace);
        assert_eq!(
            f.level_for("fishe_core::lanes"),
            LevelFilter::Info,
            "prefix ends at ::"
        );
        assert_eq!(
            f.level_for("fishe_core::monitor::engine"),
            LevelFilter::Info
        );
        assert_eq!(f.level_for("hyper::proto"), LevelFilter::Error);
        assert_eq!(f.level_for("rusqlite"), LevelFilter::Warn);
        assert_eq!(f.max(), LevelFilter::Trace);
        assert!(!f.modules.iter().any(|(t, _)| t == "bogus"));
    }

    #[test]
    fn default_spec_is_info_with_a_quiet_http_stack() {
        let f = Filter::parse(DEFAULT_SPEC);
        assert_eq!(f.level_for("fishe_core::mcp"), LevelFilter::Info);
        assert_eq!(f.level_for("hyper::client"), LevelFilter::Warn);
        assert_eq!(f.max(), LevelFilter::Info);
        // The user's setting is appended, so `debug` raises everything but
        // the HTTP stack, which needs its own entry.
        let f = Filter::parse(&format!("{DEFAULT_SPEC},debug,hyper=debug"));
        assert_eq!(f.level_for("fishe_core::lan"), LevelFilter::Debug);
        assert_eq!(f.level_for("hyper"), LevelFilter::Debug);
        assert_eq!(f.level_for("axum"), LevelFilter::Warn);
    }

    #[test]
    fn utc_timestamps() {
        assert_eq!(utc(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(utc(1_700_000_000_123), "2023-11-14T22:13:20.123Z");
        assert_eq!(utc(951_782_400_000), "2000-02-29T00:00:00.000Z");
    }

    #[test]
    fn log_file_appends_then_rotates() {
        let dir = std::env::temp_dir().join(format!("fishe-log-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(FILE_NAME);
        std::fs::write(&path, "old\n").unwrap();

        let mut f = LogFile::open(path.clone(), 40).unwrap();
        assert_eq!(f.size, 4, "appends to what is there");
        f.write("0123456789012345678901234\n").unwrap(); // 26 → 30
        f.write("second\n").unwrap(); // 37
        f.write("third line\n").unwrap(); // would be 48: rotates first
        assert_eq!(f.size, 11);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "third line\n");
        let rotated = std::fs::read_to_string(dir.join(ROTATED_NAME)).unwrap();
        assert!(rotated.starts_with("old\n0123") && rotated.ends_with("second\n"));

        // The next rotation replaces the rotated copy.
        f.write("0123456789012345678901234567890123456\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join(ROTATED_NAME)).unwrap(),
            "third line\n"
        );
        drop(f);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

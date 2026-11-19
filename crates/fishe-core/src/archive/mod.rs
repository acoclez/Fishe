//! Recordings: saving sessions on demand and reading them back.
//!
//! ```text
//!  aggregator ── tick ──▶ RecordingSlot ──▶ recorder thread ──▶ SQLite (fishe.db)
//!  workers ── matched packets ──▶ PacketTap ──▶ pcapng thread ──▶ captures/*.pcapng
//! ```
//!
//! Everything lives in `Paths::archive()` (`%APPDATA%\com.fishe.app\archive`
//! by default). See `docs/archive.md`.

pub mod db;
pub mod export;
pub mod pcapng;
pub mod recorder;

use crate::error::{AppError, AppResult};
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

/// Tauri-managed handle to the archive.
pub struct ArchiveState {
    dir: PathBuf,
    conn: Mutex<Option<Connection>>,
}

impl ArchiveState {
    /// `dir` is created on first use.
    pub fn new(dir: PathBuf) -> Self {
        ArchiveState {
            dir,
            conn: Mutex::new(None),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn db_path(&self) -> PathBuf {
        self.dir.join("fishe.db")
    }

    pub fn captures_dir(&self) -> PathBuf {
        self.dir.join("captures")
    }

    /// The shared read/maintenance connection (opened lazily).
    pub fn conn(&self) -> AppResult<ConnGuard<'_>> {
        let mut guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_none() {
            std::fs::create_dir_all(&self.dir)
                .map_err(|e| AppError::io("cannot create archive folder", e))?;
            let conn = db::open(&self.db_path())?;
            db::recover_interrupted(&conn)?;
            *guard = Some(conn);
        }
        Ok(ConnGuard(guard))
    }
}

pub struct ConnGuard<'a>(MutexGuard<'a, Option<Connection>>);

impl std::ops::Deref for ConnGuard<'_> {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        self.0
            .as_ref()
            .expect("connection opened in ArchiveState::conn")
    }
}

impl From<rusqlite::Error> for AppError {
    fn from(e: rusqlite::Error) -> Self {
        AppError::Internal(format!("archive database: {e}"))
    }
}

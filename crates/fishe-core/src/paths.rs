//! Where Fishe keeps its files. One root, decided once at startup:
//! `FISHE_DATA_DIR` when set (test builds, see `docs/development.md`), else
//! the per-user app data folder (`%APPDATA%\com.fishe.app`).
//!
//! ```text
//! <root>/archive/fishe.db, captures/*.pcapng   recordings   (archive)
//! <root>/geo/*.mmdb, meta.json                 owner data   (geo)
//! <root>/mcp.json                              MCP settings (mcp)
//! <root>/logs/fishe.log, fishe.1.log           log file     (logging)
//! ```

use std::path::{Path, PathBuf};

/// Bundle identifier, as in `tauri.conf.json`; names the app data folder.
pub const IDENTIFIER: &str = "com.fishe.app";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    root: PathBuf,
}

impl Paths {
    /// `FISHE_DATA_DIR` when set and non-empty, else `default`.
    pub fn from_env_or(default: PathBuf) -> Self {
        let root = match std::env::var_os("FISHE_DATA_DIR") {
            Some(d) if !d.is_empty() => PathBuf::from(d),
            _ => default,
        };
        Paths { root }
    }

    /// Exactly this folder, whatever the environment says (tests, tools).
    pub fn at(root: PathBuf) -> Self {
        Paths { root }
    }

    /// For processes without a Tauri app handle (the stdio bridge): the same
    /// folder Tauri's `app_data_dir()` resolves to on Windows.
    pub fn from_env_or_default() -> Self {
        let base = std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_default();
        Self::from_env_or(base.join(IDENTIFIER))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Recordings database and capture files.
    pub fn archive(&self) -> PathBuf {
        self.root.join("archive")
    }

    /// Offline owner / country databases.
    pub fn geo(&self) -> PathBuf {
        self.root.join("geo")
    }

    /// MCP server settings (also read by the stdio bridge).
    pub fn mcp_config(&self) -> PathBuf {
        self.root.join("mcp.json")
    }

    /// The log file and its rotated predecessor.
    pub fn logs(&self) -> PathBuf {
        self.root.join("logs")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_under_root() {
        let p = Paths::from_env_or(PathBuf::from("X:/data"));
        if std::env::var_os("FISHE_DATA_DIR").is_some_and(|d| !d.is_empty()) {
            // The override wins; the layout below still holds under it.
            assert_ne!(p.root(), Path::new("X:/data"));
        } else {
            assert_eq!(p.root(), Path::new("X:/data"));
        }
        let root = p.root().to_path_buf();
        assert_eq!(p.archive(), root.join("archive"));
        assert_eq!(p.geo(), root.join("geo"));
        assert_eq!(p.mcp_config(), root.join("mcp.json"));
        assert_eq!(p.logs(), root.join("logs"));
        assert!(
            Paths::from_env_or_default()
                .root()
                .to_string_lossy()
                .ends_with(IDENTIFIER)
                || std::env::var_os("FISHE_DATA_DIR").is_some()
        );
    }
}

//! Local MCP server: lets AI agents read (and, if allowed, drive) Fishe.
//!
//! - **Transport**: MCP "Streamable HTTP" on `127.0.0.1` only, built on the
//!   official Rust SDK `rmcp` ([`server`]); `fishe.exe --mcp-stdio` bridges
//!   stdio clients to it ([`bridge`]).
//! - **Off by default.** Enabled from Settings → Agents (MCP), with an
//!   access level ([`Access`]) and a bearer token every request must carry.
//! - **Tools** ([`tools`]) are listed and callable only up to the access
//!   level; every call is logged ([`Activity`]) and shown in the app.
//! - Actions an agent takes (start monitoring, record, ping) go through the
//!   same service layer as the UI (`crate::ops`), on the same
//!   [`Services`]; a window follows them through its monitor subscription
//!   and the "changed" notices. The server needs no window: it runs on its
//!   own small async runtime.
//!
//! See `docs/mcp.md`.

pub mod bridge;
mod server;
mod tools;

use crate::services::{Notice, Services};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

pub const DEFAULT_PORT: u16 = 47823;
/// Calls kept in the activity log.
const ACTIVITY_CAP: usize = 200;

/// What agents may do. Each level includes the ones before it.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    Default,
    specta::Type,
)]
#[serde(rename = "McpAccess", rename_all = "camelCase")]
pub enum Access {
    /// Read live data, recordings, traces, pings.
    #[default]
    Read,
    /// Also start/stop monitoring and recording.
    Control,
    /// Also send packets: traceroute, ping.
    Network,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct McpConfig {
    pub enabled: bool,
    pub access: Access,
    pub port: u16,
    /// Bearer token required on every request.
    pub token: String,
}

impl Default for McpConfig {
    fn default() -> Self {
        McpConfig {
            enabled: false,
            access: Access::Read,
            port: DEFAULT_PORT,
            token: new_token(),
        }
    }
}

/// 192 random bits, hex.
pub fn new_token() -> String {
    let mut b = [0u8; 24];
    if getrandom::fill(&mut b).is_err() {
        // Extremely unlikely; fall back to time-derived bytes rather than a constant.
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        for (i, x) in b.iter_mut().enumerate() {
            *x = (t >> ((i % 16) * 8)) as u8 ^ (i as u8).wrapping_mul(151);
        }
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn load_config(path: &Path) -> McpConfig {
    let mut cfg: McpConfig = std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    if cfg.token.len() < 32 {
        cfg.token = new_token();
    }
    if cfg.port < 1024 {
        cfg.port = DEFAULT_PORT;
    }
    cfg
}

fn save_config(path: &Path, cfg: &McpConfig) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    std::fs::write(path, json).map_err(|e| format!("cannot save {}: {e}", path.display()))
}

/// One tool call, for the activity log.
#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(rename = "McpActivity", rename_all = "camelCase")]
pub struct Activity {
    /// Unix ms.
    pub at_ms: u64,
    pub tool: String,
    /// Arguments, compact and truncated.
    pub args: String,
    pub ok: bool,
    pub duration_ms: u64,
    /// Error message, or a short result note.
    pub note: String,
    /// The client, from `initialize` (e.g. "claude-code 2.1").
    pub client: String,
}

/// Shown in Settings.
#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct McpStatus {
    pub enabled: bool,
    pub access: Access,
    pub port: u16,
    pub running: bool,
    pub error: Option<String>,
    pub url: String,
    pub token: String,
    pub calls: u64,
    /// The configuration file (the stdio bridge reads it).
    pub config_path: String,
    /// This executable, for the stdio bridge command line.
    pub exe_path: Option<String>,
}

/// The MCP server's settings, listener and activity log (part of [`Services`]).
pub struct McpState {
    path: PathBuf,
    config: Mutex<McpConfig>,
    server: Mutex<Option<server::Handle>>,
    error: Mutex<Option<String>>,
    activity: Mutex<VecDeque<Activity>>,
    calls: AtomicU64,
}

impl McpState {
    /// `path` is the settings file (`Paths::mcp_config()`), created on first save.
    pub fn new(path: PathBuf) -> Self {
        let config = load_config(&path);
        McpState {
            path,
            config: Mutex::new(config),
            server: Mutex::new(None),
            error: Mutex::new(None),
            activity: Mutex::new(VecDeque::new()),
            calls: AtomicU64::new(0),
        }
    }

    fn cfg(&self) -> McpConfig {
        self.config
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn access(&self) -> Access {
        self.cfg().access
    }

    pub fn token(&self) -> String {
        self.cfg().token
    }

    /// Start or stop the server to match the configuration. The server
    /// keeps a weak reference to `svc`, the services its tools work on.
    pub fn apply(&self, svc: &Arc<Services>) {
        let cfg = self.cfg();
        let mut server = self.server.lock().unwrap_or_else(|e| e.into_inner());
        // Dropping the handle stops the listener (and frees the port).
        *server = None;
        let mut error = self.error.lock().unwrap_or_else(|e| e.into_inner());
        *error = None;
        if !cfg.enabled {
            return;
        }
        match server::serve(Arc::downgrade(svc), cfg.port) {
            Ok(h) => {
                log::info!("MCP server on http://127.0.0.1:{}/mcp", cfg.port);
                *server = Some(h);
            }
            Err(e) => {
                log::warn!("MCP server could not start: {e}");
                *error = Some(e);
            }
        }
    }

    pub fn status(&self) -> McpStatus {
        let cfg = self.cfg();
        McpStatus {
            enabled: cfg.enabled,
            access: cfg.access,
            port: cfg.port,
            running: self
                .server
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_some(),
            error: self.error.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            url: format!("http://127.0.0.1:{}/mcp", cfg.port),
            token: cfg.token,
            calls: self.calls.load(Ordering::Relaxed),
            config_path: self.path.display().to_string(),
            exe_path: std::env::current_exe()
                .ok()
                .map(|p| p.display().to_string()),
        }
    }

    pub fn configure(
        &self,
        svc: &Arc<Services>,
        enabled: bool,
        access: Access,
        port: u16,
    ) -> Result<McpStatus, String> {
        if port < 1024 {
            return Err("choose a port between 1024 and 65535".into());
        }
        let restart = {
            let mut cfg = self.config.lock().unwrap_or_else(|e| e.into_inner());
            let restart = cfg.enabled != enabled || cfg.port != port;
            cfg.enabled = enabled;
            cfg.access = access;
            cfg.port = port;
            save_config(&self.path, &cfg)?;
            restart
        };
        // The access level is checked on every call: no restart needed for it.
        let running = self
            .server
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some();
        if restart || (enabled && !running) {
            self.apply(svc);
        }
        Ok(self.status())
    }

    /// Replace the token (existing clients must be reconfigured).
    pub fn new_token(&self) -> Result<McpStatus, String> {
        {
            let mut cfg = self.config.lock().unwrap_or_else(|e| e.into_inner());
            cfg.token = new_token();
            save_config(&self.path, &cfg)?;
        }
        Ok(self.status())
    }

    pub fn activity(&self) -> Vec<Activity> {
        self.activity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .rev()
            .cloned()
            .collect()
    }

    pub fn clear_activity(&self) {
        self.activity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    /// Log a call and tell whoever listens (the window).
    fn record(&self, svc: &Services, a: Activity) {
        self.calls.fetch_add(1, Ordering::Relaxed);
        {
            let mut log = self.activity.lock().unwrap_or_else(|e| e.into_inner());
            if log.len() >= ACTIVITY_CAP {
                log.pop_front();
            }
            log.push_back(a.clone());
        }
        svc.notify(Notice::McpActivity(a));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_and_round_trip() {
        let dir = std::env::temp_dir().join(format!("fishe-mcp-test-{}", std::process::id()));
        let path = dir.join("mcp.json");
        let _ = std::fs::remove_file(&path);
        let c = load_config(&path);
        assert!(!c.enabled, "off by default");
        assert_eq!(c.access, Access::Read);
        assert_eq!(c.port, DEFAULT_PORT);
        assert_eq!(c.token.len(), 48);
        assert_ne!(c.token, new_token(), "random");
        let mut c2 = c.clone();
        c2.enabled = true;
        c2.access = Access::Network;
        save_config(&path, &c2).unwrap();
        let back = load_config(&path);
        assert!(back.enabled);
        assert_eq!(back.access, Access::Network);
        assert_eq!(back.token, c.token);
        assert!(Access::Read < Access::Control && Access::Control < Access::Network);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

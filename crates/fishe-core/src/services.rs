//! Everything Fishe's operations work on, in one plain value.
//!
//! The window (the Tauri commands) and the agents (the MCP tools) are two
//! front doors onto the same [`Services`]. Nothing in it knows about a
//! window or a GUI toolkit: what a window needs to hear leaves through
//! callbacks it registers, [`Services::on_notice`] here and
//! [`MonitorState::subscribe`] for the session events. With nobody
//! listening (a headless run, a test) the same code just runs quietly.

use crate::archive::ArchiveState;
use crate::geo::Geo;
use crate::lan::inventory::LanState;
use crate::mcp::{Activity, McpState};
use crate::monitor::MonitorState;
use crate::paths::Paths;
use crate::route::ping::PingBook;
use crate::route::trace::TraceBook;
use std::sync::{Arc, Mutex};

/// Something changed that has no event stream of its own: whoever shows
/// Fishe reads it back (pings, traces) or appends it (agent calls).
#[derive(Debug, Clone)]
pub enum Notice {
    /// A ping started, stopped or was removed, by anyone.
    PingsChanged,
    /// A traceroute finished, by anyone.
    TracesChanged,
    /// An agent called a tool.
    McpActivity(Activity),
}

type NoticeFn = Box<dyn Fn(Notice) + Send + Sync>;

/// The state of one running Fishe. Created once, shared behind an [`Arc`].
pub struct Services {
    /// Where the data folder is and how it is laid out.
    pub paths: Paths,
    /// The capture session (at most one) and what it measures.
    pub monitor: MonitorState,
    /// Recordings.
    pub archive: ArchiveState,
    /// Owner and country of addresses.
    pub geo: Arc<Geo>,
    /// Traceroutes of this run.
    pub traces: TraceBook,
    /// Running and finished pings.
    pub pings: PingBook,
    /// The MCP server for agents: settings, listener, activity log.
    pub mcp: McpState,
    /// Devices seen on the local networks, remembered between scans.
    pub lan: LanState,
    listener: Mutex<Option<NoticeFn>>,
}

impl Services {
    /// Set everything up under `paths`. Opens nothing yet: the archive
    /// database, the capture and the MCP listener start on first use (see
    /// [`McpState::apply`] for the listener).
    pub fn new(paths: Paths) -> Arc<Self> {
        Arc::new(Services {
            monitor: MonitorState::default(),
            archive: ArchiveState::new(paths.archive()),
            geo: Arc::new(Geo::new(paths.geo())),
            traces: TraceBook::default(),
            pings: PingBook::default(),
            mcp: McpState::new(paths.mcp_config()),
            lan: LanState::new(paths.lan_inventory()),
            listener: Mutex::new(None),
            paths,
        })
    }

    /// Who to tell about [`Notice`]s (the window). One listener; a new one
    /// replaces the previous.
    pub fn on_notice(&self, f: impl Fn(Notice) + Send + Sync + 'static) {
        *self.listener.lock().unwrap_or_else(|e| e.into_inner()) = Some(Box::new(f));
    }

    /// Tell the listener, if there is one.
    pub fn notify(&self, notice: Notice) {
        if let Some(f) = self
            .listener
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            f(notice);
        }
    }

    /// Stop everything that sends or captures packets: the session and any
    /// ping still running (they would otherwise probe until the process dies).
    pub fn shutdown(&self) {
        self.pings.stop_all();
        self.monitor.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notices_reach_the_listener_and_nobody_listening_is_fine() {
        let dir = std::env::temp_dir().join(format!("fishe-services-{}", std::process::id()));
        let svc = Services::new(Paths::at(dir.clone()));
        // No listener yet: nothing happens.
        svc.notify(Notice::PingsChanged);

        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        svc.on_notice(move |n| {
            log.lock().unwrap().push(match n {
                Notice::PingsChanged => "pings",
                Notice::TracesChanged => "traces",
                Notice::McpActivity(_) => "activity",
            })
        });
        svc.notify(Notice::PingsChanged);
        svc.notify(Notice::TracesChanged);
        assert_eq!(*seen.lock().unwrap(), ["pings", "traces"]);

        // Every part lives under the data folder it was given.
        assert_eq!(svc.paths.root(), dir.as_path());
        assert!(svc.archive.dir().starts_with(&dir));
        // Nothing runs, so shutting down is a no-op.
        svc.shutdown();
        assert!(svc.monitor.status().is_none());
        std::fs::remove_dir_all(&dir).ok();
    }
}

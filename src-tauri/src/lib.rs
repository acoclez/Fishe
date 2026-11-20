//! Fishe, the desktop app: the window, the IPC commands and the generated
//! TypeScript bindings.
//!
//! Everything it shows comes from `fishe-core` (measurement, recordings,
//! probes, the MCP server). This crate creates one [`Services`] at startup,
//! hands it to the commands as Tauri state, and turns what the core tells a
//! window into Tauri events. See `docs/architecture.md`.

mod commands;

use fishe_core::services::{Notice, Services};
use fishe_core::{logging, npcap, paths};
use specta_typescript::semantic;
use std::sync::Arc;
use tauri::{Emitter, Manager, RunEvent};
use tauri_specta::{Builder, ErrorHandlingMode, collect_commands};

/// Tauri event: a ping started, stopped or was removed, by anyone.
const PINGS_CHANGED: &str = "fishe://pings-changed";
/// Tauri event: a traceroute finished, by anyone.
const TRACES_CHANGED: &str = "fishe://traces-changed";
/// Tauri event: an agent called a tool (payload: the activity entry).
const MCP_ACTIVITY: &str = "fishe://mcp-activity";

/// Where the TypeScript bindings are written (relative to this crate).
const BINDINGS_PATH: &str = "../src/lib/api/bindings.ts";

/// The IPC surface: every command, with the types it uses. `tauri dev` and
/// `cargo test` regenerate `src/lib/api/bindings.ts` from it (see
/// `docs/ipc-api.md`).
fn ipc_builder() -> Builder<tauri::Wry> {
    Builder::<tauri::Wry>::new()
        .error_handling(ErrorHandlingMode::Throw)
        // One TypeScript type per Rust type: the UI reads what the backend
        // serialises, so the serialize/deserialize split is noise here.
        .disable_serde_phases()
        // u64 / i64 fields are byte counts and unix-ms timestamps, always far
        // below 2^53; the UI reads them as plain numbers.
        .dangerously_cast_bigints_to_number()
        // f64 as `number`, not `number | null`: serde_json never produces NaN
        // or infinities here (rates and ratios are finite by construction).
        .semantic_types(semantic::Configuration::empty().enable_lossless_floats())
        .commands(collect_commands![
            commands::npcap_status,
            commands::npcap_recheck,
            commands::open_npcap_site,
            commands::default_gauge_config,
            commands::list_interfaces,
            commands::resolve_target,
            commands::suggest_interface,
            commands::list_processes,
            commands::system_capabilities,
            commands::start_recording,
            commands::stop_recording,
            commands::list_recordings,
            commands::get_recording,
            commands::get_endpoint_series,
            commands::rename_recording,
            commands::delete_recording,
            commands::export_recording,
            commands::archive_location,
            commands::reveal_in_folder,
            commands::logs_location,
            commands::open_logs_folder,
            commands::geo_status,
            commands::geo_download,
            commands::geo_remove,
            commands::set_online_lookup,
            commands::geo_lookup,
            commands::trace_route,
            commands::ping_start,
            commands::ping_stop,
            commands::ping_remove,
            commands::ping_status,
            commands::mcp_status,
            commands::mcp_configure,
            commands::mcp_new_token,
            commands::mcp_activity,
            commands::mcp_clear_activity,
            commands::cached_traces,
            commands::network_context,
            commands::scan_lan,
            commands::subscribe_monitor,
            commands::set_monitor_defaults,
            commands::start_monitor,
            commands::stop_monitor,
            commands::monitor_status,
            commands::set_packet_feed,
            commands::recent_packets,
        ])
}

/// Write `src/lib/api/bindings.ts` from the Rust definitions.
#[cfg(any(debug_assertions, test))]
fn export_bindings(path: &std::path::Path) -> Result<(), specta_typescript::Error> {
    ipc_builder().export(
        specta_typescript::Typescript::default().header(BINDINGS_HEADER),
        path,
    )
}

#[cfg(any(debug_assertions, test))]
const BINDINGS_HEADER: &str =
    "// Generated from the Rust IPC types by tauri-specta (src-tauri/src/lib.rs).
// Regenerate with `cargo test` or `npm run tauri dev`; do not edit by hand.

/* eslint-disable */";

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    logging::init();

    // Must run before any pcap call: wpcap.dll is delay-loaded from the Npcap folder.
    let status = npcap::init();
    if status.available {
        log::info!(
            "capture ready: {}",
            status.version.as_deref().unwrap_or("unknown version")
        );
    } else {
        log::warn!(
            "capture unavailable: {}",
            status.message.as_deref().unwrap_or("-")
        );
    }

    let ipc = ipc_builder();
    #[cfg(debug_assertions)]
    if let Err(e) =
        export_bindings(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(BINDINGS_PATH))
    {
        log::warn!("could not write {BINDINGS_PATH}: {e}");
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            // FISHE_DATA_DIR keeps test builds away from the real archive
            // and owner database (see docs/development.md).
            let paths = paths::Paths::from_env_or(app.path().app_data_dir()?);
            match logging::attach_file(&paths.logs()) {
                Ok(p) => log::info!("log file: {}", p.display()),
                Err(e) => log::warn!("no log file ({}): {e}", paths.logs().display()),
            }
            log::info!("data folder: {}", paths.root().display());
            let services = Services::new(paths);
            // What the window re-reads or appends when something changes
            // that has no event stream of its own (see src/lib/stores/agents.svelte.ts).
            let window = app.handle().clone();
            services.on_notice(move |notice| {
                let _ = match notice {
                    Notice::PingsChanged => window.emit(PINGS_CHANGED, ()),
                    Notice::TracesChanged => window.emit(TRACES_CHANGED, ()),
                    Notice::McpActivity(call) => window.emit(MCP_ACTIVITY, call),
                };
            });
            services.mcp.apply(&services);
            app.manage(services);
            Ok(())
        })
        .invoke_handler(ipc.invoke_handler())
        .build(tauri::generate_context!())
        .expect("error while building Fishe")
        .run(|app, event| {
            if let RunEvent::Exit = event {
                app.state::<Arc<Services>>().shutdown();
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `src/lib/api/bindings.ts` must match the Rust types. If it doesn't, this
    /// rewrites it and fails once; re-run and check the new file in.
    #[test]
    fn bindings_are_current() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(BINDINGS_PATH);
        let before = std::fs::read_to_string(&path)
            .map(|s| s.replace("\r\n", "\n"))
            .unwrap_or_default();
        export_bindings(&path).expect("bindings export failed");
        let after = std::fs::read_to_string(&path).expect("bindings.ts not written");
        assert!(
            before == after.replace("\r\n", "\n"),
            "{BINDINGS_PATH} was stale and has been regenerated: run the tests again and check it in"
        );
    }
}

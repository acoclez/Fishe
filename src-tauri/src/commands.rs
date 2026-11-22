//! Tauri command handlers: the IPC surface used by the frontend.
//!
//! Thin: argument shapes and Tauri plumbing live here, the work that the MCP
//! tools share lives in `ops.rs`, and all state in the one [`Services`]
//! value Tauri manages. Commands that may block (DNS, device enumeration,
//! joining the capture thread) run on Tauri's blocking pool so the UI thread
//! never stalls. See `docs/ipc-api.md` for the full contract.

use fishe_core::archive::db::{self, RecordingDetail, RecordingSummary, SeriesPoint};
use fishe_core::archive::export::{self, ExportFormat};
use fishe_core::archive::recorder::{RecordOptions, RecordingInfo};
use fishe_core::error::{AppError, AppResult};
use fishe_core::geo::{self, Geo, Owner};
use fishe_core::mcp::{Access, Activity, McpStatus};
use fishe_core::monitor::events::MonitorEvent;
use fishe_core::monitor::gauge::GaugeConfig;
use fishe_core::monitor::{SessionDefaults, SessionInfo, StartRequest};
use fishe_core::net::interfaces;
use fishe_core::net::interfaces::InterfaceInfo;
use fishe_core::net::resolve::{self, ResolvedTarget};
use fishe_core::npcap::{self, NpcapStatus};
use fishe_core::ops;
use fishe_core::process::elevation;
use fishe_core::process::processes::{self, ProcessGroup};
use fishe_core::route::TraceResult;
use fishe_core::route::lan::{self, NetContext};
use fishe_core::route::ping::PingStatus;
use fishe_core::security::SecurityReport;
use fishe_core::services::Services;
use std::sync::Arc;
use tauri::ipc::Channel;

/// The one piece of managed state: everything the commands work on.
type Svc<'a> = tauri::State<'a, Arc<Services>>;

async fn blocking<T, F>(f: F) -> AppResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> AppResult<T> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| AppError::Internal(format!("worker task failed: {e}")))?
}

/// Hand a folder or a web address to the desktop: Explorer on Windows, the
/// user's file manager or browser elsewhere.
fn open_on_desktop(target: &std::ffi::OsStr, what: &'static str) -> AppResult<()> {
    let program = if cfg!(windows) {
        "explorer"
    } else if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    let mut child = std::process::Command::new(program)
        .arg(target)
        .spawn()
        .map_err(|e| AppError::io(what, e))?;
    // Collect its exit status when it ends, so no finished process lingers.
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

/// Whether Npcap was found, and its version.
#[tauri::command]
#[specta::specta]
pub fn npcap_status() -> NpcapStatus {
    npcap::init()
}

/// Look for Npcap again, after the user installed it while Fishe was running.
/// (On Linux the answer cannot change while Fishe runs: see `npcap.rs`.)
#[tauri::command]
#[specta::specta]
pub fn npcap_recheck() -> NpcapStatus {
    let status = npcap::recheck();
    match &status.message {
        None => log::info!(
            "capture available: {}",
            status.version.as_deref().unwrap_or("unknown version")
        ),
        Some(why) => log::info!("capture still unavailable: {why}"),
    }
    status
}

/// Open Npcap's download page in the default browser. The address is fixed
/// (`npcap::DOWNLOAD_URL`): the window cannot make the app open anything else.
/// Windows only: nowhere else is there anything to download.
#[tauri::command]
#[specta::specta]
pub fn open_npcap_site() -> AppResult<()> {
    #[cfg(windows)]
    open_on_desktop(npcap::DOWNLOAD_URL.as_ref(), "cannot open the browser")?;
    Ok(())
}

/// Default detector settings, so the UI can show and edit them.
#[tauri::command]
#[specta::specta]
pub fn default_gauge_config() -> GaugeConfig {
    GaugeConfig::default()
}

/// All capture interfaces.
#[tauri::command]
#[specta::specta]
pub async fn list_interfaces() -> AppResult<Vec<InterfaceInfo>> {
    blocking(ops::list_interfaces).await
}

/// Resolve an IP literal or host name.
#[tauri::command]
#[specta::specta]
pub async fn resolve_target(input: String) -> AppResult<ResolvedTarget> {
    blocking(move || resolve::resolve(&input)).await
}

/// Name of the interface that routes to `target`, if one can be determined.
#[tauri::command]
#[specta::specta]
pub async fn suggest_interface(target: String) -> AppResult<Option<String>> {
    blocking(move || {
        let ip = resolve::resolve(&target)?.ip;
        let devices = interfaces::list_devices()?;
        Ok(interfaces::pick_for(ip, &devices).map(|d| d.name))
    })
    .await
}

/// Processes grouped by executable, busiest network users first.
#[tauri::command]
#[specta::specta]
pub async fn list_processes() -> AppResult<Vec<ProcessGroup>> {
    blocking(processes::groups).await
}

/// The system Fishe runs on, for the wording that differs (how capture is
/// allowed, what the file manager is called).
#[derive(serde::Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub enum Platform {
    Windows,
    Linux,
    Other,
}

/// What this instance can do (elevation decides whether ETW is used).
#[derive(serde::Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    pub platform: Platform,
    pub process_mode: bool,
    /// Administrator on Windows, root on Linux.
    pub elevated: bool,
    pub etw: bool,
}

#[tauri::command]
#[specta::specta]
pub fn system_capabilities() -> Capabilities {
    let elevated = elevation::is_elevated();
    Capabilities {
        platform: if cfg!(windows) {
            Platform::Windows
        } else if cfg!(target_os = "linux") {
            Platform::Linux
        } else {
            Platform::Other
        },
        process_mode: fishe_core::process::SUPPORTED,
        elevated,
        etw: cfg!(windows) && elevated,
    }
}

/// Receive every monitor event (sessions, samples, recordings) from now on,
/// whoever starts them. Called once when the window mounts; a running
/// session is announced at once with `started`.
#[tauri::command]
#[specta::specta]
pub fn subscribe_monitor(svc: Svc<'_>, on_event: Channel<MonitorEvent>) {
    // A failed send means the webview is gone: the sink then drops us.
    svc.monitor
        .subscribe(move |event| on_event.send(event).is_ok());
}

/// The window's start settings (sensitivity, reverse DNS), used for sessions
/// that agents start so they measure like one started with the button.
#[tauri::command]
#[specta::specta]
pub fn set_monitor_defaults(svc: Svc<'_>, defaults: SessionDefaults) {
    svc.monitor.set_defaults(defaults);
}

/// Start monitoring (stopping any running session); events arrive through
/// `subscribe_monitor`.
#[tauri::command]
#[specta::specta]
pub async fn start_monitor(svc: Svc<'_>, request: StartRequest) -> AppResult<SessionInfo> {
    let svc = svc.inner().clone();
    blocking(move || ops::start_monitor(&svc, request)).await
}

/// Stop monitoring. Returns `true` if a session was running.
#[tauri::command]
#[specta::specta]
pub async fn stop_monitor(svc: Svc<'_>) -> AppResult<bool> {
    let svc = svc.inner().clone();
    blocking(move || Ok(ops::stop_monitor(&svc))).await
}

/// The active session, if any.
#[tauri::command]
#[specta::specta]
pub fn monitor_status(svc: Svc<'_>) -> Option<SessionInfo> {
    svc.monitor.status()
}

/// Turn the live packet list (Packets view) on or off. `false` if idle.
#[tauri::command]
#[specta::specta]
pub fn set_packet_feed(svc: Svc<'_>, enabled: bool) -> bool {
    svc.monitor.set_packet_feed(enabled)
}

/// Latest counted packets after sequence number `after` (headers only).
#[tauri::command]
#[specta::specta]
pub fn recent_packets(
    svc: Svc<'_>,
    after: Option<u64>,
    limit: Option<u32>,
) -> fishe_core::monitor::packets::PacketBatch {
    svc.monitor
        .recent_packets(after, limit.unwrap_or(500) as usize)
}

// ─────────────────────────── recording & archive ───────────────────────────

use ops::with_archive;

/// Start recording the running session.
#[tauri::command]
#[specta::specta]
pub async fn start_recording(svc: Svc<'_>, options: RecordOptions) -> AppResult<RecordingInfo> {
    let svc = svc.inner().clone();
    blocking(move || ops::start_recording(&svc, options)).await
}

/// Stop the active recording; returns what was saved.
#[tauri::command]
#[specta::specta]
pub async fn stop_recording(svc: Svc<'_>) -> AppResult<Option<RecordingInfo>> {
    let svc = svc.inner().clone();
    blocking(move || Ok(ops::stop_recording(&svc))).await
}

#[tauri::command]
#[specta::specta]
pub async fn list_recordings(svc: Svc<'_>) -> AppResult<Vec<RecordingSummary>> {
    let svc = svc.inner().clone();
    blocking(move || with_archive(&svc, db::list)).await
}

#[tauri::command]
#[specta::specta]
pub async fn get_recording(svc: Svc<'_>, id: i64) -> AppResult<RecordingDetail> {
    let svc = svc.inner().clone();
    blocking(move || with_archive(&svc, |c| db::detail(c, id))).await
}

#[tauri::command]
#[specta::specta]
pub async fn get_endpoint_series(svc: Svc<'_>, id: i64, ip: String) -> AppResult<Vec<SeriesPoint>> {
    let svc = svc.inner().clone();
    blocking(move || with_archive(&svc, |c| db::endpoint_series(c, id, &ip))).await
}

#[tauri::command]
#[specta::specta]
pub async fn rename_recording(svc: Svc<'_>, id: i64, name: String) -> AppResult<()> {
    let svc = svc.inner().clone();
    blocking(move || with_archive(&svc, |c| db::rename(c, id, &name))).await
}

/// Permanently delete a recording and its capture file.
#[tauri::command]
#[specta::specta]
pub async fn delete_recording(svc: Svc<'_>, id: i64) -> AppResult<()> {
    let svc = svc.inner().clone();
    blocking(move || with_archive(&svc, |c| db::delete(c, id).map(|_| ()))).await
}

/// Ask where to save, then write the recording there. Returns the path, or
/// `None` when the dialog was cancelled.
///
/// The dialog opens here, not in the window: the window can only suggest a
/// file name, so the one place a recording can be written to is a place the
/// user just picked.
#[tauri::command]
#[specta::specta]
pub async fn export_recording(
    window: tauri::WebviewWindow,
    svc: Svc<'_>,
    id: i64,
    format: ExportFormat,
    suggested_name: String,
) -> AppResult<Option<String>> {
    use tauri_plugin_dialog::DialogExt;
    let svc = svc.inner().clone();
    blocking(move || {
        let ext = format.extension();
        let picked = window
            .dialog()
            .file()
            .set_parent(&window)
            .set_file_name(export::suggested_file_name(&suggested_name, format))
            .add_filter(ext.to_uppercase(), &[ext])
            .blocking_save_file()
            .and_then(|p| p.into_path().ok());
        let Some(path) = picked else {
            return Ok(None);
        };
        with_archive(&svc, |c| export::export(c, id, format, &path))?;
        Ok(Some(path.display().to_string()))
    })
    .await
}

/// Where recordings are stored.
#[tauri::command]
#[specta::specta]
pub fn archive_location(svc: Svc<'_>) -> String {
    svc.archive.dir().display().to_string()
}

/// Show a file from the archive folder in the file manager: selected in
/// Explorer on Windows; elsewhere its folder is opened.
#[tauri::command]
#[specta::specta]
pub fn reveal_in_folder(svc: Svc<'_>, path: String) -> AppResult<()> {
    let p = std::path::PathBuf::from(&path);
    let inside = p
        .canonicalize()
        .ok()
        .zip(svc.archive.dir().canonicalize().ok())
        .is_some_and(|(p, dir)| p.starts_with(dir));
    if !inside {
        return Err(AppError::InvalidArgument(
            "only files in the Fishe archive can be revealed".into(),
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        std::process::Command::new("explorer")
            .raw_arg(format!("/select,\"{}\"", p.display()))
            .spawn()
            .map_err(|e| AppError::io("cannot open Explorer", e))?;
    }
    #[cfg(not(windows))]
    open_on_desktop(
        p.parent().unwrap_or(&p).as_os_str(),
        "cannot open the file manager",
    )?;
    Ok(())
}

// ─────────────────────────── diagnostics ───────────────────────────

/// Folder holding `fishe.log` (and the rotated `fishe.1.log`).
#[tauri::command]
#[specta::specta]
pub fn logs_location(svc: Svc<'_>) -> String {
    svc.paths.logs().display().to_string()
}

/// Open the logs folder in the file manager (created if it does not exist yet).
#[tauri::command]
#[specta::specta]
pub fn open_logs_folder(svc: Svc<'_>) -> AppResult<()> {
    let dir = svc.paths.logs();
    std::fs::create_dir_all(&dir).map_err(|e| AppError::io("cannot create the logs folder", e))?;
    open_on_desktop(dir.as_os_str(), "cannot open the file manager")
}

// ─────────────────────────── owner & country ───────────────────────────

#[derive(serde::Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct GeoStatus {
    pub installed: bool,
    pub has_asn: bool,
    pub has_country: bool,
    /// Release month of the installed files, "YYYY-MM".
    pub month: Option<String>,
    /// Database build time, unix ms.
    pub built_at: Option<i64>,
    pub downloaded_at: Option<i64>,
    pub current_month: String,
    pub update_available: bool,
    pub bytes: u64,
    pub online_enabled: bool,
    pub attribution: &'static str,
    pub dir: String,
}

fn geo_status_of(geo: &Geo) -> GeoStatus {
    let dbs = geo.dbs();
    let current_month = geo::download::current_month();
    let month = dbs
        .as_ref()
        .and_then(|d| d.meta.as_ref().map(|m| m.month.clone()));
    let bytes = [geo::db::ASN_FILE, geo::db::COUNTRY_FILE]
        .iter()
        .filter_map(|f| std::fs::metadata(geo.dir().join(f)).ok())
        .map(|m| m.len())
        .sum();
    GeoStatus {
        installed: dbs.is_some(),
        has_asn: dbs.as_ref().is_some_and(|d| d.has_asn()),
        has_country: dbs.as_ref().is_some_and(|d| d.has_country()),
        update_available: dbs.is_some() && month.as_deref() != Some(current_month.as_str()),
        month,
        built_at: dbs
            .as_ref()
            .and_then(|d| d.build_epoch())
            .map(|s| s as i64 * 1000),
        downloaded_at: dbs
            .as_ref()
            .and_then(|d| d.meta.as_ref().map(|m| m.downloaded_at)),
        current_month,
        bytes,
        online_enabled: geo.online.enabled(),
        attribution: geo::ATTRIBUTION,
        dir: geo.dir().display().to_string(),
    }
}

#[tauri::command]
#[specta::specta]
pub fn geo_status(svc: Svc<'_>) -> GeoStatus {
    geo_status_of(&svc.geo)
}

/// Download (or update) DB-IP Lite. Only ever called from the user's click.
#[tauri::command]
#[specta::specta]
pub async fn geo_download(
    svc: Svc<'_>,
    on_progress: Channel<geo::download::Progress>,
) -> AppResult<GeoStatus> {
    let svc = svc.inner().clone();
    blocking(move || {
        let geo = svc.geo.clone();
        geo::download::install(geo.dir(), |p| {
            let _ = on_progress.send(p);
        })?;
        geo.reload();
        Ok(geo_status_of(&geo))
    })
    .await
}

/// Delete the downloaded database files.
#[tauri::command]
#[specta::specta]
pub async fn geo_remove(svc: Svc<'_>) -> AppResult<GeoStatus> {
    let svc = svc.inner().clone();
    blocking(move || {
        let geo = svc.geo.clone();
        for f in [geo::db::ASN_FILE, geo::db::COUNTRY_FILE, geo::db::META_FILE] {
            let p = geo.dir().join(f);
            if p.exists() {
                std::fs::remove_file(&p)
                    .map_err(|e| AppError::io(format_args!("cannot delete {}", p.display()), e))?;
            }
        }
        geo.reload();
        Ok(geo_status_of(&geo))
    })
    .await
}

/// Opt in/out of ipinfo.io lookups for addresses the offline data doesn't cover.
#[tauri::command]
#[specta::specta]
pub fn set_online_lookup(svc: Svc<'_>, enabled: bool) -> GeoStatus {
    svc.geo.online.set_enabled(enabled);
    geo_status_of(&svc.geo)
}

/// Owner of one address (host mode header). May queue an online lookup.
#[tauri::command]
#[specta::specta]
pub fn geo_lookup(svc: Svc<'_>, ip: String) -> Option<Owner> {
    ip.parse().ok().and_then(|ip| ops::owner(&svc, ip))
}

// ─────────────────────────── routes / network map ───────────────────────────

/// Traceroute to `ip` (ICMP, no admin). Cached for 10 minutes unless `force`.
/// Sends real probes: only called from an explicit user action.
#[tauri::command]
#[specta::specta]
pub async fn trace_route(svc: Svc<'_>, ip: String, force: bool) -> AppResult<TraceResult> {
    let svc = svc.inner().clone();
    let target = ops::probe_target(&ip)?;
    blocking(move || Ok(ops::trace_route(&svc, target, force))).await
}

/// Start pinging `ip` once per second (ICMP). Sends real probes: only
/// called from an explicit user action. At most 4 at once, 30 min each.
#[tauri::command]
#[specta::specta]
pub fn ping_start(svc: Svc<'_>, ip: String) -> AppResult<PingStatus> {
    ops::ping_start(&svc, ops::probe_target(&ip)?)
}

/// Stop pinging `ip`; its figures stay until `ping_remove` or the next `ping_start`.
#[tauri::command]
#[specta::specta]
pub fn ping_stop(svc: Svc<'_>, ip: String) -> AppResult<bool> {
    Ok(ops::ping_stop(&svc, ops::probe_target(&ip)?))
}

/// Forget a ping target (stopping it if needed).
#[tauri::command]
#[specta::specta]
pub fn ping_remove(svc: Svc<'_>, ip: String) -> AppResult<()> {
    ops::ping_remove(&svc, ops::probe_target(&ip)?);
    Ok(())
}

/// Every ping target of this run with its live figures.
#[tauri::command]
#[specta::specta]
pub fn ping_status(svc: Svc<'_>) -> Vec<PingStatus> {
    svc.pings.status()
}

// ─────────────────────────────── MCP ───────────────────────────────

/// The local MCP server's settings and state (Settings → Agents).
#[tauri::command]
#[specta::specta]
pub fn mcp_status(svc: Svc<'_>) -> McpStatus {
    svc.mcp.status()
}

/// Enable/disable the MCP server, set its access level and port.
#[tauri::command]
#[specta::specta]
pub fn mcp_configure(
    svc: Svc<'_>,
    enabled: bool,
    access: Access,
    port: u16,
) -> AppResult<McpStatus> {
    svc.mcp
        .configure(svc.inner(), enabled, access, port)
        .map_err(AppError::Internal)
}

/// Replace the MCP token (clients must be updated).
#[tauri::command]
#[specta::specta]
pub fn mcp_new_token(svc: Svc<'_>) -> AppResult<McpStatus> {
    svc.mcp.new_token().map_err(AppError::Internal)
}

/// Agent calls, newest first (at most 200).
#[tauri::command]
#[specta::specta]
pub fn mcp_activity(svc: Svc<'_>) -> Vec<Activity> {
    svc.mcp.activity()
}

#[tauri::command]
#[specta::specta]
pub fn mcp_clear_activity(svc: Svc<'_>) {
    svc.mcp.clear_activity();
}

/// Traces done this run (restores the map after switching views).
#[tauri::command]
#[specta::specta]
pub fn cached_traces(svc: Svc<'_>) -> Vec<TraceResult> {
    svc.traces.cached()
}

/// Default gateways and the LAN neighbour table.
#[tauri::command]
#[specta::specta]
pub async fn network_context() -> AppResult<NetContext> {
    blocking(|| Ok(lan::context())).await
}

/// Scan the local network(s) for devices: an ARP sweep, then MAC vendors,
/// reverse-DNS names and (when `probePorts`) a probe of a few common ports.
/// Sends packets, so it runs only when the user asks.
#[tauri::command]
#[specta::specta]
pub async fn scan_lan(svc: Svc<'_>, probe_ports: bool) -> AppResult<fishe_core::lan::ScanResult> {
    let svc = svc.inner().clone();
    blocking(move || ops::scan_lan(&svc, probe_ports)).await
}

/// Forget the devices remembered from LAN scans (`lan.json`).
#[tauri::command]
#[specta::specta]
pub fn lan_forget(svc: Svc<'_>) -> AppResult<()> {
    ops::lan_forget(&svc)
}

// ─────────────────────────── security ───────────────────────────

/// The security view: what the running all-traffic session saw, the
/// programs accepting connections, the local networks scanned so far, and
/// the findings derived from them. Reads; sends nothing.
#[tauri::command]
#[specta::specta]
pub async fn security_report(svc: Svc<'_>) -> AppResult<SecurityReport> {
    let svc = svc.inner().clone();
    blocking(move || Ok(ops::security_report(&svc))).await
}

//! Npcap runtime discovery.
//!
//! `wpcap.dll` is delay-loaded (see `build.rs`). Before *any* pcap function is
//! called we must:
//!
//! 1. locate `%SystemRoot%\System32\Npcap`,
//! 2. confirm `wpcap.dll` exists there, and
//! 3. add that folder to the DLL search path with `SetDllDirectoryW`.
//!
//! If step 2 fails, calling into pcap would make the delay-load helper raise
//! an unrecoverable exception, so the rest of the app checks
//! [`NpcapStatus::available`] before touching the capture engine.
//!
//! Npcap is **not shipped with Fishe**: its licence asks each user to install
//! it themselves, so a missing runtime is an expected first-run state. The UI
//! then shows how to install it and calls [`recheck`] afterwards: nothing
//! was loaded by a failed probe, so looking again is safe and no restart is
//! needed.

use serde::Serialize;
use std::sync::Mutex;

/// Where the installer is; the only page the app ever opens for the user.
#[cfg(windows)]
pub const DOWNLOAD_URL: &str = "https://npcap.com/#download";

/// Result of probing for the Npcap runtime, shared with the UI.
#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct NpcapStatus {
    /// `true` when pcap functions can safely be called.
    pub available: bool,
    /// Folder the DLLs were loaded from (Windows only).
    pub dll_dir: Option<String>,
    /// Version string reported by `pcap_lib_version()`.
    pub version: Option<String>,
    /// Human-readable explanation when unavailable.
    pub message: Option<String>,
}

static STATUS: Mutex<Option<NpcapStatus>> = Mutex::new(None);

/// Probe and initialise Npcap once; later calls return the cached result.
pub fn init() -> NpcapStatus {
    let mut status = STATUS.lock().unwrap_or_else(|e| e.into_inner());
    status.get_or_insert_with(probe).clone()
}

/// Look again after a failed probe (Npcap installed while Fishe was running).
/// A successful probe is final: the DLL folder is set and may be in use.
pub fn recheck() -> NpcapStatus {
    let mut status = STATUS.lock().unwrap_or_else(|e| e.into_inner());
    match status.as_ref() {
        Some(found) if found.available => found.clone(),
        _ => {
            let now = probe();
            *status = Some(now.clone());
            now
        }
    }
}

/// Shortcut used by the capture code to refuse work early.
pub fn ensure_available() -> crate::error::AppResult<()> {
    let status = init();
    if status.available {
        Ok(())
    } else {
        Err(crate::error::AppError::NpcapUnavailable(
            status.message.unwrap_or_else(|| "unknown reason".into()),
        ))
    }
}

#[cfg(windows)]
fn probe() -> NpcapStatus {
    match system_dir() {
        Some(d) => probe_dir(&std::path::PathBuf::from(d).join("Npcap")),
        None => unavailable(None, "could not determine the Windows system directory"),
    }
}

/// Check one folder for the runtime, and make it the DLL folder if it is there.
#[cfg(windows)]
fn probe_dir(dir: &std::path::Path) -> NpcapStatus {
    let dir_str = dir.display().to_string();

    if !dir.join("wpcap.dll").is_file() {
        return unavailable(
            Some(dir_str),
            "wpcap.dll not found. Install Npcap from https://npcap.com (the default options are fine).",
        );
    }

    let wide: Vec<u16> = dir.as_os_str().encode_wide_nul();
    // SAFETY: `wide` is a valid NUL-terminated UTF-16 string that outlives the call.
    let ok = unsafe { ffi::SetDllDirectoryW(wide.as_ptr()) } != 0;
    if !ok {
        return unavailable(
            Some(dir_str),
            "SetDllDirectoryW failed for the Npcap folder",
        );
    }

    NpcapStatus {
        available: true,
        dll_dir: Some(dir_str),
        version: lib_version(),
        message: None,
    }
}

#[cfg(not(windows))]
fn probe() -> NpcapStatus {
    // On Unix the system libpcap is linked normally.
    NpcapStatus {
        available: true,
        dll_dir: None,
        version: lib_version(),
        message: None,
    }
}

#[cfg(windows)]
fn unavailable(dir: Option<String>, msg: &str) -> NpcapStatus {
    NpcapStatus {
        available: false,
        dll_dir: dir,
        version: None,
        message: Some(msg.to_string()),
    }
}

/// `pcap_lib_version()` is not exposed by the `pcap` crate, so we bind it here.
fn lib_version() -> Option<String> {
    // SAFETY: returns a pointer to a static NUL-terminated string owned by libpcap.
    let ptr = unsafe { ffi::pcap_lib_version() };
    if ptr.is_null() {
        return None;
    }
    let s = unsafe { std::ffi::CStr::from_ptr(ptr) };
    Some(s.to_string_lossy().into_owned())
}

#[cfg(windows)]
fn system_dir() -> Option<String> {
    let mut buf = [0u16; 260];
    // SAFETY: buffer pointer and length are valid for the duration of the call.
    let n = unsafe { ffi::GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    (n > 0 && n < buf.len()).then(|| String::from_utf16_lossy(&buf[..n]))
}

#[cfg(windows)]
trait EncodeWideNul {
    fn encode_wide_nul(&self) -> Vec<u16>;
}

#[cfg(windows)]
impl EncodeWideNul for std::ffi::OsStr {
    fn encode_wide_nul(&self) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        self.encode_wide().chain(std::iter::once(0)).collect()
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn a_folder_without_the_runtime_says_how_to_install_it() {
        let dir = std::env::temp_dir().join(format!("fishe-no-npcap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let status = probe_dir(&dir);
        std::fs::remove_dir_all(&dir).ok();
        assert!(!status.available);
        assert_eq!(status.version, None);
        assert_eq!(
            status.dll_dir.as_deref(),
            Some(dir.display().to_string().as_str())
        );
        assert!(status.message.unwrap().contains("https://npcap.com"));
    }

    #[test]
    fn the_only_page_opened_is_npcaps_own() {
        assert!(DOWNLOAD_URL.starts_with("https://npcap.com/"));
    }
}

mod ffi {
    use std::ffi::c_char;

    #[cfg(windows)]
    #[link(name = "kernel32")]
    unsafe extern "system" {
        pub fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
        pub fn SetDllDirectoryW(path: *const u16) -> i32;
    }

    #[cfg_attr(windows, link(name = "wpcap"))]
    #[cfg_attr(not(windows), link(name = "pcap"))]
    unsafe extern "C" {
        pub fn pcap_lib_version() -> *const c_char;
    }
}

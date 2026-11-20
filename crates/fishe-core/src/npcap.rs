//! Can this process capture? On Windows that means finding the Npcap
//! runtime; on Linux, where libpcap is a normal library, it means holding
//! the permission to open a capture (see [`may_capture`]).
//!
//! ## Windows: Npcap runtime discovery
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
//!
//! ## Linux: the capture permission
//!
//! Opening a capture (and the raw ICMP socket ping and traceroute use) needs
//! the `CAP_NET_RAW` capability, which root has and ordinary programs do
//! not. Fishe never raises its own rights: when the capability is missing
//! the status carries the one command that grants it to this executable
//! ([`NpcapStatus::grant_command`]), for the user to run. A capability is
//! read when a program starts, so it takes effect at the next launch.

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
    /// Folder the Npcap DLLs were loaded from (Windows).
    pub dll_dir: Option<String>,
    /// Version string reported by `pcap_lib_version()`.
    pub version: Option<String>,
    /// Human-readable explanation when unavailable.
    pub message: Option<String>,
    /// Linux, when capturing is not permitted: the command that grants this
    /// executable the permission. `None` when no command can (the file sits
    /// where capabilities do not apply).
    pub grant_command: Option<String>,
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
        grant_command: None,
    }
}

#[cfg(not(windows))]
fn probe() -> NpcapStatus {
    // The system libpcap is linked normally; what can be missing is the
    // right to use it.
    #[cfg(target_os = "linux")]
    if !may_capture(&std::fs::read_to_string("/proc/self/status").unwrap_or_default()) {
        return NpcapStatus {
            available: false,
            dll_dir: None,
            version: None,
            message: Some(
                "Fishe is not allowed to capture packets: it needs the CAP_NET_RAW capability (or to run as root)."
                    .into(),
            ),
            grant_command: std::env::current_exe()
                .ok()
                .and_then(|exe| grant_command(&exe.to_string_lossy())),
        };
    }
    NpcapStatus {
        available: true,
        dll_dir: None,
        version: lib_version(),
        message: None,
        grant_command: None,
    }
}

/// Does `/proc/self/status` show `CAP_NET_RAW` among the effective
/// capabilities? Root has it; so does an executable it was granted to.
/// When the file cannot be read as expected the answer is yes: opening the
/// capture will then say what is wrong.
#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
fn may_capture(proc_status: &str) -> bool {
    const CAP_NET_RAW: u32 = 13;
    proc_status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
        .is_none_or(|caps| caps & (1 << CAP_NET_RAW) != 0)
}

/// The command that lets `exe` capture without being root. `None` for a
/// file inside a mounted AppImage (a read-only image: capabilities cannot be
/// set there) and for a path that cannot be quoted safely.
#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
fn grant_command(exe: &str) -> Option<String> {
    if exe.is_empty() || exe.contains(['\'', '\n']) || exe.contains("/.mount_") {
        return None;
    }
    let plain = exe
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "/._-+".contains(c));
    Some(if plain {
        format!("sudo setcap cap_net_raw=ep {exe}")
    } else {
        format!("sudo setcap cap_net_raw=ep '{exe}'")
    })
}

#[cfg(windows)]
fn unavailable(dir: Option<String>, msg: &str) -> NpcapStatus {
    NpcapStatus {
        available: false,
        dll_dir: dir,
        version: None,
        message: Some(msg.to_string()),
        grant_command: None,
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

#[cfg(test)]
mod permission_tests {
    use super::*;

    #[test]
    fn the_capture_capability_is_read_from_proc_status() {
        let status = |caps: &str| {
            format!("Name:\tfishe\nCapPrm:\t{caps}\nCapEff:\t{caps}\nCapBnd:\t000001ffffffffff\n")
        };
        assert!(may_capture(&status("000001ffffffffff")), "root");
        assert!(
            may_capture(&status("0000000000002000")),
            "granted to the file"
        );
        assert!(
            !may_capture(&status("0000000000000000")),
            "an ordinary program"
        );
        assert!(
            !may_capture(&status("0000000000001000")),
            "CAP_NET_ADMIN alone is not it"
        );
        // Unreadable: do not claim it is forbidden.
        assert!(may_capture(""));
        assert!(may_capture("CapEff:\tnot-hex\n"));
    }

    #[test]
    fn the_grant_command_names_this_executable() {
        assert_eq!(
            grant_command("/usr/bin/fishe").as_deref(),
            Some("sudo setcap cap_net_raw=ep /usr/bin/fishe")
        );
        assert_eq!(
            grant_command("/home/ada/My Apps/fishe").as_deref(),
            Some("sudo setcap cap_net_raw=ep '/home/ada/My Apps/fishe'")
        );
        // Nothing a shell could read as more than one argument.
        assert_eq!(grant_command("/tmp/it's/fishe"), None);
        assert_eq!(grant_command("/tmp/a\nb/fishe"), None);
        // An AppImage is mounted read-only for each run.
        assert_eq!(grant_command("/tmp/.mount_FisheAbC123/usr/bin/fishe"), None);
        assert_eq!(grant_command(""), None);
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

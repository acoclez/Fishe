//! Process enumeration and the grouped list shown in the process picker.

use super::sockets::{self, SocketEntry};
use crate::error::AppResult;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessEntry {
    pub pid: u32,
    pub parent_pid: u32,
    /// Executable file name, e.g. `chrome.exe` (Windows) or `firefox` (Linux).
    pub name: String,
}

/// All processes sharing an executable name. This is what the picker shows,
/// and what "bind by name" follows.
#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct ProcessGroup {
    pub name: String,
    pub pids: Vec<u32>,
    /// Full image path of one instance, when readable.
    pub exe_path: Option<String>,
    /// All TCP/UDP sockets owned by the group.
    pub sockets: u32,
    /// TCP connections with a remote peer.
    pub connections: u32,
    pub listening: u32,
}

#[cfg(windows)]
pub use win::{exe_path, list};

#[cfg(target_os = "linux")]
pub use super::procfs::{exe_path, processes as list};

#[cfg(not(any(windows, target_os = "linux")))]
pub fn list() -> AppResult<Vec<ProcessEntry>> {
    Err(crate::error::AppError::Unavailable(
        "telling programs apart is not supported on this platform".into(),
    ))
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn exe_path(_pid: u32) -> Option<String> {
    None
}

/// Processes grouped by executable name, busiest network users first.
pub fn groups() -> AppResult<Vec<ProcessGroup>> {
    let procs = list()?;
    let socks = sockets::snapshot()?;
    Ok(group(&procs, &socks, true))
}

/// Pure grouping logic (testable without the OS).
pub fn group(procs: &[ProcessEntry], socks: &[SocketEntry], with_paths: bool) -> Vec<ProcessGroup> {
    let mut by_pid: HashMap<u32, (u32, u32, u32)> = HashMap::new();
    for s in socks {
        let e = by_pid.entry(s.pid).or_default();
        e.0 += 1;
        if s.remote.is_some() {
            e.1 += 1;
        }
        if s.listening {
            e.2 += 1;
        }
    }

    let mut groups: HashMap<String, ProcessGroup> = HashMap::new();
    for p in procs.iter().filter(|p| p.pid != 0) {
        let g = groups
            .entry(p.name.to_ascii_lowercase())
            .or_insert_with(|| ProcessGroup {
                name: p.name.clone(),
                pids: Vec::new(),
                exe_path: None,
                sockets: 0,
                connections: 0,
                listening: 0,
            });
        g.pids.push(p.pid);
        if let Some(&(s, c, l)) = by_pid.get(&p.pid) {
            g.sockets += s;
            g.connections += c;
            g.listening += l;
        }
    }

    let mut out: Vec<ProcessGroup> = groups.into_values().collect();
    for g in &mut out {
        g.pids.sort_unstable();
        if with_paths {
            g.exe_path = g.pids.iter().find_map(|&pid| exe_path(pid));
        }
    }
    out.sort_by(|a, b| {
        b.connections
            .cmp(&a.connections)
            .then(b.sockets.cmp(&a.sockets))
            .then_with(|| {
                a.name
                    .to_ascii_lowercase()
                    .cmp(&b.name.to_ascii_lowercase())
            })
    });
    out
}

#[cfg(windows)]
mod win {
    use super::*;
    use crate::error::AppError;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
    };

    /// Every process on the system (names are readable without admin).
    pub fn list() -> AppResult<Vec<ProcessEntry>> {
        // SAFETY: Toolhelp snapshot iteration; the handle is closed on every path.
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == INVALID_HANDLE_VALUE {
                return Err(AppError::Internal("CreateToolhelp32Snapshot failed".into()));
            }
            let mut out = Vec::with_capacity(512);
            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
            let mut ok = Process32FirstW(snap, &mut entry) != 0;
            while ok {
                let len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                out.push(ProcessEntry {
                    pid: entry.th32ProcessID,
                    parent_pid: entry.th32ParentProcessID,
                    name: String::from_utf16_lossy(&entry.szExeFile[..len]),
                });
                ok = Process32NextW(snap, &mut entry) != 0;
            }
            CloseHandle(snap);
            Ok(out)
        }
    }

    /// Full path of a process image; `None` for protected/system processes.
    pub fn exe_path(pid: u32) -> Option<String> {
        // SAFETY: limited-information handle, closed before returning.
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                return None;
            }
            let mut buf = [0u16; 1024];
            let mut len = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len);
            CloseHandle(h);
            (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::parse::Transport;

    fn sock(pid: u32, remote: bool, listening: bool) -> SocketEntry {
        SocketEntry {
            transport: Transport::Tcp,
            local: "10.0.0.2:5000".parse().unwrap(),
            remote: remote.then(|| "1.1.1.1:443".parse().unwrap()),
            pid,
            listening,
        }
    }

    #[test]
    fn groups_by_name_and_sorts_by_activity() {
        let procs = vec![
            ProcessEntry {
                pid: 0,
                parent_pid: 0,
                name: "[System Process]".into(),
            },
            ProcessEntry {
                pid: 10,
                parent_pid: 1,
                name: "chrome.exe".into(),
            },
            ProcessEntry {
                pid: 11,
                parent_pid: 10,
                name: "Chrome.exe".into(),
            },
            ProcessEntry {
                pid: 20,
                parent_pid: 1,
                name: "idle.exe".into(),
            },
            ProcessEntry {
                pid: 30,
                parent_pid: 1,
                name: "server.exe".into(),
            },
        ];
        let socks = vec![
            sock(10, true, false),
            sock(11, true, false),
            sock(11, false, false),
            sock(30, false, true),
        ];
        let g = group(&procs, &socks, false);
        assert_eq!(g[0].name, "chrome.exe");
        assert_eq!(g[0].pids, vec![10, 11]);
        assert_eq!((g[0].sockets, g[0].connections), (3, 2));
        assert_eq!(g[1].name, "server.exe");
        assert_eq!(g[1].listening, 1);
        assert!(g.iter().all(|x| !x.pids.contains(&0)));
    }

    #[cfg(windows)]
    #[test]
    fn lists_ourselves() {
        let me = std::process::id();
        let all = list().unwrap();
        let entry = all
            .iter()
            .find(|p| p.pid == me)
            .expect("current process listed");
        assert!(entry.name.to_ascii_lowercase().ends_with(".exe"));
        assert!(exe_path(me).is_some());
    }
}

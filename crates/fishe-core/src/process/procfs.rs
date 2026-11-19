//! Linux: sockets and processes from `/proc`.
//!
//! The kernel lists every TCP and UDP socket in `/proc/net/{tcp,tcp6,udp,udp6}`
//! with its inode, but not with its owner. The owner is whichever process
//! holds a file descriptor that links to `socket:[inode]` in
//! `/proc/<pid>/fd`. Reading the lists is cheap (four files); finding owners
//! means walking the processes' descriptors, so owners are remembered per
//! inode and the walk only runs when a socket appears that isn't known yet
//! (see [`Owners`]).
//!
//! Another user's descriptors are only readable by root, so without root
//! only the current user's programs get an owner; the other sockets are
//! reported with PID 0, which the ownership table ignores.
//!
//! The parsers are plain functions over text, compiled and tested on every
//! platform; only [`os`] reads `/proc`.

use super::sockets::SocketEntry;
use crate::net::parse::Transport;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// TCP state number of a listening socket (`TCP_LISTEN`).
const TCP_LISTEN: u8 = 10;

/// One socket as `/proc/net/*` describes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetRow {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    /// Kernel socket state (TCP state numbers; UDP reuses them).
    pub state: u8,
    /// Identifies the socket; 0 for sockets no process holds any more.
    pub inode: u64,
}

/// One line of `/proc/net/{tcp,tcp6,udp,udp6}`:
/// `slot: local remote state tx:rx timer retransmits uid timeout inode …`.
/// `None` for the header and for anything that doesn't parse.
pub fn parse_net_line(line: &str) -> Option<NetRow> {
    let mut fields = line.split_ascii_whitespace();
    let (_slot, local, remote, state) = (
        fields.next()?,
        fields.next()?,
        fields.next()?,
        fields.next()?,
    );
    // Skips queues, timer, retransmits, uid and timeout.
    let inode = fields.nth(5)?.parse().ok()?;
    Some(NetRow {
        local: parse_addr(local)?,
        remote: parse_addr(remote)?,
        state: u8::from_str_radix(state, 16).ok()?,
        inode,
    })
}

/// `0100007F:1F90` or 32 hex digits and a port. The kernel prints each
/// 32-bit word of the address as a native integer, so the bytes come back in
/// network order through `to_ne_bytes` (the text is always this machine's).
fn parse_addr(s: &str) -> Option<SocketAddr> {
    let (addr, port) = s.rsplit_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let word = |i: usize| {
        u32::from_str_radix(addr.get(i * 8..i * 8 + 8)?, 16)
            .ok()
            .map(u32::to_ne_bytes)
    };
    let ip: IpAddr = match addr.len() {
        8 => Ipv4Addr::from(word(0)?).into(),
        32 => {
            let mut bytes = [0u8; 16];
            for i in 0..4 {
                bytes[i * 4..i * 4 + 4].copy_from_slice(&word(i)?);
            }
            Ipv6Addr::from(bytes).into()
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// A row as the rest of Fishe wants it, owned by `pid` (0 = owner unknown).
pub fn entry(transport: Transport, row: &NetRow, pid: u32) -> SocketEntry {
    let tcp = transport == Transport::Tcp;
    let listening = tcp && row.state == TCP_LISTEN;
    SocketEntry {
        transport,
        local: row.local,
        remote: (tcp && !listening && row.remote.port() != 0).then_some(row.remote),
        pid,
        listening,
    }
}

/// The inode in a descriptor link like `socket:[12345]`.
pub fn socket_inode(link: &str) -> Option<u64> {
    link.strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// Command name and parent PID from `/proc/<pid>/stat`:
/// `1234 (name) S 1200 …`. The name may itself contain spaces and brackets,
/// so it ends at the *last* closing bracket.
pub fn parse_stat(stat: &str) -> Option<(&str, u32)> {
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    let comm = stat.get(open + 1..close)?;
    let mut rest = stat.get(close + 1..)?.split_ascii_whitespace();
    let (_state, parent) = (rest.next()?, rest.next()?);
    Some((comm, parent.parse().ok()?))
}

/// File name of an executable path, without the ` (deleted)` the kernel
/// appends once the file was replaced (a program updated while running).
pub fn exe_name(path: &str) -> &str {
    let path = path.strip_suffix(" (deleted)").unwrap_or(path);
    path.rsplit('/').next().unwrap_or(path)
}

#[cfg(target_os = "linux")]
pub use os::{exe_path, processes, sockets};

#[cfg(target_os = "linux")]
mod os {
    use super::*;
    use crate::error::{AppError, AppResult};
    use crate::process::processes::ProcessEntry;
    use std::collections::{HashMap, HashSet};
    use std::fs;
    use std::sync::{LazyLock, Mutex};
    use std::time::{Duration, Instant};

    /// How long sockets whose owner could not be found wait before another
    /// walk is tried for them alone (new sockets trigger one at once).
    const RETRY: Duration = Duration::from_secs(2);

    /// Who owns each socket inode, remembered between snapshots. An inode
    /// names one socket for as long as it exists, so an owner stays right
    /// until the socket goes or the owner exits.
    #[derive(Default)]
    struct Owners {
        /// inode → PID; 0 when no readable process holds it.
        by_inode: HashMap<u64, u32>,
        last_walk: Option<Instant>,
    }

    static OWNERS: LazyLock<Mutex<Owners>> = LazyLock::new(Mutex::default);

    impl Owners {
        /// Bring the map in line with the sockets that exist now.
        fn update(&mut self, live: &HashSet<u64>) {
            self.by_inode.retain(|inode, _| live.contains(inode));
            // A socket outlives the process that opened it when a child
            // inherited it: forget owners that are gone, and look again.
            let mut alive: HashMap<u32, bool> = HashMap::new();
            self.by_inode.retain(|_, pid| {
                *pid == 0
                    || *alive
                        .entry(*pid)
                        .or_insert_with(|| fs::metadata(format!("/proc/{pid}")).is_ok())
            });

            let unknown: HashSet<u64> = live
                .iter()
                .filter(|inode| !self.by_inode.contains_key(inode))
                .copied()
                .collect();
            let unresolved = self.by_inode.values().any(|&pid| pid == 0);
            let retry = unresolved && self.last_walk.is_none_or(|t| t.elapsed() >= RETRY);
            if unknown.is_empty() && !retry {
                return;
            }
            let mut wanted = unknown;
            if retry {
                wanted.extend(
                    self.by_inode
                        .iter()
                        .filter(|&(_, &pid)| pid == 0)
                        .map(|(inode, _)| *inode),
                );
            }
            let found = walk(&wanted, self.by_inode.values().copied().collect());
            for inode in wanted {
                self.by_inode
                    .insert(inode, found.get(&inode).copied().unwrap_or(0));
            }
            self.last_walk = Some(Instant::now());
        }
    }

    /// Find which process holds each of the `wanted` socket inodes. Processes
    /// that already own sockets are looked at first (they open most new
    /// ones), and the walk stops as soon as every inode has an owner.
    fn walk(wanted: &HashSet<u64>, known_owners: HashSet<u32>) -> HashMap<u64, u32> {
        let mut pids: Vec<u32> = match fs::read_dir("/proc") {
            Ok(dir) => dir
                .flatten()
                .filter_map(|e| e.file_name().to_str()?.parse().ok())
                .collect(),
            Err(_) => return HashMap::new(),
        };
        // Owners first, then by PID so that a socket shared by a parent and
        // its children goes to the parent.
        pids.sort_unstable_by_key(|pid| (!known_owners.contains(pid), *pid));

        let mut found = HashMap::new();
        for pid in pids {
            // Fails for other users' processes without root: skipped.
            let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else {
                continue;
            };
            for fd in fds.flatten() {
                if let Ok(link) = fs::read_link(fd.path())
                    && let Some(inode) = link.to_str().and_then(socket_inode)
                    && wanted.contains(&inode)
                {
                    found.entry(inode).or_insert(pid);
                }
            }
            if found.len() == wanted.len() {
                break;
            }
        }
        found
    }

    /// Every TCP and UDP socket (IPv4 and IPv6) with its owner.
    pub fn sockets() -> AppResult<Vec<SocketEntry>> {
        let mut rows: Vec<(Transport, NetRow)> = Vec::with_capacity(512);
        for (file, transport) in [
            ("tcp", Transport::Tcp),
            ("tcp6", Transport::Tcp),
            ("udp", Transport::Udp),
            ("udp6", Transport::Udp),
        ] {
            match fs::read_to_string(format!("/proc/net/{file}")) {
                Ok(text) => rows.extend(
                    text.lines()
                        .filter_map(parse_net_line)
                        // Inode 0: closed sockets still winding down.
                        .filter(|row| row.inode != 0)
                        .map(|row| (transport, row)),
                ),
                // The IPv6 files don't exist with IPv6 disabled.
                Err(_) if file.ends_with('6') => {}
                Err(e) => {
                    return Err(AppError::Unavailable(format!(
                        "cannot read /proc/net/{file}: {e}"
                    )));
                }
            }
        }
        let live: HashSet<u64> = rows.iter().map(|(_, row)| row.inode).collect();
        let mut owners = OWNERS.lock().unwrap_or_else(|e| e.into_inner());
        owners.update(&live);
        Ok(rows
            .iter()
            .map(|(transport, row)| {
                let pid = owners.by_inode.get(&row.inode).copied().unwrap_or(0);
                entry(*transport, row, pid)
            })
            .collect())
    }

    /// Every process, named after its executable when that is readable (it
    /// is for the user's own processes, and for all of them as root), else
    /// after the kernel's 15-character command name.
    pub fn processes() -> AppResult<Vec<ProcessEntry>> {
        let dir = fs::read_dir("/proc")
            .map_err(|e| AppError::Unavailable(format!("cannot read /proc: {e}")))?;
        let mut out = Vec::with_capacity(512);
        for pid in dir
            .flatten()
            .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        {
            // Gone between listing and reading: skip.
            let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
                continue;
            };
            let Some((comm, parent_pid)) = parse_stat(&stat) else {
                continue;
            };
            let name = exe_path(pid)
                .map(|p| exe_name(&p).to_string())
                .unwrap_or_else(|| comm.to_string());
            out.push(ProcessEntry {
                pid,
                parent_pid,
                name,
            });
        }
        Ok(out)
    }

    /// Full path of a process's executable; `None` for kernel threads and
    /// for processes this user may not inspect.
    pub fn exe_path(pid: u32) -> Option<String> {
        let path = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
        let path = path.to_str()?;
        Some(path.strip_suffix(" (deleted)").unwrap_or(path).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The sample lines are what a little-endian machine prints.
    #[cfg(target_endian = "little")]
    #[test]
    fn reads_tcp_and_udp_lines() {
        let header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";
        assert_eq!(parse_net_line(header), None);
        assert_eq!(parse_net_line(""), None);
        assert_eq!(parse_net_line("   0: garbage"), None);

        // A listener on 127.0.0.1:8080.
        let listen = "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 31337 1 0000000000000000 100 0 0 10 0";
        let row = parse_net_line(listen).unwrap();
        assert_eq!(row.local, "127.0.0.1:8080".parse().unwrap());
        assert_eq!((row.state, row.inode), (10, 31337));
        let e = entry(Transport::Tcp, &row, 42);
        assert!(e.listening);
        assert_eq!((e.remote, e.pid), (None, 42));

        // An established connection 192.168.1.19:50000 → 1.1.1.1:443.
        let conn = "   1: 1301A8C0:C350 01010101:01BB 01 00000000:00000000 02:000A1B2C 00000000  1000        0 31338 2 0000000000000000 20 4 30 10 -1";
        let row = parse_net_line(conn).unwrap();
        let e = entry(Transport::Tcp, &row, 7);
        assert_eq!(e.local, "192.168.1.19:50000".parse().unwrap());
        assert_eq!(e.remote, Some("1.1.1.1:443".parse().unwrap()));
        assert!(!e.listening);

        // UDP has no peer and never listens, whatever its state says.
        let udp = " 2345: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000   108        0 4242 2 0000000000000000 0";
        let row = parse_net_line(udp).unwrap();
        let e = entry(Transport::Udp, &row, 9);
        assert_eq!(e.local, "0.0.0.0:5353".parse().unwrap());
        assert_eq!((e.remote, e.listening), (None, false));
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn reads_ipv6_addresses() {
        // [::1]:631 listening.
        let v6 = "   0: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 9001 1 0000000000000000 100 0 0 10 0";
        let row = parse_net_line(v6).unwrap();
        assert_eq!(row.local, "[::1]:631".parse().unwrap());
        // A dual-stack socket talking IPv4: ::ffff:127.0.0.1.
        let mapped = "   1: 0000000000000000FFFF00000100007F:1F90 0000000000000000FFFF00000100007F:C001 01 00000000:00000000 00:00000000 00000000  1000        0 9002 1 0000000000000000 20 0 0 10 -1";
        let row = parse_net_line(mapped).unwrap();
        assert_eq!(row.local, "[::ffff:127.0.0.1]:8080".parse().unwrap());
        assert_eq!(row.remote.port(), 0xC001);
        // 2001:db8::1 keeps its byte order word by word.
        let global = "   2: B80D0120000000000000000001000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 9003 1 0000000000000000 100 0 0 10 0";
        assert_eq!(
            parse_net_line(global).unwrap().local,
            "[2001:db8::1]:443".parse().unwrap()
        );
        // Neither 8 nor 32 hex digits: not an address.
        assert_eq!(
            parse_net_line("   3: 0100:1F90 00000000:0000 0A 0:0 0:0 0 0 0 1"),
            None
        );
    }

    #[test]
    fn reads_descriptor_links_and_stat() {
        assert_eq!(socket_inode("socket:[31337]"), Some(31337));
        assert_eq!(socket_inode("pipe:[31337]"), None);
        assert_eq!(socket_inode("/dev/null"), None);
        assert_eq!(socket_inode("socket:[x]"), None);

        assert_eq!(
            parse_stat("1234 (curl) S 1200 1234 1200 0 -1 4194304"),
            Some(("curl", 1200))
        );
        // Spaces and brackets inside the name.
        assert_eq!(
            parse_stat("77 (Web Content) R 60 77 60 0"),
            Some(("Web Content", 60))
        );
        assert_eq!(
            parse_stat("78 (tricky) name)) S 1 78 78 0"),
            Some(("tricky) name)", 1))
        );
        assert_eq!(parse_stat("no brackets here"), None);

        assert_eq!(exe_name("/usr/lib/firefox/firefox"), "firefox");
        assert_eq!(exe_name("/usr/bin/curl (deleted)"), "curl");
        assert_eq!(exe_name("curl"), "curl");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn finds_this_process_and_its_sockets() {
        use std::net::{TcpListener, TcpStream, UdpSocket};
        let me = std::process::id();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let lport = listener.local_addr().unwrap().port();
        let client = TcpStream::connect(("127.0.0.1", lport)).unwrap();
        let cport = client.local_addr().unwrap().port();
        let udp = UdpSocket::bind("[::1]:0").unwrap();
        let uport = udp.local_addr().unwrap().port();

        let snap = sockets().unwrap();
        let l = snap
            .iter()
            .find(|e| e.transport == Transport::Tcp && e.local.port() == lport && e.listening)
            .expect("listener present");
        assert_eq!((l.pid, l.remote), (me, None));
        let c = snap
            .iter()
            .find(|e| e.transport == Transport::Tcp && e.local.port() == cport)
            .expect("client connection present");
        assert_eq!(c.pid, me);
        assert_eq!(c.remote.unwrap().port(), lport);
        let u = snap
            .iter()
            .find(|e| e.transport == Transport::Udp && e.local.port() == uport)
            .expect("udp v6 socket present");
        assert_eq!(u.pid, me);
        assert!(u.local.is_ipv6());

        // A socket opened after the first snapshot is found by the next one.
        let late = UdpSocket::bind("127.0.0.1:0").unwrap();
        let late_port = late.local_addr().unwrap().port();
        let again = sockets().unwrap();
        let found = again
            .iter()
            .find(|e| e.transport == Transport::Udp && e.local.port() == late_port)
            .expect("late socket present");
        assert_eq!(found.pid, me);

        let all = processes().unwrap();
        let entry = all.iter().find(|p| p.pid == me).expect("this process");
        assert!(!entry.name.is_empty() && !entry.name.contains('/'));
        assert!(exe_path(me).is_some_and(|p| p.starts_with('/')));
    }
}

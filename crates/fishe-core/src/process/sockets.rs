//! Snapshot of every TCP/UDP socket on the host with its owning PID.
//!
//! Windows: the IP Helper API (`GetExtendedTcpTable` / `GetExtendedUdpTable`),
//! without administrator rights. Linux: `/proc` (see [`super::procfs`]),
//! where other users' programs are only visible to root.

#[cfg(not(target_os = "linux"))]
use crate::error::AppResult;
use crate::net::parse::Transport;
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketEntry {
    pub transport: Transport,
    pub local: SocketAddr,
    /// Connected peer (TCP connections only).
    pub remote: Option<SocketAddr>,
    pub pid: u32,
    pub listening: bool,
}

#[cfg(windows)]
pub use win::snapshot;

#[cfg(target_os = "linux")]
pub use super::procfs::sockets as snapshot;

#[cfg(not(any(windows, target_os = "linux")))]
pub fn snapshot() -> AppResult<Vec<SocketEntry>> {
    Err(crate::error::AppError::Unavailable(
        "telling programs apart is not supported on this platform".into(),
    ))
}

#[cfg(windows)]
mod win {
    use super::*;
    use crate::error::AppError;
    use std::ffi::c_void;
    use std::net::{IpAddr, Ipv6Addr};
    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP_STATE_LISTEN, MIB_TCP6ROW_OWNER_PID,
        MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
        MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID,
        MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    /// All TCP and UDP sockets (IPv4 and IPv6).
    pub fn snapshot() -> AppResult<Vec<SocketEntry>> {
        let mut out = Vec::with_capacity(1024);
        tcp4(&mut out)?;
        tcp6(&mut out)?;
        udp4(&mut out)?;
        udp6(&mut out)?;
        Ok(out)
    }

    /// Call a size-negotiating IP Helper function until the buffer fits.
    /// Returns an 8-byte aligned buffer holding the table.
    fn fetch(call: impl Fn(*mut c_void, *mut u32) -> u32) -> AppResult<Vec<u64>> {
        let mut size = 0u32;
        let mut buf: Vec<u64> = Vec::new();
        for _ in 0..8 {
            let ptr = if buf.is_empty() {
                std::ptr::null_mut()
            } else {
                buf.as_mut_ptr().cast()
            };
            match call(ptr, &mut size) {
                NO_ERROR if !buf.is_empty() => return Ok(buf),
                NO_ERROR | ERROR_INSUFFICIENT_BUFFER => {
                    // Tables grow between calls; leave some headroom.
                    let words = (size as usize).div_ceil(8) + 256;
                    buf = vec![0u64; words];
                    size = (words * 8) as u32;
                }
                code => {
                    return Err(AppError::Internal(format!(
                        "IP Helper query failed (error {code})"
                    )));
                }
            }
        }
        Err(AppError::Internal("socket table kept growing".into()))
    }

    /// Port fields hold a network-order u16 in their low bytes.
    fn port(dw: u32) -> u16 {
        u16::from_be(dw as u16)
    }

    fn v4(dw: u32) -> IpAddr {
        IpAddr::V4(crate::util::ipv4_from_ne(dw))
    }

    /// Reinterpret a table buffer as `(count, rows)`.
    ///
    /// SAFETY: `buf` must hold a `T` table filled by the matching API, whose
    /// layout is `{ dwNumEntries: u32, table: [Row; N] }`.
    unsafe fn rows<T, Row>(
        buf: &[u64],
        count: impl Fn(*const T) -> u32,
        first: impl Fn(*const T) -> *const Row,
    ) -> &[Row] {
        let table = buf.as_ptr().cast::<T>();
        let n = count(table) as usize;
        let max = (buf.len() * 8).saturating_sub(8) / size_of::<Row>();
        unsafe { std::slice::from_raw_parts(first(table), n.min(max)) }
    }

    fn tcp4(out: &mut Vec<SocketEntry>) -> AppResult<()> {
        let buf = fetch(|p, s| unsafe {
            GetExtendedTcpTable(p, s, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0)
        })?;
        // SAFETY: buffer filled by GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL, AF_INET).
        let rows: &[MIB_TCPROW_OWNER_PID] = unsafe {
            rows(
                &buf,
                |t: *const MIB_TCPTABLE_OWNER_PID| (*t).dwNumEntries,
                |t| std::ptr::addr_of!((*t).table).cast(),
            )
        };
        for r in rows {
            let listening = r.dwState == MIB_TCP_STATE_LISTEN as u32;
            out.push(SocketEntry {
                transport: Transport::Tcp,
                local: SocketAddr::new(v4(r.dwLocalAddr), port(r.dwLocalPort)),
                remote: (!listening)
                    .then(|| SocketAddr::new(v4(r.dwRemoteAddr), port(r.dwRemotePort))),
                pid: r.dwOwningPid,
                listening,
            });
        }
        Ok(())
    }

    fn tcp6(out: &mut Vec<SocketEntry>) -> AppResult<()> {
        let buf = fetch(|p, s| unsafe {
            GetExtendedTcpTable(p, s, 0, AF_INET6 as u32, TCP_TABLE_OWNER_PID_ALL, 0)
        })?;
        // SAFETY: buffer filled by GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL, AF_INET6).
        let rows: &[MIB_TCP6ROW_OWNER_PID] = unsafe {
            rows(
                &buf,
                |t: *const MIB_TCP6TABLE_OWNER_PID| (*t).dwNumEntries,
                |t| std::ptr::addr_of!((*t).table).cast(),
            )
        };
        for r in rows {
            let listening = r.dwState == MIB_TCP_STATE_LISTEN as u32;
            out.push(SocketEntry {
                transport: Transport::Tcp,
                local: SocketAddr::new(Ipv6Addr::from(r.ucLocalAddr).into(), port(r.dwLocalPort)),
                remote: (!listening).then(|| {
                    SocketAddr::new(Ipv6Addr::from(r.ucRemoteAddr).into(), port(r.dwRemotePort))
                }),
                pid: r.dwOwningPid,
                listening,
            });
        }
        Ok(())
    }

    fn udp4(out: &mut Vec<SocketEntry>) -> AppResult<()> {
        let buf = fetch(|p, s| unsafe {
            GetExtendedUdpTable(p, s, 0, AF_INET as u32, UDP_TABLE_OWNER_PID, 0)
        })?;
        // SAFETY: buffer filled by GetExtendedUdpTable(UDP_TABLE_OWNER_PID, AF_INET).
        let rows: &[MIB_UDPROW_OWNER_PID] = unsafe {
            rows(
                &buf,
                |t: *const MIB_UDPTABLE_OWNER_PID| (*t).dwNumEntries,
                |t| std::ptr::addr_of!((*t).table).cast(),
            )
        };
        for r in rows {
            out.push(SocketEntry {
                transport: Transport::Udp,
                local: SocketAddr::new(v4(r.dwLocalAddr), port(r.dwLocalPort)),
                remote: None,
                pid: r.dwOwningPid,
                listening: false,
            });
        }
        Ok(())
    }

    fn udp6(out: &mut Vec<SocketEntry>) -> AppResult<()> {
        let buf = fetch(|p, s| unsafe {
            GetExtendedUdpTable(p, s, 0, AF_INET6 as u32, UDP_TABLE_OWNER_PID, 0)
        })?;
        // SAFETY: buffer filled by GetExtendedUdpTable(UDP_TABLE_OWNER_PID, AF_INET6).
        let rows: &[MIB_UDP6ROW_OWNER_PID] = unsafe {
            rows(
                &buf,
                |t: *const MIB_UDP6TABLE_OWNER_PID| (*t).dwNumEntries,
                |t| std::ptr::addr_of!((*t).table).cast(),
            )
        };
        for r in rows {
            out.push(SocketEntry {
                transport: Transport::Udp,
                local: SocketAddr::new(Ipv6Addr::from(r.ucLocalAddr).into(), port(r.dwLocalPort)),
                remote: None,
                pid: r.dwOwningPid,
                listening: false,
            });
        }
        Ok(())
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream, UdpSocket};

    #[test]
    fn sees_our_own_sockets() {
        let me = std::process::id();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let lport = listener.local_addr().unwrap().port();
        let client = TcpStream::connect(("127.0.0.1", lport)).unwrap();
        let cport = client.local_addr().unwrap().port();
        let udp = UdpSocket::bind("[::1]:0").unwrap();
        let uport = udp.local_addr().unwrap().port();

        let snap = snapshot().unwrap();
        let find = |t: Transport, p: u16| {
            snap.iter()
                .find(|e| e.transport == t && e.local.port() == p)
        };

        // The server side of the accepted connection shares the listener's port.
        let l = snap
            .iter()
            .find(|e| e.transport == Transport::Tcp && e.local.port() == lport && e.listening)
            .expect("listener present");
        assert_eq!(l.pid, me);
        assert!(l.remote.is_none());
        let c = find(Transport::Tcp, cport).expect("client connection present");
        assert_eq!(c.pid, me);
        assert_eq!(c.remote.unwrap().port(), lport);
        let u = find(Transport::Udp, uport).expect("udp v6 socket present");
        assert_eq!(u.pid, me);
        assert!(u.local.is_ipv6());
    }
}

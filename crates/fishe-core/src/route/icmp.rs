//! One ICMP echo probe with a given TTL (Windows ICMP API, no admin needed).

use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeKind {
    /// The destination itself answered.
    Reached,
    /// A router on the way answered "TTL expired in transit".
    TtlExpired,
    /// A router answered "destination/network unreachable".
    Unreachable,
    /// Nothing came back in time.
    Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeReply {
    pub kind: ProbeKind,
    pub from: Option<IpAddr>,
    pub rtt_ms: Option<u32>,
}

#[cfg(windows)]
impl ProbeReply {
    fn timeout() -> Self {
        ProbeReply {
            kind: ProbeKind::Timeout,
            from: None,
            rtt_ms: None,
        }
    }
}

#[cfg(windows)]
pub use win::probe;

/// Windows only: elsewhere ping and traceroute report this error instead of
/// probing.
#[cfg(not(windows))]
pub fn probe(_dest: IpAddr, _ttl: u8, _timeout_ms: u32) -> std::io::Result<ProbeReply> {
    Err(std::io::Error::other(
        "ping and traceroute are only implemented on Windows",
    ))
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use windows_sys::Win32::Foundation::{GetLastError, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ICMP_ECHO_REPLY, ICMPV6_ECHO_REPLY_LH, IP_DEST_HOST_UNREACHABLE, IP_DEST_NET_UNREACHABLE,
        IP_OPTION_INFORMATION, IP_REQ_TIMED_OUT, IP_SUCCESS, IP_TTL_EXPIRED_TRANSIT,
        Icmp6CreateFile, Icmp6ParseReplies, Icmp6SendEcho2, IcmpCloseHandle, IcmpCreateFile,
        IcmpSendEcho,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET6, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN6};

    /// Payload, like `tracert`'s (content is irrelevant).
    const PAYLOAD: [u8; 32] = *b"fishe-route-probe-fishe-route-pr";
    const IP_DEST_PROT_UNREACHABLE: u32 = 11004;
    const IP_DEST_PORT_UNREACHABLE: u32 = 11005;

    fn kind(status: u32) -> Option<ProbeKind> {
        match status {
            IP_SUCCESS => Some(ProbeKind::Reached),
            IP_TTL_EXPIRED_TRANSIT => Some(ProbeKind::TtlExpired),
            IP_DEST_HOST_UNREACHABLE
            | IP_DEST_NET_UNREACHABLE
            | IP_DEST_PROT_UNREACHABLE
            | IP_DEST_PORT_UNREACHABLE => Some(ProbeKind::Unreachable),
            _ => None,
        }
    }

    /// Send one echo with `ttl`; waits up to `timeout_ms`.
    pub fn probe(dest: IpAddr, ttl: u8, timeout_ms: u32) -> std::io::Result<ProbeReply> {
        match dest {
            IpAddr::V4(v4) => probe_v4(v4, ttl, timeout_ms),
            IpAddr::V6(v6) => probe_v6(v6, ttl, timeout_ms),
        }
    }

    fn options(ttl: u8) -> IP_OPTION_INFORMATION {
        IP_OPTION_INFORMATION {
            Ttl: ttl,
            Tos: 0,
            Flags: 0,
            OptionsSize: 0,
            OptionsData: std::ptr::null_mut(),
        }
    }

    fn probe_v4(dest: Ipv4Addr, ttl: u8, timeout_ms: u32) -> std::io::Result<ProbeReply> {
        // Reply buffer: one ICMP_ECHO_REPLY + payload + 8 bytes for an ICMP
        // error, rounded up generously; u64-aligned.
        let mut buf =
            vec![0u64; (size_of::<ICMP_ECHO_REPLY>() + PAYLOAD.len() + 8 + 128).div_ceil(8)];
        // SAFETY: handle closed on every path; buffers outlive the call.
        unsafe {
            let h = IcmpCreateFile();
            if h == INVALID_HANDLE_VALUE {
                return Err(std::io::Error::last_os_error());
            }
            let opts = options(ttl);
            let n = IcmpSendEcho(
                h,
                u32::from_ne_bytes(dest.octets()),
                PAYLOAD.as_ptr().cast(),
                PAYLOAD.len() as u16,
                &opts,
                buf.as_mut_ptr().cast(),
                (buf.len() * 8) as u32,
                timeout_ms,
            );
            let err = GetLastError();
            IcmpCloseHandle(h);
            if n == 0 {
                return if err == IP_REQ_TIMED_OUT {
                    Ok(ProbeReply::timeout())
                } else {
                    status_only(err)
                };
            }
            let r = &*buf.as_ptr().cast::<ICMP_ECHO_REPLY>();
            Ok(match kind(r.Status) {
                Some(k) => ProbeReply {
                    kind: k,
                    from: Some(crate::util::ipv4_from_ne(r.Address).into()),
                    rtt_ms: Some(r.RoundTripTime),
                },
                None => ProbeReply::timeout(),
            })
        }
    }

    fn probe_v6(dest: Ipv6Addr, ttl: u8, timeout_ms: u32) -> std::io::Result<ProbeReply> {
        let mut buf =
            vec![0u64; (size_of::<ICMPV6_ECHO_REPLY_LH>() + PAYLOAD.len() + 8 + 256).div_ceil(8)];
        // SAFETY: as above; the reply struct is packed, so it is read unaligned.
        unsafe {
            let h = Icmp6CreateFile();
            if h == INVALID_HANDLE_VALUE {
                return Err(std::io::Error::last_os_error());
            }
            let mut src: SOCKADDR_IN6 = std::mem::zeroed();
            src.sin6_family = AF_INET6;
            let mut dst: SOCKADDR_IN6 = std::mem::zeroed();
            dst.sin6_family = AF_INET6;
            dst.sin6_addr = IN6_ADDR {
                u: IN6_ADDR_0 {
                    Byte: dest.octets(),
                },
            };
            let opts = options(ttl);
            let n = Icmp6SendEcho2(
                h,
                std::ptr::null_mut(),
                None,
                std::ptr::null(),
                &src,
                &dst,
                PAYLOAD.as_ptr().cast(),
                PAYLOAD.len() as u16,
                &opts,
                buf.as_mut_ptr().cast(),
                (buf.len() * 8) as u32,
                timeout_ms,
            );
            let err = GetLastError();
            if n == 0 {
                IcmpCloseHandle(h);
                return if err == IP_REQ_TIMED_OUT {
                    Ok(ProbeReply::timeout())
                } else {
                    status_only(err)
                };
            }
            Icmp6ParseReplies(buf.as_mut_ptr().cast(), (buf.len() * 8) as u32);
            IcmpCloseHandle(h);
            let r: ICMPV6_ECHO_REPLY_LH = std::ptr::read_unaligned(buf.as_ptr().cast());
            let words = r.Address.sin6_addr;
            let mut bytes = [0u8; 16];
            for (i, w) in words.iter().enumerate() {
                bytes[i * 2..i * 2 + 2].copy_from_slice(&w.to_ne_bytes());
            }
            Ok(match kind(r.Status) {
                Some(k) => ProbeReply {
                    kind: k,
                    from: Some(Ipv6Addr::from(bytes).into()),
                    rtt_ms: Some(r.RoundTripTime),
                },
                None => ProbeReply::timeout(),
            })
        }
    }

    /// Some ICMP statuses come back as the call's error code with no reply.
    fn status_only(code: u32) -> std::io::Result<ProbeReply> {
        match kind(code) {
            Some(k) => Ok(ProbeReply {
                kind: k,
                from: None,
                rtt_ms: None,
            }),
            None if (11000..11100).contains(&code) => Ok(ProbeReply::timeout()),
            None => Err(std::io::Error::from_raw_os_error(code as i32)),
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn loopback_answers_directly() {
        let r = probe("127.0.0.1".parse().unwrap(), 64, 1000).unwrap();
        assert_eq!(r.kind, ProbeKind::Reached);
        assert_eq!(r.from, Some("127.0.0.1".parse().unwrap()));
        let r = probe("::1".parse().unwrap(), 64, 1000).unwrap();
        assert_eq!(r.kind, ProbeKind::Reached);
    }
}

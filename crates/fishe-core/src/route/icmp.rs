//! One ICMP echo probe with a given TTL.
//!
//! - Windows: the ICMP API (`IcmpSendEcho`), no administrator rights.
//! - Linux: a raw ICMP socket, which needs the permission capture needs too
//!   (`CAP_NET_RAW`, see `npcap.rs`). The socket receives every ICMP
//!   message addressed to this machine, so replies are matched to the probe
//!   by the identifier and sequence number of the echo request, which
//!   routers quote back in their errors ([`wire`]).

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

#[cfg(any(windows, target_os = "linux"))]
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

#[cfg(target_os = "linux")]
pub use linux::probe;

/// Other platforms: ping and traceroute report this error instead of probing.
#[cfg(not(any(windows, target_os = "linux")))]
pub fn probe(_dest: IpAddr, _ttl: u8, _timeout_ms: u32) -> std::io::Result<ProbeReply> {
    Err(std::io::Error::other(
        "ping and traceroute are not implemented on this platform",
    ))
}

/// ICMP echo on the wire: building the request and recognising the answers
/// to it. Pure, so it is tested on every platform.
#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
mod wire {
    use super::ProbeKind;

    /// Like the Windows probe's payload (content is irrelevant).
    const PAYLOAD: [u8; 32] = *b"fishe-route-probe-fishe-route-pr";

    const V4_ECHO_REPLY: u8 = 0;
    const V4_UNREACHABLE: u8 = 3;
    const V4_ECHO_REQUEST: u8 = 8;
    const V4_TIME_EXCEEDED: u8 = 11;
    const V6_UNREACHABLE: u8 = 1;
    const V6_TIME_EXCEEDED: u8 = 3;
    const V6_ECHO_REQUEST: u8 = 128;
    const V6_ECHO_REPLY: u8 = 129;
    const PROTO_ICMP: u8 = 1;
    const PROTO_ICMPV6: u8 = 58;

    /// The Internet checksum (RFC 1071).
    pub fn checksum(data: &[u8]) -> u16 {
        let mut sum = 0u32;
        for pair in data.chunks(2) {
            sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// An echo request. The IPv4 checksum is filled in; for IPv6 the kernel
    /// computes it (it covers addresses only the kernel knows).
    pub fn echo_request(v6: bool, id: u16, seq: u16) -> Vec<u8> {
        let mut p = vec![0u8; 8 + PAYLOAD.len()];
        p[0] = if v6 { V6_ECHO_REQUEST } else { V4_ECHO_REQUEST };
        p[4..6].copy_from_slice(&id.to_be_bytes());
        p[6..8].copy_from_slice(&seq.to_be_bytes());
        p[8..].copy_from_slice(&PAYLOAD);
        if !v6 {
            let sum = checksum(&p);
            p[2..4].copy_from_slice(&sum.to_be_bytes());
        }
        p
    }

    /// Is this ICMP message (header onwards) an echo of `kind` with our
    /// identifier and sequence number?
    fn is_echo(icmp: &[u8], kind: u8, id: u16, seq: u16) -> bool {
        icmp.len() >= 8
            && icmp[0] == kind
            && icmp[4..6] == id.to_be_bytes()
            && icmp[6..8] == seq.to_be_bytes()
    }

    /// What an IPv4 packet received on the raw socket (IP header included)
    /// says about our probe; `None` when it is about something else.
    pub fn classify_v4(packet: &[u8], id: u16, seq: u16) -> Option<ProbeKind> {
        let icmp = packet.get(usize::from(packet.first()? & 0x0f) * 4..)?;
        let kind = match *icmp.first()? {
            V4_ECHO_REPLY => {
                return is_echo(icmp, V4_ECHO_REPLY, id, seq).then_some(ProbeKind::Reached);
            }
            V4_TIME_EXCEEDED => ProbeKind::TtlExpired,
            V4_UNREACHABLE => ProbeKind::Unreachable,
            _ => return None,
        };
        // An error quotes the packet it is about: its IP header, then the
        // first 8 bytes of our echo request.
        let quoted = icmp.get(8..)?;
        let inner = quoted.get(usize::from(quoted.first()? & 0x0f) * 4..)?;
        (quoted.get(9) == Some(&PROTO_ICMP) && is_echo(inner, V4_ECHO_REQUEST, id, seq))
            .then_some(kind)
    }

    /// The same for an ICMPv6 message (raw IPv6 sockets deliver no IP header).
    pub fn classify_v6(icmp: &[u8], id: u16, seq: u16) -> Option<ProbeKind> {
        let kind = match *icmp.first()? {
            V6_ECHO_REPLY => {
                return is_echo(icmp, V6_ECHO_REPLY, id, seq).then_some(ProbeKind::Reached);
            }
            V6_TIME_EXCEEDED => ProbeKind::TtlExpired,
            V6_UNREACHABLE => ProbeKind::Unreachable,
            _ => return None,
        };
        // Quoted: the fixed 40-byte IPv6 header, then our echo request.
        let quoted = icmp.get(8..)?;
        (quoted.get(6) == Some(&PROTO_ICMPV6)
            && is_echo(quoted.get(40..)?, V6_ECHO_REQUEST, id, seq))
        .then_some(kind)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::io;
    use std::mem::MaybeUninit;
    use std::net::SocketAddr;
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicU16, Ordering};
    use std::time::{Duration, Instant};

    /// Identifier of this process's probes (random, so two programs pinging
    /// at once do not read each other's replies) and a running sequence.
    fn next_id() -> (u16, u16) {
        static ID: OnceLock<u16> = OnceLock::new();
        static SEQ: AtomicU16 = AtomicU16::new(0);
        let id = *ID.get_or_init(|| {
            let mut b = [0u8; 2];
            if getrandom::fill(&mut b).is_err() {
                b = (std::process::id() as u16).to_be_bytes();
            }
            u16::from_be_bytes(b)
        });
        (id, SEQ.fetch_add(1, Ordering::Relaxed))
    }

    /// Send one echo with `ttl`; waits up to `timeout_ms`.
    pub fn probe(dest: IpAddr, ttl: u8, timeout_ms: u32) -> io::Result<ProbeReply> {
        let v6 = dest.is_ipv6();
        let (domain, protocol) = if v6 {
            (Domain::IPV6, Protocol::ICMPV6)
        } else {
            (Domain::IPV4, Protocol::ICMPV4)
        };
        let socket = Socket::new(domain, Type::RAW, Some(protocol)).map_err(|e| {
            if e.kind() == io::ErrorKind::PermissionDenied {
                io::Error::new(
                    e.kind(),
                    "ping and traceroute need the permission to capture packets (CAP_NET_RAW)",
                )
            } else {
                e
            }
        })?;
        if v6 {
            socket.set_unicast_hops_v6(u32::from(ttl))?;
        } else {
            socket.set_ttl_v4(u32::from(ttl))?;
        }

        let (id, seq) = next_id();
        let timeout = Duration::from_millis(u64::from(timeout_ms));
        let started = Instant::now();
        socket.send_to(
            &wire::echo_request(v6, id, seq),
            &SockAddr::from(SocketAddr::new(dest, 0)),
        )?;

        let mut buf = [MaybeUninit::<u8>::uninit(); 1500];
        loop {
            let Some(left) = timeout
                .checked_sub(started.elapsed())
                .filter(|d| !d.is_zero())
            else {
                return Ok(ProbeReply::timeout());
            };
            socket.set_read_timeout(Some(left))?;
            let (n, from) = match socket.recv_from(&mut buf) {
                Ok(r) => r,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue; // the deadline check above ends the wait
                }
                Err(e) => return Err(e),
            };
            // SAFETY: `recv_from` initialised the first `n` bytes.
            let data = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n) };
            let kind = if v6 {
                wire::classify_v6(data, id, seq)
            } else {
                wire::classify_v4(data, id, seq)
            };
            if let Some(kind) = kind {
                return Ok(ProbeReply {
                    kind,
                    from: from.as_socket().map(|a| a.ip()),
                    rtt_ms: Some(started.elapsed().as_millis() as u32),
                });
            }
        }
    }
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

#[cfg(test)]
mod wire_tests {
    use super::ProbeKind;
    use super::wire::*;

    /// An IPv4 header (20 bytes, protocol ICMP) in front of `payload`.
    fn ipv4(payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[9] = 1;
        p.extend_from_slice(payload);
        p
    }

    /// An ICMP error of `kind` quoting `original`.
    fn error(kind: u8, original: &[u8]) -> Vec<u8> {
        let mut p = vec![kind, 0, 0, 0, 0, 0, 0, 0];
        p.extend_from_slice(original);
        p
    }

    #[test]
    fn checksum_of_a_request_verifies() {
        let p = echo_request(false, 0x1234, 7);
        assert_eq!(p[0], 8);
        assert_eq!(checksum(&p), 0, "a packet with its checksum sums to zero");
        // RFC 1071's example.
        assert_eq!(
            checksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]),
            !0xddf2
        );
        assert_eq!(checksum(&[0xff]), !0xff00, "an odd byte is padded");
    }

    #[test]
    fn ipv4_answers_are_matched_to_the_probe() {
        let (id, seq) = (0xbeef, 42);
        let request = echo_request(false, id, seq);
        let mut reply = request.clone();
        reply[0] = 0;
        assert_eq!(
            classify_v4(&ipv4(&reply), id, seq),
            Some(ProbeKind::Reached)
        );
        assert_eq!(
            classify_v4(&ipv4(&reply), id, seq + 1),
            None,
            "another probe's reply"
        );
        assert_eq!(
            classify_v4(&ipv4(&reply), id + 1, seq),
            None,
            "another program's reply"
        );
        assert_eq!(
            classify_v4(&ipv4(&request), id, seq),
            None,
            "our own request, seen on loopback"
        );

        // A router quotes the IP header and the first 8 bytes of the request.
        let quoted = ipv4(&request[..8]);
        assert_eq!(
            classify_v4(&ipv4(&error(11, &quoted)), id, seq),
            Some(ProbeKind::TtlExpired)
        );
        assert_eq!(
            classify_v4(&ipv4(&error(3, &quoted)), id, seq),
            Some(ProbeKind::Unreachable)
        );
        assert_eq!(classify_v4(&ipv4(&error(11, &quoted)), id, seq + 1), None);
        // An error about somebody's UDP packet is not ours.
        let mut udp = quoted.clone();
        udp[9] = 17;
        assert_eq!(classify_v4(&ipv4(&error(11, &udp)), id, seq), None);
        // Truncated and empty input.
        assert_eq!(classify_v4(&ipv4(&error(11, &quoted))[..30], id, seq), None);
        assert_eq!(classify_v4(&[], id, seq), None);
        assert_eq!(classify_v4(&[0x4f, 0, 0], id, seq), None);
    }

    #[test]
    fn ipv6_answers_are_matched_to_the_probe() {
        let (id, seq) = (0x0102, 9);
        let request = echo_request(true, id, seq);
        assert_eq!(request[0], 128);
        assert_eq!(
            &request[2..4],
            &[0, 0],
            "the kernel fills the IPv6 checksum"
        );
        let mut reply = request.clone();
        reply[0] = 129;
        assert_eq!(classify_v6(&reply, id, seq), Some(ProbeKind::Reached));
        assert_eq!(classify_v6(&reply, id, seq + 1), None);

        let mut quoted = vec![0u8; 40];
        quoted[0] = 0x60;
        quoted[6] = 58;
        quoted.extend_from_slice(&request);
        assert_eq!(
            classify_v6(&error(3, &quoted), id, seq),
            Some(ProbeKind::TtlExpired)
        );
        assert_eq!(
            classify_v6(&error(1, &quoted), id, seq),
            Some(ProbeKind::Unreachable)
        );
        assert_eq!(
            classify_v6(&error(3, &quoted[..44]), id, seq),
            None,
            "truncated"
        );
        // Neighbour discovery and the like.
        assert_eq!(classify_v6(&[135, 0, 0, 0, 0, 0, 0, 0], id, seq), None);
    }
}

#[cfg(all(test, any(windows, target_os = "linux")))]
mod tests {
    use super::*;

    /// On Linux this needs `CAP_NET_RAW` (root in the check container).
    #[test]
    #[cfg_attr(target_os = "linux", ignore = "needs CAP_NET_RAW")]
    fn loopback_answers_directly() {
        let r = probe("127.0.0.1".parse().unwrap(), 64, 1000).unwrap();
        assert_eq!(r.kind, ProbeKind::Reached);
        assert_eq!(r.from, Some("127.0.0.1".parse().unwrap()));
        let r = probe("::1".parse().unwrap(), 64, 1000).unwrap();
        assert_eq!(r.kind, ProbeKind::Reached);
    }
}

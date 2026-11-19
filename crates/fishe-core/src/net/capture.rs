//! Opening a pcap capture: the measuring captures (headers only, see
//! `docs/capture-engine.md` § 3) and the naming captures (payload, small
//! filter). Reading from one is the worker's job in `monitor/engine.rs`,
//! always through [`next_packet`] so that a read never blocks for long.

use crate::error::{AppError, AppResult};
use crate::net::parse::LinkLayer;
use pcap::{Active, Capture};

/// Bytes copied per packet: enough for Ethernet + VLAN + IPv6 + ext headers + ports.
pub const SNAPLEN: i32 = 192;
/// Upper bound on how long [`next_packet`] waits.
pub const READ_TIMEOUT_MS: i32 = 50;
/// Kernel buffer per interface.
const BUFFER_BYTES_SINGLE: i32 = 8 * 1024 * 1024;
const BUFFER_BYTES_MULTI: i32 = 4 * 1024 * 1024;

/// An opened, filtered capture ready for a worker.
pub struct OpenCapture {
    pub capture: Capture<Active>,
    pub link: LinkLayer,
    pub link_type: i32,
    pub device_name: String,
    pub device_description: String,
}

/// Prepare an opened capture for [`next_packet`]. On Unix that means
/// non-blocking: libpcap on Linux does not return from a read when no packet
/// arrives, whatever its timeout says, so the wait is done on the file
/// descriptor instead. Npcap honours the timeout and needs nothing.
pub fn bounded(capture: Capture<Active>) -> Result<Capture<Active>, pcap::Error> {
    #[cfg(unix)]
    let capture = capture.setnonblock()?;
    Ok(capture)
}

/// The next packet, or `Err(TimeoutExpired)` when none arrived within the
/// capture's read timeout ([`READ_TIMEOUT_MS`] for [`open`]). Every loop that
/// reads packets uses this, so it gets to look at its stop flag between
/// reads even on a silent interface. The capture must come from [`bounded`].
pub fn next_packet(capture: &mut Capture<Active>) -> Result<pcap::Packet<'_>, pcap::Error> {
    #[cfg(unix)]
    wait_readable(capture, READ_TIMEOUT_MS);
    capture.next_packet()
}

/// Wait until `capture` has a packet to read, at most `timeout_ms`.
#[cfg(unix)]
fn wait_readable(capture: &Capture<Active>, timeout_ms: i32) {
    use std::os::unix::io::AsRawFd;
    let mut fd = libc::pollfd {
        fd: capture.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `fd` is one valid `pollfd` that outlives the call. A failed or
    // interrupted poll just means the read below finds nothing.
    unsafe { libc::poll(&mut fd, 1, timeout_ms) };
}

/// Open `device` for measuring with the given BPF `filter` (headers only).
pub fn open(device: pcap::Device, filter: &str, multi: bool) -> AppResult<OpenCapture> {
    let buffer = if multi {
        BUFFER_BYTES_MULTI
    } else {
        BUFFER_BYTES_SINGLE
    };
    open_with(device, filter, SNAPLEN, buffer)
}

/// Open `device` with an explicit snap length and kernel buffer size.
pub fn open_with(
    device: pcap::Device,
    filter: &str,
    snaplen: i32,
    buffer: i32,
) -> AppResult<OpenCapture> {
    let device_name = device.name.clone();
    let device_description = device.desc.clone().unwrap_or_else(|| device.name.clone());
    let mut capture = bounded(
        Capture::from_device(device)?
            .promisc(false)
            .snaplen(snaplen)
            .timeout(READ_TIMEOUT_MS)
            .immediate_mode(true)
            .buffer_size(buffer)
            .open()?,
    )?;

    let link_type = capture.get_datalink().0;
    let link = LinkLayer::from_dlt(link_type).ok_or_else(|| {
        AppError::Unavailable(format!(
            "unsupported link type {link_type} on {device_description}"
        ))
    })?;
    capture.filter(filter, true)?;

    Ok(OpenCapture {
        capture,
        link,
        link_type,
        device_name,
        device_description,
    })
}

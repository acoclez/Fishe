//! Routes: which routers sit between this machine and an endpoint.
//!
//! - [`icmp`]: one ICMP echo probe with a chosen TTL, through the Windows
//!   ICMP API (`IcmpSendEcho` / `Icmp6SendEcho2`, no admin rights) or a raw
//!   ICMP socket on Linux. A router that drops the probe because its TTL
//!   ran out answers "time exceeded", revealing itself; the destination
//!   answers the echo.
//! - [`trace`]: a traceroute built from those probes, TTLs probed in parallel.
//! - [`lan`]: default gateways and the neighbour (ARP/NDP) table, from the
//!   IP Helper API on Windows and from [`netlink`] on Linux.
//! - [`ping`]: continuous ping (1/s) for RTT, jitter and loss.
//!
//! Traceroutes and pings send real packets, so they only run when the UI asks.
//! See `docs/network-map.md`.

pub mod icmp;
pub mod lan;
pub mod netlink;
pub mod ping;
pub mod trace;

use crate::geo::Owner;
use crate::naming::addr::AddrScope;
use serde::Serialize;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub enum HopStatus {
    /// A router answered "time exceeded".
    Router,
    /// The destination answered.
    Destination,
    /// A router answered "unreachable" (route ends here).
    Unreachable,
    /// No answer to any probe.
    Silent,
}

#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Hop {
    /// 1 = first router (usually the home gateway).
    pub ttl: u8,
    pub addr: Option<IpAddr>,
    /// Other addresses answering at the same TTL (load-balanced paths).
    pub alternates: Vec<IpAddr>,
    /// Fastest probe round trip, milliseconds.
    pub rtt_ms: Option<u32>,
    pub sent: u8,
    pub received: u8,
    pub status: HopStatus,
    pub name: Option<String>,
    pub owner: Option<Owner>,
    pub scope: Option<AddrScope>,
}

#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct TraceResult {
    pub target: IpAddr,
    /// Unix ms.
    pub started_at: i64,
    pub duration_ms: u64,
    /// The destination answered.
    pub reached: bool,
    pub hops: Vec<Hop>,
}

//! Process mode: who owns which socket.
//!
//! Captured packets carry no process id, so Fishe attributes each packet by
//! its **local port** using two sources that feed one
//! [`ownership::OwnershipTable`]:
//!
//! | source | how | needs admin | catches |
//! |---|---|---|---|
//! | [`sockets`] | poll the socket table every tick: Windows' TCP/UDP tables (`GetExtended{Tcp,Udp}Table`), or `/proc` on Linux ([`procfs`]) | no on Windows; on Linux root is needed to see other users' programs | every socket alive at poll time |
//! | [`etw`] | Microsoft-Windows-Kernel-Network events (connect / accept / UDP send / recv); Windows | yes | short-lived sockets the poll would miss |
//!
//! [`scope`] decides which packets belong to a monitored program (process
//! mode); [`machine`] labels every packet with its owner (all-traffic mode);
//! [`refresh`] keeps both current from the socket table each tick.
//!
//! See `docs/process-mode.md` and `docs/all-traffic.md`.

/// Whether this platform can tell which program a packet belongs to
/// (process mode and all-traffic mode).
pub const SUPPORTED: bool = cfg!(any(windows, target_os = "linux"));

pub mod elevation;
pub mod etw;
pub mod machine;
pub mod ownership;
pub mod processes;
pub mod procfs;
pub mod refresh;
pub mod scope;
pub mod sockets;

//! Fishe's core: everything that measures, records and answers, with no
//! window in it.
//!
//! The desktop app (`src-tauri`) is one front door onto this crate, the MCP
//! server inside it is another; both work on one [`services::Services`]
//! value through [`ops`]. Nothing here depends on a GUI toolkit, so the same
//! code can run without a window, and platform-specific parts sit behind
//! `cfg` in their own modules.
//!
//! Module map (details in `docs/architecture.md`):
//!
//! | module      | role                                                         |
//! |-------------|--------------------------------------------------------------|
//! | `services`  | `Services`: all the state, and the notices a window listens to |
//! | `ops`       | operations shared by the IPC commands and the MCP tools      |
//! | `npcap`     | locate & load the Npcap runtime (delay-loaded wpcap.dll)     |
//! | `net`       | packet parsing, interface discovery, target resolution       |
//! | `process`   | process list, socket ownership (IP Helper + ETW), PID scope  |
//! | `naming`    | endpoint names: DNS/mDNS, TLS SNI, reverse DNS, address type |
//! | `monitor`   | capture workers, aggregator, counters, detector, events      |
//! | `archive`   | recordings: SQLite store, recorder, pcapng, exports          |
//! | `route`     | traceroute and ping (Windows ICMP API), gateways, neighbours |
//! | `lan`       | LAN map: adapter list, ARP sweep, MAC vendor, port probe     |
//! | `geo`       | endpoint owner & country: DB-IP Lite (offline), ipinfo (opt-in) |
//! | `mcp`       | the local MCP server for agents, and its stdio bridge        |
//! | `error`     | `AppError`, serialised as `{ code, message }`                |
//! | `paths`     | the data folder (`FISHE_DATA_DIR` or app data) and its layout |
//! | `logging`   | stderr + `logs/fishe.log`, per-module levels from `FISHE_LOG` |
//! | `util`      | time, address formatting, bounded parallel loop              |

pub mod archive;
pub mod error;
pub mod geo;
pub mod lan;
pub mod logging;
pub mod mcp;
pub mod monitor;
pub mod naming;
pub mod net;
pub mod npcap;
pub mod ops;
pub mod paths;
pub mod process;
pub mod route;
pub mod services;
pub mod util;

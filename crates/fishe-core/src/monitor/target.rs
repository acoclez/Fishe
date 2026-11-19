//! What a session monitors, and how a packet is matched against it.

use super::stats::Direction;
use crate::net::parse::PacketInfo;
use crate::process::machine::MachineScope;
use crate::process::scope::ProcessScope;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;

/// The target requested by the UI.
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum TargetSpec {
    /// All traffic between this machine and one remote address.
    Host { address: String },
    /// All traffic of one program (or one PID), to any address.
    Process { selector: ProcessSelector },
    /// Every packet of this machine, labelled with its program.
    All,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(tag = "by", rename_all = "camelCase")]
pub enum ProcessSelector {
    /// Every process with this executable name (case-insensitive), including
    /// ones started after monitoring began.
    Name { name: String },
    /// Exactly one process.
    Pid { pid: u32 },
}

/// Outcome of matching one packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Match(Direction),
    /// All-traffic mode: always counted, with the owning PID when known.
    Owned(Direction, Option<u32>),
    /// Not part of the target.
    Skip,
    /// Owner not known yet; hold briefly and retry (process mode only).
    Pending,
}

/// Per-packet matcher, cloned into every capture worker.
#[derive(Debug, Clone)]
pub enum Matcher {
    Host(IpAddr),
    Process(Arc<ProcessScope>),
    All(Arc<MachineScope>),
}

impl Matcher {
    pub fn classify(&self, info: &PacketInfo) -> Verdict {
        match self {
            Matcher::Host(target) => {
                if info.src == *target {
                    Verdict::Match(Direction::In)
                } else if info.dst == *target {
                    Verdict::Match(Direction::Out)
                } else {
                    Verdict::Skip
                }
            }
            Matcher::Process(scope) => scope.classify(info),
            Matcher::All(scope) => scope.classify(info),
        }
    }

    /// What a pending packet becomes when its owner never shows up: dropped
    /// (process mode: it isn't known to be ours) or counted without an owner
    /// (all-traffic mode: it is this machine's either way).
    pub fn unowned(&self, info: &PacketInfo) -> Option<Verdict> {
        match self {
            Matcher::All(scope) => Some(Verdict::Owned(scope.direction(info), None)),
            _ => None,
        }
    }

    /// Changes when a `Pending` packet might now classify differently.
    pub fn generation(&self) -> u64 {
        match self {
            Matcher::Host(_) => 0,
            Matcher::Process(scope) => scope.generation(),
            Matcher::All(scope) => scope.generation(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::parse::Transport;

    #[test]
    fn host_matcher_directions() {
        let m = Matcher::Host([1, 1, 1, 1].into());
        let mut p = PacketInfo {
            src: [1, 1, 1, 1].into(),
            dst: [10, 0, 0, 2].into(),
            transport: Transport::Udp,
            src_port: Some(53),
            dst_port: Some(5000),
            ttl: 64,
        };
        assert_eq!(m.classify(&p), Verdict::Match(Direction::In));
        std::mem::swap(&mut p.src, &mut p.dst);
        assert_eq!(m.classify(&p), Verdict::Match(Direction::Out));
        p.dst = [8, 8, 8, 8].into();
        assert_eq!(m.classify(&p), Verdict::Skip);
    }

    #[test]
    fn spec_json_shape() {
        let host: TargetSpec =
            serde_json::from_str(r#"{"kind":"host","address":"1.1.1.1"}"#).unwrap();
        assert!(matches!(host, TargetSpec::Host { .. }));
        let p: TargetSpec = serde_json::from_str(
            r#"{"kind":"process","selector":{"by":"name","name":"chrome.exe"}}"#,
        )
        .unwrap();
        assert!(matches!(
            p,
            TargetSpec::Process {
                selector: ProcessSelector::Name { .. }
            }
        ));
        let p: TargetSpec =
            serde_json::from_str(r#"{"kind":"process","selector":{"by":"pid","pid":42}}"#).unwrap();
        assert!(matches!(
            p,
            TargetSpec::Process {
                selector: ProcessSelector::Pid { pid: 42 }
            }
        ));
        let all: TargetSpec = serde_json::from_str(r#"{"kind":"all"}"#).unwrap();
        assert!(matches!(all, TargetSpec::All));
    }
}

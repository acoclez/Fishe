//! The devices seen on each local network, remembered between scans.
//!
//! A scan says who is there now. Remembering who was there before turns it
//! into two facts the security view uses: a device that was not there last
//! time, and a gateway that answers from a hardware address never seen for
//! it. The second matters because a device that answers ARP in the
//! gateway's place receives the whole network's traffic.
//!
//! A network is recognised by its address range, its gateway's address and
//! its gateway's hardware address together. Two places that both use
//! `192.168.1.0/24` behind `192.168.1.1` are therefore two networks, each
//! with its own devices; the first scan of the second one is reported as a
//! gateway change, once, because the two cases cannot be told apart.
//!
//! The inventory is a small JSON file in the data folder (`lan.json`). It
//! holds hardware addresses, names and vendors of devices on the user's own
//! networks, never leaves the machine, and is deleted by
//! [`LanState::forget`].

use super::ScanResult;
use super::dhcp::DhcpServer;
use crate::security::{KnownLan, NewDevice};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Mutex;

/// Networks remembered; the one scanned longest ago makes room.
pub const MAX_NETWORKS: usize = 32;
/// Devices remembered per network; the one seen longest ago makes room.
pub const MAX_DEVICES: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownDevice {
    pub ip: Ipv4Addr,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    /// Unix ms.
    pub first_seen: i64,
    pub last_seen: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownNetwork {
    /// "192.168.1.0/24"
    pub network: String,
    pub gateway: Option<Ipv4Addr>,
    /// The gateway's hardware address: part of what identifies the network.
    pub gateway_mac: Option<String>,
    /// Set by the scan that first saw this gateway address on a range and
    /// gateway already known with another one; cleared by the next scan.
    #[serde(default)]
    pub gateway_was: Option<String>,
    pub first_scan: i64,
    pub last_scan: i64,
    pub scans: u32,
    /// By hardware address.
    pub devices: BTreeMap<String, KnownDevice>,
    /// Hardware addresses first seen in the latest scan.
    #[serde(default)]
    pub new_devices: Vec<String>,
    /// The DHCP servers that answered in the latest scan.
    #[serde(default)]
    pub dhcp: Vec<DhcpServer>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Inventory {
    #[serde(default)]
    pub networks: Vec<KnownNetwork>,
}

/// What one scan changed for one network.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Changes {
    /// Hardware addresses not seen before on this network (empty on its
    /// first scan, when everything is new).
    pub new_devices: Vec<String>,
    /// The gateway's previous hardware address, if it changed.
    pub gateway_was: Option<String>,
}

/// "192.168.1.0/24" for an address and its prefix length.
pub fn network_of(ip: Ipv4Addr, prefix: u8) -> String {
    let prefix = prefix.min(32);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    format!("{}/{prefix}", Ipv4Addr::from(u32::from(ip) & mask))
}

impl Inventory {
    /// Fold a scan in. Returns, per scanned network (same order), what
    /// changed since that network was last scanned.
    pub fn record(&mut self, scan: &ScanResult, now: i64) -> Vec<Changes> {
        let changes = scan
            .networks
            .iter()
            .map(|n| self.record_network(n, now))
            .collect();
        // Latest first; beyond the cap the oldest go.
        self.networks.sort_by(|a, b| {
            b.last_scan
                .cmp(&a.last_scan)
                .then_with(|| a.network.cmp(&b.network))
        });
        self.networks.truncate(MAX_NETWORKS);
        changes
    }

    fn record_network(&mut self, net: &super::Network, now: i64) -> Changes {
        let network = network_of(net.ip, net.prefix);
        let gateway_mac = net
            .devices
            .iter()
            .find(|d| d.is_gateway)
            .and_then(|d| d.mac.clone());

        // Same range and gateway address: candidates. Among them, the one
        // with this gateway hardware address is this network; if the
        // gateway stayed silent, assume the one scanned last.
        let same_place = |k: &KnownNetwork| k.network == network && k.gateway == net.gateway;
        let index = match &gateway_mac {
            Some(mac) => self
                .networks
                .iter()
                .position(|k| same_place(k) && k.gateway_mac.as_ref() == Some(mac)),
            None => self
                .networks
                .iter()
                .enumerate()
                .filter(|(_, k)| same_place(k))
                .max_by_key(|(_, k)| k.last_scan)
                .map(|(i, _)| i),
        };

        let (index, first_time, gateway_was) = match index {
            Some(i) => (i, false, None),
            None => {
                // A gateway address not seen here before. If this range and
                // gateway were known with another one, say which.
                let was = self
                    .networks
                    .iter()
                    .filter(|k| same_place(k) && k.gateway_mac.is_some())
                    .max_by_key(|k| k.last_scan)
                    .and_then(|k| k.gateway_mac.clone());
                self.networks.push(KnownNetwork {
                    network,
                    gateway: net.gateway,
                    gateway_mac: gateway_mac.clone(),
                    gateway_was: None,
                    first_scan: now,
                    last_scan: now,
                    scans: 0,
                    devices: BTreeMap::new(),
                    new_devices: Vec::new(),
                    dhcp: Vec::new(),
                });
                (self.networks.len() - 1, true, was)
            }
        };

        let known = &mut self.networks[index];
        known.last_scan = now;
        known.scans = known.scans.saturating_add(1);
        known.gateway_was = gateway_was.clone();
        if known.gateway_mac.is_none() {
            known.gateway_mac = gateway_mac;
        }

        let mut new_devices = Vec::new();
        for d in net.devices.iter().filter(|d| !d.is_self) {
            let Some(mac) = &d.mac else {
                continue;
            };
            match known.devices.get_mut(mac) {
                Some(k) => {
                    k.ip = d.ip;
                    k.last_seen = now;
                    if d.vendor.is_some() {
                        k.vendor = d.vendor.clone();
                    }
                    if d.hostname.is_some() {
                        k.hostname = d.hostname.clone();
                    }
                }
                None => {
                    known.devices.insert(
                        mac.clone(),
                        KnownDevice {
                            ip: d.ip,
                            vendor: d.vendor.clone(),
                            hostname: d.hostname.clone(),
                            first_seen: now,
                            last_seen: now,
                        },
                    );
                    if !first_time {
                        new_devices.push(mac.clone());
                    }
                }
            }
        }
        while known.devices.len() > MAX_DEVICES {
            let Some(oldest) = known
                .devices
                .iter()
                .min_by_key(|(mac, d)| (d.last_seen, (*mac).clone()))
                .map(|(mac, _)| mac.clone())
            else {
                break;
            };
            known.devices.remove(&oldest);
        }
        known.new_devices = new_devices.clone();
        known.dhcp = net.dhcp.clone();
        Changes {
            new_devices,
            gateway_was,
        }
    }

    /// When a device was first seen on any known network.
    pub fn first_seen(&self, mac: &str) -> Option<i64> {
        self.networks
            .iter()
            .filter_map(|n| n.devices.get(mac))
            .map(|d| d.first_seen)
            .min()
    }

    /// The networks as the security report shows them, latest first.
    pub fn summary(&self) -> Vec<KnownLan> {
        let mut nets: Vec<&KnownNetwork> = self.networks.iter().collect();
        nets.sort_by(|a, b| {
            b.last_scan
                .cmp(&a.last_scan)
                .then_with(|| a.network.cmp(&b.network))
        });
        nets.into_iter()
            .map(|n| KnownLan {
                network: n.network.clone(),
                gateway: n.gateway.map(|g| g.to_string()),
                gateway_mac: n.gateway_mac.clone(),
                devices: n.devices.len() as u32,
                scans: n.scans,
                first_scan: n.first_scan,
                last_scan: n.last_scan,
                new_devices: n
                    .new_devices
                    .iter()
                    .filter_map(|mac| {
                        let d = n.devices.get(mac)?;
                        Some(NewDevice {
                            mac: mac.clone(),
                            ip: d.ip.to_string(),
                            vendor: d.vendor.clone(),
                            hostname: d.hostname.clone(),
                        })
                    })
                    .collect(),
                gateway_was: n.gateway_was.clone(),
                dhcp: n.dhcp.clone(),
            })
            .collect()
    }
}

/// The inventory on disk, loaded on first use.
pub struct LanState {
    path: PathBuf,
    cache: Mutex<Option<Inventory>>,
}

impl LanState {
    pub fn new(path: PathBuf) -> Self {
        LanState {
            path,
            cache: Mutex::new(None),
        }
    }

    fn with<T>(&self, f: impl FnOnce(&mut Inventory) -> T) -> T {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        let inv = cache.get_or_insert_with(|| {
            // Missing or unreadable: start empty (a damaged file is
            // replaced at the next scan).
            std::fs::read_to_string(&self.path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default()
        });
        f(inv)
    }

    /// A copy of what is known.
    pub fn inventory(&self) -> Inventory {
        self.with(|inv| inv.clone())
    }

    /// Fold a scan in, mark its devices (new, first seen) and save.
    pub fn record(&self, scan: &mut ScanResult, now: i64) {
        let json = self.with(|inv| {
            let changes = inv.record(scan, now);
            for (net, change) in scan.networks.iter_mut().zip(&changes) {
                for d in &mut net.devices {
                    let Some(mac) = &d.mac else {
                        continue;
                    };
                    d.is_new = change.new_devices.contains(mac);
                    d.first_seen = inv.first_seen(mac);
                }
            }
            serde_json::to_string(inv)
        });
        match json {
            Ok(json) => {
                if let Err(e) = crate::util::write_atomic(&self.path, json.as_bytes()) {
                    log::warn!("could not save {}: {e}", self.path.display());
                }
            }
            Err(e) => log::warn!("could not encode the device inventory: {e}"),
        }
    }

    /// Forget every network and device, on disk too.
    pub fn forget(&self) -> std::io::Result<()> {
        self.with(|inv| *inv = Inventory::default());
        match std::fs::remove_file(&self.path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Device, Network};
    use super::*;

    fn device(ip: [u8; 4], mac: &str) -> Device {
        Device {
            ip: ip.into(),
            mac: Some(mac.into()),
            vendor: None,
            hostname: None,
            randomized_mac: false,
            is_gateway: false,
            is_self: false,
            is_new: false,
            first_seen: None,
            ports: Vec::new(),
        }
    }

    /// 192.168.1.0/24 behind 192.168.1.1 (hardware address `gw`), with
    /// this PC and the given devices.
    fn scan(gw: Option<&str>, devices: &[Device]) -> ScanResult {
        let mut all = vec![
            Device {
                is_gateway: true,
                mac: gw.map(str::to_string),
                ..device([192, 168, 1, 1], "")
            },
            Device {
                is_self: true,
                ..device([192, 168, 1, 19], "02:00:00:00:00:19")
            },
        ];
        all.extend(devices.iter().cloned());
        ScanResult {
            networks: vec![Network {
                interface: "Ethernet".into(),
                description: String::new(),
                ip: [192, 168, 1, 19].into(),
                prefix: 24,
                gateway: Some([192, 168, 1, 1].into()),
                wireless: false,
                narrowed: false,
                devices: all,
                dhcp: Vec::new(),
            }],
            duration_ms: 1,
            probed_ports: false,
            note: None,
        }
    }

    const ROUTER: &str = "c8:7f:2b:35:1a:c0";
    const NAS: &str = "00:11:32:aa:bb:cc";
    const PHONE: &str = "a2:b4:c6:d8:e0:f2";

    #[test]
    fn network_ranges() {
        assert_eq!(network_of([192, 168, 1, 19].into(), 24), "192.168.1.0/24");
        assert_eq!(network_of([10, 20, 30, 40].into(), 16), "10.20.0.0/16");
        assert_eq!(network_of([10, 20, 30, 40].into(), 0), "0.0.0.0/0");
        assert_eq!(network_of([10, 20, 30, 40].into(), 40), "10.20.30.40/32");
    }

    #[test]
    fn the_first_scan_has_nothing_new_and_later_ones_say_who_joined() {
        let mut inv = Inventory::default();
        let nas = device([192, 168, 1, 50], NAS);
        let c = inv.record(&scan(Some(ROUTER), std::slice::from_ref(&nas)), 1000);
        assert_eq!(c, [Changes::default()], "everything is new the first time");
        assert_eq!(inv.networks.len(), 1);
        let n = &inv.networks[0];
        assert_eq!((n.network.as_str(), n.scans), ("192.168.1.0/24", 1));
        assert_eq!(n.gateway_mac.as_deref(), Some(ROUTER));
        // The gateway and the NAS, not this PC.
        assert_eq!(n.devices.keys().collect::<Vec<_>>(), [NAS, ROUTER]);

        // A phone joins; the NAS moved to another address.
        let moved = device([192, 168, 1, 51], NAS);
        let phone = device([192, 168, 1, 77], PHONE);
        let c = inv.record(&scan(Some(ROUTER), &[moved, phone.clone()]), 2000);
        assert_eq!(c[0].new_devices, [PHONE]);
        assert_eq!(c[0].gateway_was, None);
        let n = &inv.networks[0];
        assert_eq!(n.scans, 2);
        assert_eq!(n.devices[NAS].ip, Ipv4Addr::new(192, 168, 1, 51));
        assert_eq!(
            (n.devices[NAS].first_seen, n.devices[NAS].last_seen),
            (1000, 2000)
        );
        assert_eq!(inv.first_seen(PHONE), Some(2000));

        let lan = &inv.summary()[0];
        assert_eq!((lan.devices, lan.scans, lan.last_scan), (3, 2, 2000));
        assert_eq!(lan.new_devices.len(), 1);
        assert_eq!(lan.new_devices[0].ip, "192.168.1.77");

        // The next scan: nobody new any more.
        let c = inv.record(&scan(Some(ROUTER), &[phone]), 3000);
        assert_eq!(c, [Changes::default()]);
        assert!(inv.summary()[0].new_devices.is_empty());
        // The NAS was off: still remembered.
        assert_eq!(inv.networks[0].devices[NAS].last_seen, 2000);
    }

    #[test]
    fn a_gateway_with_another_hardware_address_is_said_once() {
        let mut inv = Inventory::default();
        inv.record(&scan(Some(ROUTER), &[device([192, 168, 1, 50], NAS)]), 1000);

        let other = "de:ad:be:ef:00:01";
        let c = inv.record(&scan(Some(other), &[device([192, 168, 1, 50], NAS)]), 2000);
        assert_eq!(c[0].gateway_was.as_deref(), Some(ROUTER));
        assert!(
            c[0].new_devices.is_empty(),
            "a network seen for the first time has no 'new' devices"
        );
        assert_eq!(inv.networks.len(), 2, "kept apart from the first one");
        let latest = &inv.summary()[0];
        assert_eq!(latest.gateway_mac.as_deref(), Some(other));
        assert_eq!(latest.gateway_was.as_deref(), Some(ROUTER));

        // Scanning it again: known now, nothing to say.
        let c = inv.record(&scan(Some(other), &[]), 3000);
        assert_eq!(c[0].gateway_was, None);
        assert_eq!(inv.summary()[0].gateway_was, None);
        // Back on the first network: known too.
        let c = inv.record(&scan(Some(ROUTER), &[]), 4000);
        assert_eq!(c, [Changes::default()]);
        assert_eq!(inv.networks.len(), 2);
        assert_eq!(inv.summary()[0].gateway_mac.as_deref(), Some(ROUTER));
    }

    #[test]
    fn the_dhcp_servers_of_the_latest_scan_are_kept() {
        let server = |ip: [u8; 4]| DhcpServer {
            ip: ip.into(),
            mac: None,
            vendor: None,
            offered: None,
            router: Some(ip.into()),
            dns: vec![ip.into()],
            lease_secs: Some(3600),
            is_gateway: ip == [192, 168, 1, 1],
        };
        let mut inv = Inventory::default();
        let mut s = scan(Some(ROUTER), &[]);
        s.networks[0].dhcp = vec![server([192, 168, 1, 1]), server([192, 168, 1, 66])];
        inv.record(&s, 1000);
        assert_eq!(inv.summary()[0].dhcp.len(), 2);
        // The next scan only hears the router: that is what is kept.
        s.networks[0].dhcp.pop();
        inv.record(&s, 2000);
        assert_eq!(inv.summary()[0].dhcp, [server([192, 168, 1, 1])]);
        // An inventory written before this field existed still loads.
        let old = r#"{"networks":[{"network":"10.0.0.0/24","gateway":"10.0.0.1","gatewayMac":null,
            "firstScan":1,"lastScan":1,"scans":1,"devices":{}}]}"#;
        let inv: Inventory = serde_json::from_str(old).unwrap();
        assert!(inv.networks[0].dhcp.is_empty());
    }

    #[test]
    fn a_silent_gateway_is_not_a_change() {
        let mut inv = Inventory::default();
        inv.record(&scan(Some(ROUTER), &[]), 1000);
        let c = inv.record(&scan(None, &[device([192, 168, 1, 77], PHONE)]), 2000);
        assert_eq!(c[0].gateway_was, None);
        assert_eq!(c[0].new_devices, [PHONE]);
        assert_eq!(inv.networks.len(), 1);
        assert_eq!(inv.networks[0].gateway_mac.as_deref(), Some(ROUTER));
        // And a network whose gateway never answered learns it later.
        let mut inv = Inventory::default();
        inv.record(&scan(None, &[]), 1000);
        inv.record(&scan(None, &[]), 2000);
        assert_eq!(inv.networks.len(), 1);
        assert_eq!(inv.networks[0].gateway_mac, None);
    }

    #[test]
    fn the_inventory_is_bounded() {
        let mut inv = Inventory::default();
        for i in 0..(MAX_NETWORKS as u8 + 5) {
            let mut s = scan(Some(ROUTER), &[]);
            s.networks[0].ip = [10, i, 0, 19].into();
            s.networks[0].gateway = Some([10, i, 0, 1].into());
            inv.record(&s, i64::from(i));
        }
        assert_eq!(inv.networks.len(), MAX_NETWORKS);
        assert!(
            inv.networks.iter().all(|n| n.network != "10.0.0.0/24"),
            "the oldest went"
        );

        let mut inv = Inventory::default();
        let many: Vec<Device> = (0..(MAX_DEVICES as u32 + 10))
            .map(|i| {
                let b = i.to_be_bytes();
                device(
                    [192, 168, 1, 50],
                    &format!("02:00:{:02x}:{:02x}:{:02x}:{:02x}", b[0], b[1], b[2], b[3]),
                )
            })
            .collect();
        inv.record(&scan(Some(ROUTER), &many), 1);
        assert_eq!(inv.networks[0].devices.len(), MAX_DEVICES);
    }

    #[test]
    fn saved_loaded_marked_and_forgotten() {
        let dir = std::env::temp_dir().join(format!("fishe-lan-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("lan.json");
        let state = LanState::new(path.clone());
        assert_eq!(state.inventory(), Inventory::default());

        let mut first = scan(Some(ROUTER), &[device([192, 168, 1, 50], NAS)]);
        state.record(&mut first, 1000);
        assert!(first.networks[0].devices.iter().all(|d| !d.is_new));
        assert!(path.is_file());

        // Another process (the next run) reads the same thing back.
        let again = LanState::new(path.clone());
        assert_eq!(again.inventory(), state.inventory());
        let mut second = scan(
            Some(ROUTER),
            &[
                device([192, 168, 1, 50], NAS),
                device([192, 168, 1, 77], PHONE),
            ],
        );
        again.record(&mut second, 2000);
        let by_mac = |mac: &str| {
            second.networks[0]
                .devices
                .iter()
                .find(|d| d.mac.as_deref() == Some(mac))
                .unwrap()
        };
        assert!(by_mac(PHONE).is_new);
        assert_eq!(by_mac(PHONE).first_seen, Some(2000));
        assert!(!by_mac(NAS).is_new);
        assert_eq!(by_mac(NAS).first_seen, Some(1000));

        again.forget().unwrap();
        assert!(!path.exists());
        assert_eq!(again.inventory(), Inventory::default());
        again.forget().unwrap(); // nothing left: still fine

        // A damaged file is not fatal.
        std::fs::write(&path, b"{ not json").unwrap();
        assert_eq!(LanState::new(path).inventory(), Inventory::default());
        std::fs::remove_dir_all(&dir).ok();
    }
}

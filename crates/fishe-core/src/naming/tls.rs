//! Server Name Indication from a TLS ClientHello.
//!
//! The ClientHello is the first thing a client sends on a TLS connection
//! and, unless Encrypted Client Hello (ECH) is in use, it names the server
//! in clear text. Modern ClientHellos (post-quantum key shares) are often
//! larger than one TCP segment, so [`Reassembler`] stitches the first few
//! segments of each client→server flow together.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xFE0D;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sni {
    /// Server name found. `ech`: the hello also carries an ECH extension, so
    /// this is only the *outer*, public name (e.g. `cloudflare-ech.com`).
    Found { name: String, ech: bool },
    /// Need at least this many bytes in total.
    Incomplete(usize),
    /// A ClientHello without a server name.
    NoName,
    /// Not a TLS ClientHello.
    NotHello,
}

/// Parse the start of a client→server TLS stream.
pub fn client_hello_sni(data: &[u8]) -> Sni {
    // Record header: type 22 (handshake), version 3.x, length.
    if data.len() < 6 {
        return if data.first().is_none_or(|&b| b == 0x16) {
            Sni::Incomplete(6)
        } else {
            Sni::NotHello
        };
    }
    if data[0] != 0x16 || data[1] != 0x03 || data[5] != 0x01 {
        return Sni::NotHello;
    }
    let record_len = usize::from(u16::from_be_bytes([data[3], data[4]]));
    let need = 5 + record_len;
    if data.len() < need {
        return Sni::Incomplete(need);
    }
    parse_hello(&data[5..need]).unwrap_or(Sni::NoName)
}

fn parse_hello(hs: &[u8]) -> Option<Sni> {
    // handshake type(1) + length(3) + version(2) + random(32)
    let mut p = 4 + 2 + 32;
    let sid_len = usize::from(*hs.get(p)?);
    p += 1 + sid_len;
    let cs_len = usize::from(u16::from_be_bytes([*hs.get(p)?, *hs.get(p + 1)?]));
    p += 2 + cs_len;
    let comp_len = usize::from(*hs.get(p)?);
    p += 1 + comp_len;
    let ext_total = usize::from(u16::from_be_bytes([*hs.get(p)?, *hs.get(p + 1)?]));
    p += 2;
    let ext_end = (p + ext_total).min(hs.len());

    let mut name = None;
    let mut ech = false;
    while p + 4 <= ext_end {
        let ty = u16::from_be_bytes([hs[p], hs[p + 1]]);
        let len = usize::from(u16::from_be_bytes([hs[p + 2], hs[p + 3]]));
        let body = hs.get(p + 4..p + 4 + len)?;
        match ty {
            EXT_SERVER_NAME => name = server_name(body),
            EXT_ENCRYPTED_CLIENT_HELLO => ech = true,
            _ => {}
        }
        p += 4 + len;
    }
    Some(match name {
        Some(name) => Sni::Found { name, ech },
        None => Sni::NoName,
    })
}

fn server_name(body: &[u8]) -> Option<String> {
    // list length(2), then entries: type(1) = 0 host_name, length(2), name
    let mut p = 2;
    while p + 3 <= body.len() {
        let kind = body[p];
        let len = usize::from(u16::from_be_bytes([body[p + 1], body[p + 2]]));
        let value = body.get(p + 3..p + 3 + len)?;
        if kind == 0 {
            let s = std::str::from_utf8(value).ok()?;
            return super::is_host_name(s).then(|| s.to_ascii_lowercase());
        }
        p += 3 + len;
    }
    None
}

// ───────────────────────── reassembly ─────────────────────────

type FlowKey = (IpAddr, u16, IpAddr, u16);

struct Partial {
    next_seq: u32,
    buf: Vec<u8>,
    started: Instant,
}

/// Stitches the first segments of client→server flows until the SNI is known.
pub struct Reassembler {
    flows: HashMap<FlowKey, Partial>,
}

const MAX_HELLO: usize = 16 * 1024;
const MAX_FLOWS: usize = 1024;
const FLOW_TIMEOUT: Duration = Duration::from_secs(3);

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    pub fn new() -> Self {
        Reassembler {
            flows: HashMap::new(),
        }
    }

    /// Feed one client→server segment. Returns the server name once known.
    pub fn push(&mut self, key: FlowKey, seq: u32, payload: &[u8]) -> Option<Sni> {
        if payload.is_empty() {
            return None;
        }
        let buf = match self.flows.get_mut(&key) {
            Some(p) if p.next_seq == seq => {
                p.buf.extend_from_slice(payload);
                p.next_seq = seq.wrapping_add(payload.len() as u32);
                std::mem::take(&mut p.buf)
            }
            Some(_) => return None, // out of order / retransmit: ignore
            None => {
                if payload[0] != 0x16 {
                    return None; // not the start of a TLS handshake
                }
                payload.to_vec()
            }
        };

        match client_hello_sni(&buf) {
            Sni::Incomplete(need) if need <= MAX_HELLO && self.flows.len() < MAX_FLOWS => {
                let next_seq = seq.wrapping_add(payload.len() as u32);
                let started = self
                    .flows
                    .get(&key)
                    .map_or_else(Instant::now, |p| p.started);
                self.flows.insert(
                    key,
                    Partial {
                        next_seq,
                        buf,
                        started,
                    },
                );
                None
            }
            Sni::Incomplete(_) | Sni::NotHello => {
                self.flows.remove(&key);
                None
            }
            done => {
                self.flows.remove(&key);
                Some(done)
            }
        }
    }

    /// Drop flows that never completed.
    pub fn expire(&mut self) {
        self.flows.retain(|_, p| p.started.elapsed() < FLOW_TIMEOUT);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A plausible ClientHello record naming `host`, padded to `pad` extra bytes.
    pub(crate) fn hello(host: &str, pad: usize, ech: bool) -> Vec<u8> {
        let mut ext = Vec::new();
        // GREASE-ish unknown extension first
        ext.extend_from_slice(&[0x0A, 0x0A, 0, 0]);
        // padding extension (21)
        ext.extend_from_slice(&21u16.to_be_bytes());
        ext.extend_from_slice(&(pad as u16).to_be_bytes());
        ext.extend(std::iter::repeat_n(0u8, pad));
        // SNI
        let mut sni = vec![0u8];
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host.as_bytes());
        let mut list = (sni.len() as u16).to_be_bytes().to_vec();
        list.extend(sni);
        ext.extend_from_slice(&0u16.to_be_bytes());
        ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
        ext.extend(list);
        if ech {
            ext.extend_from_slice(&[0xFE, 0x0D, 0, 2, 0xAB, 0xCD]);
        }

        let mut body = vec![0x03, 0x03];
        body.extend([7u8; 32]); // random
        body.push(32);
        body.extend([1u8; 32]); // session id
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01, 0x13, 0x02]);
        body.extend_from_slice(&[1, 0]); // compression
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend(ext);

        let mut hs = vec![0x01];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend(body);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend(hs);
        rec
    }

    #[test]
    fn finds_sni() {
        assert_eq!(
            client_hello_sni(&hello("API.Example.com", 10, false)),
            Sni::Found {
                name: "api.example.com".into(),
                ech: false
            }
        );
    }

    #[test]
    fn flags_ech_outer_name() {
        assert_eq!(
            client_hello_sni(&hello("cloudflare-ech.com", 0, true)),
            Sni::Found {
                name: "cloudflare-ech.com".into(),
                ech: true
            }
        );
    }

    #[test]
    fn incomplete_and_not_tls() {
        let h = hello("example.com", 2000, false);
        assert_eq!(client_hello_sni(&h[..1400]), Sni::Incomplete(h.len()));
        assert_eq!(client_hello_sni(b"GET / HTTP/1.1\r\n"), Sni::NotHello);
        assert_eq!(
            client_hello_sni(&[0x17, 0x03, 0x03, 0, 5, 1]),
            Sni::NotHello
        ); // app data
    }

    #[test]
    fn reassembles_split_hello() {
        let h = hello("big.example.org", 2500, false);
        let key: FlowKey = (
            "10.0.0.2".parse().unwrap(),
            50000,
            "1.2.3.4".parse().unwrap(),
            443,
        );
        let mut r = Reassembler::new();
        assert_eq!(r.push(key, 1000, &h[..1400]), None);
        assert_eq!(r.push(key, 9999, &h[1400..]), None, "wrong seq ignored");
        assert_eq!(
            r.push(key, 1000 + 1400, &h[1400..]),
            Some(Sni::Found {
                name: "big.example.org".into(),
                ech: false
            })
        );
        assert!(r.flows.is_empty());
    }

    #[test]
    fn non_tls_flows_are_not_tracked() {
        let mut r = Reassembler::new();
        let key: FlowKey = (
            "10.0.0.2".parse().unwrap(),
            50001,
            "1.2.3.4".parse().unwrap(),
            443,
        );
        assert_eq!(r.push(key, 1, b"\x17\x03\x03\x00\x10payload"), None);
        assert!(r.flows.is_empty());
    }
}

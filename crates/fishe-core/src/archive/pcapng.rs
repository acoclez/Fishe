//! Minimal pcapng writer (little-endian).
//!
//! pcapng (rather than classic pcap) because one recording can span several
//! interfaces with different link types (Ethernet + loopback): each gets its
//! own Interface Description Block and packets reference it by index.
//!
//! Blocks written: Section Header, Interface Description (with name and
//! description), Enhanced Packet. Timestamps are microseconds (the default
//! resolution). Spec: <https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-02.html>

use std::io::{self, Write};

const SHB: u32 = 0x0A0D_0D0A;
const IDB: u32 = 0x0000_0001;
const EPB: u32 = 0x0000_0006;
const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;
const OPT_ENDOFOPT: u16 = 0;
const OPT_SHB_USERAPPL: u16 = 4;
const OPT_IF_NAME: u16 = 2;
const OPT_IF_DESCRIPTION: u16 = 3;

pub struct InterfaceDesc {
    pub link_type: u16,
    pub snaplen: u32,
    pub name: String,
    pub description: String,
}

pub struct PcapngWriter<W: Write> {
    out: W,
    pub packets: u64,
}

fn pad4(n: usize) -> usize {
    (4 - n % 4) % 4
}

/// Encode options (code, value) + end-of-options.
fn options(opts: &[(u16, &[u8])]) -> Vec<u8> {
    let mut v = Vec::new();
    for (code, value) in opts {
        v.extend_from_slice(&code.to_le_bytes());
        v.extend_from_slice(&(value.len() as u16).to_le_bytes());
        v.extend_from_slice(value);
        v.extend(std::iter::repeat_n(0u8, pad4(value.len())));
    }
    v.extend_from_slice(&OPT_ENDOFOPT.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v
}

fn block(out: &mut impl Write, kind: u32, body: &[u8]) -> io::Result<()> {
    let total = (12 + body.len()) as u32;
    out.write_all(&kind.to_le_bytes())?;
    out.write_all(&total.to_le_bytes())?;
    out.write_all(body)?;
    out.write_all(&total.to_le_bytes())
}

impl<W: Write> PcapngWriter<W> {
    pub fn new(mut out: W, interfaces: &[InterfaceDesc]) -> io::Result<Self> {
        let mut shb = Vec::new();
        shb.extend_from_slice(&BYTE_ORDER_MAGIC.to_le_bytes());
        shb.extend_from_slice(&1u16.to_le_bytes()); // major
        shb.extend_from_slice(&0u16.to_le_bytes()); // minor
        shb.extend_from_slice(&(-1i64).to_le_bytes()); // section length unknown
        let app = format!("Fishe {}", env!("CARGO_PKG_VERSION"));
        shb.extend(options(&[(OPT_SHB_USERAPPL, app.as_bytes())]));
        block(&mut out, SHB, &shb)?;

        for i in interfaces {
            let mut idb = Vec::new();
            idb.extend_from_slice(&i.link_type.to_le_bytes());
            idb.extend_from_slice(&0u16.to_le_bytes());
            idb.extend_from_slice(&i.snaplen.to_le_bytes());
            idb.extend(options(&[
                (OPT_IF_NAME, i.name.as_bytes()),
                (OPT_IF_DESCRIPTION, i.description.as_bytes()),
            ]));
            block(&mut out, IDB, &idb)?;
        }
        Ok(PcapngWriter { out, packets: 0 })
    }

    /// Write one packet captured on interface `iface` at `ts_us` (µs since epoch).
    pub fn write_packet(
        &mut self,
        iface: u32,
        ts_us: u64,
        orig_len: u32,
        data: &[u8],
    ) -> io::Result<()> {
        let mut epb = Vec::with_capacity(20 + data.len() + 8);
        epb.extend_from_slice(&iface.to_le_bytes());
        epb.extend_from_slice(&((ts_us >> 32) as u32).to_le_bytes());
        epb.extend_from_slice(&(ts_us as u32).to_le_bytes());
        epb.extend_from_slice(&(data.len() as u32).to_le_bytes());
        epb.extend_from_slice(&orig_len.to_le_bytes());
        epb.extend_from_slice(data);
        epb.extend(std::iter::repeat_n(0u8, pad4(data.len())));
        block(&mut self.out, EPB, &epb)?;
        self.packets += 1;
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<W> {
        self.out.flush()?;
        Ok(self.out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u32_at(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
    }

    #[test]
    fn writes_well_formed_blocks() {
        let ifs = [
            InterfaceDesc {
                link_type: 1,
                snaplen: 192,
                name: "eth".into(),
                description: "Ethernet".into(),
            },
            InterfaceDesc {
                link_type: 0,
                snaplen: 192,
                name: "lo".into(),
                description: "Loopback".into(),
            },
        ];
        let mut w = PcapngWriter::new(Vec::new(), &ifs).unwrap();
        w.write_packet(1, 1_700_000_000_123_456, 1500, &[0xAB; 61])
            .unwrap();
        let bytes = w.finish().unwrap();

        // Walk the blocks: each starts with type + length and ends with the same length.
        let mut pos = 0;
        let mut kinds = Vec::new();
        while pos < bytes.len() {
            let kind = u32_at(&bytes, pos);
            let len = u32_at(&bytes, pos + 4) as usize;
            assert_eq!(len % 4, 0, "blocks are 32-bit aligned");
            assert_eq!(
                u32_at(&bytes, pos + len - 4) as usize,
                len,
                "trailing length matches"
            );
            kinds.push(kind);
            if kind == EPB {
                assert_eq!(u32_at(&bytes, pos + 8), 1, "interface index");
                let ts = (u64::from(u32_at(&bytes, pos + 12)) << 32)
                    | u64::from(u32_at(&bytes, pos + 16));
                assert_eq!(ts, 1_700_000_000_123_456);
                assert_eq!(u32_at(&bytes, pos + 20), 61, "captured length");
                assert_eq!(u32_at(&bytes, pos + 24), 1500, "original length");
            }
            pos += len;
        }
        assert_eq!(kinds, vec![SHB, IDB, IDB, EPB]);
        assert_eq!(u32_at(&bytes, 8), BYTE_ORDER_MAGIC);
    }
}

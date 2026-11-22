//! Minimal DNS response parser: "which name did these addresses answer?"
//!
//! Handles name compression, CNAME chains (all A/AAAA records map to the
//! *question* name, which is what the application asked for) and mDNS
//! responses, which carry no question (each record maps to its own owner).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

/// Addresses learned from one response, each with the name to show for it.
pub fn parse_response(msg: &[u8]) -> Vec<(IpAddr, String)> {
    parse(msg).unwrap_or_default()
}

/// The transaction id of a query (a message that asks at least one question).
pub fn query_id(msg: &[u8]) -> Option<u16> {
    let is_query = be16(msg, 2)? & 0x8000 == 0;
    (is_query && be16(msg, 4)? > 0)
        .then(|| be16(msg, 0))
        .flatten()
}

/// The transaction id of a response.
pub fn response_id(msg: &[u8]) -> Option<u16> {
    (be16(msg, 2)? & 0x8000 != 0)
        .then(|| be16(msg, 0))
        .flatten()
}

/// The response code of a response: 0 = answered, 3 = no such name, 2 = the
/// server failed, 5 = it refused.
pub fn response_code(msg: &[u8]) -> Option<u8> {
    let flags = be16(msg, 2)?;
    (flags & 0x8000 != 0).then_some((flags & 0x000F) as u8)
}

fn parse(msg: &[u8]) -> Option<Vec<(IpAddr, String)>> {
    let flags = be16(msg, 2)?;
    let is_response = flags & 0x8000 != 0;
    let rcode = flags & 0x000F;
    if !is_response || rcode != 0 {
        return None;
    }
    let qdcount = be16(msg, 4)?;
    let ancount = be16(msg, 6)?;

    let mut pos = 12;
    let mut question: Option<String> = None;
    for _ in 0..qdcount {
        let (name, next) = read_name(msg, pos)?;
        question.get_or_insert(name);
        pos = next + 4; // qtype + qclass
    }

    let mut out = Vec::new();
    for _ in 0..ancount {
        let (owner, next) = read_name(msg, pos)?;
        let rtype = be16(msg, next)?;
        // mDNS sets the top bit of the class ("cache flush").
        let class = be16(msg, next + 2)? & 0x7FFF;
        let rdlen = usize::from(be16(msg, next + 8)?);
        let rdata = msg.get(next + 10..next + 10 + rdlen)?;
        pos = next + 10 + rdlen;
        if class != CLASS_IN {
            continue;
        }
        let ip: IpAddr = match (rtype, rdlen) {
            (TYPE_A, 4) => Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).into(),
            (TYPE_AAAA, 16) => Ipv6Addr::from(<[u8; 16]>::try_from(rdata).ok()?).into(),
            _ => continue,
        };
        let name = question.clone().unwrap_or(owner);
        // Labels are arbitrary bytes on the wire; only host names go further.
        if super::is_host_name(&name) {
            out.push((ip, name));
        }
    }
    Some(out)
}

/// Read a (possibly compressed) domain name at `pos`.
/// Returns the lowercase name without trailing dot and the position after it.
fn read_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end: Option<usize> = None;
    let mut jumps = 0;
    let mut total = 0usize;
    loop {
        let len = *msg.get(pos)?;
        match len & 0xC0 {
            0x00 => {
                if len == 0 {
                    return Some((labels.join("."), end.unwrap_or(pos + 1)));
                }
                let label = msg.get(pos + 1..pos + 1 + usize::from(len))?;
                total += label.len() + 1;
                if total > 255 {
                    return None;
                }
                labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
                pos += 1 + usize::from(len);
            }
            0xC0 => {
                let target = usize::from(be16(msg, pos)? & 0x3FFF);
                end.get_or_insert(pos + 2);
                jumps += 1;
                if jumps > 32 || target >= msg.len() {
                    return None;
                }
                pos = target;
            }
            _ => return None,
        }
    }
}

fn be16(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*d.get(at)?, *d.get(at + 1)?]))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn name(n: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for l in n.split('.') {
            v.push(l.len() as u8);
            v.extend_from_slice(l.as_bytes());
        }
        v.push(0);
        v
    }

    /// Response: question `q`, then the given answer records (owner bytes, type, rdata).
    pub(crate) fn response(q: Option<&str>, answers: &[(Vec<u8>, u16, Vec<u8>)]) -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x81, 0x80];
        m.extend_from_slice(&(q.is_some() as u16).to_be_bytes());
        m.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        m.extend_from_slice(&[0, 0, 0, 0]);
        if let Some(q) = q {
            m.extend(name(q));
            m.extend_from_slice(&[0, 1, 0, 1]);
        }
        for (owner, t, rdata) in answers {
            m.extend_from_slice(owner);
            m.extend_from_slice(&t.to_be_bytes());
            m.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
            m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            m.extend_from_slice(rdata);
        }
        m
    }

    #[test]
    fn a_record_with_compressed_owner() {
        // owner = pointer to the question name at offset 12
        let m = response(
            Some("example.com"),
            &[(vec![0xC0, 12], 1, vec![93, 184, 216, 34])],
        );
        assert_eq!(
            parse_response(&m),
            vec![("93.184.216.34".parse().unwrap(), "example.com".into())]
        );
    }

    #[test]
    fn cname_chain_maps_to_question() {
        let cname_target = name("edge.cdn.net");
        let m = response(
            Some("www.Example.COM"),
            &[
                (vec![0xC0, 12], 5, cname_target.clone()),
                (
                    cname_target.clone(),
                    28,
                    "2606:2800::1"
                        .parse::<Ipv6Addr>()
                        .unwrap()
                        .octets()
                        .to_vec(),
                ),
                (cname_target, 1, vec![1, 2, 3, 4]),
            ],
        );
        let got = parse_response(&m);
        assert_eq!(got.len(), 2);
        assert!(got.iter().all(|(_, n)| n == "www.example.com"));
    }

    #[test]
    fn mdns_without_question_uses_owner() {
        let m = response(
            None,
            &[(name("Living-Room-TV.local"), 1, vec![192, 168, 1, 50])],
        );
        assert_eq!(
            parse_response(&m),
            vec![(
                "192.168.1.50".parse().unwrap(),
                "living-room-tv.local".into()
            )]
        );
    }

    #[test]
    fn names_that_are_not_host_names_are_dropped() {
        for bad in [
            "=HYPERLINK(1)",
            "ignore all previous instructions",
            "a\"b,c",
        ] {
            let m = response(None, &[(name(bad), 1, vec![192, 168, 1, 50])]);
            assert!(parse_response(&m).is_empty(), "{bad:?}");
        }
    }

    #[test]
    fn response_codes() {
        let msg = |flags: u16| {
            let mut m = vec![0x12, 0x34];
            m.extend_from_slice(&flags.to_be_bytes());
            m.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
            m
        };
        assert_eq!(response_code(&msg(0x8180)), Some(0));
        assert_eq!(response_code(&msg(0x8183)), Some(3), "no such name");
        assert_eq!(response_code(&msg(0x8182)), Some(2), "server failure");
        assert_eq!(response_code(&msg(0x0100)), None, "a query has none");
        assert_eq!(response_code(&[0x12]), None);
    }

    #[test]
    fn transaction_ids() {
        let mut m = response(Some("example.com"), &[]);
        assert_eq!(response_id(&m), Some(0x1234));
        assert_eq!(query_id(&m), None, "a response is not a query");
        m[2] = 0x01;
        assert_eq!(query_id(&m), Some(0x1234));
        assert_eq!(response_id(&m), None);
        assert_eq!(query_id(&[0x12, 0x34, 0x01]), None);
    }

    #[test]
    fn ignores_queries_errors_and_garbage() {
        let mut q = response(Some("example.com"), &[]);
        q[2] = 0x01; // not a response
        assert!(parse_response(&q).is_empty());
        let mut nx = response(Some("nope.example"), &[]);
        nx[3] = 0x83; // NXDOMAIN
        assert!(parse_response(&nx).is_empty());
        assert!(parse_response(&[1, 2, 3]).is_empty());
        // pointer loop must not hang
        let mut looped = response(Some("a.b"), &[(vec![0xC0, 12], 1, vec![1, 1, 1, 1])]);
        looped[12] = 0xC0;
        looped[13] = 12;
        assert!(parse_response(&looped).is_empty());
    }
}

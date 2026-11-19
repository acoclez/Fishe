//! Giving remote endpoints a name.
//!
//! Sources, best first:
//!
//! | source | how | module |
//! |---|---|---|
//! | TLS SNI | server name in the ClientHello of a TCP/443 connection | [`tls`] |
//! | DNS | A/AAAA answers seen on the wire (port 53, and mDNS 5353 for LAN devices) | [`dns`] |
//! | reverse DNS | PTR lookup through the OS resolver, in the background | [`rdns`] |
//!
//! plus an address [`addr::AddrScope`] (LAN, loopback, multicast, public…).
//! Everything lands in a shared [`book::NameBook`]. See `docs/endpoints.md`.

pub mod addr;
pub mod book;
pub mod dns;
pub mod rdns;
pub mod sniffer;
pub mod tls;

/// Whether `s` reads as a host name: ASCII letters, digits, `-`, `.` and
/// `_`, at most 253 bytes.
///
/// Names come out of packets anyone on the network can send, and go on to
/// the window, to agents and into exports, so nothing else is let through.
/// Internationalised names are punycode on the wire and pass.
pub fn is_host_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::is_host_name;

    #[test]
    fn host_names_are_plain_ascii() {
        for ok in [
            "example.com",
            "xn--bcher-kva.example",
            "_dmarc.a-b.c",
            "living-room-tv.local",
        ] {
            assert!(is_host_name(ok), "{ok}");
        }
        for bad in [
            "",
            "two words.example",
            "=cmd|' /c calc'!a1",
            "ignore previous instructions",
            "a\nb.example",
            "caf\u{e9}.example",
            "<b>x</b>.example",
        ] {
            assert!(!is_host_name(bad), "{bad:?}");
        }
        assert!(!is_host_name(&"a".repeat(254)));
    }
}

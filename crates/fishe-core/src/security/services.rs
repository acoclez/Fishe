//! What a port number says about a connection, for the security view.
//!
//! Fishe reads packet headers, not content, so "unencrypted" here means "the
//! protocol that normally runs on this port sends its content in clear
//! text". Where a protocol can switch to encryption after connecting
//! (STARTTLS), the headers do not show whether it did: those ports are
//! reported as [`Clear::Maybe`], never as a certainty.

use crate::net::parse::Transport;

/// How sure the port alone makes us that content travels unencrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Clear {
    /// The protocol can upgrade to TLS after connecting; the headers do
    /// not tell whether it did.
    Maybe,
    /// The protocol has no encryption of its own on this port.
    Yes,
    /// As [`Clear::Yes`], and the protocol carries logins or commands.
    Credentials,
}

/// A service whose content is, or may be, readable on the way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlainService {
    pub name: &'static str,
    pub clear: Clear,
}

/// The unencrypted service a port usually carries, if any.
///
/// DNS (53) is left out on purpose: it has its own card, with the resolver
/// and its failures.
pub fn plaintext(transport: Transport, port: u16) -> Option<PlainService> {
    use Clear::{Credentials, Maybe, Yes};
    let (name, clear) = match (transport, port) {
        (Transport::Tcp, 21) => ("FTP", Credentials),
        (Transport::Tcp, 23) => ("Telnet", Credentials),
        (Transport::Tcp, 513) => ("rlogin", Credentials),
        (Transport::Tcp, 514) => ("rsh", Credentials),
        (Transport::Tcp, 80) => ("HTTP", Yes),
        (Transport::Udp, 69) => ("TFTP", Yes),
        (Transport::Udp, 161) => ("SNMP", Yes),
        (Transport::Udp, 514) => ("syslog", Yes),
        (Transport::Tcp, 25) => ("SMTP", Maybe),
        (Transport::Tcp, 587) => ("SMTP submission", Maybe),
        (Transport::Tcp, 110) => ("POP3", Maybe),
        (Transport::Tcp, 143) => ("IMAP", Maybe),
        (Transport::Tcp, 389) => ("LDAP", Maybe),
        _ => return None,
    };
    Some(PlainService { name, clear })
}

/// Does `name` serve, over plain HTTP by design, content that is public
/// and checked by other means? Certificate status and revocation lists
/// (signed, and fetched before a secure connection exists), connectivity
/// checks (a fixed page, there to detect captive portals), and operating
/// system updates (signed packages). HTTP to these says nothing about the
/// program that used it.
pub fn is_http_by_design(name: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    const PREFIXES: [&str; 5] = ["ocsp.", "ocsp2.", "crl.", "crls.", "crl3."];
    const DOMAINS: [&str; 16] = [
        // certificate status and revocation lists
        "lencr.org",
        "pki.goog",
        "digicert.com",
        "sectigo.com",
        "globalsign.com",
        "ctldl.windowsupdate.com",
        // connectivity checks
        "msftconnecttest.com",
        "msftncsi.com",
        "connectivitycheck.gstatic.com",
        "detectportal.firefox.com",
        "captive.apple.com",
        "connectivity-check.ubuntu.com",
        // operating system updates
        "windowsupdate.com",
        "delivery.mp.microsoft.com",
        "deb.debian.org",
        "archive.ubuntu.com",
    ];
    PREFIXES.iter().any(|p| name.starts_with(p))
        || DOMAINS.iter().any(|d| name == *d || is_subdomain(&name, d))
}

/// A listening port worth pointing out when it accepts connections from
/// other machines: remote access, file sharing, databases. `None` for
/// everything else, which is listed without a remark.
pub fn sensitive_listener(transport: Transport, port: u16) -> Option<&'static str> {
    if transport != Transport::Tcp {
        return None;
    }
    Some(match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        445 => "Windows file sharing (SMB)",
        3389 => "Remote Desktop",
        5900..=5903 => "VNC",
        5985 | 5986 => "Windows Remote Management",
        1433 => "SQL Server",
        3306 => "MySQL",
        5432 => "PostgreSQL",
        6379 => "Redis",
        27017 => "MongoDB",
        9200 => "Elasticsearch",
        2375 => "Docker API (unencrypted)",
        _ => return None,
    })
}

/// A short name for a well-known listening port, for the table.
pub fn listener_name(transport: Transport, port: u16) -> Option<&'static str> {
    if let Some(name) = sensitive_listener(transport, port) {
        return Some(name);
    }
    Some(match (transport, port) {
        (Transport::Tcp, 80) => "HTTP",
        (Transport::Tcp, 443) => "HTTPS",
        (Transport::Tcp, 135) => "Windows RPC",
        (Transport::Tcp, 139) | (Transport::Udp, 137 | 138) => "NetBIOS",
        (Transport::Udp, 53) | (Transport::Tcp, 53) => "DNS",
        (Transport::Udp, 67 | 68) => "DHCP",
        (Transport::Udp, 123) => "NTP",
        (Transport::Udp, 1900) => "SSDP (device discovery)",
        (Transport::Udp, 5353) => "mDNS",
        (Transport::Udp, 5355) => "LLMNR",
        (Transport::Tcp, 631) => "Printing (IPP)",
        (Transport::Tcp, 5357) => "Web Services for Devices",
        (Transport::Udp, 3702) => "WS-Discovery",
        _ => return None,
    })
}

/// Port of DNS over TLS.
pub const DNS_OVER_TLS: u16 = 853;

/// TCP service ports whose use the audit reports: the unencrypted ones
/// and DNS over TLS. Only connections that carried data count as use, so
/// the capture notes the payload on these ports (see `Tally::note_payload`):
/// a connection request that was refused is not "using Telnet".
pub fn audited_tcp_port(port: u16) -> bool {
    port == DNS_OVER_TLS || plaintext(Transport::Tcp, port).is_some()
}

/// Is `name` the host of a public DNS-over-HTTPS resolver? A connection to
/// one of these on port 443 is, as far as headers can tell, encrypted DNS.
pub fn is_doh_host(name: &str) -> bool {
    const HOSTS: [&str; 14] = [
        "dns.google",
        "dns.google.com",
        "cloudflare-dns.com",
        "mozilla.cloudflare-dns.com",
        "chrome.cloudflare-dns.com",
        "one.one.one.one",
        "dns.quad9.net",
        "dns.nextdns.io",
        "doh.opendns.com",
        "dns.adguard-dns.com",
        "dns.adguard.com",
        "doh.cleanbrowsing.org",
        "dns.mullvad.net",
        "doh.dns.sb",
    ];
    let name = name.trim_end_matches('.');
    HOSTS
        .iter()
        .any(|h| name.eq_ignore_ascii_case(h) || is_subdomain(name, h))
}

/// `name` is `something.` + `parent` (case-insensitive).
fn is_subdomain(name: &str, parent: &str) -> bool {
    name.len() > parent.len() + 1
        && name.as_bytes()[name.len() - parent.len() - 1] == b'.'
        && name[name.len() - parent.len()..].eq_ignore_ascii_case(parent)
}

/// `TLS 1.2` for 0x0303, and so on; `None` for a value that is no version.
pub fn tls_version_name(v: u16) -> Option<&'static str> {
    Some(match v {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => return None,
    })
}

/// The oldest version still considered current.
pub const TLS_1_2: u16 = 0x0303;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_ports_and_how_sure_they_are() {
        assert_eq!(
            plaintext(Transport::Tcp, 80),
            Some(PlainService {
                name: "HTTP",
                clear: Clear::Yes
            })
        );
        assert_eq!(
            plaintext(Transport::Tcp, 23).unwrap().clear,
            Clear::Credentials
        );
        assert_eq!(plaintext(Transport::Tcp, 143).unwrap().clear, Clear::Maybe);
        // The same number on the other transport is another protocol.
        assert_eq!(plaintext(Transport::Udp, 80), None);
        assert_eq!(plaintext(Transport::Udp, 514).unwrap().name, "syslog");
        assert_eq!(plaintext(Transport::Tcp, 514).unwrap().name, "rsh");
        // Encrypted, or covered elsewhere.
        for port in [443, 993, 995, 465, 22, 53, 853] {
            assert_eq!(plaintext(Transport::Tcp, port), None, "{port}");
        }
        assert!(Clear::Credentials > Clear::Yes && Clear::Yes > Clear::Maybe);
    }

    #[test]
    fn tcp_ports_whose_payload_is_noted() {
        for port in [21, 23, 80, 110, 143, 853] {
            assert!(audited_tcp_port(port), "{port}");
        }
        // UDP services and encrypted ones are not.
        for port in [69, 161, 443, 22, 53] {
            assert!(!audited_tcp_port(port), "{port}");
        }
    }

    #[test]
    fn listeners_are_named_and_some_are_sensitive() {
        assert_eq!(
            sensitive_listener(Transport::Tcp, 3389),
            Some("Remote Desktop")
        );
        assert_eq!(sensitive_listener(Transport::Tcp, 5901), Some("VNC"));
        assert_eq!(sensitive_listener(Transport::Udp, 3389), None);
        assert_eq!(sensitive_listener(Transport::Tcp, 135), None);
        assert_eq!(listener_name(Transport::Tcp, 135), Some("Windows RPC"));
        assert_eq!(
            listener_name(Transport::Tcp, 445),
            Some("Windows file sharing (SMB)")
        );
        assert_eq!(listener_name(Transport::Udp, 5353), Some("mDNS"));
        assert_eq!(listener_name(Transport::Tcp, 49664), None);
    }

    #[test]
    fn doh_hosts() {
        assert!(is_doh_host("dns.google"));
        assert!(is_doh_host("DNS.Google."));
        assert!(is_doh_host("abc123.dns.nextdns.io"));
        assert!(!is_doh_host("google.com"));
        assert!(!is_doh_host("notdns.google"));
        assert!(!is_doh_host("evil-dns.google.example.com"));
        assert!(!is_doh_host(""));
    }

    #[test]
    fn http_that_is_plain_by_design() {
        for name in [
            "ocsp.digicert.com",
            "yr1.c.lencr.org",
            "crls.ssl.com",
            "crl.microsoft.com",
            "www.msftconnecttest.com",
            "connectivitycheck.gstatic.com",
            "tlu.dl.delivery.mp.microsoft.com",
            "download.windowsupdate.com",
            "Deb.Debian.Org.",
        ] {
            assert!(is_http_by_design(name), "{name}");
        }
        for name in [
            "example.com",
            "neverssl.com",
            "ocsp-like.example.com",
            "notlencr.org",
            "lencr.org.evil.example",
            "",
        ] {
            assert!(!is_http_by_design(name), "{name}");
        }
    }

    #[test]
    fn tls_versions() {
        assert_eq!(tls_version_name(0x0304), Some("TLS 1.3"));
        assert_eq!(tls_version_name(0x0301), Some("TLS 1.0"));
        assert_eq!(tls_version_name(0x7a7a), None, "a GREASE value");
        assert_eq!(tls_version_name(TLS_1_2), Some("TLS 1.2"));
    }
}

//! Turn user input (an IP literal or a host name) into an IP address.

use crate::error::{AppError, AppResult};
use serde::Serialize;
use std::net::{IpAddr, ToSocketAddrs};

#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedTarget {
    /// The trimmed user input.
    pub input: String,
    /// The address that will be monitored.
    pub ip: IpAddr,
    /// `true` when `input` was a host name and DNS was used.
    pub from_hostname: bool,
    /// Every address DNS returned (the first IPv4 one is preferred).
    pub candidates: Vec<IpAddr>,
}

/// Resolve `input`. Blocking when DNS is needed: call from a worker thread.
pub fn resolve(input: &str) -> AppResult<ResolvedTarget> {
    let trimmed = input.trim();
    let literal = trimmed.trim_start_matches('[').trim_end_matches(']');

    if let Ok(ip) = literal.parse::<IpAddr>() {
        return Ok(ResolvedTarget {
            input: trimmed.to_string(),
            ip,
            from_hostname: false,
            candidates: vec![ip],
        });
    }

    if !is_plausible_hostname(trimmed) {
        return Err(AppError::InvalidTarget(trimmed.to_string()));
    }

    let mut candidates: Vec<IpAddr> = (trimmed, 0)
        .to_socket_addrs()
        .map_err(|_| AppError::InvalidTarget(trimmed.to_string()))?
        .map(|sa| sa.ip())
        .collect();
    candidates.dedup();

    let ip = candidates
        .iter()
        .copied()
        .find(IpAddr::is_ipv4)
        .or_else(|| candidates.first().copied())
        .ok_or_else(|| AppError::InvalidTarget(trimmed.to_string()))?;

    Ok(ResolvedTarget {
        input: trimmed.to_string(),
        ip,
        from_hostname: true,
        candidates,
    })
}

fn is_plausible_hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_literals() {
        assert_eq!(resolve(" 8.8.8.8 ").unwrap().ip, IpAddr::from([8, 8, 8, 8]));
        let v6 = resolve("[2001:db8::1]").unwrap();
        assert_eq!(v6.ip, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert!(!v6.from_hostname);
    }

    #[test]
    fn localhost_resolves() {
        assert!(resolve("localhost").unwrap().ip.is_loopback());
    }

    #[test]
    fn rejects_garbage() {
        for bad in [
            "",
            "not a host",
            "a..b",
            "-bad.com",
            "1.2.3.4:80",
            "http://x.com",
        ] {
            assert!(resolve(bad).is_err(), "{bad} should be rejected");
        }
    }
}

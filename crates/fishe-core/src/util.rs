//! Small helpers shared by several modules: time, address formatting and a
//! bounded parallel loop. Nothing here knows about the domain.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Unix time in milliseconds (0 if the clock is before 1970).
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Shorten `s` to at most `max` bytes without splitting a character
/// (`String::truncate` panics inside one).
pub fn truncate_at_char(s: &mut String, max: usize) {
    if s.len() > max {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
}

/// Proleptic Gregorian `(year, month, day)` for a day count since
/// 1970-01-01 (Howard Hinnant's civil-from-days; valid for any `i64`).
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// "aa:bb:cc:dd:ee:ff" (any length; empty for an empty slice).
pub fn format_mac(mac: &[u8]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// An IPv4 address from a Win32 `DWORD` in network byte order (`S_addr`,
/// `MIB_*` rows, `ICMP_ECHO_REPLY::Address`).
pub fn ipv4_from_ne(dw: u32) -> Ipv4Addr {
    Ipv4Addr::from(dw.to_ne_bytes())
}

/// Run `f` over every item on at most `workers` threads and return when all
/// are done. For short blocking I/O (connects, DNS lookups) where a thread
/// per item would be too many and one thread too slow.
pub fn par_for_each<T: Sync, F: Fn(&T) + Sync>(items: &[T], workers: usize, f: F) {
    if items.is_empty() {
        return;
    }
    let next = AtomicUsize::new(0);
    let workers = items.len().min(workers.max(1));
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(item) = items.get(i) else {
                        break;
                    };
                    f(item);
                }
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn truncation_never_splits_a_character() {
        let mut s = "abcdef".to_string();
        truncate_at_char(&mut s, 10);
        assert_eq!(s, "abcdef", "short strings are left alone");
        truncate_at_char(&mut s, 3);
        assert_eq!(s, "abc");
        // "é" is two bytes, "日" three: every cut point must land on a boundary.
        for max in 0..12 {
            let mut s = "éé日本é".to_string();
            truncate_at_char(&mut s, max);
            assert!(s.len() <= max);
            assert!("éé日本é".starts_with(&s));
        }
    }

    #[test]
    fn helpers() {
        assert_eq!(
            format_mac(&[0, 0x1a, 0x11, 0xaa, 0xbb, 0xcc]),
            "00:1a:11:aa:bb:cc"
        );
        assert_eq!(format_mac(&[]), "");
        assert_eq!(
            ipv4_from_ne(u32::from_ne_bytes([192, 168, 1, 19])),
            Ipv4Addr::new(192, 168, 1, 19)
        );
        assert!(now_ms() > 1_700_000_000_000);
    }

    #[test]
    fn civil_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(civil_from_days(19_675), (2023, 11, 14));
        assert_eq!(civil_from_days(20_765), (2026, 11, 8));
    }

    #[test]
    fn par_for_each_visits_every_item_once() {
        let items: Vec<u32> = (0..1000).collect();
        let seen = Mutex::new(Vec::new());
        par_for_each(&items, 7, |&i| seen.lock().unwrap().push(i));
        let mut seen = seen.into_inner().unwrap();
        seen.sort_unstable();
        assert_eq!(seen, items);
        par_for_each(&[] as &[u32], 4, |_| panic!("not called"));
    }
}

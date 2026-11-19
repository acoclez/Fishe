//! Background reverse-DNS (PTR) lookups through the OS resolver.
//!
//! Lookups can take seconds (timeouts), so they run on a small pool of
//! threads fed by a channel. Each address is looked up at most once per
//! session. Dropping the [`Resolver`] closes the channel; the threads work
//! through what was already queued and exit.

use super::book::{NameBook, Rdns};
use std::net::IpAddr;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};

const WORKERS: usize = 3;

pub struct Resolver {
    tx: Sender<IpAddr>,
    book: Arc<NameBook>,
}

impl Resolver {
    pub fn new(book: Arc<NameBook>) -> Self {
        let (tx, rx) = mpsc::channel::<IpAddr>();
        let rx = Arc::new(Mutex::new(rx));
        for i in 0..WORKERS {
            let (rx, book) = (rx.clone(), book.clone());
            let _ = std::thread::Builder::new()
                .name(format!("fishe-rdns-{i}"))
                .spawn(move || worker(rx, book));
        }
        Resolver { tx, book }
    }

    /// Queue a lookup unless one was already requested or a name is known.
    pub fn request(&self, ip: IpAddr) -> bool {
        if !self.book.wants_rdns(ip) {
            return false;
        }
        self.book.set_rdns(ip, Rdns::Pending);
        self.tx.send(ip).is_ok()
    }
}

fn worker(rx: Arc<Mutex<Receiver<IpAddr>>>, book: Arc<NameBook>) {
    loop {
        let next = rx.lock().unwrap_or_else(|e| e.into_inner()).recv();
        let Ok(ip) = next else { return };
        book.set_rdns(ip, Rdns::Done(lookup(ip)));
    }
}

/// PTR lookup; `None` when there is no name (the resolver echoes the address).
pub fn lookup(ip: IpAddr) -> Option<String> {
    let name = dns_lookup::lookup_addr(&ip).ok()?;
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    // A PTR record is written by whoever runs the address's reverse zone.
    (super::is_host_name(&name) && name.parse::<IpAddr>().is_err()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_resolves_or_is_absent() {
        // Must not panic or return the address itself.
        if let Some(n) = lookup("127.0.0.1".parse().unwrap()) {
            assert!(n.parse::<IpAddr>().is_err());
        }
    }

    #[test]
    #[ignore = "requires network DNS"]
    fn public_ptr() {
        let n = lookup("8.8.8.8".parse().unwrap());
        println!("8.8.8.8 -> {n:?}");
        assert_eq!(n.as_deref(), Some("dns.google"));
    }
}

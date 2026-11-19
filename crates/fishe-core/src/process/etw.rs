//! Exact, real-time socket ownership from kernel ETW (admin only).
//!
//! Subscribes to **Microsoft-Windows-Kernel-Network** and records the owning
//! PID the moment a socket is used, so connections that open and close
//! between two socket-table polls are still attributed.
//!
//! Only a few event ids are enabled (filtered in the kernel):
//!
//! | id | event | | id | event |
//! |---|---|---|---|---|
//! | 12 | TCPv4 connect | | 28 | TCPv6 connect |
//! | 15 | TCPv4 accept  | | 31 | TCPv6 accept  |
//! | 42 | UDPv4 send    | | 58 | UDPv6 send    |
//! | 43 | UDPv4 receive | | 59 | UDPv6 receive |
//!
//! Each event carries `PID`, `saddr`, `daddr`, `sport`, `dport` (ports in
//! network byte order). The local side is whichever address belongs to this
//! host.

use super::ownership::OwnershipTable;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

pub const KERNEL_NETWORK_GUID: &str = "7DD42A49-5329-4832-8DFD-43D979153A88";
#[cfg(windows)]
const KEYWORD_IPV4: u64 = 0x10;
#[cfg(windows)]
const KEYWORD_IPV6: u64 = 0x20;
pub const EVENT_IDS: [u16; 8] = [12, 15, 28, 31, 42, 43, 58, 59];

/// Microsoft-Windows-Kernel-Process: event 1 = ProcessStart (`ProcessID`, `ImageName`).
pub const KERNEL_PROCESS_GUID: &str = "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716";
#[cfg(windows)]
const KEYWORD_PROCESS: u64 = 0x10;
#[cfg(windows)]
const PROCESS_START: u16 = 1;

/// Where ETW observations go: a process scope (process mode) or the
/// machine-wide scope (all-traffic mode).
pub trait EtwSink: Send + Sync + 'static {
    fn ownership(&self) -> &OwnershipTable;
    /// Every address of this host.
    fn local(&self) -> &HashSet<IpAddr>;
    /// A process just started; `image` is its full image path.
    fn process_started(&self, pid: u32, image: &str);
}

/// A running ETW session; stopped when dropped.
pub struct EtwTracker {
    #[cfg(windows)]
    _trace: ferrisetw::UserTrace,
}

/// Start one trace with two providers: socket ownership (Kernel-Network) and
/// process starts (Kernel-Process), both feeding `sink`.
#[cfg(windows)]
pub fn start(sink: Arc<dyn EtwSink>, session_name: String) -> Result<EtwTracker, String> {
    use crate::net::parse::Transport;
    use ferrisetw::EventRecord;
    use ferrisetw::parser::Parser;
    use ferrisetw::provider::{EventFilter, Provider};
    use ferrisetw::schema_locator::SchemaLocator;
    use ferrisetw::trace::UserTrace;

    let net_sink = sink.clone();
    let network = move |record: &EventRecord, locator: &SchemaLocator| {
        let transport = match record.event_id() {
            12 | 15 | 28 | 31 => Transport::Tcp,
            42 | 43 | 58 | 59 => Transport::Udp,
            _ => return,
        };
        let Ok(schema) = locator.event_schema(record) else {
            return;
        };
        let p = Parser::create(record, &schema);
        let (Ok(pid), Ok(saddr), Ok(daddr), Ok(sport), Ok(dport)) = (
            p.try_parse::<u32>("PID"),
            p.try_parse::<IpAddr>("saddr"),
            p.try_parse::<IpAddr>("daddr"),
            p.try_parse::<u16>("sport"),
            p.try_parse::<u16>("dport"),
        ) else {
            return;
        };
        let (sport, dport) = (u16::from_be(sport), u16::from_be(dport));
        if let Some(port) = local_port(net_sink.local(), saddr, sport, daddr, dport) {
            net_sink.ownership().note(transport, port, pid);
        }
    };

    let processes = move |record: &EventRecord, locator: &SchemaLocator| {
        if record.event_id() != PROCESS_START {
            return;
        }
        let Ok(schema) = locator.event_schema(record) else {
            return;
        };
        let p = Parser::create(record, &schema);
        if let (Ok(pid), Ok(image)) = (
            p.try_parse::<u32>("ProcessID"),
            p.try_parse::<String>("ImageName"),
        ) {
            sink.process_started(pid, &image);
        }
    };

    let network = Provider::by_guid(KERNEL_NETWORK_GUID)
        .any(KEYWORD_IPV4 | KEYWORD_IPV6)
        .add_filter(EventFilter::ByEventIds(EVENT_IDS.to_vec()))
        .add_callback(network)
        .build();
    let processes = Provider::by_guid(KERNEL_PROCESS_GUID)
        .any(KEYWORD_PROCESS)
        .add_filter(EventFilter::ByEventIds(vec![PROCESS_START]))
        .add_callback(processes)
        .build();

    let trace = UserTrace::new()
        .named(session_name)
        .enable(network)
        .enable(processes)
        .start_and_process()
        .map_err(|e| format!("{e:?}"))?;
    Ok(EtwTracker { _trace: trace })
}

#[cfg(not(windows))]
pub fn start(_: Arc<dyn EtwSink>, _: String) -> Result<EtwTracker, String> {
    Err("ETW is only available on Windows".into())
}

/// Pick the port that belongs to this host.
pub fn local_port(
    local: &HashSet<IpAddr>,
    saddr: IpAddr,
    sport: u16,
    daddr: IpAddr,
    dport: u16,
) -> Option<u16> {
    if local.contains(&saddr) {
        Some(sport)
    } else if local.contains(&daddr) {
        Some(dport)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_the_local_side() {
        let local: HashSet<IpAddr> = ["10.0.0.2".parse().unwrap()].into();
        let me: IpAddr = "10.0.0.2".parse().unwrap();
        let them: IpAddr = "1.1.1.1".parse().unwrap();
        assert_eq!(local_port(&local, me, 5000, them, 443), Some(5000));
        assert_eq!(local_port(&local, them, 443, me, 5000), Some(5000));
        assert_eq!(local_port(&local, them, 1, them, 2), None);
    }

    /// Needs an elevated shell:
    /// `cargo test -- --ignored etw_attributes_new_connection --nocapture`
    #[cfg(windows)]
    #[test]
    #[ignore = "requires administrator rights"]
    fn etw_attributes_new_connection() {
        use crate::net::parse::Transport;
        use std::net::{TcpListener, TcpStream};
        use std::time::{Duration, Instant};

        assert!(
            crate::process::elevation::is_elevated(),
            "run this test elevated"
        );
        use crate::monitor::target::ProcessSelector;
        use crate::process::scope::ProcessScope;
        let local: Arc<HashSet<IpAddr>> = Arc::new(["127.0.0.1".parse().unwrap()].into());
        let scope = Arc::new(ProcessScope::new(
            ProcessSelector::Pid {
                pid: std::process::id(),
            },
            Arc::new(OwnershipTable::new()),
            local,
        ));
        let table = scope.ownership.clone();
        let _etw = start(scope, format!("Fishe-test-{}", std::process::id())).expect("ETW session");
        std::thread::sleep(Duration::from_millis(500));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let lport = listener.local_addr().unwrap().port();
        let client = TcpStream::connect(("127.0.0.1", lport)).unwrap();
        let cport = client.local_addr().unwrap().port();
        let _server_side = listener.accept().unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
        while table.owner(Transport::Tcp, cport).is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        println!("ETW mappings: {}", table.len());
        assert_eq!(table.owner(Transport::Tcp, cport), Some(std::process::id()));
    }
}

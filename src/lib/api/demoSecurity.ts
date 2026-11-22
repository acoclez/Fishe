/**
 * The Security page's data for the browser preview: one of everything the
 * real report can contain, so the page can be worked on without a capture.
 */
import type { DhcpServer, Finding, KnownLan, Listener, SecurityReport, SessionAudit, SessionState, VpnAudit } from "./types";

// `?vpn` shows the preview with a VPN up (and IPv6 leaving beside it);
// `?dhcp2` adds a second DHCP server to the local network.
const params = typeof location !== "undefined" ? new URLSearchParams(location.search) : new URLSearchParams();
const withVpn = params.has("vpn");
const withSecondDhcp = params.has("dhcp2");

/** The DHCP servers the preview's scan finds. */
export function demoDhcp(): DhcpServer[] {
  const router: DhcpServer = {
    ip: "192.168.1.1",
    mac: "c8:7f:2b:35:1a:c0",
    vendor: "Arcadyan",
    offered: "192.168.1.19",
    router: "192.168.1.1",
    dns: ["192.168.1.1"],
    leaseSecs: 86_400,
    isGateway: true,
  };
  const second: DhcpServer = {
    ip: "192.168.1.66",
    mac: "da:a1:19:7f:00:21",
    vendor: null,
    offered: "192.168.1.201",
    router: "192.168.1.66",
    dns: ["192.168.1.66"],
    leaseSecs: 600,
    isGateway: false,
  };
  return withSecondDhcp ? [router, second] : [router];
}

function vpn(auditing: boolean): VpnAudit {
  const adapter = "Intel Wi-Fi 6 AX201";
  if (!withVpn) {
    return {
      tunnels: [],
      ipv4: { via: "direct", interface: adapter },
      ipv6: { via: "direct", interface: adapter },
      error: null,
      measured: false,
      insideBytes: 0,
      outsideBytes: 0,
      carrier: null,
      outside: [],
      outsideCount: 0,
      dnsOutside: 0,
    };
  }
  return {
    tunnels: [{ name: "\\Device\\NPF_{7D2C}", description: "WireGuard Tunnel", kind: "WireGuard", addresses: ["10.2.0.2"] }],
    ipv4: { via: "tunnel", interface: "WireGuard Tunnel" },
    ipv6: { via: "direct", interface: adapter },
    error: null,
    measured: auditing,
    insideBytes: auditing ? 61_400_000 : 0,
    outsideBytes: auditing ? 63_900_000 : 0,
    carrier: auditing ? ep("185.159.157.129", null, 63_100_000) : null,
    outside: auditing ? [ep("2a00:1450:4007:80c::200e", "www.google.com", 640_000), ep("17.253.144.10", "time.apple.com", 160_000)] : [],
    outsideCount: auditing ? 2 : 0,
    dnsOutside: auditing ? 14 : 0,
  };
}

const ep = (ip: string, name: string | null, bytes: number, scope: "public" | "private" = "public") => ({ ip, name, scope, bytes });

const SESSION: SessionAudit = {
  tMs: 0,
  programCount: 5,
  inboundCount: 3,
  programs: [
    {
      key: "chrome.exe",
      name: "chrome.exe",
      bytes: 48_200_000,
      endpoints: 41,
      publicEndpoints: 39,
      countries: [
        { name: "US", bytes: 31_000_000, endpoints: 24 },
        { name: "IE", bytes: 9_800_000, endpoints: 7 },
        { name: "DE", bytes: 4_100_000, endpoints: 5 },
        { name: "NL", bytes: 2_200_000, endpoints: 3 },
      ],
      owners: [
        { name: "Google LLC", bytes: 22_000_000, endpoints: 14 },
        { name: "Cloudflare, Inc.", bytes: 11_500_000, endpoints: 9 },
        { name: "Amazon.com, Inc.", bytes: 7_900_000, endpoints: 8 },
        { name: "Fastly, Inc.", bytes: 3_300_000, endpoints: 4 },
      ],
      ownerCount: 9,
      unknownOwner: 2,
      plaintext: [
        {
          service: "HTTP",
          transport: "tcp",
          port: 80,
          certainty: "yes",
          bytes: 18_400,
          publicBytes: 18_400,
          endpointCount: 2,
          endpoints: [ep("93.184.216.34", "example.com", 12_100), ep("23.215.0.136", "ocsp.digicert.com", 6_300)],
        },
      ],
      plainBytes: 18_400,
      tlsHellos: 212,
      oldTls: [],
    },
    {
      key: "backup-agent.exe",
      name: "backup-agent.exe",
      bytes: 9_600_000,
      endpoints: 3,
      publicEndpoints: 2,
      countries: [{ name: "FR", bytes: 9_100_000, endpoints: 2 }],
      owners: [{ name: "OVH SAS", bytes: 9_100_000, endpoints: 2 }],
      ownerCount: 1,
      unknownOwner: 0,
      plaintext: [
        {
          service: "FTP",
          transport: "tcp",
          port: 21,
          certainty: "credentials",
          bytes: 6_400,
          publicBytes: 6_400,
          endpointCount: 1,
          endpoints: [ep("51.38.99.12", "ftp.backup.example", 6_400)],
        },
        {
          service: "HTTP",
          transport: "tcp",
          port: 80,
          certainty: "yes",
          bytes: 8_900_000,
          publicBytes: 8_900_000,
          endpointCount: 1,
          endpoints: [ep("51.38.99.12", "ftp.backup.example", 8_900_000)],
        },
      ],
      plainBytes: 8_906_400,
      tlsHellos: 4,
      oldTls: [{ server: ep("51.38.99.40", "api.backup.example", 120_000), version: "TLS 1.0" }],
    },
    {
      key: "discord.exe",
      name: "Discord.exe",
      bytes: 6_100_000,
      endpoints: 7,
      publicEndpoints: 7,
      countries: [{ name: "US", bytes: 6_100_000, endpoints: 7 }],
      owners: [
        { name: "Cloudflare, Inc.", bytes: 5_200_000, endpoints: 5 },
        { name: "Google LLC", bytes: 900_000, endpoints: 2 },
      ],
      ownerCount: 2,
      unknownOwner: 0,
      plaintext: [],
      plainBytes: 0,
      tlsHellos: 18,
      oldTls: [],
    },
    {
      key: "svchost.exe",
      name: "svchost.exe",
      bytes: 1_900_000,
      endpoints: 12,
      publicEndpoints: 8,
      countries: [
        { name: "US", bytes: 1_300_000, endpoints: 5 },
        { name: "IE", bytes: 400_000, endpoints: 3 },
      ],
      owners: [
        { name: "Microsoft Corporation", bytes: 1_500_000, endpoints: 6 },
        { name: "Akamai Technologies, Inc.", bytes: 200_000, endpoints: 2 },
      ],
      ownerCount: 2,
      unknownOwner: 0,
      plaintext: [
        {
          service: "HTTP",
          transport: "tcp",
          port: 80,
          certainty: "yes",
          bytes: 4_200,
          publicBytes: 4_200,
          endpointCount: 1,
          endpoints: [ep("13.107.4.52", "www.msftconnecttest.com", 4_200)],
        },
      ],
      plainBytes: 4_200,
      tlsHellos: 31,
      oldTls: [],
    },
    {
      key: "",
      name: "Unattributed",
      bytes: 310_000,
      endpoints: 4,
      publicEndpoints: 1,
      countries: [],
      owners: [],
      ownerCount: 0,
      unknownOwner: 1,
      plaintext: [],
      plainBytes: 0,
      tlsHellos: 0,
      oldTls: [],
    },
  ],
  inbound: [
    {
      ip: "192.168.1.66",
      name: null,
      scope: "private",
      owner: null,
      portCount: 64,
      ports: [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445],
      attempts: 71,
      accepted: 2,
      acceptedPorts: [135, 445],
      scan: true,
      lastMs: 0,
    },
    {
      ip: "45.155.205.233",
      name: null,
      scope: "public",
      owner: { asn: 211_252, org: "Delis LLC", country: "NL", source: "dbip" },
      portCount: 1,
      ports: [3389],
      attempts: 3,
      accepted: 1,
      acceptedPorts: [3389],
      scan: false,
      lastMs: 0,
    },
    {
      ip: "192.168.1.40",
      name: "nas.home",
      scope: "private",
      owner: null,
      portCount: 1,
      ports: [445],
      attempts: 4,
      accepted: 4,
      acceptedPorts: [445],
      scan: false,
      lastMs: 0,
    },
  ],
  dns: {
    servers: [
      {
        ip: "192.168.1.1",
        name: "livebox.home",
        scope: "private",
        owner: null,
        queries: 412,
        answered: 405,
        unanswered: 3,
        nxdomain: 21,
        failed: 4,
        avgMs: 14.2,
        maxMs: 310,
      },
      {
        ip: "8.8.8.8",
        name: "dns.google",
        scope: "public",
        owner: { asn: 15_169, org: "Google LLC", country: "US", source: "dbip" },
        queries: 38,
        answered: 38,
        unanswered: 0,
        nxdomain: 2,
        failed: 0,
        avgMs: 21.7,
        maxMs: 64,
      },
    ],
    overTls: [],
    overHttps: [ep("104.16.249.249", "chrome.cloudflare-dns.com", 96_000)],
  },
  dhcp: [],
};

const LISTENERS: Listener[] = [
  { program: "System", pid: 4, port: 445, reach: "network", address: "all addresses", service: "Windows file sharing (SMB)", sensitive: true },
  { program: "svchost.exe", pid: 1320, port: 3389, reach: "network", address: "all addresses", service: "Remote Desktop", sensitive: true },
  { program: "svchost.exe", pid: 1004, port: 135, reach: "network", address: "all addresses", service: "Windows RPC", sensitive: false },
  { program: "System", pid: 4, port: 139, reach: "network", address: "192.168.1.19", service: "NetBIOS", sensitive: false },
  { program: "node.exe", pid: 9912, port: 5173, reach: "network", address: "all addresses", service: null, sensitive: false },
  { program: "lsass.exe", pid: 820, port: 49664, reach: "network", address: "all addresses", service: null, sensitive: false },
  { program: "postgres.exe", pid: 5120, port: 5432, reach: "loopback", address: "127.0.0.1, ::1", service: "PostgreSQL", sensitive: false },
  { program: "fishe.exe", pid: 7700, port: 47823, reach: "loopback", address: "127.0.0.1", service: null, sensitive: false },
];

const FINDINGS: Finding[] = [
  {
    id: "accepted:3389",
    severity: "warning",
    kind: "inboundAccepted",
    title: "1 Internet address connected to this machine on port 3389 (Remote Desktop)",
    detail:
      "This machine is reachable from the Internet on that port and a program accepted the connection. Expected for a server, a game host or a file-sharing program; otherwise check why the port is open.",
    program: "svchost.exe",
    subjects: ["45.155.205.233"],
  },
  {
    id: "plain:backup-agent.exe:Tcp:21",
    severity: "warning",
    kind: "plaintext",
    title: "backup-agent.exe used FTP (unencrypted, carries logins): 6.4 kB",
    detail:
      "FTP sends everything in clear text, passwords and commands included: anyone on the way can read them. Some of it crossed the Internet.",
    program: "backup-agent.exe",
    subjects: ["ftp.backup.example (51.38.99.12)"],
  },
  {
    id: "scan:192.168.1.66",
    severity: "warning",
    kind: "portScan",
    title: "192.168.1.66 on the local network tried 64 ports of this machine",
    detail:
      "Trying many ports is how a device looks for services to connect to: a security scanner, a network tool, or something probing for weaknesses. This machine accepted at least one of those connections.",
    program: null,
    subjects: ["192.168.1.66", "accepted on 135, 445"],
  },
  {
    id: "old-tls:backup-agent.exe",
    severity: "notice",
    kind: "oldTls",
    title: "backup-agent.exe offered nothing newer than TLS 1.0 to 1 server",
    detail:
      "TLS 1.0 and 1.1 are retired: their protection is weaker and current servers refuse them. A program that offers nothing newer is usually old or unmaintained. This is what the program offered, not what the server chose.",
    program: "backup-agent.exe",
    subjects: ["api.backup.example (51.38.99.40) (TLS 1.0)"],
  },
  {
    id: "plain:backup-agent.exe:Tcp:80",
    severity: "notice",
    kind: "plaintext",
    title: "backup-agent.exe used HTTP (unencrypted): 8.9 MB",
    detail:
      "The content of HTTP can be read and altered on the way. Fishe sees the port, not the content: this says the service is unencrypted, not what was sent. Small amounts are usual (connectivity checks, certificate status).",
    program: "backup-agent.exe",
    subjects: ["ftp.backup.example (51.38.99.12)"],
  },
  {
    id: "dns-clear:8.8.8.8",
    severity: "info",
    kind: "dnsUnencrypted",
    title: "DNS questions go unencrypted to 8.8.8.8 (Google LLC)",
    detail:
      "Every network between this machine and that server can read which names are looked up, and could alter the answers. Encrypted DNS (DNS over HTTPS or TLS) prevents both.",
    program: null,
    subjects: ["38 questions"],
  },
  {
    id: "plain:chrome.exe:Tcp:80",
    severity: "info",
    kind: "plaintext",
    title: "chrome.exe used HTTP (unencrypted): 18 kB",
    detail:
      "The content of HTTP can be read and altered on the way. Fishe sees the port, not the content: this says the service is unencrypted, not what was sent. Small amounts are usual (connectivity checks, certificate status).",
    program: "chrome.exe",
    subjects: ["example.com (93.184.216.34)", "ocsp.digicert.com (23.215.0.136)"],
  },
  {
    id: "plain:svchost.exe:Tcp:80",
    severity: "info",
    kind: "plaintext",
    title: "svchost.exe used HTTP (unencrypted): 4.2 kB",
    detail:
      "The content of HTTP can be read and altered on the way. Fishe sees the port, not the content: this says the service is unencrypted, not what was sent. Small amounts are usual (connectivity checks, certificate status).",
    program: "svchost.exe",
    subjects: ["www.msftconnecttest.com (13.107.4.52)"],
  },
];

const LISTENER_FINDINGS: Finding[] = [
  {
    id: "listener:svchost.exe:3389",
    severity: "info",
    kind: "sensitiveListener",
    title: "svchost.exe accepts Remote Desktop connections from the network (port 3389)",
    detail:
      "Other machines on this network can try to connect to it, unless a firewall stops them (Fishe does not see firewall rules). Fine on a network you trust; worth turning off on public Wi-Fi if unused.",
    program: "svchost.exe",
    subjects: ["bound to all addresses"],
  },
  {
    id: "listener:system:445",
    severity: "info",
    kind: "sensitiveListener",
    title: "System accepts Windows file sharing (SMB) connections from the network (port 445)",
    detail:
      "Other machines on this network can try to connect to it, unless a firewall stops them (Fishe does not see firewall rules). Fine on a network you trust; worth turning off on public Wi-Fi if unused.",
    program: "System",
    subjects: ["bound to all addresses"],
  },
];

/** LAN scans done in this preview: the second one finds a new device. */
let scans = 0;
let forgotten = false;
export function demoLanScanned(): number {
  forgotten = false;
  return ++scans;
}
export function demoLanForget() {
  scans = 0;
  forgotten = true;
}

function lans(): KnownLan[] {
  if (forgotten || scans === 0) return [];
  const fresh = scans === 2;
  return [
    {
      network: "192.168.1.0/24",
      gateway: "192.168.1.1",
      gatewayMac: "c8:7f:2b:35:1a:c0",
      devices: 6,
      scans,
      firstScan: Date.now() - 86_400_000 * 12,
      lastScan: Date.now(),
      newDevices: fresh ? [{ mac: "da:a1:19:7f:00:21", ip: "192.168.1.66", vendor: null, hostname: null }] : [],
      gatewayWas: null,
      dhcp: demoDhcp(),
    },
  ];
}

/** Findings the VPN and DHCP preview states add (the texts the backend writes). */
function extraFindings(v: VpnAudit, networks: KnownLan[]): Finding[] {
  const out: Finding[] = [];
  if (v.ipv4.via === "tunnel" && v.ipv6.via === "direct") {
    out.push({
      id: "vpn-ipv6",
      severity: "warning",
      kind: "vpnOutside",
      title: `IPv6 traffic does not go through ${v.ipv4.interface}`,
      detail:
        "IPv4 traffic to the Internet is routed through the VPN, but IPv6 still leaves through the ordinary connection. Sites reached over IPv6 see this machine's real address, and that traffic is not protected by the VPN.",
      program: null,
      subjects: [`IPv6 leaves through ${v.ipv6.interface}`],
    });
  }
  if (v.measured && v.dnsOutside > 0) {
    out.push({
      id: "vpn-dns",
      severity: "notice",
      kind: "vpnOutside",
      title: `${v.dnsOutside} DNS questions left outside ${v.ipv4.interface}`,
      detail:
        "The names this machine looks up were sent, unencrypted, through the ordinary connection instead of the VPN: the local network and the Internet provider can see them. VPN clients usually have a setting to send DNS through the tunnel.",
      program: null,
      subjects: [],
    });
  }
  if (v.measured && v.outsideCount > 0) {
    out.push({
      id: "vpn-outside",
      severity: "notice",
      kind: "vpnOutside",
      title: `${v.outsideCount} Internet addresses were reached outside ${v.ipv4.interface}`,
      detail:
        "Besides the VPN server itself, this machine exchanged traffic with these addresses through the ordinary connection. That is what split tunnelling does on purpose; if the VPN is meant to carry everything, it is a leak.",
      program: null,
      subjects: v.outside.map((e) => `${e.name ?? e.ip} (${e.ip})`),
    });
  }
  for (const lan of networks) {
    if (lan.dhcp.length > 1) {
      out.push({
        id: `dhcp:${lan.network}`,
        severity: "warning",
        kind: "secondDhcpServer",
        title: `${lan.dhcp.length} DHCP servers answer on ${lan.network}`,
        detail:
          "A DHCP server tells every device that joins which gateway and DNS servers to use. These hand out different gateways or DNS servers, so devices end up sending their traffic or their DNS questions to different places. Normal where two servers are set up to back each other up; on a home network a second one is a misconfigured device, or one placing itself in the path of the others' traffic.",
        program: null,
        subjects: lan.dhcp.map((d) => `${d.ip} (${d.mac}): gateway ${d.router}, DNS ${d.dns.join(" ")}`),
      });
    }
  }
  return out;
}

const order = { warning: 0, notice: 1, info: 2 } as const;

/** The report for a preview session in `mode` running since `startedAt`. */
export function demoSecurityReport(mode: "host" | "process" | "all" | null, startedAt: number): SecurityReport {
  const state: SessionState = mode === null ? "noSession" : mode === "all" ? "auditing" : "notAllTraffic";
  const tMs = Math.max(0, Date.now() - startedAt);
  const networks = lans();
  const tunnel = vpn(state === "auditing");
  const findings: Finding[] = [...LISTENER_FINDINGS, ...extraFindings(tunnel, networks)];
  if (state === "auditing") findings.push(...FINDINGS);
  for (const lan of networks) {
    if (lan.newDevices.length) {
      findings.push({
        id: `new-devices:${lan.network}:${scans}`,
        severity: "info",
        kind: "newDevice",
        title: `${lan.newDevices.length} new device on ${lan.network} since the previous scan`,
        detail:
          "Devices that were not there before: a guest, a new appliance, a phone with a new private address, or something that should not be there.",
        program: null,
        subjects: lan.newDevices.map((d) => `${d.ip} (${d.mac})`),
      });
    }
  }
  findings.sort((a, b) => order[a.severity] - order[b.severity] || a.id.localeCompare(b.id));
  return {
    state,
    session:
      state === "auditing"
        ? { ...SESSION, tMs, inbound: SESSION.inbound.map((p) => ({ ...p, lastMs: Math.max(0, tMs - 4000) })) }
        : null,
    listeners: LISTENERS,
    listenersError: null,
    lans: networks,
    vpn: tunnel,
    ownerData: true,
    findings,
  };
}

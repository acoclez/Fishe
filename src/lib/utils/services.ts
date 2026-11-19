/** Friendly names for common service ports (best-effort, for display only). */
import type { Transport } from "../api/types";

const TCP: Record<number, string> = {
  20: "FTP data",
  21: "FTP",
  22: "SSH",
  23: "Telnet",
  25: "SMTP",
  53: "DNS",
  80: "HTTP",
  110: "POP3",
  143: "IMAP",
  443: "HTTPS",
  445: "SMB",
  465: "SMTPS",
  587: "SMTP submit",
  993: "IMAPS",
  995: "POP3S",
  1433: "SQL Server",
  3074: "Xbox Live",
  3306: "MySQL",
  3389: "RDP",
  5222: "XMPP",
  5432: "PostgreSQL",
  5900: "VNC",
  6379: "Redis",
  8080: "HTTP alt",
  8443: "HTTPS alt",
  25565: "Minecraft",
  27017: "MongoDB",
};

const UDP: Record<number, string> = {
  53: "DNS",
  67: "DHCP",
  68: "DHCP",
  123: "NTP",
  137: "NetBIOS",
  161: "SNMP",
  443: "QUIC",
  500: "IKE",
  1900: "SSDP",
  3074: "Xbox Live",
  3478: "STUN/TURN",
  4500: "IPsec NAT-T",
  5353: "mDNS",
  51820: "WireGuard",
};

export function serviceName(transport: Transport, port: number): string | null {
  if (transport === "tcp") return TCP[port] ?? null;
  if (transport === "udp") return UDP[port] ?? null;
  return null;
}

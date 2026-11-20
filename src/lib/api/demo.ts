/**
 * Browser-only demo backend.
 *
 * When the UI runs outside Tauri (`npm run dev` in a normal browser) there is
 * no Rust side, so this module simulates one: it streams synthetic samples
 * with periodic bursts through the same MonitorEvent shape. It exists for UI
 * development and screenshots and is never used inside the desktop app:
 * `index.ts` imports it lazily, and only outside a production build.
 */
import type { Api } from "./index";
import type {
  Hop,
  LanDevice,
  LanScan,
  NetContext,
  TraceResult,
  Episode,
  RecordingDetail,
  RecordingInfo,
  RecordingSummary,
  Sample,
  SeriesPoint,
  Capabilities,
  GaugeConfig,
  InterfaceInfo,
  Level,
  MonitorEvent,
  NpcapStatus,
  EndpointRow,
  PacketBatch,
  PacketRow,
  PingStatus,
  QualityTick,
  McpAccess,
  McpStatus,
  ProgramRow,
  PortUsage,
  ProcessGroup,
  SessionInfo,
  StartRequest,
} from "./types";

export const DEMO_GAUGE: GaugeConfig = {
  busyRatio: 2,
  spikeRatio: 5,
  idleFloorBps: 256,
  baselineFloorBps: 2048,
  smoothingSecs: 0.6,
  baselineRiseSecs: 60,
  baselineFallSecs: 20,
  warmupSecs: 5,
};

const DEMO_NPCAP: NpcapStatus = {
  available: true,
  dllDir: null,
  version: "Demo mode: simulated traffic",
  message: null,
  grantCommand: null,
};
/** What the app reports on a PC without Npcap. */
const DEMO_NPCAP_MISSING: NpcapStatus = {
  available: false,
  dllDir: "C:\\Windows\\System32\\Npcap",
  version: null,
  message: "wpcap.dll not found. Install Npcap from https://npcap.com (the default options are fine).",
  grantCommand: null,
};
/** What the app reports on Linux before it was allowed to capture. */
const DEMO_CAPTURE_NOT_ALLOWED: NpcapStatus = {
  available: false,
  dllDir: null,
  version: null,
  message: "Fishe is not allowed to capture packets: it needs the CAP_NET_RAW capability (or to run as root).",
  grantCommand: "sudo setcap cap_net_raw=ep /usr/bin/fishe",
};
// Open the preview with `?npcap-missing` to see the install prompt: the first
// "Check again" still finds nothing, the second one finds it. `?linux` makes
// the preview speak as it does on Linux, where the same parameter shows the
// permission prompt instead (which only a restart resolves).
const demoParams = typeof location !== "undefined" ? new URLSearchParams(location.search) : new URLSearchParams();
const demoNpcapMissing = demoParams.has("npcap-missing");
const demoLinux = demoParams.has("linux");
let demoRechecks = 0;
export const demoNpcap = (): NpcapStatus => {
  if (!demoNpcapMissing) return DEMO_NPCAP;
  if (demoLinux) return DEMO_CAPTURE_NOT_ALLOWED;
  return demoRechecks < 2 ? DEMO_NPCAP_MISSING : DEMO_NPCAP;
};
export const demoNpcapRecheck = (): NpcapStatus => {
  demoRechecks++;
  return demoNpcap();
};

export const demoInterfaces: InterfaceInfo[] = [
  {
    name: "demo0",
    description: "Simulated Ethernet",
    addresses: ["192.168.1.20"],
    isUp: true,
    isRunning: true,
    isLoopback: false,
    isWireless: false,
  },
];

export const demoCapabilities: Capabilities = { platform: demoLinux ? "linux" : "windows", processMode: true, elevated: false, etw: false };

const DEMO_PROCS: ProcessGroup[] = [
  { name: "chrome.exe", pids: [4120, 4188, 5012, 6630], exePath: "C:\Program Files\Google\Chrome\Application\chrome.exe", sockets: 64, connections: 41, listening: 0 },
  { name: "Discord.exe", pids: [9012, 9044], exePath: null, sockets: 12, connections: 7, listening: 0 },
  { name: "steam.exe", pids: [7720], exePath: null, sockets: 9, connections: 5, listening: 1 },
  { name: "svchost.exe", pids: [1004, 1188, 1320, 1544, 2012], exePath: null, sockets: 30, connections: 3, listening: 9 },
  { name: "Code.exe", pids: [3300, 3312], exePath: null, sockets: 6, connections: 2, listening: 1 },
  { name: "notepad.exe", pids: [8100], exePath: null, sockets: 0, connections: 0, listening: 0 },
];

export function demoProcesses(): ProcessGroup[] {
  return DEMO_PROCS.map((p) => ({ ...p, pids: [...p.pids] }));
}

type DemoEndpoint = Pick<EndpointRow, "ip" | "name" | "nameSource" | "scope" | "owner"> & {
  share: number;
  /** All-traffic mode: the program talking to it. */
  program: string;
  port: number;
  transport: "tcp" | "udp";
  /** Appears after this many ms. */
  from: number;
};

const DEMO_ENDPOINTS: DemoEndpoint[] = [
  { ip: "142.250.201.174", owner: { asn: 15169, org: "Google LLC", country: "US", source: "dbip" }, name: "www.youtube.com", nameSource: "sni", scope: "public", program: "chrome.exe", share: 0.52, port: 443, transport: "udp", from: 0 },
  { ip: "172.217.20.78", owner: { asn: 15169, org: "Google LLC", country: "FR", source: "dbip" }, name: "rr3---sn-25ge7nsd.googlevideo.com", nameSource: "sni", scope: "public", program: "chrome.exe", share: 0.28, port: 443, transport: "tcp", from: 0 },
  { ip: "104.16.124.96", owner: { asn: 13335, org: "Cloudflare, Inc.", country: "US", source: "dbip" }, name: "cdnjs.cloudflare.com", nameSource: "dns", scope: "public", program: "chrome.exe", share: 0.08, port: 443, transport: "tcp", from: 0 },
  { ip: "2a00:1450:4007:80f::200e", owner: { asn: 15169, org: "Google LLC", country: "FR", source: "dbip" }, name: "accounts.google.com", nameSource: "sni", scope: "public", program: "chrome.exe", share: 0.05, port: 443, transport: "tcp", from: 0 },
  { ip: "192.168.1.1", owner: null, name: "livebox.home", nameSource: "reverseDns", scope: "private", program: "svchost.exe", share: 0.01, port: 53, transport: "udp", from: 0 },
  { ip: "13.107.42.14", owner: { asn: 8068, org: "Microsoft Corporation", country: "US", source: "dbip" }, name: "cloudflare-ech.com", nameSource: "echOuter", scope: "public", program: "Discord.exe", share: 0.03, port: 443, transport: "tcp", from: 4000 },
  { ip: "52.84.150.12", owner: { asn: 16509, org: "Amazon.com, Inc.", country: "DE", source: "ipinfo" }, name: null, nameSource: null, scope: "public", program: "steam.exe", share: 0.02, port: 443, transport: "tcp", from: 9000 },
  { ip: "192.168.1.50", owner: null, name: "living-room-tv.local", nameSource: "dns", scope: "private", program: "Code.exe", share: 0.01, port: 8009, transport: "tcp", from: 15000 },
];

let timer: ReturnType<typeof setInterval> | null = null;
let session = 0;
/** The window's subscription (see `subscribe_monitor`). */
let sink: (e: MonitorEvent) => void = () => {};

export function demoSubscribe(onEvent: (e: MonitorEvent) => void) {
  sink = onEvent;
  if (demoSession && timer) sink({ kind: "started", session: demoSession });
}

export function demoStop(): boolean {
  finishDemoRecording();
  if (!timer) return false;
  clearInterval(timer);
  timer = null;
  const id = demoSession?.sessionId ?? 0;
  demoSession = null;
  sink({ kind: "stopped", sessionId: id, reason: "userRequested", message: null });
  return true;
}

/** Same contract as the real `start_monitor`: events go to the subscriber. */
export function demoStart(req: StartRequest): SessionInfo {
  demoStop();
  const sessionId = ++session;
  const onEvent = (e: MonitorEvent) => sink(e);
  // Like the backend: a missing or null override keeps the default.
  const gauge: GaugeConfig = { ...DEMO_GAUGE };
  for (const [k, v] of Object.entries(req.gauge ?? {})) {
    if (v != null) gauge[k as keyof GaugeConfig] = v;
  }
  const tickMs = 250;
  const iface = { name: "demo0", description: "Simulated Ethernet", linkType: 1 };
  let info: SessionInfo;
  if (req.target.kind === "host") {
    const input = req.target.address;
    const target = /^[\d.:a-f]+$/i.test(input) ? input : "203.0.113.7";
    info = {
      sessionId, mode: "host", label: target, target, resolvedFrom: target === input ? null : input,
      process: null, attribution: null, naming: null, interfaces: [iface], filter: `host ${target}`, tickMs, gauge,
    };
  } else if (req.target.kind === "all") {
    info = {
      sessionId, mode: "all", label: "All traffic", target: null, resolvedFrom: null, process: null,
      attribution: { method: "socketTable", elevated: false, note: "Run Fishe as administrator to also catch very short-lived connections (ETW)." },
      naming: { sniffers: 1, reverseDns: req.naming?.reverseDns ?? true },
      interfaces: [iface], filter: "ip or ip6", tickMs, gauge,
    };
  } else {
    const sel = req.target.selector;
    const group = DEMO_PROCS.find((p) => (sel.by === "name" ? p.name.toLowerCase() === sel.name.toLowerCase() : p.pids.includes(sel.pid)));
    const pids = sel.by === "pid" ? [sel.pid] : (group?.pids ?? []);
    info = {
      sessionId, mode: "process",
      label: sel.by === "name" ? sel.name : `${group?.name ?? "process"} (PID ${sel.pid})`,
      target: null, resolvedFrom: null,
      process: { selector: sel, pids, exePath: group?.exePath ?? null },
      attribution: { method: "socketTable", elevated: false, note: "Run Fishe as administrator to also catch very short-lived connections (ETW)." },
      naming: { sniffers: 2, reverseDns: req.naming?.reverseDns ?? true },
      interfaces: [iface, { name: "demo-lo", description: "Simulated Loopback", linkType: 0 }],
      filter: "tcp or udp", tickMs, gauge,
    };
  }
  const allMode = info.mode === "all";
  const withEndpoints = info.process !== null || allMode;
  const processTick = info.process
    ? { pids: info.process.pids, pidCount: info.process.pids.length, sockets: 18, knownPorts: 240 }
    : allMode
      ? { pids: [], pidCount: 41, sockets: 212, knownPorts: 236 }
      : null;
  onEvent({ kind: "started", session: info });
  demoSession = info;
  const tickOut = (e: MonitorEvent) => {
    if (e.kind === "sample" && rec) {
      rec.samples.push(e);
      e.recording = { id: rec.info.id, elapsedMs: Date.now() - rec.info.startedAt, samples: rec.samples.length, pcapPackets: 0, pcapDropped: 0 };
    }
    onEvent(e);
  };

  // Simple mirror of the Rust BusyDetector (see src-tauri/src/monitor/gauge.rs).
  let t = 0;
  let smoothed = 0;
  let baseline = 0;
  let warmSum = 0;
  let warmN = 0;
  let level: Level = "idle";
  let peak = 0;
  const eps = new Map<string, { smoothed: number; baseline: number; peak: number; totals: { bytesIn: number; bytesOut: number; packetsIn: number; packetsOut: number }; ports: number; first: number; last: number }>();
  let burstUntil = 0;
  let burstGain = 1;
  let nextBurst = 8000;
  const totals = { bytesIn: 0, bytesOut: 0, packetsIn: 0, packetsOut: 0 };
  const transports = { tcp: 0, udp: 0, icmp: 0, other: 0 };
  const ports = new Map<string, PortUsage>([
    ["tcp:443", { transport: "tcp", port: 443, bytes: 0, packets: 0 }],
    ["udp:443", { transport: "udp", port: 443, bytes: 0, packets: 0 }],
    ["udp:53", { transport: "udp", port: 53, bytes: 0, packets: 0 }],
    ["tcp:80", { transport: "tcp", port: 80, bytes: 0, packets: 0 }],
  ]);
  const ewma = (prev: number, x: number, dt: number, tau: number) => prev + (1 - Math.exp(-dt / tau)) * (x - prev);

  // The burst goes mostly to the video endpoint, like a real player buffering.
  function demoEndpoints(inBps: number, outBps: number) {
    const dt = tickMs / 1000;
    const live = DEMO_ENDPOINTS.filter((d) => t >= d.from);
    const rows: EndpointRow[] = live.map((d) => {
      const w = d.share * (0.7 + Math.random() * 0.6) * (t < burstUntil && d.share > 0.25 ? 1.6 : 1);
      const eIn = inBps * w;
      const eOut = outBps * w;
      let e = eps.get(d.ip);
      if (!e) {
        e = { smoothed: eIn + eOut, baseline: eIn + eOut, peak: 0, totals: { bytesIn: 0, bytesOut: 0, packetsIn: 0, packetsOut: 0 }, ports: 0, first: t, last: t };
        eps.set(d.ip, e);
      }
      e.smoothed = ewma(e.smoothed, eIn + eOut, dt, gauge.smoothingSecs);
      e.baseline = Math.exp(ewma(Math.log(Math.max(e.baseline, 256)), Math.log(Math.max(e.smoothed, 256)), dt, e.smoothed > e.baseline ? gauge.baselineRiseSecs : gauge.baselineFallSecs));
      e.peak = Math.max(e.peak, eIn + eOut);
      e.totals.bytesIn += Math.round(eIn * dt);
      e.totals.bytesOut += Math.round(eOut * dt);
      e.totals.packetsIn += Math.round((eIn * dt) / 1200);
      e.totals.packetsOut += Math.round((eOut * dt) / 120);
      if (eIn + eOut > 200) e.last = t;
      const ratio = e.smoothed / Math.max(e.baseline, gauge.baselineFloorBps);
      const lvl: Level = e.smoothed < gauge.idleFloorBps ? "idle" : ratio >= gauge.spikeRatio ? "spike" : ratio >= gauge.busyRatio ? "busy" : "calm";
      return {
        ip: d.ip, name: d.name, nameSource: d.nameSource, scope: d.scope, owner: d.owner,
        hops: d.scope === "private" ? 0 : 8 + (d.ip.length % 5),
        inBps: eIn, outBps: eOut, smoothedBps: e.smoothed, baselineBps: e.baseline, ratio, level: lvl, peakBps: e.peak,
        totals: { ...e.totals },
        topPorts: [{ transport: d.transport, port: d.port, bytes: e.totals.bytesIn + e.totals.bytesOut }],
        firstSeenMs: e.first, lastSeenMs: e.last,
        programs: allMode ? [{ key: d.program.toLowerCase(), name: d.program, bytes: e.totals.bytesIn + e.totals.bytesOut }] : undefined,
        quality: demoQuality(d, t < burstUntil),
      };
    });
    rows.sort((a, b) => b.smoothedBps - a.smoothedBps);
    demoLastRows = rows;
    return { total: rows.length + 23, rows };
  }

  // Session quality: mean of the TCP endpoints' RTTs; bursts add queueing delay and a few retransmissions.
  let minRtt = Infinity;
  function sessionQuality(rows: EndpointRow[] | null, bursting: boolean): QualityTick {
    const tcp = (rows ?? []).filter((r) => r.quality?.srttMs != null);
    const rtt = tcp.length ? tcp.reduce((n, r) => n + r.quality!.srttMs!, 0) / tcp.length : demoBaseRtt(info.target ?? "x");
    const tick = rtt * (0.85 + Math.random() * 0.3) * (bursting ? 1.5 : 1);
    minRtt = Math.min(minRtt, tick);
    const dataOut = Math.round(t * 2.2);
    const dataIn = Math.round(t * 14);
    return {
      rttMs: rtt * (bursting ? 1.4 : 1), rttTickMs: tick, minRttMs: minRtt, srttMs: rtt, jitterMs: rtt * 0.06 * (bursting ? 3 : 1),
      recentSamples: 40, retransOutPct: bursting ? 1.5 + Math.random() * 2 : Math.random() * 0.3, retransInPct: bursting ? 0.8 : 0.05,
      dataOut, dataIn, retransOut: Math.round(dataOut * 0.004), retransIn: Math.round(dataIn * 0.001), rttSamples: Math.round(t / 50),
    };
  }

  // All-traffic mode: programs are the sum of their endpoints, plus unattributed ICMP.
  const progFirst = new Map<string, number>();
  function demoPrograms(rows: EndpointRow[]) {
    const by = new Map<string, ProgramRow>();
    for (const r of rows) {
      const name = DEMO_ENDPOINTS.find((d) => d.ip === r.ip)?.program ?? "chrome.exe";
      const key = name.toLowerCase();
      if (!progFirst.has(key)) progFirst.set(key, t);
      const pids = DEMO_PROCS.find((p) => p.name === name)?.pids ?? [];
      const p = by.get(key) ?? {
        key, name, pids, inBps: 0, outBps: 0, smoothedBps: 0, baselineBps: 0, ratio: 0, level: "idle" as Level, peakBps: 0,
        totals: { bytesIn: 0, bytesOut: 0, packetsIn: 0, packetsOut: 0 }, endpoints: 0, firstSeenMs: progFirst.get(key)!, lastSeenMs: 0,
      };
      p.inBps += r.inBps; p.outBps += r.outBps; p.smoothedBps += r.smoothedBps; p.baselineBps += r.baselineBps; p.peakBps += r.peakBps;
      p.totals.bytesIn += r.totals.bytesIn; p.totals.bytesOut += r.totals.bytesOut;
      p.totals.packetsIn += r.totals.packetsIn; p.totals.packetsOut += r.totals.packetsOut;
      p.endpoints += 1; p.lastSeenMs = Math.max(p.lastSeenMs, r.lastSeenMs);
      by.set(key, p);
    }
    for (const p of by.values()) {
      p.ratio = p.smoothedBps / Math.max(p.baselineBps, gauge.baselineFloorBps);
      p.level = p.smoothedBps < gauge.idleFloorBps ? "idle" : p.ratio >= gauge.spikeRatio ? "spike" : p.ratio >= gauge.busyRatio ? "busy" : "calm";
    }
    if (!progFirst.has("")) progFirst.set("", t);
    by.set("", {
      key: "", name: "Unattributed", pids: [], inBps: 60, outBps: 60, smoothedBps: 120, baselineBps: 120, ratio: 1, level: "idle", peakBps: 400,
      totals: { bytesIn: t / 8, bytesOut: t / 8, packetsIn: t / 600, packetsOut: t / 600 }, endpoints: 3, firstSeenMs: 0, lastSeenMs: t,
    });
    const list = [...by.values()].sort((a, b) => b.smoothedBps - a.smoothedBps);
    return { total: list.length, rows: list };
  }

  timer = setInterval(() => {
    t += tickMs;
    const dt = tickMs / 1000;

    if (t >= nextBurst) {
      burstGain = Math.random() < 0.4 ? 2.5 + Math.random() : 7 + Math.random() * 8;
      burstUntil = t + 2500 + Math.random() * 4000;
      nextBurst = burstUntil + 9000 + Math.random() * 12000;
    }
    const gain = t < burstUntil ? burstGain : 1;
    const wave = 1 + 0.25 * Math.sin(t / 4000);
    const inBps = 140_000 * wave * gain * (0.75 + Math.random() * 0.5);
    const outBps = 18_000 * wave * Math.sqrt(gain) * (0.7 + Math.random() * 0.6);
    const inPps = inBps / 1200;
    const outPps = outBps / 120;
    const total = inBps + outBps;

    smoothed = t === tickMs ? total : ewma(smoothed, total, dt, gauge.smoothingSecs);
    if (t / 1000 <= gauge.warmupSecs) {
      warmSum += total;
      warmN += 1;
      baseline = warmSum / warmN;
    } else if (smoothed >= gauge.idleFloorBps) {
      // log-domain adaptation, like the Rust detector
      const f = gauge.idleFloorBps;
      const tau = smoothed > baseline ? gauge.baselineRiseSecs : gauge.baselineFallSecs;
      baseline = Math.exp(ewma(Math.log(Math.max(baseline, f)), Math.log(Math.max(smoothed, f)), dt, tau));
    }
    const ratio = smoothed / Math.max(baseline, gauge.baselineFloorBps);
    level = smoothed < gauge.idleFloorBps ? "idle" : ratio >= gauge.spikeRatio ? "spike" : ratio >= gauge.busyRatio ? "busy" : "calm";
    peak = Math.max(peak, total);

    const bIn = inBps * dt;
    const bOut = outBps * dt;
    totals.bytesIn += Math.round(bIn);
    totals.bytesOut += Math.round(bOut);
    totals.packetsIn += Math.round(inPps * dt);
    totals.packetsOut += Math.round(outPps * dt);
    transports.tcp += Math.round((bIn + bOut) * 0.78);
    transports.udp += Math.round((bIn + bOut) * 0.215);
    transports.icmp += Math.round((bIn + bOut) * 0.005);
    const split: [string, number][] = [["tcp:443", 0.7], ["udp:443", 0.21], ["udp:53", 0.005], ["tcp:80", 0.08]];
    for (const [k, f] of split) {
      const p = ports.get(k)!;
      p.bytes += Math.round((bIn + bOut) * f);
      p.packets += Math.max(1, Math.round((inPps + outPps) * dt * f));
    }

    tickOut({
      kind: "sample",
      sessionId,
      tMs: t,
      intervalMs: tickMs,
      inBps,
      outBps,
      inPps,
      outPps,
      smoothedBps: smoothed,
      baselineBps: baseline,
      ratio,
      level,
      peakBps: peak,
      totals: { ...totals },
      transports: { ...transports },
      topPorts: [...ports.values()].sort((a, b) => b.bytes - a.bytes).map((p) => ({ ...p })),
      dropped: 0,
      ifDropped: 0,
      unattributed: withEndpoints ? Math.round(t / 4000) : 0,
      process: processTick,
      ...(() => {
        const endpoints = withEndpoints ? demoEndpoints(inBps, outBps) : null;
        return {
          endpoints,
          programs: allMode && endpoints ? demoPrograms(endpoints.rows) : null,
          quality: sessionQuality(endpoints?.rows ?? null, t < burstUntil),
        };
      })(),
      recording: null,
    });
  }, tickMs);

  return info;
}


// ───────────── browser-preview quality and ping ─────────────

/** A stable fake RTT per address: LAN ~2 ms, Internet 12–90 ms. */
function demoBaseRtt(ip: string): number {
  if (ip.startsWith("192.168.")) return 2;
  let h = 0;
  for (const c of ip) h = (h * 31 + c.charCodeAt(0)) % 997;
  return 12 + (h % 78);
}

function demoQuality(d: DemoEndpoint, bursting: boolean): EndpointRow["quality"] {
  if (d.transport !== "tcp") return null; // passive RTT needs TCP
  const base = demoBaseRtt(d.ip);
  return {
    srttMs: base * (bursting ? 1.35 : 1.05), minRttMs: base, jitterMs: base * (bursting ? 0.2 : 0.05), rttSamples: 120,
    retransOutPct: bursting && d.share > 0.25 ? 2.4 : 0.1, retransInPct: 0.05,
  };
}

const demoPingTargets = new Map<string, { st: PingStatus; timer: ReturnType<typeof setInterval> }>();

export const demoPings = {
  pingStart: async (ip: string): Promise<PingStatus> => {
    const have = demoPingTargets.get(ip);
    if (have?.st.running) return { ...have.st };
    if ([...demoPingTargets.values()].filter((x) => x.st.running).length >= 4) {
      throw { code: "busy", message: "at most 4 pings can run at once; stop one first" };
    }
    if (have) clearInterval(have.timer);
    const base = demoBaseRtt(ip);
    const st: PingStatus = {
      ip, running: true, startedAtMs: Date.now(), sent: 0, received: 0, lossPct: null, lastMs: null,
      avgMs: null, minMs: null, maxMs: null, jitterMs: null, history: [], error: null,
    };
    const timer = setInterval(() => {
      const lost = Math.random() < 0.02;
      const v = lost ? null : Math.round(base * (0.9 + Math.random() * 0.3) + (Math.random() < 0.05 ? base * 2 : 0));
      st.sent++;
      st.history = [...st.history, v].slice(-120);
      if (v !== null) {
        st.jitterMs = st.lastMs === null ? 0 : (st.jitterMs ?? 0) + (Math.abs(v - st.lastMs) - (st.jitterMs ?? 0)) / 16;
        st.received++;
        st.minMs = Math.min(st.minMs ?? v, v);
        st.maxMs = Math.max(st.maxMs ?? v, v);
      }
      st.lastMs = v;
      const recent = st.history.slice(-60);
      const got = recent.filter((x): x is number => x !== null);
      st.lossPct = ((recent.length - got.length) * 100) / recent.length;
      st.avgMs = got.length ? got.reduce((a, b) => a + b, 0) / got.length : null;
    }, 1000);
    demoPingTargets.set(ip, { st, timer });
    return { ...st };
  },
  pingStop: async (ip: string) => {
    const x = demoPingTargets.get(ip);
    if (!x?.st.running) return false;
    clearInterval(x.timer);
    x.st.running = false;
    return true;
  },
  pingRemove: async (ip: string) => {
    const x = demoPingTargets.get(ip);
    if (x) clearInterval(x.timer);
    demoPingTargets.delete(ip);
  },
  pingStatus: async (): Promise<PingStatus[]> => [...demoPingTargets.values()].map((x) => ({ ...x.st, history: [...x.st.history] })),
};

// ───────────── browser-preview MCP settings ─────────────

let demoMcpStatus: McpStatus = {
  enabled: false, access: "read", port: 47823, running: false, error: null, url: "http://127.0.0.1:47823/mcp",
  token: "demo-token-0123456789abcdef0123456789abcdef", calls: 0,
  configPath: "%APPDATA%\\com.fishe.app\\mcp.json", exePath: "C:\\Program Files\\Fishe\\fishe.exe",
};

export const demoMcp = {
  mcpStatus: async () => ({ ...demoMcpStatus }),
  mcpConfigure: async (enabled: boolean, access: McpAccess, port: number) => {
    demoMcpStatus = { ...demoMcpStatus, enabled, access, port, running: enabled, url: `http://127.0.0.1:${port}/mcp` };
    return { ...demoMcpStatus };
  },
  mcpNewToken: async () => {
    demoMcpStatus = { ...demoMcpStatus, token: Math.random().toString(16).slice(2).padEnd(48, "0") };
    return { ...demoMcpStatus };
  },
  mcpActivity: async () => [],
  mcpClearActivity: async () => {},
};

// ───────────── browser-preview packet list ─────────────

let demoLastRows: EndpointRow[] = [];
let demoFeed = false;
let demoSeq = 0;
let demoFeedAt = 0;

export const demoPackets = {
  setPacketFeed: async (enabled: boolean) => {
    demoFeed = enabled;
    demoFeedAt = Date.now();
    return timer !== null;
  },
  /** Synthesises the packets since the last call from the current endpoints. */
  recentPackets: async (_after: number | null, limit = 500): Promise<PacketBatch> => {
    if (!demoFeed || !timer || !demoLastRows.length) return { rows: [], nextSeq: demoSeq, enabled: demoFeed };
    const now = Date.now();
    const n = Math.min(limit, Math.max(1, Math.round((now - demoFeedAt) / 1000 * (25 + Math.random() * 40))));
    demoFeedAt = now;
    const rows: PacketRow[] = [];
    for (let i = 0; i < n; i++) {
      const r = demoLastRows[Math.floor(Math.random() * Math.min(demoLastRows.length, 1 + Math.random() * demoLastRows.length))];
      const d = DEMO_ENDPOINTS.find((x) => x.ip === r.ip)!;
      const inbound = Math.random() < 0.7;
      const me = r.ip.includes(":") ? "2a01:cb00:1:2::20" : "192.168.1.20";
      const eph = 50000 + (r.ip.length * 97) % 9000;
      rows.push({
        seq: demoSeq++, tsUs: (now - (n - i) * 7) * 1000, iface: 0, dir: inbound ? "in" : "out",
        src: inbound ? r.ip : me, dst: inbound ? me : r.ip, transport: d.transport,
        srcPort: inbound ? d.port : eph, dstPort: inbound ? eph : d.port,
        len: inbound ? 1200 + Math.floor(Math.random() * 314) : 54 + Math.floor(Math.random() * 80),
        ttl: inbound ? 64 - (r.hops ?? 0) : 64, pid: demoSession?.mode === "all" ? 4120 : null,
        program: demoSession?.mode === "all" ? d.program : null, remoteName: r.name,
      });
    }
    return { rows, nextSeq: demoSeq, enabled: true };
  },
};

// ───────────── browser-preview archive (in memory, lost on reload) ─────────────

let demoSession: SessionInfo | null = null;
let rec: { info: RecordingInfo; samples: Sample[] } | null = null;
const stored: { summary: RecordingSummary; detail: RecordingDetail }[] = [];

function finishDemoRecording(): RecordingInfo | null {
  if (!rec || !demoSession) return null;
  const { info, samples } = rec;
  rec = null;
  sink({ kind: "recordingStopped", sessionId: demoSession.sessionId, recording: info });
  const t0 = samples.length ? samples[0].tMs - samples[0].intervalMs : 0;
  const series: SeriesPoint[] = samples.map((x) => ({
    tMs: x.tMs - t0, inBps: x.inBps, outBps: x.outBps, smoothedBps: x.smoothedBps,
    baselineBps: x.baselineBps, ratio: x.ratio, level: x.level, rttMs: x.quality?.rttTickMs ?? undefined,
  }));
  const episodes: Episode[] = [];
  let open: Episode | null = null;
  for (const p of series) {
    const hot = p.level === "busy" || p.level === "spike";
    if (hot) {
      open ??= { startMs: p.tMs, endMs: p.tMs, maxLevel: p.level, peakBps: 0, peakRatio: 0 };
      if (p.level === "spike") open.maxLevel = "spike";
      open.peakBps = Math.max(open.peakBps, p.inBps + p.outBps);
      open.peakRatio = Math.max(open.peakRatio, p.ratio);
      open.endMs = p.tMs;
    } else if (open) {
      episodes.push(open);
      open = null;
    }
  }
  if (open) episodes.push(open);
  const last = samples[samples.length - 1];
  const first = samples[0];
  const totals = last && first
    ? {
        bytesIn: last.totals.bytesIn - first.totals.bytesIn, bytesOut: last.totals.bytesOut - first.totals.bytesOut,
        packetsIn: last.totals.packetsIn - first.totals.packetsIn, packetsOut: last.totals.packetsOut - first.totals.packetsOut,
      }
    : { bytesIn: 0, bytesOut: 0, packetsIn: 0, packetsOut: 0 };
  const order = ["idle", "calm", "busy", "spike"] as const;
  const maxLevel = series.reduce<(typeof order)[number]>((m, p) => (order.indexOf(p.level) > order.indexOf(m) ? p.level : m), "idle");
  const rows = last?.endpoints?.rows ?? [];
  const summary: RecordingSummary = {
    id: info.id, name: info.name, mode: demoSession.mode, label: demoSession.label,
    startedAt: info.startedAt, endedAt: Date.now(), durationMs: Date.now() - info.startedAt, status: "complete",
    sampleCount: series.length, totals, peakBps: Math.max(0, ...series.map((p) => p.inBps + p.outBps)), maxLevel,
    endpointCount: rows.length, pcapPath: null, pcapPackets: 0, pcapDropped: 0, pcapBytes: null,
  };
  const detail: RecordingDetail = {
    summary, session: demoSession,
    extra: last ? { transports: last.transports, topPorts: last.topPorts, dropped: 0, ifDropped: 0, unattributed: last.unattributed } : null,
    samples: series, downsampled: false, episodes,
    endpoints: rows.map((r) => ({
      ip: r.ip, name: r.name, nameSource: r.nameSource, scope: r.scope, owner: r.owner, totals: r.totals,
      firstSeenMs: Math.max(0, r.firstSeenMs - t0), lastSeenMs: Math.max(0, r.lastSeenMs - t0), peakBps: r.peakBps, maxLevel: r.level, topPorts: r.topPorts,
      quality: r.quality,
    })),
  };
  stored.unshift({ summary, detail });
  return info;
}

const unavailable = () => Promise.reject({ code: "unavailable", message: "Not available in the browser preview." });

export const demoArchive = {
  startRecording: async (o: { name?: string | null }) => {
    if (!timer || !demoSession) throw { code: "invalid_state", message: "start monitoring before recording" };
    rec = { info: { id: stored.length + 1, name: o.name?.trim() || demoSession.label, startedAt: Date.now(), pcapPath: null }, samples: [] };
    sink({ kind: "recordingStarted", sessionId: demoSession.sessionId, recording: rec.info });
    return rec.info;
  },
  stopRecording: async () => finishDemoRecording(),
  listRecordings: async () => stored.map((x) => x.summary),
  getRecording: async (id: number) => {
    const r = stored.find((x) => x.summary.id === id);
    if (!r) throw { code: "not_found", message: `recording ${id} not found` };
    return r.detail;
  },
  getEndpointSeries: async () => [] as SeriesPoint[],
  renameRecording: async (id: number, name: string) => {
    const r = stored.find((x) => x.summary.id === id);
    if (r) r.summary.name = r.detail.summary.name = name;
  },
  deleteRecording: async (id: number) => {
    const i = stored.findIndex((x) => x.summary.id === id);
    if (i >= 0) stored.splice(i, 1);
  },
  archiveLocation: async () => "(browser preview: in memory)",
  revealInFolder: unavailable,
  exportRecording: unavailable,
  logsLocation: async () => "(browser preview: no log file)",
  openLogsFolder: unavailable,
};

// ───────────── browser-preview owner database (pretend-installed) ─────────────

let demoOnline = false;
const demoGeoStatus = () => ({
  installed: true, hasAsn: true, hasCountry: true, month: "2026-11", builtAt: Date.UTC(2026, 10, 1), downloadedAt: Date.now(),
  currentMonth: "2026-11", updateAvailable: false, bytes: 21_400_000, onlineEnabled: demoOnline,
  attribution: "IP data by DB-IP.com, licensed CC BY 4.0", dir: "(browser preview)",
});

export const demoGeo = {
  geoStatus: async () => demoGeoStatus(),
  geoDownload: async () => demoGeoStatus(),
  geoRemove: async () => demoGeoStatus(),
  setOnlineLookup: async (on: boolean) => {
    demoOnline = on;
    return demoGeoStatus();
  },
  geoLookup: async (ip: string) => DEMO_ENDPOINTS.find((d) => d.ip === ip)?.owner ?? { asn: 64500, org: "Example Networks", country: "NL", source: "dbip" as const },
};

// ───────────── browser-preview routes (synthetic) ─────────────

const demoTraces = new Map<string, TraceResult>();

function demoHop(ttl: number, addr: string | null, name: string | null, owner: Hop["owner"], status: Hop["status"] = "router"): Hop {
  return {
    ttl, addr, alternates: [], rttMs: addr ? 2 + ttl * 3 : null, sent: 2, received: addr ? 2 : 0, status, name, owner,
    scope: addr ? (addr.startsWith("192.168.") ? "private" : "public") : null,
  };
}

const ISP = { asn: 64496, org: "Example ISP", country: "FR", source: "dbip" as const };
const TRANSIT = { asn: 64510, org: "Example Transit", country: "DE", source: "dbip" as const };

export const demoRoutes = {
  traceRoute: async (ip: string) => {
    await new Promise((r) => setTimeout(r, 600));
    const ep = DEMO_ENDPOINTS.find((d) => d.ip === ip);
    const hops: Hop[] = [demoHop(1, "192.168.1.1", "livebox.home", null)];
    // Routes differ in length and shape, like real ones: a short one that
    // peers at the ISP, a long one through a transit network with silent
    // hops, and one that stops answering before its endpoint.
    let reached = true;
    if (ep?.scope !== "private") {
      const owner = ep?.owner ?? null;
      const asn = owner?.asn ?? 64511;
      const shape = [...ip].reduce((s, ch) => s + ch.charCodeAt(0), 0) % 3;
      const next = (addr: string | null, name: string | null, o: Hop["owner"]) =>
        hops.push(demoHop(hops.length + 1, addr, name, o, addr ? "router" : "silent"));
      next("198.51.100.1", "bras-1.example-isp.net", ISP);
      next("198.51.100.9", "core-2.example-isp.net", ISP);
      if (shape === 0) {
        next(`203.0.113.${asn % 200}`, `edge.as${asn}.example`, owner);
      } else if (shape === 1) {
        next(null, null, null);
        next("192.0.2.17", "ae4.fra.example-transit.net", TRANSIT);
        next("192.0.2.33", "ae9.ams.example-transit.net", TRANSIT);
        next(null, null, null);
        next(null, null, null);
        next(`203.0.113.${asn % 200}`, `edge.as${asn}.example`, owner);
        next(`203.0.113.${(asn % 200) + 1}`, null, owner);
      } else {
        next("192.0.2.17", "ae4.fra.example-transit.net", TRANSIT);
        next(`203.0.113.${asn % 200}`, `edge.as${asn}.example`, owner);
        next(null, null, null);
        next(null, null, null);
        reached = false;
      }
    }
    if (reached) hops.push({ ...demoHop(hops.length + 1, ip, ep?.name ?? null, ep?.owner ?? null, "destination") });
    const t: TraceResult = { target: ip, startedAt: Date.now(), durationMs: 600, reached, hops };
    demoTraces.set(ip, t);
    return t;
  },
  cachedTraces: async () => [...demoTraces.values()],
  networkContext: async (): Promise<NetContext> => ({
    gateways: [{ ip: "192.168.1.1", interfaceIndex: 9, metric: 0 }],
    neighbors: [
      { ip: "192.168.1.1", mac: "c8:7f:2b:35:1a:c0", state: "reachable", interfaceIndex: 9 },
      { ip: "192.168.1.50", mac: "a4:5e:60:12:34:56", state: "stale", interfaceIndex: 9 },
      { ip: "192.168.1.23", mac: "3c:22:fb:aa:bb:cc", state: "reachable", interfaceIndex: 9 },
    ],
  }),
  scanLan: async (probePorts: boolean): Promise<LanScan> => {
    await new Promise((r) => setTimeout(r, 1200));
    const port = (n: number, s: string | null) => ({ port: n, service: s });
    const devices: LanDevice[] = [
      { ip: "192.168.1.1", mac: "c8:7f:2b:35:1a:c0", vendor: "Arcadyan", hostname: "livebox.home", randomizedMac: false, isGateway: true, isSelf: false, ports: probePorts ? [port(53, "DNS"), port(80, "HTTP"), port(443, "HTTPS")] : [] },
      { ip: "192.168.1.19", mac: "e4:5f:01:aa:12:7c", vendor: "Raspberry Pi Foundation", hostname: "fishe-pc.home", randomizedMac: false, isGateway: false, isSelf: true, ports: [] },
      { ip: "192.168.1.23", mac: "3c:22:fb:aa:bb:cc", vendor: "Apple", hostname: null, randomizedMac: false, isGateway: false, isSelf: false, ports: probePorts ? [port(62078, "iPhone sync")] : [] },
      { ip: "192.168.1.40", mac: "b0:95:75:de:ad:01", vendor: "Texas Instruments", hostname: "nas.home", randomizedMac: false, isGateway: false, isSelf: false, ports: probePorts ? [port(80, "HTTP"), port(139, "NetBIOS"), port(445, "SMB"), port(5000, "Web / UPnP")] : [] },
      { ip: "192.168.1.52", mac: "9c:8e:cd:31:44:aa", vendor: "HP", hostname: "officejet.home", randomizedMac: false, isGateway: false, isSelf: false, ports: probePorts ? [port(80, "HTTP"), port(515, "Printer (LPD)"), port(631, "Printer (IPP)"), port(9100, "Printer (raw)")] : [] },
      { ip: "192.168.1.66", mac: "da:a1:19:7f:00:21", vendor: null, hostname: null, randomizedMac: true, isGateway: false, isSelf: false, ports: probePorts ? [port(554, "RTSP (camera)")] : [] },
      { ip: "192.168.1.88", mac: "44:65:0d:12:9b:55", vendor: "Amazon Technologies", hostname: "echo-dot.home", randomizedMac: false, isGateway: false, isSelf: false, ports: probePorts ? [port(8080, "Web (alt)")] : [] },
    ];
    return {
      networks: [
        { interface: "Wi-Fi", description: "Intel Wi-Fi 6 AX201", ip: "192.168.1.19", prefix: 24, gateway: "192.168.1.1", wireless: true, narrowed: false, devices },
      ],
      durationMs: 1200,
      probedPorts: probePorts,
      note: null,
    };
  },
};

/** The whole API, as `index.ts` serves it outside Tauri. */
export const demoApi: Api = {
  npcapStatus: async () => demoNpcap(),
  npcapRecheck: async () => {
    await new Promise((r) => setTimeout(r, 400));
    return demoNpcapRecheck();
  },
  openNpcapSite: async () => {
    window.open("https://npcap.com/#download", "_blank", "noopener");
  },
  defaultGaugeConfig: async () => DEMO_GAUGE,
  listInterfaces: async () => demoInterfaces,
  resolveTarget: async (input) => ({ input, ip: input, fromHostname: false, candidates: [input] }),
  suggestInterface: async () => "demo0",
  monitorStatus: async () => null,
  stopMonitor: async () => demoStop(),
  listProcesses: async () => demoProcesses(),
  ...demoPackets,
  systemCapabilities: async () => demoCapabilities,
  ...demoArchive,
  ...demoGeo,
  ...demoRoutes,
  ...demoPings,
  ...demoMcp,
  subscribeMonitor: async (onEvent) => demoSubscribe(onEvent),
  setMonitorDefaults: async () => {},
  startMonitor: async (request) => demoStart(request),
};

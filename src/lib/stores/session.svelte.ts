/**
 * The session controller: what the pages share about the running session.
 *
 * It starts, restarts and records sessions on behalf of the target bar, the
 * programs panel and the toasts; keeps what the window learnt at startup
 * (Npcap, interfaces, capabilities, detector defaults); follows sessions an
 * agent started; and derives the one "view" the Live page's gauge, tiles and
 * chart show, which is the whole session or the focused endpoint / program.
 * The pages read it; `monitor` holds the raw samples.
 */
import { api, errorMessage } from "../api";
import { agents } from "./agents.svelte";
import { formatPps, formatRate } from "../utils/format";
import { monitor } from "./monitor.svelte";
import { nav } from "./nav.svelte";
import type { MapEndpoint } from "../utils/netgraph";
import { pings } from "./pings.svelte";
import { routes } from "./routes.svelte";
import { settings } from "./settings.svelte";
import type { Capabilities, GaugeConfig, InterfaceInfo, NpcapStatus, Owner, ProcessSelector, SessionInfo, TargetSpec, TopItem } from "../api/types";

export interface StartArgs {
  target: TargetSpec;
  iface: string | null;
}

/** The `TargetSpec` a running session was started from (for Apply / Monitor ▸ after an agent start). */
export function targetOf(s: SessionInfo): TargetSpec {
  if (s.mode === "host") return { kind: "host", address: s.resolvedFrom ?? s.target ?? s.label };
  if (s.mode === "process" && s.process) return { kind: "process", selector: s.process.selector };
  return { kind: "all" };
}

class SessionController {
  npcap = $state<NpcapStatus | null>(null);
  interfaces = $state<InterfaceInfo[]>([]);
  /** Backend detector defaults (the gauge's zones before a session runs). */
  defaults = $state<GaugeConfig | null>(null);
  caps = $state<Capabilities | null>(null);
  /** Recording the Archive page should open (the "saved" toast's Open). */
  openRecording = $state<number | null>(null);
  /** Bumped to make the archive list reload. */
  archiveKey = $state(0);
  /** What the process picker shows; bound to the target bar. */
  formSelection = $state<ProcessSelector | null>(
    settings.recentProcesses[0] ? { by: "name", name: settings.recentProcesses[0] } : null,
  );
  /** Host mode: who owns the target (an online lookup may arrive a moment later). */
  hostOwner = $state<Owner | null>(null);

  #lastRequest: StartArgs | null = null;

  /** Startup: what the backend offers, the event subscription, the Settings the backend needs. */
  async init() {
    monitor.onForeignStart = (s) => this.#showForeign(s);
    try {
      [this.npcap, this.defaults, this.caps] = await Promise.all([api.npcapStatus(), api.defaultGaugeConfig(), api.systemCapabilities()]);
      if (this.npcap.available) this.interfaces = await api.listInterfaces();
      if (settings.onlineLookup) await api.setOnlineLookup(true);
      await this.pushDefaults();
      await monitor.attach();
      await pings.refresh();
      await agents.refresh();
    } catch (err) {
      monitor.error = errorMessage(err);
    }
  }

  /** Look for Npcap again after the user installed it; `true` when capture is now possible. */
  async recheckNpcap(): Promise<boolean> {
    try {
      this.npcap = await api.npcapRecheck();
      if (this.npcap.available) this.interfaces = await api.listInterfaces();
    } catch (err) {
      monitor.error = errorMessage(err);
    }
    return this.npcap?.available ?? false;
  }

  /** Pings and traces an agent starts have their own stores: reload them on notice. */
  listenChanges(): Promise<() => void> {
    return agents.listen({ pings: () => pings.refresh(), traces: () => routes.reloadTraces() });
  }

  /** The Settings a session an agent starts should measure with (same as a click). */
  pushDefaults() {
    return api
      .setMonitorDefaults({ gauge: settings.gaugeOverrides(), naming: { sniff: true, reverseDns: settings.reverseDns } })
      .catch(() => {});
  }

  start(target: TargetSpec, iface: string | null) {
    this.#lastRequest = { target, iface };
    if (target.kind === "host") settings.rememberTarget(target.address);
    else if (target.kind === "process" && target.selector.by === "name") settings.rememberProcess(target.selector.name);
    monitor.start({
      target,
      interface: iface,
      gauge: settings.gaugeOverrides(),
      naming: { sniff: true, reverseDns: settings.reverseDns },
    });
  }

  /** Settings → Apply: the same target with the new settings. */
  async restart() {
    if (!this.#lastRequest) return;
    await monitor.stop();
    this.start(this.#lastRequest.target, this.#lastRequest.iface);
  }

  /** Programs panel "Monitor ▸": switch to process mode bound to that program. */
  async monitorProgram(name: string) {
    const iface = this.#lastRequest?.iface ?? null;
    await monitor.stop();
    settings.mode = "process";
    this.formSelection = { by: "name", name };
    this.start({ kind: "process", selector: { by: "name", name } }, iface);
  }

  toggleRecording() {
    if (monitor.recording) {
      monitor.stopRecording().then(() => this.archiveKey++);
    } else if (monitor.session) {
      const when = new Intl.DateTimeFormat(undefined, { dateStyle: "short", timeStyle: "short" }).format(new Date());
      monitor.startRecording({ name: `${monitor.session.label} · ${when}`, pcap: settings.recordPcap });
    }
  }

  /** The "saved" toast's Open: show the recording in the archive. */
  openSaved() {
    if (!monitor.lastSaved) return;
    this.openRecording = monitor.lastSaved.id;
    monitor.dismissSaved();
    nav.go("archive");
  }

  /** A session started elsewhere (an agent, or before a reload): show it like a click would. */
  #showForeign(s: SessionInfo) {
    nav.go("live");
    settings.mode = s.mode;
    if (s.process) this.formSelection = s.process.selector;
    this.#lastRequest = { target: targetOf(s), iface: null };
  }

  // ───────────── derived: what the pages show ─────────────

  readonly info = $derived(monitor.session);
  readonly units = $derived(settings.units);
  readonly active = $derived(monitor.phase === "running" && monitor.latest !== null);
  readonly gauge = $derived(monitor.session?.gauge ?? this.defaults);
  readonly allMode = $derived(monitor.session?.mode === "all");
  /** Modes with an endpoints table / map (process and all traffic). */
  readonly processMode = $derived(monitor.session?.mode === "process" || this.allMode);
  readonly wholeName = $derived(this.allMode ? "all traffic" : "whole process");

  // Focus: the gauge, tiles and chart follow one endpoint (or, in all-traffic
  // mode, one program) instead of the whole session.
  readonly focusEp = $derived(this.processMode ? monitor.focusedRow : null);
  readonly focusProg = $derived(this.allMode ? monitor.focusedProgram : null);
  readonly focus = $derived(this.focusEp ?? this.focusProg);
  readonly focusName = $derived(this.focusEp ? (this.focusEp.name ?? this.focusEp.ip) : (this.focusProg?.name ?? null));
  readonly programFilter = $derived(this.focusProg ? { key: this.focusProg.key, name: this.focusProg.name } : null);

  readonly view = $derived.by(() => {
    const s = monitor.latest;
    const f = this.focus;
    return f
      ? {
          smoothed: f.smoothedBps, baseline: f.baselineBps, ratio: f.ratio, level: f.level,
          inBps: f.inBps, outBps: f.outBps, inPps: null, outPps: null, peak: f.peakBps, totals: f.totals,
        }
      : {
          smoothed: s?.smoothedBps ?? 0, baseline: s?.baselineBps ?? 0, ratio: s?.ratio ?? 0, level: s?.level ?? ("idle" as const),
          inBps: s?.inBps ?? 0, outBps: s?.outBps ?? 0, inPps: s?.inPps ?? 0, outPps: s?.outPps ?? 0, peak: s?.peakBps ?? 0,
          totals: s?.totals ?? { bytesIn: 0, bytesOut: 0, packetsIn: 0, packetsOut: 0 },
        };
  });
  readonly chartPoints = $derived(
    this.focusEp ? monitor.endpointHistory(this.focusEp.ip) : this.focusProg ? monitor.programHistory(this.focusProg.key) : monitor.history,
  );

  readonly inRate = $derived(formatRate(this.view.inBps, this.units));
  readonly outRate = $derived(formatRate(this.view.outBps, this.units));
  readonly peak = $derived(formatRate(this.view.peak, this.units));
  readonly totalBytes = $derived(monitor.latest ? monitor.latest.totals.bytesIn + monitor.latest.totals.bytesOut : 0);
  readonly viewBytes = $derived(this.view.totals.bytesIn + this.view.totals.bytesOut);
  readonly drops = $derived((monitor.latest?.dropped ?? 0) + (monitor.latest?.ifDropped ?? 0));
  readonly inSub = $derived(
    this.focusEp
      ? `${pps(this.view.inPps)}from ${this.focusName}`
      : this.focusProg
        ? `${pps(this.view.inPps)}received by ${this.focusName}`
        : this.allMode
          ? `${pps(this.view.inPps)}received by this PC`
          : this.processMode
            ? `${pps(this.view.inPps)}received by process`
            : `${pps(this.view.inPps)}from target`,
  );
  readonly outSub = $derived(
    this.focusEp
      ? `${pps(this.view.outPps)}to ${this.focusName}`
      : this.focusProg
        ? `${pps(this.view.outPps)}sent by ${this.focusName}`
        : this.allMode
          ? `${pps(this.view.outPps)}sent by this PC`
          : this.processMode
            ? `${pps(this.view.outPps)}sent by process`
            : `${pps(this.view.outPps)}to target`,
  );

  // Connection quality: the focused endpoint, the host-mode target, or all connections.
  readonly quality = $derived.by(() => {
    const s = monitor.latest;
    const session = monitor.session;
    const q = s?.quality ?? null;
    const f = this.focusEp;
    if (f) {
      const e = f.quality;
      return {
        subject: this.focusName ?? f.ip, pingIp: f.ip,
        rttMs: e?.srttMs ?? null, rttHint: "smoothed", minRttMs: e?.minRttMs ?? null,
        jitterMs: e?.jitterMs ?? null, jitterHint: "between round-trip samples",
        retransOutPct: e?.retransOutPct ?? null, retransInPct: e?.retransInPct ?? null, retransHint: "this session",
        points: this.chartPoints, // the same slice the chart uses; don't cut it twice per tick
      };
    }
    if (session?.mode === "host") {
      return {
        subject: session.resolvedFrom ?? session.target ?? session.label, pingIp: session.target,
        rttMs: q?.srttMs ?? null, rttHint: "smoothed", minRttMs: q?.minRttMs ?? null,
        jitterMs: q?.jitterMs ?? null, jitterHint: "between round-trip samples",
        retransOutPct: q?.retransOutPct ?? null, retransInPct: q?.retransInPct ?? null, retransHint: "last 10 s",
        points: monitor.history,
      };
    }
    return {
      subject: "all connections", pingIp: null,
      rttMs: q?.rttMs ?? null, rttHint: "average, last 10 s", minRttMs: q?.minRttMs ?? null,
      jitterMs: null, jitterHint: "focus an endpoint to see its jitter",
      retransOutPct: q?.retransOutPct ?? null, retransInPct: q?.retransInPct ?? null, retransHint: "last 10 s",
      points: monitor.history,
    };
  });

  // Map inputs: process endpoints, or the single host-mode target.
  readonly mapEndpoints = $derived.by((): MapEndpoint[] => {
    const s = monitor.latest;
    const session = monitor.session;
    if (this.processMode) {
      const rows = s?.endpoints?.rows ?? [];
      const pf = this.programFilter;
      const shown = pf ? rows.filter((r) => r.programs?.some((p) => p.key === pf.key)) : rows;
      return shown.map((r) => ({
        ip: r.ip, name: r.name, owner: r.owner, scope: r.scope, level: r.level,
        rateBps: r.inBps + r.outBps, totalBytes: r.totals.bytesIn + r.totals.bytesOut, hops: r.hops,
      }));
    }
    if (session?.mode === "host" && session.target) {
      return [{
        ip: session.target, name: session.resolvedFrom, owner: this.hostOwner, scope: "public", level: s?.level ?? "idle",
        rateBps: (s?.inBps ?? 0) + (s?.outBps ?? 0), totalBytes: this.totalBytes, hops: null,
      }];
    }
    return [];
  });

  // Live page: the five busiest programs (all traffic) or endpoints.
  readonly topItems = $derived.by((): TopItem[] => {
    const s = monitor.latest;
    if (this.allMode) {
      return (s?.programs?.rows ?? []).map((r) => ({
        key: r.key, name: r.name, sub: r.pids.length > 1 ? `${r.pids.length} processes` : null, bps: r.smoothedBps, level: r.level,
      }));
    }
    if (this.processMode) {
      return monitor.endpointRows.map((r) => ({
        key: r.ip, name: r.name ?? r.ip, sub: r.name ? r.ip : (r.owner?.org ?? null), bps: r.smoothedBps, level: r.level,
      }));
    }
    return [];
  });
}

const pps = (v: number | null) => (v === null ? "" : `${formatPps(v)} · `);

export const session = new SessionController();

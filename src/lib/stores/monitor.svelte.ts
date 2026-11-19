/**
 * Reactive monitoring session store (Svelte 5 runes).
 *
 * Mirrors the backend's one session: lifecycle (idle → starting → running →
 * idle), the latest sample, a bounded history buffer for the chart, and the
 * recording state. The window subscribes to monitor events once (`attach`);
 * from then on every session and recording shows up here whether it was
 * started with the Start button or by an agent over MCP, and the backend's
 * `started` / `stopped` events are the truth about what runs.
 */
import { api, errorMessage } from "../api";
import type {
  EndpointRow,
  TrafficPoint,
  MonitorEvent,
  ProgramRow,
  RecordOptions,
  RecordingInfo,
  Sample,
  SessionInfo,
  StartRequest,
} from "../api/types";

export type Phase = "idle" | "starting" | "running" | "stopping";

/** 5 minutes at the default 250 ms tick. */
const HISTORY_CAP = 1200;
/** Forget an endpoint's history after this long without appearing in a sample. */
const ENDPOINT_FORGET_MS = 5 * 60_000;
/** Endpoints kept in the table after they drop out of the samples (shown idle). */
const ROW_CACHE_CAP = 400;

interface EndpointTrack {
  points: TrafficPoint[];
  lastMs: number;
  /** RTT samples seen so far (a new RTT point only when it grows). */
  rttSamples?: number;
}

class MonitorStore {
  phase = $state<Phase>("idle");
  session = $state<SessionInfo | null>(null);
  latest = $state.raw<Sample | null>(null);
  history = $state.raw<TrafficPoint[]>([]);
  error = $state<string | null>(null);
  /** Non-fatal notices from the backend (e.g. an interface dropped out). */
  warnings = $state<string[]>([]);
  /** The active recording (started here or by an agent), if any. */
  recording = $state<RecordingInfo | null>(null);
  /** Set when a recording finishes, for the "saved" notice. */
  lastSaved = $state<RecordingInfo | null>(null);
  recordingBusy = $state(false);

  /**
   * Called when a session appears that this window did not start (an agent
   * did, or the webview reloaded while one ran), so the page can show it.
   */
  onForeignStart: ((session: SessionInfo) => void) | null = null;

  /** Subscribe to the backend's events. Once, when the window mounts. */
  async attach() {
    try {
      await api.subscribeMonitor((e) => this.#onEvent(e));
    } catch (err) {
      this.error = errorMessage(err);
    }
  }

  async startRecording(options: RecordOptions) {
    if (this.recordingBusy) return;
    this.recordingBusy = true;
    try {
      this.recording = await api.startRecording(options);
      this.lastSaved = null;
    } catch (err) {
      this.error = errorMessage(err);
    } finally {
      this.recordingBusy = false;
    }
  }

  async stopRecording() {
    if (this.recordingBusy || !this.recording) return;
    this.recordingBusy = true;
    try {
      const info = await api.stopRecording();
      this.lastSaved = info ?? this.recording;
      this.recording = null;
    } catch (err) {
      this.error = errorMessage(err);
    } finally {
      this.recordingBusy = false;
    }
  }

  dismissWarning(index: number) {
    this.warnings = this.warnings.filter((_, i) => i !== index);
  }

  dismissSaved() {
    this.lastSaved = null;
  }

  /** Endpoint the gauge and chart are focused on (process mode), by IP. */
  focus = $state<string | null>(null);
  /** Bumped every sample; endpoint histories are read through it. */
  endpointVersion = $state(0);

  /**
   * Endpoints seen recently: the latest sample's rows plus quiet ones that
   * dropped out of it (the backend sends the busiest 150), shown idle so the
   * table doesn't lose rows every second.
   */
  endpointRows = $state.raw<EndpointRow[]>([]);
  #rowCache = new Map<string, EndpointRow>();

  /** Per-endpoint history (not reactive itself; read with `endpointVersion`). */
  #tracks = new Map<string, EndpointTrack>();
  /** Per-program history (all-traffic mode), same rules. */
  #programTracks = new Map<string, EndpointTrack>();

  /** All-traffic mode: program the gauge follows and the endpoints are filtered to, by key. */
  programFocus = $state<string | null>(null);

  programHistory(key: string, last = HISTORY_CAP): TrafficPoint[] {
    void this.endpointVersion;
    return this.#programTracks.get(key)?.points.slice(-last) ?? [];
  }

  /** The focused program's latest row. */
  get focusedProgram(): ProgramRow | null {
    if (this.programFocus === null) return null;
    return this.latest?.programs?.rows.find((r) => r.key === this.programFocus) ?? this.#lastProgramRow;
  }
  #lastProgramRow: ProgramRow | null = null;

  setProgramFocus(key: string | null) {
    this.programFocus = key;
    this.#lastProgramRow = null;
  }

  /**
   * The last `last` points of one endpoint's history. Returns a fresh array
   * each sample: the stored one is mutated in place, and consumers compare
   * by reference to decide whether to redraw.
   */
  endpointHistory(ip: string, last = HISTORY_CAP): TrafficPoint[] {
    void this.endpointVersion;
    return this.#tracks.get(ip)?.points.slice(-last) ?? [];
  }

  /** The focused endpoint's latest row, if it was in the last sample. */
  get focusedRow(): EndpointRow | null {
    if (!this.focus) return null;
    void this.endpointRows;
    return this.#rowCache.get(this.focus) ?? this.#lastFocusRow;
  }
  #lastFocusRow: EndpointRow | null = null;

  setFocus(ip: string | null) {
    this.focus = ip;
    this.#lastFocusRow = null;
  }

  /** A start requested here is in flight (its `started` is ours, not an agent's). */
  #starting = false;

  get active() {
    return this.phase === "running" || this.phase === "starting";
  }

  async start(request: StartRequest) {
    this.#starting = true;
    this.phase = "starting";
    this.error = null;
    try {
      // The `started` event (through the subscription) sets the session up.
      await api.startMonitor(request);
    } catch (err) {
      this.#starting = false;
      this.error = errorMessage(err);
      if (this.phase === "starting") this.phase = "idle";
    }
  }

  async stop() {
    if (!this.active) return;
    this.phase = "stopping";
    try {
      await api.stopMonitor();
    } catch (err) {
      this.error = errorMessage(err);
    } finally {
      // `stopped` normally lands first; this covers a backend that had nothing running.
      if (this.phase === "stopping") this.phase = "idle";
    }
  }

  dismissError() {
    this.error = null;
  }

  /** A new session: forget the previous one's data. */
  #reset(session: SessionInfo) {
    this.session = session;
    this.warnings = [];
    this.latest = null;
    this.history = [];
    this.focus = null;
    this.programFocus = null;
    this.#lastFocusRow = null;
    this.#lastProgramRow = null;
    this.#tracks.clear();
    this.#programTracks.clear();
    this.#rowCache.clear();
    this.endpointRows = [];
    this.recording = null;
  }

  #trackEndpoints(tMs: number, rows: EndpointRow[]) {
    const push = (ip: string, p: TrafficPoint) => {
      let t = this.#tracks.get(ip);
      if (!t) this.#tracks.set(ip, (t = { points: [], lastMs: tMs }));
      if (t.points.length >= HISTORY_CAP) t.points.shift();
      t.points.push(p);
      t.lastMs = tMs;
    };
    for (const r of rows) {
      const t = this.#tracks.get(r.ip);
      const n = r.quality?.rttSamples ?? 0;
      const fresh = n > (t?.rttSamples ?? 0);
      push(r.ip, {
        tMs, inBps: r.inBps, outBps: r.outBps, smoothedBps: r.smoothedBps,
        baselineBps: r.baselineBps, ratio: r.ratio, level: r.level,
        rttMs: fresh ? (r.quality?.srttMs ?? null) : null,
      });
      this.#tracks.get(r.ip)!.rttSamples = n;
    }
    // A focused endpoint that fell out of the selection is idle: keep its line going.
    if (this.focus && !rows.some((r) => r.ip === this.focus)) {
      const t = this.#tracks.get(this.focus);
      const last = t?.points[t.points.length - 1];
      if (last) push(this.focus, { ...last, tMs, inBps: 0, outBps: 0, smoothedBps: 0, ratio: 0, level: "idle", rttMs: null });
    } else if (this.focus) {
      this.#lastFocusRow = rows.find((r) => r.ip === this.focus) ?? null;
    }
    for (const [ip, t] of this.#tracks) {
      if (tMs - t.lastMs > ENDPOINT_FORGET_MS && ip !== this.focus) this.#tracks.delete(ip);
    }
    // Row cache: fresh rows replace, missing ones go idle, the oldest go.
    const fresh = new Set<string>();
    for (const r of rows) {
      this.#rowCache.set(r.ip, r);
      fresh.add(r.ip);
    }
    for (const [ip, r] of this.#rowCache) {
      if (fresh.has(ip)) continue;
      if (tMs - r.lastSeenMs > ENDPOINT_FORGET_MS && ip !== this.focus) this.#rowCache.delete(ip);
      else if (r.inBps || r.outBps || r.smoothedBps)
        this.#rowCache.set(ip, { ...r, inBps: 0, outBps: 0, smoothedBps: 0, ratio: 0, level: "idle" });
    }
    if (this.#rowCache.size > ROW_CACHE_CAP) {
      const old = [...this.#rowCache.values()].filter((r) => !fresh.has(r.ip)).sort((a, b) => a.lastSeenMs - b.lastSeenMs);
      for (const r of old.slice(0, this.#rowCache.size - ROW_CACHE_CAP)) this.#rowCache.delete(r.ip);
    }
    this.endpointRows = [...this.#rowCache.values()];
    this.endpointVersion++;
  }

  #trackPrograms(tMs: number, rows: ProgramRow[]) {
    const push = (key: string, p: TrafficPoint) => {
      let t = this.#programTracks.get(key);
      if (!t) this.#programTracks.set(key, (t = { points: [], lastMs: tMs }));
      if (t.points.length >= HISTORY_CAP) t.points.shift();
      t.points.push(p);
      t.lastMs = tMs;
    };
    for (const r of rows) {
      push(r.key, {
        tMs, inBps: r.inBps, outBps: r.outBps, smoothedBps: r.smoothedBps,
        baselineBps: r.baselineBps, ratio: r.ratio, level: r.level,
      });
    }
    const f = this.programFocus;
    if (f !== null) {
      const row = rows.find((r) => r.key === f);
      if (row) this.#lastProgramRow = row;
      else {
        const t = this.#programTracks.get(f);
        const last = t?.points[t.points.length - 1];
        if (last) push(f, { ...last, tMs, inBps: 0, outBps: 0, smoothedBps: 0, ratio: 0, level: "idle" });
      }
    }
    for (const [key, t] of this.#programTracks) {
      if (tMs - t.lastMs > ENDPOINT_FORGET_MS && key !== f) this.#programTracks.delete(key);
    }
  }

  #onEvent(e: MonitorEvent) {
    switch (e.kind) {
      case "started": {
        // Events are in order: the previous session's `stopped` came first.
        this.#reset(e.session);
        this.phase = "running";
        const foreign = !this.#starting;
        this.#starting = false;
        if (foreign) this.onForeignStart?.(e.session);
        break;
      }
      case "warning":
        if (e.sessionId !== this.session?.sessionId) break;
        this.warnings = [...this.warnings, e.message].slice(-5);
        break;
      case "recordingStarted":
        if (e.sessionId !== this.session?.sessionId) break;
        this.recording = e.recording;
        this.lastSaved = null;
        break;
      case "recordingStopped":
        if (e.sessionId !== this.session?.sessionId) break;
        this.lastSaved = e.recording;
        this.recording = null;
        break;
      case "sample": {
        if (e.sessionId !== this.session?.sessionId) break;
        // Row lists arrive about once a second (see engine.rs); on the ticks
        // between, keep the last ones so readers see a steady snapshot.
        const prev = this.latest;
        this.latest = e.endpoints || e.programs || !prev ? e : { ...e, endpoints: prev.endpoints, programs: prev.programs };
        const point: TrafficPoint = {
          tMs: e.tMs,
          inBps: e.inBps,
          outBps: e.outBps,
          smoothedBps: e.smoothedBps,
          baselineBps: e.baselineBps,
          ratio: e.ratio,
          level: e.level,
          rttMs: e.quality?.rttTickMs ?? null,
        };
        const next = this.history.length >= HISTORY_CAP ? this.history.slice(1) : this.history.slice();
        next.push(point);
        this.history = next;
        if (e.programs) this.#trackPrograms(e.tMs, e.programs.rows);
        if (e.endpoints) this.#trackEndpoints(e.tMs, e.endpoints.rows);
        break;
      }
      case "stopped":
        if (e.sessionId !== this.session?.sessionId) break;
        // While a start is in flight, this is the old session making room.
        if (!this.#starting) this.phase = "idle";
        this.recording = null;
        if (e.reason === "error") this.error = e.message ?? "Capture stopped unexpectedly";
        break;
    }
  }
}

export const monitor = new MonitorStore();

/**
 * User preferences, persisted per machine in localStorage.
 * These are conveniences only; the app works with defaults if storage fails.
 */
import type { GaugeConfig, Mode, Units } from "../api/types";

export interface SensitivityPreset {
  id: "sensitive" | "balanced" | "relaxed";
  label: string;
  hint: string;
  gauge: Pick<GaugeConfig, "busyRatio" | "spikeRatio" | "baselineRiseSecs">;
}

export const PRESETS: SensitivityPreset[] = [
  {
    id: "sensitive",
    label: "Sensitive",
    hint: "Flags small bursts: busy at 1.5×, spike at 3×",
    gauge: { busyRatio: 1.5, spikeRatio: 3, baselineRiseSecs: 120 },
  },
  {
    id: "balanced",
    label: "Balanced",
    hint: "Busy at 2×, spike at 5× the normal level",
    gauge: { busyRatio: 2, spikeRatio: 5, baselineRiseSecs: 60 },
  },
  {
    id: "relaxed",
    label: "Relaxed",
    hint: "Only big surges: busy at 3×, spike at 8×",
    gauge: { busyRatio: 3, spikeRatio: 8, baselineRiseSecs: 30 },
  },
];

export const WINDOWS = [30, 60, 300] as const;
export type WindowSecs = (typeof WINDOWS)[number];

interface Stored {
  /** Last page shown (see nav.svelte.ts). */
  page: string;
  mode: Mode;
  endpointsView: "table" | "map" | "packets";
  mapGroup: boolean;
  mapNeighbors: boolean;
  /** Endpoints shown on the map (0 = all, up to 150). */
  mapLimit: number;
  /** Probe common ports during a LAN scan. */
  lanProbePorts: boolean;
  onlineLookup: boolean;
  recordPcap: boolean;
  reverseDns: boolean;
  recentProcesses: string[];
  units: Units;
  windowSecs: WindowSecs;
  preset: SensitivityPreset["id"];
  busyRatio: number;
  spikeRatio: number;
  baselineRiseSecs: number;
  recentTargets: string[];
}

const KEY = "fishe.settings.v1";
const DEFAULTS: Stored = {
  page: "live",
  mode: "process",
  endpointsView: "table",
  mapGroup: false,
  mapNeighbors: false,
  mapLimit: 20,
  lanProbePorts: true,
  onlineLookup: false,
  recordPcap: false,
  reverseDns: true,
  recentProcesses: [],
  units: "bits",
  windowSecs: 60,
  preset: "balanced",
  busyRatio: 2,
  spikeRatio: 5,
  baselineRiseSecs: 60,
  recentTargets: [],
};

function load(): Stored {
  try {
    const raw = localStorage.getItem(KEY);
    return raw ? { ...DEFAULTS, ...JSON.parse(raw) } : { ...DEFAULTS };
  } catch {
    return { ...DEFAULTS };
  }
}

class Settings {
  #s = $state<Stored>(load());

  get page() { return this.#s.page; }
  set page(v: string) { this.#s.page = v; this.#save(); }
  get mode() { return this.#s.mode; }
  set mode(v: Mode) { this.#s.mode = v; this.#save(); }

  get recentProcesses() { return this.#s.recentProcesses; }

  get endpointsView() { return this.#s.endpointsView; }
  set endpointsView(v: "table" | "map" | "packets") { this.#s.endpointsView = v; this.#save(); }
  get mapGroup() { return this.#s.mapGroup; }
  set mapGroup(v: boolean) { this.#s.mapGroup = v; this.#save(); }
  get mapNeighbors() { return this.#s.mapNeighbors; }
  set mapNeighbors(v: boolean) { this.#s.mapNeighbors = v; this.#save(); }
  get mapLimit() { return this.#s.mapLimit ?? 20; }
  set mapLimit(v: number) { this.#s.mapLimit = v; this.#save(); }
  get lanProbePorts() { return this.#s.lanProbePorts ?? true; }
  set lanProbePorts(v: boolean) { this.#s.lanProbePorts = v; this.#save(); }

  get onlineLookup() { return this.#s.onlineLookup; }
  set onlineLookup(v: boolean) { this.#s.onlineLookup = v; this.#save(); }

  get recordPcap() { return this.#s.recordPcap; }
  set recordPcap(v: boolean) { this.#s.recordPcap = v; this.#save(); }

  get reverseDns() { return this.#s.reverseDns; }
  set reverseDns(v: boolean) { this.#s.reverseDns = v; this.#save(); }

  rememberProcess(name: string) {
    const v = name.trim();
    if (!v) return;
    const lower = v.toLowerCase();
    this.#s.recentProcesses = [v, ...this.#s.recentProcesses.filter((x) => x.toLowerCase() !== lower)].slice(0, 6);
    this.#save();
  }

  get units() { return this.#s.units; }
  set units(v: Units) { this.#s.units = v; this.#save(); }

  get windowSecs() { return this.#s.windowSecs; }
  set windowSecs(v: WindowSecs) { this.#s.windowSecs = v; this.#save(); }

  get preset() { return this.#s.preset; }
  get busyRatio() { return this.#s.busyRatio; }
  get spikeRatio() { return this.#s.spikeRatio; }
  get baselineRiseSecs() { return this.#s.baselineRiseSecs; }
  get recentTargets() { return this.#s.recentTargets; }

  applyPreset(id: SensitivityPreset["id"]) {
    const p = PRESETS.find((x) => x.id === id) ?? PRESETS[1];
    Object.assign(this.#s, { preset: p.id, ...p.gauge });
    this.#save();
  }

  /** Gauge overrides sent with start_monitor. */
  gaugeOverrides(): Partial<GaugeConfig> {
    return {
      busyRatio: this.#s.busyRatio,
      spikeRatio: this.#s.spikeRatio,
      baselineRiseSecs: this.#s.baselineRiseSecs,
    };
  }

  rememberTarget(t: string) {
    const v = t.trim();
    if (!v) return;
    this.#s.recentTargets = [v, ...this.#s.recentTargets.filter((x) => x !== v)].slice(0, 8);
    this.#save();
  }

  #save() {
    try {
      localStorage.setItem(KEY, JSON.stringify(this.#s));
    } catch {
      /* storage unavailable: keep in-memory values */
    }
  }
}

export const settings = new Settings();

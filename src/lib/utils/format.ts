/**
 * Number formatting. Rates and sizes use decimal SI prefixes (k = 1000),
 * the networking convention, so "100 Mb/s" matches what ISPs advertise.
 */
import type { Units } from "../api/types";

const PREFIXES = ["", "k", "M", "G", "T"];

function scale(v: number): { x: number; prefix: string } {
  let x = Math.abs(v);
  let i = 0;
  while (x >= 1000 && i < PREFIXES.length - 1) {
    x /= 1000;
    i++;
  }
  return { x: v < 0 ? -x : x, prefix: PREFIXES[i] };
}

function digits(x: number): number {
  const a = Math.abs(x);
  return a >= 100 ? 0 : a >= 10 ? 1 : 2;
}

/** Convert a bytes/s rate into the display unit. */
export function toUnits(bytesPerSec: number, units: Units): number {
  return units === "bits" ? bytesPerSec * 8 : bytesPerSec;
}

/** `{ value: "12.4", unit: "Mb/s" }` */
export function formatRate(bytesPerSec: number, units: Units): { value: string; unit: string } {
  const { x, prefix } = scale(toUnits(bytesPerSec, units));
  const sym = units === "bits" ? "b" : "B";
  return { value: prefix === "" ? Math.round(x).toString() : x.toFixed(digits(x)), unit: `${prefix}${sym}/s` };
}

export function rateText(bytesPerSec: number, units: Units): string {
  const r = formatRate(bytesPerSec, units);
  return `${r.value} ${r.unit}`;
}

/** Compact axis label for a value already in display units: 1k, 2.5M … */
export function shortSi(v: number): string {
  if (v === 0) return "0";
  const { x, prefix } = scale(v);
  const s = Number.isInteger(x) ? x.toString() : x.toFixed(x < 10 ? 1 : 0);
  return `${s}${prefix}`;
}

export function formatBytes(n: number): string {
  const { x, prefix } = scale(n);
  if (prefix === "") return `${Math.round(n)} B`;
  return `${x.toFixed(digits(x))} ${prefix}B`;
}

export function formatCount(n: number): string {
  const { x, prefix } = scale(n);
  if (prefix === "") return Math.round(n).toLocaleString();
  return `${x.toFixed(digits(x))}${prefix}`;
}

export function formatPps(pps: number): string {
  return `${pps < 10 ? pps.toFixed(1) : formatCount(pps)} pkt/s`;
}

export function formatRatio(r: number): string {
  if (!Number.isFinite(r)) return "–";
  return r < 10 ? `${r.toFixed(1)}×` : `${Math.round(r)}×`;
}

export function formatDuration(ms: number): string {
  const total = Math.floor(ms / 1000);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  const mm = String(m).padStart(h ? 2 : 1, "0");
  const ss = String(s).padStart(2, "0");
  return h ? `${h}:${mm}:${ss}` : `${mm}:${ss}`;
}

export function formatPercent(part: number, whole: number): string {
  if (whole <= 0) return "0%";
  const p = (part / whole) * 100;
  return p >= 10 || p === 0 ? `${Math.round(p)}%` : `${p.toFixed(1)}%`;
}

/** Smallest "nice" number (1, 2, 2.5, 5 × 10ⁿ) ≥ v. */
export function niceCeil(v: number): number {
  if (v <= 0 || !Number.isFinite(v)) return 1;
  const p = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 2, 2.5, 5, 10]) {
    if (v <= m * p + 1e-9) return m * p;
  }
  return 10 * p;
}

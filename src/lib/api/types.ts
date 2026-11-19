/**
 * Types shared by the UI.
 *
 * Everything that crosses the IPC boundary is generated from the Rust
 * definitions into `bindings.ts` (tauri-specta; see docs/ipc-api.md) and
 * re-exported here, so the UI imports its types from one place
 * (`$lib/api/types`). Only UI-only types are declared below.
 */
import type { Level } from "./bindings";

export type * from "./bindings";

export type Units = "bits" | "bytes";

/** One row of the Live page's "busiest" list: a program or an endpoint. */
export interface TopItem {
  key: string;
  name: string;
  sub: string | null;
  bps: number;
  level: Level;
}

/**
 * Compact per-tick record kept in the UI's history buffers (session, per
 * endpoint, per program). Built from samples; never sent over IPC.
 */
export interface TrafficPoint {
  tMs: number;
  inBps: number;
  outBps: number;
  smoothedBps: number;
  baselineBps: number;
  ratio: number;
  level: Level;
  /** TCP RTT measured in this tick (session) or the endpoint's smoothed RTT. */
  rttMs?: number | null;
}

/**
 * Connection-quality grading and formatting, shared by the live card, the
 * endpoints table and recordings. Thresholds are for interactive use
 * (games, calls, browsing); see docs/connection-quality.md.
 */

export type Grade = "good" | "fair" | "poor";

export const rttGrade = (ms: number): Grade => (ms < 80 ? "good" : ms < 150 ? "fair" : "poor");
export const jitterGrade = (ms: number): Grade => (ms < 10 ? "good" : ms < 30 ? "fair" : "poor");
/** Retransmitted or lost share, in percent. */
export const lossGrade = (pct: number): Grade => (pct < 1 ? "good" : pct < 3 ? "fair" : "poor");

/** Colour of a value by grade (good values stay in the normal text colour). */
export const GRADE_COLOR: Record<Grade, string> = {
  good: "var(--text-primary)",
  fair: "var(--level-busy)",
  poor: "var(--level-spike)",
};

export function msText(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return "–";
  if (ms < 10) return `${ms.toFixed(1)} ms`;
  return `${Math.round(ms)} ms`;
}

export function pctText(p: number | null | undefined): string {
  if (p === null || p === undefined || !Number.isFinite(p)) return "–";
  if (p > 0 && p < 0.1) return "<0.1%";
  return `${p.toFixed(p < 10 ? 1 : 0)}%`;
}

/**
 * The security report, read while the Security page is open.
 *
 * The backend builds the report on request (nothing is pushed): the page
 * asks every two seconds while it shows. The part that comes from an
 * all-traffic session disappears from the report when that session ends,
 * so the last one seen is kept here: stopping a session to read what it
 * found must not empty the page.
 */
import { api, errorMessage } from "../api";
import type { Finding, FindingKind, SecurityReport, SessionAudit } from "../api/types";

const EVERY_MS = 2000;

/** Findings that come from the session part of a report. */
const SESSION_KINDS: ReadonlySet<FindingKind> = new Set(["plaintext", "oldTls", "portScan", "inboundAccepted", "dnsFailures", "dnsUnencrypted"]);

class Security {
  report = $state.raw<SecurityReport | null>(null);
  /** The latest session audit seen, and its findings: kept after the session ends. */
  kept = $state.raw<{ session: SessionAudit; findings: Finding[] } | null>(null);
  error = $state<string | null>(null);
  forgetting = $state(false);

  #timer: ReturnType<typeof setInterval> | null = null;
  #watchers = 0;
  #busy = false;

  /** The session audit to show: the running session's, else the last one seen. */
  get session(): SessionAudit | null {
    return this.report?.session ?? this.kept?.session ?? null;
  }

  /** True when `session` is from a session that is no longer running. */
  get ended(): boolean {
    return !!this.report && !this.report.session && !!this.kept;
  }

  /** Every finding to show, most severe first; ids are stable, so rows hold still. */
  get findings(): Finding[] {
    const r = this.report;
    if (!r) return [];
    if (r.session || !this.kept) return r.findings;
    const order = { warning: 0, notice: 1, info: 2 } as const;
    return [...r.findings, ...this.kept.findings].sort((a, b) => order[a.severity] - order[b.severity] || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  }

  async refresh() {
    if (this.#busy) return;
    this.#busy = true;
    try {
      const r = await api.securityReport();
      this.report = r;
      // "dhcp-seen:…" are the DHCP servers heard during the session (the ones a scan found stay in the report).
      if (r.session) this.kept = { session: r.session, findings: r.findings.filter((f) => SESSION_KINDS.has(f.kind) || f.id.startsWith("dhcp-seen:")) };
      this.error = null;
    } catch (err) {
      this.error = errorMessage(err);
    } finally {
      this.#busy = false;
    }
  }

  /** Keep the report fresh while a page shows it. Returns the function that stops it. */
  watch(): () => void {
    this.#watchers++;
    void this.refresh();
    this.#timer ??= setInterval(() => void this.refresh(), EVERY_MS);
    return () => {
      if (--this.#watchers > 0 || this.#timer === null) return;
      clearInterval(this.#timer);
      this.#timer = null;
    };
  }

  /** Forget the devices remembered from LAN scans. */
  async forgetLan() {
    this.forgetting = true;
    try {
      await api.lanForget();
      await this.refresh();
    } catch (err) {
      this.error = errorMessage(err);
    } finally {
      this.forgetting = false;
    }
  }
}

export const security = new Security();

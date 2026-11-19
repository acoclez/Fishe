/**
 * Traceroute results and the LAN context, shared by the map and the
 * endpoints table. Traces run only when the user asks (they send ICMP
 * probes); at most 3 at a time, the rest queue.
 */
import { api, errorMessage } from "../api";
import type { NetContext, TraceResult } from "../api/types";

const PARALLEL = 3;

class Routes {
  /** Latest trace per target IP. */
  traces = $state.raw<Record<string, TraceResult>>({});
  /** Targets queued or being traced. */
  pending = $state.raw<string[]>([]);
  context = $state<NetContext | null>(null);
  error = $state<string | null>(null);

  #queue: { ip: string; force: boolean }[] = [];
  #active = 0;
  #loaded = false;

  /** Restore traces done earlier in this app run, and read gateways/neighbours. */
  async load() {
    if (!this.#loaded) {
      this.#loaded = true;
      try {
        const cached = await api.cachedTraces();
        this.traces = Object.fromEntries(cached.map((t) => [t.target, t]));
      } catch (err) {
        this.error = errorMessage(err);
      }
    }
    await this.refreshContext();
  }

  /** Reload traces done elsewhere (e.g. by an agent). */
  async reloadTraces() {
    try {
      const cached = await api.cachedTraces();
      this.traces = Object.fromEntries(cached.map((t) => [t.target, t]));
    } catch (err) {
      this.error = errorMessage(err);
    }
  }

  async refreshContext() {
    try {
      this.context = await api.networkContext();
    } catch (err) {
      this.error = errorMessage(err);
    }
  }

  isPending(ip: string) {
    return this.pending.includes(ip);
  }

  trace(ip: string, force = false) {
    if (this.isPending(ip)) return;
    this.#queue.push({ ip, force });
    this.pending = [...this.pending, ip];
    this.#pump();
  }

  /** Trace several targets (skipping ones already traced unless `force`). */
  traceMany(ips: string[], force = false) {
    for (const ip of ips) if (force || !this.traces[ip]) this.trace(ip, force);
  }

  #pump() {
    while (this.#active < PARALLEL && this.#queue.length) {
      const job = this.#queue.shift()!;
      this.#active++;
      api
        .traceRoute(job.ip, job.force)
        .then(
          (t) => (this.traces = { ...this.traces, [job.ip]: t }),
          (err) => (this.error = `Trace to ${job.ip} failed: ${errorMessage(err)}`),
        )
        .finally(() => {
          this.#active--;
          this.pending = this.pending.filter((p) => p !== job.ip);
          this.#pump();
        });
    }
  }
}

export const routes = new Routes();

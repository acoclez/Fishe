/**
 * Continuous pings (1 ICMP echo per second) started from the UI.
 * Polls `ping_status` once a second while any ping runs.
 */
import { api, errorMessage } from "../api";
import type { PingStatus } from "../api/types";

class PingStore {
  list = $state.raw<PingStatus[]>([]);
  error = $state<string | null>(null);
  #timer: ReturnType<typeof setInterval> | null = null;

  get(ip: string | null | undefined): PingStatus | null {
    if (!ip) return null;
    return this.list.find((p) => p.ip === ip) ?? null;
  }

  running(ip: string | null | undefined): boolean {
    return this.get(ip)?.running ?? false;
  }

  async start(ip: string) {
    try {
      this.error = null;
      await api.pingStart(ip);
      await this.refresh();
    } catch (err) {
      this.error = errorMessage(err);
    }
  }

  async stop(ip: string) {
    try {
      await api.pingStop(ip);
      await this.refresh();
    } catch (err) {
      this.error = errorMessage(err);
    }
  }

  async stopAll() {
    for (const p of this.list.filter((x) => x.running)) await api.pingStop(p.ip).catch(() => {});
    await this.refresh();
  }

  toggle(ip: string) {
    return this.running(ip) ? this.stop(ip) : this.start(ip);
  }

  async remove(ip: string) {
    await api.pingRemove(ip).catch(() => {});
    await this.refresh();
  }

  async refresh() {
    try {
      this.list = await api.pingStatus();
    } catch (err) {
      this.error = errorMessage(err);
    }
    const anyRunning = this.list.some((p) => p.running);
    if (anyRunning && !this.#timer) this.#timer = setInterval(() => this.refresh(), 1000);
    if (!anyRunning && this.#timer) {
      clearInterval(this.#timer);
      this.#timer = null;
    }
  }
}

export const pings = new PingStore();

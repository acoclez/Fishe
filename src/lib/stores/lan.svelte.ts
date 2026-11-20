/**
 * The last LAN scan. A scan runs only when the user asks (it sends ARP
 * requests and, optionally, probes a few ports). Its result lives here, not
 * in the Map page, so it is still there after a visit to another page, and
 * a scan started before leaving the page finishes into it. Kept in memory
 * only: gone when the app closes.
 */
import { api, errorMessage } from "../api";
import type { LanScan } from "../api/types";

class Lan {
  scanning = $state(false);
  result = $state.raw<LanScan | null>(null);
  error = $state<string | null>(null);
  /** How the devices are shown: remembered with the result. */
  view = $state<"list" | "map">("list");

  /** Scan the local network; the result replaces the previous one whole. */
  async scan(probePorts: boolean) {
    if (this.scanning) return;
    this.scanning = true;
    this.error = null;
    try {
      this.result = await api.scanLan(probePorts);
    } catch (err) {
      this.error = errorMessage(err);
    } finally {
      this.scanning = false;
    }
  }
}

export const lan = new Lan();

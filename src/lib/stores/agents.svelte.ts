/**
 * The local MCP server as the UI sees it: settings, the activity log, and
 * the "changed" notifications for what has its own store here (pings,
 * traces). Sessions and recordings an agent starts need nothing special:
 * they arrive through the monitor subscription like the window's own.
 */
import { api, errorMessage, inTauri } from "../api";
import type { McpAccess, McpActivity, McpStatus } from "../api/types";

/** Backend notifications (see src-tauri/src/ops.rs). */
export interface ChangeHandlers {
  pings: () => void;
  traces: () => void;
}

class Agents {
  status = $state<McpStatus | null>(null);
  activity = $state.raw<McpActivity[]>([]);
  error = $state<string | null>(null);
  busy = $state(false);
  /** Bumped on every call, for a brief header flash. */
  pulse = $state(0);

  async refresh() {
    try {
      [this.status, this.activity] = await Promise.all([api.mcpStatus(), api.mcpActivity()]);
    } catch (err) {
      this.error = errorMessage(err);
    }
  }

  async configure(enabled: boolean, access: McpAccess, port: number) {
    this.busy = true;
    this.error = null;
    try {
      this.status = await api.mcpConfigure(enabled, access, port);
    } catch (err) {
      this.error = errorMessage(err);
    } finally {
      this.busy = false;
    }
  }

  async newToken() {
    try {
      this.status = await api.mcpNewToken();
    } catch (err) {
      this.error = errorMessage(err);
    }
  }

  async clear() {
    await api.mcpClearActivity().catch(() => {});
    this.activity = [];
  }

  /** Subscribe to the activity log and change notifications (desktop app only). Returns an unsubscribe function. */
  async listen(h: ChangeHandlers): Promise<() => void> {
    if (!inTauri) return () => {};
    const { listen } = await import("@tauri-apps/api/event");
    const offs = await Promise.all([
      listen<McpActivity>("fishe://mcp-activity", (e) => {
        this.activity = [e.payload, ...this.activity].slice(0, 200);
        if (this.status) this.status = { ...this.status, calls: this.status.calls + 1 };
        this.pulse++;
      }),
      listen("fishe://pings-changed", () => h.pings()),
      listen("fishe://traces-changed", () => h.traces()),
    ]);
    return () => offs.forEach((off) => off());
  }
}

export const agents = new Agents();

/**
 * The backend API as the UI sees it.
 *
 * Inside Tauri every call goes through the generated `commands` in
 * `bindings.ts` (tauri-specta, from the Rust command signatures); this module
 * only adapts them where the UI wants a different shape (defaults, channel
 * callbacks, `void` results). Outside Tauri (plain browser during UI work)
 * the same API is served by the simulated backend in `demo.ts`, which only
 * the dev server ever loads: it is not part of a production build.
 */
import { Channel } from "@tauri-apps/api/core";
import { commands } from "./bindings";
import type { AppError, ExportFormat, GeoProgress, MonitorEvent, SessionDefaults } from "./types";

/** True when running inside the Tauri webview (false in a plain browser). */
export const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

/** Commands without a result come back as `null`; the UI treats them as `void`. */
const done = (p: Promise<unknown>): Promise<void> => p.then(() => undefined);

const tauriApi = {
  npcapStatus: commands.npcapStatus,
  /** Look for Npcap again (after installing it while the app runs). */
  npcapRecheck: commands.npcapRecheck,
  /** Open Npcap's download page in the default browser. */
  openNpcapSite: () => done(commands.openNpcapSite()),
  defaultGaugeConfig: commands.defaultGaugeConfig,
  listInterfaces: commands.listInterfaces,
  resolveTarget: commands.resolveTarget,
  suggestInterface: commands.suggestInterface,
  monitorStatus: commands.monitorStatus,
  stopMonitor: commands.stopMonitor,
  listProcesses: commands.listProcesses,
  /** Live packet list (Packets view): on while the view is open. */
  setPacketFeed: commands.setPacketFeed,
  recentPackets: (after: number | null, limit = 500) => commands.recentPackets(after, limit),
  systemCapabilities: commands.systemCapabilities,

  geoStatus: commands.geoStatus,
  /** Download DB-IP Lite (user-initiated only). */
  geoDownload(onProgress: (p: GeoProgress) => void) {
    const channel = new Channel<GeoProgress>();
    channel.onmessage = onProgress;
    return commands.geoDownload(channel);
  },
  geoRemove: commands.geoRemove,
  setOnlineLookup: commands.setOnlineLookup,
  geoLookup: commands.geoLookup,

  /** Traceroute (sends ICMP probes): only from an explicit user action. */
  traceRoute: (ip: string, force = false) => commands.traceRoute(ip, force),
  cachedTraces: commands.cachedTraces,
  /** Continuous ping (1 ICMP echo/s): only from an explicit user action. */
  pingStart: commands.pingStart,
  pingStop: commands.pingStop,
  pingRemove: (ip: string) => done(commands.pingRemove(ip)),
  pingStatus: commands.pingStatus,

  /** Local MCP server for AI agents (off by default). */
  mcpStatus: commands.mcpStatus,
  mcpConfigure: commands.mcpConfigure,
  mcpNewToken: commands.mcpNewToken,
  mcpActivity: commands.mcpActivity,
  mcpClearActivity: commands.mcpClearActivity,
  networkContext: commands.networkContext,
  scanLan: commands.scanLan,

  startRecording: commands.startRecording,
  stopRecording: commands.stopRecording,
  listRecordings: commands.listRecordings,
  getRecording: commands.getRecording,
  getEndpointSeries: commands.getEndpointSeries,
  renameRecording: (id: number, name: string) => done(commands.renameRecording(id, name)),
  deleteRecording: (id: number) => done(commands.deleteRecording(id)),
  archiveLocation: commands.archiveLocation,
  revealInFolder: (path: string) => done(commands.revealInFolder(path)),
  /** Diagnostics: where `fishe.log` is, and a button to get there. */
  logsLocation: commands.logsLocation,
  openLogsFolder: () => done(commands.openLogsFolder()),
  /**
   * Export a recording. The backend asks where to save (the window never
   * names a path). Resolves to the path, or null if cancelled.
   */
  exportRecording: (id: number, format: ExportFormat, suggestedName: string): Promise<string | null> =>
    commands.exportRecording(id, format, suggestedName),

  /**
   * Receive every monitor event from now on: sessions and recordings started
   * here or by an agent. Once, when the window mounts; a running session is
   * announced at once.
   */
  subscribeMonitor(onEvent: (e: MonitorEvent) => void) {
    const channel = new Channel<MonitorEvent>();
    channel.onmessage = onEvent;
    return done(commands.subscribeMonitor(channel));
  },
  /** The Settings an agent-started session should measure with. */
  setMonitorDefaults: (defaults: SessionDefaults) => done(commands.setMonitorDefaults(defaults)),
  /** Start a session (events arrive through `subscribeMonitor`). */
  startMonitor: commands.startMonitor,
};

export type Api = typeof tauriApi;

/**
 * The simulated backend, fetched on the first call. Every method of the API
 * is asynchronous, so waiting for the module first changes nothing for callers.
 */
function demoApi(): Api {
  let loaded: Promise<Api> | undefined;
  const load = () => (loaded ??= import("./demo").then((m) => m.demoApi));
  return new Proxy({} as Api, {
    get: (_, method) =>
      // Not a thenable: an `await` or a debugger must not mistake the API for a promise.
      typeof method !== "string" || method === "then"
        ? undefined
        : (...args: unknown[]) => load().then((demo) => (demo[method as keyof Api] as (...a: unknown[]) => unknown)(...args)),
  });
}

// `PROD` is a build-time constant: in a production build the right-hand side
// and the demo module behind it are dropped from the bundle.
export const api: Api = import.meta.env.PROD || inTauri ? tauriApi : demoApi();

/** Normalise anything thrown by `invoke` into a readable message. */
export function errorMessage(err: unknown): string {
  if (err && typeof err === "object" && "message" in err) {
    return String((err as AppError).message);
  }
  return String(err);
}

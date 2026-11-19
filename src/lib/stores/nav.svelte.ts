/**
 * Which page the window shows. One page at a time, chosen from the side rail
 * or the number keys. The last page is remembered across launches; each page
 * keeps its scroll position while the app runs.
 */
import { settings } from "./settings.svelte";

export type Page = "live" | "connections" | "map" | "archive" | "settings";

export interface PageInfo {
  id: Page;
  label: string;
  /** Number key that opens it. */
  key: string;
  hint: string;
}

export const PAGES: PageInfo[] = [
  { id: "live", label: "Live", key: "1", hint: "Gauge, traffic chart, quality and the busiest programs or endpoints" },
  { id: "connections", label: "Connections", key: "2", hint: "Every program, endpoint and packet of the session" },
  { id: "map", label: "Map", key: "3", hint: "Where the traffic goes: routes, owners, countries" },
  { id: "archive", label: "Archive", key: "4", hint: "Saved recordings" },
  { id: "settings", label: "Settings", key: "5", hint: "Sensitivity, units, owners database, agents (MCP), diagnostics" },
];

/** Sections of the settings page, for deep links (e.g. the Agents chip). */
export const SETTINGS_SECTIONS = [
  { id: "measure", label: "Measurement", hint: "Sensitivity, units, chart window" },
  { id: "capture", label: "Recording and names", hint: "Packet files, reverse DNS" },
  { id: "owners", label: "Owners database", hint: "DB-IP download, online lookup" },
  { id: "agents", label: "Agents (MCP)", hint: "Access level, token, client setup, activity" },
  { id: "diagnostics", label: "Diagnostics", hint: "Log file for bug reports" },
] as const;
export type SettingsSection = (typeof SETTINGS_SECTIONS)[number]["id"];

class Nav {
  page = $state<Page>(PAGES.some((p) => p.id === settings.page) ? (settings.page as Page) : "live");
  /** Settings section to scroll to once the page shows (then cleared). */
  section = $state<SettingsSection | null>(null);
  /** Scroll position per page, kept while the app runs. */
  scroll = new Map<Page, number>();

  go(page: Page, section: SettingsSection | null = null) {
    this.section = section;
    if (page === this.page) return;
    this.page = page;
    settings.page = page;
  }
}

export const nav = new Nav();

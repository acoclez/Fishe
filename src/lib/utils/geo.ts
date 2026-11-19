/** Display helpers for endpoint owners and countries. */
import type { Owner } from "../api/types";

let regionNames: Intl.DisplayNames | null = null;
try {
  regionNames = new Intl.DisplayNames(undefined, { type: "region" });
} catch {
  regionNames = null;
}

/** "AU" → "Australia" (in the user's language); falls back to the code. */
export function countryName(code: string | null | undefined): string {
  if (!code) return "";
  try {
    return regionNames?.of(code.toUpperCase()) ?? code;
  } catch {
    return code;
  }
}

/** Tooltip text: "AS13335 Cloudflare, Inc. · Australia · DB-IP". */
export function ownerTitle(o: Owner | null | undefined): string {
  if (!o) return "";
  return [
    [o.asn ? `AS${o.asn}` : "", o.org ?? ""].filter(Boolean).join(" "),
    countryName(o.country),
    o.source === "dbip" ? "source: DB-IP Lite" : "source: ipinfo.io",
  ]
    .filter(Boolean)
    .join(" · ");
}

/** Searchable text for filters. */
export function ownerText(o: Owner | null | undefined): string {
  if (!o) return "";
  return `${o.org ?? ""} ${o.asn ? `as${o.asn}` : ""} ${o.country ?? ""} ${countryName(o.country)}`.toLowerCase();
}

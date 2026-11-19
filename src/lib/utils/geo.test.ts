import { describe, expect, it } from "vitest";
import { countryName, ownerText, ownerTitle } from "./geo";
import type { Owner } from "../api/types";

const cloudflare: Owner = { asn: 13335, org: "Cloudflare, Inc.", country: "AU", source: "dbip" };

describe("countryName", () => {
  it("is empty for no code and spells out a known code", () => {
    expect(countryName(null)).toBe("");
    expect(countryName(undefined)).toBe("");
    const au = countryName("au");
    // Localised, so only its shape is checked: a word, not the code.
    expect(au.length).toBeGreaterThan(2);
    expect(au).not.toBe("au");
  });

  it("falls back to the code for garbage", () => {
    expect(countryName("not a code")).toBe("not a code");
  });
});

describe("owner text", () => {
  it("builds the tooltip from the parts that exist", () => {
    expect(ownerTitle(null)).toBe("");
    const t = ownerTitle(cloudflare);
    expect(t.startsWith("AS13335 Cloudflare, Inc. · ")).toBe(true);
    expect(t.endsWith(" · source: DB-IP Lite")).toBe(true);
    expect(ownerTitle({ asn: null, org: null, country: null, source: "ipinfo" })).toBe("source: ipinfo.io");
    expect(ownerTitle({ asn: 64500, org: null, country: null, source: "ipinfo" })).toBe("AS64500 · source: ipinfo.io");
  });

  it("makes lower-case searchable text", () => {
    expect(ownerText(null)).toBe("");
    const s = ownerText(cloudflare);
    expect(s).toContain("cloudflare, inc.");
    expect(s).toContain("as13335");
    expect(s).toContain("au");
    expect(s).toBe(s.toLowerCase());
  });
});

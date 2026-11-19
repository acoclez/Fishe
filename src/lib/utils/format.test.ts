import { describe, expect, it } from "vitest";
import { formatBytes, formatCount, formatDuration, formatPercent, formatPps, formatRate, formatRatio, niceCeil, rateText, shortSi, toUnits } from "./format";

describe("rates", () => {
  it("converts bytes/s to the display unit", () => {
    expect(toUnits(100, "bits")).toBe(800);
    expect(toUnits(100, "bytes")).toBe(100);
  });

  it("scales with SI prefixes and 3 significant digits", () => {
    expect(formatRate(1_550_000, "bits")).toEqual({ value: "12.4", unit: "Mb/s" });
    expect(formatRate(1_550_000, "bytes")).toEqual({ value: "1.55", unit: "MB/s" });
    expect(formatRate(0, "bytes")).toEqual({ value: "0", unit: "B/s" });
    expect(formatRate(12.6, "bytes")).toEqual({ value: "13", unit: "B/s" });
    // The prefix table ends at tera.
    expect(formatRate(125_000_000_000_000, "bits")).toEqual({ value: "1000", unit: "Tb/s" });
    expect(rateText(125, "bits")).toBe("1.00 kb/s");
  });

  it("makes compact axis labels", () => {
    expect(shortSi(0)).toBe("0");
    expect(shortSi(1000)).toBe("1k");
    expect(shortSi(2500)).toBe("2.5k");
    expect(shortSi(12_345_678)).toBe("12M");
  });
});

describe("sizes and counts", () => {
  it("formats bytes", () => {
    expect(formatBytes(999)).toBe("999 B");
    expect(formatBytes(1536)).toBe("1.54 kB");
    expect(formatBytes(2.5e9)).toBe("2.50 GB");
  });

  it("formats counts and packet rates", () => {
    expect(formatCount(999)).toBe("999");
    expect(formatCount(1500)).toBe("1.50k");
    expect(formatPps(3.14159)).toBe("3.1 pkt/s");
    expect(formatPps(12_000)).toBe("12.0k pkt/s");
  });

  it("formats ratios and percentages", () => {
    expect(formatRatio(Infinity)).toBe("–");
    expect(formatRatio(2.345)).toBe("2.3×");
    expect(formatRatio(12.6)).toBe("13×");
    expect(formatPercent(1, 0)).toBe("0%");
    expect(formatPercent(0, 5)).toBe("0%");
    expect(formatPercent(1, 40)).toBe("2.5%");
    expect(formatPercent(3, 4)).toBe("75%");
  });

  it("formats durations", () => {
    expect(formatDuration(0)).toBe("0:00");
    expect(formatDuration(65_000)).toBe("1:05");
    expect(formatDuration(3_725_000)).toBe("1:02:05");
  });
});

describe("niceCeil", () => {
  it("rounds up to 1, 2, 2.5, 5 × 10ⁿ", () => {
    expect(niceCeil(0)).toBe(1);
    expect(niceCeil(-3)).toBe(1);
    expect(niceCeil(0.3)).toBe(0.5);
    expect(niceCeil(1)).toBe(1);
    expect(niceCeil(1.1)).toBe(2);
    expect(niceCeil(2.2)).toBe(2.5);
    expect(niceCeil(3)).toBe(5);
    expect(niceCeil(7)).toBe(10);
    expect(niceCeil(10)).toBe(10);
    expect(niceCeil(1234)).toBe(2000);
  });
});

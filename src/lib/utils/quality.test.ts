import { describe, expect, it } from "vitest";
import { jitterGrade, lossGrade, msText, pctText, rttGrade } from "./quality";

describe("grades", () => {
  it("rate RTT, jitter and loss for interactive use", () => {
    expect([rttGrade(79), rttGrade(80), rttGrade(150)]).toEqual(["good", "fair", "poor"]);
    expect([jitterGrade(9), jitterGrade(10), jitterGrade(30)]).toEqual(["good", "fair", "poor"]);
    expect([lossGrade(0.9), lossGrade(1), lossGrade(3)]).toEqual(["good", "fair", "poor"]);
  });
});

describe("text", () => {
  it("formats milliseconds", () => {
    expect(msText(null)).toBe("–");
    expect(msText(undefined)).toBe("–");
    expect(msText(NaN)).toBe("–");
    expect(msText(5.26)).toBe("5.3 ms");
    expect(msText(123.6)).toBe("124 ms");
  });

  it("formats percentages", () => {
    expect(pctText(null)).toBe("–");
    expect(pctText(0)).toBe("0.0%");
    expect(pctText(0.05)).toBe("<0.1%");
    expect(pctText(2.345)).toBe("2.3%");
    expect(pctText(12.3)).toBe("12%");
  });
});

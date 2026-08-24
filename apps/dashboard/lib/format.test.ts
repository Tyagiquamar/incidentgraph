import { describe, expect, it } from "vitest";
import { formatCost, formatMs, pct, shortID, statusColor } from "./format";

describe("shortID", () => {
  it("truncates uuids to 8 chars", () => {
    expect(shortID("a1b2c3d4-e5f6-7890-abcd-ef0123456789")).toBe("a1b2c3d4");
  });
});

describe("statusColor", () => {
  it("maps terminal statuses", () => {
    expect(statusColor("complete")).toBe("#1a7f37");
    expect(statusColor("failed")).toBe("#cf222e");
    expect(statusColor("needs_approval")).toBe("#9a6700");
    expect(statusColor("running")).toBe("#0969da");
    expect(statusColor("unknown")).toBe("#0969da");
  });
});

describe("formatMs", () => {
  it("formats milliseconds, seconds and minutes", () => {
    expect(formatMs(250)).toBe("250 ms");
    expect(formatMs(1500)).toBe("1.5 s");
    expect(formatMs(125_000)).toBe("2m 5s");
  });
});

describe("formatCost", () => {
  it("formats cents", () => {
    expect(formatCost(0)).toBe("$0");
    expect(formatCost(0.25)).toBe("25.00¢");
    expect(formatCost(2.5)).toBe("$2.50");
  });
});

describe("pct", () => {
  it("rounds fractions to percent strings", () => {
    expect(pct(0.2647)).toBe("26%");
    expect(pct(1)).toBe("100%");
  });
});

import { describe, expect, it } from "vitest";
import type { Prediction } from "./api";
import { bestIndex, cellIntensity, filterPredictions, formatBytes, formatDuration, page, reasonBars, rowShares } from "./ml";

const pred = (ts: string, label: string, confidence: number) => ({ ts_utc: ts, label, confidence }) as Prediction;

describe("ML Advanced helpers", () => {
  it("formats sizes and durations", () => {
    expect(formatBytes(1_455_667)).toBe("1.46 MB");
    expect(formatBytes(11_334)).toBe("11.3 KB");
    expect(formatDuration(300)).toBe("300 µs");
    expect(formatDuration(9_500)).toBe("9.5 ms");
    expect(formatDuration(2_500_000)).toBe("2.50 s");
  });

  it("scales confusion-matrix cells logarithmically and normalises rows", () => {
    expect(cellIntensity(0, 1000)).toBe(0);
    expect(cellIntensity(1000, 1000)).toBeCloseTo(1);
    expect(cellIntensity(10, 1000)).toBeGreaterThan(0.3);
    expect(rowShares([[3, 1], [0, 0]])).toEqual([[0.75, 0.25], [0, 0]]);
  });

  it("finds the best model per metric", () => {
    expect(bestIndex([0.8, 0.85, 0.85])).toBe(1);
    expect(bestIndex([0.2, 0.1, 0.3], true)).toBe(1);
  });

  it("turns explanation weights into shares and ignores non-positive ones", () => {
    const bars = reasonBars([
      { feature: "a", text: "A", weight: 60 },
      { feature: "b", text: "B", weight: 20 },
      { feature: "c", text: "C", weight: 0 },
    ]);
    expect(bars.map((b) => b.feature)).toEqual(["a", "b"]);
    expect(bars[0].share).toBeCloseTo(0.75);
    expect(reasonBars(null)).toEqual([]);
  });

  it("filters, sorts and pages predictions", () => {
    const rows = [pred("2026-10-14T10:00:00Z", "PortScan", 0.9), pred("2026-10-14T11:00:00Z", "DDoS", 0.6), pred("2026-10-14T12:00:00Z", "PortScan", 0.99)];
    expect(filterPredictions(rows, "PortScan", "time").map((p) => p.confidence)).toEqual([0.99, 0.9]);
    expect(filterPredictions(rows, "all", "confidence").map((p) => p.label)).toEqual(["PortScan", "PortScan", "DDoS"]);
    expect(page([1, 2, 3, 4, 5], 1, 2)).toEqual({ rows: [3, 4], pages: 3, index: 1 });
    expect(page([1, 2], 9, 2).index).toBe(0);
    expect(page([], 0, 10).pages).toBe(1);
  });
});

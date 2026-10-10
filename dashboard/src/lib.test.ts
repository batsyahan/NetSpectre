import { describe, expect, it } from "vitest";
import { severityOf, summarize } from "./lib";

const anomaly = (c: number) => ({ label: "Anomaly (unknown)", avg_confidence: c });

describe("severityOf", () => {
  it("rates weak unknown anomalies as low", () => {
    expect(severityOf(anomaly(0.5))).toBe("low");
    expect(severityOf(anomaly(0.59))).toBe("low");
  });
  it("rates strong unknown anomalies as medium (0.6 is the boundary)", () => {
    expect(severityOf(anomaly(0.6))).toBe("medium");
    expect(severityOf(anomaly(1))).toBe("medium");
  });
  it("uses the fixed severity for known attack labels", () => {
    expect(severityOf({ label: "PortScan", avg_confidence: 0.9 })).toBe("medium");
    expect(severityOf({ label: "DoS Hulk", avg_confidence: 0.9 })).toBe("high");
    expect(severityOf({ label: "DDoS", avg_confidence: 0.9 })).toBe("critical");
    expect(severityOf({ label: "Heartbleed", avg_confidence: 0.9 })).toBe("critical");
  });
  it("does not downgrade a known attack because confidence is low", () => {
    expect(severityOf({ label: "PortScan", avg_confidence: 0.3 })).toBe("medium");
  });
  it("defaults to medium for a label it does not know", () => {
    expect(severityOf({ label: "SomethingNew", avg_confidence: 0.9 })).toBe("medium");
  });
});

describe("summarize", () => {
  const a = (label: string, c: number, ts: string) => ({ label, avg_confidence: c, ts_utc: ts });

  it("handles a device with no alerts", () => {
    expect(summarize([])).toEqual({ total: 0, byLabel: [], top: null, first: "", last: "" });
  });
  it("counts per attack, most frequent first", () => {
    const r = summarize([
      a("PortScan", 0.9, "2026-10-09T09:00:00Z"),
      a("Anomaly (unknown)", 0.9, "2026-10-09T09:05:00Z"),
      a("PortScan", 0.9, "2026-10-09T09:10:00Z"),
    ]);
    expect(r.total).toBe(3);
    expect(r.byLabel).toEqual([["PortScan", 2], ["Anomaly (unknown)", 1]]);
  });
  it("reports the worst severity and the time range", () => {
    const r = summarize([
      a("Anomaly (unknown)", 0.5, "2026-10-09T09:10:00Z"),
      a("DoS Hulk", 0.9, "2026-10-09T09:00:00Z"),
      a("PortScan", 0.9, "2026-10-09T09:20:00Z"),
    ]);
    expect(r.top).toBe("high");
    expect(r.first).toBe("2026-10-09T09:00:00Z");
    expect(r.last).toBe("2026-10-09T09:20:00Z");
  });
});

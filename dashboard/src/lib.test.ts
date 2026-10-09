import { describe, expect, it } from "vitest";
import { severityOf } from "./lib";

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

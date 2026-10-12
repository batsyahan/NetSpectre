import { describe, expect, it } from "vitest";
import type { Alert, Device } from "./api";
import {
  ANOMALY,
  attackColors,
  barTone,
  countByLabel,
  deviceState,
  deviceStateCounts,
  inRange,
  ongoing,
  share,
  toSlices,
  topSources,
} from "./metrics";

const NOW = Date.parse("2026-10-12T12:00:00Z");
const MIN = 60_000;
const at = (minutesAgo: number) => new Date(NOW - minutesAgo * MIN).toISOString();

const alert = (over: Partial<Alert>): Alert => ({
  id: 1,
  ts_utc: at(1),
  src_ip: "10.0.0.1",
  label: "PortScan",
  flow_count: 10,
  avg_confidence: 0.9,
  status: "new",
  ...over,
});
const device = (ip: string, minutesAgo: number, flows = 1): Device => ({
  ip,
  first_seen: at(1000),
  last_seen: at(minutesAgo),
  flow_count: flows,
  alert_count: 0,
});

describe("deviceState", () => {
  it("is online within 5 minutes and offline after", () => {
    expect(deviceState({ last_seen: at(4) }, NOW)).toBe("online");
    expect(deviceState({ last_seen: at(5) }, NOW)).toBe("online");
    expect(deviceState({ last_seen: at(6) }, NOW)).toBe("offline");
  });
  it("is unknown when the timestamp cannot be parsed", () => {
    expect(deviceState({ last_seen: "not a date" }, NOW)).toBe("unknown");
  });
  it("counts each state", () => {
    const c = deviceStateCounts([device("a", 1), device("b", 60), device("c", 2)], NOW);
    expect(c).toEqual({ online: 2, offline: 1, unknown: 0 });
  });
});

describe("inRange", () => {
  const rows = [alert({ id: 1, ts_utc: at(60) }), alert({ id: 2, ts_utc: at(60 * 30) }), alert({ id: 3, ts_utc: at(60 * 24 * 8) })];
  it("keeps everything for all time", () => {
    expect(inRange(rows, "all", NOW)).toHaveLength(3);
  });
  it("filters by window", () => {
    expect(inRange(rows, "24h", NOW).map((a) => a.id)).toEqual([1]);
    expect(inRange(rows, "7d", NOW).map((a) => a.id)).toEqual([1, 2]);
  });
  it("drops alerts with a bad timestamp from a bounded range", () => {
    expect(inRange([alert({ ts_utc: "bad" })], "24h", NOW)).toHaveLength(0);
  });
});

describe("countByLabel and share", () => {
  it("sorts by count then name", () => {
    const rows = countByLabel([{ label: "B" }, { label: "A" }, { label: "A" }, { label: "C" }]);
    expect(rows).toEqual([
      { label: "A", count: 2 },
      { label: "B", count: 1 },
      { label: "C", count: 1 },
    ]);
  });
  it("gives shares that add up to 100.0 for the reference counts", () => {
    const parts = [35, 20, 1].map((n) => Number(share(n, 56)));
    expect(parts).toEqual([62.5, 35.7, 1.8]);
    expect(parts.reduce((a, b) => a + b, 0)).toBeCloseTo(100, 5);
  });
  it("does not divide by zero", () => {
    expect(share(0, 0)).toBe("0.0");
  });
});

describe("ongoing", () => {
  it("counts only new, recent, classified alerts as confirmed", () => {
    const r = ongoing(
      [
        alert({ ts_utc: at(2) }),
        alert({ ts_utc: at(9) }),
        alert({ ts_utc: at(11) }),
        alert({ ts_utc: at(2), status: "acknowledged" }),
        alert({ ts_utc: at(2), label: ANOMALY }),
      ],
      NOW,
    );
    expect(r).toEqual({ confirmed: 2, anomalies: 1 });
  });
  it("is zero when nothing is recent", () => {
    expect(ongoing([alert({ ts_utc: at(60 * 48) })], NOW)).toEqual({ confirmed: 0, anomalies: 0 });
  });
});

describe("topSources", () => {
  it("ranks by alerts, then flows, and fills with busy quiet devices", () => {
    const alerts = [alert({ src_ip: "a" }), alert({ src_ip: "a" }), alert({ src_ip: "b" })];
    const devices = [device("a", 1, 10), device("b", 1, 500), device("c", 1, 900), device("d", 1, 5)];
    expect(topSources(alerts, devices, 3).map((r) => [r.ip, r.alerts, r.flows])).toEqual([
      ["a", 2, 10],
      ["b", 1, 500],
      ["c", 0, 900],
    ]);
  });
});

describe("barTone", () => {
  it("scales relative to the largest value", () => {
    expect(barTone(18, 18)).toBe("red");
    expect(barTone(10, 18)).toBe("orange");
    expect(barTone(6, 18)).toBe("yellow");
    expect(barTone(4, 18)).toBe("muted");
    expect(barTone(0, 18)).toBe("muted");
  });
});

describe("colors and slices", () => {
  it("keeps fixed colors for the common attacks", () => {
    const c = attackColors(["PortScan", ANOMALY, "Heartbleed"]);
    expect(c[ANOMALY]).toBe("#2f8cff");
    expect(c.PortScan).toBe("#f58a1f");
    expect(c.Heartbleed).toBe("#2fd48f");
  });
  it("gives every other label a distinct color", () => {
    const c = attackColors(["DDoS", "DoS Hulk", "Bot"]);
    expect(new Set(Object.values(c)).size).toBe(3);
  });
  it("folds the tail into a gray Other slice", () => {
    const rows = ["a", "b", "c", "d", "e", "f", "g"].map((label, i) => ({ label, count: 10 - i }));
    const s = toSlices(rows, 5);
    expect(s).toHaveLength(6);
    expect(s[5]).toMatchObject({ label: "Other", value: 5 + 4 });
  });
  it("does not add Other when everything fits", () => {
    expect(toSlices([{ label: "PortScan", count: 3 }])).toHaveLength(1);
  });
});
